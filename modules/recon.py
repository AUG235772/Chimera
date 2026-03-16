# modules/recon.py
import requests
import urllib3
import socket
import re # NEW: Required for deep JS parsing
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from utils import logger
import concurrent.futures

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ReconEngine:
    def __init__(self, target_url, logger_callback=None):
        self.target_url = target_url.rstrip('/')
        self.domain = urlparse(self.target_url).netloc.replace('www.', '')
        
        self.session = requests.Session()
        self.session.verify = False 
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        
        self.visited_urls = set()
        self.found_urls = set()
        self.js_files = set()
        self.subdomains = set()
        self.open_ports = []
        
        self.log = logger_callback if logger_callback else logger.info

    def validate_url(self, url):
        parsed_target = urlparse(self.target_url)
        parsed_url = urlparse(url)
        is_same_domain = parsed_target.netloc == parsed_url.netloc
        is_not_media = not any(url.lower().endswith(ext) for ext in ['.jpg', '.png', '.css', '.pdf', '.gif', '.svg', '.ico'])
        return is_same_domain and is_not_media

    # --- PASSIVE SUBDOMAIN DISCOVERY ---
    def find_subdomains(self):
        self.log("🔍 [RECON] Querying Certificate Transparency logs for hidden subdomains...")
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            res = requests.get(url, timeout=15)
            if res.status_code == 200:
                data = res.json()
                for entry in data:
                    name = entry.get('name_value', '').lower()
                    if '*' not in name and name != self.domain:
                        self.subdomains.add(name)
                
                if self.subdomains:
                    self.log(f"🌐 [RECON] Found {len(self.subdomains)} subdomains (e.g., {list(self.subdomains)[0]})")
                else:
                    self.log("🌐 [RECON] No external subdomains found.")
        except Exception as e:
            self.log(f"⚠️ [RECON] Subdomain enumeration timed out.")

    # --- RAPID PORT SCANNER ---
    def scan_ports(self):
        self.log("🔍 [RECON] Initiating rapid port scan for exposed services...")
        ports_to_check = [21, 22, 80, 443, 3306, 3389, 8080, 8443, 27017]
        
        def check_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((self.domain, port))
            sock.close()
            if result == 0:
                self.open_ports.append(port)
                self.log(f"🔓 [RECON] Port {port} is OPEN on {self.domain}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(check_port, ports_to_check)

    # --- UPGRADED: DIRSEARCH-LITE (SWAGGER & GRAPHQL) ---
    def discover_hidden(self):
        self.log("🔍 [RECON] Fuzzing for critical hidden APIs and exposed configs...")
        # UPGRADE: Added Swagger, OpenAPI, and GraphQL targets
        sensitive_paths = [
            '/.env', '/.git/config', '/admin', '/api/v1', '/api/v2',
            '/backup.zip', '/server-status', '/phpinfo.php', 
            '/swagger.json', '/swagger-ui.html', '/openapi.json', 
            '/graphql', '/api/graphql', '/v1/graphql'
        ]
        
        for path in sensitive_paths:
            test_url = self.target_url + path
            try:
                res = self.session.head(test_url, timeout=5, allow_redirects=False)
                if res.status_code in [200, 401, 403]:
                    self.log(f"🎯 [SHADOW API] Discovered hidden path: {path} (Status: {res.status_code})")
                    if res.status_code == 200:
                        self.found_urls.add(test_url) # Feed to ZAP
            except:
                pass

    # --- NEW MODULE: JAVASCRIPT SHADOW API HUNTER ---
    def analyze_js_files(self):
        if not self.js_files:
            return

        self.log(f"🧠 [RECON] Downloading and analyzing {len(self.js_files)} JS bundles for Shadow APIs...")
        
        # Regex to find endpoint-like paths (e.g., "/api/admin/users" or "https://api.target.com/v1")
        endpoint_pattern = re.compile(r'(?:"|\')(((?:[a-zA-Z]{1,10}://|/)[a-zA-Z0-9_/\-\.]+))(?:"|\')')
        # Regex to find hardcoded tokens/secrets
        secret_pattern = re.compile(r'(?i)(?:api_key|bearer|token|secret|password|aws_access_key)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-~]{15,})["\']')

        def parse_js(js_url):
            try:
                res = self.session.get(js_url, timeout=10)
                if res.status_code == 200:
                    content = res.text
                    
                    # Extract shadow endpoints
                    endpoints = endpoint_pattern.findall(content)
                    for ep in endpoints:
                        # Clean up paths and filter out HTML tags or generic slash
                        if len(ep) > 4 and len(ep) < 100 and not ep.startswith('<') and ep != '/':
                            if ep.startswith('/'):
                                full_ep = urljoin(self.target_url, ep)
                                if full_ep not in self.found_urls and self.validate_url(full_ep):
                                    self.found_urls.add(full_ep)
                                    self.log(f"🕵️ [SHADOW API] Extracted hidden route from JS: {ep}")
                            elif "api" in ep.lower() or "graphql" in ep.lower():
                                self.log(f"🕵️ [SHADOW API] Found external API reference: {ep}")

                    # Extract Hardcoded Secrets from Frontend
                    secrets = secret_pattern.findall(content)
                    for secret in secrets:
                        self.log(f"🚨 [CRITICAL] Hardcoded Token found in JS bundle ({js_url}): {secret[:5]}******")
            except:
                pass

        # Parse JS files concurrently for maximum speed
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(parse_js, self.js_files)

    # --- EXISTING MODULE: SPIDER ---
    def crawl_page(self, url):
        if url in self.visited_urls: return
        self.visited_urls.add(url)
        
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code == 403:
                self.log(f"⚠️ [RECON] 403 Forbidden at {url} (WAF detected)")
                return
            if response.status_code >= 400: return

            soup = BeautifulSoup(response.text, 'html.parser')
            
            for anchor in soup.find_all('a', href=True):
                full_url = urljoin(url, anchor['href'])
                if self.validate_url(full_url):
                    self.found_urls.add(full_url)
            
            # Collect JS files for deep analysis later
            for script in soup.find_all('script', src=True):
                js_url = urljoin(url, script['src'])
                if self.validate_url(js_url):
                    self.js_files.add(js_url)

        except Exception as e:
            if url == self.target_url:
                self.log(f"❌ [CRITICAL] Connection Failed to target: {str(e)}")

    def start(self):
        # 1. Run the Attack Surface modules
        self.find_subdomains()
        self.scan_ports()
        self.discover_hidden()
        
        # 2. Run the internal Spider
        self.log("🕷️ [RECON] Initiating internal deep web spidering...")
        self.crawl_page(self.target_url)
        
        # 3. Crawl discovered links (depth 1)
        if not self.found_urls:
            return []

        initial_links = list(self.found_urls)
        count = 0
        for link in initial_links:
            if count > 20: break 
            self.crawl_page(link)
            count += 1
            
        # 4. UPGRADE: Analyze collected JavaScript bundles
        self.analyze_js_files()
            
        self.log(f"✅ [RECON] Surface mapping complete. Handing {len(self.found_urls)} targets to ZAP Engine.")
        return list(self.found_urls)