# modules/scanner.py
import requests
import urllib3
from urllib.parse import urlparse, parse_qs, urlunparse, urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ScannerEngine:
    def __init__(self, logger_callback=None):
        self.session = requests.Session()
        self.session.verify = False
        # FIX: Same Browser User-Agent here
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.vulnerabilities = []
        self.log = logger_callback if logger_callback else print

    def get_params(self, url):
        return parse_qs(urlparse(url).query)

    # ... [Keep scan_sqli, scan_xss, scan_open_redirect, scan_server_config exactly as before] ...
    # (Just copy-paste them from your previous file to save space here, or I can paste if you need)
    
    # --- NEW: Sensitive File Hunter ---
    def scan_sensitive_files(self, base_url):
        # List of critical files to check for
        sensitive_files = [
            '.env', '.git/config', '.ds_store', 'robots.txt', 
            'sitemap.xml', 'backup.zip', 'database.sql', 
            'wp-config.php.bak', 'composer.json', 'package.json'
        ]
        
        parsed = urlparse(base_url)
        # Construct the root URL (e.g., https://site.com/)
        root_url = f"{parsed.scheme}://{parsed.netloc}/"
        
        for file in sensitive_files:
            target = urljoin(root_url, file)
            try:
                res = self.session.get(target, timeout=5)
                # If we get a 200 OK and it's not a custom 404 page
                if res.status_code == 200:
                    # Basic filter to ensure it's not a fake 200 (check content length)
                    if len(res.text) > 0:
                        self.vulnerabilities.append({"url": target, "type": "Sensitive File", "payload": file})
                        self.log(f"[HIGH] Sensitive File Exposed: {file}")
            except: pass

    # --- 1. SQL Injection ---
    def scan_sqli(self, url):
        params = self.get_params(url)
        if not params: return
        payloads = ["'", '"', "' OR '1'='1"]
        errors = ["you have an error in your sql syntax", "warning: mysql", "quoted string not properly terminated"]
        parsed = urlparse(url)
        for param in params.keys():
            for payload in payloads:
                query = parsed.query.replace(f"{param}={params[param][0]}", f"{param}={params[param][0]}{payload}")
                target = urlunparse(parsed._replace(query=query))
                try:
                    res = self.session.get(target, timeout=5)
                    for err in errors:
                        if err in res.text.lower():
                            self.vulnerabilities.append({"url": url, "type": "SQLi", "payload": payload})
                            self.log(f"[CRITICAL] SQL Injection found at parameter '{param}'")
                            return
                except: pass

    # --- 2. XSS ---
    def scan_xss(self, url):
        params = self.get_params(url)
        if not params: return
        payload = "<ChimeraXSS>"
        parsed = urlparse(url)
        for param in params.keys():
            query = parsed.query.replace(f"{param}={params[param][0]}", f"{param}={payload}")
            target = urlunparse(parsed._replace(query=query))
            try:
                res = self.session.get(target, timeout=5)
                if payload in res.text:
                    self.vulnerabilities.append({"url": url, "type": "XSS", "payload": payload})
                    self.log(f"[HIGH] Reflected XSS found at parameter '{param}'")
            except: pass

    # --- 3. Open Redirects ---
    def scan_open_redirect(self, url):
        params = self.get_params(url)
        if not params: return
        payload = "http://evil.com"
        redirect_params = ['next', 'url', 'target', 'dest', 'r', 'u', 'go']
        parsed = urlparse(url)
        for param in params.keys():
            if param in redirect_params:
                query = parsed.query.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                target = urlunparse(parsed._replace(query=query))
                try:
                    res = self.session.get(target, timeout=5, allow_redirects=False)
                    if res.status_code in [301, 302] and 'evil.com' in res.headers.get('Location', ''):
                        self.vulnerabilities.append({"url": url, "type": "Open Redirect", "payload": payload})
                        self.log(f"[MEDIUM] Open Redirect found at parameter '{param}'")
                except: pass

    # --- 4. Server Config ---
    def scan_server_config(self, url):
        try:
            res = self.session.get(url, timeout=5)
            headers = res.headers
            if 'X-Frame-Options' not in headers:
                self.vulnerabilities.append({"url": url, "type": "Clickjacking", "payload": "Missing X-Frame-Options"})
                self.log(f"[LOW] Clickjacking Risk (Missing X-Frame-Options)")
            if 'Strict-Transport-Security' not in headers and url.startswith("https"):
                self.vulnerabilities.append({"url": url, "type": "Security Misconfig", "payload": "Missing HSTS"})
                self.log(f"[LOW] Missing HSTS Header")
        except: pass

    def start(self, url_list):
        if not url_list: return []
        
        # 1. Scan Server Config
        self.log(f"[*] Analyzing Server Security Headers on {url_list[0]}...")
        self.scan_server_config(url_list[0])

        # 2. NEW: Scan for Sensitive Files (Checking the root domain)
        self.log(f"[*] Hunting for Sensitive Files (.env, .git, backups)...")
        self.scan_sensitive_files(url_list[0])

        # 3. Scan Parameters
        target_urls = [u for u in url_list if "?" in u]
        self.log(f"[*] Attacking {len(target_urls)} parameterized endpoints...")
        
        for url in target_urls:
            self.scan_sqli(url)
            self.scan_xss(url)
            self.scan_open_redirect(url)
        
        return self.vulnerabilities