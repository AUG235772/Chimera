# modules/waf_detector.py
import requests
import urllib3
from utils import logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WAFDetector:
    def __init__(self, target_url, logger_callback=None):
        self.target_url = target_url
        self.log = logger_callback if logger_callback else logger.info
        
        # Enterprise WAF Signatures (Headers & Cookies)
        self.waf_signatures = {
            "Cloudflare": {"headers": ["cf-ray", "cloudflare"], "cookies": ["__cfduid", "cf_clearance"]},
            "Vercel Edge Security": {"headers": ["x-vercel-id", "x-vercel-cache"]},
            "Akamai": {"headers": ["x-akamai-request-id"], "cookies": ["ak_bmsc"]},
            "AWS WAF": {"headers": ["x-amzn-requestid", "x-amzn-trace-id"], "cookies": ["awsalb"]},
            "Imperva / Incapsula": {"headers": ["x-cdn"], "cookies": ["incap_ses", "visid_incap"]},
            "F5 BIG-IP": {"headers": ["x-cnection", "x-wa-info"], "cookies": ["f5_cspm", "bigipserver"]},
            "Sucuri": {"headers": ["x-sucuri-id", "x-sucuri-cache"]},
        }

    def detect(self):
        self.log(f"🛡️ [WAF DETECTOR] Probing active edge defenses on {self.target_url}...")
        try:
            # Send a standard request with a normal user-agent
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'}
            response = requests.get(self.target_url, headers=headers, timeout=10, verify=False)
            
            # Convert response headers to lowercase for easy matching
            res_headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            res_cookies = response.cookies.get_dict().keys()

            detected_wafs = []

            for waf_name, sigs in self.waf_signatures.items():
                # Check for WAF-specific headers
                for header in sigs.get("headers", []):
                    if header in res_headers or any(header in v for v in res_headers.values()):
                        if waf_name not in detected_wafs:
                            detected_wafs.append(waf_name)
                
                # Check for WAF-specific session cookies
                for cookie in sigs.get("cookies", []):
                    if cookie in res_cookies:
                        if waf_name not in detected_wafs:
                            detected_wafs.append(waf_name)

            if detected_wafs:
                waf_str = " & ".join(detected_wafs)
                self.log(f"🚨 [WAF DETECTED] Target is actively protected by: {waf_str}")
                return waf_str
            else:
                self.log("✅ [WAF DETECTOR] No standard WAF signatures detected. Target edge is exposed.")
                return "None Detected"

        except Exception as e:
            self.log(f"⚠️ [WAF DETECTOR] Probe failed: {str(e)}")
            return "Unknown"