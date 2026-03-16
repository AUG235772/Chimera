# modules/analyst.py
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AnalystEngine:
    def __init__(self, raw_vulnerabilities, logger_callback=None):
        self.raw_vulns = raw_vulnerabilities
        self.log = logger_callback if logger_callback else print
        self.verified_vulns = [] 

    def get_risk_score(self, severity, url):
        """Calculates a 1-10 score based on ZAP severity and asset sensitivity."""
        scores = {"CRITICAL": 9, "HIGH": 7, "MEDIUM": 5, "LOW": 3}
        base = scores.get(severity, 1)
        
        # Context Awareness: High value paths increase the score
        sensitive_paths = ['login', 'admin', 'auth', 'pricing', 'config', 'checkout']
        if any(path in url.lower() for path in sensitive_paths):
            base += 1
            
        return min(base, 10)

    def verify_reflection(self, url, payload):
        """Proof of Concept: Verifies if an XSS payload actually renders in the page."""
        if not payload or payload == "Header/Parameter Check": return False
        try:
            # Check for actual reflection in the source code
            res = requests.get(url, timeout=10, verify=False, headers={'User-Agent': 'Chimera-Beast/2.0'})
            if payload in res.text:
                return True
        except: pass
        return False

    def audit_headers(self, url):
        """Custom audit for critical security headers often missed by automation."""
        findings = []
        try:
            res = requests.head(url, timeout=10, verify=False, allow_redirects=True)
            headers = res.headers
            if 'Content-Security-Policy' not in headers:
                findings.append({'name': 'Missing CSP Header', 'severity': 'HIGH', 'desc': 'No Content Security Policy detected.'})
            if 'X-Frame-Options' not in headers:
                findings.append({'name': 'Missing Anti-clickjacking Header', 'severity': 'MEDIUM', 'desc': 'X-Frame-Options or CSP frame-ancestors is missing.'})
        except: pass
        return findings

    def start(self):
        self.log("[*] Starting Smart Analysis, Deduplication & Verification...")
        
        self.verified_vulns = []
        unique_hashes = set()

        # 1. Inject Custom Header Audit Findings
        if self.raw_vulns:
            base_url = self.raw_vulns[0]['url']
            header_issues = self.audit_headers(base_url)
            for issue in header_issues:
                self.verified_vulns.append({
                    'type': issue['name'],
                    'url': base_url,
                    'severity': issue['severity'],
                    'risk_score': self.get_risk_score(issue['severity'], base_url),
                    'payload': 'Header Check',
                    'description': issue['desc']
                })

        # 2. Process ZAP Findings with Intelligence
        for v in self.raw_vulns:
            # Create a unique fingerprint to prevent 100+ duplicate listings
            # We group by Type + Base URL (stripping dynamic params)
            fingerprint = f"{v['type']}-{v['url'].split('?')[0]}"
            
            if fingerprint not in unique_hashes:
                unique_hashes.add(fingerprint)
                
                # Assign Intelligence Score
                v['risk_score'] = self.get_risk_score(v['severity'], v['url'])
                
                # Perform "Deadly" Verification for XSS
                if "XSS" in v['type'] or "Cross Site Scripting" in v['type']:
                    if self.verify_reflection(v['url'], v['payload']):
                        v['severity'] = "CRITICAL (VERIFIED)"
                        v['risk_score'] = 10
                        self.log(f"🔥 [VERIFIED] High-confidence XSS at {v['url']}")
                
                self.verified_vulns.append(v)

        self.log(f"✅ Analysis Complete: Condensed {len(self.raw_vulns)} alerts into {len(self.verified_vulns)} unique threats.")
        return self.verified_vulns