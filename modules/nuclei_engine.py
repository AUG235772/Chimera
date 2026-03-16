# modules/nuclei_engine.py
import subprocess
import json
import os
from utils import logger

class NucleiEngine:
    def __init__(self, target_url, auth_header=None, logger_callback=None):
        self.target_url = target_url
        self.auth_header = auth_header
        self.log = logger_callback if logger_callback else logger.info

    def start_scan(self):
        self.log(f"☢️ [NUCLEI] Initiating Advanced CVE & Zero-Day Scan on {self.target_url}...")
        
        output_file = "nuclei_results.json"
        
        # Command: Scan for CVEs, High/Critical vulnerabilities, and Exposed Panels
        cmd = [
            "nuclei", "-u", self.target_url,
            "-t", "cves,vulnerabilities,misconfiguration,exposed-panels",
            "-severity", "critical,high,medium",
            "-json-export", output_file,
            "-disable-update-check"
        ]

        if self.auth_header:
            # Inject the cookie into Nuclei so it scans authenticated areas!
            cmd.extend(["-H", f"Cookie: {self.auth_header}"])

        findings = []
        try:
            # Run Nuclei (Timeout after 5 minutes to keep it fast)
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Parse the JSON results exported by Nuclei
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    for line in f:
                        try:
                            data = json.loads(line.strip())
                            info = data.get('info', {})
                            
                            # Extract CVE ID if it exists
                            cve_id = ""
                            classification = info.get('classification', {})
                            if 'cve-id' in classification and classification['cve-id']:
                                cve_id = f"[{classification['cve-id'][0]}] "

                            # 🔴 NUCLEI GIVES US THE EXACT WEAPONIZED CURL COMMAND FOR THE EXPLOIT LAB!
                            poc_payload = data.get('curl-command', 'N/A')
                            
                            finding = {
                                'type': f"NUCLEI: {cve_id}{info.get('name', 'Unknown Vulnerability')}",
                                'severity': info.get('severity', 'high').upper(),
                                'url': data.get('matched-at', self.target_url),
                                'payload': data.get('extracted-results', [''])[0] if data.get('extracted-results') else data.get('matcher-name', 'Template Match'),
                                'proof_of_concept': poc_payload,
                                'impact': info.get('description', 'Exploitable CVE identified by Nuclei template engine.'),
                                'remediation': info.get('remediation', 'Apply the latest vendor patches immediately.')
                            }
                            findings.append(finding)
                        except json.JSONDecodeError:
                            continue
                os.remove(output_file) # Cleanup

            if findings:
                self.log(f"🔥 [NUCLEI] Critical Hit! Found {len(findings)} CVEs/Misconfigurations.")
            else:
                self.log("✅ [NUCLEI] No known CVEs detected on the external attack surface.")
                
            return findings

        except subprocess.TimeoutExpired:
            self.log("⚠️ [NUCLEI] Scan timed out. Returning partial results.")
            return findings
        except Exception as e:
            self.log(f"❌ [NUCLEI] Engine failure: {str(e)}")
            return []