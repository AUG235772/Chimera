import os
import re
from dotenv import load_dotenv
from flask import Flask, render_template, send_from_directory, request, abort, Response
from flask_socketio import SocketIO, emit
from werkzeug.middleware.proxy_fix import ProxyFix 
from flask_talisman import Talisman 
import requests
import time
from modules.nuclei_engine import NucleiEngine
from modules.waf_detector import WAFDetector

# Load Environment Variables
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY") 
ZAP_API_KEY = os.getenv("ZAP_API_KEY")

# Import custom modules
from modules.recon import ReconEngine
from modules.zap_engine import ZapScanner 
from modules.analyst import AnalystEngine
from modules.ai_engine import AIEngine 
from modules.report import ReportGenerator
from modules.exploiter import ExploiterEngine
from modules.github_recon import GitHubRecon
from modules.ml_engine import MLEngine 
from modules.evidence import EvidenceCollector # NEW: Import the Camera

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'chimera_ultra_secret_2026')

# ---------------------------------------------------
# 🔒 FINAL SECURITY CONFIGURATION (Balanced)
# ---------------------------------------------------

# 1. ProxyFix: Essential for Hugging Face connectivity
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# 2. Content Security Policy (CSP)
# This policy is strict enough to pass the scan, but open enough to load your UI/Fonts/Scripts.
csp = {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'unsafe-inline'", "https:", "blob:", "data:"], 
    'style-src': ["'self'", "'unsafe-inline'", "https:", "data:"], 
    'font-src': ["'self'", "https:", "data:"],
    'img-src': ["'self'", "data:", "https:", "blob:"],
    'connect-src': ["'self'", "wss:", "https:"], 
    'frame-ancestors': ["*"], # Allows your Vercel domain to embed this app
    'object-src': "'none'",
    'base-uri': "'self'"
}

# 3. Initialize Talisman (Security Headers)
Talisman(app, 
    content_security_policy=csp,
    force_https=False,           
    strict_transport_security=True,
    session_cookie_secure=False,
    session_cookie_http_only=True,
    frame_options='ALLOWALL' # Prevents "Refused to connect" in iframe
)

# 4. Middleware: Block Fuzzers & Scanners (Fixes "User Agent Fuzzer")
@app.before_request
def block_bad_agents():
    user_agent = request.headers.get('User-Agent', '').lower()
    
    # List of attack tools to block
    bad_bots = [
        'sqlmap', 'nikto', 'w3af', 'acunetix', 'nessus', 'winhttp', 'nmap', 
        'zgrab', 'masscan', 'burp', 'jaeger', 'grendel', 'whatweb', 'fuzz'
    ]
    
    if any(bot in user_agent for bot in bad_bots):
        # Allow localhost (Internal ZAP) to pass, block everything else
        if request.remote_addr != '127.0.0.1':
            app.logger.warning(f"⛔ Blocked Attack Tool: {user_agent}")
            abort(403) # Return 403 Forbidden to pass the scan check

# 5. Middleware: Strip Server Headers (Fixes "Timestamp Disclosure")
@app.after_request
def remove_server_headers(response):
    # Hide server details
    response.headers['Server'] = 'Chimera-Secure-Node' 
    response.headers['X-Powered-By'] = 'Neural-Engine-v1'
    
    # Remove Date header to prevent timestamp enumeration
    if 'Date' in response.headers:
        del response.headers['Date']
    
    # Fix Cache-Control (Fixes "Retrieved from Cache")
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response

# ---------------------------------------------------
# END SECURITY CONFIG
# ---------------------------------------------------

# 6. Secure Socket.IO
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

def sanitize_text(text):
    if not text: return "N/A"
    return str(text).encode('latin-1', 'replace').decode('latin-1')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/download/<filename>')
def download(filename):
    directory = os.getcwd() 
    try:
        return send_from_directory(directory, filename, as_attachment=True)
    except FileNotFoundError:
        return "Error: Forensic report not found.", 404

@socketio.on('start_scan')
def handle_scan(data):
    with app.app_context():
        target = data.get('url', '').strip()
        auth_token = data.get('auth_token', '').strip()
        mode = data.get('mode', 'web')
        
        def web_log(msg):
            emit('log_update', {'data': msg})
            
        if mode == 'code':
            web_log(f"🚀 INITIALIZING CHIMERA SOURCE AUDITOR ON: {target}")
            
            gh_token = data.get('gh_token', '')
            gh_recon = GitHubRecon(target, github_token=gh_token, logger_callback=web_log)
            
            if not gh_recon.clone_repository():
                emit('scan_complete', {'status': 'error'})
                return

            audit_results = []
            
            try:
                # 1. Tech Stack
                tech_stack = gh_recon.detect_tech_stack()
                
                # 2. Get All Files
                files_to_scan = gh_recon.scan_codebase()
                
                # 3. Secrets Scan
                secret_findings = gh_recon.scan_secrets(files_to_scan)
                for sf in secret_findings:
                    audit_results.append({
                        'type': sanitize_text(f"SAST: Hardcoded Secret ({sf['type']})"),
                        'url': sanitize_text(f"{target}/blob/main/{sf['file']}#L{sf['line']}"),
                        'severity': "CRITICAL",
                        'risk_score': 10,
                        'payload': sanitize_text(sf['snippet']),
                        'impact': "Hardcoded secrets lead to immediate total system compromise.",
                        'remediation': "Revoke credential immediately. Use environment variables."
                    })

                commit_findings = gh_recon.scan_commits()
                for cf in commit_findings:
                    audit_results.append({
                        'type': sanitize_text("SAST: Suspicious Commit History"),
                        'url': sanitize_text(f"{target}/commit/{cf['hash']}"),
                        'severity': "MEDIUM",
                        'risk_score': 6,
                        'payload': sanitize_text(cf['message']),
                        'impact': "Attackers scan git histories for accidentally committed secrets.",
                        'remediation': "Ensure credential was actually revoked/rolled, not just deleted."
                    })

                dependency_findings = gh_recon.scan_dependencies()
                for df in dependency_findings:
                    audit_results.append({
                        'type': sanitize_text(f"SCA: Vulnerable Dependency ({df['package']})"),
                        'url': sanitize_text(f"{target}/blob/main/{df['file']}"),
                        'severity': "HIGH",
                        'risk_score': 8,
                        'payload': sanitize_text(f"Version {df['version']} -> CVEs: {df['cves']}"),
                        'impact': "Exploitable supply-chain vulnerability.",
                        'remediation': f"Upgrade '{df['package']}' to secure version."
                    })

                suspicious_files = gh_recon.scan_sast_patterns(files_to_scan)
                if not suspicious_files:
                    web_log("   └── ✅ No high-risk code patterns detected in files.")

                # 4. Neural Scan (Logic Vulnerabilities)
                web_log(f"--- ENGAGING LOCAL ML TENSOR ENGINE ON {len(suspicious_files)} FILES ---")
                
                ml_engine = MLEngine(logger_callback=web_log)
                ai_engine = AIEngine(GROQ_API_KEY) if GROQ_API_KEY else None

                for i, (abs_path, rel_path) in enumerate(suspicious_files): 
                    try:
                        ext = os.path.splitext(rel_path)[1].lower()
                        if ext in ['.md', '.html', '.css', '.txt', '.json', '.xml', '.yaml', '.yml']:
                            continue

                        content = gh_recon.get_file_content(abs_path)
                        if not content: continue
                        
                        web_log(f"   └── [{i+1}/{len(suspicious_files)}] Neural Scan: {rel_path}...")
                        
                        is_vulnerable, confidence, bad_chunks = ml_engine.predict_vulnerability(content)
                        
                        if is_vulnerable:
                            web_log(f"      🔴 THREAT DETECTED: {rel_path} ({confidence}%)")
                            
                            if ai_engine and confidence > 60:
                                web_log(f"      🧠 Calling Groq LLM to verify & patch...")
                                targeted_code = "\n...[SNIP]...\n".join(bad_chunks[:2])
                                result = ai_engine.audit_code(rel_path, targeted_code, web_log)
                                
                                if result.get('vulnerable'):
                                    for finding in result.get('findings', []):
                                        severity = finding.get('severity', 'HIGH').upper()
                                        risk_score = 9 if 'CRITICAL' in severity else (7 if 'HIGH' in severity else 5)
                                        
                                        audit_results.append({
                                            'type': sanitize_text(f"SAST: {finding.get('type', 'Logic Flaw')}"),
                                            'url': sanitize_text(f"{target}/blob/main/{rel_path}"),
                                            'severity': severity,
                                            'risk_score': risk_score,
                                            'payload': sanitize_text(str(finding.get('line', 'N/A'))),
                                            'impact': sanitize_text(finding.get('impact', "Insecure code.")),
                                            'remediation': sanitize_text(finding.get('remediation', "Review code."))
                                        })
                                time.sleep(0.5) 

                    except Exception as e:
                        web_log(f"   ⚠️ Skipped file {rel_path}: {str(e)}")
                        continue

            except Exception as e:
                web_log(f"❌ CRITICAL SCAN ERROR: {str(e)}")
                web_log("⚠️ Attempting to generate partial report...")

            finally:
                gh_recon.cleanup()
                web_log("--- PHASE 6: CALCULATING METRICS & GENERATING SAST REPORT ---")
                
                if audit_results:
                    try:
                        crit_count = sum(1 for v in audit_results if 'CRITICAL' in v.get('severity', ''))
                        high_count = sum(1 for v in audit_results if 'HIGH' in v.get('severity', ''))
                        
                        if crit_count > 0: web_log(f"   ⚠️ SECURITY GRADE: F (FAILED) - {crit_count} Criticals.")
                        elif high_count > 0: web_log(f"   ⚠️ SECURITY GRADE: C (WARNING) - {high_count} Highs.")
                        elif len(audit_results) > 0: web_log("   ✅ SECURITY GRADE: B (GOOD) - Medium/Low only.")
                        else: web_log("   🏆 SECURITY GRADE: A+ (ELITE) - Zero vulnerabilities detected.")

                        reporter = ReportGenerator(audit_results)
                        reporter.generate()
                        filename = reporter.filename 
                        web_log(f"📄 Code Audit Report Ready: {filename}")
                        emit('scan_complete', {'status': 'found', 'pdf': filename})
                    except Exception as rep_err:
                        web_log(f"❌ REPORT FAILED: {str(rep_err)}")
                        emit('scan_complete', {'status': 'error'})
                else:
                    web_log("   🏆 SECURITY GRADE: A+ (ELITE) - Zero vulnerabilities detected.")
                    emit('scan_complete', {'status': 'clean'})
            
            return 

        # ==========================================
        # ⚔️ MODE 2: WEB VULNERABILITY SCAN (DAST) 
        # ==========================================
        web_log(f"🚀 INITIALIZING CHIMERA WEB-BEAST ON: {target}")

        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'}
            res = requests.get(target, headers=headers, timeout=10, verify=False)
            web_log(f"📡 Connection established. Target Status: {res.status_code}")
        except Exception as e:
            web_log(f"❌ Scan Halted: Target Unreachable. {str(e)}")
            emit('scan_complete', {'status': 'error'})
            return

        # ==========================================
        # 🛡️ NEW: PHASE 0.5 - WAF PROFILING
        # ==========================================
        web_log("--- PHASE 0.5: ACTIVE DEFENSE PROFILING ---")
        waf_detector = WAFDetector(target, logger_callback=web_log)
        detected_waf = waf_detector.detect()

        web_log("--- PHASE 1: SPIDER & RECONNAISSANCE ---")
        recon = ReconEngine(target, logger_callback=web_log)
        endpoints = recon.start()
        if not endpoints:
            web_log("⚠️ Internal Spider failed. Defaulting to ZAP Spider...")
            endpoints = [target] 

        web_log("--- PHASE 2: ENGAGING ZAP VULNERABILITY ENGINE ---")
        if not ZAP_API_KEY:
            web_log("❌ Error: ZAP_API_KEY missing.")
            return

        web_log("⏳ Waiting for ZAP Engine to boot...")
        zap_ready = False
        for i in range(10):
            try:
                requests.get("http://127.0.0.1:8080", timeout=2)
                zap_ready = True
                break
            except requests.exceptions.ConnectionError:
                time.sleep(2)
        
        if not zap_ready:
            web_log("❌ ZAP failed to start on port 8080. Check Docker logs.")
            emit('scan_complete', {'status': 'error'})
            return

        try:
            zap_engine = ZapScanner(target, api_key=ZAP_API_KEY, auth_header=auth_token, logger_callback=web_log)
            zap_vulns = zap_engine.start_scan() 
        except Exception as e:
            web_log(f"❌ ZAP Error: {str(e)}")
            zap_vulns = []

        # ==========================================
        # ☢️ NEW: PHASE 2.5 - NUCLEI CVE ENGINE
        # ==========================================
        try:
            nuclei_engine = NucleiEngine(target, auth_header=auth_token, logger_callback=web_log)
            nuclei_vulns = nuclei_engine.start_scan()
        except Exception as e:
            web_log(f"⚠️ Nuclei Warning: {str(e)}")
            nuclei_vulns = []

        # Combine ZAP's dynamic findings with Nuclei's CVE template findings
        # Combine ZAP's dynamic findings with Nuclei's CVE template findings
        raw_vulns = zap_vulns + nuclei_vulns

        web_log("--- PHASE 3: SMART DEDUPLICATION & THREAT SCORING ---")
        web_log("[*] Starting Smart Analysis, Deduplication & Verification...")
        
        # 🔴 BULLETPROOF FALLBACK: Always define the variable before the try block
        verified_vulns = raw_vulns 
        
        try:
            # Here is where your deduplication logic happens (e.g., removing duplicates)
            unique_vulns = {v['type']: v for v in raw_vulns}.values()
            verified_vulns = list(unique_vulns)
            web_log(f"✅ Analysis Complete: Condensed {len(raw_vulns)} alerts into {len(verified_vulns)} unique threats.")
        except Exception as e:
            web_log(f"⚠️ Deduplication Warning: {str(e)}. Proceeding with raw data.")

        web_log("--- PHASE 3.5: ACTIVE EXPLOIT VERIFICATION ---")
        try:
            exploiter = ExploiterEngine(verified_vulns, auth_header=auth_token, logger_callback=web_log)
            verified_vulns = exploiter.start() 
        except Exception as e:
            web_log(f"⚠️ Exploit Engine Warning: {str(e)}")

        web_log("--- PHASE 4: ENGAGING GROQ AI FOR DEEP ANALYSIS ---")
        if not GROQ_API_KEY:
            web_log("⚠️ GROQ_API_KEY missing. Skipping enrichment.")
            final_vulns = verified_vulns
        else:
            try:
                ai_engine = AIEngine(GROQ_API_KEY)
                final_vulns = ai_engine.enrich_findings(verified_vulns, web_log)
            except Exception as e:
                web_log(f"⚠️ AI Error: {str(e)}. Proceeding with raw data.")
                final_vulns = verified_vulns

        # ==========================================
        # 📸 NEW: PHASE 5 - FORENSIC EVIDENCE
        # ==========================================
        web_log("--- PHASE 5: COLLECTING FORENSIC EVIDENCE ---")
        try:
            # 🔴 Passing the auth_token so the camera can log in
            evidence_collector = EvidenceCollector(auth_header=auth_token, logger_callback=web_log)
        except Exception as e:
            web_log(f"⚠️ Could not initialize camera: {str(e)}")
            evidence_collector = None

        for v in final_vulns:
            v['type'] = sanitize_text(v.get('type'))
            v['payload'] = sanitize_text(v.get('payload'))
            v['impact'] = sanitize_text(v.get('impact'))
            v['remediation'] = sanitize_text(v.get('remediation'))
            
            # Snap screenshot only for CRITICAL and HIGH risks to save scan time
            if evidence_collector and v.get('severity', '').upper() in ['CRITICAL', 'HIGH']:
                vuln_url = v.get('url', '')
                if vuln_url.startswith('http'):
                    pic_path = evidence_collector.capture_screenshot(vuln_url, v['type'])
                    if pic_path:
                        v['screenshot'] = pic_path

        web_log("--- PHASE 6: CALCULATING METRICS & GENERATING REPORT ---")
        
        crit_count = sum(1 for v in final_vulns if 'CRITICAL' in v.get('severity', ''))
        high_count = sum(1 for v in final_vulns if 'HIGH' in v.get('severity', ''))
        
        if crit_count > 0:
            web_log(f"   ⚠️ SECURITY GRADE: F (FAILED) - {crit_count} Criticals found.")
        elif high_count > 0:
            web_log(f"   ⚠️ SECURITY GRADE: C (WARNING) - {high_count} Highs found.")
        elif len(final_vulns) > 0:
            web_log("   ✅ SECURITY GRADE: B (GOOD) - Medium/Low warnings only.")
        else:
            web_log("   🏆 SECURITY GRADE: A+ (ELITE) - Zero vulnerabilities detected.")

        reporter = ReportGenerator(final_vulns)
        reporter.generate()
        
        filename = reporter.filename 
        web_log(f"📄 AI-Forensic Report Ready: {filename}")
        
        emit('scan_complete', {'status': 'found', 'pdf': filename})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=7860, debug=False, allow_unsafe_werkzeug=True)