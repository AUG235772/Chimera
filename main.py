from flask import Flask
from flask_socketio import SocketIO
import argparse
from utils import logger
from modules.recon import ReconEngine
from modules.scanner import ScannerEngine
from modules.analyst import AnalystEngine
from modules.report import ReportGenerator

app = Flask(__name__)
socketio = SocketIO(app)
def banner():
    print(r"""
      CHIMERA V1.0
      [ Automated Vulnerability & Logic Scanner ]
      [ GitHub Ready | Smart Context-Aware ]
    """)

def main():
    banner()
    parser = argparse.ArgumentParser(description="Chimera Web Scanner")
    parser.add_argument("-u", "--url", help="Target URL", required=True)
    args = parser.parse_args()

    target = args.url

    # --- PHASE 1: RECON ---
    logger.info("--- PHASE 1: RECONNAISSANCE ---")
    recon = ReconEngine(target)
    endpoints = recon.start()
    
    if not endpoints:
        logger.error("No endpoints found. Exiting.")
        return

    # --- PHASE 2: ATTACK ---
    logger.info("\n--- PHASE 2: VULNERABILITY SCANNING ---")
    scanner = ScannerEngine()
    raw_vulnerabilities = scanner.start(endpoints)

    if not raw_vulnerabilities:
        logger.success("No vulnerabilities found.")
        return

    # --- PHASE 3: ANALYSIS (The Brain) ---
    logger.info("\n--- PHASE 3: INTELLIGENT ANALYSIS ---")
    analyst = AnalystEngine(raw_vulnerabilities)
    final_vulnerabilities = analyst.start()

    # --- PHASE 4: REPORTING ---
    logger.info("\n--- PHASE 4: REPORT GENERATION ---")
    reporter = ReportGenerator(final_vulnerabilities)
    reporter.generate()

if __name__ == '__main__':
    # Setting use_reloader=False prevents the context crash on startup
    socketio.run(app, debug=True, use_reloader=False)