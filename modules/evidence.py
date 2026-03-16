# modules/evidence.py
import os
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from utils import logger

class EvidenceCollector:
    def __init__(self, logger_callback=None):
        self.log = logger_callback if logger_callback else logger.info
        self.evidence_dir = os.path.join(os.getcwd(), 'evidence')
        
        # Create evidence folder if it doesn't exist
        if not os.path.exists(self.evidence_dir):
            os.makedirs(self.evidence_dir)

    def capture_screenshot(self, url, finding_name="Target"):
        self.log(f"📸 [EVIDENCE] Snapping proof-of-concept photo for: {url}")
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--window-size=1920,1080")
            chrome_options.add_argument("--ignore-certificate-errors")
            
            # 🔴 SMART DRIVER SELECTOR
            # If running on Hugging Face (Linux) with system Chromium installed
            if platform.system() == 'Linux' and os.path.exists('/usr/bin/chromedriver'):
                chrome_options.binary_location = '/usr/bin/chromium'
                service = Service('/usr/bin/chromedriver')
                driver = webdriver.Chrome(service=service, options=chrome_options)
            else:
                # If running locally on Windows/Mac
                service = Service(ChromeDriverManager().install())
                driver = webdriver.Chrome(service=service, options=chrome_options)
            
            driver.get(url)
            time.sleep(3) # Wait for page to render
            
            safe_name = "".join(x for x in finding_name if x.isalnum() or x in " _-").strip().replace(' ', '_')
            filename = f"proof_{safe_name}_{int(time.time())}.png"
            filepath = os.path.join(self.evidence_dir, filename)
            
            driver.save_screenshot(filepath)
            driver.quit()
            
            self.log(f"✅ [EVIDENCE] Proof acquired: {filename}")
            return filepath
            
        except Exception as e:
            self.log(f"⚠️ [EVIDENCE] Camera malfunction: {str(e)}")
            return None

    def format_http_traffic(self, req_header, req_body, res_header, res_body):
        """Formats raw HTTP traffic to look like Burp Suite repeater output for the PDF report"""
        evidence = "=== RAW HTTP REQUEST ===\n"
        evidence += f"{req_header}\n\n{req_body if req_body else ''}\n\n"
        evidence += "=== RAW HTTP RESPONSE ===\n"
        # Truncate response body so it doesn't flood the PDF with 100 pages of HTML
        safe_res_body = (res_body[:1000] + '\n...[TRUNCATED]') if len(res_body) > 1000 else res_body
        evidence += f"{res_header}\n\n{safe_res_body}"
        return evidence