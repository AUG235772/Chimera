# modules/evidence.py
import os
import time
import platform
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium_stealth import stealth
from urllib.parse import urlparse
from utils import logger

class EvidenceCollector:
    def __init__(self, auth_header=None, logger_callback=None):
        self.log = logger_callback if logger_callback else logger.info
        self.evidence_dir = os.path.join(os.getcwd(), 'evidence')
        self.auth_header = auth_header # NEW: The keys to the castle
        
        if not os.path.exists(self.evidence_dir):
            os.makedirs(self.evidence_dir)

    def capture_screenshot(self, url, finding_name="Target"):
        self.log(f"📸 [EVIDENCE] Deploying stealth camera to: {url}")
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--window-size=1920,1080")
            chrome_options.add_argument("--ignore-certificate-errors")
            chrome_options.add_argument("--disable-blink-features=AutomationControlled")
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            # SMART DRIVER SELECTOR
            if platform.system() == 'Linux' and os.path.exists('/usr/bin/chromium'):
                chrome_options.binary_location = '/usr/bin/chromium'
                service = Service('/usr/bin/chromedriver')
                driver = webdriver.Chrome(service=service, options=chrome_options)
            else:
                service = Service(ChromeDriverManager().install())
                driver = webdriver.Chrome(service=service, options=chrome_options)

            # 🔴 THE GHOST PROTOCOL: Spoofing a real human fingerprint to bypass Vercel/Cloudflare
            stealth(driver,
                languages=["en-US", "en"],
                vendor="Google Inc.",
                platform="Win32",
                webgl_vendor="Intel Inc.",
                renderer="Intel Iris OpenGL Engine",
                fix_hairline=True,
            )
            
            # 🔴 THE AUTHENTICATION INJECTOR: Bypassing the Login Page
            if self.auth_header:
                self.log("🔑 [EVIDENCE] Injecting authentication credentials...")
                # To set a cookie, we must first visit the domain
                domain = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                driver.get(domain)
                time.sleep(2)
                
                # Assume auth_header is passed as a standard cookie string (e.g., "session_id=12345")
                try:
                    cookie_name, cookie_value = self.auth_header.split('=', 1)
                    driver.add_cookie({"name": cookie_name.strip(), "value": cookie_value.strip()})
                except Exception:
                    self.log("⚠️ [EVIDENCE] Auth token format not recognized for cookie injection. Attempting access anyway.")
            
            # Navigate to the actual vulnerable endpoint
            driver.get(url)
            
            # Wait 6 seconds for WAF challenges to pass and React/Vue apps to load
            time.sleep(6) 
            
            safe_name = "".join(x for x in finding_name if x.isalnum() or x in " _-").strip().replace(' ', '_')
            filename = f"proof_{safe_name}_{int(time.time())}.png"
            filepath = os.path.join(self.evidence_dir, filename)
            
            driver.save_screenshot(filepath)
            driver.quit()
            
            self.log(f"✅ [EVIDENCE] Stealth proof acquired: {filename}")
            return filepath
            
        except Exception as e:
            self.log(f"⚠️ [EVIDENCE] Camera malfunction: {str(e)}")
            return None