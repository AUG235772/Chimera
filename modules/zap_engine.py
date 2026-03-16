import time
from zapv2 import ZAPv2

class ZapScanner:
    def __init__(self, target_url, api_key='', auth_header='', logger_callback=None):
        self.target = target_url
        self.auth_header = auth_header
        self.zap = ZAPv2(apikey=api_key, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
        self.log = logger_callback if logger_callback else print

    def setup_auth(self):
        if not self.auth_header: return
        self.log("🔑 [AUTH] Configuring ZAP to bypass login walls...")
        if "Cookie:" in self.auth_header or "=" in self.auth_header and "Bearer" not in self.auth_header:
            header_name = "Cookie"
            header_value = self.auth_header.replace("Cookie:", "").strip()
        else:
            header_name = "Authorization"
            header_value = self.auth_header.replace("Authorization:", "").strip()
        try:
            self.zap.replacer.remove_rule(description="ChimeraAuth")
        except: pass
        try:
            self.zap.replacer.add_rule(description="ChimeraAuth", enabled=True, matchtype="REQ_HEADER", matchregex=False, matchstring=header_name, replacement=header_value)
            self.log(f"🔓 [AUTH] Success! Injected '{header_name}' for deep-scanning.")
        except Exception as e:
            self.log(f"⚠️ [AUTH] Failed to set auth rule: {str(e)}")

    def start_scan(self):
        self.log("🧹 Clearing previous ZAP session...")
        self.zap.core.new_session(name='ChimeraSession', overwrite=True)
        self.setup_auth()

        self.log(f"🕷️ Spidering: {self.target}...")
        scan_id = self.zap.spider.scan(self.target)
        while int(self.zap.spider.status(scan_id)) < 100:
            self.log(f"   └── Spider Progress: {self.zap.spider.status(scan_id)}%")
            time.sleep(2)

        self.log(f"🚀 Active Attack: {self.target}...")
        ascan_id = self.zap.ascan.scan(self.target)
        while int(self.zap.ascan.status(ascan_id)) < 100:
            self.log(f"   └── Attack Progress: {self.zap.ascan.status(ascan_id)}%")
            time.sleep(5)

        self.log("📊 Extracting alerts in batches...")
        all_alerts = []
        start = 0
        count = 10 

        while True:
            batch = self.zap.core.alerts(baseurl=self.target, start=start, count=count)
            if not batch: break
            
            batch_crit_count = 0 # Track criticals in this specific batch

            for alert in batch:
                risk = alert.get('risk')
                severity = "LOW"
                if risk == "High": 
                    severity = "CRITICAL"
                    batch_crit_count += 1
                elif risk == "Medium": 
                    severity = "HIGH"
                    batch_crit_count += 1 # Treating Medium as High-priority for counter
                elif risk == "Low": severity = "MEDIUM"

                all_alerts.append({
                    "type": alert.get('name'),
                    "url": alert.get('url'),
                    "severity": severity,
                    "description": alert.get('description'),
                    "payload": alert.get('evidence') or alert.get('param') or alert.get('other') or 'N/A',
                    "solution": alert.get('solution', 'N/A')
                })
            
            # THE FIX: Emit telemetry signal for the frontend to catch
            if batch_crit_count > 0:
                self.log(f"   └── [TELEMETRY] Identified {batch_crit_count} CRITICAL/HIGH risks in this batch.")

            start += count
            self.log(f"   └── Downloaded {len(all_alerts)} alerts...")

        return all_alerts