from groq import Groq
import json
import time
import re

class AIEngine:
    def __init__(self, api_key):
        self.client = Groq(api_key=api_key)
        self.model_id = 'llama-3.3-70b-versatile' 

    def enrich_findings(self, vulns, log_callback):
        log_callback("🧠 AI THINKING: Analyzing threat landscape via Groq LPUs...")
        
        grouped_vulns = {}
        for v in vulns:
            v_type = v['type']
            if v_type not in grouped_vulns:
                grouped_vulns[v_type] = v

        enriched_library = {}
        
        for v_type, v_data in grouped_vulns.items():
            prompt = f"""
            Analyze this vulnerability: {v_type}
            Provide:
            1. Impact: Real-world exploitation scenario.
            2. Remediation: Technical fix.
            Output JSON format: {{"impact": "...", "remediation": "..."}}
            """
            try:
                response = self.client.chat.completions.create(
                    model=self.model_id,
                    messages=[
                        {"role": "system", "content": "You are a cyber security auditor. Always output valid JSON."},
                        {"role": "user", "content": prompt}
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.2
                )
                
                clean_json = response.choices[0].message.content
                enriched_library[v_type] = json.loads(clean_json)
                time.sleep(0.5) 
            except Exception:
                enriched_library[v_type] = {
                    "impact": "Potential security compromise.",
                    "remediation": "Review OWASP guidelines."
                }

        for v in vulns:
            if v['type'] in enriched_library:
                v['impact'] = enriched_library[v['type']]['impact']
                v['remediation'] = enriched_library[v['type']]['remediation']
        
        return vulns

    def audit_code(self, file_path, code_content, log_callback):
        if len(code_content) > 20000:
            code_content = code_content[:20000] + "\n...[TRUNCATED]..."

        # THE FIX: Strongly enforcing custom Impact and Remediation in the JSON schema
        prompt = f"""
        Review this file for SECURITY VULNERABILITIES (Secrets, SQLi, XSS, RCE, Auth Bypass, IDOR, Insecure Config).
        File: {file_path}
        Code:
        {code_content}
        
        Task:
        1. Ignore best practices. Focus ONLY on severe vulnerabilities.
        2. If Clean: Return "vulnerable": false.
        3. If Vulnerable: Return "vulnerable": true and detailed findings.
        
        Output JSON format exactly like this:
        {{
            "vulnerable": true,
            "findings": [
                {{
                    "type": "Vulnerability Name (e.g., IDOR, SQLi)",
                    "severity": "CRITICAL, HIGH, or MEDIUM",
                    "line": "Exact line of code that is vulnerable",
                    "impact": "Explain EXACTLY how a hacker exploits this specific line of code and the real-world damage.",
                    "remediation": "Provide the EXACT corrected code snippet to fix this."
                }}
            ],
            "message": "Brief summary"
        }}
        """
        
        try:
            response = self.client.chat.completions.create(
                model=self.model_id,
                messages=[
                    {"role": "system", "content": "You are a strict Source Code Security Auditor. Always output valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.1 
            )
            
            clean_json = response.choices[0].message.content
            return json.loads(clean_json)

        except Exception as e:
            error_msg = str(e)
            if "Rate limit" in error_msg or "429" in error_msg:
                return {"vulnerable": False, "findings": [], "message": "⚠️ API Quota Limit Exceeded."}
            return {"vulnerable": False, "findings": [], "message": f"AI Error: {error_msg[:60]}..."}