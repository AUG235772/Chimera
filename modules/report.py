import os
from fpdf import FPDF
from datetime import datetime

class ReportGenerator:
    def __init__(self, vulns):
        self.vulns = vulns
        self.filename = "Chimera_Scan_Report.pdf"

    def get_severity_color(self, severity):
        """Returns RGB color codes based on threat severity."""
        sev = severity.upper()
        if "CRITICAL" in sev: return (220, 38, 38)   # Deep Red
        if "HIGH" in sev: return (234, 88, 12)      # Orange
        if "MEDIUM" in sev: return (202, 138, 4)    # Yellow/Gold
        return (37, 99, 235)                        # Blue

    def sanitize_text(self, text):
        """
        Sanitizes text to be compatible with FPDF's latin-1 encoding.
        Replaces common problematic characters and strips unencodable ones.
        """
        if not text:
            return "N/A"
        
        # Replace common Unicode characters with ASCII equivalents
        replacements = {
            '\u2013': '-',   # En dash
            '\u2014': '-',   # Em dash
            '\u2018': "'",   # Left single quote
            '\u2019': "'",   # Right single quote
            '\u201c': '"',   # Left double quote
            '\u201d': '"',   # Right double quote
            '\u2022': '-',   # Bullet point
            '\u2026': '...', # Ellipsis
        }
        
        text = str(text)
        for char, replacement in replacements.items():
            text = text.replace(char, replacement)
            
        # Final safety net: encode to latin-1, replacing errors with '?'
        return text.encode('latin-1', 'replace').decode('latin-1')

    def generate(self):
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        
        # ==========================================
        # 🎨 STYLED HEADER (Black Background)
        # ==========================================
        pdf.set_fill_color(10, 15, 10) 
        pdf.rect(0, 0, 210, 40, 'F') 
        
        pdf.set_y(15)
        pdf.set_font("Courier", 'B', 24)
        pdf.set_text_color(0, 255, 65) # Neon Green
        pdf.cell(0, 10, txt=">> CHIMERA: FORENSIC AUDIT", ln=True, align='C')
        
        pdf.set_font("Courier", '', 10)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 10, txt=f"REPORT GENERATED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC", ln=True, align='C')
        
        pdf.set_y(50) 
        
        # ==========================================
        # 📊 EXECUTIVE SUMMARY
        # ==========================================
        pdf.set_font("Helvetica", 'B', 16)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, txt="1.0 EXECUTIVE SUMMARY", ln=True)
        
        # Green Underline
        pdf.set_line_width(0.5)
        pdf.set_draw_color(0, 255, 65)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y()) 
        pdf.ln(5)
        
        pdf.set_font("Helvetica", '', 11)
        pdf.set_text_color(50, 50, 50)
        
        crit_count = sum(1 for v in self.vulns if 'CRITICAL' in v.get('severity', '').upper())
        high_count = sum(1 for v in self.vulns if 'HIGH' in v.get('severity', '').upper())
        med_count = sum(1 for v in self.vulns if 'MEDIUM' in v.get('severity', '').upper())
        
        summary_text = (
            f"The Chimera Engine has completed a deep forensic security audit of the target application. "
            f"During the automated scan, a total of {len(self.vulns)} security threats were identified.\n\n"
            f"THREAT BREAKDOWN:\n"
            f"- CRITICAL RISKS: {crit_count}\n"
            f"- HIGH RISKS: {high_count}\n"
            f"- MEDIUM/LOW RISKS: {med_count}\n\n"
            f"Immediate remediation is strictly advised for all Critical and High severity findings to prevent "
            f"unauthorized system compromise, data exfiltration, or denial of service."
        )
        # Apply sanitization to summary text
        pdf.multi_cell(0, 6, txt=self.sanitize_text(summary_text))
        pdf.ln(10)
        
        # ==========================================
        # 🕵️‍♂️ DETAILED THREAT ANALYSIS
        # ==========================================
        pdf.set_font("Helvetica", 'B', 16)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, txt="2.0 DETAILED THREAT ANALYSIS", ln=True)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y()) 
        pdf.ln(8)
        
        for i, vuln in enumerate(self.vulns):
            # Sanitize inputs to prevent FPDF Latin-1 crashes
            v_type = self.sanitize_text(vuln.get('type', 'Unknown'))
            severity = self.sanitize_text(vuln.get('severity', 'HIGH')).upper()
            url = self.sanitize_text(vuln.get('url', 'N/A'))
            impact = self.sanitize_text(vuln.get('impact', 'Potential compromise.'))
            remediation = self.sanitize_text(vuln.get('remediation', 'Manual audit required.'))
            evidence = self.sanitize_text(vuln.get('payload', 'N/A'))
            risk_score = vuln.get('risk_score', 'N/A')

            # 1. Colored Title Box based on Threat Level
            r, g, b = self.get_severity_color(severity)
            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(255, 255, 255) # White text inside box
            pdf.set_font("Helvetica", 'B', 12)
            pdf.cell(0, 10, txt=f" FINDING #{i+1}: {v_type} [{severity}]", ln=True, fill=True)
            
            # 2. Target Info
            pdf.ln(2)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", 'B', 10)
            pdf.cell(30, 6, txt="TARGET:")
            pdf.set_font("Courier", '', 10)
            pdf.set_text_color(37, 99, 235) # Blue link style
            pdf.multi_cell(0, 6, txt=url)
            
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", 'B', 10)
            pdf.cell(30, 6, txt="RISK SCORE:")
            pdf.set_font("Helvetica", '', 10)
            pdf.cell(0, 6, txt=f"{risk_score} / 10", ln=True)
            
            # 3. Code / Evidence Box (Light Gray Background)
            pdf.ln(2)
            pdf.set_font("Helvetica", 'B', 10)
            pdf.cell(0, 6, txt="EVIDENCE / VULNERABLE CODE:", ln=True)
            pdf.set_fill_color(245, 245, 245) 
            pdf.set_font("Courier", '', 9)
            pdf.multi_cell(0, 5, txt=f"{evidence}", fill=True)
            
            # 4. Impact Analysis (Red Highlight)
            pdf.ln(4)
            pdf.set_font("Helvetica", 'B', 10)
            pdf.set_text_color(220, 38, 38) 
            pdf.cell(0, 6, txt=">> AI IMPACT ANALYSIS:", ln=True)
            pdf.set_text_color(40, 40, 40)
            pdf.set_font("Helvetica", '', 10)
            pdf.multi_cell(0, 5, txt=impact)
            
            # 5. Remediation (Green Highlight)
            pdf.ln(2)
            pdf.set_font("Helvetica", 'B', 10)
            pdf.set_text_color(22, 163, 74) 
            pdf.cell(0, 6, txt=">> AI SYSTEM REMEDIATION:", ln=True)
            pdf.set_text_color(40, 40, 40)
            pdf.set_font("Helvetica", '', 10)
            pdf.multi_cell(0, 5, txt=remediation)
            
            # ==========================================
            # 📸 NEW: FORENSIC SCREENSHOT RENDERER
            # ==========================================
            screenshot_path = vuln.get('screenshot')
            if screenshot_path and os.path.exists(screenshot_path):
                pdf.ln(4)
                pdf.set_font("Helvetica", 'B', 10)
                pdf.set_text_color(0, 0, 0)
                pdf.cell(0, 6, txt=">> FORENSIC EVIDENCE (SCREENSHOT):", ln=True)
                try:
                    # x=20 adds an indent, w=170 ensures it fits on A4 paper perfectly
                    pdf.image(screenshot_path, x=20, w=170) 
                    pdf.ln(5)
                except Exception:
                    pdf.set_text_color(220, 38, 38)
                    pdf.cell(0, 6, txt="[Error rendering screenshot]", ln=True)
            
            pdf.ln(8) # Spacing before next finding
                
        pdf.output(self.filename)