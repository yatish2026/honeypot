"""PDF Security Audit Report Generator using fpdf2."""

import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from config import REPORTS_DIR
from modules.reporting.metrics import compute_unified_risk_matrix


class SecurityAuditPDF:
    """Generates professional, styled PDF security reports."""

    def __init__(self):
        self.reports_dir = REPORTS_DIR
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        honeypot_result: Optional[Dict[str, Any]],
        llm_result: Optional[Dict[str, Any]],
        filename: Optional[str] = None
    ) -> str:
        """Generates a complete PDF audit report and returns the absolute file path."""
        try:
            from fpdf import FPDF
            from fpdf.enums import XPos, YPos
        except ImportError:
            return self._generate_html_fallback(honeypot_result, llm_result)

        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"Security_Audit_Report_{timestamp}.pdf"
            
        pdf_path = self.reports_dir / filename
        matrix = compute_unified_risk_matrix(honeypot_result, llm_result)
        
        pdf = FPDF(orientation="P", unit="mm", format="A4")
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        
        # --- HEADER BANNER ---
        pdf.set_fill_color(15, 23, 42)  # Dark slate navy
        pdf.rect(0, 0, 210, 38, "F")
        
        pdf.set_font("Helvetica", "B", 18)
        pdf.set_text_color(255, 255, 255)
        pdf.set_xy(15, 10)
        pdf.cell(0, 8, "DECEPTISCAN & LLM SHIELD", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(148, 163, 184)
        pdf.set_xy(15, 20)
        pdf.cell(0, 6, "Unified Network Deception & AI Prompt Security Audit Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        pdf.set_xy(15, 28)
        pdf.cell(0, 5, f"Audit Date: {datetime.now().strftime('%B %d, %Y - %H:%M:%S')} | Target: Automated Audit", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        pdf.ln(15)
        
        # --- SECTION 1: EXECUTIVE SUMMARY ---
        pdf.set_text_color(15, 23, 42)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 7, "1. Executive Risk Summary", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(4)
        
        # Threat Gauge Box
        pdf.set_fill_color(241, 245, 249)
        pdf.set_draw_color(203, 213, 225)
        pdf.rect(15, pdf.get_y(), 180, 24, "FD")
        
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(71, 85, 105)
        pdf.set_xy(20, pdf.get_y() + 4)
        pdf.cell(60, 5, "Composite Threat Index:", new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.cell(60, 5, "Overall Security Posture:", new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.cell(50, 5, "Assessment Status:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        pdf.set_xy(20, pdf.get_y() + 2)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(225, 29, 72)
        pdf.cell(60, 6, f"{matrix['threat_index']} / 100", new_x=XPos.RIGHT, new_y=YPos.TOP)
        
        pdf.set_text_color(15, 23, 42)
        pdf.cell(60, 6, matrix["composite_verdict"], new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_text_color(16, 185, 129)
        pdf.cell(50, 6, "COMPLETED", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        pdf.ln(8)
        
        # --- SECTION 2: MODULE 1 HONEYPOT & OSINT AUDIT ---
        pdf.set_text_color(15, 23, 42)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 7, "2. Network Deception, OSINT & Honeypot Analysis", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(4)
        
        if honeypot_result and not honeypot_result.get("error"):
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(45, 6, "Scanned Target:", new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, f"{honeypot_result.get('target')} ({honeypot_result.get('ip')})", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
            # OSINT Details
            osint = honeypot_result.get("osint", {})
            if osint and osint.get("available"):
                pdf.set_font("Helvetica", "", 10)
                pdf.cell(45, 6, "OSINT Geolocation:", new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(0, 6, f"{osint.get('city', 'Unknown')}, {osint.get('country', 'Unknown')} | ISP: {osint.get('isp', 'Unknown')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                
                pdf.set_font("Helvetica", "", 10)
                pdf.cell(45, 6, "ASN & Reverse DNS:", new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.set_font("Helvetica", "", 10)
                pdf.cell(0, 6, f"{osint.get('asn', 'N/A')} | {osint.get('reverse_dns', 'N/A')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(45, 6, "Deception Score:", new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, f"{honeypot_result.get('deception_percentage')}% ({honeypot_result.get('risk_level')} Risk)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(45, 6, "Identified Entity:", new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, f"{honeypot_result.get('identified_honeypot')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, "Findings & Explainability Breakdown:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", "", 9)
            for r in honeypot_result.get("reasons", []):
                pdf.cell(5, 5, chr(149), new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.multi_cell(175, 5, f" {r}")
                
            pdf.ln(2)
            # Open Ports Table
            ports = honeypot_result.get("open_ports", [])
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 5, f"Open Services Detected: {len(ports)} (Ports: {ports})", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
        else:
            pdf.set_font("Helvetica", "I", 9)
            pdf.cell(0, 6, "No network scan data provided in this audit session.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
        pdf.ln(6)
        
        # --- SECTION 3: MODULE 2 LLM PROMPT AUDIT ---
        pdf.set_text_color(15, 23, 42)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 7, "3. LLM Prompt Vulnerability & Guardrail Audit", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(4)
        
        if llm_result:
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(45, 6, "Hardening Applied:", new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, f"{llm_result.get('hardening_applied')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(45, 6, "Defense Pass Rate:", new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, f"{llm_result.get('defense_rate')}% ({llm_result.get('defended_count')}/{llm_result.get('total_tests')} Tests Defended)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(45, 6, "Vulnerability Rate:", new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, f"{llm_result.get('vulnerability_rate')}% ({llm_result.get('vulnerable_count')} Vulnerabilities)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, "OWASP LLM Vulnerability Scorecard:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
            # Scorecard Table Header
            pdf.set_fill_color(226, 232, 240)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(20, 6, "Test ID", border=1, new_x=XPos.RIGHT, new_y=YPos.TOP, align="C", fill=True)
            pdf.cell(60, 6, "Test Name", border=1, new_x=XPos.RIGHT, new_y=YPos.TOP, align="L", fill=True)
            pdf.cell(45, 6, "Category", border=1, new_x=XPos.RIGHT, new_y=YPos.TOP, align="L", fill=True)
            pdf.cell(25, 6, "Verdict", border=1, new_x=XPos.RIGHT, new_y=YPos.TOP, align="C", fill=True)
            pdf.cell(30, 6, "Severity", border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C", fill=True)
            
            pdf.set_font("Helvetica", "", 8)
            for r in llm_result.get("results", [])[:10]:
                v_color = (225, 29, 72) if r["verdict"] == "VULNERABLE" else (16, 185, 129)
                pdf.cell(20, 5, str(r.get("test_id")), border=1, new_x=XPos.RIGHT, new_y=YPos.TOP, align="C")
                pdf.cell(60, 5, str(r.get("test_name"))[:30], border=1, new_x=XPos.RIGHT, new_y=YPos.TOP, align="L")
                pdf.cell(45, 5, str(r.get("category"))[:25], border=1, new_x=XPos.RIGHT, new_y=YPos.TOP, align="L")
                
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color(*v_color)
                pdf.cell(25, 5, str(r.get("verdict")), border=1, new_x=XPos.RIGHT, new_y=YPos.TOP, align="C")
                
                pdf.set_text_color(15, 23, 42)
                pdf.set_font("Helvetica", "", 8)
                pdf.cell(30, 5, str(r.get("severity")), border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                
        else:
            pdf.set_font("Helvetica", "I", 9)
            pdf.cell(0, 6, "No LLM security audit data provided in this audit session.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
        pdf.ln(6)
        
        # --- SECTION 4: REMEDIATION ROADMAP ---
        pdf.set_text_color(15, 23, 42)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 7, "4. Remediation & Hardening Roadmap", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(4)
        
        pdf.set_font("Helvetica", "", 9)
        remediation_items = [
            "1. Enforce XML Delimiter Encapsulation: Wrap all external untrusted user inputs inside explicit <user_input> tags.",
            "2. Deploy Sandwich Defense: Repeat strict boundary rules before and after user context to overcome LLM recency bias.",
            "3. Cryptographic Canary Tripwires: Place confidential tokens in system prompts and implement output regex guardrails.",
            "4. Continuous Network Fingerprint Auditing: Proactively detect exposed deception traps and anomalous banner configurations."
        ]
        for item in remediation_items:
            pdf.multi_cell(180, 5, item)
            pdf.ln(1)
            
        pdf.output(str(pdf_path))
        return str(pdf_path)

    def _generate_html_fallback(self, honeypot_result: Optional[Dict[str, Any]], llm_result: Optional[Dict[str, Any]]) -> str:
        """Generates styled HTML report as a fallback."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"Security_Audit_Report_{timestamp}.html"
        html_path = self.reports_dir / filename
        matrix = compute_unified_risk_matrix(honeypot_result, llm_result)
        
        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Security Audit Report</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; padding: 30px; }}
.card {{ background: #1e293b; border-radius: 12px; padding: 24px; margin-bottom: 20px; border: 1px solid #334155; }}
h1 {{ color: #38bdf8; margin: 0 0 10px 0; }}
.badge {{ display: inline-block; padding: 4px 12px; border-radius: 6px; font-weight: bold; background: {matrix['badge_color']}; color: white; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
th, td {{ border: 1px solid #334155; padding: 8px 12px; text-align: left; }}
th {{ background: #334155; }}
</style>
</head>
<body>
<div class="card">
<h1>DeceptiScan & LLM Shield Audit Report</h1>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p>Composite Threat Index: <strong>{matrix['threat_index']} / 100</strong> | <span class="badge">{matrix['composite_verdict']}</span></p>
</div>
</body>
</html>"""
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        return str(html_path)
