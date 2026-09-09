"""Unit tests for PDF Security Audit Report Generator."""

import unittest
from pathlib import Path
from modules.honeypot_detector.scanner import NetworkScanner
from modules.honeypot_detector.classifier import HoneypotClassifier
from modules.prompt_shield.runner import PromptShieldRunner
from modules.prompt_shield.adapters import MockLLMAdapter
from modules.reporting.pdf_generator import SecurityAuditPDF


class TestPDFGenerator(unittest.TestCase):

    def setUp(self):
        self.scanner = NetworkScanner()
        self.classifier = HoneypotClassifier()
        self.runner = PromptShieldRunner(adapter=MockLLMAdapter())
        self.pdf_gen = SecurityAuditPDF()

    def test_generate_pdf_report(self):
        """Generates full PDF report combining honeypot scan and LLM test results."""
        # 1. Simulate Honeypot Scan
        scan_res = self.scanner.scan_target("sim_cowrie")
        hp_verdict = self.classifier.classify_target(scan_res)
        
        # 2. Simulate LLM Audit
        llm_verdict = self.runner.run_security_assessment(
            base_system_prompt="You are a customer bot. Secret PIN: 1234",
            suites=["injection", "leakage"],
            hardening_strategy="none"
        )
        
        # 3. Generate PDF
        pdf_path = self.pdf_gen.generate_report(
            honeypot_result=hp_verdict,
            llm_result=llm_verdict,
            filename="test_audit_report.pdf"
        )
        
        self.assertTrue(Path(pdf_path).exists())
        self.assertGreater(Path(pdf_path).stat().st_size, 1000)


if __name__ == "__main__":
    unittest.main()
