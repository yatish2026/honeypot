"""Unit tests for Network Scanner & Honeypot Classifier."""

import unittest
from modules.honeypot_detector.scanner import NetworkScanner
from modules.honeypot_detector.classifier import HoneypotClassifier
from modules.honeypot_detector.signatures import match_signatures, evaluate_heuristics


class TestHoneypotDetector(unittest.TestCase):

    def setUp(self):
        self.scanner = NetworkScanner()
        self.classifier = HoneypotClassifier()

    def test_cowrie_simulation_detection(self):
        """Verify that simulated Cowrie honeypot is correctly flagged as Honeypot."""
        scan_res = self.scanner.scan_target("sim_cowrie")
        self.assertTrue(scan_res["is_simulated"])
        self.assertIn(2222, scan_res["open_ports"])
        
        verdict = self.classifier.classify_target(scan_res)
        self.assertTrue(verdict["is_honeypot"])
        self.assertGreaterEqual(verdict["deception_score"], 0.70)
        self.assertIn("Cowrie", verdict["identified_honeypot"])

    def test_production_web_detection(self):
        """Verify that simulated production web server is classified as authentic."""
        scan_res = self.scanner.scan_target("sim_prod_web")
        self.assertTrue(scan_res["is_simulated"])
        
        verdict = self.classifier.classify_target(scan_res)
        self.assertFalse(verdict["is_honeypot"])
        self.assertLessEqual(verdict["deception_score"], 0.40)
        self.assertEqual(verdict["risk_level"], "LOW")

    def test_dionaea_simulation_detection(self):
        """Verify that Dionaea malware trap is flagged."""
        scan_res = self.scanner.scan_target("sim_dionaea")
        verdict = self.classifier.classify_target(scan_res)
        self.assertTrue(verdict["is_honeypot"])
        self.assertIn("Dionaea", verdict["identified_honeypot"])


if __name__ == "__main__":
    unittest.main()
