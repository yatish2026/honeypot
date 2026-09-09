"""Honeypot Classification & Risk Scoring Engine."""

import os
from pathlib import Path
from typing import Dict, List, Any, Optional
import numpy as np
import joblib

from config import MODELS_DIR, HONEYPOT_RISK_THRESHOLDS
from modules.honeypot_detector.feature_extractor import extract_features_from_scan, FEATURE_NAMES
from modules.honeypot_detector.signatures import match_signatures, evaluate_heuristics


class HoneypotClassifier:
    """Combines Signature Matching, Anomaly Heuristics, and Machine Learning Inference."""
    
    def __init__(self):
        self.model_path = MODELS_DIR / "honeypot_model.joblib"
        self.model_bundle = None
        self._load_model()
        
    def _load_model(self):
        """Attempts to load the trained Random Forest model artifact."""
        if self.model_path.exists():
            try:
                self.model_bundle = joblib.load(self.model_path)
            except Exception as e:
                print(f"[!] Warning: Could not load ML model: {e}")
                self.model_bundle = None
        else:
            self.model_bundle = None

    def classify_target(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates scan results and produces a comprehensive deception verdict.
        """
        if scan_result.get("error"):
            return {
                "target": scan_result.get("target"),
                "ip": scan_result.get("ip"),
                "error": scan_result.get("error"),
                "is_honeypot": False,
                "deception_score": 0.0,
                "risk_level": "UNKNOWN",
                "summary": "Target resolution or scan failed.",
                "signatures_matched": [],
                "anomalies_detected": [],
                "ml_probability": 0.0,
                "reasons": ["Scan failed or host unreachable."]
            }
            
        open_ports = scan_result.get("open_ports", [])
        banners = scan_result.get("banners", {})
        
        # 1. Signature Matching
        sig_matches = match_signatures(banners)
        
        # 2. Heuristic Anomalies
        anomalies = evaluate_heuristics(open_ports, banners)
        
        # 3. Machine Learning Inference
        features = extract_features_from_scan(scan_result)
        
        if self.model_bundle and "model" in self.model_bundle:
            import pandas as pd
            features_df = pd.DataFrame([features], columns=FEATURE_NAMES)
            clf = self.model_bundle["model"]
            ml_prob = float(clf.predict_proba(features_df)[0][1])
        else:
            # Fallback statistical estimate if model not yet trained
            heuristic_weight = sum(a["weight"] for a in anomalies)
            sig_max = max([s["confidence"] for s in sig_matches], default=0.0)
            ml_prob = max(sig_max, min(1.0, heuristic_weight + (0.5 if 2222 in open_ports else 0.0)))
            
        # 4. Ensemble Score Fusion
        # If definitive signature matched (e.g. Cowrie/Dionaea banner), score is heavily weighted to signature confidence
        if sig_matches:
            highest_sig_conf = max(s["confidence"] for s in sig_matches)
            final_score = max(highest_sig_conf, (highest_sig_conf * 0.7 + ml_prob * 0.3))
        else:
            anomaly_sum = sum(a["weight"] for a in anomalies)
            final_score = (ml_prob * 0.75) + min(0.25, anomaly_sum * 0.5)
            
        final_score = round(float(min(1.0, max(0.0, final_score))), 3)
        
        # 5. Risk Level Assignment
        if final_score >= HONEYPOT_RISK_THRESHOLDS["CRITICAL"]:
            risk_level = "CRITICAL"
        elif final_score >= HONEYPOT_RISK_THRESHOLDS["HIGH"]:
            risk_level = "HIGH"
        elif final_score >= HONEYPOT_RISK_THRESHOLDS["MEDIUM"]:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
            
        is_honeypot = (final_score >= 0.50)
        
        # 6. Generate Explainability Reasons
        reasons = []
        for s in sig_matches:
            reasons.append(f"Matched known signature for {s['honeypot_name']} on port {s['matched_port']}.")
        for a in anomalies:
            reasons.append(f"Heuristic Anomaly: {a['description']}.")
        if ml_prob > 0.6 and not sig_matches:
            reasons.append("ML Classifier flagged suspicious behavioral profile (latency, entropy, and legacy port correlation).")
        if not is_honeypot:
            reasons.append("Services and protocol banners exhibit authentic production distributions.")
            
        return {
            "target": scan_result.get("target"),
            "ip": scan_result.get("ip"),
            "is_honeypot": is_honeypot,
            "deception_score": final_score,
            "deception_percentage": round(final_score * 100, 1),
            "risk_level": risk_level,
            "ml_probability": round(ml_prob, 3),
            "signatures_matched": sig_matches,
            "anomalies_detected": anomalies,
            "reasons": reasons,
            "identified_honeypot": sig_matches[0]["honeypot_name"] if sig_matches else ("Suspected Honeypot" if is_honeypot else "Legitimate Production Host"),
            "open_ports": open_ports,
            "banners": banners,
            "port_results": scan_result.get("port_results", [])
        }
