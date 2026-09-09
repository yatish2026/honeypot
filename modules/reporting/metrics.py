"""Security Metrics, Risk Calculation, and Audit Data Serialization."""

import json
from datetime import datetime
from typing import Dict, Any, Optional


def compute_unified_risk_matrix(honeypot_result: Optional[Dict[str, Any]], llm_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes unified cybersecurity risk posture across Network Deception & AI Security domains.
    """
    hp_score = honeypot_result.get("deception_score", 0.0) if honeypot_result else 0.0
    hp_level = honeypot_result.get("risk_level", "N/A") if honeypot_result else "N/A"
    
    llm_vuln_rate = llm_result.get("vulnerability_rate", 0.0) if llm_result else 0.0
    llm_level = llm_result.get("overall_risk", "N/A") if llm_result else "N/A"
    
    # Combined Threat Index (0 - 100)
    scores = []
    if honeypot_result and not honeypot_result.get("error"):
        scores.append(hp_score * 100.0)
    if llm_result:
        scores.append(llm_vuln_rate)
        
    avg_threat_index = round(float(sum(scores) / len(scores)), 1) if scores else 0.0
    
    if avg_threat_index >= 70:
        composite_verdict = "CRITICAL RISK"
        badge_color = "#ef4444"
    elif avg_threat_index >= 40:
        composite_verdict = "ELEVATED RISK"
        badge_color = "#f59e0b"
    elif avg_threat_index > 15:
        composite_verdict = "MODERATE RISK"
        badge_color = "#3b82f6"
    else:
        composite_verdict = "SECURE / LOW RISK"
        badge_color = "#10b981"
        
    return {
        "timestamp": datetime.now().isoformat(),
        "threat_index": avg_threat_index,
        "composite_verdict": composite_verdict,
        "badge_color": badge_color,
        "honeypot_module": {
            "score": hp_score,
            "risk_level": hp_level,
            "target": honeypot_result.get("target") if honeypot_result else None,
            "identified": honeypot_result.get("identified_honeypot") if honeypot_result else None
        },
        "llm_module": {
            "vulnerability_rate": llm_vuln_rate,
            "overall_risk": llm_level,
            "defended_count": llm_result.get("defended_count", 0) if llm_result else 0,
            "vulnerable_count": llm_result.get("vulnerable_count", 0) if llm_result else 0,
            "total_tests": llm_result.get("total_tests", 0) if llm_result else 0
        }
    }


def export_audit_json(honeypot_result: Optional[Dict[str, Any]], llm_result: Optional[Dict[str, Any]]) -> str:
    """Serializes complete audit session data to JSON string."""
    matrix = compute_unified_risk_matrix(honeypot_result, llm_result)
    bundle = {
        "platform": "DeceptiScan & LLM Shield (HoneyPrompt)",
        "version": "2.0",
        "audit_meta": matrix,
        "honeypot_scan_details": honeypot_result,
        "llm_vulnerability_details": llm_result
    }
    return json.dumps(bundle, indent=2)
