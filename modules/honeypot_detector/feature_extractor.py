"""Feature Extraction Engine for Honeypot Machine Learning Classifier."""

import math
import re
from typing import Dict, List, Any
import numpy as np

# Feature Column Names used by the ML Model
FEATURE_NAMES = [
    "open_port_count",
    "has_port_22",
    "has_port_2222",
    "has_port_21",
    "has_port_23",
    "has_port_80",
    "has_port_443",
    "has_port_502",
    "has_port_1433",
    "has_port_3306",
    "banner_count",
    "avg_banner_length",
    "max_banner_entropy",
    "contains_cowrie_keyword",
    "contains_dionaea_keyword",
    "contains_generic_ssh",
    "contains_conpot_keyword",
    "avg_latency_ms",
    "latency_std_dev",
    "multi_service_legacy_ratio",
]


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of banner text to detect generated/synthetic responses."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def extract_features_from_scan(scan_result: Dict[str, Any]) -> np.ndarray:
    """
    Extracts a 1D numerical feature vector from network scan results.
    """
    open_ports = set(scan_result.get("open_ports", []))
    banners = scan_result.get("banners", {})
    latencies = list(scan_result.get("latencies", {}).values())
    
    banner_texts = [str(b) for b in banners.values() if b]
    combined_banners = " ".join(banner_texts).lower()
    
    # 1. Port presence features
    open_port_count = len(open_ports)
    has_port_22 = 1.0 if 22 in open_ports else 0.0
    has_port_2222 = 1.0 if 2222 in open_ports else 0.0
    has_port_21 = 1.0 if 21 in open_ports else 0.0
    has_port_23 = 1.0 if 23 in open_ports else 0.0
    has_port_80 = 1.0 if 80 in open_ports else 0.0
    has_port_443 = 1.0 if 443 in open_ports else 0.0
    has_port_502 = 1.0 if 502 in open_ports else 0.0
    has_port_1433 = 1.0 if 1433 in open_ports else 0.0
    has_port_3306 = 1.0 if 3306 in open_ports else 0.0
    
    # 2. Banner textual metrics
    banner_count = len(banner_texts)
    avg_banner_length = float(np.mean([len(b) for b in banner_texts])) if banner_texts else 0.0
    entropies = [calculate_entropy(b) for b in banner_texts]
    max_banner_entropy = float(max(entropies)) if entropies else 0.0
    
    # 3. Keyword / Heuristic indicators
    contains_cowrie = 1.0 if ("cowrie" in combined_banners or "twisted" in combined_banners or "openssh_6.0p1" in combined_banners) else 0.0
    contains_dionaea = 1.0 if ("dionaea" in combined_banners or "virtual ftp" in combined_banners or "smb-emulation" in combined_banners) else 0.0
    contains_generic_ssh = 1.0 if (re.search(r"ssh-2\.0-openssh\b", combined_banners) and not re.search(r"ubuntu|debian|centos|arch|alpine", combined_banners)) else 0.0
    contains_conpot = 1.0 if ("conpot" in combined_banners or "s7-200" in combined_banners or "modbus" in combined_banners) else 0.0
    
    # 4. Latency profiling
    avg_latency = float(np.mean(latencies)) if latencies else 50.0
    latency_std = float(np.std(latencies)) if len(latencies) > 1 else 0.0
    
    # 5. Multi-service legacy ratio (honeypots often expose FTP + Telnet + SMB + DB all together)
    legacy_ports = {21, 23, 445, 1433, 3306, 502}
    multi_service_legacy_ratio = len(open_ports.intersection(legacy_ports)) / max(1, open_port_count)
    
    features = [
        open_port_count,
        has_port_22,
        has_port_2222,
        has_port_21,
        has_port_23,
        has_port_80,
        has_port_443,
        has_port_502,
        has_port_1433,
        has_port_3306,
        banner_count,
        avg_banner_length,
        max_banner_entropy,
        contains_cowrie,
        contains_dionaea,
        contains_generic_ssh,
        contains_conpot,
        avg_latency,
        latency_std,
        multi_service_legacy_ratio
    ]
    
    return np.array(features, dtype=np.float32)
