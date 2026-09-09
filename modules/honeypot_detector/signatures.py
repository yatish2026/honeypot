"""Known Honeypot Signatures, Fingerprints, and Behavioral Heuristics."""

import re
from typing import Dict, List, Any

# Signature database for known honeypot software
HONEYPOT_SIGNATURES: List[Dict[str, Any]] = [
    {
        "name": "Cowrie SSH/Telnet Honeypot",
        "type": "Medium/High Interaction SSH & Telnet Deception",
        "confidence": 0.95,
        "patterns": [
            r"SSH-2\.0-Cowrie",
            r"SSH-2\.0-OpenSSH_6\.0p1\s+Debian-4",
            r"SSH-2\.0-OpenSSH_7\.9p1\s+Raspbian",
            r"twisted\.conch",
            r"cowrie",
        ],
        "default_ports": [22, 2222, 23, 2223],
        "indicators": [
            "Default Cowrie SSH banner strings",
            "Python Twisted Conch cryptographic engine fingerprint",
            "Standard simulated Ubuntu/Debian environment signatures"
        ]
    },
    {
        "name": "Kippo SSH Honeypot",
        "type": "Medium Interaction SSH Deception",
        "confidence": 0.92,
        "patterns": [
            r"SSH-2\.0-OpenSSH_5\.1p1\s+Debian-5",
            r"SSH-2\.0-OpenSSH_5\.5p1",
            r"kippo",
        ],
        "default_ports": [22, 2222],
        "indicators": [
            "Legacy OpenSSH 5.1/5.5 default Debian banners",
            "Fixed filesystem layout (fs.pickle artifact)"
        ]
    },
    {
        "name": "Dionaea Malware Capture Honeypot",
        "type": "Low/Medium Interaction Protocol Honeypot (SMB/FTP/MSSQL/SIP)",
        "confidence": 0.90,
        "patterns": [
            r"dionaea",
            r"220\s+FTP\s+server\s+ready",
            r"220\s+Welcome\s+to\s+virtual\s+FTP",
            r"smb\s+emulation\s+dionaea",
            r"DIONAEA",
        ],
        "default_ports": [21, 445, 1433, 3306, 5060, 69],
        "indicators": [
            "Generic simulated FTP greeting banner without vendor tokens",
            "Known Dionaea SMB fingerprint and memory capture buffer patterns",
            "High port density with lightweight emulated protocol daemons"
        ]
    },
    {
        "name": "Conpot ICS/SCADA Honeypot",
        "type": "Industrial Control System Honeypot (Modbus/S7/BACnet)",
        "confidence": 0.96,
        "patterns": [
            r"Siemens\s+S7-200",
            r"conpot",
            r"Modicon",
            r"Schneider\s+Electric",
        ],
        "default_ports": [102, 502, 47808, 161],
        "indicators": [
            "Simulated Siemens SIMATIC S7 PLC protocol responder",
            "Default Conpot Modbus slave ID and coil memory configuration",
            "Exposed industrial protocol on public cloud IP ranges"
        ]
    },
    {
        "name": "Glastopf / SNARE Web Honeypot",
        "type": "Web Application Vulnerability Honeypot",
        "confidence": 0.88,
        "patterns": [
            r"Server:\s*Glastopf",
            r"Server:\s*Python/.*SimpleHTTP",
            r"X-Powered-By:\s*Glastopf",
            r"snare-tanner",
        ],
        "default_ports": [80, 8080, 443, 8000],
        "indicators": [
            "Simulated vulnerable PHP/SQL web endpoints (e.g. blog, rfi, admin.php)",
            "Python SimpleHTTP / Glastopf server header response",
            "Accepts any SQL injection query without DB error or state change"
        ]
    },
    {
        "name": "HoneyPy Generic Protocol Honeypot",
        "type": "Low Interaction Multi-Service Honeypot",
        "confidence": 0.85,
        "patterns": [
            r"honeypy",
            r"HoneyPy",
            r"echo\s+service\s+simulated"
        ],
        "default_ports": [21, 22, 23, 80, 443, 10000],
        "indicators": [
            "HoneyPy default echo and response profiles",
            "Simulated Telnet / Echo daemon with immediate echo back"
        ]
    }
]

# Heuristic anomaly rules
ANOMALY_RULES: List[Dict[str, Any]] = [
    {
        "id": "ANOM_PORT_2222_SSH",
        "description": "SSH service exposed on port 2222 (standard honeypot redirect port)",
        "weight": 0.35,
        "check": lambda ports, banners: 2222 in ports and any("SSH" in str(b) for b in banners.values())
    },
    {
        "id": "ANOM_MANY_SIMULATED_PORTS",
        "description": "Multiple unrelated legacy services open simultaneously (FTP, Telnet, SMB, SQL) on cloud host",
        "weight": 0.40,
        "check": lambda ports, banners: len(set(ports).intersection({21, 23, 445, 1433, 3306, 502})) >= 3
    },
    {
        "id": "ANOM_SUSPICIOUS_GENERIC_BANNER",
        "description": "Overly generic banner without distribution or version patches",
        "weight": 0.25,
        "check": lambda ports, banners: any(
            banner.strip() in ["SSH-2.0-OpenSSH", "220 (vsFTPd 2.0.8)", "220 Welcome to virtual FTP"]
            for banner in banners.values()
        )
    },
    {
        "id": "ANOM_UNUSUAL_LATENCY_PROFILE",
        "description": "Suspiciously flat/synthetic response latency (<2ms across all ports or fixed delay)",
        "weight": 0.20,
        "check": lambda ports, banners: False  # Evaluated dynamically in scanner
    }
]


def match_signatures(banners: Dict[int, str]) -> List[Dict[str, Any]]:
    """
    Matches grabbed banners against known honeypot signatures.
    Returns list of matched signature detections.
    """
    matches = []
    
    for port, banner in banners.items():
        if not banner:
            continue
            
        for sig in HONEYPOT_SIGNATURES:
            for pattern in sig["patterns"]:
                if re.search(pattern, banner, re.IGNORECASE):
                    matches.append({
                        "honeypot_name": sig["name"],
                        "type": sig["type"],
                        "confidence": sig["confidence"],
                        "matched_port": port,
                        "matched_pattern": pattern,
                        "raw_banner": banner.strip(),
                        "indicators": sig["indicators"]
                    })
                    break
    
    return matches


def evaluate_heuristics(open_ports: List[int], banners: Dict[int, str]) -> List[Dict[str, Any]]:
    """
    Evaluates behavioral heuristics and anomaly rules.
    Returns list of triggered anomalies and cumulative anomaly score.
    """
    triggered = []
    
    for rule in ANOMALY_RULES:
        try:
            if rule["check"](open_ports, banners):
                triggered.append({
                    "rule_id": rule["id"],
                    "description": rule["description"],
                    "weight": rule["weight"]
                })
        except Exception:
            continue
            
    return triggered
