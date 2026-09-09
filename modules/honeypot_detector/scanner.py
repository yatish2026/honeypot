"""Network Scanner & Banner Grabbing Engine for Honeypot Identification."""

import socket
import ssl
import time
import re
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import COMMON_PORTS


# Preset simulation profiles for safe offline / college demonstration testing
SIMULATION_PROFILES: Dict[str, Dict[str, Any]] = {
    "sim_cowrie": {
        "name": "Cowrie Deception Honeypot (Simulation)",
        "ip": "192.168.1.150",
        "open_ports": [22, 2222, 23],
        "banners": {
            22: "SSH-2.0-Cowrie linux-x86_64",
            2222: "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
            23: "Linux 3.2.0-4-amd64 (debian) (pts/0)\nlogin: "
        },
        "latencies": {22: 4.2, 2222: 3.8, 23: 5.1},
        "http_headers": {},
        "target_type": "honeypot"
    },
    "sim_dionaea": {
        "name": "Dionaea Malware Capture Trap (Simulation)",
        "ip": "10.0.0.88",
        "open_ports": [21, 445, 1433, 3306, 5060],
        "banners": {
            21: "220 Welcome to virtual FTP service ready - Dionaea capture node",
            445: "SMB-Emulation-v1.0 (Dionaea core honeypot daemon)",
            1433: "Microsoft SQL Server 2012 - 11.00.2100.60 (X64) Service Pack 1",
            3306: "5.5.40-0ubuntu0.14.04.1-log MySQL honeyd responder"
        },
        "latencies": {21: 1.2, 445: 1.5, 1433: 1.1, 3306: 1.3},
        "http_headers": {},
        "target_type": "honeypot"
    },
    "sim_conpot": {
        "name": "Conpot Industrial ICS/SCADA Trap (Simulation)",
        "ip": "172.16.4.20",
        "open_ports": [102, 502, 161],
        "banners": {
            102: "Siemens S7-200 SIMATIC S7 PLC Emulated Responder conpot-v0.5",
            502: "Modbus TCP Slave ID: 1, Unit: Schneider Electric Conpot Node",
            161: "SNMPv2-MIB::sysDescr.0 = STRING: Siemens SIMATIC S7"
        },
        "latencies": {102: 8.5, 502: 9.1, 161: 7.9},
        "http_headers": {},
        "target_type": "honeypot"
    },
    "sim_prod_web": {
        "name": "Production Nginx/FastAPI Cloud Server (Simulation)",
        "ip": "104.21.55.12",
        "open_ports": [80, 443],
        "banners": {
            80: "HTTP/1.1 301 Moved Permanently\nServer: cloudflare\nLocation: https://example.com/",
            443: "HTTP/1.1 200 OK\nServer: nginx/1.24.0 (Ubuntu)\nContent-Type: text/html; charset=UTF-8\nStrict-Transport-Security: max-age=31536000"
        },
        "latencies": {80: 42.1, 443: 45.3},
        "http_headers": {
            "Server": "nginx/1.24.0 (Ubuntu)",
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Type": "text/html; charset=UTF-8"
        },
        "target_type": "production"
    },
    "sim_prod_ssh": {
        "name": "Production OpenSSH Debian Gateway (Simulation)",
        "ip": "198.51.100.45",
        "open_ports": [22, 443],
        "banners": {
            22: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2",
            443: "HTTP/1.1 404 Not Found\nServer: Apache/2.4.57 (Debian)"
        },
        "latencies": {22: 65.4, 443: 68.2},
        "http_headers": {
            "Server": "Apache/2.4.57 (Debian)"
        },
        "target_type": "production"
    }
}


class NetworkScanner:
    """Multi-threaded network scanner and banner extractor."""
    
    def __init__(self, timeout: float = 2.0, max_threads: int = 20):
        self.timeout = timeout
        self.max_threads = max_threads

    def resolve_target(self, target: str) -> Optional[str]:
        """Resolves hostname or validates IP address."""
        # Strip protocols or slashes if user entered a URL
        cleaned = re.sub(r"^https?://", "", target).strip().split("/")[0].split(":")[0]
        try:
            ip = socket.gethostbyname(cleaned)
            return ip
        except socket.gaierror:
            return None

    def probe_port(self, ip: str, port: int) -> Dict[str, Any]:
        """Probes a single port, calculates latency, and grabs banner."""
        result = {
            "port": port,
            "is_open": False,
            "banner": "",
            "latency_ms": 0.0,
            "service": self._guess_service(port)
        }
        
        start_time = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            conn_res = sock.connect_ex((ip, port))
            if conn_res == 0:
                latency = (time.perf_counter() - start_time) * 1000.0
                result["is_open"] = True
                result["latency_ms"] = round(latency, 2)
                
                # Attempt banner grab
                banner = self._grab_banner(sock, ip, port)
                result["banner"] = banner
        except Exception:
            pass
        finally:
            sock.close()
            
        return result

    def _grab_banner(self, sock: socket.socket, ip: str, port: int) -> str:
        """Attempts protocol-specific banner acquisition."""
        try:
            # HTTP / HTTPS Ports
            if port in [80, 8080, 8000, 8888]:
                sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
                raw = sock.recv(2048)
                return raw.decode("utf-8", errors="ignore").strip()
                
            elif port in [443, 8443]:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    ssock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    raw = ssock.recv(2048)
                    return raw.decode("utf-8", errors="ignore").strip()
            
            # SSH / Telnet / FTP / SMTP / Modbus (Wait for initial greeting)
            sock.settimeout(1.5)
            try:
                raw = sock.recv(1024)
                if raw:
                    return raw.decode("utf-8", errors="ignore").strip()
            except socket.timeout:
                pass
                
            # If no greeting, send generic probe
            sock.sendall(b"\r\n")
            raw = sock.recv(1024)
            return raw.decode("utf-8", errors="ignore").strip()
            
        except Exception:
            return ""

    def _guess_service(self, port: int) -> str:
        """Returns standard service name for given port."""
        service_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 102: "Siemens S7", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 502: "Modbus TCP", 1433: "MSSQL",
            2222: "SSH-Alt (Cowrie/Kippo)", 3306: "MySQL", 5000: "HTTP-Alt",
            5060: "SIP", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt"
        }
        return service_map.get(port, f"Port-{port}")

    def scan_target(self, target: str, ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """Scans the specified target across ports."""
        if ports is None:
            ports = COMMON_PORTS
            
        # Check if target is a simulation profile key
        if target in SIMULATION_PROFILES:
            sim = SIMULATION_PROFILES[target]
            return {
                "target": sim["name"],
                "ip": sim["ip"],
                "is_simulated": True,
                "open_ports": sim["open_ports"],
                "banners": sim["banners"],
                "latencies": sim["latencies"],
                "port_results": [
                    {
                        "port": p,
                        "is_open": True,
                        "banner": sim["banners"].get(p, ""),
                        "latency_ms": sim["latencies"].get(p, 10.0),
                        "service": self._guess_service(p)
                    }
                    for p in sim["open_ports"]
                ]
            }
            
        resolved_ip = self.resolve_target(target)
        if not resolved_ip:
            return {
                "target": target,
                "ip": None,
                "error": f"Could not resolve hostname or IP address: {target}",
                "is_simulated": False,
                "open_ports": [],
                "banners": {},
                "latencies": {},
                "port_results": []
            }
            
        open_ports = []
        banners = {}
        latencies = {}
        port_results = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {executor.submit(self.probe_port, resolved_ip, port): port for port in ports}
            for future in as_completed(future_to_port):
                res = future.result()
                port_results.append(res)
                if res["is_open"]:
                    open_ports.append(res["port"])
                    banners[res["port"]] = res["banner"]
                    latencies[res["port"]] = res["latency_ms"]
                    
        # Sort results by port number
        port_results.sort(key=lambda x: x["port"])
        open_ports.sort()
        
        return {
            "target": target,
            "ip": resolved_ip,
            "is_simulated": False,
            "open_ports": open_ports,
            "banners": banners,
            "latencies": latencies,
            "port_results": port_results
        }
