"""
OSINT Intelligence & IP Geolocation Helper
Provides real-time IP Geolocation, ASN, ISP, and Reverse DNS intelligence
using free OSINT endpoints with fallback simulation profiles.
"""

import socket
import requests
from typing import Dict, Any, Optional


def country_code_to_flag(code: str) -> str:
    """Converts a 2-letter ISO country code into a flag emoji."""
    if not code or len(code) != 2:
        return "🌐"
    try:
        return "".join(chr(127397 + ord(c.upper())) for c in code)
    except Exception:
        return "🌐"


# Simulation fallbacks for local/preset targets
SIMULATION_OSINT_PROFILES = {
    "192.168.1.150": {
        "country": "Germany",
        "country_code": "DE",
        "flag": "🇩🇪",
        "city": "Frankfurt am Main",
        "region": "Hesse",
        "isp": "Amazon Web Services, Inc.",
        "org": "AWS EC2 Cloud Deception Node",
        "asn": "AS16509 Amazon.com, Inc.",
        "reverse_dns": "ec2-54-93-12-88.eu-central-1.compute.amazonaws.com",
        "lat": 50.1109,
        "lon": 8.6821,
        "is_simulated": True
    },
    "10.0.0.88": {
        "country": "United States",
        "country_code": "US",
        "flag": "🇺🇸",
        "city": "North Bergen",
        "region": "New Jersey",
        "isp": "DigitalOcean, LLC",
        "org": "DigitalOcean Droplet / Honeypot Sandbox",
        "asn": "AS14061 DigitalOcean, LLC",
        "reverse_dns": "sandbox-dionaea-trap.threat-intel.net",
        "lat": 40.8043,
        "lon": -74.0121,
        "is_simulated": True
    },
    "172.16.4.20": {
        "country": "Switzerland",
        "country_code": "CH",
        "flag": "🇨🇭",
        "city": "Zurich",
        "region": "Zurich",
        "isp": "Swisscom Enterprise Cloud",
        "org": "ICS / SCADA Testbed Simulation",
        "asn": "AS3303 Swisscom (Switzerland) Ltd",
        "reverse_dns": "scada-conpot-gw.industrial-grid.ch",
        "lat": 47.3769,
        "lon": 8.5417,
        "is_simulated": True
    },
    "104.21.55.12": {
        "country": "United States",
        "country_code": "US",
        "flag": "🇺🇸",
        "city": "San Francisco",
        "region": "California",
        "isp": "Cloudflare, Inc.",
        "org": "Cloudflare Edge Web Infrastructure",
        "asn": "AS13335 Cloudflare, Inc.",
        "reverse_dns": "prod-nginx-edge.enterprise-corp.com",
        "lat": 37.7749,
        "lon": -122.4194,
        "is_simulated": True
    },
    "198.51.100.45": {
        "country": "United Kingdom",
        "country_code": "GB",
        "flag": "🇬🇧",
        "city": "London",
        "region": "England",
        "isp": "Akamai Connected Cloud / Linode",
        "org": "Enterprise Linux Production Node",
        "asn": "AS63949 Akamai Technologies, Inc.",
        "reverse_dns": "prod-ssh-bastion.corp-infra.co.uk",
        "lat": 51.5074,
        "lon": -0.1278,
        "is_simulated": True
    }
}


class OSINTIntelligenceHelper:
    """Queries free OSINT sources for IP Geolocation, ASN, and Hostname."""

    def __init__(self, timeout: float = 3.5):
        self.timeout = timeout

    def lookup(self, ip: str, hostname: str = "") -> Dict[str, Any]:
        """
        Retrieves OSINT metadata for an IP or target.
        Tries simulation presets first; then live endpoints; falls back gracefully.
        """
        # 1. Check direct simulation profile map
        if ip in SIMULATION_OSINT_PROFILES:
            profile = dict(SIMULATION_OSINT_PROFILES[ip])
            profile["available"] = True
            profile["ip"] = ip
            profile["target"] = hostname or ip
            return profile

        # Check by preset name
        preset_map = {
            "sim_cowrie": "192.168.1.150",
            "sim_dionaea": "10.0.0.88",
            "sim_conpot": "172.16.4.20",
            "sim_prod_web": "104.21.55.12",
            "sim_prod_ssh": "198.51.100.45"
        }
        if hostname in preset_map and preset_map[hostname] in SIMULATION_OSINT_PROFILES:
            profile = dict(SIMULATION_OSINT_PROFILES[preset_map[hostname]])
            profile["available"] = True
            profile["ip"] = ip
            profile["target"] = hostname
            return profile

        # 2. Check for localhost or private LAN
        if ip in ["127.0.0.1", "localhost", "0.0.0.0"] or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16."):
            return {
                "available": True,
                "ip": ip,
                "target": hostname or ip,
                "country": "Internal / Local Network",
                "country_code": "LOCAL",
                "flag": "🏠",
                "city": "Private Subnet",
                "region": "Localhost / LAN",
                "isp": "Local Area Network (RFC 1918)",
                "org": "Private Intranet Infrastructure",
                "asn": "N/A (Private)",
                "reverse_dns": self._get_reverse_dns(ip) or "localhost",
                "lat": 0.0,
                "lon": 0.0,
                "is_simulated": False
            }

        # 3. Live OSINT lookup using ip-api.com (free, keyless)
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query,reverse"
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    cc = data.get("countryCode", "")
                    return {
                        "available": True,
                        "ip": ip,
                        "target": hostname or ip,
                        "country": data.get("country", "Unknown"),
                        "country_code": cc,
                        "flag": country_code_to_flag(cc),
                        "city": data.get("city", "Unknown"),
                        "region": data.get("regionName", "Unknown"),
                        "isp": data.get("isp", "Unknown ISP"),
                        "org": data.get("org", data.get("isp", "Unknown Org")),
                        "asn": data.get("as", "Unknown ASN"),
                        "reverse_dns": data.get("reverse") or self._get_reverse_dns(ip) or hostname or ip,
                        "lat": data.get("lat", 0.0),
                        "lon": data.get("lon", 0.0),
                        "timezone": data.get("timezone", "UTC"),
                        "is_simulated": False
                    }
        except Exception:
            pass

        # 4. Fallback: Secondary OSINT endpoint (ipwho.is)
        try:
            url = f"https://ipwho.is/{ip}"
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success", False):
                    cc = data.get("country_code", "")
                    conn = data.get("connection", {})
                    return {
                        "available": True,
                        "ip": ip,
                        "target": hostname or ip,
                        "country": data.get("country", "Unknown"),
                        "country_code": cc,
                        "flag": country_code_to_flag(cc),
                        "city": data.get("city", "Unknown"),
                        "region": data.get("region", "Unknown"),
                        "isp": conn.get("isp", "Unknown ISP"),
                        "org": conn.get("org", conn.get("isp", "Unknown Org")),
                        "asn": f"AS{conn.get('asn', '')} {conn.get('org', '')}".strip(),
                        "reverse_dns": self._get_reverse_dns(ip) or hostname or ip,
                        "lat": data.get("latitude", 0.0),
                        "lon": data.get("longitude", 0.0),
                        "is_simulated": False
                    }
        except Exception:
            pass

        # 5. Final Graceful Fallback with Reverse DNS
        rdns = self._get_reverse_dns(ip) or hostname or ip
        return {
            "available": True,
            "ip": ip,
            "target": hostname or ip,
            "country": "Public Host (Cloud / Edge)",
            "country_code": "GLOBAL",
            "flag": "🌐",
            "city": "Cloud Edge",
            "region": "Global Infrastructure",
            "isp": "Autonomous System Provider",
            "org": "Remote Server",
            "asn": "BGP Autonomous System",
            "reverse_dns": rdns,
            "lat": 0.0,
            "lon": 0.0,
            "is_simulated": False
        }

    def _get_reverse_dns(self, ip: str) -> Optional[str]:
        """Resolves PTR reverse DNS record for an IP."""
        try:
            host_info = socket.gethostbyaddr(ip)
            return host_info[0]
        except Exception:
            return None
