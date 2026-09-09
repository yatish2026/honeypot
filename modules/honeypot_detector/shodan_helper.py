"""Shodan OSINT Intelligence Helper."""

from typing import Dict, Any, Optional
import requests
from config import SHODAN_API_KEY


class ShodanHelper:
    """Queries Shodan API for host intelligence and tags."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or SHODAN_API_KEY

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Queries Shodan API for IP metadata, tags, and known vulnerabilities."""
        if not self.api_key:
            return {
                "available": False,
                "message": "No Shodan API Key configured. Skipping OSINT lookup.",
                "tags": [],
                "org": "N/A",
                "isp": "N/A",
                "country": "N/A",
                "is_known_honeypot": False
            }
            
        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={self.api_key}"
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                tags = data.get("tags", [])
                return {
                    "available": True,
                    "tags": tags,
                    "org": data.get("org", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "country": data.get("country_name", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "ports": data.get("ports", []),
                    "vulns": list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else data.get("vulns", []),
                    "is_known_honeypot": "honeypot" in tags or "cloud" in tags
                }
            elif resp.status_code == 404:
                return {
                    "available": True,
                    "message": "Host not indexed in Shodan database.",
                    "tags": [],
                    "org": "N/A",
                    "isp": "N/A",
                    "country": "N/A",
                    "is_known_honeypot": False
                }
            else:
                return {
                    "available": False,
                    "message": f"Shodan API Error: HTTP {resp.status_code}",
                    "tags": [],
                    "is_known_honeypot": False
                }
        except Exception as e:
            return {
                "available": False,
                "message": f"Shodan lookup error: {str(e)}",
                "tags": [],
                "is_known_honeypot": False
            }
