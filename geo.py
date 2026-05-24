"""
IP geolocation module.
Supports ipinfo.io (free tier) and freegeoip.app as fallback providers.
"""

import threading
import requests
from functools import lru_cache
from config import ENABLE_GEOIP, GEOIP_PROVIDER


# Cache geolocation results to avoid repeated API calls
# Thread-safe via LRU cache wrapper
@lru_cache(maxsize=10000)
def _cached_lookup(ip_address):
    """Internal cached lookup"""
    # We are going to skip lookup for private/local IPs 
    if ip_address.startswith(("10.", "172.16.", "172.17.", "172.18.",
                               "172.19.", "172.20.", "172.21.", "172.22.",
                               "172.23.", "172.24.", "172.25.", "172.26.",
                               "172.27.", "172.28.", "172.29.", "172.30.",
                               "172.31.", "192.168.", "127.", "0.")):
        return {
            "ip": ip_address,
            "country": "Private",
            "city": "Private",
            "org": "Private"
        }

    if GEOIP_PROVIDER == "ipinfo":
        try:
            resp = requests.get(
                f"https://ipinfo.io/{ip_address}/json",
                timeout=3
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "ip": ip_address,
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "org": data.get("org", "Unknown"),
                }
        except requests.RequestException:
            pass

    # Fallback to freegeoip or return defaults
    try:
        resp = requests.get(
            f"https://freegeoip.app/json/{ip_address}",
            headers={"Accept": "application/json"},
            timeout=3
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "ip": ip_address,
                "country": data.get("country_name", "Unknown"),
                "city": data.get("city", "Unknown"),
                "org": "Unknown",
            }
    except requests.RequestException:
        pass

    return {
        "ip": ip_address,
        "country": "Unknown",
        "city": "Unknown",
        "org": "Unknown",
    }


def lookup_ip(ip_address):
    """
    Lookup geolocation for an IP address.
    """
    if not ENABLE_GEOIP:
        return {
            "ip": ip_address,
            "country": "Disabled",
            "city": "Disabled",
            "org": "Disabled",
        }
    return _cached_lookup(ip_address)