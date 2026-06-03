"""
GeoIP lookup for attacker IP addresses.
Uses a public IP-API service as primary, with caching.
"""
import requests
import threading

_cache = {}
_lock = threading.Lock()

PRIVATE_RANGES = [
    ("10.", "Private"),
    ("192.168.", "Private"),
    ("172.16.", "Private"),
    ("172.17.", "Private"),
    ("172.18.", "Private"),
    ("172.19.", "Private"),
    ("127.", "Loopback"),
    ("0.", "Invalid"),
    ("Unknown", "Unknown"),
]

def is_private(ip: str) -> bool:
    for prefix, _ in PRIVATE_RANGES:
        if ip.startswith(prefix):
            return True
    return False


def lookup(ip: str) -> dict:
    with _lock:
        if ip in _cache:
            return _cache[ip]

    default = {"country": "Unknown", "city": "Unknown", "lat": 0, "lon": 0, "isp": "Unknown", "ip": ip}

    if is_private(ip) or ip == "Unknown":
        return default

    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,isp", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                result = {
                    "ip": ip,
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "lat": data.get("lat", 0),
                    "lon": data.get("lon", 0),
                    "isp": data.get("isp", "Unknown"),
                }
                with _lock:
                    _cache[ip] = result
                return result
    except Exception:
        pass

    return default


def lookup_async(ip: str, callback=None):
    """Non-blocking lookup, calls callback(result) when done."""
    def _run():
        result = lookup(ip)
        if callback:
            callback(result)
    t = threading.Thread(target=_run, daemon=True)
    t.start()
