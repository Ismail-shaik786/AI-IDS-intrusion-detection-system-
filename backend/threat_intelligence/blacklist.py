"""
IP Blacklist & Auto-Block (IPS mode).
Tracks repeated attackers and applies iptables DROP rules.
"""
import subprocess
import threading
import time
import json
import os
from collections import defaultdict

BLACKLIST_FILE = os.path.join(os.path.dirname(__file__), "../../logs/blacklist.json")
BLOCK_THRESHOLD = 5          # hits before auto-block
TEMP_BLOCK_SECS = 3600       # 1 hour temporary block

_lock = threading.Lock()
_hit_counter = defaultdict(int)   # ip -> hit count
_blacklist = {}                   # ip -> {"blocked_at": ..., "reason": ..., "permanent": bool}

# ── Persistence ────────────────────────────────────────────────────────────────
def _load():
    global _blacklist
    try:
        if os.path.exists(BLACKLIST_FILE):
            with open(BLACKLIST_FILE) as f:
                _blacklist = json.load(f)
            print(f"[Blacklist] Loaded {len(_blacklist)} blocked IPs")
    except Exception as e:
        print(f"[Blacklist] Load error: {e}")

def _save():
    try:
        os.makedirs(os.path.dirname(BLACKLIST_FILE), exist_ok=True)
        with open(BLACKLIST_FILE, "w") as f:
            json.dump(_blacklist, f, indent=2)
    except Exception as e:
        print(f"[Blacklist] Save error: {e}")


_load()

# ── iptables helpers ───────────────────────────────────────────────────────────
PRIVATE_RANGES = ["10.", "192.168.", "127.", "172."]

def _is_private(ip: str) -> bool:
    return any(ip.startswith(r) for r in PRIVATE_RANGES)

def _iptables_block(ip: str):
    if _is_private(ip):
        return False
    try:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True
        )
        print(f"[Firewall] Blocked {ip} via iptables")
        return True
    except Exception as e:
        print(f"[Firewall] iptables unavailable (run as root): {e}")
        return False

def _iptables_unblock(ip: str):
    try:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True
        )
        print(f"[Firewall] Unblocked {ip}")
    except Exception:
        pass


# ── Public API ─────────────────────────────────────────────────────────────────
def record_hit(ip: str, attack_type: str, severity: str) -> bool:
    """
    Record an attack hit for an IP.
    Returns True if the IP was newly blocked.
    """
    if not ip or ip == "Unknown" or _is_private(ip):
        return False

    with _lock:
        if ip in _blacklist:
            return False  # already blocked

        _hit_counter[ip] += 1

        if severity == "CRITICAL":
            _hit_counter[ip] += 3  # accelerate blocking for critical attacks
        elif severity == "HIGH":
            _hit_counter[ip] += 1

        if _hit_counter[ip] >= BLOCK_THRESHOLD:
            _blacklist[ip] = {
                "blocked_at": time.time(),
                "reason": attack_type,
                "severity": severity,
                "hits": _hit_counter[ip],
                "permanent": severity == "CRITICAL"
            }
            _save()
            _iptables_block(ip)
            return True

    return False


def is_blocked(ip: str) -> bool:
    with _lock:
        return ip in _blacklist


def unblock(ip: str):
    with _lock:
        if ip in _blacklist:
            del _blacklist[ip]
            _hit_counter.pop(ip, None)
            _save()
            _iptables_unblock(ip)


def get_blacklist() -> list:
    with _lock:
        result = []
        for ip, info in _blacklist.items():
            result.append({"ip": ip, **info})
        return sorted(result, key=lambda x: x["blocked_at"], reverse=True)


def get_hit_count(ip: str) -> int:
    return _hit_counter.get(ip, 0)


# ── Background cleanup of expired temporary blocks ─────────────────────────────
def _cleanup_loop():
    while True:
        time.sleep(300)
        now = time.time()
        expired = []
        with _lock:
            for ip, info in list(_blacklist.items()):
                if not info.get("permanent") and (now - info["blocked_at"]) > TEMP_BLOCK_SECS:
                    expired.append(ip)
            for ip in expired:
                del _blacklist[ip]
                _hit_counter.pop(ip, None)
                _iptables_unblock(ip)
        if expired:
            _save()
            print(f"[Blacklist] Auto-expired {len(expired)} IP(s)")

threading.Thread(target=_cleanup_loop, daemon=True).start()
