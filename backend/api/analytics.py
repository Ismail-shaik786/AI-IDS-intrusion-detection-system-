"""
Analytics engine — in-memory counters + CSV-backed statistics.
Supports: attack trends, top IPs, top ports, severity breakdown, protocol stats.
"""
import csv
import os
import time
import threading
from collections import defaultdict, deque
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(__file__), "../../logs/threat_logs.csv")

_lock = threading.Lock()

# Live in-memory counters
_stats = {
    "total":    0,
    "benign":   0,
    "blocked":  0,
    "critical": 0,
    "high":     0,
    "medium":   0,
    "low":      0,
}
_attack_counts   = defaultdict(int)
_top_ips         = defaultdict(int)
_top_ports       = defaultdict(int)
_protocol_counts = defaultdict(int)
_timeline        = deque(maxlen=300)   # last 300 events for graphing
_packets_analyzed = 0
_start_time = time.time()


def update(data: dict):
    global _packets_analyzed
    with _lock:
        _packets_analyzed += 1
        _stats["total"] += 1

        attack  = data.get("attack_type", "BENIGN")
        severity = data.get("severity", "LOW")
        src_ip  = data.get("src_ip", "Unknown")
        protocol = data.get("protocol", "TCP")
        dport   = data.get("dst_port", 0)

        if attack == "BENIGN":
            _stats["benign"] += 1
        if severity == "CRITICAL":
            _stats["critical"] += 1
        elif severity == "HIGH":
            _stats["high"] += 1
            _stats["blocked"] += 1
        elif severity == "MEDIUM":
            _stats["medium"] += 1
        else:
            _stats["low"] += 1

        _attack_counts[attack] += 1
        if src_ip != "Unknown":
            _top_ips[src_ip] += 1
        if dport:
            _top_ports[str(dport)] += 1
        _protocol_counts[protocol] += 1

        _timeline.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "attack_type": attack,
            "severity": severity,
        })


def get_dashboard_stats() -> dict:
    with _lock:
        uptime = int(time.time() - _start_time)
        rate = round(_packets_analyzed / max(uptime, 1), 2)

        top_ips = sorted(_top_ips.items(), key=lambda x: x[1], reverse=True)[:5]
        top_ports = sorted(_top_ports.items(), key=lambda x: x[1], reverse=True)[:5]

        # Build traffic timeline for chart (last 20 events bucketed)
        timeline_list = list(_timeline)

        return {
            **_stats,
            "packets_analyzed": _packets_analyzed,
            "packets_per_sec": rate,
            "uptime_secs": uptime,
            "attack_counts": dict(_attack_counts),
            "protocol_counts": dict(_protocol_counts),
            "top_ips": [{"ip": ip, "count": cnt} for ip, cnt in top_ips],
            "top_ports": [{"port": p, "count": cnt} for p, cnt in top_ports],
            "timeline": timeline_list[-50:],
        }


def load_from_csv():
    """Seed in-memory counters from existing CSV log on startup."""
    if not os.path.exists(LOG_FILE):
        return
    try:
        with open(LOG_FILE, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                with _lock:
                    _stats["total"] += 1
                    attack = row.get("Attack_Type", "BENIGN")
                    sev = row.get("Severity", "LOW")
                    _attack_counts[attack] += 1
                    if sev == "HIGH":
                        _stats["high"] += 1
                        _stats["blocked"] += 1
                    elif sev == "CRITICAL":
                        _stats["critical"] += 1
                        _stats["blocked"] += 1
                    elif sev == "MEDIUM":
                        _stats["medium"] += 1
                    else:
                        _stats["low"] += 1
        print(f"[Analytics] Seeded {_stats['total']} records from CSV")
    except Exception as e:
        print(f"[Analytics] CSV seed error: {e}")


# Seed on import
threading.Thread(target=load_from_csv, daemon=True).start()
