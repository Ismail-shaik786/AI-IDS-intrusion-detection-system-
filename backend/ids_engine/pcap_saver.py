"""
PCAP evidence saver — captures suspicious packet streams to .pcap files
organized by attack type for digital forensics.
"""
import os
import time
import threading
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import wrpcap, Packet
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

ATTACKS_DIR = os.path.join(os.path.dirname(__file__), "../../attacks")

ATTACK_FOLDER_MAP = {
    "DDoS":              "ddos",
    "DoS Hulk":          "ddos",
    "DoS GoldenEye":     "ddos",
    "DoS Slowhttptest":  "ddos",
    "DoS slowloris":     "ddos",
    "PortScan":          "portscan",
    "SSH-Patator":       "brute_force",
    "FTP-Patator":       "brute_force",
    "Web Attack XSS":    "xss",
    "Web Attack SQL":    "xss",
    "Bot":               "bot",
}

# Buffer: attack_type -> list of packets
_buffer = defaultdict(list)
_lock = threading.Lock()
MAX_BUFFER = 200   # packets per file


def save_packet(packet, attack_type: str):
    """Buffer a suspicious packet. Flushes to disk when buffer is full."""
    if not SCAPY_AVAILABLE or attack_type == "BENIGN":
        return

    with _lock:
        _buffer[attack_type].append(packet)
        if len(_buffer[attack_type]) >= MAX_BUFFER:
            _flush(attack_type)


def _flush(attack_type: str):
    """Write buffered packets to a timestamped .pcap file (must hold _lock)."""
    packets = _buffer.pop(attack_type, [])
    if not packets:
        return

    folder = ATTACK_FOLDER_MAP.get(attack_type, "unknown")
    attack_dir = os.path.join(ATTACKS_DIR, folder)
    os.makedirs(attack_dir, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(attack_dir, f"{folder}_{ts}.pcap")

    try:
        wrpcap(filename, packets)
        print(f"[PCAP] Saved {len(packets)} packets → {filename}")
    except Exception as e:
        print(f"[PCAP] Save error: {e}")


def flush_all():
    """Flush all buffers to disk (call on shutdown)."""
    with _lock:
        for attack_type in list(_buffer.keys()):
            _flush(attack_type)


# Background periodic flush (every 60 seconds)
def _periodic_flush():
    while True:
        time.sleep(60)
        with _lock:
            for attack_type in list(_buffer.keys()):
                if _buffer[attack_type]:
                    _flush(attack_type)

threading.Thread(target=_periodic_flush, daemon=True).start()
