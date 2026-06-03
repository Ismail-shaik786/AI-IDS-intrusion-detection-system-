import warnings
warnings.filterwarnings("ignore")

from scapy.all import *
from collections import defaultdict
import time
import joblib
import numpy as np
import pandas as pd
import requests
import csv
import os
from datetime import datetime

# =========================================
# LOAD AI MODEL
# =========================================

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "multi_ids_model.pkl")
model = joblib.load(MODEL_PATH)
# Single-threaded inference: we predict one packet at a time, so joblib
# worker threads only add overhead and spawn the sklearn.utils.parallel warning.
model.n_jobs = 1
# Feature names the model was trained with — used to build named DataFrames
# so sklearn never fires the "X does not have valid feature names" warning.
FEATURE_NAMES = list(model.feature_names_in_) if hasattr(model, "feature_names_in_") else [f"f{i}" for i in range(78)]

# =========================================
# FLOW STORAGE
# =========================================

flows = defaultdict(lambda: {
    "packet_count": 0,
    "byte_count": 0,
    "start_time": time.time(),
    "syn_count": 0
})

# =========================================
# ATTACK LABELS
# =========================================

attack_labels = {
    0: "BENIGN",
    1: "Bot",
    2: "DDoS",
    3: "DoS GoldenEye",
    4: "DoS Hulk",
    5: "DoS Slowhttptest",
    6: "DoS slowloris",
    7: "FTP-Patator",
    8: "Heartbleed",
    9: "Infiltration",
    10: "PortScan",
    11: "SSH-Patator",
    12: "Web Attack Brute Force",
    13: "Web Attack Sql Injection",
    14: "Web Attack XSS"
}

# =========================================
# THREAT SEVERITY
# =========================================

def get_severity(prediction):

    if prediction in ["BENIGN"]:
        return "LOW"

    elif prediction in [
        "PortScan",
        "Bot",
        "FTP-Patator",
        "SSH-Patator"
    ]:
        return "HIGH"

    elif prediction in [
        "DDoS",
        "DoS Hulk",
        "DoS GoldenEye",
        "DoS Slowhttptest",
        "DoS slowloris"
    ]:
        return "CRITICAL"

    else:
        return "MEDIUM"

# =========================================
# CSV LOGGING PATH
# =========================================

LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "threat_logs.csv")
CSV_HEADER = ["Timestamp", "Source_IP", "Destination_IP", "Attack_Type",
              "Severity", "Confidence", "Packet_Length", "Country", "Anomaly_Score"]


def _csv_needs_header():
    """Return True only if the file is missing or has no correct header."""
    if not os.path.exists(LOG_FILE):
        return True
    try:
        with open(LOG_FILE, "r") as f:
            return f.readline().strip() != ",".join(CSV_HEADER)
    except Exception:
        return True


def write_to_csv(src_ip, dst_ip, attack_type, severity, confidence, byte_count, anomaly_score=0.0):
    """Append one prediction row to the threat log CSV."""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, mode="a", newline="") as f:
        writer = csv.writer(f)
        if _csv_needs_header():
            writer.writerow(CSV_HEADER)
        writer.writerow([
            datetime.now().isoformat(),
            src_ip, dst_ip, attack_type, severity,
            f"{confidence:.2f}", byte_count, "Unknown", anomaly_score
        ])


# =========================================
# AUTO-BLOCK HIGH/CRITICAL IPs
# =========================================

_blocked_ips = set()   # in-process cache to avoid spamming the API

def auto_block(src_ip, attack_type, severity):
    """POST to dashboard blacklist API if threat is HIGH or CRITICAL."""
    if severity not in ("HIGH", "CRITICAL"):
        return
    if src_ip in _blocked_ips:
        return
    try:
        requests.post(
            "http://127.0.0.1:5000/api/blacklist/block",
            json={"ip": src_ip, "reason": attack_type, "permanent": severity == "CRITICAL"},
            timeout=1
        )
        _blocked_ips.add(src_ip)
        print(f"[AUTO-BLOCK] {src_ip} blocked → {attack_type} ({severity})")
    except Exception:
        pass


# =========================================
# SEND DATA TO DASHBOARD (Socket.IO event)
# =========================================

def send_to_dashboard(data):
    try:
        requests.post(
            "http://127.0.0.1:5000/alert",
            json=data,
            timeout=1
        )
    except:
        pass

# =========================================
# PROCESS PACKETS
# =========================================

def process_packet(packet):

    try:

        if packet.haslayer(IP):

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto

            flow_id = f"{src_ip}-{dst_ip}-{protocol}"

            flow = flows[flow_id]

            # =========================================
            # UPDATE FLOW STATS
            # =========================================

            flow["packet_count"] += 1
            flow["byte_count"] += len(packet)

            if packet.haslayer(TCP):

                if packet[TCP].flags == "S":
                    flow["syn_count"] += 1

            flow_duration = time.time() - flow["start_time"]

            # =========================================
            # CREATE FEATURE VECTOR (named DataFrame)
            # =========================================

            raw = np.zeros(len(FEATURE_NAMES))

            # Map the few features we compute into the correct column indices
            _idx = {name: i for i, name in enumerate(FEATURE_NAMES)}
            raw[_idx.get("Total Fwd Packets", 0)]          = flow["packet_count"]
            raw[_idx.get("Total Length of Fwd Packets", 4)] = flow["byte_count"]
            raw[_idx.get("Flow Duration", 1)]              = flow_duration
            raw[_idx.get("SYN Flag Count", 44)]            = flow["syn_count"]

            # Wrap in a named DataFrame — matches training format, no warning
            features = pd.DataFrame([raw], columns=FEATURE_NAMES)

            # =========================================
            # AI PREDICTION
            # =========================================

            prediction_num = model.predict(features)[0]

            prediction = attack_labels.get(
                prediction_num,
                "BENIGN"
            )

            confidence = np.max(
                model.predict_proba(features)
            ) * 100

            # =========================================
            # HYBRID DETECTION RULES
            # =========================================

            # PORT SCAN DETECTION
            if flow["syn_count"] > 20:

                prediction = "PortScan"
                confidence = 99.0

            # DDoS DETECTION
            elif flow["packet_count"] > 200:

                prediction = "DDoS"
                confidence = 99.0

            severity = get_severity(prediction)

            # =========================================
            # DISPLAY ALERT
            # =========================================

            print("\n===================================")
            print("        LIVE AI IDS ALERT")
            print("===================================")

            print(f"Detected Traffic : {prediction}")
            print(f"Threat Severity  : {severity}")
            print(f"Confidence Score : {confidence:.2f}%")

            print(f"Source IP        : {src_ip}")
            print(f"Destination IP   : {dst_ip}")

            print(f"Packet Count     : {flow['packet_count']}")
            print(f"SYN Count        : {flow['syn_count']}")
            print(f"Bytes Transferred: {flow['byte_count']}")

            print("===================================")

            # =========================================
            # WRITE TO CSV (primary log — always works)
            # =========================================

            write_to_csv(
                src_ip=src_ip,
                dst_ip=dst_ip,
                attack_type=prediction,
                severity=severity,
                confidence=float(confidence),
                byte_count=flow["byte_count"],
                anomaly_score=1.0 if severity in ("HIGH", "CRITICAL") else 0.0
            )

            # =========================================
            # AUTO-BLOCK HIGH / CRITICAL SOURCES
            # =========================================

            auto_block(src_ip, prediction, severity)

            # =========================================
            # ALSO PUSH TO DASHBOARD VIA /alert
            # =========================================

            dashboard_data = {
                "attack_type": prediction,
                "severity": severity,
                "confidence": float(confidence),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "packet_count": flow["packet_count"],
                "syn_count": flow["syn_count"],
                "bytes": flow["byte_count"]
            }

            send_to_dashboard(dashboard_data)

    except Exception as e:

        print("Error:", e)

# =========================================
# START IDS
# =========================================

# Get interface from environment or auto-detect using Scapy's default
interface = os.getenv("IDS_INTERFACE")
if not interface or interface.lower() == "auto":
    try:
        # conf is imported from scapy.all
        scapy_iface = conf.iface
        if hasattr(scapy_iface, "name"):
            interface = scapy_iface.name
        else:
            interface = str(scapy_iface)
    except Exception:
        interface = "wlan0"

print("\n========================================")
print("   ThreatVision AI — REALTIME IDS ENGINE")
print("========================================")
print(f"Monitoring Network Traffic on interface: {interface}...\n")

sniff(
    iface=interface,
    filter="ip",
    prn=process_packet,
    store=False
)