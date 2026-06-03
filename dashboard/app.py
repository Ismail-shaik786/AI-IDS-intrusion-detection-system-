"""
ThreatVision AI — Enterprise Flask Backend
Integrates: AI IDS, MongoDB, GeoIP, Telegram, Blacklist, PCAP, Anomaly Detection, Analytics
"""
import csv
import os
import sys
import time
from datetime import datetime

# ── Path setup ─────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
sys.path.insert(0, ROOT_DIR)

from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO
from flask_cors import CORS
import pandas as pd

# ── Enterprise modules ─────────────────────────────────────────────────────────
from backend.database.mongo_client import insert_alert, get_alerts, get_stats as mongo_stats
from backend.utils.geoip import lookup_async
from backend.utils.telegram_alerts import notify as telegram_notify
from backend.threat_intelligence.blacklist import (
    record_hit, is_blocked, get_blacklist, unblock, get_hit_count
)
from backend.ai_models.anomaly_detector import score as anomaly_score
from backend.api.analytics import update as analytics_update, get_dashboard_stats

# ── Flask App ──────────────────────────────────────────────────────────────────
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

LOG_FILE = os.path.join(ROOT_DIR, "logs", "threat_logs.csv")
CSV_HEADER = ["Timestamp", "Source_IP", "Destination_IP", "Attack_Type",
              "Severity", "Confidence", "Packet_Length", "Country", "Anomaly_Score"]


def _csv_needs_header() -> bool:
    """Return True only if the file is missing or has no header line yet."""
    if not os.path.exists(LOG_FILE):
        return True
    try:
        with open(LOG_FILE, "r") as f:
            first = f.readline().strip()
        return first != ",".join(CSV_HEADER)
    except Exception:
        return True


def _write_csv(data: dict):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, mode="a", newline="") as f:
        writer = csv.writer(f)
        if _csv_needs_header():
            writer.writerow(CSV_HEADER)
        writer.writerow([
            data.get("timestamp", datetime.now().isoformat()),
            data.get("src_ip", "Unknown"),
            data.get("dst_ip", "Unknown"),
            data.get("attack_type", "Unknown"),
            data.get("severity", "LOW"),
            f"{data.get('confidence', 0):.2f}",
            data.get("bytes", 0),
            data.get("country", "Unknown"),
            data.get("anomaly_score", 0.0),
        ])


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/threats")
def api_threats():
    """Returns last N alerts from MongoDB or CSV fallback."""
    limit = int(request.args.get("limit", 100))
    skip  = int(request.args.get("skip", 0))
    severity_filter = request.args.get("severity")

    # Try MongoDB first
    filters = {}
    if severity_filter:
        filters["severity"] = severity_filter.upper()
    alerts = get_alerts(limit=limit, skip=skip, filters=filters)

    # Fallback: CSV
    if not alerts:
        try:
            df = pd.read_csv(LOG_FILE).fillna("Unknown")
            if severity_filter:
                df = df[df["Severity"] == severity_filter.upper()]
            alerts = df.tail(limit).to_dict(orient="records")
        except Exception:
            alerts = []

    return jsonify({"alerts": alerts, "count": len(alerts)})


@app.route("/api/threats/csv-live")
def api_threats_csv_live():
    """
    Incremental CSV tail for the Live Threat Feed.
    ?after=N  — return all rows after index N (0-based, data rows only).
    Handles duplicate header rows and blank lines gracefully.
    """
    after = int(request.args.get("after", -1))
    try:
        # Read CSV, skip blank lines; force Timestamp column to string
        df = pd.read_csv(
            LOG_FILE,
            skip_blank_lines=True,
            dtype={"Timestamp": str},
            on_bad_lines="skip",
        ).fillna("Unknown")

        # Drop any rows where Timestamp == 'Timestamp' (duplicate header rows)
        if "Timestamp" in df.columns:
            df = df[df["Timestamp"] != "Timestamp"].reset_index(drop=True)

        total_rows = len(df)

        if after < 0:
            new_rows = df.tail(50)          # first load: last 50 real rows
        else:
            new_rows = df.iloc[after + 1:]  # only rows we haven't seen

        alerts = []
        for _, row in new_rows.iterrows():
            try:
                conf = float(row.get("Confidence", 0))
            except (ValueError, TypeError):
                conf = 0.0
            try:
                anom = float(row.get("Anomaly_Score", 0))
            except (ValueError, TypeError):
                anom = 0.0
            alerts.append({
                "timestamp":     str(row.get("Timestamp", "")),
                "src_ip":        str(row.get("Source_IP", "--")),
                "dst_ip":        str(row.get("Destination_IP", "--")),
                "attack_type":   str(row.get("Attack_Type", "--")),
                "severity":      str(row.get("Severity", "LOW")),
                "confidence":    conf,
                "country":       str(row.get("Country", "--")),
                "anomaly_score": anom,
            })
        return jsonify({"alerts": alerts, "total_rows": total_rows})
    except Exception as e:
        return jsonify({"alerts": [], "total_rows": 0, "error": str(e)})


@app.route("/api/stats")
def api_stats():
    """Returns aggregated dashboard statistics."""
    live = get_dashboard_stats()

    # Enrich with MongoDB if available
    mongo = mongo_stats()
    if mongo:
        live["mongo"] = mongo

    return jsonify(live)


@app.route("/api/analytics")
def api_analytics():
    """Extended analytics for the Threat Analytics tab."""
    return jsonify(get_dashboard_stats())


@app.route("/api/blacklist")
def api_blacklist():
    return jsonify({"blacklist": get_blacklist()})


@app.route("/api/blacklist/unblock", methods=["POST"])
def api_unblock():
    ip = request.json.get("ip")
    if not ip:
        return jsonify({"error": "IP required"}), 400
    unblock(ip)
    return jsonify({"status": "unblocked", "ip": ip})


@app.route("/api/blacklist/block", methods=["POST"])
def api_block():
    """Called by realtime_ids.py to auto-block HIGH/CRITICAL source IPs."""
    data = request.json or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP required"}), 400
    reason    = data.get("reason", "Auto-blocked by ThreatVision AI")
    permanent = bool(data.get("permanent", False))
    record_hit(ip, reason=reason, permanent=permanent)
    socketio.emit("ip_blocked", {"ip": ip, "reason": reason, "permanent": permanent})
    return jsonify({"status": "blocked", "ip": ip, "reason": reason})


@app.route("/api/threats/export")
def api_export():
    """Export CSV of alerts."""
    try:
        with open(LOG_FILE) as f:
            content = f.read()
        return app.response_class(content, mimetype="text/csv",
                                  headers={"Content-Disposition": "attachment;filename=sentinelx_threats.csv"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Alert ingestion endpoint (called by realtime_ids.py) ──────────────────────
@app.route("/alert", methods=["POST"])
def receive_alert():
    data = request.json
    if not data:
        return jsonify({"error": "no data"}), 400

    now = datetime.now()
    data["timestamp"] = now.isoformat()

    # 1. Write CSV log
    _write_csv(data)

    # 2. Update in-memory analytics
    analytics_update(data)

    # 3. MongoDB (async-style — non-blocking)
    insert_alert(dict(data))

    # 4. Blacklist / IPS
    src_ip = data.get("src_ip", "Unknown")
    newly_blocked = record_hit(src_ip, data.get("attack_type", ""), data.get("severity", "LOW"))
    if newly_blocked:
        data["auto_blocked"] = True
        socketio.emit("ip_blocked", {"ip": src_ip, "reason": data.get("attack_type")})

    # 5. GeoIP enrichment (async, emits enriched alert when ready)
    def _on_geo(geo):
        data["country"] = geo.get("country", "Unknown")
        data["city"]    = geo.get("city", "Unknown")
        data["lat"]     = geo.get("lat", 0)
        data["lon"]     = geo.get("lon", 0)
        data["isp"]     = geo.get("isp", "Unknown")
        # 6. Telegram (high/critical only)
        telegram_notify(data)
        # 7. Broadcast enriched alert to all dashboard clients
        socketio.emit("new_alert", data)
        socketio.emit("stats_update", get_dashboard_stats())

    lookup_async(src_ip, callback=_on_geo)

    return jsonify({"status": "received"})


# ── Socket.IO events ──────────────────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    socketio.emit("stats_update", get_dashboard_stats())


@socketio.on("request_stats")
def on_request_stats():
    socketio.emit("stats_update", get_dashboard_stats())


if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("  SentinelX SOC Platform — Starting...")
    print("=" * 50)
    socketio.run(app, debug=True, port=5000, allow_unsafe_werkzeug=True)