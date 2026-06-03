"""
Telegram alert notification module.
Sends critical/high severity alerts to a configured Telegram bot.
"""
import os
import threading
import requests

# ── Configuration ──────────────────────────────────────────────────────────────
# Set these as environment variables OR edit here directly:
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "8986675659:AAGTm0wrInBmyte9WGuLRBJ9rbCePEULHZg")   # e.g. "123456:ABC-DEF..."
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "8416266813") # e.g. "123456789"

ALERT_SEVERITIES = {"HIGH", "CRITICAL"}

EMOJI_MAP = {
    "CRITICAL": "🚨",
    "HIGH":     "⚠️",
    "MEDIUM":   "🔶",
    "LOW":      "🟢",
}

ATTACK_EMOJI = {
    "DDoS":              "💣",
    "PortScan":          "🔍",
    "SSH-Patator":       "🔑",
    "FTP-Patator":       "🔑",
    "Bot":               "🤖",
    "Web Attack XSS":    "🕸️",
    "Web Attack SQL":    "🗄️",
    "DoS Hulk":          "💀",
    "DoS GoldenEye":     "👁️",
    "BENIGN":            "✅",
}


def _send(message: str):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return  # silently skip if not configured
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML"
    }
    try:
        requests.post(url, json=payload, timeout=5)
    except Exception as e:
        print(f"[Telegram] Send failed: {e}")


def notify(alert: dict):
    """
    Send a Telegram alert for HIGH/CRITICAL threats.
    Runs in a background thread so it never blocks the main loop.
    """
    severity = alert.get("severity", "LOW")
    if severity not in ALERT_SEVERITIES:
        return

    attack = alert.get("attack_type", "Unknown")
    src_ip = alert.get("src_ip", "Unknown")
    dst_ip = alert.get("dst_ip", "Unknown")
    confidence = alert.get("confidence", 0)
    packets = alert.get("packet_count", 0)
    country = alert.get("country", "Unknown")

    emoji = EMOJI_MAP.get(severity, "⚠️")
    atk_emoji = ATTACK_EMOJI.get(attack, "🔴")

    message = (
        f"{emoji} <b>{severity} THREAT DETECTED</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"{atk_emoji} <b>Attack Type:</b> {attack}\n"
        f"🌐 <b>Source IP:</b> <code>{src_ip}</code> ({country})\n"
        f"🎯 <b>Target IP:</b> <code>{dst_ip}</code>\n"
        f"🧠 <b>Confidence:</b> {confidence:.1f}%\n"
        f"📦 <b>Packets:</b> {packets:,}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"<i>SentinelX AI SOC Platform</i>"
    )

    t = threading.Thread(target=_send, args=(message,), daemon=True)
    t.start()
