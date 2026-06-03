#!/bin/bash

# ==============================================================================
# ThreatVision AI (SentinelX SOC) — Automated Installer Script
# ==============================================================================

# Exit immediately if a command exits with a non-zero status
set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ASCII Art Banner
show_banner() {
    echo -e "${CYAN}"
    echo "======================================================================"
    echo "  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗██╗   ██╗██╗███████╗ ██████╗ ███╗   ██╗ "
    echo "  ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║   ██║██║██╔════╝██╔═══██╗████╗  ██║ "
    echo "     ██║   ███████║██████╔╝█████╗  ███████║   ██║   ██║   ██║██║███████╗██║   ██║██╔██╗ ██║ "
    echo "     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ╚██╗ ██╔╝██║╚════██║██║   ██║██║╚██╗██║ "
    echo "     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║    ╚████╔╝ ██║███████║╚██████╔╝██║ ╚████║ "
    echo "     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝     ╚═══╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝ "
    echo "                     REAL-TIME AI-POWERED IDS & IPS SOC                     "
    echo "======================================================================"
    echo -e "${NC}"
}

# 1. Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Please run this installer as root (e.g., sudo ./install.sh).${NC}"
  exit 1
fi

show_banner

# 2. Identify workspace directory
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="/opt/threatvision-ids"

echo -e "${YELLOW}[*] Detecting and installing system requirements...${NC}"

# Check for apt package manager
if command -v apt-get &> /dev/null; then
    apt-get update
    apt-get install -y tcpdump libpcap-dev python3-pip python3-venv jq
else
    echo -e "${YELLOW}Warning: Non-Debian based system detected. Please ensure 'libpcap-dev' and 'tcpdump' are manually installed.${NC}"
fi

# 3. Stop running services if upgrading
echo -e "${YELLOW}[*] Stopping existing ThreatVision services...${NC}"
systemctl stop threatvision-ids.service 2>/dev/null || true
systemctl stop threatvision-dashboard.service 2>/dev/null || true

# 4. Create destination structure
echo -e "${YELLOW}[*] Preparing installation directory structure...${NC}"
mkdir -p "$DEST_DIR"
mkdir -p "$DEST_DIR/logs"
mkdir -p "$DEST_DIR/attacks"

# 5. Copy workspace files to /opt
echo -e "${YELLOW}[*] Deploying application source files...${NC}"
cp -f "$SRC_DIR/realtime_ids.py" "$DEST_DIR/"
cp -f "$SRC_DIR/live_capture.py" "$DEST_DIR/"
cp -f "$SRC_DIR/requirements.txt" "$DEST_DIR/"
cp -f "$SRC_DIR/uninstall.sh" "$DEST_DIR/"
chmod +x "$DEST_DIR/uninstall.sh"

# Copy directories recursively
cp -rf "$SRC_DIR/models" "$DEST_DIR/"
cp -rf "$SRC_DIR/backend" "$DEST_DIR/"
cp -rf "$SRC_DIR/dashboard" "$DEST_DIR/"

# 6. Setup local Python virtual environment
echo -e "${YELLOW}[*] Setting up isolated Python virtual environment...${NC}"
python3 -m venv "$DEST_DIR/venv"

echo -e "${YELLOW}[*] Installing dependencies in virtual environment (this may take a few minutes)...${NC}"
"$DEST_DIR/venv/bin/pip" install --upgrade pip
"$DEST_DIR/venv/bin/pip" install -r "$DEST_DIR/requirements.txt"

# 7. Create/Preserve Configuration
echo -e "${YELLOW}[*] Establishing configuration file...${NC}"
if [ -f "/etc/threatvision-ids.conf" ]; then
    echo -e "${GREEN}[+] Preserved existing configuration file at /etc/threatvision-ids.conf${NC}"
else
    cp -f "$SRC_DIR/threatvision-ids.conf" /etc/threatvision-ids.conf
    chmod 600 /etc/threatvision-ids.conf
    echo -e "${GREEN}[+] Created default configuration file at /etc/threatvision-ids.conf${NC}"
fi

# 8. Create systemd Service Files
echo -e "${YELLOW}[*] Registering systemd background services...${NC}"

# Dashboard systemd service
cat <<EOF > /etc/systemd/system/threatvision-dashboard.service
[Unit]
Description=ThreatVision AI SOC Dashboard Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$DEST_DIR
EnvironmentFile=-/etc/threatvision-ids.conf
ExecStart=$DEST_DIR/venv/bin/python dashboard/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# IDS Sniffer systemd service
cat <<EOF > /etc/systemd/system/threatvision-ids.service
[Unit]
Description=ThreatVision AI IDS Sniffer Engine
After=network.target threatvision-dashboard.service

[Service]
Type=simple
User=root
WorkingDirectory=$DEST_DIR
EnvironmentFile=-/etc/threatvision-ids.conf
ExecStart=$DEST_DIR/venv/bin/python realtime_ids.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 9. Reload daemon and start/enable services
echo -e "${YELLOW}[*] Activating and starting system services...${NC}"
systemctl daemon-reload
systemctl enable threatvision-dashboard.service
systemctl enable threatvision-ids.service
systemctl start threatvision-dashboard.service
systemctl start threatvision-ids.service

# 10. Install CLI Controller Tool
echo -e "${YELLOW}[*] Installing command line wrapper...${NC}"
cp -f "$SRC_DIR/threatvision-ids" /usr/local/bin/
chmod +x /usr/local/bin/threatvision-ids

# 11. Install Desktop Entry
echo -e "${YELLOW}[*] Creating desktop application shortcut...${NC}"
cp -f "$SRC_DIR/threatvision-ids.desktop" /usr/share/applications/
chmod 644 /usr/share/applications/threatvision-ids.desktop

# Fix permissions on application folder
chown -R root:root "$DEST_DIR"
chmod -R 755 "$DEST_DIR"
# Logs directory must be writable
chmod -R 777 "$DEST_DIR/logs"
chmod -R 777 "$DEST_DIR/attacks"

echo -e "${GREEN}"
echo "======================================================================"
echo "      ThreatVision AI (SentinelX SOC) Installed Successfully!"
echo "======================================================================"
echo -e "${NC}"
echo -e "You can manage ThreatVision AI using the launcher in your application menu,"
echo -e "or via the command line utility:"
echo -e "  - View status:  ${GREEN}threatvision-ids status${NC}"
echo -e "  - Open panel:   ${GREEN}threatvision-ids open${NC}  (or go to http://127.0.0.1:5000)"
echo -e "  - Configure:    ${GREEN}threatvision-ids config${NC} (configure interface or Telegram)"
echo -e "  - IDS Logs:     ${GREEN}threatvision-ids logs-ids${NC}"
echo -e "  - Web Logs:     ${GREEN}threatvision-ids logs-dash${NC}"
echo ""
echo -e "Configuration is stored at: ${CYAN}/etc/threatvision-ids.conf${NC}"
echo -e "Threat logs database is at: ${CYAN}/opt/threatvision-ids/logs/threat_logs.csv${NC}"
echo ""
echo -e "Enjoy monitoring network traffic with ThreatVision AI!"
echo ""
