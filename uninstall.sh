#!/bin/bash

# ==============================================================================
# ThreatVision AI (SentinelX SOC) — Uninstaller Script
# ==============================================================================

# Exit immediately if a command exits with a non-zero status
set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "======================================================================"
echo "          ThreatVision AI — System-wide Uninstaller"
echo "======================================================================"
echo -e "${NC}"

# 1. Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Please run this uninstaller as root (e.g., sudo ./uninstall.sh).${NC}"
  exit 1
fi

# 2. Stop and disable systemd services
echo -e "${YELLOW}[*] Stopping and disabling systemd services...${NC}"
systemctl stop threatvision-ids.service 2>/dev/null || true
systemctl stop threatvision-dashboard.service 2>/dev/null || true
systemctl disable threatvision-ids.service 2>/dev/null || true
systemctl disable threatvision-dashboard.service 2>/dev/null || true

# 3. Clean up systemd configuration
echo -e "${YELLOW}[*] Removing systemd service files...${NC}"
rm -f /etc/systemd/system/threatvision-ids.service
rm -f /etc/systemd/system/threatvision-dashboard.service
systemctl daemon-reload

# 4. Remove binaries, launchers, and menu items
echo -e "${YELLOW}[*] Removing CLI controller and desktop launcher...${NC}"
rm -f /usr/local/bin/threatvision-ids
rm -f /usr/share/applications/threatvision-ids.desktop

# 5. Flush firewall block rules set by the IPS engine
echo -e "${YELLOW}[*] Restoring iptables firewall state...${NC}"
if [ -f "/opt/threatvision-ids/logs/blacklist.json" ]; then
    # Attempt to read IPs and remove rules
    if command -v jq &> /dev/null; then
        IPS=$(jq -r 'keys[]' /opt/threatvision-ids/logs/blacklist.json 2>/dev/null || true)
        for IP in $IPS; do
            echo -e "${YELLOW}    - Removing iptables rule for IP: ${IP}${NC}"
            iptables -D INPUT -s "$IP" -j DROP 2>/dev/null || true
        done
    else
        echo -e "${YELLOW}    - jq tool not found. Re-checking iptables for INPUT DROP rules...${NC}"
        # Fallback: remove input drops referencing blocked ips
        iptables-save | grep "DROP" | awk '{print $4}' | while read -r IP; do
            # Verify if it is an IP address
            if [[ $IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                iptables -D INPUT -s "$IP" -j DROP 2>/dev/null || true
            fi
        done
    fi
fi

# 6. Backup configuration and threat logs before deletion
echo -e "${YELLOW}[*] Backing up configuration and database logs...${NC}"

BACKUP_DIR="/var/log/threatvision-ids-backup-$(date +%Y%m%d%H%M%S)"
mkdir -p "$BACKUP_DIR"

if [ -f "/etc/threatvision-ids.conf" ]; then
    cp /etc/threatvision-ids.conf "$BACKUP_DIR/threatvision-ids.conf.bak"
    rm -f /etc/threatvision-ids.conf
    echo -e "${GREEN}    - Configuration backed up to: $BACKUP_DIR/threatvision-ids.conf.bak${NC}"
fi

if [ -d "/opt/threatvision-ids/logs" ]; then
    cp -r /opt/threatvision-ids/logs "$BACKUP_DIR/logs"
    echo -e "${GREEN}    - Threat logs database backed up to: $BACKUP_DIR/logs/${NC}"
fi

# 7. Remove files from /opt
echo -e "${YELLOW}[*] Deleting application source files...${NC}"
rm -rf /opt/threatvision-ids

echo -e "${GREEN}"
echo "======================================================================"
echo "   Uninstall complete! ThreatVision AI is removed from your system."
echo "======================================================================"
echo -e "${NC}"
