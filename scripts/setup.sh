#!/usr/bin/env bash
# setup.sh - install the FYP-IDS add-ons on the Raspberry Pi
# Run from the project folder AFTER Suricata is installed and working:
#   cd ~/netguard-pi && sudo ./scripts/setup.sh
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"

echo "[1/6] Packages"
apt-get install -y -q python3-flask python3-scapy jq ethtool git >/dev/null

echo "[2/6] Custom rules -> /etc/suricata/rules/local.rules"
mkdir -p /etc/suricata/rules
install -m 644 "$SRC/rules/local.rules" /etc/suricata/rules/local.rules
grep -q "/etc/suricata/rules/local.rules" /etc/suricata/suricata.yaml ||
  echo "  !! Add '- /etc/suricata/rules/local.rules' under rule-files: in suricata.yaml"

install -m 644 "$SRC/config/logrotate/suricata" /etc/logrotate.d/suricata

echo "[3/6] Program files -> /opt/fyp-ids"
id fyp-ids >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin fyp-ids
mkdir -p /opt/fyp-ids /var/lib/fyp-ids /etc/fyp-ids
cp -r "$SRC/collector" "$SRC/dashboard" "$SRC/scripts" /opt/fyp-ids/
# collector (root) writes the DB; dashboard (user fyp-ids) reads it via the group
chown root:fyp-ids /var/lib/fyp-ids && chmod 2770 /var/lib/fyp-ids

echo "[4/6] Config -> /etc/fyp-ids/config.env"
if [ ! -f /etc/fyp-ids/config.env ]; then
  install -m 640 -g fyp-ids "$SRC/config/config.env.example" /etc/fyp-ids/config.env
  PW=$(head -c 12 /dev/urandom | base64 | tr -d '/+=')
  sed -i "s/^DASHBOARD_PASS=.*/DASHBOARD_PASS=$PW/" /etc/fyp-ids/config.env
  echo "  Dashboard login: admin / $PW   (change it in /etc/fyp-ids/config.env)"
fi

echo "[5/6] systemd services"
install -m 644 "$SRC"/systemd/*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now nic-offload.service ids-collector.service
sleep 2
systemctl enable --now ids-dashboard.service

echo "[6/6] Test rules and restart Suricata"
suricata -T -c /etc/suricata/suricata.yaml -q && systemctl restart suricata
IP=$(hostname -I | awk '{print $1}')
echo
echo "Done. Dashboard: http://$IP:8080"
echo "Add your Telegram token/chat id to /etc/fyp-ids/config.env, then:"
echo "  sudo systemctl restart ids-collector"
