#!/usr/bin/env bash
# backup_configs.sh - copy the Pi's live configuration into the repo so every
# change you make on the system is recorded in git. Secrets are redacted.
#   cd ~/netguard-pi && sudo ./scripts/backup_configs.sh
#   git add config/snapshots && git commit -m "config: snapshot after <what you changed>"
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO/config/snapshots"
mkdir -p "$OUT"

cp /etc/suricata/suricata.yaml        "$OUT/suricata.yaml"        2>/dev/null
cp /etc/suricata/rules/local.rules    "$OUT/local.rules"          2>/dev/null
cp /etc/logrotate.d/suricata          "$OUT/logrotate-suricata"   2>/dev/null
[ -f /etc/suricata/threshold.config ] && cp /etc/suricata/threshold.config "$OUT/threshold.config"
[ -f /etc/suricata/disable.conf ] && cp /etc/suricata/disable.conf "$OUT/disable.conf"

# FYP-IDS settings with secrets removed
if [ -f /etc/fyp-ids/config.env ]; then
  sed -E 's/^(TELEGRAM_BOT_TOKEN|TELEGRAM_CHAT_ID|SMTP_PASS|SMTP_USER|EMAIL_TO|DASHBOARD_PASS)=.*/\1=<redacted>/' \
      /etc/fyp-ids/config.env > "$OUT/config.env.redacted"
fi

# System facts for the report
{
  echo "# Snapshot taken $(date '+%F %T')"
  echo "## OS";        grep PRETTY_NAME /etc/os-release
  echo "## Kernel";    uname -r
  echo "## Model";     tr -d '\0' < /proc/device-tree/model; echo
  echo "## Suricata";  suricata -V 2>/dev/null
  echo "## Rules loaded"; grep -c '^alert' /var/lib/suricata/rules/suricata.rules 2>/dev/null
  echo "## Interfaces"; ip -br addr
  echo "## Bridge";    bridge link 2>/dev/null
  echo "## Root crontab"; crontab -l 2>/dev/null
  echo "## Services"
  for s in suricata ids-collector ids-dashboard nic-offload; do
    printf '%-16s %s\n' "$s" "$(systemctl is-active $s 2>/dev/null)"
  done
} > "$OUT/system-info.md"

chown -R "${SUDO_USER:-$(id -un)}": "$OUT" 2>/dev/null
echo "Saved to $OUT:"
ls -1 "$OUT"
echo
echo "Now run:  git add config/snapshots && git commit -m \"config: snapshot\""
