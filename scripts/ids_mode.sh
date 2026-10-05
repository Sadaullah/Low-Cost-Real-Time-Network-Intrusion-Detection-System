#!/usr/bin/env bash
# =====================================================================
#  ids_mode.sh - switch NetGuard Pi back from inline IPS to passive IDS
#
#  Stops the inline Suricata, removes the NFQUEUE rules from eth0, and
#  restarts the normal passive Suricata service (AF-PACKET sniffing).
#
#  Usage: sudo ./scripts/ids_mode.sh
# =====================================================================
set -euo pipefail

IFACE="${IPS_IFACE:-eth0}"
QNUM=0
RUNDIR=/var/run/fyp-ips
PIDFILE="$RUNDIR/suricata-ips.pid"

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo."; exit 1; }

echo "[*] Stopping inline Suricata..."
[ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null || true
pkill -f 'suricata.*-q 0' 2>/dev/null || true
rm -f "$PIDFILE"
sleep 1

echo "[*] Removing NFQUEUE rules from $IFACE..."
while iptables -C INPUT  -i "$IFACE" -m comment --comment FYP-IPS -j NFQUEUE --queue-num $QNUM --queue-bypass 2>/dev/null; do
  iptables -D INPUT  -i "$IFACE" -m comment --comment FYP-IPS -j NFQUEUE --queue-num $QNUM --queue-bypass; done
while iptables -C OUTPUT -o "$IFACE" -m comment --comment FYP-IPS -j NFQUEUE --queue-num $QNUM --queue-bypass 2>/dev/null; do
  iptables -D OUTPUT -o "$IFACE" -m comment --comment FYP-IPS -j NFQUEUE --queue-num $QNUM --queue-bypass; done

echo "[*] Restarting passive IDS service..."
systemctl start suricata
sleep 2
if systemctl is-active --quiet suricata; then
  echo
  echo "============================================================"
  echo " IDS MODE ACTIVE  (passive sniffing on $IFACE)"
  echo "   Suricata only alerts; it does not drop traffic."
  echo "   Go inline again:  sudo ./scripts/ips_mode.sh"
  echo "============================================================"
else
  echo "WARNING: passive suricata service is not active. Check: systemctl status suricata"
fi
