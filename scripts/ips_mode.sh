#!/usr/bin/env bash
# =====================================================================
#  ips_mode.sh - switch NetGuard Pi from passive IDS to INLINE IPS
#
#  In IPS mode the Pi inspects each packet on the monitoring interface
#  (eth0) BEFORE the kernel delivers it, using Suricata + NFQUEUE, and
#  drops anything that matches a rule in rules/ips.rules. Attacks are
#  therefore PREVENTED, not just detected.
#
#  SAFETY:
#   * NFQUEUE is scoped to eth0 only, so Wi-Fi management (RealVNC / SSH
#     on wlan0, 192.168.1.x) is never intercepted - you cannot lock
#     yourself out.
#   * --queue-bypass means if Suricata stops, eth0 traffic flows normally
#     instead of being blackholed.
#
#  Usage:  sudo ./scripts/ips_mode.sh
#  Revert: sudo ./scripts/ids_mode.sh
# =====================================================================
set -euo pipefail

IFACE="${IPS_IFACE:-eth0}"
QNUM=0
YAML=/etc/suricata/suricata.yaml
IPS_RULES=/etc/suricata/rules/ips.rules
RUNDIR=/var/run/fyp-ips
PIDFILE="$RUNDIR/suricata-ips.pid"
LOGDIR=/var/log/suricata

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo."; exit 1; }

# --- preflight ------------------------------------------------------
if ! suricata --build-info 2>/dev/null | grep -qi 'NFQueue support.*yes'; then
  echo "ERROR: this Suricata build has no NFQUEUE support; cannot run inline IPS."
  echo "       (check:  suricata --build-info | grep -i nfqueue )"
  exit 1
fi
[ -f "$IPS_RULES" ] || { echo "ERROR: $IPS_RULES not found. Copy rules/ips.rules there first."; exit 1; }
mkdir -p "$RUNDIR"

echo "[*] Stopping passive IDS service so it does not contend with inline mode..."
systemctl stop suricata 2>/dev/null || true
# stop any previous inline instance
[ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null || true
pkill -f 'suricata.*-q 0' 2>/dev/null || true
sleep 1

echo "[*] Inserting NFQUEUE rules on $IFACE (queue $QNUM, bypass on fail)..."
# remove any leftovers first (idempotent)
while iptables -C INPUT  -i "$IFACE" -m comment --comment FYP-IPS -j NFQUEUE --queue-num $QNUM --queue-bypass 2>/dev/null; do
  iptables -D INPUT  -i "$IFACE" -m comment --comment FYP-IPS -j NFQUEUE --queue-num $QNUM --queue-bypass; done
while iptables -C OUTPUT -o "$IFACE" -m comment --comment FYP-IPS -j NFQUEUE --queue-num $QNUM --queue-bypass 2>/dev/null; do
  iptables -D OUTPUT -o "$IFACE" -m comment --comment FYP-IPS -j NFQUEUE --queue-num $QNUM --queue-bypass; done
iptables -I INPUT  -i "$IFACE" -m comment --comment FYP-IPS -j NFQUEUE --queue-num $QNUM --queue-bypass
iptables -I OUTPUT -o "$IFACE" -m comment --comment FYP-IPS -j NFQUEUE --queue-num $QNUM --queue-bypass

echo "[*] Starting Suricata INLINE (-q $QNUM) with alert rules + drop rules..."
# -q 0      : read packets from NFQUEUE 0 (inline) instead of sniffing
# -S ips.rules : additionally load our drop rules on top of the yaml rules
suricata -c "$YAML" -q $QNUM -S "$IPS_RULES" -l "$LOGDIR" \
         --pidfile "$PIDFILE" -D

sleep 3
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo
  echo "============================================================"
  echo " IPS MODE ACTIVE  (inline on $IFACE, NFQUEUE $QNUM)"
  echo "   drop rules : $(grep -c '^drop' "$IPS_RULES") loaded from ips.rules"
  echo "   alerts     : still logged to eve.json (dashboard + e-mail work)"
  echo "   blocked    : matching attacks are dropped and logged action=blocked"
  echo
  echo " Watch live :  tail -f $LOGDIR/eve.json | grep -E 'blocked|FYP-IPS'"
  echo " Revert     :  sudo ./scripts/ids_mode.sh"
  echo "============================================================"
else
  echo "ERROR: inline Suricata did not start. Check $LOGDIR/suricata.log"
  echo "Rolling back NFQUEUE rules..."
  iptables -D INPUT  -i "$IFACE" -m comment --comment FYP-IPS -j NFQUEUE --queue-num $QNUM --queue-bypass 2>/dev/null || true
  iptables -D OUTPUT -o "$IFACE" -m comment --comment FYP-IPS -j NFQUEUE --queue-num $QNUM --queue-bypass 2>/dev/null || true
  exit 1
fi
