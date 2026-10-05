#!/usr/bin/env bash
# bridge_setup.sh - turn the Pi into a transparent bridge (eth0 + USB eth1 = br0)
# Run with a monitor + keyboard attached: SSH will drop while the network changes.
#   sudo ./scripts/bridge_setup.sh 192.168.1.50/24 192.168.1.1
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo"; exit 1; }
IP=${1:?usage: bridge_setup.sh <pi-ip/cidr> <gateway>}
GW=${2:?usage: bridge_setup.sh <pi-ip/cidr> <gateway>}
ip link show eth1 >/dev/null 2>&1 || { echo "eth1 not found - plug the USB adapter into a blue USB 3.0 port"; exit 1; }

OLD=$(nmcli -t -f NAME,DEVICE con show --active | awk -F: '$2=="eth0"{print $1}')
nmcli con add type bridge ifname br0 con-name br0 bridge.stp no \
  ipv4.method manual ipv4.addresses "$IP" ipv4.gateway "$GW" ipv4.dns "$GW"
nmcli con add type ethernet ifname eth0 master br0 con-name br0-eth0
nmcli con add type ethernet ifname eth1 master br0 con-name br0-eth1
[ -n "$OLD" ] && nmcli con down "$OLD" || true
nmcli con up br0

sed -i 's/^\(\s*- interface:\s*\)eth0/\1br0/' /etc/suricata/suricata.yaml
ethtool -K eth0 gro off lro off || true
ethtool -K eth1 gro off lro off || true
systemctl restart suricata
echo "Bridge up:"; ip -br addr show br0; bridge link
echo "Suricata now listens on br0. Check: sudo tcpdump -i br0 -c 20 not port 22"
