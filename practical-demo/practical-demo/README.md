# Practical Demo: NetGuard Pi Network IDS

Demo of a Suricata-based network intrusion detection system running on a Raspberry Pi.

## Setup
- **Attacker:** Kali Linux VM (192.168.10.20), running Nmap scans
- **Sensor/Target:** Raspberry Pi `netguard-pi` (192.168.10.50)
- **Dashboard:** NetGuard Pi, a live web view of Suricata alerts (refreshes every 5 s)

## What was demonstrated
- An Nmap SYN scan (`nmap -sS 192.168.10.50`) found open ports 21 (FTP), 22 (SSH), 80 (HTTP), 5900 (VNC) and 8080.
- The IDS detected the scans and also flagged possible FTP and SSH brute-force attempts.
- The dashboard showed 37 alerts in 24 hours (2 high, 6 medium, 29 low), all from one attacker, with an average alert delay of 3.49 s.

## Screenshots
1. `01-raspberry-pi-desktop.jpeg`: Raspberry Pi desktop via VNC
2. `02-kali-nmap-scan.jpeg`: Nmap scan from Kali
3. `03-netguard-dashboard-overview.jpeg`: Dashboard overview (alerts, top attackers, most targeted)
4. `04-netguard-latest-alerts.jpeg`: Latest alerts table with sensor health
