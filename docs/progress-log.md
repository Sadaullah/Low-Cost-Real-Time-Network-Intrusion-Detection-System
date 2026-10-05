# Progress Log

One entry per working day. Write it before you stop (5 minutes).
This diary becomes Chapter 4 (Implementation) and proves the work is the team's own.

**Template – copy for each day:**

```
## Day N – YYYY-MM-DD  (who: Sada / Noroz / Aashan)

**Goal:** what we planned
**Done:**
- step (command / file changed)
**Problems & fixes:**
- error -> fix (also add to troubleshooting.md)
**Evidence:** docs/images/weekX-.../filename.png
**Next:** plan for tomorrow
**Hours:**
```

---

## Work completed before this log started

- Raspberry Pi 4 set up with Suricata
- 50,184 Suricata ET detection rules loaded
- SYN scan, port scan and service scan detection tested
- First alert script written (ids_alert.py)
- Remote access configured: PuTTY (SSH) and RealVNC
- Docs written: README, architecture, methodology

_(Add dates and screenshots for these if you have them.)_

---

## Day 1 – 2026-10-05

**Goal:** Organise the repository; add custom rules, collector, dashboard and test plan.
**Done:**
- Added repository structure (rules, collector, dashboard, scripts, systemd, results, report)
- Added 13 custom Suricata rules and the offline rule test
- Filled docs/test-plan.md with 9 attack test cases
- Fixed suricata.yaml: HOME_NET "[192.168.10.0/24,192.168.1.0/24]", EXTERNAL_NET "any" (backup saved as suricata.yaml.bak-2026-10-05)
- Saved the team's first rules into rules/team-rules-v1.rules (SID 9000001-9000005)
**Problems & fixes:**
- HOME_NET listed 10.182.215.139/16, 10.0.0.0/8, 172.16.0.0/12 but the lab is 192.168.10.x / 192.168.1.x, so rules using $HOME_NET never matched lab traffic -> set HOME_NET to the lab networks
- `suricata -T ... -q` failed: in Suricata `-q` means NFQUEUE mode, not "quiet" -> removed the flag (also fixed in scripts/setup.sh)
- Pi had no internet: netplan file /etc/netplan/90-NM-75a1216a-...yaml had a default route via 192.168.10.1 on eth0 (no internet there) -> removed with `nmcli con mod netplan-eth0 ipv4.routes ""`; internet now goes via Wi-Fi (wlan0, 192.168.1.1)
- Design decision: eth0 (RJ45, 192.168.10.50) = monitoring interface, wlan0 (Wi-Fi, 192.168.1.13) = management (internet, RealVNC, Telegram)
- Cloned repo on the Pi, loaded 13 custom rules next to the team rules, ran scripts/setup.sh (collector + dashboard + nic-offload services all active)
- Offline rule test on the Pi: 12/12 test cases detected, 0 false positives (results/raw)
- Dashboard live at http://192.168.1.13:8080
- Tuned team rule 9000001 (rev 1 -> rev 2): it fired on every IPv6 neighbour-discovery packet (23 false positives in ~20 min); now ICMP echo requests to $HOME_NET only, max 1 alert/min per source
- Telegram API blocked on this ISP (HTTP 000 timeouts) -> switched alerts to Gmail SMTP (port 587 open)
- First live detection: ping from laptop (192.168.10.1) to Pi (192.168.10.50) -> rule 9000001 -> e-mail alert received on phone at 17:37
**Evidence:**
- docs/images/week1-setup/01-first-live-alert-email.jpg
- docs/images/week1-setup/02-dashboard-first-live-alerts.png
**Next:** see Day 1 (evening).

## Day 1 (evening) – 2026-10-05

**Goal:** Run test T1 (TCP SYN port scan) 5 times, tune problems found.
**Done:**
- Installed Nmap 7.80 on the laptop (attacker 192.168.10.1, cable side)
- T1 run 1 (17:59): detected by 1000001, 9000002, 9000003, 9000004; e-mails received
- Tuned 9000002-9000005 (type threshold -> type both) and 1000008 (500 -> 2000 SYNs / 2 s)
- T1 runs 2-5 (18:35-18:38): 4/4 detected, 1 alert per rule per scan, no false SYN-flood alert
- T1 result: 5/5 runs detected = 100 % detection rate; detection 2-3 s after Nmap start; first e-mail 2.9-8.4 s after the alert
**Problems & fixes:**
- Alert flood from team rules (dozens of identical rows per scan) -> `type both`
- Port scan also reported as SYN flood (scan/flood overlap) -> raised flood threshold
- Later e-mails in a burst are slower (about +3 s each: 3, 6, 9, 12 s) because the collector sends e-mails one by one over SMTP -> possible improvement: one SMTP connection / one summary e-mail per burst
- Pi has port 111 (rpcbind) open -> not needed, to disable as hardening
**Evidence:**
- docs/images/week3-testing/T1-run1-*.png/.jpg, T1-runs2-5-*.png/.jpg
- Found false positive 2233001 (RFB/VNC anomaly) from the admin's own RealVNC session -> suppressed for the admin laptop only (config/suricata/threshold.config)
- Pi froze once (desktop/VNC hang); after reboot all 4 services came back automatically. Health: 49.6 °C, throttled=0x0 (power OK), RAM 1.6/7.6 GB, SD 34 % -> no hardware cause found
- Enabled persistent journal (max 100 MB) so the cause of any future hang can be read after reboot
**Next:** T2 stealth scans (XMAS / NULL / FIN), then T5 SSH brute force.
**Hours:**
