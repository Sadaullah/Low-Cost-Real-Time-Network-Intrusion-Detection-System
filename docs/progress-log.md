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
**Evidence:**
**Next:** Clone repo on the Pi, load custom rules, run setup.sh, Telegram alerts.
**Hours:**
