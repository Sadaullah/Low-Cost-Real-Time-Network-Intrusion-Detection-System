# NetGuard Pi — Low-Cost Real-Time NIDS

A real-time Network Intrusion Detection System built on Raspberry Pi 4 using Suricata.
BS Cyber Security Final Year Project.

## Cost: ~$70 (PKR 21,000)

## Features
- Detects SYN scans, port scans, and service scans
- Detects stealth scans (XMAS / NULL / FIN), ICMP and SYN floods, SSH and FTP brute force,
  SQL injection, XSS and malware downloads (EICAR test file)
- 50,184 Suricata ET detection rules loaded, plus 13 custom rules ([rules/local.rules](rules/local.rules))
- Real-time alerts via Python script (ids_alert.py), extended into a collector service with
  Telegram / e-mail notifications and alert-delay measurement ([collector/](collector/))
- Password-protected web dashboard: live alerts, alerts per minute, top attackers,
  sensor health, CSV export ([dashboard/](dashboard/))
- Offline rule regression test: pcap generator + PASS/FAIL checker ([scripts/](scripts/))
- Remote access via PuTTY (SSH) and RealVNC

## Team
- Sada Ullah (45871)
- Syed Noroz Ali (45496)
- Muhammad Aashan Hussain (43914)

## Supervisor
Dr. Muhammad Mansoor Alam

## Architecture

```
Kali attacker -> Router -> Raspberry Pi 4 (Suricata sensor) -> Victim PC
                                   |
   Suricata (ET Open + local.rules) -> eve.json -> Collector -> SQLite -> Dashboard :8080
                                                          \-> Telegram / e-mail alert
```

The Pi receives traffic by **switch port mirroring** (managed switch) or as an
**inline transparent bridge** (USB Ethernet adapter). Details: [docs/architecture.md](docs/architecture.md).

## Project status

| Week | Dates | Goal | Status |
| --- | --- | --- | --- |
| 1 | 5–11 Oct 2026 | Suricata running, ET rules loaded, first detection | ⏳ In progress |
| 2 | 12–18 Oct 2026 | Traffic capture (mirror/bridge), custom rules, Telegram alerts | ⬜ Not started |
| 3 | 19–25 Oct 2026 | Dashboard, 9 attack tests, performance tests | ⬜ Not started |
| 4 | 26 Oct–1 Nov 2026 | Results, report, presentation | ⬜ Not started |

Daily work: [docs/progress-log.md](docs/progress-log.md)

## Repository structure

```
├── README.md
├── rules/local.rules          custom Suricata rules
├── collector/                 eve.json -> SQLite + Telegram / e-mail alerts
├── dashboard/                 Flask web dashboard
├── config/                    config template, suricata.yaml changes, logrotate, Pi snapshots
├── systemd/                   service files (start at boot)
├── scripts/                   setup, bridge, config backup, tests, performance logger
├── tests/evidence/            alert log extracts per test run
├── results/                   attack and performance results (CSV)
├── docs/
│   ├── architecture.md        network architecture
│   ├── methodology.md         research methodology
│   ├── test-plan.md           9 attack test cases with Kali commands
│   ├── setup-guide.md         step-by-step installation
│   ├── progress-log.md        daily diary
│   ├── rule-tuning-log.md     every rule change and why
│   ├── troubleshooting.md     errors and fixes
│   └── images/                screenshots by week
└── report/                    report chapters and slides
```

## Quick start

```bash
git clone https://github.com/Sadaullah/Low-Cost-Real-Time-Network-Intrusion-Detection-System.git netguard-pi
cd netguard-pi && sudo ./scripts/setup.sh
```
Full guide: [docs/setup-guide.md](docs/setup-guide.md)

## Ethics

All tests are run only in an isolated lab on devices owned by the team.
Do not use these tools on networks you do not own or have written permission to test.

## License

MIT – see [LICENSE](LICENSE).
