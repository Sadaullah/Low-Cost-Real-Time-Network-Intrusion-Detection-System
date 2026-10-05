# NetGuard Pi — Low-Cost Real-Time NIDS/NIPS

A real-time Network Intrusion Detection System built on Raspberry Pi 4 using Suricata,
with an optional prevention (IPS) layer. BS Cyber Security Final Year Project.

## Cost: ~$70 (PKR 21,000)

## Features
- Detects SYN scans, port scans, and service scans
- Detects stealth scans (XMAS / NULL / FIN), ICMP and SYN floods, SSH and FTP brute force,
  SQL injection, XSS and malware downloads (EICAR test file)
- 50,184 Suricata ET detection rules loaded, plus 13 custom rules ([rules/local.rules](rules/local.rules))
- **Prevention (IPS):** inline NFQUEUE mode drops attacks in real time
  ([rules/ips.rules](rules/ips.rules), [scripts/ips_mode.sh](scripts/ips_mode.sh)) — see [docs/ips-mode.md](docs/ips-mode.md)
- **Active response:** auto-blocks attacker IPs with iptables after repeated alerts
  ([collector/ip_blocker.py](collector/ip_blocker.py))
- Real-time alerts collector service with Telegram / e-mail notifications and
  alert-delay measurement ([collector/](collector/))
- Password-protected web dashboard: live alerts, alerts per minute, top attackers,
  sensor health, CSV export ([dashboard/](dashboard/))
- Performance benchmarking: CPU / RAM / temperature / packet-drop under idle, load and
  attack ([scripts/perf_benchmark.sh](scripts/perf_benchmark.sh), [docs/performance.md](docs/performance.md))
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
                                                          \-> e-mail alert
                                                          \-> ip_blocker -> iptables (auto-block)
```

Detection runs passively (IDS). For prevention the Pi can run **inline (IPS)** on `eth0`
via NFQUEUE and drop matching packets, or stay passive and **auto-block** attacker IPs
after repeated alerts. Details: [docs/ips-mode.md](docs/ips-mode.md).

## Project status

| Week | Dates | Goal | Status |
| --- | --- | --- | --- |
| 1 | 5–11 Oct 2026 | Suricata running, ET rules loaded, first detection | ✅ Done |
| 2 | 12–18 Oct 2026 | Traffic capture, custom rules, alerts | ✅ Done |
| 3 | 19–25 Oct 2026 | Dashboard, 9 attack tests, performance tests | ✅ Done |
| 4 | 26 Oct–1 Nov 2026 | Prevention (IPS + auto-block), results, report, presentation | ⏳ In progress |

Daily work: [docs/progress-log.md](docs/progress-log.md)

## Repository structure

```
├── README.md
├── rules/
│   ├── local.rules            custom detection (alert) rules
│   └── ips.rules              prevention (drop) rules for inline IPS mode
├── collector/
│   ├── ids_collector.py       eve.json -> SQLite + e-mail alerts
│   └── ip_blocker.py          active response: auto-block attacker IPs
├── dashboard/                 Flask web dashboard
├── config/                    config template, suricata.yaml changes, logrotate, Pi snapshots
├── systemd/                   service files (collector, dashboard, blocker, nic-offload)
├── scripts/
│   ├── ips_mode.sh            switch to inline IPS (NFQUEUE on eth0)
│   ├── ids_mode.sh            switch back to passive IDS
│   ├── perf_benchmark.sh      measure CPU/RAM/temp/drop per scenario
│   ├── perf_report.py         build the performance table + chart
│   └── ...                    setup, bridge, config backup, tests
├── tests/evidence/            alert log extracts per test run
├── results/                   attack and performance results (CSV)
├── docs/
│   ├── architecture.md        network architecture
│   ├── methodology.md         research methodology
│   ├── test-plan.md           9 attack test cases with Kali commands
│   ├── ips-mode.md            IPS mode + auto-blocking (how-to + demo)
│   ├── performance.md         performance evaluation (Chapter 5)
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
Full guide: [docs/setup-guide.md](docs/setup-guide.md) · Prevention: [docs/ips-mode.md](docs/ips-mode.md)

## Ethics

All tests are run only in an isolated lab on devices owned by the team.
Do not use these tools on networks you do not own or have written permission to test.

## License

MIT – see [LICENSE](LICENSE).
