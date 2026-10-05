# Performance evaluation (Chapter 5)

This proves the "low-cost, real-time" claims in the project title: the Pi
keeps up with traffic and stays healthy while detecting attacks.

## How to collect the data

Run the benchmark **three times**, once per condition, while generating
the matching traffic. Each run samples CPU / RAM / temperature every 2 s,
averages them, and reads Suricata's own packet + drop counters to compute
the packet-drop percentage. Each run appends one clean row to
`results/performance-results.csv`.

```bash
sudo apt-get install -y jq        # once

# 1) Idle — no attack traffic, just let it run
sudo ./scripts/perf_benchmark.sh "Suricata idle" 60

# 2) Normal load — generate steady traffic from Kali (needs iperf3)
#    Pi:    iperf3 -s
#    Kali:  iperf3 -c 192.168.10.50 -t 60
sudo ./scripts/perf_benchmark.sh "Normal load (iperf3)" 60

# 3) Under attack — run a flood from Kali during the window
#    Kali:  sudo hping3 -1 --flood 192.168.10.50   (ICMP flood)
#       or: sudo hping3 -S -p 80 --flood 192.168.10.50  (SYN flood)
sudo ./scripts/perf_benchmark.sh "Under attack flood" 60
```

## Build the table and chart

```bash
pip3 install --user matplotlib        # once
python3 scripts/perf_report.py
```

This writes:
* `results/performance-table.md` — the table to paste into Chapter 5
* `docs/images/week4-results/fig_performance.png` — the bar chart (CPU,
  RAM, temperature, packet drop across the three conditions)

## What the numbers should show (and how to discuss them)

* **CPU**: low at idle, moderate under normal load, highest during a
  flood — but the Pi 4 (quad-core) still copes.
* **RAM**: roughly flat (~1.7 GB) — the ~50k rule set is loaded once; the
  Pi's 8 GB is far more than enough.
* **Temperature**: stays well under the 80 °C throttling point; no cooling
  problems. (`vcgencmd get_throttled` should read `0x0`.)
* **Packet drop**: 0 % under normal traffic and during scans — so no real
  attack is missed. Drop rises only during an extreme artificial flood
  (hundreds of thousands of packets), and even then detection still fires
  because the flood volume is far above the alert threshold. This is an
  honest limitation to state: a single low-cost Pi sensor has a throughput
  ceiling, which is why a flood both triggers the DoS rule *and* shows
  some drop.

Keep the discussion honest — the drop under flood is a real, expected
result for a ~$70 sensor and is worth explaining rather than hiding.
