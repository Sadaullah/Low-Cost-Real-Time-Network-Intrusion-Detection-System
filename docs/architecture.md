# Network Architecture

## Project
NetGuard Pi – Low-Cost Real-Time Network Intrusion Detection System

## Purpose
This document describes the network architecture used for the Raspberry Pi-based Intrusion Detection System.

## Components

- Raspberry Pi 4 (8 GB, 32 GB SD) – IDS Sensor
- Suricata – Intrusion Detection Engine
- Kali Linux – Test/Attacker Machine
- Victim PC – Windows or Linux (Metasploitable 2 VM recommended)
- Router
- Managed Switch (option A) or USB 3.0 Gigabit Ethernet adapter (option B)
- Internet Connection

## Option A – Port mirroring (managed switch)

```
Internet
|
Router
|
Managed Switch  (mirror: victim + Kali ports -> Pi port)
|--- Victim PC
|--- Raspberry Pi IDS Sensor  (eth0 = monitor interface)
|--- Kali Linux Test Machine
```

The Raspberry Pi receives a copy of the traffic through switch port mirroring (SPAN).
Suricata inspects the mirrored traffic and generates alerts. The Pi is fully passive:
if it fails, the network keeps working.

## Option B – Inline transparent bridge (no managed switch needed)

```
Internet
|
Router ---- Kali Linux Test Machine (Wi-Fi or cable)
|
[eth0]  Raspberry Pi IDS Sensor  (br0 bridge)  [eth1 = USB 3.0 adapter]
|
Victim PC (or unmanaged switch with several victims)
```

Every packet to the victim physically passes through the Pi, so Suricata sees all of it.
Setup: `sudo ./scripts/bridge_setup.sh 192.168.1.50/24 192.168.1.1`.
This option also allows a later IPS mode (blocking), listed as future work.

## Comparison

| | Option A: port mirroring | Option B: inline bridge |
| --- | --- | --- |
| Extra hardware | Managed switch with SPAN | USB 3.0 Gigabit adapter (~2,500 PKR) |
| Traffic seen | All mirrored ports | All traffic through the Pi |
| Effect if Pi fails | None (passive) | Victim side loses network |
| Can block attacks (IPS) | No | Yes (future work) |
| Packet loss risk | Mirror port can drop under heavy load | Limited by Pi throughput |

## Software pipeline on the Pi

```
packets -> Suricata (18 custom rules; ET Open evaluated during development, disabled in final build)
        -> /var/log/suricata/eve.json
        -> collector (Python service) -> SQLite -> Flask dashboard :8080
                                      -> Telegram / e-mail alert
        -> ip_blocker.py (reads eve.json) -> iptables auto-block (5 alerts / 30 s, 10-min ban)
```

## Addressing (lab)

| Device | IP |
| --- | --- |
| Router | 192.168.1.1 |
| Raspberry Pi sensor | 192.168.1.50 (static) |
| Victim PC | 192.168.1.60 |
| Kali | DHCP |

## Status

Architecture design: final. In the final lab tests the Pi itself was the target host:
Kali `192.168.10.20` attacked the Pi `192.168.10.50` (eth0) on the `192.168.10.0/24` lab subnet,
with management over Wi-Fi (`wlan0`). Options A and B above remain the deployment paths for
monitoring other hosts (listed as future work in the report).
