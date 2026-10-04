# Methodology

## Project Title

NetGuard Pi – Low-Cost Real-Time Network Intrusion Detection System

## 1. Research Approach

This project follows a practical experimental approach. A Raspberry Pi 4 will be configured as a dedicated Network Intrusion Detection System sensor using Suricata.

The system will monitor network traffic in a controlled lab environment, detect suspicious activities, generate alerts, and store security events for analysis.

## 2. Lab Environment

The test environment will contain:

- Raspberry Pi 4 – IDS Sensor
- Suricata – Detection Engine
- Kali Linux – Security Testing Machine
- Windows or Linux PC – Victim Machine
- Router
- Managed Network Switch

The laboratory environment will be isolated from production systems.

## 3. Network Monitoring

The managed switch will be configured using port mirroring.

Traffic generated between the test systems will be copied to the Raspberry Pi monitoring interface.

The Raspberry Pi will operate mainly as a passive IDS sensor.

## 4. Intrusion Detection

Suricata will inspect captured network traffic using detection rules.

The project will initially focus on detecting:

- ICMP traffic
- Port scanning
- SYN scanning
- Service scanning
- Repeated login attempts / brute-force behaviour
- Selected suspicious network traffic

## 5. Logging

Suricata logs will be collected from files such as:

- eve.json
- fast.log
- stats.log
- suricata.log

The `eve.json` file will be used as the main structured event source.

## 6. Alert Processing

A Python script will be developed to read Suricata alerts from `eve.json`.

The script will extract information such as:

- Timestamp
- Source IP
- Destination IP
- Source Port
- Destination Port
- Protocol
- Alert Signature
- Severity

The extracted information may later be used for notifications and dashboard visualization.

## 7. Security Testing

Controlled security tests will be performed only inside the lab environment.

Each experiment will have:

- Test ID
- Objective
- Test traffic
- Expected result
- Actual result
- Suricata alert
- Performance measurements

## 8. Performance Evaluation

The Raspberry Pi IDS will be evaluated using:

- Detection rate
- False positives
- False negatives
- CPU usage
- RAM usage
- Alert latency
- Network performance
- System temperature

## 9. Result Analysis

The results from different security tests will be recorded and compared.

Graphs and tables will be prepared to show:

- Number of detected attacks
- Detection rate by attack type
- False-positive behaviour
- CPU and RAM usage
- Average alert latency

## 10. Final Output

The final project is expected to provide:

- A working Raspberry Pi-based IDS
- Real-time Suricata monitoring
- Custom and community detection rules
- Structured security logs
- Python-based alert processing
- Security event visualization
- Performance evaluation results
