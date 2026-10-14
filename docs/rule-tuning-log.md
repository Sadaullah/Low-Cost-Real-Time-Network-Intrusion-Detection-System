# Rule Tuning Log

Every change to `rules/local.rules` or to the ET Open ruleset (disable / suppress /
threshold) is recorded here. This table goes straight into Chapter 5
("False-positive analysis and tuning").

| Date | Rule SID | Change (before -> after) | Reason / evidence | Effect |
| --- | --- | --- | --- | --- |
| 2026-10-05 | 1000001–1000013 | Initial version of 13 custom rules | Offline pcap test: 12/12 detected, 0 FP | Baseline |
| 2026-10-05 | 9000001 | rev 1 `alert icmp any any -> any any` -> rev 2 `alert icmp any any -> $HOME_NET any; itype:8; threshold limit 1/60s by_src` | 23 alerts in ~20 min from IPv6 neighbour discovery (fe80:: -> ff02::1:ff00:1), normal traffic | Only real pings alert, max 1/min per source; first live ping detected and e-mailed |
| 2026-10-05 | 9000002, 9000003, 9000004, 9000005 | rev 1 `threshold: type threshold` -> rev 2 `threshold: type both` | T1 run 1: one Nmap scan produced dozens of identical alerts (alert flood) | T1 runs 2-5: exactly 1 alert per rule per scan, detection still 100 % |
| 2026-10-05 | 1000008 | rev 1 `count 500, seconds 2` -> rev 2 `count 2000, seconds 2` | T1 run 1: a 1000-port Nmap scan (~1000 SYNs in 1.5 s) was also reported as a SYN flood | T1 runs 2-5: no false DoS alert; to re-check with real flood test T7 |
| 2026-10-05 | 2233001 (ET/Suricata RFB app-layer) | Added suppress in /etc/suricata/threshold.config: `suppress gen_id 1, sig_id 2233001, track by_either, ip fe80::342c:7d12:feae:49be` (admin laptop only) | "SURICATA RFB Unimplemented security type" fired on the admin's own RealVNC Viewer session (laptop -> Pi:5900 over IPv6) | Admin VNC sessions no longer alert; RFB anomalies from any other host still detected |
| 2026-10-05 | 1000006 (SSH brute force) | Observed only (to tune): did not fire on a hydra/libssh attack | T5: hydra reuses SSH connections (libssh), so fewer than 10 new connections in 60 s; ET rule 2006546 caught it instead | Option: also match SSH app-layer or lower the threshold; kept as-is since ET rule covers it |
| 2026-10-05 | collector e-mail queue | Observed (to improve): e-mail delay rose to ~386 s during the nikto scan | T8 nikto produced hundreds of alerts; the collector sends e-mails one at a time over SMTP, so a backlog formed | Future work: batch alerts or send one summary e-mail per burst / per source |
| 2026-10-14 | 2003068 (ET SCAN Potential SSH Scan OUTBOUND) | Disabled via /etc/suricata/disable.conf | Fired on `nmap -A` from Kali; labelled inbound lab traffic as OUTBOUND because the attacker is inside HOME_NET | Inbound rule 2001219 still detected the SSH scan |
| 2026-10-14 | ET Open ruleset (`suricata.rules`) | Removed from `rule-files` in suricata.yaml (line commented out) | Final system uses only the team's own rules; ET produced noise such as "Tomcat Auth Brute Force" on our own dashboard login (port 8080) | 18 rules loaded, 0 failed; T1-T9, UDP scan and Telnet all detected by custom rules |
| 2026-10-14 | 9000001 | rev 2 `threshold limit 1/60s track by_src` -> rev 3 `track by_dst` | DDoS test (`hping3 -1 --flood --rand-source`): every spoofed source counted as new, giving ~85,000 alerts and 85,000 "unique attackers" | Same 10 s DDoS now gives 6 alerts (1 x 9000001, 5 x 1000005 ICMP flood) |
| 2026-10-14 | 1000007 (FTP brute force) + collector | `ids_collector.py` / `ip_blocker.py`: swap src/dest for server-reply rules (REVERSED_SIDS = {1000007}); sensor IP 192.168.10.50 added to BLOCK_WHITELIST | Rule matches the server's 530 reply, so the Pi was shown (and counted for blocking) as the attacker | Kali 192.168.10.20 shown as attacker; auto-block banned Kali at 14:26:02, auto-unblocked 14:36:04 |
| 2026-10-14 | collector e-mail queue | Notifications sent by 4 parallel workers instead of one at a time (resolves the 2026-10-05 note above) | During scans e-mail delay climbed 3 -> 15 s because each SMTP login waited for the previous one | Notification delay ~3 s per alert during scans |
| | | | | |

## How to record a change

1. Edit `rules/local.rules`, increase `rev:` by 1 for the changed rule.
2. Run the offline test (README "Testing") - all must still PASS.
3. Copy to the Pi: `sudo cp rules/local.rules /etc/suricata/rules/ && sudo systemctl restart suricata`
4. Add a row above, then commit:
   `git commit -am "rules: raise SYN scan threshold to 30/5s (sid 1000001 rev 2)"`
