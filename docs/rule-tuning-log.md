# Rule Tuning Log

Every change to `rules/local.rules` or to the ET Open ruleset (disable / suppress /
threshold) is recorded here. This table goes straight into Chapter 5
("False-positive analysis and tuning").

| Date | Rule SID | Change (before -> after) | Reason / evidence | Effect |
| --- | --- | --- | --- | --- |
| 2026-10-05 | 1000001–1000013 | Initial version of 13 custom rules | Offline pcap test: 12/12 detected, 0 FP | Baseline |
| 2026-10-05 | 9000001 | rev 1 `alert icmp any any -> any any` -> rev 2 `alert icmp any any -> $HOME_NET any; itype:8; threshold limit 1/60s by_src` | 23 alerts in ~20 min from IPv6 neighbour discovery (fe80:: -> ff02::1:ff00:1), normal traffic | Only real pings alert, max 1/min per source; first live ping detected and e-mailed |
| | | | | |

## How to record a change

1. Edit `rules/local.rules`, increase `rev:` by 1 for the changed rule.
2. Run the offline test (README "Testing") - all must still PASS.
3. Copy to the Pi: `sudo cp rules/local.rules /etc/suricata/rules/ && sudo systemctl restart suricata`
4. Add a row above, then commit:
   `git commit -am "rules: raise SYN scan threshold to 30/5s (sid 1000001 rev 2)"`
