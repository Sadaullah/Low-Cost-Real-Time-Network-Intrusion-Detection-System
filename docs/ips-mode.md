# Prevention: IPS mode and auto-blocking

By default NetGuard Pi is a **passive IDS**: Suricata watches traffic on
`eth0`, and when an attack matches a rule it **detects and alerts**
(dashboard + e-mail). It does *not* stop the attack — the packets still
reach the target.

This document adds two **prevention** layers on top of that, so the
project can also *block* attacks, not only report them:

| Mode | How it stops attacks | Suricata | When to use |
|---|---|---|---|
| **Inline IPS** | Suricata inspects each packet via NFQUEUE and **drops** matching ones before delivery | runs inline (`-q 0`) | the "true IPS" demo — attack is blocked packet-by-packet |
| **Auto-blocking (reactive IDS)** | a watcher bans an attacker's IP with `iptables` after N alerts | stays passive | lightweight prevention that also works on mirrored traffic |

Both are legitimate and complementary. Inline IPS blocks the *specific
malicious packets*; auto-blocking bans the *whole source IP* for a while.

---

## Why this is safe in our lab

* The attack targets (SSH, FTP, DVWA/HTTP, ICMP) run **on the Pi**, and
  the attacker (Kali) is on `eth0`. So blocking traffic on `eth0`
  actually prevents the attack.
* All blocking is scoped to **`eth0` only**. Wi-Fi management (RealVNC /
  SSH on `wlan0`, 192.168.1.x) is never touched — you cannot lock
  yourself out.
* Inline mode uses `--queue-bypass`: if Suricata stops, `eth0` traffic
  flows normally instead of being blackholed.
* Auto-blocking has a **whitelist** (admin laptop, Wi-Fi network,
  localhost) and every ban **auto-expires**.

---

## 1. Inline IPS mode

### One-time check
```bash
suricata --build-info | grep -i nfqueue      # must say: NFQueue support: yes
sudo apt-get install -y jq                    # used by the perf script
```

### Deploy the drop rules (once)
```bash
sudo cp rules/ips.rules /etc/suricata/rules/ips.rules
```

### Turn IPS mode ON
```bash
sudo ./scripts/ips_mode.sh
```
This stops the passive service, sends `eth0` through NFQUEUE, and starts
Suricata inline with the `drop` rules. Alerts still flow to the dashboard
and e-mail; matching attacks are now dropped.

### Demo: show "before vs after"
Run the **same attack twice** — once in IDS mode, once in IPS mode — and
capture both results. This side-by-side is the strongest evidence.

| Attack from Kali | IDS mode (passive) | IPS mode (inline) |
|---|---|---|
| `hping3 -1 --flood 192.168.10.50` (ICMP flood) | alert only, pings succeed | flood packets **dropped** |
| `hydra -l pi -P list.txt ssh://192.168.10.50` | alert only, logins proceed | brute-force SYNs **dropped** |
| `sqlmap -u "http://192.168.10.50/..."` | alert only, request reaches DVWA | request **dropped** before DVWA |
| download EICAR over HTTP | alert only, file downloads | download **blocked** |

Watch it live while attacking:
```bash
tail -f /var/log/suricata/eve.json | grep -E 'blocked|FYP-IPS'
```
`"action":"blocked"` in the event = that packet was dropped by the IPS.

Good evidence to save: a terminal showing the attack failing/timing out,
and the matching `blocked` events. Put screenshots in
`docs/images/week4-results/`.

### Turn IPS mode OFF (back to passive IDS)
```bash
sudo ./scripts/ids_mode.sh
```

---

## 2. Auto-blocking (reactive IDS)

Keeps Suricata passive but adds an **active response**: `ip_blocker.py`
follows `eve.json` and, when one source IP raises **5 alerts in 30 s**
(configurable), it drops that IP with `iptables` for **10 minutes**, then
automatically unbans it. Bans are logged to the `blocks` table in the
database.

### Install
```bash
sudo cp collector/ip_blocker.py /opt/fyp-ids/collector/
sudo cp systemd/ids-blocker.service /etc/systemd/system/
# add the BLOCK_* settings to your config (see config/config.env.example)
sudo nano /etc/fyp-ids/config.env
sudo systemctl daemon-reload
sudo systemctl enable --now ids-blocker
sudo systemctl status ids-blocker --no-pager
```

### Demo
```bash
# from Kali, run any repeated attack, e.g. an SSH brute force
hydra -l pi -P passwords.txt ssh://192.168.10.50

# on the Pi, watch the ban happen and then the attacker get cut off
journalctl -u ids-blocker -f
sudo iptables -L FYP-BLOCK -n -v           # the DROP rule for the attacker IP
```
After the ban, re-running the attack from Kali will **time out** until the
ban expires. Evidence to save: the `journalctl` line `BLOCKED <ip>`, the
`iptables -L FYP-BLOCK` output, and the failed attack on Kali.

### Safety / testing tips
* To test without really blocking, set `BLOCK_DRY_RUN=1` — it logs what it
  *would* block.
* To clear all bans immediately: `sudo iptables -F FYP-BLOCK`.
* Never remove the whitelist entry for your management network.

### Don't run both at the exact same time for a demo
Inline IPS already drops the attack packets, so the auto-blocker may not
reach its alert threshold. Demo them **separately** so each result is
clean, then explain in the report that in production you would pick one
(inline IPS for strongest protection, auto-blocking for mirrored
deployments).

---

## For the report

* This moves the project from **detection** to **detection + prevention**,
  which is exactly the IPS extension listed in the proposal's future work.
* Chapter 6 (Future Work) can now be updated: inline IPS and reactive
  auto-blocking are **implemented and tested**, not just proposed.
* Remaining future work: a hardware transparent bridge so the Pi can
  protect *other* machines inline (not only itself), and ML-based anomaly
  detection.
