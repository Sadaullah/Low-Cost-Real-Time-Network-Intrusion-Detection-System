# Troubleshooting

Every error I hit and how I fixed it. Examiners value this: it shows real hands-on work.

| Date | Problem / error message | Cause | Fix |
| --- | --- | --- | --- |
| | | | |

## Known issues (from the guide)

| Problem | Fix |
| --- | --- |
| `ssh: Could not resolve hostname pi-ids.local` | Use the Pi's IP from the router's client list |
| `suricata -T` fails with a YAML error | Indentation in suricata.yaml: use spaces, keep `- ` aligned |
| No alerts at all | `sudo systemctl status suricata`; check `interface:` and `EXTERNAL_NET: "any"` |
| Alerts in fast.log but no Telegram message | Check token/chat id in `/etc/fyp-ids/config.env`; `journalctl -u ids-collector -f` |
| Dashboard does not open | `sudo systemctl status ids-dashboard`; check `DASHBOARD_PASS` is set |
| Pi reboots under load | Use the official 5V 3A power supply |
| CPU temperature above 80 °C | Fit heatsink + fan case |
