# Changes made to /etc/suricata/suricata.yaml

Only the lines below differ from the default file installed by the Suricata package.
The full live file is saved by `scripts/backup_configs.sh` into `config/snapshots/`.

| Setting | Default | My value | Why |
| --- | --- | --- | --- |
| `vars.address-groups.HOME_NET` | `[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]` | `[192.168.1.0/24]` | Only the lab network is protected |
| `vars.address-groups.EXTERNAL_NET` | `!$HOME_NET` | `any` | Attacker is on the same LAN in the lab; with `!$HOME_NET` most ET rules would never fire |
| `af-packet[0].interface` | `eth0` | `eth0` (week 1) → `br0` (week 2+) | Listen on the bridge to see all traffic |
| `rule-files` | `suricata.rules` | + `/etc/suricata/rules/local.rules` | Load my custom rules |
| `outputs.eve-log.community-id` | `false` | `true` | Flow ID that matches Zeek/Wireshark for correlation |

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.1.0/24]"
    EXTERNAL_NET: "any"

af-packet:
  - interface: br0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
  - /etc/suricata/rules/local.rules
```
