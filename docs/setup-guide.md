# Setup Guide (step by step)

Already have Suricata running with the ET rules? Skip to Stage 4 (but check Stage 6 settings, especially `EXTERNAL_NET`).

Do one stage at a time. Do not continue until the **Check** works.
Save a screenshot at every check into `docs/images/week1-setup/` and commit.

## Stage 0 – GitHub access from the Pi

The repository already exists:
https://github.com/Sadaullah/Low-Cost-Real-Time-Network-Intrusion-Detection-System

Create a token so the Pi can push: GitHub → Settings → Developer settings →
Personal access tokens → **Fine-grained tokens** → Generate → Repository access:
only this repository → Permissions: **Contents: Read and write** → copy the token
(you see it only once). Never put the token in any file inside the repo.

## Stage 1 – Prepare the SD card (laptop)

1. Install **Raspberry Pi Imager**. Choose Raspberry Pi 4 → **Raspberry Pi OS Lite (64-bit)** → SD card.
2. Edit settings: hostname `pi-ids`, username + strong password, Services → **Enable SSH**.
3. Write the card.

## Stage 2 – Boot and connect

1. SD card in the Pi, RJ45 cable from the Pi to the router, power on, wait 2 minutes.
2. Laptop PowerShell: `ssh youruser@pi-ids.local` (or the IP shown in the router's device list).

**Check:** prompt shows `youruser@pi-ids:~ $`.

## Stage 3 – Update and install

```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y suricata suricata-update jq tcpdump ethtool iperf3 git python3-flask
sudo reboot
```
SSH in again: `suricata --build-info | head -3` and `ip route`.

**Check:** Suricata version shown; note your network (e.g. 192.168.1.0/24) and router IP.

## Stage 4 – Put the repository on the Pi

```bash
git config --global user.name  "Sada Ullah"
git config --global user.email "your-github-email@example.com"
git config --global credential.helper store
git clone https://github.com/Sadaullah/Low-Cost-Real-Time-Network-Intrusion-Detection-System.git netguard-pi
cd netguard-pi
```
When git asks: username = `Sadaullah`, password = the **token** from Stage 0.

## Stage 5 – Static IP

```bash
nmcli con show
sudo nmcli con mod "Wired connection 1" ipv4.method manual ipv4.addresses 192.168.1.50/24 ipv4.gateway 192.168.1.1 ipv4.dns 192.168.1.1
sudo nmcli con up "Wired connection 1"
```
Reconnect: `ssh youruser@192.168.1.50`.

## Stage 6 – Configure Suricata

`sudo nano /etc/suricata/suricata.yaml` and make the changes listed in
[config/suricata/suricata-yaml-changes.md](../config/suricata/suricata-yaml-changes.md)
(keep `interface: eth0` for now). In nano: Ctrl+W search, Ctrl+O save, Ctrl+X exit.

## Stage 7 – Rules and first detection

```bash
sudo suricata-update
sudo mkdir -p /etc/suricata/rules && sudo cp rules/local.rules /etc/suricata/rules/
sudo suricata -T -c /etc/suricata/suricata.yaml -v
sudo systemctl enable --now suricata && sudo systemctl restart suricata
sleep 30; curl http://testmynids.org/uid/index.html
sudo tail /var/log/suricata/fast.log
```

**Check:** `-T` ends with "Configuration provided was successfully loaded", and fast.log shows
**GPL ATTACK_RESPONSE id check returned root**.

## Stage 8 – Install collector + dashboard

```bash
chmod +x scripts/*.sh
sudo ./scripts/setup.sh          # write down the dashboard password it prints
```

**Check:** browser → `http://192.168.1.50:8080` → login `admin` + password.

Offline rule test:
```bash
python3 scripts/make_test_pcap.py /tmp/attacks.pcap
mkdir -p /tmp/ids-test
sudo suricata -c /etc/suricata/suricata.yaml -r /tmp/attacks.pcap -l /tmp/ids-test -k none
sudo chmod 644 /tmp/ids-test/eve.json
python3 scripts/check_test_results.py /tmp/ids-test/eve.json
```
**Check:** "Detected 12/12" and 0 false positives.

## Stage 9 – Telegram alerts

1. Telegram → **@BotFather** → `/newbot` → copy token.
2. Send "hi" to your bot, open `https://api.telegram.org/bot<TOKEN>/getUpdates`, copy `"chat":{"id": ...}`.
3. `sudo nano /etc/fyp-ids/config.env` → fill `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` →
   `sudo systemctl restart ids-collector`.

## Stage 10 – Kali and first real attack

1. VirtualBox + Kali VM image, network = **Bridged Adapter**.
2. In Kali: `sudo nmap -sS -p 1-1000 192.168.1.50`

**Check:** alert on the dashboard and a Telegram message on your phone.

## Stage 11 – Inline bridge (week 2, USB Ethernet adapter)

With monitor + keyboard on the Pi:
```bash
sudo ./scripts/bridge_setup.sh 192.168.1.50/24 192.168.1.1
```
Wiring: router → Pi built-in port; Pi USB adapter → victim PC (Metasploitable 2, bridged).

**Check:** victim still has internet; `sudo tcpdump -i br0 -c 20 not port 22` shows its packets.

## Stage 12 – Tests, results, report

Follow [docs/test-plan.md](test-plan.md), fill [results/](../results/), write [report/](../report/).

## Saving your work to GitHub (every day)

```bash
cd ~/netguard-pi
sudo ./scripts/backup_configs.sh       # copies live configs (secrets removed)
git add -A
git commit -m "day 3: suricata configured, first alert detected"
git push
```
Screenshots: add them on github.com (folder → **Add file → Upload files**), then on the Pi run `git pull`.
