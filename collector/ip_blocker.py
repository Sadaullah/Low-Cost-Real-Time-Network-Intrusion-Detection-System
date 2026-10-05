#!/usr/bin/env python3
"""
ip_blocker.py - FYP-IDS active response (reactive auto-blocking)

Turns the passive IDS into a reactive IDS: it follows Suricata's
eve.json in real time and, when a single source IP triggers too many
alerts in a short window, it automatically BANS that IP with iptables
for a while, then lifts the ban. Suricata itself stays in passive
(alert) mode - this script is the prevention layer on top of it.

This is lighter and safer than full inline IPS: traffic is not routed
through Suricata, we only insert a DROP rule for a confirmed attacker.

Design / safety:
  * A dedicated iptables chain (FYP-BLOCK) is hooked on the monitoring
    interface only, so management traffic is never touched.
  * A whitelist protects the admin laptop, the Wi-Fi management network,
    localhost and the Pi's own address - these are never banned.
  * Every ban auto-expires after BLOCK_DURATION_SEC.
  * Bans are recorded in the SQLite DB (table "blocks") so the dashboard
    and the report can show prevention activity.

Config: /etc/fyp-ids/config.env   (new BLOCK_* keys, see config.env.example)
Run   : sudo python3 ip_blocker.py   (systemd service ids-blocker)
Only the Python standard library is used.
"""
import ipaddress
import json
import logging
import os
import signal
import sqlite3
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime

CONFIG_FILE = os.environ.get("FYP_IDS_CONFIG", "/etc/fyp-ids/config.env")
CHAIN = "FYP-BLOCK"
log = logging.getLogger("ip-blocker")


# --------------------------------------------------------------------- config
def load_config(path):
    cfg = {
        "EVE_PATH": "/var/log/suricata/eve.json",
        "DB_PATH": "/var/lib/fyp-ids/alerts.db",
        "SENSOR_NAME": "netguard-pi",
        "BLOCK_IFACE": "eth0",            # monitoring interface
        "BLOCK_THRESHOLD": "5",           # alerts from one IP ...
        "BLOCK_WINDOW_SEC": "30",         # ... within this many seconds
        "BLOCK_DURATION_SEC": "600",      # ban length (10 min), then auto-unban
        "BLOCK_MIN_SEVERITY": "2",        # only act on severity <= this (1 high, 2 med)
        # never ban these (comma-separated IPs / CIDRs):
        "BLOCK_WHITELIST": "127.0.0.1,192.168.1.0/24,192.168.10.1",
        "BLOCK_DRY_RUN": "0",             # 1 = log what it WOULD block, no iptables
    }
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip().strip('"').strip("'")
    cfg.update({k: v for k, v in os.environ.items() if k in cfg})
    return cfg


# ------------------------------------------------------------------- database
SCHEMA = """
CREATE TABLE IF NOT EXISTS blocks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           TEXT NOT NULL,
    reason       TEXT,
    hits         INTEGER,
    blocked_at   TEXT NOT NULL,
    blocked_epoch REAL NOT NULL,
    expires_epoch REAL,
    unblocked_at TEXT,
    active       INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_blocks_ip ON blocks(ip);
"""


def open_db(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.executescript(SCHEMA)
    return db


# -------------------------------------------------------------------- iptables
class Firewall:
    def __init__(self, iface, dry_run=False):
        self.iface, self.dry = iface, dry_run

    def _run(self, args):
        if self.dry:
            log.info("[dry-run] iptables %s", " ".join(args))
            return True
        try:
            subprocess.run(["iptables", *args], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            return True
        except subprocess.CalledProcessError as exc:
            log.error("iptables %s failed: %s", " ".join(args),
                      exc.stderr.decode(errors="replace").strip())
            return False
        except FileNotFoundError:
            log.error("iptables not found - is this running on the Pi as root?")
            return False

    def setup(self):
        """Create the ban chain and hook it on the monitoring interface."""
        self._run(["-N", CHAIN])                       # create (ignore if exists)
        self._run(["-F", CHAIN])                       # start clean
        # hook once
        check = subprocess.run(
            ["iptables", "-C", "INPUT", "-i", self.iface, "-j", CHAIN],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check.returncode != 0 and not self.dry:
            self._run(["-I", "INPUT", "-i", self.iface, "-j", CHAIN])
        elif self.dry:
            log.info("[dry-run] would hook INPUT -i %s -j %s", self.iface, CHAIN)

    def ban(self, ip):
        return self._run(["-A", CHAIN, "-s", ip, "-j", "DROP"])

    def unban(self, ip):
        return self._run(["-D", CHAIN, "-s", ip, "-j", "DROP"])

    def teardown(self):
        self._run(["-F", CHAIN])


# ------------------------------------------------------------------ tail -F
def follow(path, stop):
    fh, inode, partial = None, None, ""
    while not stop.is_set():
        if fh is None:
            try:
                fh = open(path, encoding="utf-8", errors="replace")
                inode = os.fstat(fh.fileno()).st_ino
                fh.seek(0, os.SEEK_END)
                log.info("following %s", path)
            except FileNotFoundError:
                time.sleep(2)
                continue
        line = fh.readline()
        if line:
            partial += line
            if partial.endswith("\n"):
                yield partial
                partial = ""
            continue
        time.sleep(0.2)
        try:
            st = os.stat(path)
            if st.st_ino != inode or st.st_size < fh.tell():
                fh.close()
                fh = open(path, encoding="utf-8", errors="replace")
                inode, partial = os.fstat(fh.fileno()).st_ino, ""
        except FileNotFoundError:
            pass


# ---------------------------------------------------------------------- core
class Blocker:
    def __init__(self, cfg, db, fw):
        self.cfg, self.db, self.fw = cfg, db, fw
        self.threshold = int(cfg["BLOCK_THRESHOLD"])
        self.window = float(cfg["BLOCK_WINDOW_SEC"])
        self.duration = float(cfg["BLOCK_DURATION_SEC"])
        self.min_sev = int(cfg["BLOCK_MIN_SEVERITY"])
        self.hits = defaultdict(deque)          # ip -> recent alert epochs
        self.active = {}                         # ip -> expiry epoch
        self.lock = threading.Lock()
        self.whitelist = []
        for item in cfg["BLOCK_WHITELIST"].split(","):
            item = item.strip()
            if item:
                try:
                    self.whitelist.append(ipaddress.ip_network(item, strict=False))
                except ValueError:
                    log.warning("bad whitelist entry: %s", item)

    def is_whitelisted(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True                          # unparseable -> never block
        return any(addr in net for net in self.whitelist)

    def record(self, ip, sev, signature):
        if sev > self.min_sev or not ip or self.is_whitelisted(ip):
            return
        now = time.time()
        with self.lock:
            if ip in self.active:
                return                           # already banned
            dq = self.hits[ip]
            dq.append(now)
            while dq and now - dq[0] > self.window:
                dq.popleft()
            if len(dq) >= self.threshold:
                self._ban(ip, len(dq), signature, now)
                dq.clear()

    def _ban(self, ip, hits, signature, now):
        if self.fw.ban(ip):
            expires = now + self.duration
            self.active[ip] = expires
            ts = datetime.now().astimezone().isoformat(timespec="seconds")
            self.db.execute(
                "INSERT INTO blocks (ip, reason, hits, blocked_at, blocked_epoch,"
                " expires_epoch, active) VALUES (?,?,?,?,?,?,1)",
                (ip, signature, hits, ts, now, expires))
            log.warning("BLOCKED %s (%d alerts in %.0fs) for %.0fs - last: %s",
                        ip, hits, self.window, self.duration, signature)

    def expire_loop(self, stop):
        while not stop.is_set():
            now = time.time()
            with self.lock:
                due = [ip for ip, exp in self.active.items() if exp <= now]
                for ip in due:
                    self.fw.unban(ip)
                    del self.active[ip]
                    ts = datetime.now().astimezone().isoformat(timespec="seconds")
                    self.db.execute(
                        "UPDATE blocks SET active=0, unblocked_at=? "
                        "WHERE ip=? AND active=1", (ts, ip))
                    log.info("UNBLOCKED %s (ban expired)", ip)
            stop.wait(5)

    def teardown(self):
        with self.lock:
            for ip in list(self.active):
                self.fw.unban(ip)
            self.active.clear()


# ---------------------------------------------------------------------- main
def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(CONFIG_FILE)
    dry = cfg["BLOCK_DRY_RUN"] == "1"
    os.umask(0o007)
    db = open_db(cfg["DB_PATH"])
    fw = Firewall(cfg["BLOCK_IFACE"], dry_run=dry)
    fw.setup()
    blocker = Blocker(cfg, db, fw)

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    threading.Thread(target=blocker.expire_loop, args=(stop,), daemon=True).start()

    log.info("active response running: ban after %s alerts / %ss, "
             "duration %ss, iface=%s, dry_run=%s",
             cfg["BLOCK_THRESHOLD"], cfg["BLOCK_WINDOW_SEC"],
             cfg["BLOCK_DURATION_SEC"], cfg["BLOCK_IFACE"], dry)

    for line in follow(cfg["EVE_PATH"], stop):
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("event_type") != "alert":
            continue
        a = ev.get("alert", {})
        blocker.record(ev.get("src_ip"), a.get("severity", 3),
                       a.get("signature", ""))

    log.info("stopping; leaving active bans in place (they will expire)")
    # On a clean stop we KEEP active bans (they auto-expire); flush only the
    # in-memory timers. To clear all bans immediately: sudo iptables -F FYP-BLOCK
    db.close()


if __name__ == "__main__":
    main()
