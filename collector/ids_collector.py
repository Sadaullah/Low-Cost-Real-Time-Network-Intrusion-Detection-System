#!/usr/bin/env python3
"""
ids_collector.py - FYP-IDS alert collector

Follows Suricata's eve.json in real time (like `tail -F`, survives log
rotation), and for every alert:
  1. stores it in an SQLite database (used by the web dashboard), and
  2. sends an instant notification to Telegram and/or e-mail.

It also stores Suricata's periodic "stats" events (packets / drops) so the
dashboard can show engine health, and records the notification delay of
every alert (used for the "alert delay" metric in the report).

Config: /etc/fyp-ids/config.env   (see config/config.env.example)
Run   : python3 ids_collector.py   (installed as systemd service ids-collector)
Only the Python standard library is used - nothing to pip install.
"""
import json
import logging
import os
import queue
import signal
import smtplib
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime
from email.message import EmailMessage

CONFIG_FILE = os.environ.get("FYP_IDS_CONFIG", "/etc/fyp-ids/config.env")
log = logging.getLogger("ids-collector")


# --------------------------------------------------------------------- config
def load_config(path):
    cfg = {
        "EVE_PATH": "/var/log/suricata/eve.json",
        "DB_PATH": "/var/lib/fyp-ids/alerts.db",
        "TELEGRAM_BOT_TOKEN": "",
        "TELEGRAM_CHAT_ID": "",
        "SMTP_HOST": "", "SMTP_PORT": "587", "SMTP_USER": "", "SMTP_PASS": "",
        "EMAIL_TO": "",
        "NOTIFY_MAX_SEVERITY": "2",     # 1 = high, 2 = medium, 3 = low
        "NOTIFY_COOLDOWN_SEC": "60",    # same rule + same attacker -> 1 msg per minute
        "SENSOR_NAME": "netguard-pi",
        "RETENTION_DAYS": "30",
        "DASHBOARD_USER": "admin", "DASHBOARD_PASS": "",
        "DASHBOARD_HOST": "0.0.0.0", "DASHBOARD_PORT": "8080",
    }
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    cfg[key.strip()] = val.strip().strip('"').strip("'")
    cfg.update({k: v for k, v in os.environ.items() if k in cfg})
    return cfg


# ------------------------------------------------------------------- database
SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,          -- Suricata timestamp (ISO 8601)
    epoch         REAL NOT NULL,
    src_ip        TEXT, src_port INTEGER,
    dest_ip       TEXT, dest_port INTEGER,
    proto         TEXT,
    sid           INTEGER, rev INTEGER,
    signature     TEXT,
    category      TEXT,
    severity      INTEGER,
    action        TEXT,
    community_id  TEXT,
    notified      INTEGER DEFAULT 0,     -- 1 if a notification was sent
    notify_delay  REAL                   -- seconds from packet to notification
);
CREATE INDEX IF NOT EXISTS idx_alerts_epoch ON alerts(epoch);
CREATE INDEX IF NOT EXISTS idx_alerts_src   ON alerts(src_ip);
CREATE TABLE IF NOT EXISTS stats (
    epoch            REAL PRIMARY KEY,
    uptime           INTEGER,
    pkts             INTEGER,
    drops            INTEGER,
    alerts_total     INTEGER,
    flows_active     INTEGER
);
"""


def open_db(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    db.execute("PRAGMA journal_mode=WAL")      # dashboard can read while we write
    db.execute("PRAGMA synchronous=NORMAL")     # fewer SD-card writes
    db.executescript(SCHEMA)
    return db


def parse_ts(ts):
    # Suricata: 2026-10-05T14:03:11.123456+0500
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
    except (ValueError, TypeError):
        return time.time()


# -------------------------------------------------------------- notifications
class Notifier(threading.Thread):
    """Sends messages in a background thread so slow networks never block
    alert processing."""

    def __init__(self, cfg, db, db_lock):
        super().__init__(daemon=True)
        self.cfg, self.db, self.db_lock = cfg, db, db_lock
        self.q = queue.Queue(maxsize=500)
        self.last_sent = {}
        self.cooldown = float(cfg["NOTIFY_COOLDOWN_SEC"])
        self.max_sev = int(cfg["NOTIFY_MAX_SEVERITY"])
        self.telegram = bool(cfg["TELEGRAM_BOT_TOKEN"] and cfg["TELEGRAM_CHAT_ID"])
        self.email = bool(cfg["SMTP_HOST"] and cfg["EMAIL_TO"])

    def submit(self, row_id, ev):
        sev = ev["alert"].get("severity", 3)
        if sev > self.max_sev or not (self.telegram or self.email):
            return
        key = (ev["alert"]["signature_id"], ev.get("src_ip"))
        now = time.time()
        if now - self.last_sent.get(key, 0) < self.cooldown:
            return                                  # de-duplicate floods
        self.last_sent[key] = now
        try:
            self.q.put_nowait((row_id, ev))
        except queue.Full:
            log.warning("notification queue full, dropping message")

    def run(self):
        while True:
            row_id, ev = self.q.get()
            text = self.format(ev)
            ok = False
            if self.telegram:
                ok |= self.send_telegram(text)
            if self.email:
                ok |= self.send_email(ev, text)
            if ok:
                delay = time.time() - parse_ts(ev.get("timestamp"))
                with self.db_lock:
                    self.db.execute("UPDATE alerts SET notified=1, notify_delay=? WHERE id=?",
                                    (round(delay, 3), row_id))
                log.info("notified sid=%s delay=%.2fs", ev["alert"]["signature_id"], delay)

    def format(self, ev):
        a = ev["alert"]
        sev = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}.get(a.get("severity"), "INFO")
        src = f"{ev.get('src_ip')}:{ev.get('src_port', '')}".rstrip(":")
        dst = f"{ev.get('dest_ip')}:{ev.get('dest_port', '')}".rstrip(":")
        return (f"🚨 [{self.cfg['SENSOR_NAME']}] {sev} severity alert\n"
                f"{a.get('signature')}\n"
                f"Attacker: {src}\nTarget:   {dst} ({ev.get('proto')})\n"
                f"Category: {a.get('category')}\nRule SID: {a.get('signature_id')}\n"
                f"Time: {ev.get('timestamp', '')[:19].replace('T', ' ')}")

    def send_telegram(self, text):
        url = f"https://api.telegram.org/bot{self.cfg['TELEGRAM_BOT_TOKEN']}/sendMessage"
        data = urllib.parse.urlencode({"chat_id": self.cfg["TELEGRAM_CHAT_ID"], "text": text}).encode()
        try:
            with urllib.request.urlopen(url, data=data, timeout=10) as resp:
                return resp.status == 200
        except Exception as exc:                      # network down, bad token...
            log.error("telegram failed: %s", exc)
            return False

    def send_email(self, ev, text):
        msg = EmailMessage()
        msg["Subject"] = f"[FYP-IDS] {ev['alert'].get('signature')}"
        msg["From"] = self.cfg["SMTP_USER"]
        msg["To"] = self.cfg["EMAIL_TO"]
        msg.set_content(text)
        try:
            with smtplib.SMTP(self.cfg["SMTP_HOST"], int(self.cfg["SMTP_PORT"]), timeout=15) as s:
                s.starttls()
                s.login(self.cfg["SMTP_USER"], self.cfg["SMTP_PASS"])
                s.send_message(msg)
            return True
        except Exception as exc:
            log.error("email failed: %s", exc)
            return False


# ------------------------------------------------------------------ tail -F
def follow(path, stop):
    """Yield new lines from path forever; reopen when logrotate replaces or
    truncates the file."""
    fh, inode, partial = None, None, ""
    while not stop.is_set():
        if fh is None:
            try:
                fh = open(path, encoding="utf-8", errors="replace")
                inode = os.fstat(fh.fileno()).st_ino
                fh.seek(0, os.SEEK_END)               # only new events
                log.info("following %s", path)
            except FileNotFoundError:
                time.sleep(2)
                continue
        line = fh.readline()
        if line:
            partial += line
            if partial.endswith("\n"):                # complete JSON line
                yield partial
                partial = ""
            continue
        time.sleep(0.2)
        try:
            st = os.stat(path)
            if st.st_ino != inode or st.st_size < fh.tell():
                log.info("log rotated, reopening")
                fh.close()
                fh = open(path, encoding="utf-8", errors="replace")
                inode, partial = os.fstat(fh.fileno()).st_ino, ""
        except FileNotFoundError:
            pass


# ---------------------------------------------------------------------- main
def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(CONFIG_FILE)
    os.umask(0o007)                 # DB files group-readable for the dashboard user
    db = open_db(cfg["DB_PATH"])
    db_lock = threading.Lock()
    notifier = Notifier(cfg, db, db_lock)
    notifier.start()
    log.info("telegram=%s email=%s", notifier.telegram, notifier.email)

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    retention = float(cfg["RETENTION_DAYS"]) * 86400
    last_cleanup = 0.0

    for line in follow(cfg["EVE_PATH"], stop):
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        etype = ev.get("event_type")
        if etype == "alert":
            a = ev["alert"]
            with db_lock:
                cur = db.execute(
                    "INSERT INTO alerts (ts, epoch, src_ip, src_port, dest_ip, dest_port, proto,"
                    " sid, rev, signature, category, severity, action, community_id)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (ev.get("timestamp"), parse_ts(ev.get("timestamp")),
                     ev.get("src_ip"), ev.get("src_port"), ev.get("dest_ip"), ev.get("dest_port"),
                     ev.get("proto"), a.get("signature_id"), a.get("rev"), a.get("signature"),
                     a.get("category"), a.get("severity"), a.get("action"), ev.get("community_id")))
            notifier.submit(cur.lastrowid, ev)
        elif etype == "stats":
            s = ev.get("stats", {})
            cap = s.get("capture", {})
            with db_lock:
                db.execute("INSERT OR REPLACE INTO stats VALUES (?,?,?,?,?,?)",
                           (parse_ts(ev.get("timestamp")), s.get("uptime"),
                            cap.get("kernel_packets", s.get("decoder", {}).get("pkts")),
                            cap.get("kernel_drops", 0),
                            s.get("detect", {}).get("alert"),
                            s.get("flow", {}).get("active")))

        if time.time() - last_cleanup > 3600:          # hourly housekeeping
            cutoff = time.time() - retention
            with db_lock:
                db.execute("DELETE FROM alerts WHERE epoch < ?", (cutoff,))
                db.execute("DELETE FROM stats WHERE epoch < ?", (time.time() - 7 * 86400,))
            last_cleanup = time.time()
    log.info("stopped")


if __name__ == "__main__":
    main()
