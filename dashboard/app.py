#!/usr/bin/env python3
"""
FYP-IDS web dashboard (Flask)

Reads the SQLite database written by ids_collector.py and shows:
live alerts, alerts per minute, top attackers, top rules, severity split,
and Pi / Suricata health (CPU temp, load, RAM, disk, packets, drops).

Protected with HTTP Basic auth (user/password from /etc/fyp-ids/config.env).
Run: python3 app.py   -> http://<pi-ip>:8080
Requires: sudo apt install python3-flask
"""
import csv
import hmac
import io
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from functools import wraps

from flask import Flask, Response, jsonify, render_template, request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "collector"))
from ids_collector import CONFIG_FILE, load_config  # noqa: E402

CFG = load_config(CONFIG_FILE)
DB_PATH = CFG["DB_PATH"]
USER = CFG.get("DASHBOARD_USER", "admin")
PASS = CFG.get("DASHBOARD_PASS", "")
app = Flask(__name__)


# ---------------------------------------------------------------- helpers
def db():
    con = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=5)
    con.row_factory = sqlite3.Row
    return con


def rows(sql, args=()):
    try:
        with db() as con:
            return [dict(r) for r in con.execute(sql, args).fetchall()]
    except sqlite3.OperationalError:          # DB not created yet
        return []


def requires_auth(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        auth = request.authorization
        if not PASS:                          # refuse to run open
            return Response("Set DASHBOARD_PASS in config.env", 503)
        if not auth or not (hmac.compare_digest(auth.username or "", USER)
                            and hmac.compare_digest(auth.password or "", PASS)):
            return Response("Login required", 401,
                            {"WWW-Authenticate": 'Basic realm="FYP-IDS"'})
        return fn(*a, **kw)
    return wrapper


def since(hours):
    return time.time() - hours * 3600


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ------------------------------------------------------------------ pages
@app.route("/")
@requires_auth
def index():
    return render_template("index.html", sensor=CFG["SENSOR_NAME"])


@app.route("/api/summary")
@requires_auth
def summary():
    h = float(request.args.get("hours", 24))
    t0 = since(h)
    total = rows("SELECT COUNT(*) n FROM alerts WHERE epoch>=?", (t0,))
    sev = rows("SELECT severity, COUNT(*) n FROM alerts WHERE epoch>=? GROUP BY severity", (t0,))
    attackers = rows("SELECT COUNT(DISTINCT src_ip) n FROM alerts WHERE epoch>=?", (t0,))
    delay = rows("SELECT AVG(notify_delay) d FROM alerts WHERE notified=1 AND epoch>=?", (t0,))
    last = rows("SELECT ts, signature FROM alerts ORDER BY epoch DESC LIMIT 1")
    by_sev = {r["severity"]: r["n"] for r in sev}
    return jsonify(
        total=total[0]["n"] if total else 0,
        high=by_sev.get(1, 0), medium=by_sev.get(2, 0), low=by_sev.get(3, 0),
        attackers=attackers[0]["n"] if attackers else 0,
        avg_notify_delay=round(delay[0]["d"], 2) if delay and delay[0]["d"] else None,
        last=last[0] if last else None,
    )


@app.route("/api/alerts")
@requires_auth
def alerts():
    limit = min(int(request.args.get("limit", 50)), 500)
    return jsonify(rows(
        "SELECT ts, src_ip, src_port, dest_ip, dest_port, proto, sid, signature,"
        " category, severity, notified, notify_delay FROM alerts ORDER BY epoch DESC LIMIT ?",
        (limit,)))


@app.route("/api/top")
@requires_auth
def top():
    t0 = since(float(request.args.get("hours", 24)))
    return jsonify(
        sources=rows("SELECT src_ip k, COUNT(*) n FROM alerts WHERE epoch>=?"
                     " GROUP BY src_ip ORDER BY n DESC LIMIT 8", (t0,)),
        signatures=rows("SELECT signature k, sid, COUNT(*) n FROM alerts WHERE epoch>=?"
                        " GROUP BY sid ORDER BY n DESC LIMIT 8", (t0,)),
        targets=rows("SELECT dest_ip || ':' || IFNULL(dest_port,'') k, COUNT(*) n FROM alerts"
                     " WHERE epoch>=? GROUP BY k ORDER BY n DESC LIMIT 8", (t0,)),
    )


@app.route("/api/timeline")
@requires_auth
def timeline():
    minutes = min(int(request.args.get("minutes", 60)), 1440)
    now = int(time.time() // 60)
    data = rows("SELECT CAST(epoch/60 AS INTEGER) m, COUNT(*) n FROM alerts"
                " WHERE epoch>=? GROUP BY m", ((now - minutes + 1) * 60,))
    counts = {r["m"]: r["n"] for r in data}
    return jsonify([{"t": (now - i) * 60, "n": counts.get(now - i, 0)}
                    for i in range(minutes - 1, -1, -1)])


@app.route("/api/health")
@requires_auth
def health():
    def read(path, default=None):
        try:
            with open(path) as fh:
                return fh.read()
        except OSError:
            return default

    temp = read("/sys/class/thermal/thermal_zone0/temp")
    mem = {}
    for line in (read("/proc/meminfo", "") or "").splitlines():
        k, v = line.split(":", 1)
        mem[k] = int(v.split()[0])
    disk = shutil.disk_usage("/")
    try:
        active = subprocess.run(["systemctl", "is-active", "suricata"],
                                capture_output=True, text=True, timeout=3).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        active = "unknown"
    st = rows("SELECT * FROM stats ORDER BY epoch DESC LIMIT 1")
    st = st[0] if st else {}
    pkts, drops = st.get("pkts") or 0, st.get("drops") or 0
    return jsonify(
        suricata=active,
        cpu_temp=round(int(temp) / 1000, 1) if temp else None,
        load=(read("/proc/loadavg", "0 0 0") or "0").split()[:3],
        mem_used_pct=round(100 * (1 - mem.get("MemAvailable", 0) / mem["MemTotal"]), 1)
        if mem.get("MemTotal") else None,
        disk_used_pct=round(100 * disk.used / disk.total, 1),
        packets=pkts, drops=drops,
        drop_pct=round(100 * drops / pkts, 3) if pkts else 0,
        uptime=st.get("uptime"),
    )


@app.route("/export.csv")
@requires_auth
def export_csv():
    data = rows("SELECT ts, src_ip, src_port, dest_ip, dest_port, proto, sid, signature,"
                " category, severity, notified, notify_delay FROM alerts ORDER BY epoch")
    buf = io.StringIO()
    if data:
        w = csv.DictWriter(buf, fieldnames=list(data[0].keys()))
        w.writeheader()
        w.writerows(data)
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=fyp-ids-alerts.csv"})


if __name__ == "__main__":
    app.run(host=CFG.get("DASHBOARD_HOST", "0.0.0.0"),
            port=int(CFG.get("DASHBOARD_PORT", 8080)), debug=False)
