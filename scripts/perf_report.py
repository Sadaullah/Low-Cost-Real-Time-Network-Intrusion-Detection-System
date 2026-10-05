#!/usr/bin/env python3
"""
perf_report.py - turn results/performance-results.csv into a performance
chart and a Markdown table for Chapter 5.

Outputs:
  docs/images/week4-results/fig_performance.png   (grouped bar chart)
  results/performance-table.md                     (table to paste in the report)

Run:  python3 scripts/perf_report.py
      (needs matplotlib:  pip3 install --user matplotlib )
"""
import csv
import os
import sys

CSV = os.environ.get("PERF_CSV", "results/performance-results.csv")
PNG = "docs/images/week4-results/fig_performance.png"
MD = "results/performance-table.md"


def num(x):
    try:
        return float(str(x).strip())
    except (TypeError, ValueError):
        return None


def load(path):
    rows = []
    with open(path, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            cond = (r.get("condition") or "").strip()
            if not cond:
                continue
            rows.append({
                "cond": cond,
                "cpu": num(r.get("cpu_percent")),
                "ram": num(r.get("ram_mb")),
                "temp": num(r.get("temp_c")),
                "drop": num(r.get("packet_drop_percent")),
                "notes": (r.get("notes") or "").strip(),
            })
    return rows


def short(label):
    """Shorten a condition label for the x-axis."""
    l = label.lower()
    if "idle" in l:
        return "Idle"
    if "normal" in l or "iperf" in l or "load" in l:
        return "Normal load"
    if "flood" in l or "attack" in l or "syn" in l or "icmp" in l:
        return "Under attack"
    return label[:16]


def write_md(rows):
    os.makedirs(os.path.dirname(MD), exist_ok=True)
    with open(MD, "w", encoding="utf-8") as fh:
        fh.write("| Condition | CPU (%) | RAM (MB) | Temp (°C) | Packet drop (%) |\n")
        fh.write("|---|---|---|---|---|\n")
        for r in rows:
            fh.write("| {c} | {cpu} | {ram} | {t} | {d} |\n".format(
                c=r["cond"],
                cpu="-" if r["cpu"] is None else f"{r['cpu']:.1f}",
                ram="-" if r["ram"] is None else f"{r['ram']:.0f}",
                t="-" if r["temp"] is None else f"{r['temp']:.1f}",
                d="-" if r["drop"] is None else f"{r['drop']:.2f}"))
    print(f"[ok] wrote {MD}")


def write_png(rows):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("[skip] matplotlib not installed; wrote the table only.\n"
              "       install with:  pip3 install --user matplotlib")
        return
    plot = [r for r in rows if any(r[k] is not None for k in ("cpu", "ram", "temp", "drop"))]
    if not plot:
        print("[skip] no numeric rows to plot yet.")
        return
    labels = [short(r["cond"]) for r in plot]
    x = range(len(plot))
    panels = [
        ("CPU usage (%)", [r["cpu"] for r in plot], "#1a73e8", "%.1f"),
        ("RAM used (MB)", [r["ram"] for r in plot], "#34a853", "%.0f"),
        ("Temperature (°C)", [r["temp"] for r in plot], "#f29900", "%.1f"),
        ("Packet drop (%)", [r["drop"] for r in plot], "#d93025", "%.2f"),
    ]
    fig, axes = plt.subplots(1, 4, figsize=(13, 4.2))
    fig.suptitle("NetGuard Pi - Performance under different traffic conditions",
                 fontsize=13, fontweight="bold")
    for ax, (title, vals, color, fmt) in zip(axes, panels):
        vv = [0 if v is None else v for v in vals]
        bars = ax.bar(list(x), vv, color=color, width=0.6)
        ax.set_title(title, fontsize=10, fontweight="bold")
        ax.set_xticks(list(x))
        ax.set_xticklabels(labels, fontsize=8, rotation=15)
        ax.grid(axis="y", alpha=0.3)
        top = max(vv) if max(vv) > 0 else 1
        ax.set_ylim(0, top * 1.25)
        for b, v in zip(bars, vals):
            if v is not None:
                ax.text(b.get_x() + b.get_width() / 2, b.get_height(),
                        fmt % v, ha="center", va="bottom", fontsize=8)
    fig.tight_layout(rect=[0, 0, 1, 0.94])
    os.makedirs(os.path.dirname(PNG), exist_ok=True)
    fig.savefig(PNG, dpi=130)
    print(f"[ok] wrote {PNG}")


def main():
    if not os.path.exists(CSV):
        print(f"ERROR: {CSV} not found. Run scripts/perf_benchmark.sh first.")
        sys.exit(1)
    rows = load(CSV)
    if not rows:
        print("ERROR: no data rows in the CSV.")
        sys.exit(1)
    write_md(rows)
    write_png(rows)
    print(f"[done] {len(rows)} condition(s) processed.")


if __name__ == "__main__":
    main()
