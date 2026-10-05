// FYP-IDS dashboard front-end: polls the Flask API every 5 seconds.
// No external libraries, so it works on a lab network with no internet.
"use strict";
const $ = (id) => document.getElementById(id);
const SEV = { 1: "HIGH", 2: "MEDIUM", 3: "LOW" };
let lastTopTs = null;

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
async function api(path) {
  const r = await fetch(path, { credentials: "same-origin" });
  if (!r.ok) throw new Error(path + " " + r.status);
  return r.json();
}
const hours = () => $("range").value;

async function loadSummary() {
  const s = await api(`/api/summary?hours=${hours()}`);
  $("k-total").textContent = s.total;
  $("k-high").textContent = s.high;
  $("k-med").textContent = s.medium;
  $("k-low").textContent = s.low;
  $("k-att").textContent = s.attackers;
  $("k-delay").textContent = s.avg_notify_delay == null ? "–" : `${s.avg_notify_delay} s`;
}

function bars(el, items) {
  if (!items.length) { el.innerHTML = '<p class="muted">No data yet</p>'; return; }
  const max = Math.max(...items.map((i) => i.n));
  el.innerHTML = items.map((i) => `
    <div class="row"><span class="name" title="${esc(i.k)}">${esc(i.k)}</span><span class="n">${i.n}</span>
    <div class="track"><div class="fill" style="width:${(100 * i.n / max).toFixed(1)}%"></div></div></div>`).join("");
}
async function loadTop() {
  const t = await api(`/api/top?hours=${hours()}`);
  bars($("top-src"), t.sources);
  bars($("top-sig"), t.signatures);
  bars($("top-dst"), t.targets);
}

async function loadTimeline() {
  const pts = await api("/api/timeline?minutes=60");
  const W = 900, H = 160, padB = 20, padT = 10;
  const max = Math.max(1, ...pts.map((p) => p.n));
  const bw = W / pts.length;
  let svg = `<line x1="0" x2="${W}" y1="${H - padB}" y2="${H - padB}"/>`;
  pts.forEach((p, i) => {
    const h = (H - padB - padT) * p.n / max;
    if (p.n) svg += `<rect x="${(i * bw + 1).toFixed(1)}" y="${(H - padB - h).toFixed(1)}" width="${(bw - 2).toFixed(1)}" height="${h.toFixed(1)}"><title>${new Date(p.t * 1000).toLocaleTimeString()}: ${p.n} alerts</title></rect>`;
    if (i % 10 === 0) svg += `<text x="${i * bw}" y="${H - 4}">${new Date(p.t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</text>`;
  });
  svg += `<text x="${W - 4}" y="${padT + 10}" text-anchor="end">max ${max}/min</text>`;
  $("timeline").innerHTML = svg;
}

async function loadAlerts() {
  const a = await api("/api/alerts?limit=50");
  if (!a.length) return;
  const newest = a[0].ts;
  $("alerts").innerHTML = a.map((r) => `
    <tr class="${lastTopTs && r.ts > lastTopTs ? "new" : ""}">
      <td>${esc((r.ts || "").slice(0, 19).replace("T", " "))}</td>
      <td><span class="sev sev${r.severity}">${SEV[r.severity] || r.severity}</span></td>
      <td class="sig">${esc(r.signature)}</td>
      <td>${esc(r.src_ip)}${r.src_port ? ":" + r.src_port : ""}</td>
      <td>${esc(r.dest_ip)}${r.dest_port ? ":" + r.dest_port : ""}</td>
      <td>${esc(r.proto)}</td><td>${r.sid}</td>
      <td>${r.notified ? `yes (${r.notify_delay}s)` : "–"}</td>
    </tr>`).join("");
  lastTopTs = newest;
}

async function loadHealth() {
  const h = await api("/api/health");
  const e = $("engine");
  e.textContent = `engine: ${h.suricata}`;
  e.className = "pill " + (h.suricata === "active" ? "ok" : "bad");
  $("h-temp").textContent = h.cpu_temp == null ? "–" : `${h.cpu_temp} °C`;
  $("h-load").textContent = h.load.join(" / ");
  $("h-mem").textContent = h.mem_used_pct == null ? "–" : `${h.mem_used_pct} %`;
  $("h-disk").textContent = `${h.disk_used_pct} %`;
  $("h-pkts").textContent = Number(h.packets).toLocaleString();
  $("h-drop").textContent = `${h.drop_pct} %`;
}

async function refresh() {
  try {
    await Promise.all([loadSummary(), loadTop(), loadTimeline(), loadAlerts(), loadHealth()]);
  } catch (err) { console.error(err); }
}
$("range").addEventListener("change", refresh);
refresh();
setInterval(refresh, 5000);
