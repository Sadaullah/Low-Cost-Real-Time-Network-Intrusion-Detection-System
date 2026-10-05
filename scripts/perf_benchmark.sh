#!/usr/bin/env bash
# =====================================================================
#  perf_benchmark.sh - measure Pi + Suricata performance for one scenario
#  and append a clean summary row to results/performance-results.csv
#  (this is what fills the performance table in Chapter 5).
#
#  Run it THREE times, once per traffic condition, e.g.:
#     sudo ./scripts/perf_benchmark.sh "Suricata idle"            60
#     sudo ./scripts/perf_benchmark.sh "Normal load (iperf3)"     60
#     sudo ./scripts/perf_benchmark.sh "Under attack flood (T4+T7)" 60
#  While each one runs, generate the matching traffic from Kali
#  (nothing for idle; iperf3 for normal; hping3 flood for attack).
#
#  It samples CPU / RAM / temperature every 2 s and averages them, and
#  reads Suricata's own packet + drop counters at the start and end of
#  the window to compute the packet-drop percentage for that scenario.
#
#  args: <condition-label> <duration-seconds> [csv-path]
# =====================================================================
set -euo pipefail

LABEL="${1:-scenario}"
DUR="${2:-60}"
CSV="${3:-results/performance-results.csv}"
EVE=/var/log/suricata/eve.json
STEP=2

command -v jq >/dev/null || { echo "Please: sudo apt-get install -y jq"; exit 1; }

# --- read Suricata capture counters (packets, drops) from the last stats event
read_counters() {
  tail -n 6000 "$EVE" 2>/dev/null | grep '"event_type":"stats"' | tail -1 \
    | jq -r '[.stats.capture.kernel_packets // 0, .stats.capture.kernel_drops // 0] | @tsv' \
    2>/dev/null || echo -e "0\t0"
}

echo "[*] Benchmarking \"$LABEL\" for ${DUR}s (sampling every ${STEP}s)..."
read -r pkt0 drop0 <<<"$(read_counters)"

# CPU sampling baseline
read -r _ a b c d e f g _ < /proc/stat
prev_idle=$((d+e)); prev_total=$((a+b+c+d+e+f+g))

cpu_sum=0; mem_sum=0; temp_sum=0; n=0
end=$(( $(date +%s) + DUR ))
while [ "$(date +%s)" -lt "$end" ]; do
  sleep "$STEP"
  read -r _ a b c d e f g _ < /proc/stat
  idle=$((d+e)); total=$((a+b+c+d+e+f+g))
  cpu=$(awk -v i=$((idle-prev_idle)) -v t=$((total-prev_total)) 'BEGIN{printf "%.1f",100*(1-i/t)}')
  prev_idle=$idle; prev_total=$total
  mem=$(free -m | awk '/Mem:/{print $3}')
  temp=$(awk '{printf "%.1f",$1/1000}' /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo 0)
  cpu_sum=$(awk -v s=$cpu_sum -v x=$cpu 'BEGIN{print s+x}')
  mem_sum=$(awk -v s=$mem_sum -v x=$mem 'BEGIN{print s+x}')
  temp_sum=$(awk -v s=$temp_sum -v x=$temp 'BEGIN{print s+x}')
  n=$((n+1))
  printf "\r    sample %2d: cpu %5s%%  mem %5sMB  temp %4s C" "$n" "$cpu" "$mem" "$temp"
done
echo

read -r pkt1 drop1 <<<"$(read_counters)"
dpkts=$((pkt1 - pkt0)); ddrops=$((drop1 - drop0))
[ "$dpkts" -lt 0 ] && dpkts=0
[ "$ddrops" -lt 0 ] && ddrops=0

cpu_avg=$(awk -v s=$cpu_sum -v n=$n 'BEGIN{printf "%.1f", n?s/n:0}')
mem_avg=$(awk -v s=$mem_sum -v n=$n 'BEGIN{printf "%.0f", n?s/n:0}')
temp_avg=$(awk -v s=$temp_sum -v n=$n 'BEGIN{printf "%.1f", n?s/n:0}')
drop_pct=$(awk -v d=$ddrops -v p=$dpkts 'BEGIN{printf "%.2f", p?100*d/p:0}')
pps=$(awk -v p=$dpkts -v t=$DUR 'BEGIN{printf "%.0f", t?p/t:0}')

# create CSV with header if missing
if [ ! -f "$CSV" ]; then
  echo "condition,throughput_mbit_s,cpu_percent,ram_mb,temp_c,packet_drop_percent,notes" > "$CSV"
fi
note="${dpkts} pkts seen in ${DUR}s (~${pps} pps); ${ddrops} dropped"
echo "\"$LABEL\",n/a,$cpu_avg,$mem_avg,$temp_avg,$drop_pct,\"$note\"" >> "$CSV"

echo
echo "============================================================"
printf " %-26s %s\n" "Condition:"        "$LABEL"
printf " %-26s %s%%\n" "Avg CPU:"         "$cpu_avg"
printf " %-26s %s MB\n" "Avg RAM used:"   "$mem_avg"
printf " %-26s %s C\n" "Avg temperature:" "$temp_avg"
printf " %-26s %s (%s pps)\n" "Packets inspected:" "$dpkts" "$pps"
printf " %-26s %s%% (%s dropped)\n" "Packet drop:" "$drop_pct" "$ddrops"
echo " Appended to: $CSV"
echo " Build the chart with: python3 scripts/perf_report.py"
echo "============================================================"
