#!/usr/bin/env bash
# perf_snapshot.sh - log Pi + Suricata performance every N seconds to a CSV
# for the performance table in Chapter 5.
#   sudo ./perf_snapshot.sh "suricata_iperf_load" 60 5  > perf_load.csv
# args: <label> <duration-seconds> <interval-seconds>
LABEL=${1:-test}; DUR=${2:-60}; STEP=${3:-5}
EVE=/var/log/suricata/eve.json
echo "label,time,cpu_pct,mem_used_mb,temp_c,suricata_rss_mb,kernel_packets,kernel_drops"
end=$(( $(date +%s) + DUR ))
read -r _ a b c d e f g _ < /proc/stat; prev_idle=$((d+e)); prev_total=$((a+b+c+d+e+f+g))
while [ "$(date +%s)" -lt "$end" ]; do
  sleep "$STEP"
  read -r _ a b c d e f g _ < /proc/stat
  idle=$((d+e)); total=$((a+b+c+d+e+f+g))
  cpu=$(awk -v i=$((idle-prev_idle)) -v t=$((total-prev_total)) 'BEGIN{printf "%.1f", 100*(1-i/t)}')
  prev_idle=$idle; prev_total=$total
  mem=$(free -m | awk '/Mem:/{print $3}')
  temp=$(awk '{printf "%.1f", $1/1000}' /sys/class/thermal/thermal_zone0/temp)
  rss=$(ps -C Suricata-Main -C suricata -o rss= 2>/dev/null | awk '{s+=$1} END{printf "%.0f", s/1024}')
  cap=$(tail -n 4000 "$EVE" 2>/dev/null | grep '"event_type":"stats"' | tail -1 |
        jq -r '[.stats.capture.kernel_packets, .stats.capture.kernel_drops] | @csv' 2>/dev/null)
  echo "$LABEL,$(date +%T),$cpu,$mem,$temp,${rss:-0},${cap:-,}"
done
