#!/usr/bin/env python3
"""
check_test_results.py - read Suricata's eve.json after replaying attacks.pcap
and report which test cases were detected (PASS/FAIL table).

    python3 check_test_results.py /tmp/ids-test/eve.json
"""
import json
import sys
from collections import Counter

EXPECTED = {
    "T1 SYN port scan": [1000001],
    "T2 XMAS scan": [1000002],
    "T2 NULL scan": [1000003],
    "T2 FIN scan": [1000004],
    "T4 ICMP flood": [1000005],
    "T5 SSH brute force": [1000006],
    "T6 FTP brute force": [1000007],
    "T7 SYN flood": [1000008],
    "T8 SQL injection": [1000010, 1000013],
    "T8 XSS": [1000011],
    "T9 EICAR malware test": [1000009],
    "Telnet policy": [1000012],
}
BENIGN_CLIENT = "192.168.1.70"


def main(path):
    sids, benign_hits = Counter(), []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if ev.get("event_type") != "alert":
                continue
            sid = ev["alert"]["signature_id"]
            sids[sid] += 1
            if BENIGN_CLIENT in (ev.get("src_ip"), ev.get("dest_ip")) and 1000000 < sid < 1000100:
                benign_hits.append(ev["alert"]["signature"])

    passed = 0
    print(f"{'Test case':28} {'SIDs':20} {'Alerts':>6}  Result")
    print("-" * 66)
    for name, want in EXPECTED.items():
        hits = sum(sids[s] for s in want)
        ok = all(sids[s] > 0 for s in want)
        passed += ok
        print(f"{name:28} {','.join(map(str, want)):20} {hits:>6}  {'PASS' if ok else 'FAIL'}")
    print("-" * 66)
    print(f"Detected {passed}/{len(EXPECTED)} test cases "
          f"({100 * passed / len(EXPECTED):.0f}% detection rate)")
    print(f"Custom-rule alerts on benign client traffic (false positives): {len(benign_hits)}")
    other = {s: c for s, c in sids.items() if not 1000000 < s < 1000100}
    if other:
        print(f"Other (ET Open) rules that fired: {len(other)} SIDs, {sum(other.values())} alerts")
    return 0 if passed == len(EXPECTED) and not benign_hits else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/var/log/suricata/eve.json"))
