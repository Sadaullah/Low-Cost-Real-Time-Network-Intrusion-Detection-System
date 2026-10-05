#!/usr/bin/env python3
"""
make_test_pcap.py - build a pcap that replays every FYP test attack (T1-T9)
plus some benign traffic, so the custom rules can be tested OFFLINE:

    python3 make_test_pcap.py attacks.pcap
    sudo suricata -c /etc/suricata/suricata.yaml -S /etc/suricata/rules/local.rules \
         -r attacks.pcap -l /tmp/ids-test
    python3 check_test_results.py /tmp/ids-test/eve.json

Use it as a "regression test": every time you tune a rule, re-run it and
confirm all expected SIDs still fire and the benign traffic stays quiet.
Requires: pip install scapy   (or: sudo apt install python3-scapy)
"""
import random
import sys

from scapy.all import IP, TCP, ICMP, Ether, Raw, wrpcap  # type: ignore

ATTACKER = "192.168.1.100"
VICTIM = "192.168.1.60"
CLIENT = "192.168.1.70"          # benign LAN user
MAC_A, MAC_V = "02:00:00:00:00:aa", "02:00:00:00:00:bb"

random.seed(7)
packets = []
clock = [1_760_000_000.0]        # fake start time (epoch seconds)


def emit(pkt, gap=0.0005):
    clock[0] += gap
    pkt.time = clock[0]
    packets.append(pkt)


def eth(src_is_client=True):
    return Ether(src=MAC_A, dst=MAC_V) if src_is_client else Ether(src=MAC_V, dst=MAC_A)


def tcp_session(cli, srv, dport, exchanges, sport=None):
    """Full TCP session: handshake, list of (direction, bytes), FIN close.
    direction 'c' = client->server, 's' = server->client."""
    sport = sport or random.randint(20000, 60000)
    cseq, sseq = random.randint(1, 2**31), random.randint(1, 2**31)
    emit(eth() / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="S", seq=cseq))
    emit(eth(False) / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1))
    cseq += 1
    sseq += 1
    emit(eth() / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq))
    for direction, data in exchanges:
        if direction == "c":
            emit(eth() / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq) / Raw(data))
            cseq += len(data)
            emit(eth(False) / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="A", seq=sseq, ack=cseq))
        else:
            emit(eth(False) / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq) / Raw(data))
            sseq += len(data)
            emit(eth() / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq))
    emit(eth() / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="FA", seq=cseq, ack=sseq))
    emit(eth(False) / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="FA", seq=sseq, ack=cseq + 1))
    emit(eth() / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1))


def http_get(cli, path, body=b"<html>ok</html>", srv=VICTIM, port=80):
    req = f"GET {path} HTTP/1.1\r\nHost: {srv}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n".encode()
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
    tcp_session(cli, srv, port, [("c", req), ("s", resp)])


# ---- Benign traffic first (should produce NO custom alerts) -----------
for i in range(5):
    http_get(CLIENT, f"/index.html?page={i}")
tcp_session(CLIENT, VICTIM, 22, [("s", b"SSH-2.0-OpenSSH_9.6\r\n"), ("c", b"SSH-2.0-OpenSSH_9.6\r\n")])
for i in range(4):
    emit(eth() / IP(src=CLIENT, dst=VICTIM) / ICMP(type=8, id=1, seq=i), gap=1.0)

# ---- T1: SYN port scan (ports 1-1000) ---------------------------------
clock[0] += 5
for port in range(1, 1001):
    emit(eth() / IP(src=ATTACKER, dst=VICTIM) / TCP(sport=45555, dport=port, flags="S"), gap=0.0002)

# ---- T2: XMAS, NULL, FIN scans ----------------------------------------
clock[0] += 5
for flags in ("FPU", "", "F"):
    for port in (21, 22, 23, 25, 80, 110, 139, 443, 445, 3306):
        emit(eth() / IP(src=ATTACKER, dst=VICTIM) / TCP(sport=45556, dport=port, flags=flags), gap=0.001)

# ---- T4: ICMP flood (400 echo requests in < 1 s) ----------------------
clock[0] += 5
for i in range(400):
    emit(eth() / IP(src=ATTACKER, dst=VICTIM) / ICMP(type=8, id=99, seq=i), gap=0.001)

# ---- T5: SSH brute force (15 connections) -----------------------------
clock[0] += 5
for i in range(15):
    tcp_session(ATTACKER, VICTIM, 22, [("s", b"SSH-2.0-OpenSSH_4.7p1\r\n"), ("c", b"SSH-2.0-libssh_0.10\r\n")])
    clock[0] += 0.5

# ---- T6: FTP brute force (6 failed logins in one session) -------------
clock[0] += 5
ftp = [("s", b"220 (vsFTPd 2.3.4)\r\n")]
for pw in ("123456", "password", "admin", "letmein", "qwerty", "root"):
    ftp += [("c", b"USER msfadmin\r\n"), ("s", b"331 Please specify the password.\r\n"),
            ("c", f"PASS {pw}\r\n".encode()), ("s", b"530 Login incorrect.\r\n")]
tcp_session(ATTACKER, VICTIM, 21, ftp)

# ---- T7: SYN flood to port 80 (1000 SYNs, spoofed sources) ------------
clock[0] += 5
for i in range(1000):
    src = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    emit(eth() / IP(src=src, dst=VICTIM) / TCP(sport=random.randint(1024, 65535), dport=80, flags="S"), gap=0.0005)

# ---- T8: web attacks --------------------------------------------------
clock[0] += 5
http_get(ATTACKER, "/dvwa/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20user,password%20FROM%20users--+&Submit=Submit")
http_get(ATTACKER, "/mutillidae/index.php?page=user-info.php&username=admin%27%20or%201=1--%20&password=x")
http_get(ATTACKER, "/dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C/script%3E")

# ---- T9: EICAR test file downloaded over HTTP -------------------------
clock[0] += 5
eicar = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
http_get(VICTIM, "/eicar.com", body=eicar, srv=ATTACKER, port=8000)

# ---- Telnet policy ----------------------------------------------------
clock[0] += 5
tcp_session(ATTACKER, VICTIM, 23, [("s", b"\xff\xfd\x18\xff\xfd\x20"), ("c", b"\xff\xfc\x18")])

out = sys.argv[1] if len(sys.argv) > 1 else "attacks.pcap"
wrpcap(out, packets)
print(f"Wrote {len(packets)} packets to {out}")
