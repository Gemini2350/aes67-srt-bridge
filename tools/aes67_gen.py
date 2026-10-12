#!/usr/bin/env python3
"""AES67 test sender: L24/48k, ptime 1 ms, sine, RTP timestamps = TAI * 48000 (CLOCK_REALTIME + 37 s).

    python3 aes67_gen.py 239.69.1.1 5004 [interface_ip] [channels]
"""
import math, socket, struct, sys, time
group, port = sys.argv[1], int(sys.argv[2])
ifip = sys.argv[3] if len(sys.argv) > 3 else "0.0.0.0"
chans = int(sys.argv[4]) if len(sys.argv) > 4 else 2
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 8)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
if ifip != "0.0.0.0":
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ifip))
seq, ssrc, n = 0, 0x12345678, 48
t0 = time.time()
k = 0
while True:
    now = time.time() + 37
    ts = int(now * 48000) & 0xFFFFFFFF
    payload = bytearray()
    for i in range(n):
        v = int(0.25 * 8388607 * math.sin(2 * math.pi * 1000 * (k + i) / 48000))
        payload += struct.pack(">i", v)[1:] * chans
    k += n
    s.sendto(struct.pack(">BBHII", 0x80, 97, seq & 0xFFFF, ts, ssrc) + payload, (group, port))
    seq += 1
    nxt = t0 + seq * 0.001
    d = nxt - time.time()
    if d > 0:
        time.sleep(d)
