#!/usr/bin/env python3
"""Receives an AES67 multicast and reports packets/s, sequence gaps and the RTP timestamp age vs. TAI.

    python3 aes67_check.py 239.69.10.1 5004 [interface_ip] [seconds]
"""
import socket, struct, sys, time
group, port = sys.argv[1], int(sys.argv[2])
ifip = sys.argv[3] if len(sys.argv) > 3 else "0.0.0.0"
dur = float(sys.argv[4]) if len(sys.argv) > 4 else 5
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((group, port))
s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(group) + socket.inet_aton(ifip))
s.settimeout(1)
end = time.time() + dur
pk, gaps, last, ages, src = 0, 0, None, [], None
while time.time() < end:
    try:
        d, a = s.recvfrom(2048)
    except socket.timeout:
        continue
    src = a
    seq, ts = struct.unpack_from(">HI", d, 2)
    if last is not None and seq != (last + 1) & 0xFFFF:
        gaps += 1
    last = seq
    pk += 1
    now = int((time.time() + 37) * 48000) & 0xFFFFFFFF
    age = ((now - ts + 0x80000000) & 0xFFFFFFFF) - 0x80000000
    ages.append(age / 48)
ages.sort()
print(f"from {src}: {pk} packets in {dur:.0f} s ({pk/dur:.0f}/s), seq gaps {gaps}, "
      f"RTP ts age ms min/median/max {ages[0]:.1f}/{ages[len(ages)//2]:.1f}/{ages[-1]:.1f}" if ages else "no packets")
