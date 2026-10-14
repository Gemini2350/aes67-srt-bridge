#!/usr/bin/env python3
"""Compares an RTP multicast before and after the bridge byte by byte (matched by SSRC + sequence number).

    python3 rtp_compare.py <in_group> <in_port> <out_group> <out_port> [if_ip] [seconds]
"""
import select, socket, sys, time


def join(group, port, ifip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((group, port))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(group) + socket.inet_aton(ifip))
    return s


ig, ip_, og, op = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
ifip = sys.argv[5] if len(sys.argv) > 5 else "0.0.0.0"
dur = float(sys.argv[6]) if len(sys.argv) > 6 else 5
si, so = join(ig, ip_, ifip), join(og, op, ifip)
sent, n_out, same, diff, unmatched = {}, 0, 0, 0, 0
first_diff = None
end = time.time() + dur
while time.time() < end:
    r, _, _ = select.select([si, so], [], [], 0.5)
    for s in r:
        d = s.recv(2048)
        key = (d[8:12], d[2:4])                      # SSRC, sequence number
        if s is si:
            sent[key] = d
        else:
            n_out += 1
            orig = sent.pop(key, None)
            if orig is None:
                unmatched += 1
            elif orig == d:
                same += 1
            else:
                diff += 1
                first_diff = first_diff or (orig[:12].hex(), d[:12].hex())
print(f"output packets {n_out}: identical {same}, different {diff}, without matching input {unmatched}")
if first_diff:
    print("first difference (RTP header in / out):", first_diff)
