"""SDP helpers for AES67 / ST 2110-30 streams: parse the transport parameters and rewrite an SDP for re-publishing."""
from __future__ import annotations

import re
import time


def parse(sdp: str) -> dict:
    """Transport + format info of the first media section.

    Returns {multicast_ip, source_ip, port, ttl, payload_type, encoding, sample_rate, channels, ptime,
    refclk, mediaclk, session_name}. Missing values are None.
    """
    info = {"multicast_ip": None, "source_ip": None, "port": None, "ttl": None, "payload_type": None,
            "encoding": None, "sample_rate": None, "channels": None, "ptime": None, "refclk": None,
            "mediaclk": None, "session_name": None, "origin_ip": None}
    in_media = False
    for raw in sdp.replace("\r", "").split("\n"):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("m="):
            if in_media:            # only the first media section (no ST 2022-7 second leg)
                break
            in_media = True
            parts = line[2:].split()
            if len(parts) >= 4:
                info["port"] = _int(parts[1].split("/")[0])
                info["payload_type"] = _int(parts[3])
        elif line.startswith("s="):
            info["session_name"] = line[2:]
        elif line.startswith("o="):
            parts = line[2:].split()
            if len(parts) >= 6:
                info["origin_ip"] = parts[5]
        elif line.startswith("c="):
            parts = line[2:].split()
            if len(parts) >= 3:
                addr = parts[2].split("/")
                info["multicast_ip"] = addr[0]
                if len(addr) > 1:
                    info["ttl"] = _int(addr[1])
        elif line.startswith("a=source-filter:"):
            parts = line.split(":", 1)[1].split()
            # a=source-filter: incl IN IP4 <dest> <src>
            if len(parts) >= 5:
                info["source_ip"] = parts[4]
        elif line.startswith("a=rtpmap:"):
            m = re.match(r"a=rtpmap:(\d+)\s+([^/]+)/(\d+)(?:/(\d+))?", line)
            if m and (info["payload_type"] is None or int(m.group(1)) == info["payload_type"]):
                info["encoding"] = m.group(2)
                info["sample_rate"] = int(m.group(3))
                info["channels"] = int(m.group(4) or 1)
        elif line.startswith("a=ptime:"):
            try:
                info["ptime"] = float(line.split(":", 1)[1])
            except ValueError:
                pass
        elif line.startswith("a=ts-refclk:"):
            info["refclk"] = info["refclk"] or line[len("a=ts-refclk:"):]
        elif line.startswith("a=mediaclk:"):
            info["mediaclk"] = line[len("a=mediaclk:"):]
    if info["source_ip"] is None and info["origin_ip"] and info["multicast_ip"] and is_multicast(info["multicast_ip"]):
        info["source_ip"] = None     # do not guess SSM from o=, origin is often not the stream source
    return info


def rewrite(sdp: str, *, dest_ip: str, dest_port: int, source_ip: str, ttl: int = 32, session_name: str | None = None,
            refclk: str | None = None, restamp: bool = False, session_id: int | None = None) -> str:
    """SDP for the re-published stream: new destination, new source, optional new reference clock.

    restamp=True means the RTP timestamps are rewritten to the local PTP time with offset 0, so the
    mediaclk offset becomes 0 and any a=sync-time from the original is dropped.
    """
    out = []
    in_media = 0
    media_seen = False
    for raw in sdp.replace("\r", "").split("\n"):
        line = raw.rstrip()
        if not line:
            continue
        if line.startswith("m="):
            in_media += 1
            if in_media > 1:
                break       # only the first leg
            media_seen = True
            parts = line[2:].split()
            parts[1] = str(dest_port)
            out.append("m=" + " ".join(parts))
            if refclk:
                out.append(f"a=ts-refclk:{refclk}")
            if restamp:
                out.append("a=mediaclk:direct=0")
            continue
        if line.startswith("o="):
            p = line[2:].split()
            if len(p) >= 6:
                sid = str(session_id) if session_id is not None else p[1]
                line = f"o={p[0]} {sid} {int(time.time())} IN IP4 {source_ip}"
        elif line.startswith("s=") and session_name:
            line = f"s={session_name}"
        elif line.startswith("c="):
            line = f"c=IN IP4 {dest_ip}/{ttl}" if is_multicast(dest_ip) else f"c=IN IP4 {dest_ip}"
        elif line.startswith("a=source-filter:"):
            line = f"a=source-filter: incl IN IP4 {dest_ip} {source_ip}"
        elif line.startswith("a=ts-refclk:") and refclk:
            continue
        elif line.startswith("a=mediaclk:") and restamp:
            continue
        elif line.startswith("a=sync-time:") and restamp:
            continue
        elif line.startswith("a=x-nmos") or line.startswith("a=x-dante"):
            continue
        out.append(line)
    if media_seen and is_multicast(dest_ip) and not any(l.startswith("a=source-filter:") for l in out):
        out.append(f"a=source-filter: incl IN IP4 {dest_ip} {source_ip}")
    return "\r\n".join(out) + "\r\n"


def is_multicast(ip: str | None) -> bool:
    try:
        first = int((ip or "").split(".")[0])
    except ValueError:
        return False
    return 224 <= first <= 239


def _int(s):
    try:
        return int(s)
    except (TypeError, ValueError):
        return None
