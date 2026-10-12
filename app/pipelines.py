"""Media pipelines around srt-live-transmit.

TX:  multicast (AES67)  ->  relay (count, inject SDP)  ->  127.0.0.1:lp  ->  srt-live-transmit  ->  srt://...
RX:  srt://...  ->  srt-live-transmit  ->  127.0.0.1:lp  ->  relay (strip SDP, restamp RTP)  ->  multicast

The source SDP travels inside the SRT stream: every second the TX relay sends one non-RTP datagram
(MAGIC + zlib(SDP)). RTP v2 packets always start with 0b10xxxxxx, MAGIC starts with 'A' (0b01000001),
so the RX relay can tell them apart without any framing.
"""
from __future__ import annotations

import json
import os
import re
import select
import shutil
import socket
import struct
import subprocess
import threading
import time
import zlib
from collections import deque
from urllib.parse import quote

from sdp import parse as sdp_parse

MAGIC = b"AES67SRT"
SLT = os.environ.get("SRT_LIVE_TRANSMIT", "srt-live-transmit")
LOCAL_BASE_PORT = int(os.environ.get("LOCAL_BASE_PORT", "41000"))
MASK32 = 0xFFFFFFFF


def local_port(index: int) -> int:
    return LOCAL_BASE_PORT + index


# ---------------------------------------------------------------- clock
class MediaClock:
    """PTP (TAI) time of the host. Needs the host clock disciplined to PTP (ptp4l + phc2sys)."""

    def __init__(self, mode: str = "auto", utc_offset: int = 37):
        self.mode, self.utc_offset = mode, utc_offset

    def tai(self) -> float:
        if self.mode in ("auto", "tai") and hasattr(time, "CLOCK_TAI"):
            t = time.clock_gettime(time.CLOCK_TAI)
            if self.mode == "tai" or t - time.time() > 10:     # kernel TAI offset is set
                return t
        return time.time() + self.utc_offset

    def source(self) -> str:
        if self.mode in ("auto", "tai") and hasattr(time, "CLOCK_TAI"):
            if self.mode == "tai" or time.clock_gettime(time.CLOCK_TAI) - time.time() > 10:
                return "CLOCK_TAI"
        return f"CLOCK_REALTIME + {self.utc_offset} s"


# ---------------------------------------------------------------- srt-live-transmit process
def srt_uri(srt: dict, *, default_mode: str, adapter: str | None = None) -> str:
    mode = srt.get("mode") or default_mode
    host = (srt.get("host") or "").strip() if mode != "listener" else ""
    q = {"mode": mode, "latency": int(srt.get("latency") or 120), "transtype": "live"}
    if srt.get("passphrase"):
        q["passphrase"] = srt["passphrase"]
        q["pbkeylen"] = int(srt.get("pbkeylen") or 16)
    if srt.get("streamid") and mode == "caller":
        q["streamid"] = srt["streamid"]
    if adapter and mode == "listener":
        q["adapter"] = adapter
    query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in q.items())
    return f"srt://{host}:{int(srt['port'])}?{query}"


class SrtProcess:
    """Supervised srt-live-transmit; stats (JSON) arrive on stdout, log lines on stderr."""

    def __init__(self, name: str, src: str, dst: str, log):
        self.name, self.src, self.dst, self.log = name, src, dst, log
        self.proc: subprocess.Popen | None = None
        self.stats: dict = {}
        self.stats_ts = 0.0
        self.totals: dict[str, int] = {}       # srt-live-transmit reports interval values: accumulated here
        self.lines: deque = deque(maxlen=50)
        self.running = False
        self.restarts = 0
        self.state = "stopped"
        self.thread: threading.Thread | None = None

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._supervise, daemon=True, name=f"slt-{self.name}")
        self.thread.start()

    def stop(self):
        self.running = False
        p = self.proc
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(2)
            except subprocess.TimeoutExpired:
                p.kill()
        self.state = "stopped"

    def cmdline(self) -> list[str]:
        cmd = [SLT, "-s:1000", "-pf:json", "-loglevel:warn", self.src, self.dst]
        if shutil.which("stdbuf"):
            cmd = ["stdbuf", "-oL", "-eL"] + cmd
        return cmd

    def _supervise(self):
        while self.running:
            cmd = self.cmdline()
            shown = " ".join(c for c in cmd if c not in ("stdbuf", "-oL", "-eL"))
            shown = re.sub(r"passphrase=[^&\s]*", "passphrase=***", shown)
            self.log("srt", f"{self.name}: start {shown}")
            try:
                self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            except OSError as e:
                self.state = f"error: {e}"
                self.log("error", f"{self.name}: cannot start srt-live-transmit: {e}")
                time.sleep(5)
                continue
            self.state = "waiting"
            t = threading.Thread(target=self._read_err, args=(self.proc,), daemon=True)
            t.start()
            for line in self.proc.stdout:
                line = line.strip()
                if line.startswith("{"):
                    try:
                        self.stats = json.loads(line)
                        self.stats_ts = time.time()
                        for d in ("send", "recv"):
                            for k in ("packets", "packetsLost", "packetsDropped", "packetsRetransmitted", "packetsBelated"):
                                v = (self.stats.get(d) or {}).get(k)
                                if isinstance(v, (int, float)):
                                    self.totals[f"{d}_{k}"] = self.totals.get(f"{d}_{k}", 0) + int(v)
                    except ValueError:
                        pass
                elif line:
                    self._line(line)
            rc = self.proc.wait()
            if not self.running:
                break
            self.restarts += 1
            self.state = f"exited ({rc}), restarting"
            self.log("srt", f"{self.name}: srt-live-transmit exited with {rc}, restart in 2 s")
            time.sleep(2)
        self.state = "stopped"

    def _read_err(self, proc):
        for line in proc.stderr:
            line = line.strip()
            if line:
                self._line(line)

    def _line(self, line: str):
        line = re.sub(r"passphrase=[^&\s']*", "passphrase=***", line)
        self.lines.append(f"{time.strftime('%H:%M:%S')} {line}")
        low = line.lower()
        if "connected" in low or "accepted" in low:
            if "not connected" not in low and "disconnected" not in low:
                self.state = "connected"
        if "disconnect" in low or "broken" in low or "lost" in low and "connection" in low:
            self.state = "disconnected"
        if "error" in low or "fail" in low:
            self.log("srt", f"{self.name}: {line}")

    def summary(self) -> dict:
        s = self.stats or {}
        fresh = time.time() - self.stats_ts < 5
        link = s.get("link") or {}
        snd = s.get("send") or {}
        rcv = s.get("recv") or {}
        t = self.totals
        return {
            "state": self.state, "restarts": self.restarts, "stats_fresh": fresh,
            "rtt_ms": link.get("rtt"), "bandwidth_mbps": link.get("bandwidth"),
            "send_mbps": snd.get("mbitRate") if fresh else 0, "recv_mbps": rcv.get("mbitRate") if fresh else 0,
            "send_lost": t.get("send_packetsLost", 0), "send_retrans": t.get("send_packetsRetransmitted", 0),
            "send_dropped": t.get("send_packetsDropped", 0),
            "recv_lost": t.get("recv_packetsLost", 0), "recv_retrans": t.get("recv_packetsRetransmitted", 0),
            "recv_dropped": t.get("recv_packetsDropped", 0), "recv_belated": t.get("recv_packetsBelated", 0),
            "lines": list(self.lines)[-12:],
        }


# ---------------------------------------------------------------- TX
class TxPipeline:
    """Feeds one AES67 multicast stream (selected via IS-05 on the virtual receiver) into SRT."""

    def __init__(self, ch: dict, index: int, interface_ip: str, log):
        self.ch, self.index, self.interface_ip, self.log = ch, index, interface_ip, log
        self.lp = local_port(index)
        src = f"udp://127.0.0.1:{self.lp}"
        self.slt = SrtProcess(f"TX {ch['label']}", src, srt_uri(ch["srt"], default_mode="caller", adapter=interface_ip), log)
        self.lock = threading.Lock()
        self.source: dict | None = None          # {multicast_ip, source_ip, port, sdp}
        self.sock: socket.socket | None = None
        self.out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.running = False
        self.packets = 0
        self.bytes = 0
        self.last_rx = 0.0
        self.rtp = RtpStats()
        self.thread: threading.Thread | None = None

    def start(self):
        self.running = True
        self.slt.start()
        self.thread = threading.Thread(target=self._loop, daemon=True, name=f"tx-{self.ch['id']}")
        self.thread.start()

    def stop(self):
        self.running = False
        self.set_source(None)
        self.slt.stop()

    def set_source(self, source: dict | None):
        """source: {multicast_ip, source_ip, port, sdp} or None (disconnect)."""
        with self.lock:
            if self.sock:
                try:
                    self.sock.close()
                except OSError:
                    pass
                self.sock = None
            self.source = source
            if not source:
                return
            info = sdp_parse(source.get("sdp") or "")
            self.rtp.reset_expectation(info.get("payload_type"), info.get("encoding"), info.get("channels"))
            try:
                self.sock = open_rx_socket(source["multicast_ip"], int(source["port"]), self.interface_ip, source.get("source_ip"))
                self.log("tx", f"{self.ch['label']}: joined {source.get('source_ip') or '*'} -> {source['multicast_ip']}:{source['port']}")
            except OSError as e:
                self.log("error", f"{self.ch['label']}: join {source['multicast_ip']}:{source['port']} failed: {e}")

    def _loop(self):
        last_sdp = 0.0
        while self.running:
            sock = self.sock
            now = time.time()
            if self.source and self.source.get("sdp") and now - last_sdp >= 1.0:
                last_sdp = now
                pkt = MAGIC + zlib.compress(self.source["sdp"].encode())
                if len(pkt) <= 1456:
                    self._send(pkt)
            if not sock:
                time.sleep(0.1)
                continue
            try:
                r, _, _ = select.select([sock], [], [], 0.2)
                if not r:
                    continue
                for _ in range(64):
                    data = sock.recv(2048)
                    if not data:
                        break
                    self.packets += 1
                    self.bytes += len(data)
                    self.last_rx = time.time()
                    self.rtp.check(data)
                    self._send(data)
            except BlockingIOError:
                pass
            except (OSError, ValueError):
                time.sleep(0.05)

    def _send(self, data: bytes):
        try:
            self.out.sendto(data, ("127.0.0.1", self.lp))
        except OSError:
            pass

    def status(self) -> dict:
        return {"source": {k: v for k, v in (self.source or {}).items() if k != "sdp"} if self.source else None,
                "packets": self.packets, "bytes": self.bytes, "rtp": self.rtp.snapshot(),
                "receiving": time.time() - self.last_rx < 1.0, "srt": self.slt.summary()}


# ---------------------------------------------------------------- RX
class RxPipeline:
    """Receives SRT, recovers the SDP, restamps RTP to local PTP time and sends the virtual sender's multicast."""

    def __init__(self, ch: dict, index: int, interface_ip: str, clock: MediaClock, log, on_sdp):
        self.ch, self.index, self.interface_ip, self.clock, self.log, self.on_sdp = ch, index, interface_ip, clock, log, on_sdp
        self.lp = local_port(index)
        dst = f"udp://127.0.0.1:{self.lp}"
        self.slt = SrtProcess(f"RX {ch['label']}", srt_uri(ch["srt"], default_mode="listener", adapter=interface_ip), dst, log)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.lp))
        self.out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.out.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, int(ch.get("out", {}).get("ttl") or 32))
        try:
            self.out.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(interface_ip))
            self.out.bind((interface_ip, 0))
        except OSError as e:
            log("error", f"{ch['label']}: bind output to {interface_ip} failed: {e}")
        self.out.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        self.source_port = self.out.getsockname()[1]
        self.dest: tuple[str, int] | None = None     # set by IS-05 activation (master_enable)
        self.running = False
        self.sdp: str | None = None
        self.sdp_ts = 0.0
        self.rate = 48000
        self.restamp = bool(ch.get("restamp", False))
        self.delta: int | None = None
        self.resyncs = 0
        self.err_ms = 0.0
        self.packets_in = 0
        self.packets_out = 0
        self.send_errors = 0
        self.last_rx = 0.0
        self.rtp = RtpStats()
        self.thread: threading.Thread | None = None

    def start(self):
        self.running = True
        self.slt.start()
        self.thread = threading.Thread(target=self._loop, daemon=True, name=f"rx-{self.ch['id']}")
        self.thread.start()

    def stop(self):
        self.running = False
        self.slt.stop()
        try:
            self.sock.close()
            self.out.close()
        except OSError:
            pass

    def set_output(self, dest: tuple[str, int] | None):
        if dest != self.dest:
            self.log("rx", f"{self.ch['label']}: output {'-> %s:%d' % dest if dest else 'off'}")
        self.dest = dest
        self.delta = None

    def set_format(self, info: dict):
        self.rtp.reset_expectation(info.get("payload_type"), info.get("encoding"), info.get("channels"))
        self.set_rate(info.get("sample_rate"))

    def set_rate(self, rate: int | None):
        if rate and rate != self.rate:
            self.rate = rate
            self.delta = None

    def _loop(self):
        sock = self.sock
        tolerance = lambda: int(self.rate * float(self.ch.get("resync_ms") or 20) / 1000)
        while self.running:
            try:
                r, _, _ = select.select([sock], [], [], 0.5)
                if not r:
                    continue
                data = sock.recv(2048)
            except (OSError, ValueError):
                if not self.running:
                    break
                time.sleep(0.05)
                continue
            if data[:8] == MAGIC:
                try:
                    sdp_text = zlib.decompress(data[8:]).decode("utf-8", errors="replace")
                except zlib.error:
                    continue
                self.sdp_ts = time.time()
                if sdp_text != self.sdp:
                    self.sdp = sdp_text
                    self.on_sdp(self.ch["id"], sdp_text)
                continue
            if len(data) < 12 or data[0] >> 6 != 2:
                continue
            self.packets_in += 1
            self.last_rx = time.time()
            self.rtp.check(data)
            dest = self.dest
            if not dest:
                continue
            if self.restamp:
                ts = struct.unpack_from(">I", data, 4)[0]
                now = int(self.clock.tai() * self.rate) & MASK32
                if self.delta is None:
                    self.delta = (now - ts) & MASK32
                new = (ts + self.delta) & MASK32
                err = ((now - new + 0x80000000) & MASK32) - 0x80000000
                if abs(err) > tolerance():
                    self.delta = (now - ts) & MASK32
                    new = now
                    self.resyncs += 1
                    if self.resyncs < 20 or self.resyncs % 100 == 0:
                        self.log("rx", f"{self.ch['label']}: RTP restamp resync #{self.resyncs} (error {err * 1000 / self.rate:.1f} ms)")
                    err = 0
                self.err_ms = self.err_ms * 0.99 + (err * 1000 / self.rate) * 0.01
                data = data[:4] + struct.pack(">I", new) + data[8:]
            try:
                self.out.sendto(data, dest)
                self.packets_out += 1
            except OSError:
                self.send_errors += 1

    def status(self) -> dict:
        return {"packets_in": self.packets_in, "packets_out": self.packets_out, "send_errors": self.send_errors,
                "rtp": self.rtp.snapshot(), "receiving": time.time() - self.last_rx < 1.0,
                "sdp_age_s": round(time.time() - self.sdp_ts, 1) if self.sdp_ts else None,
                "output": f"{self.dest[0]}:{self.dest[1]}" if self.dest else None, "source_port": self.source_port,
                "restamp": self.restamp, "restamp_resyncs": self.resyncs, "restamp_err_ms": round(self.err_ms, 2),
                "clock": self.clock.source(), "srt": self.slt.summary()}


# ---------------------------------------------------------------- RTP checks
BYTES_PER_SAMPLE = {"L16": 2, "L24": 3, "L32": 4, "AM824": 4}


class RtpStats:
    """Cumulative counters of an RTP packet stream: sequence gaps, non-RTP packets, unexpected payload type/size."""

    def __init__(self):
        self.reset_expectation(None, None, None)
        self.lost = self.not_rtp = self.pt_mismatch = self.size_mismatch = 0
        self.last_pt = self.last_payload = None

    def reset_expectation(self, payload_type, encoding, channels):
        self.expect_pt = payload_type
        bps = BYTES_PER_SAMPLE.get((encoding or "").upper())
        self.frame_bytes = bps * channels if bps and channels else None
        self.last_seq = None

    def check(self, data: bytes) -> bool:
        if len(data) < 12 or data[0] >> 6 != 2:
            self.not_rtp += 1
            return False
        seq = (data[2] << 8) | data[3]
        if self.last_seq is not None:
            gap = (seq - self.last_seq - 1) & 0xFFFF
            if 0 < gap < 3000:
                self.lost += gap
        if self.last_seq is None or ((seq - self.last_seq) & 0xFFFF) < 0x8000:
            self.last_seq = seq
        pt = data[1] & 0x7F
        self.last_pt = pt
        if self.expect_pt is not None and pt != self.expect_pt:
            self.pt_mismatch += 1
        hdr = 12 + 4 * (data[0] & 0x0F)
        if data[0] & 0x10 and len(data) >= hdr + 4:
            hdr += 4 + 4 * ((data[hdr + 2] << 8) | data[hdr + 3])
        payload = len(data) - hdr
        if data[0] & 0x20 and payload > 0:
            payload -= data[-1]
        self.last_payload = payload
        if self.frame_bytes and (payload <= 0 or payload % self.frame_bytes):
            self.size_mismatch += 1
        return True

    def snapshot(self) -> dict:
        return {"lost": self.lost, "not_rtp": self.not_rtp, "pt_mismatch": self.pt_mismatch, "size_mismatch": self.size_mismatch,
                "last_pt": self.last_pt, "last_payload": self.last_payload, "expect_pt": self.expect_pt, "frame_bytes": self.frame_bytes}


# ---------------------------------------------------------------- sockets
def open_rx_socket(group: str, port: int, interface_ip: str, source_ip: str | None = None) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    first = int(group.split(".")[0])
    multicast = 224 <= first <= 239
    s.bind((group if multicast else "0.0.0.0", port))
    if multicast:
        if source_ip:
            # Linux struct ip_mreq_source: imr_multiaddr, imr_interface, imr_sourceaddr
            mreq = socket.inet_aton(group) + socket.inet_aton(interface_ip) + socket.inet_aton(source_ip)
            s.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_ADD_SOURCE_MEMBERSHIP", 39), mreq)
        else:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(group) + socket.inet_aton(interface_ip))
    s.setblocking(False)
    return s
