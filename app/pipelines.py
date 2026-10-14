"""Media pipelines around srt-live-transmit.

TX:  srt-live-transmit  udp://@group:port?adapter=..&source=..  ->  srt://host:port          (media, direct)
     srt-live-transmit  udp://127.0.0.1:cp (SDP frames)         ->  srt://host:port+1        (SDP link)
RX:  srt-live-transmit  srt://:port                             ->  udp://group:port?adapter=..&ttl=..  (media, direct)
     srt-live-transmit  srt://:port+1                           ->  udp://127.0.0.1:cp (SDP frames)

srt-live-transmit reads and writes the multicast itself, the packets are not touched. The bridge only listens in
passively (a second socket in the same group) to count packets and check RTP for BCP-008.
Only the optional "restamp" mode on the RX side needs a relay in the path:
     srt-live-transmit  srt://:port  ->  udp://127.0.0.1:lp  ->  relay (restamp RTP)  ->  multicast

SDP frames: MAGIC + uint32 length + zlib(SDP), sent once per second as UDP datagrams of at most 1456 bytes
(one SRT message each); the receiver reassembles them, so an SDP larger than one datagram works as well.
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
CHUNK = 1456
SLT = os.environ.get("SRT_LIVE_TRANSMIT", "srt-live-transmit")
LOCAL_BASE_PORT = int(os.environ.get("LOCAL_BASE_PORT", "41000"))
MASK32 = 0xFFFFFFFF


def local_port(index: int) -> int:
    return LOCAL_BASE_PORT + index


def local_control_port(index: int) -> int:
    return LOCAL_BASE_PORT + 500 + index


def control_port(ch: dict) -> int:
    return int(ch["srt"].get("control_port") or int(ch["srt"]["port"]) + 1)


def sdp_datagrams(sdp_text: str) -> list[bytes]:
    z = zlib.compress(sdp_text.encode())
    frame = MAGIC + struct.pack(">I", len(z)) + z
    return [frame[i:i + CHUNK] for i in range(0, len(frame), CHUNK)]


class FrameParser:
    """Reassembles SDP frames from the byte stream on srt-live-transmit's stdout."""

    def __init__(self, on_frame):
        self.buf = b""
        self.on_frame = on_frame

    def feed(self, data: bytes):
        self.buf += data
        while True:
            i = self.buf.find(MAGIC)
            if i < 0:
                self.buf = self.buf[-(len(MAGIC) - 1):]
                return
            if len(self.buf) < i + 12:
                self.buf = self.buf[i:]
                return
            n = struct.unpack_from(">I", self.buf, i + 8)[0]
            if n > 65536:
                self.buf = self.buf[i + 1:]
                continue
            if len(self.buf) < i + 12 + n:
                self.buf = self.buf[i:]
                return
            payload = self.buf[i + 12:i + 12 + n]
            self.buf = self.buf[i + 12 + n:]
            try:
                self.on_frame(zlib.decompress(payload).decode("utf-8", errors="replace"))
            except zlib.error:
                pass


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
def srt_uri(srt: dict, *, default_mode: str, adapter: str | None = None, port: int | None = None, fec: bool = True) -> str:
    mode = srt.get("mode") or default_mode
    host = (srt.get("host") or "").strip() if mode != "listener" else ""
    q = {"mode": mode, "latency": int(srt.get("latency") or 120), "transtype": "live"}
    if srt.get("passphrase"):
        q["passphrase"] = srt["passphrase"]
        q["pbkeylen"] = int(srt.get("pbkeylen") or 16)
    if srt.get("streamid") and mode == "caller":
        q["streamid"] = srt["streamid"]
    if fec and (srt.get("packetfilter") or "").strip():
        q["packetfilter"] = srt["packetfilter"].strip()
    if adapter and mode == "listener":
        q["adapter"] = adapter
    query = "&".join(f"{k}={quote(str(v), safe=',:')}" for k, v in q.items())
    return f"srt://{host}:{int(port or srt['port'])}?{query}"


class SrtProcess:
    """Supervised srt-live-transmit.

    stats=True: JSON statistics on stdout (media links); log lines always on stderr.
    """

    COUNTERS = ("packets", "packetsLost", "packetsDropped", "packetsRetransmitted", "packetsBelated",
                "packetsFilterExtra", "packetsFilterSupply", "packetsFilterLoss")

    def __init__(self, name: str, src: str, dst: str, log, stats: bool = True):
        self.name, self.src, self.dst, self.log = name, src, dst, log
        self.stats_enabled = stats
        self.generation = 0                    # bumped by retarget(); a process started with an older one is replaced
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
        self._kill()
        self.state = "stopped"

    def _kill(self):
        p = self.proc
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(2)
            except subprocess.TimeoutExpired:
                p.kill()

    def retarget(self, src: str | None = None, dst: str | None = None):
        """Restart with a new source/target (e.g. a new IS-05 destination). No-op if nothing changed."""
        src, dst = src or self.src, dst or self.dst
        if (src, dst) == (self.src, self.dst):
            return
        self.src, self.dst = src, dst
        self.generation += 1
        self._kill()            # the supervisor notices the newer generation and restarts at once

    def cmdline(self) -> list[str]:
        cmd = [SLT] + (["-s:1000", "-pf:json"] if self.stats_enabled else []) + ["-loglevel:warn", self.src, self.dst]
        if shutil.which("stdbuf"):
            cmd = ["stdbuf", "-oL", "-eL"] + cmd
        return cmd

    def _supervise(self):
        while self.running:
            gen = self.generation
            cmd = self.cmdline()
            shown = " ".join(c for c in cmd if c not in ("stdbuf", "-oL", "-eL"))
            shown = re.sub(r"passphrase=[^&\s]*", "passphrase=***", shown)
            self.log("srt", f"{self.name}: start {shown}")
            try:
                self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, bufsize=0)
            except OSError as e:
                self.state = f"error: {e}"
                self.log("error", f"{self.name}: cannot start srt-live-transmit: {e}")
                time.sleep(5)
                continue
            self.state = "waiting"
            if gen != self.generation:             # retargeted while starting
                self._kill()
            threading.Thread(target=self._read_err, args=(self.proc,), daemon=True).start()
            for raw in self.proc.stdout:
                self._stdout_line(raw.decode("utf-8", errors="replace").strip())
            rc = self.proc.wait()
            if not self.running:
                break
            if gen != self.generation:
                continue
            self.restarts += 1
            self.state = f"exited ({rc}), restarting"
            self.log("srt", f"{self.name}: srt-live-transmit exited with {rc}, restart in 2 s")
            time.sleep(2)
        self.state = "stopped"

    def _stdout_line(self, line: str):
        if line.startswith("{"):
            try:
                self.stats = json.loads(line)
            except ValueError:
                return
            self.stats_ts = time.time()
            for d in ("send", "recv"):
                for k in self.COUNTERS:
                    v = (self.stats.get(d) or {}).get(k)
                    if isinstance(v, (int, float)):
                        self.totals[f"{d}_{k}"] = self.totals.get(f"{d}_{k}", 0) + int(v)
        elif line:
            self._line(line)

    def _read_err(self, proc):
        for raw in proc.stderr:
            line = raw.decode("utf-8", errors="replace").strip()
            if line and "SRTO_PAYLOADSIZE fixed" not in line:      # FEC notice repeated on every connect
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
            "send_packets": t.get("send_packets", 0), "recv_packets": t.get("recv_packets", 0),
            "send_lost": t.get("send_packetsLost", 0), "send_retrans": t.get("send_packetsRetransmitted", 0),
            "send_dropped": t.get("send_packetsDropped", 0), "send_fec_extra": t.get("send_packetsFilterExtra", 0),
            "recv_lost": t.get("recv_packetsLost", 0), "recv_retrans": t.get("recv_packetsRetransmitted", 0),
            "recv_dropped": t.get("recv_packetsDropped", 0), "recv_belated": t.get("recv_packetsBelated", 0),
            "recv_fec_recovered": t.get("recv_packetsFilterSupply", 0), "recv_fec_failed": t.get("recv_packetsFilterLoss", 0),
            "recv_fec_extra": t.get("recv_packetsFilterExtra", 0),
            "lines": list(self.lines)[-12:],
        }


IDLE_SRT = {"state": "idle", "restarts": 0, "stats_fresh": False, "rtt_ms": None, "bandwidth_mbps": None, "send_mbps": 0,
            "recv_mbps": 0, "send_packets": 0, "recv_packets": 0, "send_lost": 0, "send_retrans": 0, "send_dropped": 0,
            "send_fec_extra": 0, "recv_lost": 0, "recv_retrans": 0, "recv_dropped": 0, "recv_belated": 0,
            "recv_fec_recovered": 0, "recv_fec_failed": 0, "recv_fec_extra": 0, "lines": []}


class Monitor:
    """Passive listener in a multicast group (srt-live-transmit owns the real socket): counts and checks RTP."""

    def __init__(self, name: str, log):
        self.name, self.log = name, log
        self.sock: socket.socket | None = None
        self.lock = threading.Lock()
        self.packets = 0
        self.last_rx = 0.0
        self.rtp = RtpStats()
        self.running = True
        threading.Thread(target=self._loop, daemon=True, name=f"mon-{name}").start()

    def watch(self, group: str | None, port: int | None, interface_ip: str, source_ip: str | None = None):
        with self.lock:
            if self.sock:
                try:
                    self.sock.close()
                except OSError:
                    pass
                self.sock = None
            self.rtp.last_seq = None
            if not group:
                return
            try:
                self.sock = open_rx_socket(group, int(port), interface_ip, source_ip, reuseport=False)
            except OSError as e:
                self.log("error", f"{self.name}: cannot monitor {group}:{port}: {e}")

    def close(self):
        self.running = False
        self.watch(None, None, "")

    def _loop(self):
        while self.running:
            sock = self.sock
            if not sock:
                time.sleep(0.1)
                continue
            try:
                r, _, _ = select.select([sock], [], [], 0.3)
                if not r:
                    continue
                for _ in range(256):
                    data = sock.recv(2048)
                    self.packets += 1
                    self.last_rx = time.time()
                    self.rtp.check(data)
            except BlockingIOError:
                pass
            except (OSError, ValueError):
                time.sleep(0.05)


# ---------------------------------------------------------------- TX
class TxPipeline:
    """One TX channel: the multicast selected via IS-05 on the virtual receiver goes to SRT; the SDP on port+1."""

    def __init__(self, ch: dict, index: int, interface_ip: str, log):
        self.ch, self.index, self.interface_ip, self.log = ch, index, interface_ip, log
        self.lock = threading.Lock()
        self.source: dict | None = None          # {multicast_ip, source_ip, port, sdp}
        self.data: SrtProcess | None = None      # media link, only while a source is connected
        self.cp = local_control_port(index)
        self.ctrl = SrtProcess(f"TX {ch['label']} SDP", f"udp://127.0.0.1:{self.cp}",
                               srt_uri(ch["srt"], default_mode="caller", adapter=interface_ip, port=control_port(ch), fec=False),
                               log, stats=False)
        self.ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.monitor = Monitor(f"tx-{ch['id']}", log)
        self.running = False

    def start(self):
        self.running = True
        self.ctrl.start()
        threading.Thread(target=self._sdp_loop, daemon=True, name=f"tx-sdp-{self.ch['id']}").start()

    def stop(self):
        self.running = False
        self.set_source(None)
        self.ctrl.stop()
        self.monitor.close()

    def set_source(self, source: dict | None):
        """source: {multicast_ip, source_ip, port, sdp} or None (disconnect)."""
        with self.lock:
            if self.data:
                self.data.stop()
                self.data = None
            self.source = source
            if not source:
                self.monitor.watch(None, None, self.interface_ip)
                return
            info = sdp_parse(source.get("sdp") or "")
            self.monitor.rtp.reset_expectation(info.get("payload_type"), info.get("encoding"), info.get("channels"))
            q = f"adapter={self.interface_ip}" + (f"&source={source['source_ip']}" if source.get("source_ip") else "")
            src = f"udp://@{source['multicast_ip']}:{int(source['port'])}?{q}"
            dst = srt_uri(self.ch["srt"], default_mode="caller", adapter=self.interface_ip)
            self.data = SrtProcess(f"TX {self.ch['label']}", src, dst, self.log)
            self.data.start()
            self.monitor.watch(source["multicast_ip"], int(source["port"]), self.interface_ip, source.get("source_ip"))
            self.log("tx", f"{self.ch['label']}: {source.get('source_ip') or '*'} -> {source['multicast_ip']}:{source['port']} via SRT")

    def _sdp_loop(self):
        while self.running:
            src = self.source
            if src and src.get("sdp"):
                for d in sdp_datagrams(src["sdp"]):
                    try:
                        self.ctrl_sock.sendto(d, ("127.0.0.1", self.cp))
                    except OSError:
                        pass
            time.sleep(1.0)

    def status(self) -> dict:
        data = self.data
        return {"source": {k: v for k, v in (self.source or {}).items() if k != "sdp"} if self.source else None,
                "packets": self.monitor.packets, "rtp": self.monitor.rtp.snapshot(),
                "receiving": time.time() - self.monitor.last_rx < 1.0,
                "srt": data.summary() if data else dict(IDLE_SRT), "sdp_link": self.ctrl.state}


# ---------------------------------------------------------------- RX
class RxPipeline:
    """One RX channel: SRT to the virtual sender's multicast (direct), SDP from port+1, optional restamp relay."""

    def __init__(self, ch: dict, index: int, interface_ip: str, clock: MediaClock, log, on_sdp):
        self.ch, self.index, self.interface_ip, self.clock, self.log, self.on_sdp = ch, index, interface_ip, clock, log, on_sdp
        self.lp = local_port(index)
        self.ttl = int((ch.get("out") or {}).get("ttl") or 32)
        self.restamp = bool(ch.get("restamp", False))
        self.dest: tuple[str, int] | None = None     # set by IS-05 activation (master_enable)
        self.sdp: str | None = None
        self.sdp_ts = 0.0
        self.parser = FrameParser(self._on_frame)
        self.cp = local_control_port(index)
        self.ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ctrl_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ctrl_sock.bind(("127.0.0.1", self.cp))
        self.ctrl = SrtProcess(f"RX {ch['label']} SDP",
                               srt_uri(ch["srt"], default_mode="listener", adapter=interface_ip, port=control_port(ch), fec=False),
                               f"udp://127.0.0.1:{self.cp}", log, stats=False)
        src = srt_uri(ch["srt"], default_mode="listener", adapter=interface_ip)
        # direct: srt-live-transmit writes the multicast itself; while the output is off it writes to an unused local port
        self.data = SrtProcess(f"RX {ch['label']}", src, f"udp://127.0.0.1:{self.lp}", log)
        self.monitor = Monitor(f"rx-{ch['id']}", log)
        self.running = False
        # restamp relay (only in restamp mode)
        self.rate = 48000
        self.delta: int | None = None
        self.resyncs = 0
        self.err_ms = 0.0
        self.relay_in = self.relay_out = 0
        self.send_errors = 0
        self.sock = self.out = None
        if self.restamp:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("127.0.0.1", self.lp))
            self.out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.out.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.ttl)
            try:
                self.out.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(interface_ip))
                self.out.bind((interface_ip, 0))
            except OSError as e:
                log("error", f"{ch['label']}: bind output to {interface_ip} failed: {e}")
            self.out.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        self.source_port = self.out.getsockname()[1] if self.out else None

    def start(self):
        self.running = True
        self.ctrl.start()
        self.data.start()
        threading.Thread(target=self._ctrl_loop, daemon=True, name=f"rx-sdp-{self.ch['id']}").start()
        if self.restamp:
            threading.Thread(target=self._relay, daemon=True, name=f"rx-{self.ch['id']}").start()

    def stop(self):
        self.running = False
        self.ctrl.stop()
        self.data.stop()
        self.monitor.close()
        for s in (self.sock, self.out, self.ctrl_sock):
            try:
                if s:
                    s.close()
            except OSError:
                pass

    def _ctrl_loop(self):
        while self.running:
            try:
                r, _, _ = select.select([self.ctrl_sock], [], [], 0.5)
                if r:
                    self.parser.feed(self.ctrl_sock.recv(4096))
            except (OSError, ValueError):
                if not self.running:
                    break
                time.sleep(0.1)

    def _on_frame(self, sdp_text: str):
        self.sdp_ts = time.time()
        if sdp_text != self.sdp:
            self.sdp = sdp_text
            self.on_sdp(self.ch["id"], sdp_text)

    def set_output(self, dest: tuple[str, int] | None):
        if dest != self.dest:
            self.log("rx", f"{self.ch['label']}: output {'-> %s:%d' % dest if dest else 'off'}")
        self.dest = dest
        self.delta = None
        if not self.restamp:
            target = (f"udp://{dest[0]}:{dest[1]}?adapter={self.interface_ip}&ttl={self.ttl}" if dest
                      else f"udp://127.0.0.1:{self.lp}")
            self.data.retarget(dst=target)
        if dest:
            self.monitor.watch(dest[0], dest[1], self.interface_ip)
        else:
            self.monitor.watch(None, None, self.interface_ip)

    def set_format(self, info: dict):
        self.monitor.rtp.reset_expectation(info.get("payload_type"), info.get("encoding"), info.get("channels"))
        if info.get("sample_rate") and info["sample_rate"] != self.rate:
            self.rate = info["sample_rate"]
            self.delta = None

    def _relay(self):
        tolerance = lambda: int(self.rate * float(self.ch.get("resync_ms") or 20) / 1000)
        while self.running:
            try:
                r, _, _ = select.select([self.sock], [], [], 0.5)
                if not r:
                    continue
                data = self.sock.recv(2048)
            except (OSError, ValueError):
                if not self.running:
                    break
                time.sleep(0.05)
                continue
            if len(data) < 12 or data[0] >> 6 != 2:
                continue
            self.relay_in += 1
            dest = self.dest
            if not dest:
                continue
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
            try:
                self.out.sendto(data[:4] + struct.pack(">I", new) + data[8:], dest)
                self.relay_out += 1
            except OSError:
                self.send_errors += 1

    def status(self) -> dict:
        srt = self.data.summary()
        return {"packets_in": srt["recv_packets"], "packets_out": self.monitor.packets, "send_errors": self.send_errors,
                "rtp": self.monitor.rtp.snapshot(), "receiving": time.time() - self.monitor.last_rx < 1.0,
                "sdp_age_s": round(time.time() - self.sdp_ts, 1) if self.sdp_ts else None, "sdp_link": self.ctrl.state,
                "output": f"{self.dest[0]}:{self.dest[1]}" if self.dest else None, "source_port": self.source_port,
                "mode": "restamp relay" if self.restamp else "direct",
                "restamp": self.restamp, "restamp_resyncs": self.resyncs, "restamp_err_ms": round(self.err_ms, 2),
                "clock": self.clock.source(), "srt": srt}


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
def open_rx_socket(group: str, port: int, interface_ip: str, source_ip: str | None = None, reuseport: bool = True) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if reuseport and hasattr(socket, "SO_REUSEPORT"):
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
