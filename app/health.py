"""Derives the BCP-008 domain statuses of every channel once per second from the pipeline measurements.

TX channel -> NcReceiverMonitor (reception only: the multicast input; the SRT link is not part of it)
  link          interface operstate
  connection    no multicast packets / RTP sequence gaps on the multicast input -> Unhealthy
  stream        not RTP -> Unhealthy, payload type or payload size not matching the SDP -> PartiallyHealthy
  sync          NotUsed, source "internal" (the bridge forwards packets, it does not lock to PTP itself)

RX channel -> NcSenderMonitor
  link          interface operstate
  transmission  send errors on the multicast output -> Unhealthy
  essence       no SDP / SRT not connected / no packets -> Unhealthy,
                SRT loss, retransmissions or RTP sequence gaps -> PartiallyHealthy (inherited from the SRT "receiver")
  sync          NotUsed, source "internal"
"""
from __future__ import annotations

import threading
import time

import pipelines
from ncp import HEALTHY, PARTIAL, UNHEALTHY, INACTIVE


def link_status(ifname: str) -> tuple[int, str | None]:
    try:
        with open(f"/sys/class/net/{ifname}/operstate") as f:
            state = f.read().strip()
    except OSError:
        return 1, None          # not Linux / unknown: assume up
    if state in ("up", "unknown"):
        return 1, None
    return 3, f"{ifname} is {state}"


def _delta(cur: dict, prev: dict, key: str) -> int:
    return max(0, int(cur.get(key) or 0) - int(prev.get(key) or 0))


class Health:
    def __init__(self, bridge):
        self.b = bridge
        self.prev: dict[str, dict] = {}
        self.running = True

    def start(self):
        threading.Thread(target=self._run, daemon=True, name="health").start()

    def _run(self):
        while self.running:
            t0 = time.time()
            try:
                self.tick()
            except Exception as e:     # noqa: BLE001 - never let the monitor thread die
                self.b.log("error", f"health: {e}")
            time.sleep(max(0.1, 1.0 - (time.time() - t0)))

    def tick(self):
        link = link_status(self.b.interface_name())
        for ch in list(self.b.config()["channels"]):
            chid = ch["id"]
            p = self.b.pipes.get(chid)
            if isinstance(p, pipelines.TxPipeline):
                self._tx(ch, p, link)
            elif isinstance(p, pipelines.RxPipeline):
                self._rx(ch, p, link)
            else:
                self.b.ncp.evaluate(chid, {"link": link})

    def _flat(self, st: dict) -> dict:
        flat = dict(st.get("rtp") or {})
        flat.update({f"srt_{k}": v for k, v in (st.get("srt") or {}).items() if isinstance(v, (int, float))})
        for k in ("packets", "packets_in", "packets_out", "send_errors"):
            if k in st:
                flat[k] = st[k]
        return flat

    def _tx(self, ch, p, link):
        st = p.status()
        cur = self._flat(st)
        prev = self.prev.get(ch["id"], cur)
        self.prev[ch["id"]] = cur
        src = st.get("source") or {}
        group = f"{src.get('multicast_ip')}:{src.get('port')}" if src else "?"
        packets = _delta(cur, prev, "packets")
        lost = _delta(cur, prev, "lost")
        not_rtp = _delta(cur, prev, "not_rtp")
        pt_bad = _delta(cur, prev, "pt_mismatch")
        size_bad = _delta(cur, prev, "size_mismatch")

        # reception only: whether the multicast arrives completely (the SRT link is shown in the GUI, not here)
        if packets == 0:
            connection = (UNHEALTHY, f"no packets received from {group}")
        elif lost:
            connection = (UNHEALTHY, f"{lost} packets lost on the multicast input from {group}")
        else:
            connection = (HEALTHY, None)

        if packets == 0:
            stream = (UNHEALTHY, "no stream")
        elif not_rtp:
            stream = (UNHEALTHY, f"{not_rtp} packets are not RTP")
        elif pt_bad:
            stream = (PARTIAL, f"payload type {cur.get('last_pt')} does not match the SDP ({cur.get('expect_pt')})")
        elif size_bad:
            stream = (PARTIAL, f"payload size {cur.get('last_payload')} bytes is not a multiple of the "
                               f"{cur.get('frame_bytes')} byte frame from the SDP")
        else:
            stream = (HEALTHY, None)

        counters = {"lost": {"multicast input": (lost, "RTP sequence gaps on the multicast input")}, "late": {}}
        self.b.ncp.evaluate(ch["id"], {"link": link, "connection": connection, "stream": stream, "sync": (INACTIVE, None)},
                            counters)

    def _rx(self, ch, p, link):
        st = p.status()
        cur = self._flat(st)
        prev = self.prev.get(ch["id"], cur)
        self.prev[ch["id"]] = cur
        srt = st["srt"]
        listen = f"{ch['srt'].get('host') or 'listener'}:{ch['srt'].get('port')}"
        packets = _delta(cur, prev, "packets_in")
        send_errors = _delta(cur, prev, "send_errors")
        lost = _delta(cur, prev, "lost")
        srt_lost = _delta(cur, prev, "srt_recv_lost") + _delta(cur, prev, "srt_recv_dropped")
        retrans = _delta(cur, prev, "srt_recv_retrans")

        transmission = (UNHEALTHY, f"{send_errors} send errors on {st.get('output')}") if send_errors else (HEALTHY, None)
        if not self.b.rx_sdp(ch["id"]):
            essence = (UNHEALTHY, "no source SDP received yet")
        elif srt["state"] != "connected":
            essence = (UNHEALTHY, f"no essence: SRT {listen} not connected ({srt['state']})")
        elif packets == 0:
            essence = (UNHEALTHY, "no essence: no packets received via SRT")
        elif srt_lost or lost:
            essence = (PARTIAL, f"{max(srt_lost, lost)} packets lost on the SRT link")
        elif retrans:
            essence = (PARTIAL, f"SRT recovered losses by retransmitting {retrans} packets")
        else:
            essence = (HEALTHY, None)
        counters = {"transmission": {"send errors": (send_errors, "errors sending the multicast output")}}
        self.b.ncp.evaluate(ch["id"], {"link": link, "transmission": transmission, "essence": essence, "sync": (INACTIVE, None)},
                            counters)
