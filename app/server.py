#!/usr/bin/env python3
"""AES67 SRT Bridge: AES67 multicast <-> SRT (srt-live-transmit) with NMOS IS-04/IS-05 and a web GUI.

TX channel = virtual NMOS receiver. Connect it (IS-05) to an AES67 sender and its multicast goes out via SRT.
RX channel = virtual NMOS sender. It receives SRT and re-sends the stream to a configurable multicast group,
with the original SDP (sent in-band over SRT) rewritten for the new address.

    python3 server.py            # config in $DATA_DIR/config.json (default /data)
"""
from __future__ import annotations

import copy
import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import dnssd
import health
import hostdns
import ncp
import nmos_node
import pipelines
import sdp as sdplib
from websocket import ServerWebSocket

BASE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(BASE, "static")
DATA_DIR = os.environ.get("DATA_DIR", "/data" if os.path.isdir("/data") else BASE)
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")

DEFAULT_CONFIG = {
    "node_seed": None,
    "node_label": "AES67 SRT Bridge",
    "http_port": int(os.environ.get("HTTP_PORT", "8095")),
    "interface": os.environ.get("MEDIA_INTERFACE", ""),
    "registry": {"mode": "auto", "url": "", "query_url": "", "domains": [], "dns_server": "", "mdns": True},
    "ptp_gmid": "",
    "clock": {"mode": "auto", "utc_offset": 37},
    "channels": [],
    "conn_state": {},
    "rx_sdp_cache": {},
    "annotations": {},
    "ncp_state": {},
}

TX_DEFAULT = {"dir": "tx", "label": "SRT TX", "enabled": True,
              "srt": {"mode": "caller", "host": "", "port": 9000, "latency": 120, "passphrase": "", "pbkeylen": 16, "streamid": ""}}
RX_DEFAULT = {"dir": "rx", "label": "SRT RX", "enabled": True,
              "srt": {"mode": "listener", "host": "", "port": 9000, "latency": 120, "passphrase": "", "pbkeylen": 16, "streamid": ""},
              "out": {"dest_ip": "239.69.10.1", "dest_port": 5004, "ttl": 32},
              "restamp": False, "resync_ms": 20, "refclk": "", "manual_sdp": "", "default_channels": 2, "auto_enable": True}

LOG: deque = deque(maxlen=400)


def log(kind: str, text: str):
    LOG.appendleft({"ts": time.strftime("%H:%M:%S"), "kind": kind, "text": text})
    print(f"[{kind}] {text}", flush=True)


def merge(default: dict, saved: dict) -> dict:
    out = copy.deepcopy(default)
    for k, v in (saved or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict) and k not in ("conn_state", "rx_sdp_cache", "annotations", "ncp_state"):
            out[k] = merge(out[k], v)
        else:
            out[k] = v
    return out


# ====================================================================== interfaces
def list_interfaces() -> list[dict]:
    try:
        out = subprocess.run(["ip", "-j", "-4", "addr", "show"], capture_output=True, text=True, timeout=3).stdout
        res = []
        for it in json.loads(out or "[]"):
            for a in it.get("addr_info", []):
                if a.get("family") == "inet":
                    res.append({"name": it["ifname"], "ip": a["local"], "prefix": a.get("prefixlen"), "up": "UP" in it.get("flags", [])})
        return res
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    # fallback (development on macOS): only the default route address
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return [{"name": "default", "ip": s.getsockname()[0], "prefix": None, "up": True}]
    except OSError:
        return [{"name": "lo", "ip": "127.0.0.1", "prefix": 8, "up": True}]
    finally:
        s.close()


def default_interface() -> dict:
    ifs = [i for i in list_interfaces() if not i["ip"].startswith("127.")]
    try:
        out = subprocess.run(["ip", "-j", "-4", "route", "show", "default"], capture_output=True, text=True, timeout=3).stdout
        dev = (json.loads(out or "[]") or [{}])[0].get("dev")
        for i in ifs:
            if i["name"] == dev:
                return i
    except (OSError, ValueError, subprocess.TimeoutExpired, IndexError):
        pass
    return ifs[0] if ifs else {"name": "lo", "ip": "127.0.0.1"}


# ====================================================================== bridge
class Bridge:
    def __init__(self):
        self.lock = threading.RLock()
        self.cfg = merge(DEFAULT_CONFIG, self._load())
        if not self.cfg.get("node_seed"):
            self.cfg["node_seed"] = str(uuid.uuid4())
            self.save()
        self.clock = pipelines.MediaClock(self.cfg["clock"].get("mode", "auto"), int(self.cfg["clock"].get("utc_offset", 37)))
        self.pipes: dict[str, object] = {}
        self.pipe_sig: dict[str, str] = {}
        self.rx_sdps: dict[str, str] = dict(self.cfg.get("rx_sdp_cache") or {})
        self.tx_sdps: dict[str, str] = {}
        self._iface = None
        self.node = nmos_node.Node(self)
        self.ncp = ncp.NcpServer(self)
        self.health = health.Health(self)

    def log(self, kind: str, text: str):
        log(kind, text)

    # ------------------------------------------------------------------ config
    def _load(self) -> dict:
        try:
            with open(CONFIG_FILE, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def save(self):
        with self.lock:
            os.makedirs(DATA_DIR, exist_ok=True)
            tmp = CONFIG_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.cfg, f, indent=2)
            os.replace(tmp, CONFIG_FILE)

    def config(self) -> dict:
        return self.cfg

    def channel(self, chid: str) -> dict | None:
        for ch in self.cfg["channels"]:
            if ch["id"] == chid:
                return ch
        return None

    def http_port(self) -> int:
        return int(self.cfg.get("http_port") or 8095)

    def iface(self) -> dict:
        if self._iface is None:
            name = self.cfg.get("interface")
            ifs = list_interfaces()
            self._iface = next((i for i in ifs if i["name"] == name), None) or default_interface()
        return self._iface

    def interface_ip(self) -> str:
        return self.iface()["ip"]

    def interface_name(self) -> str:
        return self.iface()["name"]

    def save_conn_state(self):
        with self.node.lock:
            self.cfg["conn_state"] = {rid: copy.deepcopy(st.active) for rid, st in self.node.conn.items()}
        self.save()

    # ------------------------------------------------------------------ SDP
    def rx_sdp(self, chid: str) -> str | None:
        ch = self.channel(chid) or {}
        manual = (ch.get("manual_sdp") or "").strip()
        return manual or self.rx_sdps.get(chid)

    def rx_source_port(self, chid: str) -> int | None:
        p = self.pipes.get(chid)
        return getattr(p, "source_port", None)

    def on_rx_sdp(self, chid: str, text: str):
        ch = self.channel(chid)
        if not ch:
            return
        old = self.rx_sdps.get(chid)
        if old == text:
            return
        self.rx_sdps[chid] = text
        self.cfg["rx_sdp_cache"][chid] = text
        self.save()
        info = sdplib.parse(text)
        log("rx", f"{ch['label']}: source SDP {'received' if not old else 'changed'} "
                  f"({info.get('encoding')}/{info.get('sample_rate')}/{info.get('channels')}ch, {info.get('multicast_ip')}:{info.get('port')})")
        p = self.pipes.get(chid)
        if isinstance(p, pipelines.RxPipeline):
            p.set_format(info)
        self.node.build()
        if ch.get("auto_enable") and not old:
            st = self.node.conn_state(self.node.sender_id(chid), "sender")
            if not st.active.get("master_enable"):
                self.node.internal_patch("sender", chid, {"master_enable": True})

    # ------------------------------------------------------------------ IS-05 callbacks
    def tx_activate(self, chid: str, active: dict):
        p = self.pipes.get(chid)
        ch = self.channel(chid)
        tp = active["transport_params"][0]
        sdp_text = (active.get("transport_file") or {}).get("data")
        if active.get("master_enable") and tp.get("multicast_ip") and tp.get("rtp_enabled", True):
            src = {"multicast_ip": tp["multicast_ip"], "source_ip": tp.get("source_ip"),
                   "port": int(tp.get("destination_port") or 5004), "sdp": sdp_text, "sender_id": active.get("sender_id")}
            self.tx_sdps[chid] = sdp_text or ""
            log("is05", f"TX {ch['label']}: connected to {src['source_ip'] or '*'} -> {src['multicast_ip']}:{src['port']}")
        else:
            src = None
            log("is05", f"TX {ch['label']}: disconnected")
        if isinstance(p, pipelines.TxPipeline):
            p.set_source(src)
        self.ncp.activate(chid) if src else self.ncp.deactivate(chid)

    def rx_activate(self, chid: str, active: dict):
        p = self.pipes.get(chid)
        ch = self.channel(chid)
        tp = active["transport_params"][0]
        dest = (tp["destination_ip"], int(tp["destination_port"])) if active.get("master_enable") and tp.get("rtp_enabled", True) else None
        log("is05", f"RX {ch['label']}: output {'%s:%d' % dest if dest else 'disabled'}")
        if isinstance(p, pipelines.RxPipeline):
            p.set_output(dest)
        self.ncp.activate(chid) if dest else self.ncp.deactivate(chid)

    # ------------------------------------------------------------------ pipelines
    def sync_monitors(self):
        """One BCP-008 monitor per channel, labelled like its (possibly IS-13 annotated) NMOS resource."""
        chans = []
        for ch in self.cfg["channels"]:
            kind = "receiver" if ch["dir"] == "tx" else "sender"
            rid = self.node.receiver_id(ch["id"]) if kind == "receiver" else self.node.sender_id(ch["id"])
            res = self.node.get(kind, rid)
            chans.append({"chid": ch["id"], "kind": kind, "resource_id": rid, "label": (res or {}).get("label") or ch["label"]})
        self.ncp.sync_channels(chans)

    def annotations_changed(self):
        self.sync_monitors()

    def apply(self):
        """Start/stop/restart pipelines so they match the configuration."""
        self.node.build()
        self.sync_monitors()
        with self.lock:
            want = {ch["id"]: ch for ch in self.cfg["channels"] if ch.get("enabled", True)}
            ip = self.interface_ip()
            for chid in list(self.pipes):
                ch = want.get(chid)
                sig = json.dumps([ch, ip], sort_keys=True) if ch else None
                if sig != self.pipe_sig.get(chid):
                    self.pipes.pop(chid).stop()
                    self.pipe_sig.pop(chid, None)
            for chid, ch in want.items():
                if chid in self.pipes:
                    continue
                index = int(chid)
                try:
                    if ch["dir"] == "tx":
                        p = pipelines.TxPipeline(ch, index, ip, log)
                    else:
                        p = pipelines.RxPipeline(ch, index, ip, self.clock, log, self.on_rx_sdp)
                        sdp_text = self.rx_sdp(chid)
                        if sdp_text:
                            p.set_format(sdplib.parse(sdp_text))
                except OSError as e:
                    log("error", f"{ch['label']}: cannot start pipeline: {e}")
                    continue
                p.start()
                self.pipes[chid] = p
                self.pipe_sig[chid] = json.dumps([ch, ip], sort_keys=True)
                # re-apply the active IS-05 state
                if ch["dir"] == "tx":
                    st = self.node.conn_state(self.node.receiver_id(chid), "receiver")
                    self.tx_activate(chid, st.active)
                else:
                    st = self.node.conn_state(self.node.sender_id(chid), "sender")
                    active = copy.deepcopy(st.active)
                    active["transport_params"] = [self.node.resolve("sender", chid, active["transport_params"][0])]
                    self.rx_activate(chid, active)
        self.node.build()
        self.sync_monitors()

    def stop(self):
        for p in list(self.pipes.values()):
            p.stop()

    # ------------------------------------------------------------------ GUI API
    def state(self) -> dict:
        chans = []
        for ch in self.cfg["channels"]:
            p = self.pipes.get(ch["id"])
            entry = copy.deepcopy(ch)
            entry["status"] = p.status() if p else None
            if ch["dir"] == "tx":
                rid = self.node.receiver_id(ch["id"])
                st = self.node.conn_state(rid, "receiver")
                entry["nmos_id"] = rid
                entry["active"] = {k: v for k, v in st.active.items() if k != "transport_file"}
                entry["has_sdp"] = bool((st.active.get("transport_file") or {}).get("data"))
            else:
                sid = self.node.sender_id(ch["id"])
                st = self.node.conn_state(sid, "sender")
                entry["nmos_id"] = sid
                entry["active"] = copy.deepcopy(st.active)
                entry["active"]["transport_params"] = [self.node.resolve("sender", ch["id"], st.active["transport_params"][0])]
                src = self.rx_sdp(ch["id"])
                entry["sdp_info"] = sdplib.parse(src) if src else None
                entry["sdp_source"] = "manual" if (ch.get("manual_sdp") or "").strip() else ("in-band" if src else None)
            res = self.node.get("receiver" if ch["dir"] == "tx" else "sender", entry["nmos_id"]) or {}
            entry["nmos_label"] = res.get("label")
            entry["nmos_tags"] = {k: v for k, v in (res.get("tags") or {}).items() if v}
            entry["monitor"] = self.ncp.summary(ch["id"])
            chans.append(entry)
        cfg = {k: v for k, v in self.cfg.items() if k not in ("channels", "conn_state", "rx_sdp_cache", "annotations", "ncp_state")}
        return {
            "config": cfg, "channels": chans, "interface": self.iface(), "interfaces": list_interfaces(),
            "node": {"id": self.node.node_id, "device_id": self.node.device_id, "api": self.node.base_url() + "/x-nmos/",
                     "ncp": f"ws://{self.interface_ip()}:{self.http_port()}/x-nmos/ncp/v1.0",
                     "is12_controllers": self.ncp.controller_count()},
            "registry": {"url": self.node.registry, "via": self.node.registry_label, "status": self.node.reg_status,
                         "error": self.node.reg_error, "query": self.node.query_url()},
            "clock": self.clock.source(), "log": list(LOG)[:150],
        }

    def update_settings(self, body: dict):
        with self.lock:
            old_reg = json.dumps(self.cfg["registry"], sort_keys=True)
            old_if = self.cfg.get("interface")
            for k in ("node_label", "interface", "ptp_gmid"):
                if k in body:
                    self.cfg[k] = str(body[k] or "").strip()
            if "registry" in body:
                self.cfg["registry"] = merge(self.cfg["registry"], body["registry"])
                doms = self.cfg["registry"].get("domains")
                if isinstance(doms, str):
                    self.cfg["registry"]["domains"] = [d.strip() for d in doms.replace(",", " ").split() if d.strip()]
            if "clock" in body:
                self.cfg["clock"] = merge(self.cfg["clock"], body["clock"])
                self.clock.mode = self.cfg["clock"].get("mode", "auto")
                self.clock.utc_offset = int(self.cfg["clock"].get("utc_offset", 37))
            self.save()
        if self.cfg.get("interface") != old_if:
            self._iface = None
            self.node.reset_registry()
        if json.dumps(self.cfg["registry"], sort_keys=True) != old_reg:
            self.node.reset_registry()
        self.apply()

    def upsert_channel(self, body: dict, chid: str | None = None) -> dict:
        with self.lock:
            if chid:
                ch = self.channel(chid)
                if not ch:
                    raise KeyError(chid)
                d = body.get("dir", ch["dir"])
                if "label" in body and body["label"] != ch["label"]:
                    ids = [self.node.receiver_id(chid)] if ch["dir"] == "tx" else \
                          [self.node.sender_id(chid), self.node.uid("source", chid), self.node.uid("flow", chid)]
                    for rid in ids:
                        a = self.cfg.get("annotations", {}).get(rid)
                        if a:
                            a.pop("label", None)
                            if not a:
                                self.cfg["annotations"].pop(rid, None)
                    for role in (f"receiver-monitor-{chid}", f"sender-monitor-{chid}"):
                        self.cfg.get("ncp_state", {}).get("monitors", {}).get(role, {}).pop("userLabel", None)
                new = merge(ch, body)
                new["dir"], new["id"] = ch["dir"], ch["id"]
                self.cfg["channels"][self.cfg["channels"].index(ch)] = new
            else:
                d = body.get("dir")
                if d not in ("tx", "rx"):
                    raise ValueError("dir must be tx or rx")
                used = {int(c["id"]) for c in self.cfg["channels"]}
                nid = next(i for i in range(1, 1000) if i not in used)
                new = merge(TX_DEFAULT if d == "tx" else RX_DEFAULT, body)
                new["id"] = str(nid)
                new["dir"] = d
                self.cfg["channels"].append(new)
            self._validate(new)
            self.save()
        self.apply()
        return new

    def _validate(self, ch: dict):
        ch["srt"]["port"] = int(ch["srt"]["port"])
        ch["srt"]["latency"] = int(ch["srt"].get("latency") or 120)
        if ch["srt"].get("mode") == "caller" and not (ch["srt"].get("host") or "").strip():
            raise ValueError("SRT caller needs a host")
        pw = ch["srt"].get("passphrase") or ""
        if pw and not 10 <= len(pw) <= 79:
            raise ValueError("SRT passphrase must be 10..79 characters")
        if ch["dir"] == "rx":
            if not sdplib.is_multicast(ch["out"].get("dest_ip")):
                raise ValueError("output address must be a multicast address")
            ch["out"]["dest_port"] = int(ch["out"]["dest_port"])
            ch["out"]["ttl"] = int(ch["out"].get("ttl") or 32)

    def delete_channel(self, chid: str):
        with self.lock:
            ch = self.channel(chid)
            if not ch:
                raise KeyError(chid)
            self.cfg["channels"].remove(ch)
            self.cfg["rx_sdp_cache"].pop(chid, None)
            for rid in (self.node.receiver_id(chid), self.node.sender_id(chid), self.node.uid("source", chid), self.node.uid("flow", chid)):
                self.cfg.get("annotations", {}).pop(rid, None)
            for role in (f"receiver-monitor-{chid}", f"sender-monitor-{chid}"):
                self.cfg.get("ncp_state", {}).get("monitors", {}).pop(role, None)
            self.rx_sdps.pop(chid, None)
            for rid in (self.node.receiver_id(chid), self.node.sender_id(chid)):
                self.cfg["conn_state"].pop(rid, None)
            self.save()
        self.apply()

    def registry_senders(self) -> list[dict]:
        q = self.node.query_url()
        if not q:
            raise RuntimeError("no registry known")
        reg = nmos_query(q)
        flows = {f["id"]: f for f in reg.get("flows")}
        devices = {d["id"]: d for d in reg.get("devices")}
        nodes = {n["id"]: n for n in reg.get("nodes")}
        own = {self.node.sender_id(c["id"]) for c in self.cfg["channels"]}
        out = []
        for s in reg.get("senders"):
            f = flows.get(s.get("flow_id")) or {}
            if not str(f.get("format", "")).endswith("audio") or not str(s.get("transport", "")).startswith("urn:x-nmos:transport:rtp"):
                continue
            dev = devices.get(s.get("device_id")) or {}
            out.append({"id": s["id"], "label": s.get("label"), "manifest_href": s.get("manifest_href"),
                        "node": (nodes.get(dev.get("node_id")) or {}).get("label", ""), "media_type": f.get("media_type"),
                        "own": s["id"] in own})
        return sorted(out, key=lambda x: (x["node"], x["label"] or ""))

    def connect_tx(self, chid: str, body: dict) -> tuple[int, dict]:
        sdp_text, sender_id = body.get("sdp"), body.get("sender_id")
        if sender_id and not sdp_text:
            q = self.node.query_url()
            s = nmos_query(q).get(f"senders/{sender_id}")
            href = s.get("manifest_href")
            if not href:
                return 400, {"error": "sender has no manifest_href"}
            sdp_text = http_text(href)
        if not sdp_text:
            return 400, {"error": "need sdp or sender_id"}
        return self.node.internal_patch("receiver", chid, {"sender_id": sender_id, "master_enable": True,
                                                           "transport_file": {"data": sdp_text, "type": "application/sdp"}})


def nmos_query(base: str):
    from nmos_query import Query
    return Query(base)


def http_text(url: str) -> str:
    import urllib.request
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.read().decode("utf-8", errors="replace")


# ====================================================================== HTTP
BRIDGE: Bridge | None = None


class Handler(BaseHTTPRequestHandler):
    server_version = "aes67-srt-bridge/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code: int, payload, ctype: str = "application/json"):
        if ctype == "application/json":
            data = json.dumps(payload, indent=None).encode()
        elif isinstance(payload, (bytes, bytearray)):
            data = bytes(payload)
        else:
            data = str(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, PUT, POST, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization")
        self.send_header("Access-Control-Expose-Headers", "Link, Content-Length")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return None
        raw = self.rfile.read(n)
        try:
            return json.loads(raw)
        except ValueError:
            return raw.decode("utf-8", errors="replace")

    def do_OPTIONS(self):
        self._send(200, b"", "text/plain")

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if self.path.rstrip("/") == "/x-nmos/ncp/v1.0" and ServerWebSocket.is_upgrade(self):
            return BRIDGE.ncp.serve(self)
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_PUT(self):
        self._route("PUT")

    def do_PATCH(self):
        self._route("PATCH")

    def do_DELETE(self):
        self._route("DELETE")

    def _route(self, method: str):
        url = urlparse(self.path)
        path = url.path.rstrip("/") or "/"
        try:
            body = self._body() if method in ("POST", "PUT", "PATCH") else None
            if path.startswith("/x-nmos"):
                code, payload, ctype = BRIDGE.node.handle(method, path, body)
                return self._send(code, payload, ctype)
            if path.startswith("/api"):
                return self._api(method, path, body, parse_qs(url.query))
            return self._static(path)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:      # noqa: BLE001 - report every failure to the client
            log("error", f"{method} {self.path}: {e}")
            try:
                self._send(500, {"code": 500, "error": str(e), "debug": None})
            except OSError:
                pass

    def _api(self, method, path, body, query):
        b = BRIDGE
        parts = path.split("/")[2:]
        if parts == ["state"] and method == "GET":
            return self._send(200, b.state())
        if parts == ["settings"] and method == "POST":
            b.update_settings(body or {})
            return self._send(200, {"ok": True})
        if parts == ["discover"] and method == "POST":
            reg = b.cfg["registry"]
            res = []
            for svc in ("_nmos-register._tcp", "_nmos-query._tcp"):
                res += [dict(r, service=svc) for r in dnssd.discover(
                    mdns=reg.get("mdns", True), unicast=True, extra_domains=reg.get("domains") or [], service=svc,
                    servers=[x for x in [(reg.get("dns_server") or "").strip()] if x])]
            srv, dom = dnssd.resolver_config()
            if (reg.get("dns_server") or "").strip():
                srv = [reg["dns_server"].strip()]
            return self._send(200, {"results": res, "nameservers": srv, "domains": dom + (reg.get("domains") or [])})
        if parts == ["dns", "flush"] and method == "POST":
            res = hostdns.flush()
            # caches of the bridge itself: passively learned mDNS records, failed registries, pending candidates
            with b.node.browser.lock:
                b.node.browser.recs.clear()
            b.node.failed.clear()
            res["message"] += "; bridge DNS-SD caches cleared"
            if (b.cfg.get("registry") or {}).get("mode") != "manual":
                b.node.reset_registry()
                res["message"] += ", registry discovery restarted"
            log("dns", res["message"])
            return self._send(200, res)
        if parts == ["reregister"] and method == "POST":
            b.node.reset_registry()
            return self._send(200, {"ok": True})
        if parts == ["registry", "senders"] and method == "GET":
            try:
                return self._send(200, b.registry_senders())
            except Exception as e:     # noqa: BLE001
                return self._send(502, {"error": f"registry query failed: {e}"})
        if parts == ["channels"] and method == "POST":
            try:
                return self._send(200, b.upsert_channel(body or {}))
            except (ValueError, TypeError) as e:
                return self._send(400, {"error": str(e)})
        if len(parts) >= 2 and parts[0] == "channels":
            chid = parts[1]
            ch = b.channel(chid)
            if not ch:
                return self._send(404, {"error": "no such channel"})
            if len(parts) == 2 and method == "PUT":
                try:
                    return self._send(200, b.upsert_channel(body or {}, chid))
                except (ValueError, TypeError) as e:
                    return self._send(400, {"error": str(e)})
            if len(parts) == 2 and method == "DELETE":
                b.delete_channel(chid)
                return self._send(200, {"ok": True})
            if parts[2:] == ["connect"] and method == "POST" and ch["dir"] == "tx":
                try:
                    code, res = b.connect_tx(chid, body or {})
                except Exception as e:     # noqa: BLE001
                    return self._send(502, {"error": str(e)})
                return self._send(code, res)
            if parts[2:] == ["disconnect"] and method == "POST" and ch["dir"] == "tx":
                code, res = b.node.internal_patch("receiver", chid, {"sender_id": None, "master_enable": False,
                                                                     "transport_file": {"data": None, "type": None}})
                return self._send(code, res)
            if parts[2:] == ["output"] and method == "POST" and ch["dir"] == "rx":
                body = body or {}
                patch = {"master_enable": bool(body.get("enable"))}
                tp = {k: body[k] for k in ("destination_ip", "destination_port") if body.get(k)}
                if tp:
                    patch["transport_params"] = [tp]
                code, res = b.node.internal_patch("sender", chid, patch)
                return self._send(code, res)
            if parts[2:] == ["monitor"] and method == "POST":
                m = b.ncp.monitors.get(chid)
                if not m:
                    return self._send(404, {"error": "no monitor"})
                body = body or {}
                with b.ncp.lock:
                    if body.get("reset"):
                        b.ncp._reset(m)
                        b.ncp._overall(m)
                    if "delay" in body:
                        b.ncp._set(m, b.ncp.models.property(m.class_id, 3, 3), 3, 3, int(body["delay"]))
                    if "auto_reset" in body:
                        b.ncp._set(m, b.ncp.models.property(m.class_id, 4, 14), 4, 14, bool(body["auto_reset"]))
                b.ncp.flush()
                return self._send(200, b.ncp.summary(chid))
            if parts[2:] == ["sdp"] and method == "GET":
                if ch["dir"] == "rx":
                    txt = b.node.transport_file(b.node.sender_id(chid))
                    src = b.rx_sdp(chid)
                    return self._send(200, {"source": src, "output": txt})
                st = b.node.conn_state(b.node.receiver_id(chid), "receiver")
                return self._send(200, {"source": (st.active.get("transport_file") or {}).get("data")})
        return self._send(404, {"error": "not found"})

    def _static(self, path):
        if path == "/":
            path = "/index.html"
        full = os.path.normpath(os.path.join(STATIC, path.lstrip("/")))
        if not full.startswith(STATIC) or not os.path.isfile(full):
            return self._send(404, {"error": "not found"})
        ctype = {"html": "text/html; charset=utf-8", "js": "text/javascript", "css": "text/css", "svg": "image/svg+xml"}.get(
            full.rsplit(".", 1)[-1], "application/octet-stream")
        with open(full, "rb") as f:
            self._send(200, f.read(), ctype)


def main():
    global BRIDGE
    BRIDGE = Bridge()
    port = BRIDGE.http_port()
    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    httpd.daemon_threads = True
    log("info", f"AES67 SRT Bridge on http://{BRIDGE.interface_ip()}:{port}/ (interface {BRIDGE.interface_name()}, data {DATA_DIR})")
    BRIDGE.apply()
    BRIDGE.health.start()
    threading.Thread(target=BRIDGE.node.run, daemon=True, name="registration").start()
    import signal

    def shutdown(*_):
        log("info", "shutting down")
        BRIDGE.node.running = False
        BRIDGE.node.unregister()
        BRIDGE.stop()
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
