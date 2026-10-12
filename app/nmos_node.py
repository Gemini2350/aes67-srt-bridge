"""NMOS node: IS-04 resources + registration client, IS-04 Node API and IS-05 Connection API (single + bulk).

The bridge owns one node with one device. A TX channel is a virtual *receiver*, an RX channel is a
virtual *sender* (with source and flow). Resource ids are derived from a per-installation seed, so they
stay stable across restarts.
"""
from __future__ import annotations

import copy
import json
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid

import dnssd
import sdp as sdplib

REG_VERSION = "v1.3"
NODE_VERSIONS = ["v1.2", "v1.3"]
CONN_VERSIONS = ["v1.0", "v1.1"]
RTP_MCAST = "urn:x-nmos:transport:rtp.mcast"
RTP = "urn:x-nmos:transport:rtp"
SDP_TYPE = "application/sdp"


def tai_version() -> str:
    t = time.time() + 37
    return f"{int(t)}:{int((t % 1) * 1e9)}"


class _Version:
    """Strictly increasing IS-04 version strings."""

    def __init__(self):
        self.last = (0, 0)
        self.lock = threading.Lock()

    def __call__(self) -> str:
        with self.lock:
            s, n = (int(x) for x in tai_version().split(":"))
            if (s, n) <= self.last:
                s, n = self.last[0], self.last[1] + 1
            self.last = (s, n)
            return f"{s}:{n}"


new_version = _Version()


def http(method: str, url: str, body=None, timeout: float = 4.0):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw) if raw else None
        except ValueError:
            return e.code, raw.decode(errors="replace")


def mac_of(ifname: str) -> str:
    try:
        with open(f"/sys/class/net/{ifname}/address") as f:
            return f.read().strip().replace(":", "-").lower()
    except OSError:
        return "00-00-00-00-00-00"


# ====================================================================== IS-05 state
def empty_activation():
    return {"mode": None, "requested_time": None, "activation_time": None}


def receiver_params(**kw):
    p = {"source_ip": None, "multicast_ip": None, "interface_ip": "auto", "destination_port": "auto", "rtp_enabled": True}
    p.update(kw)
    return p


def sender_params(**kw):
    p = {"source_ip": "auto", "destination_ip": "auto", "source_port": "auto", "destination_port": "auto", "rtp_enabled": True}
    p.update(kw)
    return p


class ConnState:
    """staged/active of one IS-05 sender or receiver."""

    def __init__(self, kind: str, saved: dict | None = None):
        self.kind = kind
        if kind == "receiver":
            self.staged = {"sender_id": None, "master_enable": False, "activation": empty_activation(),
                           "transport_file": {"data": None, "type": None}, "transport_params": [receiver_params()]}
        else:
            self.staged = {"receiver_id": None, "master_enable": False, "activation": empty_activation(),
                           "transport_params": [sender_params()]}
        self.active = copy.deepcopy(self.staged)
        if saved:
            self.active = saved
            self.staged = copy.deepcopy(saved)
            self.staged["activation"] = empty_activation()
        self.timer: threading.Timer | None = None


# ====================================================================== node
class Node:
    def __init__(self, bridge):
        """bridge provides: config(), interface_ip(), interface_name(), http_port(), log(),
        tx_activate(chid, active), rx_activate(chid, active), rx_sdp(chid) -> str|None, save_conn_state()."""
        self.b = bridge
        self.lock = threading.RLock()
        self.conn: dict[str, ConnState] = {}      # resource id -> state
        self.res: dict[str, dict] = {}            # "type/id" -> resource
        self.registry: str | None = None          # .../x-nmos/registration/v1.3
        self.registry_label = ""
        self.registered: set[str] = set()
        self.dirty: set[str] = set()
        self.deleted: list[tuple[str, str]] = []
        self.reg_status = "not registered"
        self.reg_error = ""
        self.last_heartbeat = 0.0
        self.wake = threading.Event()
        self.running = True

    # ------------------------------------------------------------------ ids
    def uid(self, *parts) -> str:
        seed = uuid.UUID(self.b.config()["node_seed"])
        return str(uuid.uuid5(seed, ":".join(str(p) for p in parts)))

    @property
    def node_id(self):
        return self.uid("node")

    @property
    def device_id(self):
        return self.uid("device")

    def receiver_id(self, chid):
        return self.uid("receiver", chid)

    def sender_id(self, chid):
        return self.uid("sender", chid)

    # ------------------------------------------------------------------ resources
    def base_url(self) -> str:
        return f"http://{self.b.interface_ip()}:{self.b.http_port()}"

    def build(self):
        """(Re)build all resources from the configuration; changed ones get a new version and are re-registered."""
        cfg = self.b.config()
        ip, port, ifname = self.b.interface_ip(), self.b.http_port(), self.b.interface_name()
        label = cfg.get("node_label") or "AES67 SRT Bridge"
        base = self.base_url()
        tags = {"urn:x-nmos:tag:grouphint/v1.0": []}
        want: dict[str, dict] = {}
        gmid = (cfg.get("ptp_gmid") or "").strip().lower().replace(":", "-")
        clock = ({"name": "clk0", "ref_type": "ptp", "traceable": True, "version": "IEEE1588-2008", "gmid": gmid, "locked": True}
                 if gmid else {"name": "clk0", "ref_type": "internal"})
        want[f"node/{self.node_id}"] = {
            "id": self.node_id, "label": label, "description": "AES67 over SRT bridge (srt-live-transmit)", "tags": {},
            "href": base + "/", "hostname": socket.gethostname(),
            "api": {"versions": NODE_VERSIONS, "endpoints": [{"host": ip, "port": port, "protocol": "http", "authorization": False}]},
            "caps": {}, "services": [], "clocks": [clock],
            "interfaces": [{"chassis_id": None, "port_id": mac_of(ifname), "name": ifname}],
        }
        senders, receivers = [], []
        for ch in cfg["channels"]:
            if ch["dir"] == "tx":
                rid = self.receiver_id(ch["id"])
                receivers.append(rid)
                st = self.conn_state(rid, "receiver")
                want[f"receiver/{rid}"] = {
                    "id": rid, "label": ch["label"], "description": f"SRT TX -> {ch['srt'].get('host') or 'listener'}:{ch['srt'].get('port')}",
                    "tags": tags, "device_id": self.device_id, "transport": RTP, "interface_bindings": [ifname],
                    "subscription": {"sender_id": st.active.get("sender_id") if st.active["master_enable"] else None,
                                     "active": bool(st.active["master_enable"])},
                    "format": "urn:x-nmos:format:audio",
                    "caps": {"media_types": ["audio/L24", "audio/L16", "audio/L32", "audio/AM824"]},
                }
            else:
                sid = self.sender_id(ch["id"])
                src_id, flow_id = self.uid("source", ch["id"]), self.uid("flow", ch["id"])
                senders.append(sid)
                st = self.conn_state(sid, "sender")
                info = sdplib.parse(self.b.rx_sdp(ch["id"]) or "")
                enc = (info.get("encoding") or "L24").upper()
                chans = info.get("channels") or int(ch.get("default_channels") or 2)
                want[f"source/{src_id}"] = {
                    "id": src_id, "label": ch["label"], "description": "audio received via SRT", "tags": tags, "caps": {},
                    "device_id": self.device_id, "parents": [], "clock_name": "clk0", "format": "urn:x-nmos:format:audio",
                    "channels": [{"label": f"Ch {i + 1}"} for i in range(chans)],
                }
                flow = {
                    "id": flow_id, "label": ch["label"], "description": "audio received via SRT", "tags": tags,
                    "source_id": src_id, "device_id": self.device_id, "parents": [], "format": "urn:x-nmos:format:audio",
                    "sample_rate": {"numerator": info.get("sample_rate") or 48000, "denominator": 1},
                }
                if enc == "AM824":
                    flow["media_type"] = "audio/AM824"
                else:
                    flow["media_type"] = f"audio/{enc}"
                    flow["bit_depth"] = int(enc[1:]) if enc[1:].isdigit() else 24
                want[f"flow/{flow_id}"] = flow
                want[f"sender/{sid}"] = {
                    "id": sid, "label": ch["label"],
                    "description": f"SRT RX {ch['srt'].get('host') or 'listener'}:{ch['srt'].get('port')}" + ("" if info.get("port") else " (waiting for source SDP)"),
                    "tags": tags, "flow_id": flow_id, "transport": RTP_MCAST, "device_id": self.device_id,
                    "manifest_href": f"{base}/x-nmos/connection/v1.1/single/senders/{sid}/transportfile",
                    "interface_bindings": [ifname],
                    "subscription": {"receiver_id": None, "active": bool(st.active["master_enable"])},
                }
        want[f"device/{self.device_id}"] = {
            "id": self.device_id, "label": label, "description": "AES67 over SRT bridge", "tags": {},
            "type": "urn:x-nmos:device:generic", "node_id": self.node_id, "senders": senders, "receivers": receivers,
            "controls": [{"href": f"{base}/x-nmos/connection/{v}/", "type": f"urn:x-nmos:control:sr-ctrl/{v}", "authorization": False}
                         for v in CONN_VERSIONS],
        }
        with self.lock:
            for key, r in want.items():
                old = self.res.get(key)
                cmp_old = {k: v for k, v in (old or {}).items() if k != "version"}
                if cmp_old != r:
                    r["version"] = new_version()
                    self.res[key] = r
                    self.dirty.add(key)
            for key in list(self.res):
                if key not in want:
                    del self.res[key]
                    self.dirty.discard(key)
                    if key in self.registered:
                        self.deleted.append(tuple(key.split("/", 1)))
                        self.registered.discard(key)
            live = {k.split("/", 1)[1] for k in want if k.startswith(("sender/", "receiver/"))}
            for rid in list(self.conn):
                if rid not in live:
                    del self.conn[rid]
        self.wake.set()

    def conn_state(self, rid: str, kind: str) -> ConnState:
        with self.lock:
            if rid not in self.conn:
                saved = (self.b.config().get("conn_state") or {}).get(rid)
                self.conn[rid] = ConnState(kind, saved)
            return self.conn[rid]

    def get(self, rtype: str, rid: str | None = None):
        with self.lock:
            items = [copy.deepcopy(v) for k, v in self.res.items() if k.startswith(rtype + "/")]
        if rid is None:
            return items
        for it in items:
            if it["id"] == rid:
                return it
        return None

    # ------------------------------------------------------------------ registration
    def find_registry(self) -> str | None:
        cfg = self.b.config()
        reg = cfg.get("registry") or {}
        if reg.get("mode") == "manual" and reg.get("url"):
            url = reg["url"].rstrip("/")
            if "/x-nmos/registration" not in url:
                url += f"/x-nmos/registration/{REG_VERSION}"
            self.registry_label = "manual"
            return url
        found = []
        for service in ("_nmos-register._tcp", "_nmos-registration._tcp"):
            found = dnssd.discover(mdns=reg.get("mdns", True), unicast=True, extra_domains=reg.get("domains") or [], service=service,
                                  servers=[x for x in [(reg.get("dns_server") or "").strip()] if x])
            found = [f for f in found if not f["api_ver"] or REG_VERSION in f["api_ver"]] or found
            if found:
                break
        if not found:
            return None
        best = found[0]
        self.registry_label = f"DNS-SD {best['name']} ({best['source']}, pri {best['pri']})"
        return f"{best['base']}/x-nmos/registration/{REG_VERSION}"

    def query_url(self) -> str | None:
        reg = self.b.config().get("registry") or {}
        if reg.get("query_url"):
            u = reg["query_url"].rstrip("/")
            return u if "/x-nmos/query" in u else u + "/x-nmos/query/v1.3"
        if self.registry:
            return self.registry.split("/x-nmos/")[0] + "/x-nmos/query/v1.3"
        return None

    def run(self):
        order = ["node", "device", "source", "flow", "sender", "receiver"]
        failures = 0
        while self.running:
            try:
                if not self.registry:
                    self.reg_status = "discovering"
                    self.registry = self.find_registry()
                    if not self.registry:
                        self.reg_status = "no registry found"
                        self.wake.wait(10)
                        self.wake.clear()
                        continue
                    self.b.log("nmos", f"registry: {self.registry} [{self.registry_label}]")
                    with self.lock:
                        self.registered.clear()
                        self.dirty = set(self.res)
                # deletions
                with self.lock:
                    deleted, self.deleted = self.deleted, []
                for rtype, rid in deleted:
                    http("DELETE", f"{self.registry}/resource/{rtype}s/{rid}")
                # (re)registrations, parents first
                with self.lock:
                    pending = sorted(self.dirty, key=lambda k: order.index(k.split("/")[0]))
                for key in pending:
                    rtype = key.split("/")[0]
                    with self.lock:
                        r = copy.deepcopy(self.res.get(key))
                    if r is None:
                        continue
                    code, body = http("POST", f"{self.registry}/resource", {"type": rtype, "data": r})
                    if code in (200, 201):
                        with self.lock:
                            if self.res.get(key, {}).get("version") == r["version"]:
                                self.dirty.discard(key)
                            self.registered.add(key)
                    elif code == 409 and rtype == "node":
                        # stale node from an earlier run: delete and retry
                        http("DELETE", f"{self.registry}/resource/nodes/{r['id']}")
                        raise RuntimeError("node conflict (409), re-registering")
                    else:
                        raise RuntimeError(f"POST {rtype} -> {code} {str(body)[:200]}")
                # heartbeat
                if time.time() - self.last_heartbeat >= 5:
                    code, body = http("POST", f"{self.registry}/health/nodes/{self.node_id}")
                    if code == 404:
                        self.b.log("nmos", "heartbeat 404: node unknown to registry, re-registering")
                        with self.lock:
                            self.registered.clear()
                            self.dirty = set(self.res)
                        continue
                    if code != 200:
                        raise RuntimeError(f"heartbeat -> {code}")
                    self.last_heartbeat = time.time()
                failures = 0
                self.reg_status = "registered"
                self.reg_error = ""
            except (OSError, RuntimeError, ValueError) as e:
                failures += 1
                self.reg_error = str(e)
                self.reg_status = "error"
                self.b.log("error", f"registration: {e}")
                if failures >= 3:
                    self.b.log("nmos", "registry unreachable, rediscovering")
                    self.registry = None
                    failures = 0
                self.wake.wait(3)
                self.wake.clear()
                continue
            self.wake.wait(max(0.1, 5 - (time.time() - self.last_heartbeat)))
            self.wake.clear()

    def unregister(self):
        """Remove the node from the registry (resources follow via garbage collection, but be explicit)."""
        if not self.registry:
            return
        with self.lock:
            keys = sorted(self.registered, key=lambda k: -["node", "device", "source", "flow", "sender", "receiver"].index(k.split("/")[0]))
        for key in keys:
            rtype, rid = key.split("/", 1)
            try:
                http("DELETE", f"{self.registry}/resource/{rtype}s/{rid}", timeout=2)
            except OSError:
                pass

    def reset_registry(self):
        self.registry = None
        self.wake.set()

    # ------------------------------------------------------------------ IS-05
    def resolve(self, kind: str, chid: str, params: dict) -> dict:
        p = dict(params)
        ip = self.b.interface_ip()
        if kind == "receiver":
            if p.get("interface_ip") in (None, "auto"):
                p["interface_ip"] = ip
            if p.get("destination_port") in (None, "auto"):
                p["destination_port"] = 5004
        else:
            ch = self.b.channel(chid) or {}
            out = ch.get("out") or {}
            if p.get("source_ip") in (None, "auto"):
                p["source_ip"] = ip
            if p.get("destination_ip") in (None, "auto"):
                p["destination_ip"] = out.get("dest_ip") or "239.69.0.1"
            if p.get("destination_port") in (None, "auto"):
                p["destination_port"] = int(out.get("dest_port") or 5004)
            if p.get("source_port") in (None, "auto"):
                p["source_port"] = self.b.rx_source_port(chid) or 5004
        return p

    def find_channel(self, kind: str, rid: str) -> str | None:
        for ch in self.b.config()["channels"]:
            if kind == "receiver" and ch["dir"] == "tx" and self.receiver_id(ch["id"]) == rid:
                return ch["id"]
            if kind == "sender" and ch["dir"] == "rx" and self.sender_id(ch["id"]) == rid:
                return ch["id"]
        return None

    def patch_staged(self, kind: str, rid: str, body: dict) -> tuple[int, dict]:
        chid = self.find_channel(kind, rid)
        if chid is None:
            return 404, {"code": 404, "error": "not found", "debug": None}
        st = self.conn_state(rid, kind)
        if not isinstance(body, dict):
            return 400, {"code": 400, "error": "body must be an object", "debug": None}
        with self.lock:
            staged = copy.deepcopy(st.staged)
            if kind == "receiver":
                if "sender_id" in body:
                    staged["sender_id"] = body["sender_id"]
                tf = body.get("transport_file")
                if isinstance(tf, dict) and "data" in tf:
                    staged["transport_file"] = {"data": tf.get("data"), "type": tf.get("type") or (SDP_TYPE if tf.get("data") else None)}
                    if tf.get("data"):
                        info = sdplib.parse(tf["data"])
                        if not info.get("multicast_ip") or not info.get("port"):
                            return 400, {"code": 400, "error": "SDP has no connection address / port", "debug": None}
                        staged["transport_params"][0].update(
                            multicast_ip=info["multicast_ip"] if sdplib.is_multicast(info["multicast_ip"]) else None,
                            source_ip=info.get("source_ip"), destination_port=info["port"])
            else:
                if "receiver_id" in body:
                    staged["receiver_id"] = body["receiver_id"]
            if "master_enable" in body:
                if not isinstance(body["master_enable"], bool):
                    return 400, {"code": 400, "error": "master_enable must be boolean", "debug": None}
                staged["master_enable"] = body["master_enable"]
            tps = body.get("transport_params")
            if tps is not None:
                if not isinstance(tps, list) or len(tps) > 1:
                    return 400, {"code": 400, "error": "exactly one transport_params leg supported", "debug": None}
                if tps:
                    allowed = set(staged["transport_params"][0])
                    bad = set(tps[0]) - allowed
                    if bad:
                        return 400, {"code": 400, "error": f"unknown transport params: {sorted(bad)}", "debug": None}
                    if kind == "sender" and "source_ip" in tps[0] and tps[0]["source_ip"] not in ("auto", self.b.interface_ip()):
                        return 400, {"code": 400, "error": "source_ip must be auto or the interface ip", "debug": None}
                    staged["transport_params"][0].update(tps[0])
            act = body.get("activation")
            if act is not None and st.timer:
                st.timer.cancel()
                st.timer = None
                staged["activation"] = empty_activation()
            st.staged = staged
            if not act or act.get("mode") is None:
                return 200, copy.deepcopy(st.staged)
            mode = act.get("mode")
            if mode == "activate_immediate":
                result = self._activate(kind, rid, chid)
                return 200, result
            if mode in ("activate_scheduled_absolute", "activate_scheduled_relative"):
                req = act.get("requested_time")
                try:
                    sec, nsec = (int(x) for x in str(req).split(":"))
                except ValueError:
                    return 400, {"code": 400, "error": "invalid requested_time", "debug": None}
                if mode == "activate_scheduled_absolute":
                    delay = sec + nsec / 1e9 - (time.time() + 37)
                    at = req
                else:
                    delay = sec + nsec / 1e9
                    t = time.time() + 37 + delay
                    at = f"{int(t)}:{int((t % 1) * 1e9)}"
                st.staged["activation"] = {"mode": mode, "requested_time": req, "activation_time": at}
                st.timer = threading.Timer(max(0.0, delay), lambda: self._activate(kind, rid, chid))
                st.timer.daemon = True
                st.timer.start()
                return 202, copy.deepcopy(st.staged)
            return 400, {"code": 400, "error": f"invalid activation mode {mode}", "debug": None}

    def _activate(self, kind: str, rid: str, chid: str) -> dict:
        with self.lock:
            st = self.conn[rid]
            staged = copy.deepcopy(st.staged)
            act_time = tai_version()
            active = copy.deepcopy(staged)
            active["transport_params"] = [self.resolve(kind, chid, staged["transport_params"][0])]
            active["activation"] = {"mode": staged["activation"]["mode"] or "activate_immediate",
                                    "requested_time": staged["activation"]["requested_time"], "activation_time": act_time}
            st.active = active
            st.staged["activation"] = empty_activation()
            st.timer = None
            response = copy.deepcopy(staged)
            response["activation"] = copy.deepcopy(active["activation"])
        try:
            if kind == "receiver":
                self.b.tx_activate(chid, copy.deepcopy(active))
            else:
                self.b.rx_activate(chid, copy.deepcopy(active))
        except Exception as e:     # never break the API because a pipeline failed
            self.b.log("error", f"activation of {kind} {chid}: {e}")
        self.b.save_conn_state()
        self.build()
        return response

    def internal_patch(self, kind: str, chid: str, body: dict) -> tuple[int, dict]:
        rid = self.receiver_id(chid) if kind == "receiver" else self.sender_id(chid)
        body = dict(body)
        body.setdefault("activation", {"mode": "activate_immediate"})
        return self.patch_staged(kind, rid, body)

    def constraints(self, kind: str):
        ip = self.b.interface_ip()
        if kind == "receiver":
            return [{"interface_ip": {"enum": [ip]}, "multicast_ip": {}, "source_ip": {}, "destination_port": {},
                     "rtp_enabled": {}}]
        return [{"source_ip": {"enum": [ip]}, "destination_ip": {}, "source_port": {}, "destination_port": {},
                 "rtp_enabled": {}}]

    def transport_file(self, sid: str) -> str | None:
        chid = self.find_channel("sender", sid)
        if chid is None:
            return None
        src = self.b.rx_sdp(chid)
        if not src:
            return None
        ch = self.b.channel(chid)
        st = self.conn_state(sid, "sender")
        p = self.resolve("sender", chid, st.active["transport_params"][0])
        return sdplib.rewrite(src, dest_ip=p["destination_ip"], dest_port=int(p["destination_port"]), source_ip=p["source_ip"],
                              ttl=int((ch.get("out") or {}).get("ttl") or 32), session_name=ch["label"],
                              refclk=(ch.get("refclk") or "").strip() or None, restamp=bool(ch.get("restamp")),
                              session_id=int(uuid.UUID(sid).int % 10 ** 9))

    # ------------------------------------------------------------------ HTTP dispatch
    def handle(self, method: str, path: str, body) -> tuple[int, object, str]:
        """Returns (status, payload, content_type). payload is JSON-serialisable unless content_type says otherwise."""
        parts = [p for p in path.split("/") if p]
        J = "application/json"
        if parts == ["x-nmos"]:
            return 200, ["node/", "connection/"], J
        if len(parts) >= 2 and parts[1] == "node":
            if method != "GET":
                return 405, {"code": 405, "error": "method not allowed", "debug": None}, J
            if len(parts) == 2:
                return 200, [v + "/" for v in NODE_VERSIONS], J
            if parts[2] not in NODE_VERSIONS:
                return 404, {"code": 404, "error": "version not supported", "debug": None}, J
            if len(parts) == 3:
                return 200, ["self/", "sources/", "flows/", "devices/", "senders/", "receivers/"], J
            coll = parts[3]
            if coll == "self":
                return 200, self.get("node")[0], J
            m = {"sources": "source", "flows": "flow", "devices": "device", "senders": "sender", "receivers": "receiver"}
            if coll not in m:
                return 404, {"code": 404, "error": "not found", "debug": None}, J
            if len(parts) == 4:
                return 200, self.get(m[coll]), J
            r = self.get(m[coll], parts[4])
            return (200, r, J) if r else (404, {"code": 404, "error": "not found", "debug": None}, J)
        if len(parts) >= 2 and parts[1] == "connection":
            return self._connection(method, parts[2:], body)
        return 404, {"code": 404, "error": "not found", "debug": None}, J

    def _connection(self, method, parts, body):
        J = "application/json"
        nf = (404, {"code": 404, "error": "not found", "debug": None}, J)
        if not parts:
            return 200, [v + "/" for v in CONN_VERSIONS], J
        if parts[0] not in CONN_VERSIONS:
            return nf
        if len(parts) == 1:
            return 200, ["bulk/", "single/"], J
        if parts[1] == "bulk":
            if len(parts) == 2:
                return 200, ["senders/", "receivers/"], J
            if len(parts) != 3 or parts[2] not in ("senders", "receivers"):
                return nf
            if method != "POST":
                return 405, {"code": 405, "error": "method not allowed", "debug": None}, J
            kind = parts[2][:-1]
            out = []
            for item in body if isinstance(body, list) else []:
                code, res = self.patch_staged(kind, item.get("id"), item.get("params") or {})
                entry = {"id": item.get("id"), "code": code}
                if code >= 400:
                    entry["error"] = res.get("error")
                out.append(entry)
            return 200, out, J
        if parts[1] != "single":
            return nf
        if len(parts) == 2:
            return 200, ["senders/", "receivers/"], J
        coll = parts[2]
        if coll not in ("senders", "receivers"):
            return nf
        kind = coll[:-1]
        ids = [r["id"] for r in self.get(kind)]
        if len(parts) == 3:
            return 200, [i + "/" for i in ids], J
        rid = parts[3]
        if rid not in ids:
            return nf
        if len(parts) == 4:
            items = ["constraints/", "staged/", "active/"] + (["transportfile/"] if kind == "sender" else [])
            if parts[0] == "v1.1":
                items.append("transporttype/")
            return 200, items, J
        leaf = parts[4]
        st = self.conn_state(rid, kind)
        if leaf == "constraints" and method == "GET":
            return 200, self.constraints(kind), J
        if leaf == "transporttype" and method == "GET" and parts[0] == "v1.1":
            return 200, RTP_MCAST if kind == "sender" else RTP, J
        if leaf == "active" and method == "GET":
            with self.lock:
                return 200, copy.deepcopy(st.active), J
        if leaf == "staged":
            if method == "GET":
                with self.lock:
                    return 200, copy.deepcopy(st.staged), J
            if method == "PATCH":
                code, res = self.patch_staged(kind, rid, body if body is not None else {})
                return code, res, J
            return 405, {"code": 405, "error": "method not allowed", "debug": None}, J
        if leaf == "transportfile" and kind == "sender" and method == "GET":
            txt = self.transport_file(rid)
            if not txt:
                return 404, {"code": 404, "error": "no source SDP received yet", "debug": None}, J
            return 200, txt, SDP_TYPE
        return nf
