"""IS-12 NMOS Control Protocol server with an MS-05-02 device model and BCP-008 status monitors.

Device model (oids are constant):

    1          root NcBlock
    2          NcDeviceManager                      role "DeviceManager"
    3          NcClassManager                       role "ClassManager"   (full descriptors from models/)
    100 + n    NcReceiverMonitor (BCP-008-01)       role "receiver-monitor-<channel>", one per TX channel
    100 + n    NcSenderMonitor   (BCP-008-02)       role "sender-monitor-<channel>",   one per RX channel

Status behaviour follows BCP-008-01/-02:
* on activation the domains with an Inactive option go to Healthy immediately; for statusReportingDelay
  seconds afterwards non-healthy states are held back,
* after that a healthier state is reported only once it persisted for statusReportingDelay; a less healthy
  state is reported once it persisted for degradation_delay (setting "bcp008.degradation_delay", default 3 s –
  a deliberate deviation from BCP-008, which reports it immediately; 0 restores the BCP-008 behaviour),
* deactivation sets connection/transmission, stream/essence and overall to Inactive immediately,
* transition counters count transitions to less healthy states (not to/from neutral states),
* autoResetCountersAndMessages (default true) resets counters and messages on every activation,
* messages of recovered domains keep the previous cause as "Previously: ...".
"""
from __future__ import annotations

import glob
import json
import os
import threading
import time

from websocket import ServerWebSocket, WebSocketClosed

MODELS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")

MT_COMMAND, MT_COMMAND_RESPONSE, MT_NOTIFICATION, MT_SUBSCRIPTION, MT_SUBSCRIPTION_RESPONSE, MT_ERROR = range(6)

OK, BAD_FORMAT, BAD_OID, READONLY, INVALID, INDEX_OOB, PARAM_ERROR = 200, 400, 404, 405, 406, 414, 417
NOT_IMPL_METHOD, NOT_IMPL_PROP, DEVICE_ERROR = 501, 502, 500

CID_BLOCK, CID_DEVICE_MANAGER, CID_CLASS_MANAGER = [1, 1], [1, 3, 1], [1, 3, 2]
CID_RECEIVER_MONITOR, CID_SENDER_MONITOR = [1, 2, 2, 1], [1, 2, 2, 2]

INACTIVE, HEALTHY, PARTIAL, UNHEALTHY = 0, 1, 2, 3
STATUS_NAMES = {0: "Inactive", 1: "Healthy", 2: "PartiallyHealthy", 3: "Unhealthy"}
LINK_NAMES = {1: "AllUp", 2: "SomeDown", 3: "AllDown"}
SYNC_NAMES = {0: "NotUsed", 1: "Healthy", 2: "PartiallyHealthy", 3: "Unhealthy"}

# domain name -> base property index at level 4 (status, message, transition counter)
RX_DOMAINS = {"link": 1, "connection": 4, "sync": 7, "stream": 11}
TX_DOMAINS = {"link": 1, "transmission": 4, "sync": 7, "essence": 11}
INACTIVE_CAPABLE = {"connection", "stream", "transmission", "essence"}

PRIMITIVES = ["NcBoolean", "NcInt16", "NcInt32", "NcInt64", "NcUint16", "NcUint32", "NcUint64", "NcFloat32", "NcFloat64", "NcString"]


def ok(value=None, has_value=True):
    return {"status": OK, "value": value} if has_value else {"status": OK}


def err(status, message):
    return {"status": status, "errorMessage": message}


def pid(level, index):
    return {"level": level, "index": index}


# ====================================================================== class/datatype descriptors
class Models:
    def __init__(self):
        self.classes: dict[tuple, dict] = {}
        for f in glob.glob(os.path.join(MODELS, "classes", "*.json")):
            with open(f) as fh:
                d = json.load(fh)
            self.classes[tuple(d["classId"])] = d
        self.datatypes: dict[str, dict] = {}
        for f in glob.glob(os.path.join(MODELS, "datatypes", "*.json")):
            with open(f) as fh:
                d = json.load(fh)
            self.datatypes[d["name"]] = d
        for p in PRIMITIVES:
            self.datatypes.setdefault(p, {"description": "Primitive datatype", "name": p, "type": 0, "constraints": None})

    def lineage(self, class_id) -> list[tuple]:
        cid = tuple(class_id)
        return [cid[:i] for i in range(1, len(cid) + 1) if cid[:i] in self.classes]

    def class_descriptor(self, class_id, include_inherited: bool) -> dict | None:
        cid = tuple(class_id)
        if cid not in self.classes:
            return None
        d = json.loads(json.dumps(self.classes[cid]))
        if include_inherited:
            props, methods, events = [], [], []
            for c in self.lineage(cid):
                base = self.classes[c]
                props += base["properties"]
                methods += base["methods"]
                events += base["events"]
            d["properties"], d["methods"], d["events"] = props, methods, events
        return d

    def property(self, class_id, level: int, index: int) -> dict | None:
        for c in self.lineage(class_id):
            for p in self.classes[c]["properties"]:
                if p["id"]["level"] == level and p["id"]["index"] == index:
                    return p
        return None

    def has_method(self, class_id, level: int, index: int) -> bool:
        return any(m["id"]["level"] == level and m["id"]["index"] == index
                   for c in self.lineage(class_id) for m in self.classes[c]["methods"])

    def is_derived(self, class_id, base) -> bool:
        return list(class_id[:len(base)]) == list(base)

    def datatype(self, name: str, include_inherited: bool) -> dict | None:
        d = self.datatypes.get(name)
        if d is None:
            return None
        d = json.loads(json.dumps(d))
        if include_inherited and d.get("type") == 2:
            fields, parent = list(d.get("fields", [])), d.get("parentType")
            while parent:
                p = self.datatypes.get(parent)
                if not p:
                    break
                fields = list(p.get("fields", [])) + fields
                parent = p.get("parentType")
            d["fields"] = fields
        return d


# ====================================================================== objects
class NcObj:
    def __init__(self, oid, class_id, role, user_label, owner=1, touchpoints=None):
        self.oid, self.class_id, self.role, self.user_label = oid, list(class_id), role, user_label
        self.owner, self.touchpoints = owner, touchpoints

    def descriptor(self) -> dict:
        return {"description": None, "role": self.role, "oid": self.oid, "constantOid": True,
                "classId": self.class_id, "userLabel": self.user_label, "owner": self.owner if self.owner is not None else 1}

    def get(self, level, index):
        """Returns (found, value)."""
        if level == 1:
            return True, {1: self.class_id, 2: self.oid, 3: True, 4: self.owner, 5: self.role, 6: self.user_label,
                          7: self.touchpoints, 8: None}.get(index)
        return False, None


class Domain:
    def __init__(self, status):
        self.status = status
        self.message = None
        self.counter = 0
        self.pending = None          # (status, message, since)


class Monitor(NcObj):
    """NcReceiverMonitor / NcSenderMonitor with the BCP-008 state machine."""

    def __init__(self, oid, kind, chid, resource_id, label):
        cid = CID_RECEIVER_MONITOR if kind == "receiver" else CID_SENDER_MONITOR
        super().__init__(oid, cid, f"{kind}-monitor-{chid}", label,
                         touchpoints=[{"contextNamespace": "x-nmos", "resource": {"resourceType": kind, "id": resource_id}}])
        self.kind, self.chid, self.resource_id = kind, chid, resource_id
        self.domain_index = RX_DOMAINS if kind == "receiver" else TX_DOMAINS
        self.domains = {name: Domain(HEALTHY if name == "link" else INACTIVE) for name in self.domain_index}
        self.overall, self.overall_message = INACTIVE, None
        self.delay = 3
        self.auto_reset = True
        self.enabled = True
        self.active = False
        self.activation_until = 0.0
        self.sync_source = "internal"
        self.label_override = None              # userLabel set explicitly via IS-12 (else: NMOS label)
        self.counters: dict[str, dict] = {}      # group -> {name: value}
        self.counter_desc: dict[str, str] = {}

    def get(self, level, index):
        found, v = super().get(level, index)
        if found:
            return found, v
        if level == 2 and index == 1:
            return True, self.enabled
        if level == 3:
            return index in (1, 2, 3), {1: self.overall, 2: self.overall_message, 3: self.delay}.get(index)
        if level == 4:
            if index == 10:
                return True, self.sync_source
            if index == 14:
                return True, self.auto_reset
            for name, base in self.domain_index.items():
                d = self.domains[name]
                if index == base:
                    return True, d.status
                if index == base + 1:
                    return True, d.message
                if index == base + 2:
                    return True, d.counter
        return False, None

    def counter_list(self, group: str) -> list[dict]:
        return [{"name": n, "value": int(v), "description": self.counter_desc.get(n)} for n, v in (self.counters.get(group) or {}).items()]


# ====================================================================== server
class NcpServer:
    def __init__(self, bridge):
        """bridge provides: config(), save(), log(kind, text)."""
        self.b = bridge
        self.models = Models()
        self.lock = threading.RLock()
        self.flush_lock = threading.Lock()
        self.outbox: list[tuple[int, dict]] = []
        self.connections: dict[ServerWebSocket, set[int]] = {}
        state = self.b.config().setdefault("ncp_state", {})
        dm = state.setdefault("device", {})
        self.root = NcObj(1, CID_BLOCK, "root", "root", owner=None)
        self.device_manager = NcObj(2, CID_DEVICE_MANAGER, "DeviceManager", "Device manager")
        self.class_manager = NcObj(3, CID_CLASS_MANAGER, "ClassManager", "Class manager")
        self.dm_values = {5: dm.get("userInventoryCode"), 6: dm.get("deviceName"), 7: dm.get("deviceRole")}
        self.monitors: dict[str, Monitor] = {}     # chid -> monitor

    # ------------------------------------------------------------------ model
    def objects(self) -> list[NcObj]:
        return [self.root, self.device_manager, self.class_manager] + sorted(self.monitors.values(), key=lambda m: m.oid)

    def find(self, oid) -> NcObj | None:
        for o in self.objects():
            if o.oid == oid:
                return o
        return None

    def members(self) -> list[dict]:
        return [o.descriptor() for o in self.objects()[1:]]

    def sync_channels(self, channels: list[dict]):
        """channels: [{chid, kind, resource_id, label}] — creates/removes monitors (state of kept ones survives)."""
        state = self.b.config().setdefault("ncp_state", {}).setdefault("monitors", {})
        with self.lock:
            before = json.dumps(self.members())
            want = {c["chid"]: c for c in channels}
            for chid in list(self.monitors):
                m = self.monitors[chid]
                c = want.get(chid)
                if not c or c["kind"] != m.kind or c["resource_id"] != m.resource_id:
                    del self.monitors[chid]
            for chid, c in want.items():
                if chid in self.monitors:
                    m = self.monitors[chid]
                    label = m.label_override or c["label"]
                    if label != m.user_label:
                        m.user_label = label
                        self._notify(m.oid, 1, 6, label)
                    continue
                m = Monitor(100 + int(chid), c["kind"], chid, c["resource_id"], c["label"])
                saved = state.get(m.role, {})
                m.label_override = saved.get("userLabel")
                m.user_label = m.label_override or c["label"]
                m.delay = int(saved.get("statusReportingDelay", 3))
                m.auto_reset = bool(saved.get("autoResetCountersAndMessages", True))
                self.monitors[chid] = m
            if json.dumps(self.members()) != before:
                self._notify(1, 2, 2, self.members())
        self.flush()

    def _persist(self, m: Monitor):
        state = self.b.config().setdefault("ncp_state", {}).setdefault("monitors", {})
        state[m.role] = {"statusReportingDelay": m.delay, "autoResetCountersAndMessages": m.auto_reset}
        if m.label_override:
            state[m.role]["userLabel"] = m.label_override
        self.b.save()

    # ------------------------------------------------------------------ device manager values
    def device_manager_get(self, index):
        cfg = self.b.config()
        values = {
            1: "v1.0.0",
            2: {"name": "aes67-srt-bridge", "organizationId": None, "website": "https://github.com/Gemini2350/aes67-srt-bridge"},
            3: {"name": "AES67 SRT Bridge", "key": "aes67-srt-bridge", "revisionLevel": "1.1", "brandName": None,
                "uuid": None, "description": "AES67 over SRT (srt-live-transmit) with NMOS"},
            4: cfg.get("node_seed", ""),
            5: self.dm_values[5], 6: self.dm_values[6], 7: self.dm_values[7],
            8: {"generic": 1, "deviceSpecificDetails": None},
            9: 1,
            10: None,
        }
        return index in values, values.get(index)

    def degradation_delay(self) -> float:
        try:
            return float((self.b.config().get("bcp008") or {}).get("degradation_delay", 3))
        except (TypeError, ValueError):
            return 3.0

    # ------------------------------------------------------------------ BCP-008 state machine
    def activate(self, chid: str):
        """IS-05 activation with master_enable true (also re-activation with new parameters)."""
        with self.lock:
            m = self.monitors.get(chid)
            if not m:
                return
            now = time.time()
            if m.auto_reset:
                self._reset(m)
            m.active = True
            m.activation_until = now + m.delay
            for name, d in m.domains.items():
                d.pending = None
                if name in INACTIVE_CAPABLE:
                    self._apply(m, name, HEALTHY, None, transition=False)
            self._overall(m)
        self.flush()

    def deactivate(self, chid: str):
        with self.lock:
            m = self.monitors.get(chid)
            if not m:
                return
            m.active = False
            for name, d in m.domains.items():
                d.pending = None
                if name in INACTIVE_CAPABLE:
                    self._apply(m, name, INACTIVE, d.message, transition=False)
            self._overall(m)
        self.flush()

    def evaluate(self, chid: str, raw: dict, counters: dict | None = None, sync_source: str | None = "internal"):
        """raw: {domain: (status, message)} measured right now. counters: {group: {name: delta}}."""
        with self.lock:
            m = self.monitors.get(chid)
            if not m:
                return
            now = time.time()
            for group, items in (counters or {}).items():
                g = m.counters.setdefault(group, {})
                for name, (delta, desc) in items.items():
                    g[name] = g.get(name, 0) + max(0, int(delta))
                    m.counter_desc[name] = desc
            if sync_source != m.sync_source:
                m.sync_source = sync_source
                self._notify(m.oid, 4, 10, sync_source)
            for name, (status, message) in raw.items():
                if name not in m.domains:
                    continue
                d = m.domains[name]
                if name in INACTIVE_CAPABLE and not m.active:
                    continue
                if status == d.status:
                    d.pending = None
                    if status not in (INACTIVE, HEALTHY) and message != d.message:
                        self._set_message(m, name, message)
                    continue
                neutral = status == INACTIVE or d.status == INACTIVE
                in_grace = m.active and now < m.activation_until
                if in_grace and status != HEALTHY and not neutral:
                    continue                                   # hold back non-healthy states after activation
                if neutral:
                    self._apply(m, name, status, message)
                    continue
                if status > d.status:
                    # worse: BCP-008 reports it immediately; the bridge holds it back for degradation_delay (default 3 s,
                    # 0 = BCP-008 conform) so short dropouts do not raise alarms
                    hold = self.degradation_delay()
                    if hold <= 0:
                        self._apply(m, name, status, message)
                    elif d.pending and d.pending[0] > d.status:  # already degraded: keep the start time
                        if now - d.pending[2] >= hold:
                            self._apply(m, name, status, message)
                        else:
                            d.pending = (status, message, d.pending[2])
                    else:
                        d.pending = (status, message, now)
                    continue
                if m.delay == 0:
                    self._apply(m, name, status, message)
                    continue
                if d.pending and d.pending[0] == status:        # better: only after it persisted
                    if now - d.pending[2] >= m.delay:
                        self._apply(m, name, status, message)
                else:
                    d.pending = (status, message, now)
            self._overall(m)
        self.flush()

    def _apply(self, m: Monitor, name: str, status: int, message, transition=True):
        d = m.domains[name]
        base = m.domain_index[name]
        old = d.status
        d.pending = None
        if status == old:
            return
        if transition and old != INACTIVE and status != INACTIVE and status > old:
            d.counter += 1
            self._notify(m.oid, 4, base + 2, d.counter)
        d.status = status
        self._notify(m.oid, 4, base, status)
        if status == HEALTHY and old in (PARTIAL, UNHEALTHY) and d.message:
            message = d.message if d.message.startswith("Previously: ") else "Previously: " + d.message
        elif status == HEALTHY and old in (INACTIVE, HEALTHY):
            message = d.message if message is None else message
        self._set_message(m, name, message)

    def _set_message(self, m: Monitor, name: str, message):
        d = m.domains[name]
        if message != d.message:
            d.message = message
            self._notify(m.oid, 4, m.domain_index[name] + 1, message)

    def _overall(self, m: Monitor):
        if not m.active:
            status, message = INACTIVE, None
        else:
            worst = max([d.status for d in m.domains.values() if d.status != INACTIVE] or [HEALTHY])
            status = worst
            if worst > HEALTHY:
                message = "; ".join(f"{n}: {d.message}" for n, d in m.domains.items() if d.status == worst and d.message)
            elif m.overall in (PARTIAL, UNHEALTHY) and m.overall_message:
                message = m.overall_message if m.overall_message.startswith("Previously: ") else "Previously: " + m.overall_message
            else:
                message = m.overall_message if m.overall == HEALTHY else None
        if status != m.overall:
            m.overall = status
            self._notify(m.oid, 3, 1, status)
        if message != m.overall_message:
            m.overall_message = message
            self._notify(m.oid, 3, 2, message)

    def _reset(self, m: Monitor):
        for name, d in m.domains.items():
            if d.counter:
                d.counter = 0
                self._notify(m.oid, 4, m.domain_index[name] + 2, 0)
            self._set_message(m, name, None)
        if m.overall_message is not None:
            m.overall_message = None
            self._notify(m.oid, 3, 2, None)
        for g in m.counters.values():
            for k in g:
                g[k] = 0

    # ------------------------------------------------------------------ notifications
    def _notify(self, oid, level, index, value, change_type=0, seq_index=None):
        self.outbox.append((oid, {"oid": oid, "eventId": {"level": 1, "index": 1},
                                  "eventData": {"propertyId": pid(level, index), "changeType": change_type,
                                                "value": value, "sequenceItemIndex": seq_index}}))

    def flush(self):
        with self.flush_lock:
            with self.lock:
                out, self.outbox = self.outbox, []
                conns = {ws: set(subs) for ws, subs in self.connections.items()}
            if not out:
                return
            for ws, subs in conns.items():
                notes = [n for oid, n in out if oid in subs]
                if not notes:
                    continue
                try:
                    ws.send(json.dumps({"messageType": MT_NOTIFICATION, "notifications": notes}))
                except WebSocketClosed:
                    with self.lock:
                        self.connections.pop(ws, None)

    # ------------------------------------------------------------------ websocket session
    def serve(self, handler):
        ws = ServerWebSocket(handler)
        ws.accept()
        with self.lock:
            self.connections[ws] = set()
        self.b.log("is12", f"controller connected from {ws.peer}")
        try:
            while True:
                text = ws.recv()
                try:
                    msg = json.loads(text)
                except ValueError:
                    ws.send(json.dumps({"messageType": MT_ERROR, "status": BAD_FORMAT, "errorMessage": "invalid JSON"}))
                    continue
                reply = self.handle_message(ws, msg)
                if reply is not None:
                    ws.send(json.dumps(reply))
                self.flush()
        except (WebSocketClosed, OSError):
            pass
        finally:
            with self.lock:
                self.connections.pop(ws, None)
            ws.close()
            self.b.log("is12", f"controller {ws.peer} disconnected")

    def handle_message(self, ws, msg) -> dict | None:
        if not isinstance(msg, dict):
            return {"messageType": MT_ERROR, "status": BAD_FORMAT, "errorMessage": "message must be an object"}
        mt = msg.get("messageType")
        if mt == MT_SUBSCRIPTION:
            subs = msg.get("subscriptions")
            if not isinstance(subs, list):
                return {"messageType": MT_ERROR, "status": BAD_FORMAT, "errorMessage": "subscriptions must be an array"}
            with self.lock:
                valid = [o for o in subs if isinstance(o, int) and self.find(o)]
                self.connections[ws] = set(valid)
            return {"messageType": MT_SUBSCRIPTION_RESPONSE, "subscriptions": valid}
        if mt == MT_COMMAND:
            cmds = msg.get("commands")
            if not isinstance(cmds, list):
                return {"messageType": MT_ERROR, "status": BAD_FORMAT, "errorMessage": "commands must be an array"}
            responses = []
            for c in cmds:
                if not isinstance(c, dict) or not isinstance(c.get("handle"), int) or isinstance(c.get("handle"), bool) \
                        or not 1 <= c["handle"] <= 65535 or not isinstance(c.get("oid"), int) or not isinstance(c.get("methodId"), dict):
                    return {"messageType": MT_ERROR, "status": BAD_FORMAT,
                            "errorMessage": "command needs handle (1..65535), oid and methodId"}
                try:
                    with self.lock:
                        result = self.command(c["oid"], c["methodId"], c.get("arguments") or {})
                except Exception as e:      # noqa: BLE001 - every failure must become a result
                    result = err(DEVICE_ERROR, str(e))
                responses.append({"handle": c["handle"], "result": result})
            return {"messageType": MT_COMMAND_RESPONSE, "responses": responses}
        return {"messageType": MT_ERROR, "status": BAD_FORMAT, "errorMessage": f"unsupported messageType {mt}"}

    # ------------------------------------------------------------------ commands (caller holds self.lock)
    def command(self, oid, method_id, args) -> dict:
        obj = self.find(oid)
        if obj is None:
            return err(BAD_OID, f"no object with oid {oid}")
        level, index = method_id.get("level"), method_id.get("index")
        if not self.models.has_method(obj.class_id, level, index):
            return err(NOT_IMPL_METHOD, f"method {level}m{index} not implemented by this class")
        if level == 1:
            return self._object_method(obj, index, args)
        if level == 2 and obj is self.root:
            return self._block_method(index, args)
        if level == 3 and obj is self.class_manager:
            if index == 1:
                cid = args.get("classId")
                if not isinstance(cid, list):
                    return err(PARAM_ERROR, "classId required")
                d = self.models.class_descriptor(cid, bool(args.get("includeInherited")))
                return ok(d) if d else err(PARAM_ERROR, f"unknown class {cid}")
            if index == 2:
                d = self.models.datatype(str(args.get("name")), bool(args.get("includeInherited")))
                return ok(d) if d else err(PARAM_ERROR, f"unknown datatype {args.get('name')}")
        if level == 4 and isinstance(obj, Monitor):
            if obj.kind == "receiver":
                if index == 1:
                    return ok(obj.counter_list("lost"))
                if index == 2:
                    return ok(obj.counter_list("late"))
                if index == 3:
                    self._reset(obj)
                    self._overall(obj)
                    return ok(has_value=False)
            else:
                if index == 1:
                    return ok(obj.counter_list("transmission"))
                if index == 2:
                    self._reset(obj)
                    self._overall(obj)
                    return ok(has_value=False)
        return err(NOT_IMPL_METHOD, "method not implemented")

    def _value(self, obj, level, index):
        if obj is self.root and level == 2:
            return {1: (True, True), 2: (True, self.members())}.get(index, (False, None))
        if obj is self.device_manager and level == 3:
            return self.device_manager_get(index)
        if obj is self.class_manager and level == 3:
            if index == 1:
                return True, [self.models.class_descriptor(c, False) for c in sorted(self.models.classes)]
            if index == 2:
                return True, [self.models.datatype(n, False) for n in sorted(self.models.datatypes)]
        return obj.get(level, index)

    def _object_method(self, obj, index, args) -> dict:
        p = args.get("id") if isinstance(args, dict) else None
        if not isinstance(p, dict):
            return err(PARAM_ERROR, "argument id (property id) required")
        level, pindex = p.get("level"), p.get("index")
        desc = self.models.property(obj.class_id, level, pindex)
        if desc is None:
            return err(NOT_IMPL_PROP, f"property {level}p{pindex} not implemented by this class")
        found, value = self._value(obj, level, pindex)
        if not found:
            return err(NOT_IMPL_PROP, f"property {level}p{pindex} not implemented")
        if index == 1:                                   # Get
            return ok(value)
        if index == 2:                                   # Set
            return self._set(obj, desc, level, pindex, args.get("value"))
        if index in (3, 7):                              # GetSequenceItem / GetSequenceLength
            if not desc.get("isSequence"):
                return err(INVALID, "property is not a sequence")
            if value is None:
                return ok(None) if index == 7 else err(INDEX_OOB, "sequence is null")
            if index == 7:
                return ok(len(value))
            i = args.get("index")
            if not isinstance(i, int) or not 0 <= i < len(value):
                return err(INDEX_OOB, "index out of bounds")
            return ok(value[i])
        if index in (4, 5, 6):                           # Set/Add/RemoveSequenceItem
            if not desc.get("isSequence"):
                return err(INVALID, "property is not a sequence")
            return err(READONLY, "property is read only")
        return err(NOT_IMPL_METHOD, "method not implemented")

    def _set(self, obj, desc, level, index, value) -> dict:
        if desc.get("isReadOnly"):
            return err(READONLY, f"{desc['name']} is read only")
        tn, nullable = desc.get("typeName"), desc.get("isNullable")
        if value is None and not nullable:
            return err(PARAM_ERROR, f"{desc['name']} must not be null")
        if value is not None:
            if tn == "NcString" and not isinstance(value, str):
                return err(PARAM_ERROR, f"{desc['name']} must be a string")
            if tn == "NcBoolean" and not isinstance(value, bool):
                return err(PARAM_ERROR, f"{desc['name']} must be a boolean")
            if tn == "NcUint32" and (not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFFFFFF):
                return err(PARAM_ERROR, f"{desc['name']} must be an unsigned 32 bit integer")
        if level == 1 and index == 6:                    # userLabel
            obj.user_label = value
            if isinstance(obj, Monitor):
                obj.label_override = value               # null: back to the NMOS label on the next sync
                self._persist(obj)
            self._notify(obj.oid, 1, 6, value)
            self._notify(1, 2, 2, self.members())
            return ok(has_value=False)
        if obj is self.device_manager and level == 3 and index in (5, 6, 7):
            self.dm_values[index] = value
            dm = self.b.config().setdefault("ncp_state", {}).setdefault("device", {})
            dm[{5: "userInventoryCode", 6: "deviceName", 7: "deviceRole"}[index]] = value
            self.b.save()
            self._notify(obj.oid, 3, index, value)
            return ok(has_value=False)
        if isinstance(obj, Monitor):
            if level == 2 and index == 1:
                return err(INVALID, "enabled has no meaning for monitors and cannot be changed")
            if level == 3 and index == 3:
                obj.delay = value
                self._persist(obj)
                self._notify(obj.oid, 3, 3, value)
                return ok(has_value=False)
            if level == 4 and index == 14:
                obj.auto_reset = value
                self._persist(obj)
                self._notify(obj.oid, 4, 14, value)
                return ok(has_value=False)
        if obj is self.root and level == 2 and index == 1:
            return err(INVALID, "the root block cannot be disabled")
        return err(READONLY, f"{desc['name']} cannot be changed on this object")

    def _block_method(self, index, args) -> dict:
        objs = self.objects()[1:]
        if index == 1:                                   # GetMemberDescriptors
            return ok(self.members())
        if index == 2:                                   # FindMembersByPath
            path = args.get("path")
            if not isinstance(path, list) or not path or not all(isinstance(p, str) for p in path):
                return err(PARAM_ERROR, "path must be a non-empty array of roles")
            if len(path) != 1:
                return err(PARAM_ERROR, "path not found")
            hit = [o.descriptor() for o in objs if o.role == path[0]]
            return ok(hit) if hit else err(PARAM_ERROR, "path not found")
        if index == 3:                                   # FindMembersByRole
            role = args.get("role")
            if not isinstance(role, str) or not role:
                return err(PARAM_ERROR, "role required")
            cs, whole = bool(args.get("caseSensitive")), bool(args.get("matchWholeString"))

            def match(r):
                a, b = (r, role) if cs else (r.lower(), role.lower())
                return a == b if whole else b in a
            return ok([o.descriptor() for o in objs if match(o.role)])
        if index == 4:                                   # FindMembersByClassId
            cid = args.get("classId")
            if not isinstance(cid, list) or not cid:
                return err(PARAM_ERROR, "classId required")
            derived = bool(args.get("includeDerived"))
            return ok([o.descriptor() for o in objs
                       if o.class_id == cid or (derived and self.models.is_derived(o.class_id, cid))])
        return err(NOT_IMPL_METHOD, "method not implemented")

    # ------------------------------------------------------------------ GUI
    def summary(self, chid: str) -> dict | None:
        with self.lock:
            m = self.monitors.get(chid)
            if not m:
                return None
            names = {"link": LINK_NAMES, "sync": SYNC_NAMES}
            return {
                "oid": m.oid, "role": m.role, "overall": STATUS_NAMES[m.overall], "overall_code": m.overall,
                "overall_message": m.overall_message, "delay": m.delay, "auto_reset": m.auto_reset,
                "sync_source": m.sync_source,
                "domains": {n: {"status": names.get(n, STATUS_NAMES).get(d.status, str(d.status)), "code": d.status,
                                "message": d.message, "transitions": d.counter} for n, d in m.domains.items()},
                "counters": {g: dict(v) for g, v in m.counters.items()},
                "subscribers": sum(1 for s in self.connections.values() if m.oid in s),
            }

    def controller_count(self) -> int:
        return len(self.connections)
