#!/usr/bin/env python3
"""IS-12 / BCP-008 probe: walks the device model, checks descriptors and prints notifications.

    python3 is12_probe.py ws://host:8095/x-nmos/ncp/v1.0 [listen_seconds]
"""
import json, sys, time
from ws_client import WebSocket

url = sys.argv[1]
listen = float(sys.argv[2]) if len(sys.argv) > 2 else 0
ws = WebSocket(url, 5)
handle = 0


def cmd(oid, level, index, args=None):
    global handle
    handle += 1
    c = {"handle": handle, "oid": oid, "methodId": {"level": level, "index": index}}
    if args is not None:
        c["arguments"] = args
    ws.send(json.dumps({"messageType": 0, "commands": [c]}))
    while True:
        m = json.loads(ws.recv(5))
        if m["messageType"] == 1:
            return m["responses"][0]["result"]
        if m["messageType"] == 2:
            print("  (notification)", m["notifications"])


def get(oid, level, index):
    return cmd(oid, 1, 1, {"id": {"level": level, "index": index}})


print("root members (2p2):", [(m["oid"], m["role"], m["classId"]) for m in get(1, 2, 2)["value"]])
print("root 2p1 enabled:", get(1, 2, 1))
mons = cmd(1, 2, 4, {"classId": [1, 2, 2], "includeDerived": True, "recurse": True})["value"]
print("FindMembersByClassId(NcStatusMonitor, derived):", [(m["oid"], m["role"]) for m in mons])
print("FindMembersByRole('monitor'):", [m["role"] for m in cmd(1, 2, 3, {"role": "monitor", "caseSensitive": False, "matchWholeString": False, "recurse": True})["value"]])
print("FindMembersByPath(['DeviceManager']):", cmd(1, 2, 2, {"path": ["DeviceManager"]})["status"])
print("device manager product:", get(2, 3, 3)["value"]["name"], "| ncVersion", get(2, 3, 1)["value"])
cls = get(3, 3, 1)["value"]
dts = get(3, 3, 2)["value"]
print(f"class manager: {len(cls)} classes, {len(dts)} datatypes")
rm = cmd(3, 3, 1, {"classId": [1, 2, 2, 1], "includeInherited": True})["value"]
print("GetControlClass(NcReceiverMonitor, inherited):", rm["name"], len(rm["properties"]), "props", len(rm["methods"]), "methods")
print("GetDatatype(NcTouchpointNmos, inherited) fields:", [f["name"] for f in cmd(3, 3, 2, {"name": "NcTouchpointNmos", "includeInherited": True})["value"]["fields"]])
for m in mons:
    oid = m["oid"]
    tp = get(oid, 1, 7)["value"]
    vals = {f"{l}p{i}": get(oid, l, i).get("value") for l, i in [(3, 1), (3, 2), (3, 3), (4, 1), (4, 4), (4, 7), (4, 10), (4, 11), (4, 14)]}
    print(f"monitor {oid} {m['role']} touchpoint={tp[0]['resource']}\n   {vals}")
    print("   counters 4m1:", cmd(oid, 4, 1)["value"])
    print("   Set 3p3=5:", cmd(oid, 1, 2, {"id": {"level": 3, "index": 3}, "value": 5})["status"], "->", get(oid, 3, 3)["value"],
          "| back to 3:", cmd(oid, 1, 2, {"id": {"level": 3, "index": 3}, "value": 3})["status"])
    print("   Set 3p1 (readonly):", cmd(oid, 1, 2, {"id": {"level": 3, "index": 1}, "value": 1}))
    print("   Set 3p3='x' (bad type):", cmd(oid, 1, 2, {"id": {"level": 3, "index": 3}, "value": "x"})["status"],
          "| Get 9p9:", get(oid, 9, 9)["status"], "| method 7m7:", cmd(oid, 7, 7)["status"],
          "| GetSequenceLength touchpoints:", cmd(oid, 1, 7, {"id": {"level": 1, "index": 7}}))
print("bad oid:", get(999, 1, 1)["status"])
if listen:
    oids = [1] + [m["oid"] for m in mons]
    ws.send(json.dumps({"messageType": 3, "subscriptions": oids}))
    t0 = time.time()
    while time.time() - t0 < listen:
        raw = ws.recv(0.5)
        if not raw:
            continue
        m = json.loads(raw)
        if m["messageType"] == 4:
            print("subscribed:", m["subscriptions"])
        elif m["messageType"] == 2:
            for n in m["notifications"]:
                p = n["eventData"]["propertyId"]
                print(f"  t+{time.time() - t0:5.1f}s oid {n['oid']} {p['level']}p{p['index']} = {json.dumps(n['eventData']['value'])[:110]}")
ws.close()
