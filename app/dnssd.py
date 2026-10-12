"""DNS-SD discovery of NMOS registries (IS-04 registration/query APIs): mDNS (RFC 6762) and unicast DNS-SD (RFC 6763) – stdlib only.

    registries = discover()            # beides
    registries = discover(mdns=True, unicast=False)

Each hit: {name, host, port, api_proto, api_ver, pri, url, source}. Sorted by pri (lower = preferred).
"""
from __future__ import annotations

import os
import random
import socket
import struct
import time

SERVICE = "_nmos-query._tcp"
MDNS_GROUP, MDNS_PORT = "224.0.0.251", 5353
TYPE_A, TYPE_PTR, TYPE_TXT, TYPE_SRV, TYPE_ANY = 1, 12, 16, 33, 255


# ---------------------------------------------------------------- packets
def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode("utf-8")
    return out + b"\x00"


def build_query(name: str, qtype: int, unicast_response: bool = False, rd: bool = False) -> bytes:
    qid = random.randint(1, 0xFFFF)
    flags = 0x0100 if rd else 0x0000
    qclass = 1 | (0x8000 if unicast_response else 0)
    return struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0) + _encode_name(name) + struct.pack(">HH", qtype, qclass)


def _read_name(pkt: bytes, pos: int) -> tuple[str, int]:
    labels, jumped, end = [], False, pos
    guard = 0
    while True:
        guard += 1
        if guard > 128 or pos >= len(pkt):
            raise ValueError("malformed name")
        n = pkt[pos]
        if n == 0:
            pos += 1
            if not jumped:
                end = pos
            break
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", pkt[pos:pos + 2])[0] & 0x3FFF
            if not jumped:
                end = pos + 2
            pos, jumped = ptr, True
            continue
        labels.append(pkt[pos + 1:pos + 1 + n].decode("utf-8", errors="replace"))
        pos += 1 + n
    return ".".join(labels), end


def parse_records(pkt: bytes) -> list[dict]:
    """All resource records (answer + authority + additional) of a DNS packet."""
    try:
        qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", pkt[:12])
        pos = 12
        for _ in range(qd):
            _, pos = _read_name(pkt, pos)
            pos += 4
        out = []
        for _ in range(an + ns + ar):
            name, pos = _read_name(pkt, pos)
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", pkt[pos:pos + 10])
            pos += 10
            rdata = pkt[pos:pos + rdlen]
            rec = {"name": name, "type": rtype, "ttl": ttl}
            if rtype == TYPE_PTR:
                rec["value"], _ = _read_name(pkt, pos)
            elif rtype == TYPE_SRV:
                pri, weight, port = struct.unpack(">HHH", rdata[:6])
                target, _ = _read_name(pkt, pos + 6)
                rec.update(priority=pri, weight=weight, port=port, target=target)
            elif rtype == TYPE_TXT:
                txt, p = {}, 0
                while p < len(rdata):
                    n = rdata[p]
                    item = rdata[p + 1:p + 1 + n].decode("utf-8", errors="replace")
                    p += 1 + n
                    k, _, v = item.partition("=")
                    txt[k] = v
                rec["txt"] = txt
            elif rtype == TYPE_A and rdlen == 4:
                rec["address"] = socket.inet_ntoa(rdata)
            out.append(rec)
            pos += rdlen
        return out
    except (struct.error, ValueError):
        return []


# ---------------------------------------------------------------- mDNS
def mdns_query(service: str = SERVICE, wait: float = 2.0) -> list[dict]:
    """Queries <service>.local via multicast; collects PTR/SRV/TXT/A from all answers."""
    name = f"{service}.local"
    recs: list[dict] = []
    socks = []
    # 1) regular socket with QU bit (unicast answer to our port)
    s1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s1.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    s1.bind(("0.0.0.0", 0))
    socks.append(s1)
    # 2) additionally listen on 5353 (answers that still arrive via multicast)
    try:
        s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        s2.bind(("0.0.0.0", MDNS_PORT))
        s2.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(MDNS_GROUP) + socket.inet_aton("0.0.0.0"))
        socks.append(s2)
    except OSError:
        pass
    q = build_query(name, TYPE_PTR, unicast_response=True)
    for _ in range(2):
        s1.sendto(q, (MDNS_GROUP, MDNS_PORT))
        time.sleep(0.05)
    deadline = time.time() + wait
    for s in socks:
        s.setblocking(False)
    import select
    while time.time() < deadline:
        r, _, _ = select.select(socks, [], [], max(0.01, deadline - time.time()))
        for s in r:
            try:
                pkt, src = s.recvfrom(9000)
            except OSError:
                continue
            recs += [dict(r, source_ip=src[0]) for r in parse_records(pkt)]
    # ask for missing SRV/TXT/A explicitly (some responders do not include them)
    instances = {r["value"] for r in recs if r["type"] == TYPE_PTR and r["name"].lower() == name.lower()}
    have = {(r["name"].lower(), r["type"]) for r in recs}
    for inst in instances:
        for t in (TYPE_SRV, TYPE_TXT):
            if (inst.lower(), t) not in have:
                s1.sendto(build_query(inst, t, unicast_response=True), (MDNS_GROUP, MDNS_PORT))
    targets = {r["target"] for r in recs if r["type"] == TYPE_SRV}
    for tgt in targets:
        if (tgt.lower(), TYPE_A) not in have:
            s1.sendto(build_query(tgt, TYPE_A, unicast_response=True), (MDNS_GROUP, MDNS_PORT))
    deadline = time.time() + 0.8
    while time.time() < deadline:
        r, _, _ = select.select(socks, [], [], max(0.01, deadline - time.time()))
        for s in r:
            try:
                pkt, src = s.recvfrom(9000)
            except OSError:
                continue
            recs += [dict(r, source_ip=src[0]) for r in parse_records(pkt)]
    for s in socks:
        s.close()
    return _assemble(recs, name, "mdns", service)


# ---------------------------------------------------------------- unicast DNS-SD
def resolver_config() -> tuple[list[str], list[str]]:
    """(nameservers, search domains) as provided by the host (DHCP). Sources, in order:
    /etc/resolv.conf, systemd-resolved (/run/systemd/resolve/resolv.conf, resolvectl), NetworkManager (nmcli),
    the domain part of the host's own FQDN."""
    servers, domains = [], []

    def add(lst, items):
        for it in items:
            it = it.strip().strip(".")
            if it and it not in lst and not it.endswith((".arpa", "localhost")):
                lst.append(it)

    def read_resolv(path):
        try:
            with open(path) as f:
                for line in f:
                    p = line.split()
                    if not p or p[0].startswith("#"):
                        continue
                    if p[0] == "nameserver":
                        add(servers, [p[1]])
                    elif p[0] in ("search", "domain"):
                        add(domains, p[1:])
        except OSError:
            pass

    read_resolv("/etc/resolv.conf")
    read_resolv("/run/systemd/resolve/resolv.conf")
    import shutil, subprocess
    if shutil.which("resolvectl"):
        try:
            out = subprocess.run(["resolvectl", "status"], capture_output=True, text=True, timeout=3).stdout
            for line in out.splitlines():
                l = line.strip()
                if l.startswith("DNS Servers:") or l.startswith("Current DNS Server:"):
                    add(servers, l.split(":", 1)[1].split())
                elif l.startswith("DNS Domain:"):
                    add(domains, [d for d in l.split(":", 1)[1].split() if not d.startswith("~")])
        except (OSError, subprocess.TimeoutExpired):
            pass
    if shutil.which("nmcli"):
        try:
            out = subprocess.run(["nmcli", "-t", "-g", "IP4.DNS,IP4.DOMAIN", "device", "show"], capture_output=True, text=True, timeout=3).stdout
            for line in out.splitlines():
                for item in line.replace("|", " ").split():
                    if item.count(".") == 3 and item.replace(".", "").isdigit():
                        add(servers, [item])
                    elif "." in item and not item.replace(".", "").isdigit():
                        add(domains, [item])
        except (OSError, subprocess.TimeoutExpired):
            pass
    try:
        fqdn = socket.getfqdn()
        if "." in fqdn and not fqdn.endswith(".local"):
            add(domains, [fqdn.split(".", 1)[1]])
    except OSError:
        pass
    servers = [x for x in servers if not x.startswith("127.")] + [x for x in servers if x.startswith("127.")]
    return servers, domains


def dns_query(server: str, name: str, qtype: int, timeout: float = 2.0) -> list[dict]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(build_query(name, qtype, rd=True), (server, 53))
        pkt, _ = s.recvfrom(9000)
        return parse_records(pkt)
    except OSError:
        return []
    finally:
        s.close()


def unicast_query(service: str = SERVICE, domains: list[str] | None = None, servers: list[str] | None = None,
                  extra_domains: list[str] | None = None) -> list[dict]:
    srv, dom = resolver_config()
    servers = servers or srv
    domains = list(extra_domains or []) + [d for d in (domains or dom) if d not in (extra_domains or [])]
    out = []
    for domain in domains:
        name = f"{service}.{domain}"
        for server in servers:
            recs = dns_query(server, name, TYPE_PTR)
            instances = [r["value"] for r in recs if r["type"] == TYPE_PTR]
            if not instances:
                continue
            for inst in instances:
                recs += dns_query(server, inst, TYPE_SRV) + dns_query(server, inst, TYPE_TXT)
            for r in [x for x in recs if x["type"] == TYPE_SRV]:
                recs += dns_query(server, r["target"], TYPE_A)
            out += _assemble(recs, name, f"dns:{domain}", service)
            break
    return out


# ---------------------------------------------------------------- assembly
def _assemble(recs: list[dict], ptr_name: str, source: str, service: str = SERVICE) -> list[dict]:
    api = "registration" if "regist" in service else "query"
    by_name: dict[str, dict] = {}
    a_recs = {r["name"].lower(): r["address"] for r in recs if r["type"] == TYPE_A}
    for r in recs:
        if r["type"] == TYPE_PTR and r["name"].lower() == ptr_name.lower():
            by_name.setdefault(r["value"].lower(), {"name": r["value"]})
    for r in recs:
        e = by_name.get(r["name"].lower())
        if e is None:
            continue
        if r["type"] == TYPE_SRV:
            e.update(port=r["port"], host=r["target"], srv_priority=r["priority"], source_ip=r.get("source_ip"))
        elif r["type"] == TYPE_TXT:
            e["txt"] = r["txt"]
    out = []
    for e in by_name.values():
        if "port" not in e:
            continue
        txt = e.get("txt", {})
        host = e["host"].rstrip(".")
        addr = a_recs.get(host.lower()) or a_recs.get(host.lower() + ".")
        if not addr and host.lower().endswith(".local") and e.get("source_ip"):
            addr = e["source_ip"]      # SRV target not resolvable via mDNS: the responder is the registry host
        if not addr:
            try:
                addr = socket.gethostbyname(host)
            except OSError:
                addr = e.get("source_ip") or host
        proto = txt.get("api_proto", "http")
        vers = [v for v in txt.get("api_ver", "").split(",") if v]
        try:
            pri = int(txt.get("pri", "100"))
        except ValueError:
            pri = 100
        out.append({"name": e["name"].split("._")[0], "host": host, "address": addr, "port": e["port"], "api_proto": proto,
                    "api_ver": vers, "pri": pri, "source": source,
                    "base": f"{proto}://{addr}:{e['port']}",
                    "url": f"{proto}://{addr}:{e['port']}/x-nmos/{api}/{vers[-1] if vers else 'v1.3'}"})
    return sorted(out, key=lambda x: (x["pri"], x["name"]))


def discover(mdns: bool = True, unicast: bool = True, wait: float = 2.0, extra_domains: list[str] | None = None,
             service: str = SERVICE, servers: list[str] | None = None) -> list[dict]:
    out = []
    if mdns:
        try:
            out += mdns_query(service, wait=wait)
        except OSError:
            pass
    if unicast:
        out += unicast_query(service, extra_domains=extra_domains, servers=servers or None)
    seen, uniq = set(), []
    for r in out:
        key = (r["address"], r["port"])
        if key not in seen:
            seen.add(key); uniq.append(r)
    return sorted(uniq, key=lambda x: (x["pri"], x["name"]))


if __name__ == "__main__":
    import json, sys
    print(json.dumps(discover(), indent=1))
    print("resolver:", resolver_config(), file=sys.stderr)


# ---------------------------------------------------------------- passive mDNS browser
class MdnsBrowser:
    """Listens to mDNS traffic (announcements, other hosts' answers, goodbyes) and keeps the records of one
    service type fresh, so a failover can pick the next instance without a new query round."""

    def __init__(self, service: str = SERVICE):
        import threading
        self.service = service
        self.ptr_name = f"{service}.local".lower()
        self.recs: dict[tuple, tuple[dict, float]] = {}    # (name, type, value) -> (record, expiry)
        self.lock = threading.Lock()
        self.running = False

    def start(self):
        import threading
        if self.running:
            return
        self.running = True
        threading.Thread(target=self._run, daemon=True, name=f"mdns-browse-{self.service}").start()

    def _run(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            s.bind(("0.0.0.0", MDNS_PORT))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(MDNS_GROUP) + socket.inet_aton("0.0.0.0"))
            s.settimeout(1.0)
        except OSError:
            self.running = False
            return
        while self.running:
            try:
                pkt, src = s.recvfrom(9000)
            except socket.timeout:
                continue
            except OSError:
                break
            now = time.time()
            with self.lock:
                for r in parse_records(pkt):
                    key = (r["name"].lower(), r["type"], json_key(r))
                    if r.get("ttl", 0) == 0:
                        self.recs.pop(key, None)          # goodbye
                    else:
                        self.recs[key] = (dict(r, source_ip=src[0]), now + min(r["ttl"], 4500))
        s.close()

    def results(self) -> list[dict]:
        now = time.time()
        with self.lock:
            for k in [k for k, (_, exp) in self.recs.items() if exp < now]:
                del self.recs[k]
            recs = [r for r, _ in self.recs.values()]
        return _assemble(recs, f"{self.service}.local", "mdns", self.service)


def json_key(r: dict) -> str:
    return str(r.get("value") or r.get("target") or r.get("address") or sorted((r.get("txt") or {}).items()))
