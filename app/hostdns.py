"""Flush the DNS cache of the Docker host (systemd-resolved via the host's D-Bus system bus).

The container needs the host's /run/dbus mounted (see docker-compose.yml) and runs as root, which
systemd-resolved accepts for FlushCaches. Other host caches (nscd, dnsmasq) cannot be reached from here.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess

SOCKET = "/run/dbus/system_bus_socket"
DEST, PATH, IFACE = "org.freedesktop.resolve1", "/org/freedesktop/resolve1", "org.freedesktop.resolve1.Manager"


def _dbus(*args: str) -> tuple[bool, str]:
    cmd = ["dbus-send", "--system", "--print-reply", f"--dest={DEST}", PATH] + list(args)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    return p.returncode == 0, (p.stdout if p.returncode == 0 else p.stderr).strip()


def cache_size() -> int | None:
    """Current number of entries in the systemd-resolved cache (CacheStatistics: size, hits, misses)."""
    ok, out = _dbus("org.freedesktop.DBus.Properties.Get", f"string:{IFACE}", "string:CacheStatistics")
    if not ok:
        return None
    nums = re.findall(r"uint64 (\d+)", out)
    return int(nums[0]) if nums else None


def flush() -> dict:
    """Returns {ok, message, before, after}."""
    if not os.path.exists(SOCKET):
        return {"ok": False, "message": "host D-Bus not available: mount /run/dbus into the container (see docker-compose.yml)"}
    if not shutil.which("dbus-send"):
        return {"ok": False, "message": "dbus-send missing in the image"}
    before = cache_size()
    ok, out = _dbus(f"{IFACE}.FlushCaches")
    if not ok:
        if "ServiceUnknown" in out or "not provided by any .service" in out:
            msg = "systemd-resolved is not running on the host, so there is no host DNS cache to flush"
        elif "AccessDenied" in out or "not allowed" in out.lower():
            msg = f"the host refused FlushCaches: {out}"
        else:
            msg = f"FlushCaches failed: {out}"
        return {"ok": False, "message": msg}
    after = cache_size()
    msg = "host DNS cache (systemd-resolved) flushed"
    if before is not None:
        msg += f": {before} → {after if after is not None else '?'} entries"
    return {"ok": True, "message": msg, "before": before, "after": after}
