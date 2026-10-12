"""Minimal IS-04 Query API client with paging (nmos-cpp: 10 per page by default) and query.downgrade
(most devices still register with v1.2; without downgrade a v1.3 query hides them)."""
from __future__ import annotations

import json
import urllib.request


class Query:
    def __init__(self, base: str):
        self.base = base.rstrip("/")

    def get(self, resource: str):
        sep = "&" if "?" in resource else "?"
        single = "/" in resource
        url = f"{self.base}/{resource}{sep}query.downgrade=v1.0" + ("" if single else "&paging.limit=100")
        out, seen = [], set()
        for _ in range(100):
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as r:
                page = json.load(r)
                links = r.headers.get_all("Link") or []
            if not isinstance(page, list):
                return page
            new = [x for x in page if x.get("id") not in seen]
            if not new:
                break
            out += new
            seen.update(x.get("id") for x in new)
            nxt = None
            for l in links:
                for part in l.split(","):
                    if 'rel="next"' in part and "<" in part:
                        nxt = part[part.index("<") + 1:part.index(">")]
            if not nxt or len(page) < 100:
                break
            url = nxt
        return out
