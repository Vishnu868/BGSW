"""Exploitability intelligence from public, key-less feeds (cached in .cache/intel):
  EPSS  (FIRST.org)  - probability that a CVE is exploited in the next 30 days
  KEV   (CISA)       - CVEs known to be exploited in the wild
"""
from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path

CACHE = Path(__file__).resolve().parents[2] / ".cache" / "intel"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _get(url: str, timeout: int = 30):
    req = urllib.request.Request(url, headers={"User-Agent": "supply-chain-guardian/0.2"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def kev(offline: bool = False) -> set[str]:
    f = CACHE / "kev.json"
    if f.exists() and (offline or time.time() - f.stat().st_mtime < 86400):
        return set(json.loads(f.read_text(encoding="utf-8")))
    if offline:
        return set()
    try:
        ids = sorted(v["cveID"] for v in _get(KEV_URL).get("vulnerabilities", []))
    except Exception:
        return set(json.loads(f.read_text(encoding="utf-8"))) if f.exists() else set()
    CACHE.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(ids), encoding="utf-8")
    return set(ids)


def epss(cves: list[str], offline: bool = False) -> dict[str, dict]:
    f = CACHE / "epss.json"
    cache = json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}
    todo = [c for c in sorted(set(cves)) if c not in cache]
    if todo and not offline:
        for i in range(0, len(todo), 80):
            chunk = todo[i:i + 80]
            try:
                data = _get("https://api.first.org/data/v1/epss?cve=" + ",".join(chunk))
            except Exception:
                break
            for row in data.get("data", []):
                cache[row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"])}
            for c in chunk:
                cache.setdefault(c, None)
        CACHE.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps(cache), encoding="utf-8")
    return {c: cache.get(c) for c in cves}
