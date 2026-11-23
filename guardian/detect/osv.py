"""Categories 1.1 / 1.2 (and malicious packages, 1.3) via the OSV.dev database.

OSV covers npm, PyPI, Maven, Go, crates.io, ... with one API, so this works for any ecosystem.
Results are cached on disk so a re-scan (and the demo) works offline.
"""
from __future__ import annotations

import json
import math
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..model import Finding, Graph

API = "https://api.osv.dev/v1"
CACHE = Path(__file__).resolve().parents[2] / ".cache" / "osv"
UA = {"User-Agent": "supply-chain-guardian/0.1", "Content-Type": "application/json"}


def _http(url: str, body: dict | None = None, timeout: int = 30) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=UA, method="POST" if data else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


# ---------------------------------------------------------------- CVSS v3 ---
_W = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44},
      "UI": {"N": .85, "R": .62}, "CIA": {"H": .56, "L": .22, "N": 0.0}}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    """CVSS v3.x base score from a vector string (FIRST.org formula)."""
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        changed = m["S"] == "C"
        pr = {"N": .85, "L": .68 if changed else .62, "H": .5 if changed else .27}[m["PR"]]
        iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    return _roundup(min((1.08 if changed else 1) * (impact + expl), 10))


def rating(score: float) -> str:
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "info"


LABEL_SCORE = {"critical": 9.5, "high": 7.5, "moderate": 5.5, "medium": 5.5, "low": 2.5}


def severity_of(v: dict) -> tuple[str, float, str]:
    """-> (rating, score, how we got it). Prefer a computed CVSS v3 score, then the advisory's label."""
    if v.get("id", "").startswith("MAL-"):
        return "critical", 10.0, "OSV malicious-package entry"
    for s in v.get("severity", []):
        if s.get("type") == "CVSS_V3":
            sc = cvss3_score(s.get("score", ""))
            if sc is not None:
                return rating(sc), sc, f"CVSS {sc} ({s['score']})"
    label = (v.get("database_specific", {}) or {}).get("severity", "")
    for a in v.get("affected", []):
        label = label or (a.get("ecosystem_specific", {}) or {}).get("severity", "")
    label = str(label).lower()
    if label in LABEL_SCORE:
        sc = LABEL_SCORE[label]
        return rating(sc), sc, f"advisory severity '{label}'"
    return "medium", 5.0, "no severity published - defaulted to medium"


# ---------------------------------------------------------- version logic ---
def vkey(v: str) -> tuple:
    core = re.split(r"[-+]", v.lstrip("v"), maxsplit=1)[0]
    return tuple(int(x) for x in re.findall(r"\d+", core)) or (0,)


def fixed_version(v: dict, name: str, version: str) -> str:
    """Smallest 'fixed' version of a range that contains our version."""
    best = None
    for a in v.get("affected", []):
        if a.get("package", {}).get("name", "").lower() != name.lower():
            continue
        for r in a.get("ranges", []):
            if r.get("type") == "GIT":
                continue
            intro, ev_fixed = "0", None
            for e in r.get("events", []):
                if "introduced" in e:
                    intro = e["introduced"]
                if "fixed" in e:
                    ev_fixed = e["fixed"]
                    if vkey(intro) <= vkey(version) < vkey(ev_fixed):
                        if best is None or vkey(ev_fixed) < vkey(best):
                            best = ev_fixed
    return best or ""


# ------------------------------------------------------------------ query ---
def _query_ids(comps: list) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for i in range(0, len(comps), 500):
        chunk = comps[i:i + 500]
        body = {"queries": [{"package": {"name": c.name, "ecosystem": c.ecosystem}, "version": c.version}
                            for c in chunk]}
        res = _http(f"{API}/querybatch", body, timeout=60)
        for c, r in zip(chunk, res.get("results", [])):
            ids = [v["id"] for v in r.get("vulns", [])]
            if r.get("next_page_token"):   # rare: >1000 vulns for one package - take the full list
                full = _http(f"{API}/query", {"package": {"name": c.name, "ecosystem": c.ecosystem},
                                              "version": c.version})
                ids = [v["id"] for v in full.get("vulns", [])]
            if ids:
                out[c.id] = ids
    return out


def _vuln(vid: str, offline: bool) -> dict | None:
    f = CACHE / f"{vid}.json"
    if f.exists():
        return json.loads(f.read_text(encoding="utf-8"))
    if offline:
        return None
    v = _http(f"{API}/vulns/{vid}")
    CACHE.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(v), encoding="utf-8")
    return v


def scan(graph: Graph, offline: bool = False) -> tuple[list[Finding], dict]:
    comps = [c for c in graph.nodes.values()
             if c.kind == "library" and c.version and c.version not in ("*", "?") and c.ecosystem != "generic"]
    idx_file = CACHE.parent / "osv_index.json"
    index = json.loads(idx_file.read_text()) if idx_file.exists() else {}
    status = {"queried": len(comps), "source": "osv.dev"}
    if offline:
        hits = {c.id: index[c.id] for c in comps if index.get(c.id)}
        status["source"] = "osv.dev (offline cache)"
    else:
        hits = _query_ids(comps)
        for c in comps:
            index[c.id] = hits.get(c.id, [])
        idx_file.parent.mkdir(parents=True, exist_ok=True)
        idx_file.write_text(json.dumps(index))
    all_ids = sorted({i for ids in hits.values() for i in ids})
    with ThreadPoolExecutor(16) as ex:
        details = dict(zip(all_ids, ex.map(lambda i: _vuln(i, offline), all_ids)))

    paths, intro = graph.shortest_paths(), graph.introduced_by()
    findings = []
    for cid, ids in hits.items():
        c = graph.nodes[cid]
        seen_aliases = set()
        for vid in ids:
            v = details.get(vid) or {"id": vid}
            aliases = v.get("aliases", [])
            # OSV often lists the same issue as GHSA + CVE; report it once.
            if seen_aliases & ({vid} | set(aliases)):
                continue
            seen_aliases |= {vid} | set(aliases)
            sev, score, how = severity_of(v)
            fix = fixed_version(v, c.name, c.version)
            malicious = vid.startswith("MAL-")
            cat = "1.3" if malicious else ("1.1" if c.direct else "1.2")
            cve = next((a for a in [vid] + aliases if a.startswith("CVE-")), "")
            via = sorted(graph.nodes[d].name for d in intro.get(cid, set()) if d != cid)
            ev = [{"source": f"https://osv.dev/vulnerability/{vid}", "detail": v.get("summary") or v.get("details", "")[:200]},
                  {"source": "severity", "detail": how},
                  {"source": "dependency path", "detail": " > ".join(graph.nodes[p].name for p in paths.get(cid, []))}]
            if via:
                ev.append({"source": "introduced by direct dependency", "detail": ", ".join(via[:8])})
            findings.append(Finding(
                category=cat, severity=sev,
                title=f"{'MALICIOUS package' if malicious else (cve or vid)}: {c.name}@{c.version} - {(v.get('summary') or '')[:90]}",
                component=cid, rule="osv", evidence=ev,
                recommendation=(f"Remove {c.name} immediately and rotate any secrets on machines that installed it"
                                if malicious else
                                f"Upgrade {c.name} to {fix} or later" + ("" if c.direct else f" (via {', '.join(via[:3]) or 'its parent'})")
                                if fix else f"No fixed version published - replace or mitigate {c.name}"),
                data={"vuln_id": vid, "aliases": aliases, "cve": cve, "cvss": score, "fixed": fix,
                      "via": via, "dev_only": c.dev}))
    status["vulnerable_components"] = len(hits)
    status["advisories"] = len(all_ids)
    return findings, status
