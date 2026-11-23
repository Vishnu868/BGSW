"""Symbolic prior: contextual, explainable risk score (0-100) per risk item. Every point has a reason.
The Orchestrator & Triage agent may move this score by at most 20 points, with a reason (see neurosymbolic/rules.py).

  base          CVSS x 10 (or severity for non-CVE findings)
  exploitation  +15 on CISA KEV; EPSS >= 0.5 +10, >= 0.1 +5, < 0.01 -5
  exposure      dev-only (never shipped to production) -25
  reachability  imported +5; direct but never imported -10; only via unused parents -15
  directness    direct dependency +5 (the app chose it; one edit fixes it)
  supply chain  typosquat/malicious/tampered findings +10
Priority: P1 >= 80 fix now · P2 60-79 this sprint · P3 35-59 plan · P4 < 35 accept / monitor
"""
from __future__ import annotations

SEV_BASE = {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 5}
BAND = [(80, "P1", "fix now"), (60, "P2", "fix this sprint"), (35, "P3", "plan"), (0, "P4", "accept / monitor")]


def band(score: float) -> tuple[str, str]:
    for lo, p, label in BAND:
        if score >= lo:
            return p, label
    return "P4", "accept / monitor"


def build_items(doc: dict, reach: dict, kev: set, epss: dict) -> list[dict]:
    groups: dict[str, list] = {}
    for f in doc["findings"]:
        key = f["component"] or f"{f['rule']}:{f['id']}"
        groups.setdefault(key, []).append(f)
    items = []
    for key, fs in groups.items():
        cd = fs[0].get("component_detail") or {}
        r = reach.get(key, {"status": "unknown", "evidence": [], "detail": ""})
        best, best_score, best_factors = None, -1.0, []
        for f in fs:
            factors = []
            cvss = f["data"].get("cvss")
            base = float(cvss) * 10 if cvss else SEV_BASE[f["severity"]]
            factors.append((f"base: {'CVSS ' + str(cvss) if cvss else f['severity'] + ' severity'}", base))
            cve = f["data"].get("cve")
            if cve and cve in kev:
                factors.append(("on CISA Known Exploited Vulnerabilities list", 15))
            e = epss.get(cve) if cve else None
            if e:
                if e["epss"] >= 0.5:
                    factors.append((f"EPSS {e['epss']:.2f}: exploitation likely", 10))
                elif e["epss"] >= 0.1:
                    factors.append((f"EPSS {e['epss']:.2f}: exploitation possible", 5))
                elif e["epss"] < 0.01:
                    factors.append((f"EPSS {e['epss']:.3f}: exploitation unlikely", -5))
            if f["category"] in ("1.3",) or f["rule"].startswith("diff.tampered"):
                factors.append(("supply-chain compromise indicator", 10))
            score = sum(v for _, v in factors)
            if score > best_score:
                best, best_score, best_factors = f, score, factors
        factors = list(best_factors)
        if cd.get("dev_only"):
            factors.append(("dev-only: not shipped to production", -25))
        st = r["status"]
        factors += {"imported": [("imported by application code", 5)],
                    "not-imported": [("direct dependency never imported", -10)],
                    "via-unused-parent": [("only reachable through unused dependencies", -15)]}.get(st, [])
        if cd.get("direct"):
            factors.append(("direct dependency", 5))
        score = max(0.0, min(100.0, sum(v for _, v in factors)))
        p, label = band(score)
        exact = bool(cd) and "*" not in str(cd.get("version", "")) and "?" not in str(cd.get("version", ""))
        conf = "high" if st in ("imported", "not-imported", "via-used-parent", "via-unused-parent") and (exact or not cd) else "medium"
        if not cd:
            conf = "high"      # repo-level findings (Dockerfile/workflow lines) are direct evidence
        items.append({
            "id": "", "key": key, "component": cd, "score": round(score, 1), "priority": p,
            "base_score": round(score, 1), "base_priority": p,
            "priority_label": label, "confidence": conf,
            "factors": [{"reason": a, "points": b} for a, b in factors],
            "reachability": r, "headline": best["title"], "severity": best["severity"], "category": best["category"],
            "finding_ids": [f["id"] for f in fs], "fixed": best["data"].get("fixed", ""),
            "max_fixed": max((f["data"].get("fixed", "") for f in fs if f["data"].get("fixed")), default="",
                             key=lambda v: tuple(int(x) for x in v.split(".") if x.isdigit()) or (0,)),
            "recommendation": best["recommendation"], "rule": best["rule"],
        })
    items.sort(key=lambda i: (-i["score"], i["headline"]))
    for n, it in enumerate(items, 1):
        it["rank"], it["id"] = n, f"R-{n:03d}"
    return items
