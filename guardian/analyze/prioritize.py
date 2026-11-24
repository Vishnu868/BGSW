"""Symbolic prior: contextual, explainable risk score (0-100) per risk item. Every point has a reason.
The Orchestrator & Triage agent may move this score by at most 20 points, with a reason (see neurosymbolic/rules.py).

  base          CVSS x 10 (or severity for non-CVE findings)
  exploitation  +15 on CISA KEV; EPSS >= 0.5 +10, >= 0.1 +5, < 0.01 -5
  exposure      dev-only (never shipped to production) -25 - except supply-chain compromise indicators, which run
                on developer and CI machines anyway
  reachability  imported +5; direct but never imported -10; only via unused parents -15;
                via used parents / unknown: 0 (shown as a reason line, so the breakdown explains why nothing moved)
  directness    direct dependency +5 (the app chose it; one edit fixes it)
  supply chain  typosquat/malicious, tampered lockfile, risky install script (curl/eval/base64) +10
  business      SSVC-inspired decision from config/business_rules.json (Act +15, Attend +8, Track* +3, Track 0),
                listed as its own reason line; "technical_score" is the score without it
Repo-level findings (Dockerfile / workflow lines) have no component, so directness, dev-only and reachability
do not apply to them; their base is the finding's severity.
Ties (several items capped at 100) are broken by: uncapped score, CISA KEV, imported by the app, CVSS, headline.
Priority bands come from neurosymbolic/rules.py BAND (one definition for the whole system):
P1 >= 80 fix now · P2 60-79 this sprint · P3 35-59 plan · P4 < 35 accept / monitor
"""
from __future__ import annotations

import re

from ..neurosymbolic.rules import band

SEV_BASE = {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 5}
VECTOR = re.compile(r"CVSS:(?:3\.\d|4\.0)/[A-Za-z:/]+")
REACH_FACTORS = {"imported": [("imported by application code", 5)],
                 "not-imported": [("direct dependency never imported", -10)],
                 "via-unused-parent": [("only reachable through unused dependencies", -15)],
                 "via-used-parent": [("reachable through a dependency the app uses: no adjustment", 0)]}


def version_key(v: str) -> tuple:
    """Order fixed versions across ecosystems: numeric parts first; a pre-release (-beta, rc1) sorts below its release."""
    m = re.match(r"v?(\d+(?:\.\d+)*)(.*)", str(v).strip())
    if not m:
        return ((0,), 0)
    nums = tuple(int(x) for x in m.group(1).split("."))
    nums += (0,) * (4 - len(nums)) if len(nums) < 4 else ()
    rest = m.group(2).lstrip(".-+")
    stable = 1 if not rest or rest.lower() in ("final", "release", "ga") or rest.startswith("+") else 0
    return (nums, stable)


def is_compromise(f: dict) -> bool:
    """Typosquat/malicious, tampered lockfile, or an install script doing risky things (rated high by Detect)."""
    return (f["category"] == "1.3" or f["rule"].startswith("diff.tampered")
            or (f["category"] == "1.4" and f["severity"] in ("high", "critical")))


def build_items(doc: dict, reach: dict, kev: set, epss: dict, business: dict | None = None) -> list[dict]:
    """business: business_context (see business.py); adds an SSVC-inspired business factor to every item."""
    from . import business as biz
    rules, rules_error = None, ""
    if business:
        try:
            rules = biz.load_rules()
        except (OSError, ValueError) as e:            # missing or broken config/business_rules.json
            rules_error = f"business rules unavailable ({type(e).__name__}): no business adjustment"
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
            has_cvss = cvss not in (None, "")
            base = float(cvss) * 10 if has_cvss else SEV_BASE[f["severity"]]
            factors.append((f"base: {'CVSS ' + str(cvss) if has_cvss else f['severity'] + ' severity'}", base))
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
            if is_compromise(f):
                factors.append(("supply-chain compromise indicator", 10))
            score = sum(v for _, v in factors)
            if score > best_score:
                best, best_score, best_factors = f, score, factors
        factors = list(best_factors)
        compromise = any(is_compromise(f) for f in fs)
        if cd.get("dev_only"):
            if compromise:
                factors.append(("dev-only, but a compromise indicator runs on developer/CI machines: no reduction", 0))
            else:
                factors.append(("dev-only: not shipped to production", -25))
        st = r["status"]
        if cd:
            factors += REACH_FACTORS.get(st, [(f"reachability {st}: no adjustment", 0)])
        if cd.get("direct"):
            factors.append(("direct dependency", 5))
        vec = next((m.group(0) for ev in best["evidence"] for m in [VECTOR.search(ev.get("detail", ""))] if m), "")
        technical = max(0.0, min(100.0, sum(v for _, v in factors)))
        bdec = None
        if rules_error:
            factors.append((rules_error, 0))
        elif business:
            bdec = biz.decide({"component": cd, "cve": best["data"].get("cve", ""), "reachability": r,
                               "cvss_vector": vec}, business, kev, epss, rules)
            if bdec["points"]:
                factors.append((f"business: SSVC {bdec['decision']} - {bdec['reason']}", bdec["points"]))
        raw = sum(v for _, v in factors)
        score = max(0.0, min(100.0, raw))
        p, label = band(score)
        exact = bool(cd) and "*" not in str(cd.get("version", "")) and "?" not in str(cd.get("version", ""))
        conf = "high" if st in ("imported", "not-imported", "via-used-parent", "via-unused-parent") and (exact or not cd) else "medium"
        if not cd:
            conf = "high"      # repo-level findings (Dockerfile/workflow lines) are direct evidence
        fixes = [f["data"].get("fixed", "") for f in fs if f["data"].get("fixed")]
        items.append({
            "id": "", "key": key, "component": cd, "score": round(score, 1), "priority": p,
            "base_score": round(score, 1), "base_priority": p, "technical_score": round(technical, 1),
            "priority_label": label, "confidence": conf,
            "factors": [{"reason": a, "points": b} for a, b in factors],
            "reachability": r, "headline": best["title"], "severity": best["severity"], "category": best["category"],
            "finding_ids": [f["id"] for f in fs], "fixed": best["data"].get("fixed", ""),
            "max_fixed": max(fixes, default="", key=version_key),
            "recommendation": best["recommendation"], "rule": best["rule"],
            "cve": best["data"].get("cve", ""), "cvss_vector": vec, "business": bdec,
            "_tie": (raw, bool(best["data"].get("cve") in kev), st == "imported",
                     float(best["data"].get("cvss") or 0)),
        })
    items.sort(key=lambda i: (-i["score"], -i["_tie"][0], not i["_tie"][1], not i["_tie"][2], -i["_tie"][3], i["headline"]))
    for n, it in enumerate(items, 1):
        it["rank"], it["id"] = n, f"R-{n:03d}"
        del it["_tie"]
    return items
