"""Agent 6 - Neurosymbolic Prioritizer: re-prioritises every risk from the other agents' verified outputs.

Inputs (per risk item)
  scan / public data   severity, CVSS vector, CISA KEV, EPSS, reachability, dev-only, dependency paths, scanners
  Lead (agent 1)       triage move and reason (already bounded to ±20 by the verifier)
  Vuln Analyst (2)     verdict, exploitable in this app?, confidence
  Forensics (3)        verdict on non-CVE supply-chain risks, confidence
  Critic (4)           agrees / disagrees, concern
  Business Context (5) internet-facing? which sensitive data? (file:line facts, human-confirmable)
  human review         confirmed / dismissed decisions from `guardian review`

Rules (config/neurosymbolic_rules.json) score five dimensions, each 0-100 with reasons:
  threat          severity x exploitability x exposure
  production      is the vulnerable code actually shipped and loaded?
  business_loss   worst plausible loss from the data the project handles and what the flaw breaks (C/I/A)
  supply_chain    is the artifact itself trustworthy? (malicious, tampered, look-alike, install scripts, CI, images)
  blast_radius    how many builds, projects and dependency paths it reaches
then apply hard gates, and return score + P1..P4 + confidence + a plain-language explanation built from the
rules that fired (never written by a model, so it cannot invent a reason).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import rules as sym

ROOT = Path(__file__).resolve().parents[2]
RULES_FILE = ROOT / "config" / "neurosymbolic_rules.json"
POLICY_FILE = ROOT / "config" / "policy.json"
DIMS = ("threat", "production", "business_loss", "supply_chain", "blast_radius")
TITLE = {"threat": "Threat (severity, exploitability, exposure)", "production": "Production use",
         "business_loss": "Business loss", "supply_chain": "Supply-chain integrity", "blast_radius": "Blast radius"}
REACHABLE = ("imported", "via-used-parent", "unknown")
# risks to the artifact itself: they do damage when the package is INSTALLED (install scripts, swapped tarballs),
# so "used in production" means "installed in a production build", not "imported by the code"
INSTALL_TIME = ("packages.lookalike-name", "packages.repo-name-mismatch", "packages.low-downloads", "diff.tampered",
                "lockfile.untrusted-registry", "lockfile.insecure-url", "lockfile.git-source")
SENSITIVE_ORDER = ("payment", "credentials", "personal", "auth_tokens")


def load_rules(path: Path = RULES_FILE) -> dict:
    r = json.loads(Path(path).read_text(encoding="utf-8"))
    validate(r)
    return r


def validate(r: dict) -> None:
    problems = []
    w = r.get("weights", {})
    if set(w) != set(DIMS):
        problems.append(f"weights must cover exactly {DIMS}")
    elif abs(sum(w.values()) - 1) > 1e-6:
        problems.append(f"weights sum to {sum(w.values())}, not 1")
    if abs(sum(r["threat"]["parts"].values()) - 1) > 1e-6:
        problems.append("threat.parts must sum to 1")
    for name, g in r["gates"].items():
        if g.get("priority") not in ("P1", "P2", "P3", "P4"):
            problems.append(f"gate {name}: priority must be P1..P4")
        for k in ("min_score", "max_score"):
            if k in g and sym.band(g[k])[0] != g["priority"]:
                problems.append(f"gate {name}: {k} {g[k]} is not inside band {g['priority']}")
    if problems:
        raise ValueError("neurosymbolic_rules.json: " + "; ".join(problems))


# ------------------------------------------------------------------------------------------------ inputs ---
def _vector(v: str) -> dict:
    return dict(p.split(":", 1) for p in (v or "").split("/")[1:] if ":" in p)


def _agent(entries: list, name: str) -> dict | None:
    e = next((x for x in reversed(entries or []) if x.get("agent") == name), None)
    if not e:
        return None
    o = e.get("output") or {}
    return {"source": e.get("source") or o.get("source") or "ai", "status": e.get("status"), **o}


def business_profile(ctx: dict, project: str) -> dict:
    """Internet exposure and sensitive data for one project (or the whole repo for repo-level risks), with the
    best source behind each fact: human-confirmed > agent (verified) > pattern rules."""
    from ..analyze import business
    human = (ctx or {}).get("human") or {}
    facts = [f for f in business.active_facts(ctx or {"facts": []}) if not project or f["project"] == project]

    def src(f):
        if human.get(f"{f['fact']}:{f['value']}:{f['project']}") == "confirmed":
            return "human"
        return "agent" if f.get("source") == "agent" else "rules"
    rank = {"human": 3, "agent": 2, "rules": 1}
    inet = [f for f in facts if f["fact"] == "internet_facing"]
    data: dict[str, str] = {}
    evidence: dict[str, str] = {}
    for f in facts:
        if f["fact"] == "data_class" and rank[src(f)] > rank.get(data.get(f["value"]), 0):
            data[f["value"]], evidence[f["value"]] = src(f), f["evidence"]
    best_inet = max(inet, key=lambda f: rank[src(f)], default=None)
    return {"project": project or "(whole repository)", "internet_facing": bool(inet),
            "internet_source": src(best_inet) if best_inet else None,
            "internet_evidence": best_inet["evidence"] if best_inet else None,
            "data": data, "data_evidence": evidence, "known": bool(ctx and ctx.get("facts") is not None)}


def gather(item: dict, findings: dict, intel: dict, ctx: dict, case: dict | None, review: dict,
           allow_scripts: set) -> dict:
    """Everything the prioritizer is told about one item: deterministic facts + the five agents' outputs."""
    cd = item.get("component") or {}
    fs = [findings[i] for i in item.get("finding_ids", []) if i in findings]
    cves = sorted({f["data"].get("cve") for f in fs if f["data"].get("cve")})
    epss = [e["epss"] for e in (intel["epss"].get(c) for c in cves) if e and e.get("epss") is not None]
    cvss = max((float(f["data"]["cvss"]) for f in fs if f["data"].get("cvss")), default=None)
    rule_ids = sorted({f["rule"] for f in fs} | {item.get("rule", "")} - {""})
    mal = any(str(f["data"].get("vuln_id", "")).startswith("MAL-") for f in fs)
    entries = (case or {}).get("entries", [])
    project = (item.get("business") or {}).get("project", "") if cd else ""
    return {
        "headline": item["headline"], "category": item["category"], "severity": item["severity"],
        "cvss": cvss, "vector": _vector(item.get("cvss_vector", "")), "cves": cves,
        "kev": any(c in intel["kev"] for c in cves), "epss": max(epss) if epss else None,
        "rules": rule_ids, "malicious": mal, "repo_level": not cd or cd.get("kind") in ("action", "container"),
        "reachability": (item.get("reachability") or {}).get("status", "unknown"),
        "dev_only": bool(cd.get("dev_only")), "direct": bool(cd.get("direct")),
        "introduced_by": len(cd.get("introduced_by") or []), "findings": len(fs),
        "projects": len({m for f in fs for m in ((f.get("component_detail") or {}).get("manifests") or [])}),
        "scanners": max((len(f["data"].get("scanners") or []) for f in fs), default=0),
        "allow_listed_script": cd.get("name") in allow_scripts if cd else False,
        "fix_available": bool(item.get("max_fixed")),
        "agents": {
            "lead_triage": ({"source": next((e.get("source") for e in entries if e.get("agent") == "lead_triage"), "rules"),
                             "delta": round(float(item["score"]) - float(item["base_score"]), 1),
                             "reason": item.get("triage_reason")} if item.get("triage_reason") else None),
            "vulnerability_analyst": _agent(entries, "vulnerability_analyst"),
            "supply_chain_forensics": _agent(entries, "supply_chain_forensics"),
            "critic": _agent(entries, "critic"),
        },
        "business": business_profile(ctx, project),
        "human_review": (review.get(item["id"]) or {}).get("decision"),
        "agent_score": item["score"], "agent_priority": item["priority"],
    }


# ---------------------------------------------------------------------------------------------- dimensions ---
def _conf(source: str, r: dict, agent_conf: float | None = None) -> float:
    if source == "agent" and agent_conf is not None:
        return float(agent_conf)
    return r["confidence"]["source_weight"].get(source, r["confidence"]["source_weight"]["default"])


def _sure(a: dict | None, verdict: str | None = None, exploitable: str | None = None) -> bool:
    """A specialist's verdict counts as evidence only if a model produced it, the verifier accepted it and it is
    confident. A rule fallback only restates the scan's own facts, so counting it again would double-count them."""
    if not a or a.get("source") != "ai" or a.get("status") == "rejected" or float(a.get("confidence") or 0) < 0.6:
        return False
    return (verdict is None or a.get("verdict") == verdict) and (exploitable is None or a.get("exploitable_in_context") == exploitable)


def compromised(x: dict) -> bool:
    forensics = x["agents"]["supply_chain_forensics"]
    return (x["malicious"] or any(r.startswith("diff.tampered") for r in x["rules"])
            or "packages.repo-name-mismatch" in x["rules"]
            or (x["category"] == "1.3" and _sure(forensics, "confirmed_risk")))


def dim_threat(x: dict, r: dict) -> dict:
    t, reasons = r["threat"], []
    if x["cvss"] is not None:
        sev, sev_c = x["cvss"] * 10, _conf("verified", r)
        reasons.append(f"CVSS {x['cvss']:g}")
    else:
        sev, sev_c = t["severity_by_level"][x["severity"]], _conf("verified", r)
        reasons.append(f"{x['severity']} severity (no CVSS score)")
    ex, analyst = t["exploitability"], x["agents"]["vulnerability_analyst"]
    cands = []
    if compromised(x):
        cands.append((ex["malicious_or_tampered"], "malicious or tampered artifact: the attacker's code is already inside", "verified", None))
    if x["kev"]:
        cands.append((ex["kev"], "on CISA's Known Exploited Vulnerabilities list", "verified", None))
    if x["epss"] is not None and x["epss"] >= ex["epss_high"]["min"]:
        cands.append((ex["epss_high"]["value"], f"EPSS {x['epss']:.2f}: exploitation likely", "verified", None))
    elif x["epss"] is not None and x["epss"] >= ex["epss_medium"]["min"]:
        cands.append((ex["epss_medium"]["value"], f"EPSS {x['epss']:.2f}: exploitation possible", "verified", None))
    if _sure(analyst, exploitable="yes"):
        cands.append((ex["analyst_exploitable_yes"], "Vulnerability Analyst: exploitable in this application", "agent", analyst["confidence"]))
    v = x["vector"]
    if v.get("AV") == "N" and v.get("PR") == "N" and v.get("UI") == "N":
        cands.append((ex["automatable_vector"], "remote, no login, no user action (automatable)", "verified", None))
    if any(r_.startswith(("packages.install-script", "diff.install-script-added")) for r_ in x["rules"]):
        cands.append((ex["install_script"], "runs automatically on every install", "verified", None))
    if any(r_.startswith(("cicd.script-injection", "cicd.prt-checkout")) for r_ in x["rules"]):
        cands.append((ex["ci_injection"], "attacker-controlled input reaches a CI job", "verified", None))
    if cands:
        val, why, src, ac = max(cands, key=lambda c: c[0])
    else:
        val, why, src, ac = ex["unknown"], "no exploitation data", "default", None
    if x["epss"] is not None and x["epss"] <= ex["epss_low"]["max"] and not x["kev"] and not _sure(analyst, exploitable="yes") \
            and not compromised(x):
        val, why, src, ac = ex["epss_low"]["value"], f"EPSS {x['epss']:.3f}: exploitation unlikely", "verified", None
    if _sure(analyst, exploitable="no") and not x["kev"] and val > ex["analyst_exploitable_no_cap"]:
        val, why, src, ac = ex["analyst_exploitable_no_cap"], "Vulnerability Analyst: not exploitable in this application", "agent", analyst["confidence"]
    reasons.append(why)
    exploit_c = _conf(src, r, ac)

    e, b, st = t["exposure"], x["business"], x["reachability"]
    biz_c = _conf(b["internet_source"] or "default", r)
    if x["category"] == "1.7":
        exp, why, ec = e["ci_pipeline"], "runs in the CI pipeline, which holds repository secrets", _conf("verified", r)
    elif x["category"] == "1.5":
        exp = e["internet_facing_and_reachable"] if b["internet_facing"] else e["container_image"]
        why = "image of an internet-facing service" if b["internet_facing"] else "container image that is deployed"
        ec = biz_c if b["internet_facing"] else _conf("verified", r)
    elif x["dev_only"]:
        exp, why, ec = e["dev_only"], "dev-only: not deployed", _conf("verified", r)
    elif b["internet_facing"] and st in REACHABLE:
        exp, why, ec = e["internet_facing_and_reachable"], f"internet-facing project ({b['internet_evidence']}) and the code is {st}", biz_c
    elif b["internet_facing"]:
        exp, why, ec = e["internet_facing_not_reachable"], "internet-facing project, but the package is not loaded", biz_c
    elif st in REACHABLE and b["known"]:
        exp, why, ec = e["internal_and_reachable"], "loaded, but no internet-facing entry point found", min(biz_c, 0.75)
    else:
        exp, why, ec = e["unknown"], "exposure unknown", _conf("default", r)
    reasons.append(why)
    p = t["parts"]
    score = p["severity"] * sev + p["exploitability"] * val + p["exposure"] * exp
    conf = p["severity"] * sev_c + p["exploitability"] * exploit_c + p["exposure"] * ec
    return {"score": round(score, 1), "confidence": round(conf, 2), "reasons": reasons,
            "parts": {"severity": round(sev, 1), "exploitability": val, "exposure": exp}}


def dim_production(x: dict, r: dict) -> dict:
    pr, st = r["production"], x["reachability"]
    install = any(r_.startswith(("packages.install-script", "diff.install-script-added")) for r_ in x["rules"])
    if x["category"] == "1.5":
        s, why, c = pr["container_image"], "base image of the shipped container", _conf("verified", r)
    elif x["category"] == "1.7":
        s, why, c = pr["ci_pipeline"], "build pipeline that produces every release", _conf("verified", r)
    elif install and x["dev_only"]:
        s, why, c = pr["dev_only_install_script"], "dev-only, but its install script runs on developer machines and CI", _conf("verified", r)
    elif install:
        s, why, c = pr["install_script_production"], "its install script runs in every production build", _conf("verified", r)
    elif (x["malicious"] or any(r_.startswith(INSTALL_TIME) for r_ in x["rules"])) and not x["dev_only"]:
        s, why, c = pr["installed_in_production"], "installed in every production build (harm at install time needs no import)", _conf("verified", r)
    elif x["dev_only"]:
        s, why, c = pr["dev_only"], "dev-only: never shipped to production", _conf("verified", r)
    else:
        s = pr["by_reachability"].get(st, pr["by_reachability"]["unknown"])
        why = {"imported": "imported by the application code", "via-used-parent": "loaded through a dependency the app uses",
               "used-in-scripts": "only used by build/test scripts", "not-imported": "declared but never imported",
               "via-unused-parent": "only reachable through unused dependencies"}.get(st, "reachability unknown")
        c = 0.4 if st == "unknown" else 0.85            # import-level static analysis, not a call graph
    reasons = [why]
    analyst = x["agents"]["vulnerability_analyst"]
    if _sure(analyst, exploitable="yes"):
        s = min(100, s + pr["analyst_exploitable_yes_bonus"])
        reasons.append(f"Vulnerability Analyst confirmed it is reachable/exploitable (+{pr['analyst_exploitable_yes_bonus']})")
        c = max(c, float(analyst["confidence"]))
    specs = [a for a in (x["agents"]["vulnerability_analyst"], x["agents"]["supply_chain_forensics"]) if a]
    if specs and all(_sure(a, "likely_false_positive") for a in specs):
        s = max(0, s - pr["specialists_false_positive_penalty"])
        reasons.append(f"specialists judged it a likely false positive (-{pr['specialists_false_positive_penalty']})")
    return {"score": s, "confidence": round(c, 2), "reasons": reasons}


def dim_business_loss(x: dict, r: dict) -> dict:
    bl, b, v = r["business_loss"], x["business"], x["vector"]
    data = b["data"]
    top = next((d for d in SENSITIVE_ORDER if d in data), None)
    data_txt = ", ".join(f"{d} ({b['data_evidence'][d]})" for d in SENSITIVE_ORDER if d in data) or "no sensitive data found"
    data_c = _conf(max(data.values(), key=lambda s_: {"human": 3, "agent": 2, "rules": 1}[s_]) if data else "default", r)
    losses = []
    if compromised(x) or any(r_.startswith(("cicd.script-injection", "cicd.prt-checkout")) for r_ in x["rules"]):
        losses.append((bl["full_compromise"], f"full compromise: attacker code runs with the app's or pipeline's access ({data_txt})"))
    if v:
        if v.get("C") in ("H", "L"):
            f = 1.0 if v["C"] == "H" else 0.6
            losses.append((bl["data_breach"][top or "none"] * f, f"data exposure ({'high' if f == 1 else 'partial'} confidentiality impact) of {data_txt}"))
        if v.get("I") in ("H", "L"):
            f = 1.0 if v["I"] == "H" else 0.6
            losses.append((bl["fraud_tampering"][top or "none"] * f, f"tampering/fraud ({'high' if f == 1 else 'partial'} integrity impact) on {data_txt}"))
        if v.get("A") == "H":
            k = "internet_facing" if b["internet_facing"] else "internal"
            losses.append((bl["outage"][k], f"outage of {'a customer-facing' if k == 'internet_facing' else 'an internal'} service"))
        vec_c = _conf("verified", r)
    else:
        vec_c = _conf("default", r)
    if not losses:
        # no CVSS vector (config, CI or container findings): a low-severity misconfiguration cannot plausibly
        # cause a catastrophic loss, so the assumed exposure is scaled by the finding's own severity
        sev = r["threat"]["severity_by_level"][x["severity"]] / 100
        base = bl["data_breach"][top or "none"] * bl["unknown_impact_factor"] * sev
        losses.append((base, f"impact type unknown: assumed exposure of {data_txt}, scaled by {x['severity']} severity"))
    s, why = max(losses, key=lambda l: l[0])
    cls = next(c for c in bl["classes"] if s >= c["min"])
    return {"score": round(s, 1), "confidence": round((data_c + vec_c) / 2, 2),
            "reasons": [why, f"loss class {cls['class']}: {cls['means']}"], "loss_class": cls["class"]}


def dim_supply_chain(x: dict, r: dict) -> dict | None:
    sc = r["supply_chain"]
    hits = []
    for key, val in sc["by_rule"].items():
        if key == "osv:MAL-":
            if x["malicious"]:
                hits.append((val, "known malicious package (MAL- advisory)"))
        elif any(r_.startswith(key) for r_ in x["rules"]):
            v = sc["allow_listed_install_script"] if key == "packages.install-script" and x["allow_listed_script"] else val
            hits.append((v, f"{key}{' (allow-listed in policy.json)' if v != val else ''}"))
    if not hits:
        return None
    s, why = max(hits, key=lambda h: h[0])
    reasons, c = [why], _conf("verified", r)
    fo = x["agents"]["supply_chain_forensics"]
    if _sure(fo, "confirmed_risk"):
        s = min(100, s + sc["forensics_confirmed_bonus"])
        reasons.append(f"Supply-Chain Forensics confirmed it (+{sc['forensics_confirmed_bonus']})")
    elif _sure(fo, "likely_false_positive") and not x["malicious"]:
        s = max(0, s - sc["forensics_false_positive_penalty"])
        reasons.append(f"Supply-Chain Forensics judged it a likely false positive (-{sc['forensics_false_positive_penalty']})")
        c = min(c, float(fo["confidence"]))
    return {"score": s, "confidence": round(c, 2), "reasons": reasons}


def dim_blast(x: dict, r: dict) -> dict:
    br = r["blast_radius"]
    if x["repo_level"]:
        s, why = br["repo_level"], "repository-level: affects every build or deployment"
    elif x["direct"]:
        s, why = br["direct"], "direct dependency"
    else:
        n = x["introduced_by"]
        s = br["via_one"] if n <= 1 else br["via_two_or_three"] if n <= 3 else br["via_four_plus"]
        why = f"pulled in by {n} direct dependenc{'y' if n == 1 else 'ies'}"
    reasons = [why]
    if x["findings"] >= br["many_findings_bonus"]["min_findings"]:
        s += br["many_findings_bonus"]["value"]
        reasons.append(f"{x['findings']} findings on the same component (+{br['many_findings_bonus']['value']})")
    if x["projects"] > 1:
        s += br["multiple_projects_bonus"]
        reasons.append(f"used by {x['projects']} projects (+{br['multiple_projects_bonus']})")
    return {"score": min(100, s), "confidence": _conf("verified", r), "reasons": reasons}


# ----------------------------------------------------------------------------------------------- decision ---
def assess(x: dict, r: dict) -> dict:
    dims = {"threat": dim_threat(x, r), "production": dim_production(x, r), "business_loss": dim_business_loss(x, r),
            "supply_chain": dim_supply_chain(x, r), "blast_radius": dim_blast(x, r)}
    active = {k: v for k, v in dims.items() if v is not None}
    wsum = sum(r["weights"][k] for k in active)
    for k, v in active.items():
        v["weight"] = round(r["weights"][k] / wsum, 3)
        v["contribution"] = round(v["score"] * v["weight"], 1)
    score = sum(v["contribution"] for v in active.values())
    conf = sum(v["confidence"] * v["weight"] for v in active.values())
    adjustments, gates, flags = [], [], []

    lead = x["agents"]["lead_triage"]
    if lead and lead["delta"]:
        aa = r["agent_adjustment"]
        d = max(-aa["max"], min(aa["max"], lead["delta"] * aa["lead_factor"]))
        score += d
        adjustments.append(f"Lead triage moved the score {lead['delta']:+g} ({lead['reason']}); counted at half strength: {d:+.1f}")

    cr, cc = x["agents"]["critic"], r["confidence"]
    if cr and cr.get("agree") is False:
        conf += cc["critic_disagrees"]
        flags.append(f"Critic disagrees: {cr.get('concern') or 'no reason given'}")
    elif cr and cr.get("agree"):
        conf += cc["critic_agrees"]
    specs = [a for a in (x["agents"]["vulnerability_analyst"], x["agents"]["supply_chain_forensics"]) if a]
    if len({a.get("verdict") for a in specs}) > 1:
        conf += cc["specialists_conflict"]
        flags.append("the two specialists reached different verdicts")
    if x["scanners"] >= cc["scanner_consensus"]["min_scanners"]:
        conf += cc["scanner_consensus"]["value"]
        adjustments.append(f"confirmed by {x['scanners']} independent scanners (confidence +{cc['scanner_consensus']['value']})")

    g, b = r["gates"], x["business"]

    def gate(name: str, ok: bool, why: str) -> bool:
        """Apply one gate if its condition holds; returns whether it fired."""
        nonlocal score
        if not ok:
            return False
        spec, before = g[name], score
        if "min_score" in spec:
            score = max(score, spec["min_score"])
        if "max_score" in spec:
            score = min(score, spec["max_score"])
        gates.append({"gate": name, "priority": spec["priority"], "reason": why, "changed": round(before, 1) != round(score, 1),
                      "action": spec.get("action")})
        return True

    # these two are final: nothing after them can move the score
    stop = gate("human_dismissed", x["human_review"] == "dismissed", "a person dismissed it in `guardian review`")
    if not stop:
        stop = gate("confirmed_compromise", compromised(x),
                    "confirmed compromised artifact (malicious advisory, tampered hash, starjacking or forensics-confirmed look-alike)")
    if not stop:
        gate("kev_production_internet", x["kev"] and x["reachability"] in ("imported", "via-used-parent") and b["internet_facing"]
             and not x["dev_only"], "known-exploited, loaded in production, internet-facing")
        gate("regulated_data_breach", (x["cvss"] or 0) >= g["regulated_data_breach"]["min_cvss"]
             and bool(set(b["data"]) & set(g["regulated_data_breach"]["data"])) and b["internet_facing"]
             and x["reachability"] in REACHABLE and not x["dev_only"]
             and x["vector"].get("C") == "H",
             "high-severity confidentiality flaw in an internet-facing service holding card or credential data")
        gate("human_confirmed", x["human_review"] == "confirmed", "a person confirmed it in `guardian review`")
        if gate("suspected_lookalike", x["category"] == "1.3",
                "look-alike package name that is not confirmed: installs (and may run code) wherever it is declared"):
            flags.append("unconfirmed look-alike: a person or the Forensics agent (with evidence) must confirm or clear it")
        gate("agents_agree_false_positive", bool(specs) and all(_sure(a, "likely_false_positive") for a in specs)
             and not (cr and cr.get("agree") is False), "specialists agree it is a false positive and the critic did not object")
        gate("dev_only_unreachable", x["dev_only"] and x["reachability"] in ("not-imported", "via-unused-parent")
             and dims["supply_chain"] is None, "dev-only and never loaded, no supply-chain signal")

    if x["human_review"]:
        conf = cc["source_weight"]["human"]
    score = round(max(0.0, min(100.0, score)), 1)
    conf = round(max(0.05, min(0.99, conf)), 2)
    p, label = sym.band(score)
    clabel = next(l["label"] for l in cc["labels"] if conf >= l["min"])
    if clabel == "low":
        flags.append(f"low confidence ({conf}): the inputs behind this score are mostly assumptions")
    needs_review = clabel == "low" or any(f.startswith("unconfirmed look-alike") for f in flags)
    res = {"score": score, "priority": p, "priority_label": label, "confidence": conf, "confidence_label": clabel,
           "needs_review": needs_review,
           "dimensions": dims, "adjustments": adjustments, "gates": gates, "flags": flags,
           "actions": sorted({gt["action"] for gt in gates if gt.get("action")}),
           "previous": {"score": x["agent_score"], "priority": x["agent_priority"]}}
    res["explanation"], res["why"] = explain(x, res)
    return res


def explain(x: dict, res: dict) -> tuple[list[str], str]:
    dims = {k: v for k, v in res["dimensions"].items() if v}
    lines = [f"{x['headline']}",
             f"Score {res['score']} -> {res['priority']} ({res['priority_label']}), confidence {res['confidence']} "
             f"({res['confidence_label']}). Before: {res['previous']['priority']} ({res['previous']['score']})."]
    for k, v in sorted(dims.items(), key=lambda kv: -kv[1]["contribution"]):
        lines.append(f"{TITLE[k]}: {v['score']:g}/100 x {v['weight'] * 100:.0f}% = {v['contribution']:g}. " + "; ".join(v["reasons"]) + ".")
    lines += res["adjustments"]
    lines += [f"Gate {g['gate']} ({g['priority']}): {g['reason']}{'' if g['changed'] else ' (already satisfied)'}." for g in res["gates"]]
    lines += [f"Flag: {f}." for f in res["flags"]]
    changed = [g for g in res["gates"] if g["changed"]]
    move = ("unchanged at" if res["priority"] == res["previous"]["priority"] else
            "raised to" if res["priority"] < res["previous"]["priority"] else "lowered to")
    # raised / unchanged: name what pushes it up; lowered: name what holds it back
    lowered = move == "lowered to"
    picked = sorted(dims.items(), key=lambda kv: kv[1]["score"] if lowered else -kv[1]["contribution"])[:2]
    named = " and ".join(f"{TITLE[k].split(' (')[0].lower()} {v['score']:g} ({v['reasons'][0]})" for k, v in picked)
    if changed:
        return lines, f"{move} {res['priority']} mainly because of gate {changed[-1]['gate']}: {changed[-1]['reason']}."
    if lowered:
        return lines, f"{move} {res['priority']}: held back by {named}."
    return lines, f"{move} {res['priority']} mainly because of {named}."


def run(items: list[dict], doc: dict, intel: dict, ctx: dict, cases: dict, review: dict | None = None,
        rules_: dict | None = None, policy: dict | None = None, log=print) -> dict:
    """Re-prioritise every item in place; adds the prioritizer's entry to each agent case file."""
    r = rules_ or load_rules()
    pol = policy if policy is not None else (json.loads(POLICY_FILE.read_text(encoding="utf-8")) if POLICY_FILE.exists() else {})
    allow = set(pol.get("allowed_install_scripts", []))
    findings = {f["id"]: f for f in doc["findings"]}
    review = review or {}
    queue = []
    for it in items:
        x = gather(it, findings, intel, ctx, cases.get(it["id"]), review, allow)
        res = assess(x, r)
        res["inputs"] = {"agents": x["agents"], "business": {k: x["business"][k] for k in ("project", "internet_facing", "data")},
                         "human_review": x["human_review"]}
        it["agent_score"], it["agent_priority"] = it["score"], it["priority"]
        it["score"], it["priority"], it["priority_label"] = res["score"], res["priority"], res["priority_label"]
        it["neurosymbolic"] = res
        if it["id"] in cases:
            cases[it["id"]]["entries"].append({"agent": "neurosymbolic_prioritizer", "source": "rules", "status": "accepted",
                                               "provider": "config/neurosymbolic_rules.json", "verifier_notes": [],
                                               "output": {"priority": res["priority"], "final_score": res["score"],
                                                          "confidence": res["confidence"], "reason": res["why"]}})
            cases[it["id"]]["final"] = dict(cases[it["id"]].get("final") or {}, priority=res["priority"], score=res["score"],
                                            confidence=res["confidence"])
        low = res["confidence"] < r["confidence"]["review_below"] and res["priority"] in r["confidence"]["review_priorities"]
        if low or (res["needs_review"] and res["priority"] in r["confidence"]["review_priorities"]):
            queue.append({"id": it["id"], "headline": it["headline"],
                          "reason": "neurosymbolic prioritizer: " + "; ".join(res["flags"])})
    moved = [i for i in items if i["priority"] != i["agent_priority"]]
    summary = {"rules": r["schema"], "raised": sum(i["priority"] < i["agent_priority"] for i in moved),
               "lowered": sum(i["priority"] > i["agent_priority"] for i in moved),
               "confidence": {lab: sum(i["neurosymbolic"]["confidence_label"] == lab for i in items) for lab in ("high", "medium", "low")},
               "review": queue}
    log(f"[neurosymbolic] re-prioritised {len(items)} risks: raised {summary['raised']}, lowered {summary['lowered']}; "
        f"confidence {summary['confidence']}")
    return summary
