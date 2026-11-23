"""Symbolic verifier: every agent output is checked against facts and rules before anything uses it.

Outcome per output: accepted | corrected (fixed by a rule, with a note) | rejected (caller falls back to rules).
Checks: valid enums; cited evidence ids exist; CVEs mentioned exist in the gathered evidence; file:line references
exist; versions exist in the registry and are >= the fixed version; remediation actions are allow-listed with
required parameters; priority changes stay within the allowed bound; low confidence -> human review.
"""
from __future__ import annotations

import json
import re

from . import rules


def _common(out: dict, evidence: dict, notes: list) -> float:
    refs = [r for r in (out.get("evidence_refs") or []) if isinstance(r, str)]
    bad = [r for r in refs if r not in evidence]
    if bad:
        notes.append(f"removed citations to evidence that does not exist: {bad}")
    out["evidence_refs"] = [r for r in refs if r in evidence]
    try:
        conf = max(0.0, min(1.0, float(out.get("confidence") or 0)))
    except (TypeError, ValueError):
        conf = 0.0
    if not out["evidence_refs"]:
        conf = min(conf, 0.3)
        notes.append("no valid evidence cited -> confidence capped at 0.3")
    text = json.dumps(evidence, default=str)
    for cve in set(re.findall(r"CVE-\d{4}-\d+", json.dumps({k: v for k, v in out.items() if k != "evidence_refs"}, default=str))):
        if cve not in text:
            notes.append(f"{cve} is not in the gathered evidence -> flagged")
            conf = min(conf, 0.5)
    return conf


def specialist(out: dict, evidence: dict, item: dict, facts) -> tuple[dict, list, str]:
    """Vulnerability Analyst / Supply-Chain Forensics verdicts."""
    notes: list[str] = []
    out = {k: out.get(k) for k in ("verdict", "exploitable_in_context", "risk_summary", "recommended_action",
                                   "target_version", "confidence", "evidence_refs", "reasoning")}
    status = "accepted"
    if out["verdict"] not in rules.VERDICTS:
        notes.append(f"invalid verdict '{out['verdict']}' -> needs_human_review")
        out["verdict"], status = "needs_human_review", "corrected"
    if out["exploitable_in_context"] not in rules.EXPLOITABLE:
        out["exploitable_in_context"] = "unknown"
    if out["recommended_action"] not in rules.SPECIALIST_ACTIONS:
        notes.append(f"invalid action '{out['recommended_action']}' -> escalate")
        out["recommended_action"], status = "escalate", "corrected"
    conf = _common(out, evidence, notes)
    tv = out.get("target_version")
    if tv in ("null", "", "None", None):
        out["target_version"] = None
    else:
        cd = item.get("component") or {}
        ok, why = rules.version_ok(str(tv), item.get("max_fixed") or "", facts.versions(cd.get("name", ""), cd.get("ecosystem", "")))
        if not ok:
            notes.append(f"{why} -> removed (hallucination blocked)")
            out["target_version"], conf, status = None, min(conf, 0.5), "corrected"
    for ref in re.findall(r"[\w./-]+\.(?:js|ts|py|json|yml|yaml|Dockerfile):\d+", out.get("reasoning") or ""):
        if not facts.file_line_exists(ref):
            notes.append(f"file reference {ref} does not exist -> flagged")
            conf = min(conf, 0.5)
    out["confidence"] = round(conf, 2)
    if conf < rules.REVIEW_CONFIDENCE and out["verdict"] != "needs_human_review":
        notes.append(f"confidence {conf:.2f} < {rules.REVIEW_CONFIDENCE} -> human review")
        out["verdict"], status = "needs_human_review", "corrected"
    if notes and status == "accepted":
        status = "corrected"
    return out, notes, status


def routing(out: dict, cases: list[dict]) -> tuple[dict, list, str]:
    """Lead agent's routing: CVE items must reach the Vulnerability Analyst, other items Supply-Chain Forensics;
    every P1 item gets the Critic."""
    notes, status = [], "accepted"
    ids = {c["id"]: c for c in cases}
    routes = out.get("routes") if isinstance(out.get("routes"), dict) else {}
    fixed = {}
    for cid, c in ids.items():
        want = [a for a in (routes.get(cid) or []) if a in ("vulnerability_analyst", "supply_chain_forensics")]
        need = "vulnerability_analyst" if c["category"] in ("1.1", "1.2") else "supply_chain_forensics"
        if need not in want:
            want.append(need)
            if routes:
                notes.append(f"{cid}: added required specialist {need}")
                status = "corrected"
        fixed[cid] = want
    critic = {x for x in (out.get("critic") or []) if x in ids}
    for cid, c in ids.items():
        if c["priority"] == "P1" and cid not in critic:
            critic.add(cid)
    return {"routes": fixed, "critic": sorted(critic)}, notes, status


def triage(out: dict, cases: list[dict]) -> tuple[dict, list, str]:
    """Lead agent's final priorities: score may move at most MAX_SCORE_ADJUST from the symbolic score, priority is
    recomputed from the score (never free text), and every change needs a reason."""
    notes, status = [], "accepted"
    given = {d.get("id"): d for d in (out.get("decisions") or []) if isinstance(d, dict)}
    res = {}
    for c in cases:
        d = given.get(c["id"], {})
        base = float(c["base_score"])
        try:
            s = float(d.get("final_score", base))
        except (TypeError, ValueError):
            s = base
        if abs(s - base) > rules.MAX_SCORE_ADJUST:
            notes.append(f"{c['id']}: score change {s - base:+.0f} exceeds ±{rules.MAX_SCORE_ADJUST} -> clamped")
            s = base + (rules.MAX_SCORE_ADJUST if s > base else -rules.MAX_SCORE_ADJUST)
            status = "corrected"
        if s != base and not d.get("reason"):
            notes.append(f"{c['id']}: score change without a reason -> reverted")
            s, status = base, "corrected"
        s = max(0.0, min(100.0, s))
        p, label = rules.band(s)
        res[c["id"]] = {"final_score": round(s, 1), "priority": p, "priority_label": label,
                        "reason": d.get("reason") or "symbolic score kept"}
    return {"decisions": res, "summary": out.get("summary")}, notes, status


def plan_proposal(out: dict, evidence: dict, item: dict, facts, repo_files: set) -> tuple[dict, list, str]:
    """Remediation Planner: allow-listed action, required parameters, real versions >= fixed, files exist."""
    notes: list[str] = []
    t = out.get("action_type")
    if t not in rules.REMEDIATION_ACTIONS:
        return out, [f"action '{t}' is not on the allow-list -> rejected"], "rejected"
    p = out.get("params") if isinstance(out.get("params"), dict) else {}
    missing = [k for k in rules.REQUIRED_PARAMS[t] if not p.get(k)]
    if missing:
        return out, [f"missing required parameters {missing} -> rejected"], "rejected"
    cd = item.get("component") or {}
    eco = cd.get("ecosystem", "npm")
    if t in ("npm_upgrade_direct", "npm_override_transitive", "pypi_upgrade"):
        ok, why = rules.version_ok(str(p["to"]), item.get("max_fixed") or "", facts.versions(p["package"], eco))
        if not ok:
            return out, [f"{why} -> rejected (hallucination blocked)"], "rejected"
    if t == "npm_replace":
        vs = facts.versions(p["with"], "npm")
        if vs is not None and str(p["version"]) not in vs:
            return out, [f"{p['with']}@{p['version']} does not exist -> rejected"], "rejected"
    for m in p.get("manifests", []) or []:
        if m not in repo_files:
            return out, [f"manifest {m} not in repository -> rejected"], "rejected"
    conf = _common(out, evidence, notes)
    out["confidence"] = round(conf, 2)
    return out, notes, "corrected" if notes else "accepted"


def critic(out: dict, evidence: dict, valid_ids: set) -> tuple[dict, list, str]:
    notes = []
    reviews = []
    for r in out.get("reviews") or []:
        if isinstance(r, dict) and r.get("id") in valid_ids:
            reviews.append({"id": r["id"], "agree": bool(r.get("agree", True)), "concern": str(r.get("concern") or "")[:400],
                            "suggested_verdict": r.get("suggested_verdict") if r.get("suggested_verdict") in rules.VERDICTS else None})
        elif isinstance(r, dict):
            notes.append(f"review for unknown id {r.get('id')} dropped")
    if evidence:
        _common(out, evidence, notes)
    return {"reviews": reviews}, notes, "corrected" if notes else "accepted"
