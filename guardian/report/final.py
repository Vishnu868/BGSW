"""Final Guardian report: original finding + evidence -> AI analysis (labelled inference) -> approved action
-> build/test -> before/after -> remaining/accepted risk -> confidence -> audit trail.
Writes runs/<repo>/guardian_report.json, .txt and .html."""
from __future__ import annotations

import html
import json
from pathlib import Path

from .. import audit


def _load(p: Path):
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def build(run_dir: Path, log=print) -> dict:
    findings = _load(run_dir / "findings.json")
    analysis = _load(run_dir / "analysis.json") or {}
    plan = _load(run_dir / "plan.json") or {"actions": []}
    approval = _load(run_dir / "approval.json") or {}
    applied = _load(run_dir / "apply.json") or {}
    val = _load(run_dir / "validation.json") or {}
    by_f = {f["id"]: f for f in findings["findings"]}
    items = {i["id"]: i for i in analysis.get("items", [])}
    cases = analysis.get("cases", {})
    review = _load(run_dir / "review.json") or {}
    res_by = {r["id"]: r for r in applied.get("results", [])}
    val_by = {v["id"]: v for v in val.get("per_action", [])}
    stories = []
    for a in plan["actions"]:
        item = items.get(a["risk_item"], {})
        f0 = by_f.get(a["finding_ids"][0]) if a["finding_ids"] else None
        stories.append({
            "action": a["id"], "risk_item": a["risk_item"], "risk": a["risk"], "priority": a["priority"],
            "score": a["score"], "score_factors": item.get("factors"),
            "original_finding": {"id": f0["id"], "title": f0["title"], "evidence": f0["evidence"],
                                 "dependency_path": (f0.get("component_detail") or {}).get("dependency_path")} if f0 else None,
            "verified_evidence": "deterministic (scanner, registry, advisory data)",
            "ai_inference": item.get("ai"),
            "agents": [{"agent": e["agent"], "source": e.get("source", "ai"), "status": e["status"],
                        "summary": (e["output"].get("risk_summary") or e["output"].get("reason") or e["output"].get("concern")
                                    or (", ".join(e["output"].get("specialists", [])) if e["output"].get("specialists") else "")),
                        "verdict": e["output"].get("verdict") or e["output"].get("priority") or
                                   ("agrees" if e["output"].get("agree") else "disagrees" if "agree" in e["output"] else "")}
                       for e in (cases.get(a["risk_item"]) or {}).get("entries", [])],
            "ai_steps": [st for e in (cases.get(a["risk_item"]) or {}).get("entries", []) for st in (e.get("steps") or [])],
            "ai_checker_notes": [n for e in (cases.get(a["risk_item"]) or {}).get("entries", []) for n in (e.get("verifier_notes") or []) if n],
            "planner_agent": a.get("planner"), "critic": a.get("critic"),
            "human_review": review.get(a["risk_item"]),
            "business": item.get("business"),
            "neurosymbolic": ({k: item["neurosymbolic"][k] for k in ("score", "priority", "confidence", "confidence_label",
                                                                     "why", "explanation")} if item.get("neurosymbolic") else None),
            "scanners": (f0 or {}).get("data", {}).get("scanners"),
            "applicable_scanners": (f0 or {}).get("data", {}).get("applicable_scanners"),
            "recommended_action": {"type": a["type"], "params": a["params"], "rationale": a["rationale"],
                                   "compatibility": a["compatibility"], "rollback": a["rollback"]},
            "approval": ("approved" if a["id"] in approval.get("approved_actions", []) else
                         "rejected" if approval else "pending"),
            "applied": res_by.get(a["id"]), "validation": val_by.get(a["id"]),
        })
    accepted = [{"id": i["id"], "risk": i["headline"], "priority": i["priority"], "score": i["score"],
                 "reason": "P3/P4 - accepted for now, monitored on every scan"}
                for i in analysis.get("items", []) if i["priority"] in ("P3", "P4")]
    remaining_high = [i for i in analysis.get("items", []) if i["priority"] in ("P1", "P2") and
                      not any(i["id"] == a["risk_item"] for a in plan["actions"])]
    conf = {"verified": "high", "partial": "medium", "failed": "low"}.get(val.get("verdict"), "not validated")
    rep = {"schema": "guardian.report/v1", "repository": findings["repository"]["repo"],
           "scanned_at": findings["repository"]["scanned_at"], "inventory": findings["summary"],
           "llm": analysis.get("llm"), "executive_summary": analysis.get("summary"),
           "priorities": analysis.get("counts"), "plan_hash": plan.get("plan_hash"), "approval": approval,
           "sandbox_branch": applied.get("branch"), "validation_verdict": val.get("verdict"),
           "checks": val.get("checks"), "before": val.get("before"), "after": val.get("after"),
           "new_findings_after_fix": val.get("new_findings"), "sbom_changes": val.get("sbom_changes"),
           "stories": stories, "agents": analysis.get("agents"), "review_queue": analysis.get("review_queue"),
           "review_decisions": review, "next_iteration": val.get("next_iteration"), "remaining_unplanned_high_risk": [{"id": i["id"], "risk": i["headline"]} for i in remaining_high],
           "accepted_risk": accepted, "final_confidence": conf,
           "audit_trail": audit.read(run_dir / "audit.jsonl")}
    (run_dir / "guardian_report.json").write_text(json.dumps(rep, indent=1, default=str), encoding="utf-8")
    (run_dir / "guardian_report.txt").write_text(markdown(rep), encoding="utf-8")
    (run_dir / "guardian_report.html").write_text(page(rep), encoding="utf-8")
    log(f"[report] {run_dir / 'guardian_report.html'}")
    return rep


def markdown(r: dict) -> str:
    L = [f"# Guardian report - {r['repository']}", "", f"Validation: **{r['validation_verdict'] or 'not run'}** · "
         f"final confidence: {r['final_confidence']} · LLM: {r['llm']}", ""]
    if r.get("executive_summary"):
        L += ["## Summary", "", r["executive_summary"].get("summary", ""), ""]
    if r.get("before"):
        L += ["## Before / after", "", "| | components | findings | critical | high |", "|---|---|---|---|---|",
              f"| before | {r['before']['components']} | {r['before']['findings']} | {r['before']['by_severity']['critical']} | {r['before']['by_severity']['high']} |",
              f"| after | {r['after']['components']} | {r['after']['findings']} | {r['after']['by_severity']['critical']} | {r['after']['by_severity']['high']} |", ""]
    L += ["## Finding -> action -> verified result", ""]
    for s in r["stories"]:
        ra = s["recommended_action"]
        L += [f"### {s['action']} {ra['type']} - {s['risk'][:90]}", "",
              f"- Priority {s['priority']} (score {s['score']}); approval: **{s['approval']}**",
              f"- Evidence: " + "; ".join(e["detail"] for e in (s["original_finding"] or {}).get("evidence", [])[:3]),
              f"- Action: {ra['rationale']}", f"- Compatibility: {ra['compatibility']['reason']} · Rollback: {ra['rollback']}"]
        if s.get("ai_inference"):
            L.append(f"- {'AI inference' if s['ai_inference'].get('source') == 'ai' else 'Rule-based analysis'} ({s['ai_inference'].get('source')}, confidence {s['ai_inference'].get('confidence')}): "
                     f"{s['ai_inference'].get('risk_summary')}")
        if s.get("neurosymbolic"):
            n = s["neurosymbolic"]
            L.append(f"- Neurosymbolic prioritizer: {n['priority']} (score {n['score']}, confidence {n['confidence']} "
                     f"{n['confidence_label']}) - {n['why']}")
        if s.get("business"):
            b = s["business"]
            L.append(f"- Business (SSVC): {b['decision']} ({b['points']:+d}) - {b['reason']}; exposure {b['exposure']}, "
                     f"human impact {b['human_impact']}, exploitation {b['exploitation']}")
        if s.get("scanners"):
            L.append(f"- Scanners: confirmed by {len(s['scanners'])} of {len(s.get('applicable_scanners') or [])} "
                     f"({', '.join(s['scanners'])})")
        for ag in s.get("agents") or []:
            L.append(f"- Agent {ag['agent']} ({ag['source']}, {ag['status']}): {ag['verdict']} {ag['summary'][:160]}")
        if s.get("critic"):
            L.append(f"- Critic on the plan: {'agrees' if s['critic']['agree'] else 'DISAGREES'} {s['critic'].get('concern', '')}")
        if s.get("applied"):
            L.append(f"- Applied: {s['applied']['status']} - {s['applied']['detail']}")
        if s.get("validation"):
            L.append(f"- Validation: {s['validation']['status']} ({s['validation']['resolved']}/{s['validation']['targeted']} findings resolved)")
        L.append("")
    if r.get("next_iteration"):
        L += ["## Next iteration (proposed, needs a new approval)", ""] + [
            f"- {n['params']['package']} {n['params'].get('from', '')} -> {n['params']['to']}: {n['rationale']} ({n['source']})"
            for n in r["next_iteration"]] + [""]
    L += ["## Remaining / accepted risk", "", f"{len(r['accepted_risk'])} lower-priority items accepted and monitored; "
          f"{len(r['remaining_unplanned_high_risk'])} high-priority items still need a decision.", "",
          "## Audit trail", ""] + [f"- {e['time']} {e['event']} ({e['operator']})" for e in r["audit_trail"]]
    return "\n".join(L) + "\n"


def page(r: dict) -> str:
    e = html.escape
    def sev_row(label, d):
        return (f"<tr><td>{label}</td><td>{d['components']}</td><td>{d['findings']}</td>"
                f"<td>{d['by_severity']['critical']}</td><td>{d['by_severity']['high']}</td><td>{d['by_severity']['medium']}</td></tr>")
    ba = ("<table><tr><th></th><th>components</th><th>findings</th><th>critical</th><th>high</th><th>medium</th></tr>"
          + sev_row("before", r["before"]) + sev_row("after", r["after"]) + "</table>") if r.get("before") else "<p class=m>Validation not run yet.</p>"
    cards = []
    for s in r["stories"]:
        ra, of, ai = s["recommended_action"], s["original_finding"] or {}, s.get("ai_inference")
        st = (s.get("validation") or {}).get("status", s["approval"])
        cards.append(f"""<div class=card><div class=hd><span class="pill {e(s['priority'])}">{e(s['priority'])}</span>
<b>{e(s['action'])} · {e(ra['type'])}</b> <span class="st {e(st.split()[0])}">{e(st)}</span></div>
<div class=t>{e(s['risk'])}</div>
<div class=row><div><h4>1 · Verified evidence</h4>{''.join(f'<div class=ev><b>{e(x["source"].split("/")[-1] if x["source"].startswith("http") else x["source"])}</b>: {e(x["detail"])}</div>' for x in of.get('evidence', [])[:4])}
{f"<div class=ev><b>scanners</b>: {len(s['scanners'])} of {len(s.get('applicable_scanners') or [])} ({e(', '.join(s['scanners']))})</div>" if s.get('scanners') else ''}
{f"<div class=ev><b>business (SSVC)</b>: {e(s['business']['decision'])} - {e(s['business']['reason'])}</div>" if s.get('business') else ''}
<div class=ev><b>path</b>: {e(' → '.join(of.get('dependency_path') or []))}</div></div>
<div><h4>2 · {'AI analysis <span class=m>(inference, checked)</span>' if ai and ai.get('source') == 'ai' else 'Analysis <span class=m>(rule-based, no AI)</span>'}</h4>{f"<div class=ev>{e(str(ai.get('risk_summary')))}</div><div class=ev>verdict <b>{e(str(ai.get('verdict')))}</b> · confidence {e(str(ai.get('confidence')))} · source {e(str(ai.get('source')))}</div>" if ai else '<div class=m>not investigated</div>'}
{''.join(f'<div class=ev><b>{e(ag["agent"])}</b> ({e(ag["source"])}, {e(ag["status"])}): {e(str(ag["verdict"]))} {e(str(ag["summary"])[:140])}</div>' for ag in (s.get('agents') or []))}
{''.join(f'<div class=ev>verifier: {e(n)}</div>' for n in (s.get('ai_checker_notes') or [])[:4])}
{f"<div class=ev><b>critic on plan</b>: {'agrees' if s['critic']['agree'] else 'DISAGREES'} {e(s['critic'].get('concern', ''))}</div>" if s.get('critic') else ''}</div>
<div><h4>3 · Action &amp; approval</h4><div class=ev>{e(ra['rationale'])}</div><div class=ev><b>compat</b>: {e(ra['compatibility']['reason'])}</div>
<div class=ev><b>rollback</b>: {e(ra['rollback'])}</div><div class=ev><b>approval</b>: {e(s['approval'])}</div></div>
<div><h4>4 · Result</h4><div class=ev>{e((s.get('applied') or {}).get('detail', 'not applied'))}</div>
<div class=ev>{e(str((s.get('validation') or {}).get('resolved', '-')))} / {e(str((s.get('validation') or {}).get('targeted', '-')))} targeted findings resolved</div></div></div></div>""")
    trail = "".join(f"<tr><td>{e(x['time'])}</td><td>{e(x['event'])}</td><td>{e(x['operator'])}</td>"
                    f"<td class=m>{e(json.dumps({k: v for k, v in x.items() if k not in ('time', 'event', 'operator')}, default=str)[:160])}</td></tr>"
                    for x in r["audit_trail"])
    summ = (r.get("executive_summary") or {}).get("summary", "")
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Guardian report - {e(r['repository'])}</title><style>
:root{{--bg:#f6f7f9;--p:#fff;--i:#16202c;--m:#5b6876;--l:#dfe3e8;--a:#1f4e9c}}
@media (prefers-color-scheme:dark){{:root:not([data-theme=light]){{--bg:#0f141a;--p:#171e26;--i:#e6ebf0;--m:#9aa8b6;--l:#2a3440;--a:#7fb0ff}}}}
:root[data-theme=dark]{{--bg:#0f141a;--p:#171e26;--i:#e6ebf0;--m:#9aa8b6;--l:#2a3440;--a:#7fb0ff}}
body{{margin:0;padding:20px 16px;background:var(--bg);color:var(--i);font:14px/1.5 system-ui,Segoe UI,sans-serif}}
h1{{font-size:21px;margin:0 0 4px}}h2{{font-size:16px;margin:24px 0 8px}}h4{{margin:0 0 6px;font-size:12px;color:var(--m);text-transform:uppercase}}
.m{{color:var(--m)}}table{{border-collapse:collapse;background:var(--p);border:1px solid var(--l);width:100%}}
td,th{{padding:6px 10px;border-bottom:1px solid var(--l);text-align:left;font-size:13px;word-break:break-word}}
.card{{background:var(--p);border:1px solid var(--l);border-radius:10px;padding:12px;margin:10px 0}}
.hd{{display:flex;gap:8px;align-items:center;flex-wrap:wrap}}.t{{margin:4px 0 10px}}
.row{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}}
.ev{{font-size:12.5px;margin:3px 0;word-break:break-word}}
.pill{{font-size:11px;font-weight:700;padding:1px 8px;border-radius:999px;color:#fff;background:#7d93ab}}.P1{{background:#9e0f2e}}.P2{{background:#d9432b}}
.st{{font-size:12px;padding:1px 8px;border-radius:6px;border:1px solid var(--l)}}.verified{{color:#1f7a3a;border-color:#1f7a3a}}.partial{{color:#b77700}}.not{{color:#9e0f2e}}
.verdict{{font-size:18px;font-weight:700}}</style></head><body>
<h1>Guardian report · {e(r['repository'])}</h1>
<div class=m>scanned {e(r['scanned_at'])} · LLM {e(str(r['llm']))} · plan {e(str(r.get('plan_hash') or '')[:12])}</div>
<p class=verdict>Validation: {e(str(r['validation_verdict'] or 'not run'))} · final confidence {e(r['final_confidence'])}</p>
<p>{e(summ)}</p>
<h2>Before / after</h2>{ba}
<h2>From finding to verified remediation</h2>{''.join(cards) or '<p class=m>No plan yet.</p>'}
{('<h2>Next iteration (proposed, needs a new approval)</h2><ul>' + ''.join(f"<li>{e(n['params']['package'])} {e(n['params'].get('from', ''))} → {e(n['params']['to'])}: {e(n['rationale'])} <span class=m>({e(n['source'])})</span></li>" for n in r['next_iteration']) + '</ul>') if r.get('next_iteration') else ''}
<h2>Agents</h2><p>{' · '.join(e(a['id'] + ' ' + a['name']) for a in (r.get('agents') or []))}</p>
<h2>Remaining and accepted risk</h2><p>{len(r['accepted_risk'])} P3/P4 items accepted and monitored on every scan; {len(r['remaining_unplanned_high_risk'])} P1/P2 items still need a decision.</p>
<h2>Audit trail</h2><table><tr><th>time</th><th>event</th><th>operator</th><th>details</th></tr>{trail}</table>
<p class=m>Evidence sections are deterministic; "AI analysis" is model inference checked against that evidence. Every change was applied in a sandbox only after explicit human approval.</p>
</body></html>"""
