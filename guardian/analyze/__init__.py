"""Stage 3 - Analyze & prioritise (neurosymbolic, multi-agent).

  symbolic prior : reachability (imports), EPSS + CISA KEV, explainable base score -> P1..P4
  agents         : Orchestrator & Triage lead, Vulnerability Analyst, Supply-Chain Forensics, Critic
  verifier       : every agent answer checked against facts and rules (guardian/neurosymbolic)
Input : runs/<repo>/findings.json      Output: analysis.json, analysis.md, guardian.html (with agent verdicts)
"""
from __future__ import annotations

import json
from pathlib import Path

from .. import audit
from ..agents import orchestrator
from ..llm import Router
from ..neurosymbolic.facts import Facts
from . import intel, prioritize, reachability


def run(run_dir: Path, top: int = 6, offline: bool = False, log=print) -> dict:
    doc = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    repo = Path(doc["repository"]["path"])
    trail = run_dir / "audit.jsonl"
    router = Router(audit=trail)
    audit.log(trail, "analyze_start", {"llm": router.describe()})
    log(f"[analyze] LLM chain: {router.describe()}")

    log("[analyze] symbolic prior: reachability, EPSS + CISA KEV, base scores")
    reach = reachability.analyse(doc, repo)
    cves = sorted({f["data"].get("cve") for f in doc["findings"] if f["data"].get("cve")})
    kev = intel.kev(offline)
    epss = intel.epss(cves, offline)
    items = prioritize.build_items(doc, reach, kev, epss)
    facts = Facts(doc, offline, {"kev": kev, "epss": epss})

    log(f"[analyze] multi-agent investigation of the top {top} risks (+ high supply-chain risks)")
    agents = orchestrator.run(items, facts, router, top=top, log=log)
    items.sort(key=lambda i: (-i["score"], i["headline"]))
    for n, it in enumerate(items, 1):
        it["rank"] = n

    summary = agents.get("summary")
    if summary:
        summary = {"summary": summary, "top_actions": [f"{i['id']}: {i['recommendation']}" for i in items[:3]]}
        source = "ai (lead agent)"
    else:
        p = {k: sum(i["priority"] == k for i in items) for k in ("P1", "P2", "P3", "P4")}
        summary = {"summary": f"{len(items)} risk items: {p['P1']} P1 (fix now), {p['P2']} P2, {p['P3']} P3, {p['P4']} P4. "
                              f"Top item: {items[0]['headline'] if items else 'none'}.",
                   "top_actions": [f"{i['id']}: {i['recommendation']}" for i in items[:3]]}
        source = "rules"
    out = {"schema": "guardian.analysis/v2", "repository": doc["repository"]["repo"], "repo_path": str(repo),
           "llm": router.describe(), "summary": summary, "summary_source": source,
           "reachability_files": reach.get("_meta", {}).get("source_files", 0),
           "counts": {k: sum(i["priority"] == k for i in items) for k in ("P1", "P2", "P3", "P4")},
           "agents": agents["agents"], "routing": agents["routing"], "cases": agents["cases"],
           "review_queue": agents["review_queue"], "items": items, "llm_calls": router.calls}
    (run_dir / "analysis.json").write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    (run_dir / "analysis.md").write_text(markdown(out), encoding="utf-8")
    _refresh_graph_page(run_dir, out)
    audit.log(trail, "analyze_done", {"items": len(items), "cases": len(agents["cases"]), "counts": out["counts"],
                                      "review_queue": len(agents["review_queue"])})
    log(f"[analyze] {len(items)} risk items -> {out['counts']}; {len(agents['cases'])} agent cases; "
        f"{len(agents['review_queue'])} need human review")
    return out


def _refresh_graph_page(run_dir: Path, analysis: dict) -> None:
    from ..report import html
    data_f = run_dir / "graph_data.json"
    if data_f.exists():
        data = json.loads(data_f.read_text(encoding="utf-8"))
        data["analysis"] = html.analysis_view(analysis)
        (run_dir / "guardian.html").write_text(html.render(data), encoding="utf-8")


def markdown(a: dict) -> str:
    L = [f"# Risk analysis - {a['repository']}", "", f"LLM: {a['llm']}", "",
         "Agents: " + " · ".join(f"{x['id']} {x['name']}" for x in a["agents"]), "", "## Summary", "",
         a["summary"].get("summary", ""), ""]
    L += [f"- {x}" for x in a["summary"].get("top_actions", [])] + ["",
          f"*Summary source: {a['summary_source']}. AI text is inference; evidence is verified.*", "",
          "## Prioritised risks", "", "| Rank | Priority | Score (base) | Risk | Reachability | Verdict | Agent |",
          "|---|---|---|---|---|---|---|"]
    for i in a["items"][:30]:
        ai = i.get("ai") or {}
        L.append(f"| {i['rank']} | {i['priority']} | {i['score']} ({i['base_score']}) | {i['headline'][:70].replace('|', '/')} | "
                 f"{i['reachability']['status']} | {ai.get('verdict', '-')} | {ai.get('agent', '-')} ({ai.get('source', '-')}) |")
    L += ["", "## Needs human review", ""]
    L += [f"- {q['id']}: {q['headline'][:80]} - {q['reason']}" for q in a["review_queue"]] or ["- none"]
    L += ["", "## Agent case files", ""]
    for cid, case in a["cases"].items():
        L += [f"### {cid} {case['headline'][:90]}", ""]
        for e in case["entries"]:
            o = e["output"]
            what = (o.get("verdict") or o.get("priority") or ("agree" if o.get("agree") else "disagree" if "agree" in o else "")
                    or json.dumps(o)[:80])
            L.append(f"- **{e['agent']}** ({e.get('source', 'ai')}, {e['status']}): {what}"
                     + (f" - {o.get('risk_summary') or o.get('reason') or o.get('concern') or ''}"[:300]))
            for s in e.get("steps") or []:
                L.append(f"  - step {s['step']}: `{s['tool']}({json.dumps(s['args'])})` -> {s['evidence_id']} {s['why']}")
            for n in e.get("verifier_notes") or []:
                L.append(f"  - verifier: {n}")
        L.append("")
    return "\n".join(L) + "\n"
