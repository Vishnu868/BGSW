"""Stage 3 - Analyze & prioritise: context (reachability, exploitability, exposure) + AI investigation.

Input : runs/<repo>/findings.json (from `guardian scan`)
Output: runs/<repo>/analysis.json, analysis.md
"""
from __future__ import annotations

import json
from pathlib import Path

from .. import audit
from ..llm import Router
from . import agent, intel, prioritize, reachability

SUMMARY_SYSTEM = """You write the executive summary of a software supply chain risk review for engineering leads.
Use only the data given. Be specific (package names, versions, priorities). 4-6 sentences.
Return JSON: {"summary": "...", "top_actions": ["...", "...", "..."]}"""


def run(run_dir: Path, top: int = 6, offline: bool = False, log=print) -> dict:
    doc = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    repo = Path(doc["repository"]["path"])
    trail = run_dir / "audit.jsonl"
    router = Router(audit=trail)
    audit.log(trail, "analyze_start", {"llm": router.describe()})
    log(f"[analyze] LLM chain: {router.describe()}")

    log("[analyze] reachability: searching application source for imports")
    reach = reachability.analyse(doc, repo)
    cves = sorted({f["data"].get("cve") for f in doc["findings"] if f["data"].get("cve")})
    log(f"[analyze] exploit intelligence for {len(cves)} CVEs (EPSS + CISA KEV)")
    kev = intel.kev(offline)
    epss = intel.epss(cves, offline)
    items = prioritize.build_items(doc, reach, kev, epss)

    chosen = items[:top]
    supply_chain = [i for i in items if (i["category"] in ("1.3", "1.4", "1.6") and i["severity"] in ("critical", "high"))
                    and i not in chosen][:3]
    investigations = []
    for it in chosen + supply_chain:
        log(f"[analyze] investigating {it['id']} {it['headline'][:70]}")
        inv = agent.investigate(it, doc, reach, {"kev": kev, "epss": epss}, repo, router, offline)
        it["ai"] = inv["result"]
        investigations.append(inv)

    summary, meta = (None, {"provider": "rules"})
    if router.enabled:
        brief = [{k: i[k] for k in ("id", "headline", "priority", "score", "confidence")} |
                 {"verdict": i.get("ai", {}).get("verdict"), "action": i.get("ai", {}).get("recommended_action")}
                 for i in items[:12]]
        summary, meta = router.ask_json(SUMMARY_SYSTEM, json.dumps({"repo": doc["repository"]["repo"],
                                                                    "summary": doc["summary"], "top_items": brief}),
                                        purpose="executive summary")
    if not summary:
        p = {k: sum(i["priority"] == k for i in items) for k in ("P1", "P2", "P3", "P4")}
        summary = {"summary": f"{len(items)} risk items: {p['P1']} P1 (fix now), {p['P2']} P2, {p['P3']} P3, {p['P4']} P4. "
                              f"Top item: {items[0]['headline'] if items else 'none'}.",
                   "top_actions": [f"{i['id']}: {i['recommendation']}" for i in items[:3]]}
    out = {"schema": "guardian.analysis/v1", "repository": doc["repository"]["repo"], "repo_path": str(repo),
           "llm": router.describe(), "summary": summary, "summary_source": meta.get("provider"),
           "reachability_files": reach.get("_meta", {}).get("source_files", 0),
           "counts": {k: sum(i["priority"] == k for i in items) for k in ("P1", "P2", "P3", "P4")},
           "items": items, "investigations": investigations, "llm_calls": router.calls}
    (run_dir / "analysis.json").write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    (run_dir / "analysis.md").write_text(markdown(out), encoding="utf-8")
    audit.log(trail, "analyze_done", {"items": len(items), "investigated": len(investigations), "counts": out["counts"]})
    log(f"[analyze] {len(items)} risk items -> {out['counts']}; investigated {len(investigations)}")
    return out


def markdown(a: dict) -> str:
    L = [f"# Risk analysis - {a['repository']}", "", f"LLM: {a['llm']}", "", "## Summary", "",
         a["summary"].get("summary", ""), ""]
    if a["summary"].get("top_actions"):
        L += [f"- {x}" for x in a["summary"]["top_actions"]] + [""]
    L += [f"*Summary source: {a['summary_source']}. AI text is inference; the evidence below is verified.*", "",
          "## Prioritised risks", "", "| Rank | Priority | Score | Risk | Reachability | Confidence | AI verdict |",
          "|---|---|---|---|---|---|---|"]
    for i in a["items"][:30]:
        ai = i.get("ai") or {}
        L.append(f"| {i['rank']} | {i['priority']} | {i['score']} | {i['headline'][:80].replace('|', '/')} | "
                 f"{i['reachability']['status']} | {i['confidence']} | {ai.get('verdict', '-')} |")
    L += ["", "## Investigations", ""]
    for inv in a["investigations"]:
        r = inv["result"]
        L += [f"### {inv['item']} ({inv['provider']})", "",
              f"- verdict **{r.get('verdict')}**, exploitable in context: {r.get('exploitable_in_context')}, "
              f"confidence {r.get('confidence')}",
              f"- action: {r.get('recommended_action')} {r.get('target_version') or ''}",
              f"- {r.get('risk_summary')}"]
        L += [f"- step {s['step']}: `{s['tool']}({json.dumps(s['args'])})` -> {s['evidence_id']} - {s['why']}" for s in inv["steps"]]
        L += [f"- checker: {n}" for n in inv.get("checker_notes", [])] + [""]
    return "\n".join(L) + "\n"
