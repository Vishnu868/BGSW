"""Human review queue: cases where agents disagree or are unsure. Non-blocking - decisions are recorded
(review.json + audit trail) and shown in the reports; they never apply changes."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from . import audit


def run(run_dir: Path, ask=input, log=print) -> dict:
    a = json.loads((run_dir / "analysis.json").read_text(encoding="utf-8"))
    f = run_dir / "review.json"
    decisions = json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}
    queue = [q for q in a.get("review_queue", []) if q["id"] not in decisions]
    if not queue:
        log("[review] nothing waiting for review")
        return decisions
    for q in queue:
        case = a["cases"].get(q["id"], {})
        log(f"\n{q['id']}  {q['headline']}\n  why: {q['reason']}")
        for e in case.get("entries", []):
            o = e["output"]
            log(f"  - {e['agent']}: {o.get('verdict') or o.get('priority') or ('agrees' if o.get('agree') else 'disagrees' if 'agree' in o else '')}"
                f" {o.get('risk_summary') or o.get('concern') or o.get('reason') or ''}"[:220])
        ans = ask("  [c]onfirm risk / [d]ismiss as false positive / [s]kip: ").strip().lower()[:1]
        if ans not in ("c", "d"):
            continue
        note = ask("  note (optional): ").strip()
        decisions[q["id"]] = {"decision": "confirmed" if ans == "c" else "dismissed", "note": note,
                              "operator": audit.operator(), "time": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        audit.log(run_dir / "audit.jsonl", "human_review", {"case": q["id"], **decisions[q["id"]]})
    f.write_text(json.dumps(decisions, indent=1), encoding="utf-8")
    log(f"[review] {len(decisions)} decision(s) recorded")
    return decisions


def business(run_dir: Path, ask=input, log=print) -> dict:
    """Show the business facts (rules + Business Context agent) and let a human confirm or reject each one.
    Rejected facts are ignored by the business-impact rules on the next `analyze`."""
    f = run_dir / "business_context.json"
    if not f.exists():
        log("[business] run `python -m guardian analyze <repo>` first")
        return {}
    ctx = json.loads(f.read_text(encoding="utf-8"))
    human = ctx.setdefault("human", {})
    fn = ctx.get("business_function") or {}
    log(f"Business function: {fn.get('value', '-')}  ({fn.get('evidence', '')})")
    if ctx.get("agent_function"):
        log(f"Agent's summary  : {ctx['agent_function']}")
    for fact in ctx.get("facts", []):
        key = f"{fact['fact']}:{fact['value']}:{fact['project']}"
        log(f"\n[{human.get(key, 'unreviewed')}] {fact['project']}: {fact['fact']} = {fact['value']}   ({fact['source']})")
        log(f"   evidence {fact['evidence']}: {fact['line']}")
        ans = ask("   [c]onfirm / [r]eject / [s]kip: ").strip().lower()[:1]
        if ans in ("c", "r"):
            human[key] = "confirmed" if ans == "c" else "rejected"
            audit.log(run_dir / "audit.jsonl", "business_fact_review", {"fact": key, "decision": human[key]})
    f.write_text(json.dumps(ctx, indent=1), encoding="utf-8")
    log("\n[business] saved. Re-run `python -m guardian analyze <repo>` to apply the decisions.")
    return ctx
