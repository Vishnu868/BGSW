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
