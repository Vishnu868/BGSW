"""Multi-agent analysis on a shared case file (blackboard).

  1. Lead routes every case to the specialist(s) it needs            (1 LLM call)
  2. Specialists investigate in parallel, with tools                 (<=5 steps each)
  3. Lead triages all cases at once from the specialists' verdicts   (1 LLM call)
  4. Critic reviews the high-impact cases independently              (<=3 steps)
  5. Disagreements and low confidence go to the human review queue
Every agent output passes the symbolic verifier; a rejected or missing answer falls back to rules.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from ..neurosymbolic import verifier
from . import roles
from .tools import Toolbox


def _case_view(item: dict) -> dict:
    return {k: item.get(k) for k in ("id", "headline", "category", "rule", "severity", "base_score", "base_priority",
                                     "factors", "reachability", "max_fixed", "component")}


def _specialist(agent, item, facts, router) -> dict:
    tb = Toolbox(facts, item)
    r = agent.run(router, _case_view(item), tb, purpose=item["id"])
    if r["output"] is None:
        out, notes, status, src = roles.rules_specialist(item), [r["error"] or "no LLM"], "fallback", "rules"
    else:
        out, notes, status = verifier.specialist(r["output"], r["evidence"], item, facts)
        src = "ai"
    out["source"] = src
    return {"agent": agent.name, "output": out, "verifier_notes": notes, "status": status, "steps": r["steps"],
            "provider": r["provider"], "evidence_ids": sorted(r["evidence"])}


def run(items: list[dict], facts, router, top: int = 6, workers: int = 2, log=print) -> dict:
    chosen = items[:top]
    extra = [i for i in items if i["category"] in ("1.3", "1.4", "1.6") and i["severity"] in ("critical", "high")
             and i not in chosen][:3]
    cases = chosen + extra
    board = {c["id"]: {"case": c["id"], "headline": c["headline"], "entries": []} for c in cases}

    # 1) routing by the lead
    view = [{"id": c["id"], "category": c["category"], "rule": c["rule"], "headline": c["headline"][:120],
             "priority": c["base_priority"]} for c in cases]
    r = roles.LEAD_ROUTE.run(router, {"cases": view}, Toolbox(facts, {}), purpose="route cases")
    raw = r["output"] if isinstance(r["output"], dict) else roles.rules_route([{**c, "priority": c["base_priority"]} for c in cases])
    routing, notes, status = verifier.routing(raw, [{**c, "priority": c["base_priority"]} for c in cases])
    src = "ai" if isinstance(r["output"], dict) else "rules"
    for c in cases:
        board[c["id"]]["entries"].append({"agent": "lead_router", "output": {"specialists": routing["routes"][c["id"]],
                                                                            "critic": c["id"] in routing["critic"]},
                                          "verifier_notes": notes, "status": status if src == "ai" else "fallback",
                                          "source": src, "provider": r["provider"]})
    log(f"[agents] lead routed {len(cases)} cases ({src}); critic on {len(routing['critic'])}")

    # 2) specialists in parallel
    jobs = [(c, roles.ALL[a]) for c in cases for a in routing["routes"][c["id"]]]
    with ThreadPoolExecutor(max(1, workers)) as ex:
        results = list(ex.map(lambda j: (j[0], _specialist(j[1], j[0], facts, router)), jobs))
    for c, res in results:
        board[c["id"]]["entries"].append(res)
        c.setdefault("specialist_verdicts", []).append(res)
        log(f"[agents] {res['agent']} -> {c['id']}: {res['output']['verdict']} ({res['output']['source']}, {res['status']})")

    # 3) triage by the lead (all cases in one call)
    tri_in = [{"id": c["id"], "headline": c["headline"][:120], "base_score": c["base_score"],
               "factors": c["factors"], "specialists": [{"agent": v["agent"], **{k: v["output"].get(k) for k in
                                                         ("verdict", "exploitable_in_context", "confidence", "risk_summary")}}
                                                        for v in c.get("specialist_verdicts", [])]} for c in cases]
    r = roles.LEAD_TRIAGE.run(router, {"cases": tri_in}, Toolbox(facts, {}), purpose="triage")
    raw = r["output"] if isinstance(r["output"], dict) else roles.rules_triage(cases)
    tri, tnotes, tstatus = verifier.triage(raw, cases)
    tsrc = "ai" if isinstance(r["output"], dict) else "rules"
    for c in cases:
        d = tri["decisions"][c["id"]]
        c["score"], c["priority"], c["priority_label"] = d["final_score"], d["priority"], d["priority_label"]
        c["triage_reason"] = d["reason"]
        board[c["id"]]["entries"].append({"agent": "lead_triage", "output": d, "verifier_notes": tnotes,
                                          "status": tstatus if tsrc == "ai" else "fallback", "source": tsrc,
                                          "provider": r["provider"]})

    # 4) critic on high-impact cases
    review_queue = []
    for c in cases:
        if c["id"] not in routing["critic"] and c["priority"] != "P1":
            continue
        ctx = {"item": _case_view(c), "verdicts": [{"agent": v["agent"], **v["output"]} for v in c.get("specialist_verdicts", [])],
               "final_priority": c["priority"], "triage_reason": c.get("triage_reason")}
        r = roles.CRITIC.run(router, ctx, Toolbox(facts, c), purpose=f"review {c['id']}")
        if isinstance(r["output"], dict):
            out, cnotes, cstatus = verifier.critic(r["output"], r["evidence"], {c["id"]})
            rev = next((x for x in out["reviews"] if x["id"] == c["id"]), {"id": c["id"], "agree": True, "concern": ""})
            csrc = "ai"
        else:
            rev, cnotes, cstatus, csrc = {"id": c["id"], "agree": True, "concern": "", "suggested_verdict": None}, [r["error"]], "fallback", "rules"
        board[c["id"]]["entries"].append({"agent": "critic", "output": rev, "verifier_notes": cnotes, "status": cstatus,
                                          "source": csrc, "provider": r["provider"], "steps": r["steps"]})
        c["critic"] = rev
        if not rev["agree"]:
            review_queue.append({"id": c["id"], "headline": c["headline"], "reason": f"critic disagrees: {rev['concern']}"})

    # 5) final verdict per case + review queue
    for c in cases:
        vs = c.get("specialist_verdicts", [])
        best = max(vs, key=lambda v: v["output"]["confidence"]) if vs else None
        c["ai"] = dict(best["output"], agent=best["agent"]) if best else None
        low = [v for v in vs if v["output"]["verdict"] == "needs_human_review"]
        if low and not any(q["id"] == c["id"] for q in review_queue):
            review_queue.append({"id": c["id"], "headline": c["headline"],
                                 "reason": "; ".join(f"{v['agent']}: low confidence ({v['output']['confidence']})" for v in low)})
        board[c["id"]]["final"] = {"priority": c["priority"], "score": c["score"],
                                   "verdict": c["ai"]["verdict"] if c["ai"] else None,
                                   "needs_review": any(q["id"] == c["id"] for q in review_queue)}
    return {"cases": board, "review_queue": review_queue, "summary": tri.get("summary"),
            "routing": routing, "agents": [{"id": i, "name": n, "roles": r} for i, n, r in roles.AGENTS]}
