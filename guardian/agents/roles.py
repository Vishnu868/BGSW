"""The Guardian's agents and their deterministic fallbacks (used when no LLM is configured or an answer is
rejected by the verifier). Order = data flow:

  1 Orchestrator & Triage (lead)  routes cases to specialists, then sets a first priority
  2 Vulnerability Analyst         is this CVE exploitable in THIS application?
  3 Supply-Chain Forensics        non-CVE risks: typosquats, install scripts, lockfile tampering, containers, CI/CD
  4 Critic / Reviewer             independent second opinion on P1 verdicts and on the plan
  5 Business Context              what the app does for the business: internet-facing? sensitive data? (file:line facts)
  6 Neurosymbolic Prioritizer     takes 1-5's verified outputs, applies config/neurosymbolic_rules.json and
                                  re-prioritises: score + priority + confidence + explanation (neurosymbolic/prioritizer.py)
  7 Remediation Planner           safest allow-listed fix for the re-prioritised risks; next iteration after validation
"""
from __future__ import annotations

from .base import Agent

SPECIALIST_FORMAT = """{"verdict": "confirmed_risk|likely_false_positive|needs_human_review",
 "exploitable_in_context": "yes|no|unknown",
 "risk_summary": "<2-3 sentences for an engineer>",
 "recommended_action": "upgrade|replace|pin|remove|block|escalate|accept",
 "target_version": "<exact version or null>", "confidence": <0.0-1.0>,
 "evidence_refs": ["E1", ...], "reasoning": "<evidence -> conclusion>"}"""

LEAD_ROUTE = Agent(
    name="lead_router", title="Orchestrator & Triage lead",
    mission=("Decide which specialist investigates each risk case. Specialists: vulnerability_analyst (known CVEs: "
             "exploitability in this app) and supply_chain_forensics (typosquats, malicious or hijacked packages, install "
             "scripts, lockfile/registry tampering, container images, CI/CD workflows). A case may need both. "
             "Also list the case ids the independent critic must review (always include high-impact cases)."),
    output_format='{"routes": {"R-001": ["vulnerability_analyst"], "R-005": ["supply_chain_forensics"]}, "critic": ["R-001"]}',
    tools=[], max_steps=1)

LEAD_TRIAGE = Agent(
    name="lead_triage", title="Orchestrator & Triage lead",
    mission=("Set the final priority of each case. You receive each case's symbolic base score with its factors and the "
             "specialists' verdicts. You may move a score by at most 20 points and must give a reason based on the "
             "specialists' evidence (e.g. not exploitable in this app, typosquat confirmed). Priority bands are computed "
             "from your score: P1 >= 80, P2 >= 60, P3 >= 35, else P4. Also write a 3-4 sentence summary for engineering leads."),
    output_format='{"decisions": [{"id": "R-001", "final_score": 95, "reason": "..."}], "summary": "..."}',
    tools=[], max_steps=1)

VULN_ANALYST = Agent(
    name="vulnerability_analyst", title="Vulnerability Analyst",
    mission=("Investigate ONE known-vulnerability case: is it exploitable in THIS application? Check how the package "
             "enters the app, whether the app imports it, what the advisory says, exploitation intelligence, and a safe "
             "target version. Dev-only or unreachable code lowers urgency; known exploitation raises it."),
    output_format=SPECIALIST_FORMAT,
    tools=["item_details", "dependency_paths", "code_usage", "advisory", "exploit_intel", "registry_versions", "safe_upgrade"],
    max_steps=5)

FORENSICS = Agent(
    name="supply_chain_forensics", title="Supply-Chain Forensics analyst",
    mission=("Investigate ONE non-CVE supply-chain case: is this artifact trustworthy and where did it come from? Cases: "
             "look-alike or starjacked packages, install scripts, lockfile/registry/integrity changes, container images, "
             "CI/CD workflows. Compare registry metadata, maintainers, downloads, the actual script or file lines, and "
             "what changed since the baseline."),
    output_format=SPECIALIST_FORMAT,
    tools=["item_details", "dependency_paths", "registry_info", "registry_versions", "compare_downloads", "code_usage",
           "baseline_change", "file_lines"],
    max_steps=5)

PLANNER = Agent(
    name="remediation_planner", title="Remediation Planner",
    mission=("Choose the safest fix for ONE risk, using only these action types: npm_upgrade_direct, "
             "npm_override_transitive, npm_replace, npm_remove, pypi_upgrade, docker_pin_digest, action_pin_sha, block, "
             "escalate. You are given the rule-based proposal; keep it or improve it (e.g. upgrade a parent instead of "
             "overriding a child, or a version whose own dependency tree is clean - use safe_upgrade / dependency_tree). "
             "Prefer the smallest change that removes the risk."),
    output_format=('{"action_type": "...", "params": {"package": "...", "to": "...", "manifests": ["package.json"]}, '
                   '"rationale": "...", "confidence": <0-1>, "evidence_refs": ["E1", ...]}'),
    tools=["item_details", "dependency_paths", "registry_versions", "dependency_tree", "safe_upgrade", "code_usage"],
    max_steps=4)

CRITIC = Agent(
    name="critic", title="Critic / Reviewer (independent)",
    mission=("Give an independent second opinion. For each item, decide whether you agree with the verdict or plan action. "
             "Look for: wrong reachability assumptions, a fix that keeps or introduces a vulnerable dependency, a major "
             "upgrade that may break the app, a false-positive typosquat, missing evidence. Disagree only with a concrete reason."),
    output_format='{"reviews": [{"id": "R-001", "agree": true, "concern": "", "suggested_verdict": null}], "evidence_refs": ["E1"]}',
    tools=["item_details", "code_usage", "advisory", "registry_info", "dependency_tree"],
    max_steps=3)

BUSINESS = Agent(
    name="business_context", title="Business Context analyst",
    mission=("Work out what this application does for the business, so risks can be ranked by business impact. "
             "Find (a) which projects serve network traffic (internet_facing) and (b) which sensitive data they handle "
             "(data_class: credentials, payment, personal, auth_tokens). Look at README, routes, models, config, Dockerfiles. "
             "EVERY fact must cite the exact file:line that shows it; facts without real evidence are discarded. "
             "You receive the facts the pattern rules already found - add only facts they missed."),
    output_format=('{"business_function": "<one sentence>", "facts": [{"fact": "internet_facing|data_class", '
                   '"value": true | "credentials|payment|personal|auth_tokens", "project": "<manifest e.g. package.json>", '
                   '"evidence": "<file:line>"}], "confidence": <0-1>, "evidence_refs": ["E1", ...]}'),
    tools=["list_files", "search_repo", "read_lines"], max_steps=5)

ALL = {a.name: a for a in (LEAD_ROUTE, LEAD_TRIAGE, VULN_ANALYST, FORENSICS, PLANNER, CRITIC, BUSINESS)}
AGENTS = [("1", "Orchestrator & Triage (lead)", "lead_router + lead_triage"),
          ("2", "Vulnerability Analyst", "vulnerability_analyst"),
          ("3", "Supply-Chain Forensics", "supply_chain_forensics"),
          ("4", "Critic / Reviewer", "critic"),
          ("5", "Business Context", "business_context"),
          ("6", "Neurosymbolic Prioritizer", "neurosymbolic_prioritizer (rules over agents 1-5)"),
          ("7", "Remediation Planner", "remediation_planner")]


# ------------------------------------------------------------ rule fallbacks ---
def rules_route(cases: list[dict]) -> dict:
    return {"routes": {c["id"]: ["vulnerability_analyst" if c["category"] in ("1.1", "1.2") else "supply_chain_forensics"]
                       for c in cases},
            "critic": [c["id"] for c in cases if c["priority"] == "P1"]}


def rules_specialist(item: dict) -> dict:
    cd = item.get("component") or {}
    st = item["reachability"]["status"]
    action = ("replace" if item["category"] == "1.3" else
              "pin" if item["category"] in ("1.5", "1.7") else
              "block" if item["rule"].startswith("diff.tampered") else
              "upgrade" if item.get("max_fixed") else
              "remove" if st == "not-imported" and cd.get("direct") else "escalate")
    fp = cd.get("dev_only") and st in ("not-imported", "via-unused-parent")
    return {"verdict": "likely_false_positive" if fp else ("confirmed_risk" if item["base_priority"] in ("P1", "P2") else "needs_human_review"),
            "exploitable_in_context": "no" if fp else ("yes" if st in ("imported", "via-used-parent") else "unknown"),
            "risk_summary": f"{item['headline']}. Base priority {item['base_priority']} (score {item['base_score']}). "
                            f"Reachability: {item['reachability']['detail'] or st}.",
            "recommended_action": action, "target_version": item.get("max_fixed") or None,
            "confidence": 0.7 if item["confidence"] == "high" else 0.5, "evidence_refs": [],
            "reasoning": "; ".join(f"{x['reason']} ({x['points']:+g})" for x in item["factors"])}


def rules_triage(cases: list[dict]) -> dict:
    dec = []
    for c in cases:
        s, reason = c["base_score"], "symbolic score kept"
        ver = [v for v in c.get("specialist_verdicts", []) if v.get("status") != "rejected"]
        if ver and all(v["output"]["verdict"] == "likely_false_positive" and v["output"]["confidence"] >= 0.6 for v in ver):
            s, reason = s - 20, "specialists judged it a likely false positive"
        elif any(v["output"]["exploitable_in_context"] == "yes" and v["output"]["confidence"] >= 0.6 for v in ver):
            s, reason = s + 5, "specialist confirmed it is exploitable in this application"
        dec.append({"id": c["id"], "final_score": s, "reason": reason})
    return {"decisions": dec, "summary": None}
