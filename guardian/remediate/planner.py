"""Stage 4 - Plan (neurosymbolic): rule-based proposals -> Remediation Planner agent may improve each one ->
symbolic verifier checks it -> Critic agent reviews the whole plan.

Only allow-listed action types are possible. Every action carries rationale, expected risk reduction, compatibility
impact, rollback and evidence. The plan is identified by a SHA-256 hash; approval is bound to that exact hash.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .. import audit
from ..agents import roles
from ..agents.tools import Toolbox
from ..detect.osv import vkey
from ..llm import Router
from ..neurosymbolic import rules, verifier
from ..neurosymbolic.facts import Facts, published_versions
from . import resolvers

ALLOWED = rules.REMEDIATION_ACTIONS
_FACTS: Facts | None = None


def plan_hash(actions: list[dict]) -> str:
    core = [{k: a[k] for k in ("type", "params")} for a in actions]
    return hashlib.sha256(json.dumps(core, sort_keys=True).encode()).hexdigest()


def _manifests(run_dir: Path) -> dict[str, list[str]]:
    sbom = json.loads((run_dir / "sbom.cdx.json").read_text(encoding="utf-8"))
    out = {}
    for c in sbom.get("components", []):
        props = {p["name"]: p["value"] for p in c.get("properties", [])}
        out[c["bom-ref"]] = [m for m in props.get("guardian:manifests", "").split(",") if m and not m.startswith("resolved:")]
    return out


def _manifest_for(lock_or_manifest: list[str], repo: Path) -> list[str]:
    res = []
    for m in lock_or_manifest:
        p = repo / m
        if p.name == "package-lock.json":
            p = p.with_name("package.json")
        if p.exists():
            res.append(p.relative_to(repo).as_posix())
    return sorted(set(res))


def _major(v: str) -> int:
    k = vkey(v)
    return k[0] if k else 0


def _pick_target(name: str, eco: str, need: str, ai_target: str | None, offline: bool) -> tuple[str, str]:
    """Smallest-impact published version >= the fixed version whose own dependency tree has no known CVE
    (checked with deps.dev + OSV); falls back to the latest release in the fixed version's major line."""
    if eco == "npm" and need and _FACTS is not None:
        res = _FACTS.safe_upgrade(name, need, eco)
        if res.get("version") and res.get("clean_tree"):
            return res["version"], (f"smallest major line whose dependency tree has no known vulnerability "
                                    f"(checked {', '.join(t['version'] for t in res['tried'])})")
    vs = published_versions(name, eco, offline) or []
    if ai_target and ai_target in vs and (not need or vkey(ai_target) >= vkey(need)):
        return ai_target, "AI-suggested version, verified in the registry"
    if not need:
        return "", ""
    ok = [v for v in vs if vkey(v) >= vkey(need)]
    same = [v for v in ok if _major(v) == _major(need)]
    if same:
        return same[-1], f"latest {_major(need)}.x release at or above the fixed version {need}"
    if ok:
        return ok[0], f"first published version at or above {need}"
    return need, "advisory fixed version (registry list unavailable)"


_compat = rules.compatibility


def build(run_dir: Path, analysis: dict, max_actions: int = 8, include: tuple = ("P1", "P2"), offline: bool = False,
          log=print) -> dict:
    global _FACTS
    doc = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    repo = Path(analysis["repo_path"])
    _FACTS = Facts(doc, offline)
    mans = _manifests(run_dir)
    findings = {f["id"]: f for f in doc["findings"]}
    actions, covered = [], {}
    planned_direct = set()

    def add(item, typ, params, rationale, compat, rollback, resolves, evidence=None, code_change=False):
        actions.append({"id": f"A-{len(actions) + 1:02d}", "type": typ, "description": ALLOWED[typ], "params": params,
                        "risk_item": item["id"], "risk": item["headline"], "priority": item["priority"],
                        "score": item["score"], "finding_ids": resolves, "rationale": rationale,
                        "ai_inference": ({k: item["ai"].get(k) for k in ("verdict", "risk_summary", "confidence", "source", "agent")}
                                         if item.get("ai") else None),
                        "expected_risk_reduction": f"removes {len(resolves)} finding(s); risk score {item['score']} -> ~0",
                        "compatibility": compat, "rollback": rollback, "requires_code_change": code_change,
                        "evidence": evidence or []})

    candidates = [i for i in analysis["items"] if i["priority"] in include or
                  (i["category"] in ("1.3", "1.6") and i["severity"] in ("critical", "high"))]
    # pass 1: which direct dependencies will be upgraded anyway (their transitive children may be covered)
    will_upgrade = {(i.get("component") or {}).get("name") for i in candidates
                    if (i.get("component") or {}).get("direct") and (i.get("component") or {}).get("ecosystem") == "npm"
                    and i["category"] in ("1.1", "1.2") and i.get("max_fixed")
                    and (i.get("ai") or {}).get("verdict") != "likely_false_positive"}
    for item in candidates:
        if len(actions) >= max_actions:
            break
        cd, ai = item.get("component") or {}, item.get("ai") or {}
        name, ver, eco = cd.get("name", ""), cd.get("version", ""), cd.get("ecosystem", "")
        rule, cat = item["rule"], item["category"]
        if ai.get("verdict") == "likely_false_positive":
            continue
        if rule.startswith("diff.tampered") or rule == "lockfile.integrity-conflict":
            add(item, "block", {"component": f"{name}@{ver}", "reason": item["headline"]},
                "Integrity/source of an existing version changed: treat the change as untrusted and do not merge it.",
                {"level": "none", "reason": "no file change"}, "Remove the block after the source is verified",
                item["finding_ids"])
            continue
        if cat == "1.3" and rule == "packages.repo-name-mismatch" and eco == "npm":
            f = findings[item["finding_ids"][0]]
            genuine = f["data"].get("claimed_repo", "").split("/")[-1]
            vs = published_versions(genuine, "npm", offline) or []
            same = [v for v in vs if _major(v) == _major(ver)]
            target = (same or vs or [""])[-1]
            if not genuine or not target:
                add(item, "escalate", {"component": f"{name}@{ver}", "reason": "genuine package could not be confirmed"},
                    "Possible typosquat but no verified replacement", {"level": "unknown", "reason": ""}, "n/a", item["finding_ids"])
                continue
            refs = item["reachability"].get("evidence", []) if item["reachability"]["status"] == "imported" else []
            add(item, "npm_replace", {"manifests": _manifest_for(mans.get(item["key"], []), repo), "package": name,
                                      "with": genuine, "version": target, "code_refs": refs},
                f"'{name}' claims to be built from {f['data'].get('claimed_repo')} but is published by someone else; "
                f"replace it with the genuine '{genuine}' ({target}, same major line {_major(ver)}.x).",
                {"level": "major" if _major(target) != _major(ver) else "minor",
                 "reason": f"different package; API expected to match the original it copies - {len(refs)} import(s) rewritten, run tests"},
                f"git revert the remediation commit (restores '{name}')", item["finding_ids"],
                evidence=[f"import at {r}" for r in refs], code_change=bool(refs))
            continue
        if cat in ("1.1", "1.2") and eco == "npm":
            need = item.get("max_fixed") or ""
            if not need:
                add(item, "escalate", {"component": f"{name}@{ver}", "reason": "no fixed version published"},
                    f"No fix exists for {name}; mitigate (input validation/isolation) or replace the package.",
                    {"level": "unknown", "reason": "requires design decision"}, "n/a", item["finding_ids"])
                continue
            if cd.get("direct"):
                if name in planned_direct:
                    continue
                target, why = _pick_target(name, eco, need, ai.get("target_version") if ai.get("source") == "ai" else None, offline)
                planned_direct.add(name)
                add(item, "npm_upgrade_direct", {"manifests": _manifest_for(mans.get(item["key"], []), repo),
                                                 "package": name, "from": ver, "to": target},
                    f"Upgrade {name} {ver} -> {target} ({why}).", _compat(ver, target),
                    f"Set {name} back to {ver} in package.json and regenerate the lockfile (or git revert)", item["finding_ids"])
            else:
                parents = cd.get("introduced_by") or []
                if name in will_upgrade or (parents and all(p in will_upgrade for p in parents)):
                    covered[item["id"]] = (f"{name}@{ver}: expected to be resolved by upgrading "
                                           f"{name if name in will_upgrade else ', '.join(parents)} - confirmed by the rescan")
                    continue
                target, why = _pick_target(name, eco, need, ai.get("target_version") if ai.get("source") == "ai" else None, offline)
                add(item, "npm_override_transitive", {"manifests": _manifest_for(mans.get(item["key"], []), repo),
                                                      "package": name, "from": ver, "to": target, "via": parents[:5]},
                    f"{name} {ver} arrives through {', '.join(parents[:3]) or 'other packages'}; force {target} with npm "
                    f"overrides ({why}).", _compat(ver, target),
                    "Remove the overrides entry and regenerate the lockfile (or git revert)", item["finding_ids"])
            continue
        if cat in ("1.1", "1.2") and eco == "PyPI" and cd.get("direct") and item.get("max_fixed"):
            target, why = _pick_target(name, eco, item["max_fixed"], ai.get("target_version"), offline)
            add(item, "pypi_upgrade", {"manifests": _manifest_for(mans.get(item["key"], []), repo), "package": name,
                                       "from": ver, "to": target}, f"Pin {name}=={target} ({why}).", _compat(ver, target),
                f"Restore {name}=={ver}", item["finding_ids"])
            continue
        if rule == "container.unpinned":
            f = findings[item["finding_ids"][0]]
            ev = f["evidence"][0]
            image = ev["detail"]
            try:
                digest = resolvers.image_digest(image)
            except Exception as e:
                add(item, "escalate", {"component": image, "reason": f"digest lookup failed: {e}"},
                    "Pin manually: docker buildx imagetools inspect <image>", {"level": "none", "reason": ""}, "n/a",
                    item["finding_ids"])
                continue
            add(item, "docker_pin_digest", {"file": ev["file"], "line": ev.get("line"), "image": image, "digest": digest},
                f"Pin {image} to {digest[:19]}... so the build always uses the image that was reviewed.",
                {"level": "none", "reason": "same image content as today; future updates become explicit"},
                "Remove the @sha256 suffix (or git revert)", item["finding_ids"], evidence=[f"registry digest {digest}"])
            continue
        if rule == "cicd.unpinned-action":
            f = findings[item["finding_ids"][0]]
            ev = f["evidence"][0]
            m = re.search(r"uses:\s*['\"]?([^@'\"\s]+)@([^'\"\s#]+)", ev["detail"])
            if not m:
                continue
            try:
                sha = resolvers.action_sha(m.group(1), m.group(2))
            except Exception as e:
                add(item, "escalate", {"component": m.group(0), "reason": f"SHA lookup failed: {e}"},
                    "Pin manually to the commit SHA of the tag", {"level": "none", "reason": ""}, "n/a", item["finding_ids"])
                continue
            add(item, "action_pin_sha", {"file": ev["file"], "line": ev.get("line"), "action": m.group(1),
                                         "ref": m.group(2), "sha": sha},
                f"Pin {m.group(1)}@{m.group(2)} to commit {sha[:12]} so a moved tag cannot inject code into CI.",
                {"level": "none", "reason": "same code as the current tag"}, "Restore the tag reference (or git revert)",
                item["finding_ids"], evidence=[f"GitHub: {m.group(1)}@{m.group(2)} = {sha}"])
            continue
        if item["priority"] == "P1":
            add(item, "escalate", {"component": f"{name}@{ver}" if name else item["key"], "reason": item["headline"]},
                "High-priority risk without a safe automatic fix: needs a human decision.",
                {"level": "unknown", "reason": ""}, "n/a", item["finding_ids"])

    _agents_refine(run_dir, analysis, actions, doc, offline, log)
    h = plan_hash(actions)
    plan = {"schema": "guardian.plan/v2", "repository": analysis["repository"], "repo_path": str(repo),
            "plan_hash": h, "actions": actions, "covered_by_other_actions": covered,
            "allowed_action_types": ALLOWED, "status": "awaiting_approval"}
    (run_dir / "plan.json").write_text(json.dumps(plan, indent=1), encoding="utf-8")
    (run_dir / "plan.md").write_text(markdown(plan), encoding="utf-8")
    log(f"[plan] {len(actions)} actions, plan hash {h[:12]}")
    return plan


def markdown(p: dict) -> str:
    L = [f"# Remediation plan - {p['repository']}", "", f"Plan hash: `{p['plan_hash']}` (approval is bound to this hash)", "",
         "| ID | Action | Target | Risk | Priority | Compatibility |", "|---|---|---|---|---|---|"]
    for a in p["actions"]:
        tgt = a["params"].get("package") or a["params"].get("image") or a["params"].get("action") or a["params"].get("component", "")
        if a["params"].get("to"):
            tgt += f" {a['params'].get('from', '')} -> {a['params']['to']}"
        if a["params"].get("with"):
            tgt += f" -> {a['params']['with']}@{a['params']['version']}"
        L.append(f"| {a['id']} | {a['type']} | {tgt} | {a['risk'][:60].replace('|', '/')} | {a['priority']} | "
                 f"{a['compatibility']['level']} |")
    L += ["", "## Details", ""]
    for a in p["actions"]:
        L += [f"### {a['id']} {a['type']}", "", f"- Why: {a['rationale']}", f"- Expected: {a['expected_risk_reduction']}",
              f"- Compatibility: {a['compatibility']['reason']}", f"- Rollback: {a['rollback']}"]
        if a.get("ai_inference"):
            L.append(f"- Agents' verdict ({a['ai_inference'].get('source')}): {a['ai_inference'].get('risk_summary')}")
        if a.get("planner"):
            L.append(f"- Remediation Planner agent: {a['planner']['source']}, {a['planner']['status']}"
                     + (" - changed the rule-based proposal" if a['planner'].get('changed_from') else ""))
            L += [f"  - verifier: {n}" for n in a["planner"].get("notes", []) if n]
        if a.get("critic"):
            L.append(f"- Critic ({a['critic']['source']}): {'agrees' if a['critic']['agree'] else 'DISAGREES'}"
                     + (f" - {a['critic']['concern']}" if a['critic']['concern'] else ""))
        L.append("")
    if p["covered_by_other_actions"]:
        L += ["## Covered by other actions", ""] + [f"- {k}: {v}" for k, v in p["covered_by_other_actions"].items()]
    return "\n".join(L) + "\n"


class _RepoFiles:
    def __init__(self, repo: Path):
        self.repo = repo

    def __contains__(self, rel) -> bool:
        return (self.repo / str(rel)).is_file()


def _agents_refine(run_dir: Path, analysis: dict, actions: list, doc: dict, offline: bool, log) -> None:
    """Remediation Planner agent may improve each rule-based proposal (verified symbolically); the Critic agent then
    reviews the whole plan. Without an LLM the rule-based plan is used unchanged and labelled as such."""
    router = Router(audit=run_dir / "audit.jsonl")
    items = {i["id"]: i for i in analysis["items"]}
    repo_files = _RepoFiles(Path(analysis["repo_path"]))
    for a in actions:
        item = items.get(a["risk_item"], {})
        if a["type"] == "block" or not item:
            a["planner"] = {"source": "rules", "status": "kept", "notes": ["block actions are fixed by policy"]}
            continue
        ctx = {"risk": {k: item.get(k) for k in ("id", "headline", "category", "max_fixed", "component", "reachability")},
               "agents_verdict": item.get("ai"),
               "rule_based_proposal": {"action_type": a["type"], "params": a["params"], "rationale": a["rationale"]}}
        r = roles.PLANNER.run(router, ctx, Toolbox(_FACTS, item), purpose=a["id"])
        if not isinstance(r["output"], dict):
            a["planner"] = {"source": "rules", "status": "kept", "notes": [r["error"]] if r["error"] else []}
            continue
        out, notes, st = verifier.plan_proposal(dict(r["output"]), r["evidence"], item, _FACTS, repo_files)
        info = {"source": "ai", "status": st, "notes": notes, "steps": r["steps"], "provider": r["provider"]}
        if st != "rejected" and (out["action_type"] != a["type"] or out.get("params") != a["params"]):
            old = {"type": a["type"], "params": a["params"]}
            params = dict(a["params"])
            params.update({k: v for k, v in out["params"].items() if v not in (None, "")})
            a["type"], a["params"], a["description"] = out["action_type"], params, ALLOWED[out["action_type"]]
            a["rationale"] = f"{out.get('rationale') or a['rationale']} (improved by the Remediation Planner agent, verified)"
            if params.get("to"):
                a["compatibility"] = rules.compatibility(params.get("from", ""), str(params["to"]))
            info["changed_from"] = old
        a["planner"] = info
        log(f"[plan] {a['id']} planner agent: {st}{' (changed)' if info.get('changed_from') else ''}")
    # Critic reviews the whole plan in one pass
    view = [{"id": a["id"], "type": a["type"], "params": a["params"], "risk": a["risk"][:100],
             "compatibility": a["compatibility"]["level"], "rationale": a["rationale"][:200]} for a in actions]
    r = roles.CRITIC.run(router, {"plan": view}, Toolbox(_FACTS, {}), purpose="review plan")
    if isinstance(r["output"], dict):
        out, notes, st = verifier.critic(r["output"], r["evidence"], {a["id"] for a in actions})
        reviews, src = {x["id"]: x for x in out["reviews"]}, "ai"
    else:
        reviews, notes, st, src = {}, [r["error"]] if r["error"] else [], "fallback", "rules"
    for a in actions:
        rv = reviews.get(a["id"])
        if rv is None:   # rule-based critic: flag what always deserves a second look
            concern = ("major version change - run the full test suite before merging"
                       if a["compatibility"]["level"] == "major" else
                       "no automatic fix - needs a human decision" if a["type"] == "escalate" else "")
            rv = {"id": a["id"], "agree": True, "concern": concern, "suggested_verdict": None}
        a["critic"] = dict(rv, source=src)
    audit.log(run_dir / "audit.jsonl", "plan_reviewed", {"critic": src, "disagreements": [a["id"] for a in actions if not a["critic"]["agree"]]})
