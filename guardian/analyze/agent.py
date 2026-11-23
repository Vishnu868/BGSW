"""AI investigator: for each top risk item the model chooses read-only tools one at a time, then
returns a verdict. Provider-agnostic loop (works the same on Claude, Gemini, Groq):

    model -> {"tool": "...", "args": {...}, "why": "..."}   we run it, return result as evidence E<n>
    model -> {"final": {...}}                                 evidence checker validates it

Guardrails (hallucination control):
  * tools are read-only and allow-listed; unknown tools are refused
  * every claim must cite evidence ids that really exist; uncited -> confidence capped, needs human review
  * a suggested target version must exist in the registry and be >= the advisory's fixed version
  * confidence < 0.6 -> verdict becomes needs_human_review (escalate instead of guessing)
  * no LLM available -> the same questions are answered by deterministic rules (source = "rules")
"""
from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from pathlib import Path

from ..detect.osv import CACHE as OSV_CACHE, vkey
from ..detect.packages import _get as registry_get

MAX_STEPS = 5
VERDICTS = {"confirmed_risk", "likely_false_positive", "needs_human_review"}
ACTIONS = {"upgrade", "replace", "pin", "remove", "block", "escalate", "accept"}

SYSTEM = """You are the analysis brain of a Software Supply Chain Guardian.
You investigate ONE risk item at a time using read-only tools, then decide what it means for THIS application.
Rules:
- Use only facts returned by tools. Each tool result has an evidence id like E3. Cite ids in evidence_refs.
- Prefer few, targeted tool calls (at most 4). Never invent package names, versions, CVEs or file paths.
- If evidence is insufficient, say so: verdict needs_human_review with low confidence. Escalating is better than guessing.
- Dev-only or unreachable code lowers urgency; a typosquat, tampered lockfile or known-exploited CVE raises it.
Reply with exactly one JSON object, either
  {"tool": "<name>", "args": {...}, "why": "<one sentence>"}
or
  {"final": {"verdict": "confirmed_risk|likely_false_positive|needs_human_review",
             "exploitable_in_context": "yes|no|unknown",
             "risk_summary": "<2-3 sentences for an engineer>",
             "recommended_action": "upgrade|replace|pin|remove|block|escalate|accept",
             "target_version": "<exact version or null>",
             "confidence": <0.0-1.0>,
             "evidence_refs": ["E1", ...],
             "reasoning": "<short chain of evidence -> conclusion>"}}
Tools:
  item_details()                         - the risk item, its findings and deterministic evidence
  dependency_paths()                     - how the component enters the app (path, introducing direct deps)
  code_usage(package)                    - where the app imports a package (file:line)
  advisory(vuln_id)                      - vulnerability advisory: summary, affected ranges, fixed versions
  exploit_intel()                        - EPSS probability and CISA KEV status for the item's CVEs
  registry_info(package, version)        - registry metadata: maintainers, source repo, install scripts, deprecation
  registry_versions(package)             - published versions of a package (to pick a safe upgrade)
  baseline_change()                      - what changed for this component since the last approved scan
"""


class Tools:
    def __init__(self, item: dict, doc: dict, reach: dict, intel: dict, repo: Path, offline: bool):
        self.item, self.doc, self.reach, self.intel, self.repo, self.offline = item, doc, reach, intel, repo, offline
        self.findings = {f["id"]: f for f in doc["findings"] if f["id"] in item["finding_ids"]}
        self.eco = (item.get("component") or {}).get("ecosystem", "")

    def run(self, name: str, args: dict):
        fn = getattr(self, "t_" + name, None)
        if fn is None:
            return {"error": f"unknown tool '{name}'"}
        try:
            return fn(**(args or {}))
        except TypeError as e:
            return {"error": f"bad arguments: {e}"}

    def t_item_details(self):
        return {"risk_item": {k: self.item[k] for k in ("id", "headline", "severity", "category", "score", "priority",
                                                        "factors", "fixed", "max_fixed")},
                "component": self.item.get("component"),
                "findings": [{"id": f["id"], "title": f["title"], "rule": f["rule"], "evidence": f["evidence"][:6],
                              "data": {k: v for k, v in f["data"].items() if k in ("vuln_id", "cve", "cvss", "fixed", "aliases")}}
                             for f in self.findings.values()]}

    def t_dependency_paths(self):
        cd = self.item.get("component") or {}
        return {"path": cd.get("dependency_path"), "introduced_by": cd.get("introduced_by"),
                "direct": cd.get("direct"), "dev_only": cd.get("dev_only")}

    def t_code_usage(self, package: str = ""):
        package = package or (self.item.get("component") or {}).get("name", "")
        from .reachability import Index
        if not hasattr(self, "_idx"):
            self._idx = Index(self.repo)
        hits = self._idx.uses(package, self.eco or "npm")
        return {"package": package, "imports": [f"{a}:{b}" for a, b in hits[:10]], "count": len(hits),
                "reachability": self.reach.get(self.item["key"], {}).get("status")}

    def t_advisory(self, vuln_id: str = ""):
        ids = [f["data"].get("vuln_id") for f in self.findings.values() if f["data"].get("vuln_id")]
        vuln_id = vuln_id or (ids[0] if ids else "")
        f = OSV_CACHE / f"{vuln_id}.json"
        if not vuln_id or not f.exists():
            return {"error": f"advisory {vuln_id or '(none)'} not in this item's evidence", "known_ids": ids}
        v = json.loads(f.read_text(encoding="utf-8"))
        ranges = [{"package": a.get("package", {}).get("name"), "events": r.get("events")}
                  for a in v.get("affected", []) for r in a.get("ranges", []) if r.get("type") != "GIT"]
        return {"id": v["id"], "aliases": v.get("aliases"), "summary": v.get("summary"),
                "details": (v.get("details") or "")[:900], "ranges": ranges[:6]}

    def t_exploit_intel(self):
        cves = sorted({f["data"].get("cve") for f in self.findings.values() if f["data"].get("cve")})
        return {c: {"epss": self.intel["epss"].get(c), "in_cisa_kev": c in self.intel["kev"]} for c in cves} or \
            {"note": "no CVE ids for this item"}

    def t_registry_info(self, package: str = "", version: str = ""):
        cd = self.item.get("component") or {}
        package, version = package or cd.get("name", ""), version or cd.get("version", "")
        if self.eco != "npm":
            return {"note": f"registry metadata implemented for npm only (ecosystem {self.eco})"}
        m = registry_get(f"https://registry.npmjs.org/{urllib.parse.quote(package, safe='@')}/{version}",
                         f"npm_{package}_{version}", self.offline)
        if not m:
            return {"error": "not found in registry"}
        return {"name": m.get("name"), "version": m.get("version"), "repository": m.get("repository"),
                "maintainers": [x.get("name") for x in m.get("maintainers", []) if isinstance(x, dict)],
                "publisher": (m.get("_npmUser") or {}).get("name"), "deprecated": m.get("deprecated"),
                "install_scripts": {k: v for k, v in (m.get("scripts") or {}).items() if k in ("preinstall", "install", "postinstall")},
                "dependencies": list((m.get("dependencies") or {}).keys())[:20]}

    def t_registry_versions(self, package: str = ""):
        package = package or (self.item.get("component") or {}).get("name", "")
        vs = published_versions(package, self.eco, self.offline)
        if vs is None:
            return {"error": "versions unavailable"}
        return {"package": package, "latest": vs[-1] if vs else None, "count": len(vs), "recent": vs[-15:]}

    def t_baseline_change(self):
        ch = self.doc.get("changes") or {}
        key = self.item["key"]
        hits = [x for k in ("tampered", "added", "changed") for x in ch.get(k, []) if x.get("id") == key]
        return {"baseline": ch.get("baseline"), "changes": hits} if ch else {"note": "no baseline comparison in this scan"}


def published_versions(package: str, eco: str, offline: bool) -> list[str] | None:
    if eco == "npm":
        url = f"https://registry.npmjs.org/{urllib.parse.quote(package, safe='@')}"
        req = urllib.request.Request(url, headers={"Accept": "application/vnd.npm.install-v1+json",
                                                   "User-Agent": "supply-chain-guardian/0.2"})
    elif eco == "PyPI":
        req = urllib.request.Request(f"https://pypi.org/pypi/{package}/json", headers={"User-Agent": "supply-chain-guardian/0.2"})
    else:
        return None
    cache = Path(__file__).resolve().parents[2] / ".cache" / "versions" / (re.sub(r"[^\w.-]", "_", f"{eco}_{package}") + ".json")
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))
    if offline:
        return None
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
    except Exception:
        return None
    vs = list((data.get("versions") or {}).keys()) if eco == "npm" else list((data.get("releases") or {}).keys())
    vs = sorted((v for v in vs if re.match(r"^\d+(\.\d+)*$", v)), key=vkey)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(vs), encoding="utf-8")
    return vs


# ----------------------------------------------------------------- checker ---
def check(final: dict, evidence: dict, item: dict, offline: bool) -> tuple[dict, list[str]]:
    notes = []
    out = {k: final.get(k) for k in ("verdict", "exploitable_in_context", "risk_summary", "recommended_action",
                                     "target_version", "confidence", "evidence_refs", "reasoning")}
    if out["verdict"] not in VERDICTS:
        notes.append(f"invalid verdict '{out['verdict']}' -> needs_human_review")
        out["verdict"] = "needs_human_review"
    if out["recommended_action"] not in ACTIONS:
        notes.append(f"invalid action '{out['recommended_action']}' -> escalate")
        out["recommended_action"] = "escalate"
    refs = [r for r in (out.get("evidence_refs") or []) if isinstance(r, str)]
    bad = [r for r in refs if r not in evidence]
    if bad:
        notes.append(f"removed citations to evidence that does not exist: {bad}")
    out["evidence_refs"] = [r for r in refs if r in evidence]
    try:
        conf = float(out.get("confidence") or 0)
    except (TypeError, ValueError):
        conf = 0.0
    if not out["evidence_refs"]:
        conf = min(conf, 0.3)
        notes.append("no valid evidence cited -> confidence capped at 0.3")
    tv = out.get("target_version")
    if tv in ("null", "", "None"):
        tv = out["target_version"] = None
    if tv:
        cd = item.get("component") or {}
        vs = published_versions(cd.get("name", ""), cd.get("ecosystem", ""), offline)
        need = item.get("max_fixed") or ""
        if vs is not None and tv not in vs:
            notes.append(f"target version {tv} does not exist in the registry -> removed (hallucination blocked)")
            out["target_version"], conf = None, min(conf, 0.5)
        elif need and vkey(tv) < vkey(need):
            notes.append(f"target version {tv} is below the fixed version {need} -> corrected")
            out["target_version"] = need
    known = {(item.get("component") or {}).get("name", "")} | set((item.get("component") or {}).get("introduced_by") or [])
    text = json.dumps(evidence)
    for cve in set(re.findall(r"CVE-\d{4}-\d+", (out.get("risk_summary") or "") + (out.get("reasoning") or ""))):
        if cve not in text:
            notes.append(f"{cve} is not in the gathered evidence -> flagged")
            conf = min(conf, 0.5)
    out["confidence"] = round(conf, 2)
    if conf < 0.6 and out["verdict"] != "needs_human_review":
        notes.append(f"confidence {conf:.2f} < 0.6 -> escalated to human review")
        out["verdict"] = "needs_human_review"
    out["_known_names"] = sorted(n for n in known if n)
    return out, notes


# ------------------------------------------------------------ rule fallback ---
def rules_verdict(item: dict, intel: dict) -> dict:
    cd = item.get("component") or {}
    st = item["reachability"]["status"]
    cves = [f for f in item["finding_ids"]]
    action = ("replace" if item["category"] == "1.3" else
              "pin" if item["category"] in ("1.5", "1.7") else
              "upgrade" if item.get("max_fixed") else
              "remove" if st == "not-imported" and cd.get("direct") else "escalate")
    if item["rule"].startswith("diff.tampered"):
        action = "block"
    fp = cd.get("dev_only") and st in ("not-imported", "via-unused-parent")
    return {"verdict": "likely_false_positive" if fp else ("confirmed_risk" if item["priority"] in ("P1", "P2") else "needs_human_review"),
            "exploitable_in_context": "no" if fp else ("unknown" if st in ("unknown",) else "yes" if st in ("imported", "via-used-parent") else "unknown"),
            "risk_summary": f"{item['headline']}. Priority {item['priority']} (score {item['score']}). "
                            f"Reachability: {item['reachability']['detail'] or st}.",
            "recommended_action": action, "target_version": item.get("max_fixed") or None,
            "confidence": 0.7 if item["confidence"] == "high" else 0.5, "evidence_refs": [],
            "reasoning": "; ".join(f"{x['reason']} ({x['points']:+g})" for x in item["factors"]),
            "source": "rules"}


def investigate(item: dict, doc: dict, reach: dict, intel: dict, repo: Path, router, offline: bool) -> dict:
    tools = Tools(item, doc, reach, intel, repo, offline)
    if not router.enabled:
        return {"item": item["id"], "steps": [], "result": rules_verdict(item, intel), "checker_notes": [],
                "provider": "rules"}
    evidence: dict[str, dict] = {}
    steps = []
    first = tools.t_item_details()
    evidence["E1"] = {"tool": "item_details", "result": first}
    transcript = [f"Risk item to investigate. E1 = item_details():\n{json.dumps(first, default=str)[:3500]}"]
    provider = None
    for step in range(MAX_STEPS):
        msg, meta = router.ask_json(SYSTEM, "\n\n".join(transcript)[-12000:] +
                                    ("\n\nYou have used all tool calls: reply with final now." if step == MAX_STEPS - 1 else ""),
                                    purpose=f"investigate {item['id']} step {step + 1}")
        if msg is None:
            r = rules_verdict(item, intel)
            r["note"] = "AI unavailable mid-investigation: " + "; ".join(meta["errors"])[:300]
            return {"item": item["id"], "steps": steps, "result": r, "checker_notes": [], "provider": "rules"}
        provider = f"{meta['provider']}:{meta['model']}"
        if "final" in msg and isinstance(msg["final"], dict):
            result, notes = check(msg["final"], evidence, item, offline)
            result["source"] = "ai"
            return {"item": item["id"], "steps": steps, "result": result, "checker_notes": notes,
                    "provider": provider, "evidence": evidence}
        name, args = str(msg.get("tool", "")), msg.get("args") or {}
        res = tools.run(name, args if isinstance(args, dict) else {})
        eid = f"E{len(evidence) + 1}"
        evidence[eid] = {"tool": name, "args": args, "result": res}
        steps.append({"step": step + 1, "tool": name, "args": args, "why": msg.get("why", ""), "evidence_id": eid})
        transcript.append(f"You called {name}({json.dumps(args)}) because: {msg.get('why', '')}\n"
                          f"{eid} = {json.dumps(res, default=str)[:3000]}")
    r = rules_verdict(item, intel)
    r["note"] = "AI did not finish within the step limit"
    return {"item": item["id"], "steps": steps, "result": r, "checker_notes": [], "provider": provider or "rules"}
