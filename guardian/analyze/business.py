"""Business context: what does this application do for the business, and how much would a breach hurt?

Facts (each must cite file:line evidence):
  internet_facing   the project serves network traffic (listen/routes/EXPOSE/ports)
  data_class        sensitive data it handles: credentials, payment, personal, auth tokens
  business_function one-line description (README / package description)
Facts come from two sources: deterministic patterns (always) + the Business Context agent (optional, LLM),
whose facts are only kept if the cited line really exists and really mentions the claimed data.
A human can confirm or reject facts (`python -m guardian business <repo>`); rejected facts are ignored.

Business impact per risk = SSVC-inspired decision (Act / Attend / Track* / Track) from config/business_rules.json,
using: exploitation (CISA KEV / EPSS), exposure (internet-facing + reachable + production), automatable (CVSS
vector), human impact (data classes). The decision adds bounded points to the symbolic score, with its reason.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RULES_FILE = ROOT / "config" / "business_rules.json"
SRC_EXT = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".py", ".java", ".kt", ".go", ".rb", ".php", ".cs",
           ".yml", ".yaml", ".json", ".sql", ".html"}
SKIP = {"node_modules", ".git", "dist", "build", ".angular", "coverage", "__pycache__", "vendor", "target", "test",
        "tests", "spec", "cypress", "i18n", "screenshots", ".github"}
SERVE = re.compile(r"\.listen\s*\(|createServer\s*\(|@RestController|@SpringBootApplication|Flask\s*\(__name__\)|"
                   r"app\.run\s*\(|http\.ListenAndServe|Rails\.application\.routes|express\s*\(\s*\)", re.I)
DATA = {
    "credentials": re.compile(r"\bpassword\b|\bpasswd\b|\btotp\b|\bsecret\b", re.I),
    "payment": re.compile(r"\bcard ?num|creditcard|\bcard\b.*\b(number|expir)|\bpayment\b|\bwallet\b|\biban\b|\bcvv\b", re.I),
    "personal": re.compile(r"\bemail\b|\baddress\b|\bphone\b|date ?of ?birth|\bssn\b", re.I),
    "auth_tokens": re.compile(r"\bjwt\b|jsonwebtoken|\baccess.?token\b|\bsession\b", re.I),
}


NOT_EVIDENCE = re.compile(r"(lock|\.min\.)|test|spec|mock|cypress|e2e|fixture|\.config\.|i18n|package\.json$", re.I)
PREFERRED = ("model", "schema", "entity", "route", "controller", "api", "server", "app.", "user", "order", "payment")


def _files(repo: Path, evidence_only: bool = False):
    """Repository files; with evidence_only, skip lockfiles/tests/configs and list model/route/server files first."""
    out = []
    for dp, dn, fn in os.walk(repo):
        dn[:] = [d for d in dn if d not in SKIP]
        for f in fn:
            p = Path(dp) / f
            if p.suffix.lower() in SRC_EXT or f.lower() in ("dockerfile", "docker-compose.yml"):
                rel = p.relative_to(repo).as_posix()
                if evidence_only and NOT_EVIDENCE.search(rel) and f.lower() != "dockerfile":
                    continue
                if evidence_only and p.suffix.lower() == ".json":
                    continue
                out.append(p)
    if evidence_only:
        out.sort(key=lambda p: (0 if any(k in p.relative_to(repo).as_posix().lower() for k in PREFERRED) else 1,
                                p.relative_to(repo).as_posix()))
    return out


def _project_of(rel: str, projects: list[str]) -> str:
    """The project (manifest) whose folder most specifically contains the file, e.g. frontend/ before the repo root."""
    best, best_len = "", -1
    for pr in projects:
        d = Path(pr).parent.as_posix()
        d = "" if d == "." else d
        if (d == "" or rel.startswith(d + "/")) and len(d) > best_len:
            best, best_len = pr, len(d)
    return best


def rule_facts(repo: Path, projects: list[str]) -> dict:
    facts, seen = [], set()
    for p in _files(repo, evidence_only=True):
        rel = p.relative_to(repo).as_posix()
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        proj = _project_of(rel, projects)
        for i, line in enumerate(lines[:4000], 1):
            if len(line) > 400:
                continue
            if ("internet_facing", proj) not in seen and (SERVE.search(line) or re.match(r"\s*EXPOSE\s+\d+", line)):
                seen.add(("internet_facing", proj))
                facts.append({"fact": "internet_facing", "value": True, "project": proj, "evidence": f"{rel}:{i}",
                              "line": line.strip()[:160], "source": "rules"})
            for cls, rx in DATA.items():
                if (cls, proj) not in seen and rx.search(line):
                    seen.add((cls, proj))
                    facts.append({"fact": "data_class", "value": cls, "project": proj, "evidence": f"{rel}:{i}",
                                  "line": line.strip()[:160], "source": "rules"})
    function = ""
    for name in ("README.md", "README.rst", "README.txt", "README"):
        f = repo / name
        if f.exists():
            for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                t = re.sub(r"[#*>\[\]!]|\(http\S+\)", "", line).strip()
                if len(t) > 40 and not t.lower().startswith(("http", "<", "|")):
                    function = {"value": t[:200], "evidence": f"{name}:{i}"}
                    break
            break
    return {"projects": projects, "business_function": function, "facts": facts}


def verify_agent_facts(agent_facts: list, repo: Path) -> tuple[list, list]:
    """Keep an LLM-proposed fact only if its file:line exists and the line really shows that kind of data."""
    kept, notes = [], []
    for f in agent_facts or []:
        if not isinstance(f, dict):
            continue
        ev = str(f.get("evidence", ""))
        m = re.match(r"^(.*?):(\d+)$", ev)
        path = (repo / m.group(1)).resolve() if m else None
        if not m or repo.resolve() not in path.parents or not path.is_file():
            notes.append(f"dropped '{f.get('fact')}={f.get('value')}': evidence {ev or '(none)'} does not exist")
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        n = int(m.group(2))
        if n < 1 or n > len(lines):
            notes.append(f"dropped '{f.get('fact')}={f.get('value')}': line {n} not in {m.group(1)}")
            continue
        text = lines[n - 1]
        ok = (f.get("fact") == "internet_facing" and (SERVE.search(text) or "EXPOSE" in text or "port" in text.lower())) or \
             (f.get("fact") == "data_class" and f.get("value") in DATA and DATA[f["value"]].search(text))
        if not ok:
            notes.append(f"dropped '{f.get('fact')}={f.get('value')}': {ev} does not show it")
            continue
        kept.append({"fact": f["fact"], "value": f.get("value", True), "project": f.get("project", ""), "evidence": ev,
                     "line": text.strip()[:160], "source": "agent"})
    return kept, notes


def load_rules() -> dict:
    return json.loads(RULES_FILE.read_text(encoding="utf-8"))


def active_facts(ctx: dict) -> list:
    rejected = {k for k, v in (ctx.get("human") or {}).items() if v == "rejected"}
    return [f for f in ctx.get("facts", []) if f"{f['fact']}:{f['value']}:{f['project']}" not in rejected]


def project_profile(ctx: dict, project: str) -> dict:
    fs = [f for f in active_facts(ctx) if f["project"] == project]
    return {"internet_facing": any(f["fact"] == "internet_facing" for f in fs),
            "data": sorted({f["value"] for f in fs if f["fact"] == "data_class"})}


def decide(item: dict, ctx: dict, kev: set, epss: dict, rules: dict) -> dict:
    """SSVC-inspired business decision for one risk item (deterministic, explainable)."""
    cd = item.get("component") or {}
    path = cd.get("dependency_path") or []
    m = next((re.search(r"\((.+?)\)", p) for p in path if re.search(r"\((.+?)\)", p)), None)
    project = m.group(1) if m else ""
    prof = project_profile(ctx, project) if project else {"internet_facing": False, "data": []}
    cve = item.get("cve", "")
    e = epss.get(cve) if cve else None
    exploitation = "active" if cve in kev else ("poc" if e and e["epss"] >= rules["epss_poc_threshold"] else "none")
    st = (item.get("reachability") or {}).get("status", "unknown")
    if cd.get("dev_only"):
        exposure = "small"
    elif prof["internet_facing"] and st in ("imported", "via-used-parent", "unknown"):
        exposure = "open"
    else:
        exposure = "controlled"
    vec = item.get("cvss_vector", "")
    automatable = "yes" if all(x in vec for x in ("AV:N", "PR:N", "UI:N")) else "no"
    data = set(prof["data"])
    impact = ("very_high" if {"credentials", "payment"} <= data else
              "high" if data & {"credentials", "payment"} else
              "medium" if data & {"personal", "auth_tokens"} else "low")
    point = {"exploitation": exploitation, "exposure": exposure, "automatable": automatable, "human_impact": impact}
    for r in rules["decision_table"]:
        if all(point[k] in (v if isinstance(v, list) else [v]) for k, v in r["when"].items()):
            return {**point, "decision": r["decision"], "points": rules["points"][r["decision"]], "project": project,
                    "reason": r["why"]}
    return {**point, "decision": "Track", "points": rules["points"]["Track"], "project": project, "reason": "default"}
