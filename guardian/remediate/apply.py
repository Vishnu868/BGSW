"""Apply APPROVED actions in a sandbox copy of the repository (a git branch inside runs/<repo>/sandbox).

Safety checks before any change:
  1. approval.json exists and its plan_hash equals the current plan's hash (plan not modified after approval)
  2. kill switch absent: runs/<repo>/STOP file or GUARDIAN_KILL=1 stops everything
  3. every action type is on the allow-list; at most MAX_ACTIONS changes
  4. the original repository is never modified; nothing is pushed, merged or published
Output: sandbox branch + remediation.patch (PR-ready diff) + apply.json
"""
from __future__ import annotations

import json
import time
import os
import re
import shutil
import subprocess
from pathlib import Path

from .. import audit
from ..pipeline import NPM
from .planner import ALLOWED, plan_hash

MAX_ACTIONS = 12
COPY_IGNORE = shutil.ignore_patterns("node_modules", ".git", "*.png", "*.jpg", "*.gif", "*.mp4", "*.pdf", "*.zip")


class Refused(Exception):
    pass


def _git(cwd: Path, *args) -> str:
    r = subprocess.run(["git", "-c", "user.name=guardian", "-c", "user.email=guardian@localhost",
                        "-c", "core.autocrlf=false", *args], cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()[:300]}")
    return r.stdout


def preflight(run_dir: Path, plan: dict) -> dict:
    if (run_dir / "STOP").exists() or os.environ.get("GUARDIAN_KILL") == "1":
        raise Refused("kill switch is active (STOP file or GUARDIAN_KILL=1)")
    ap_f = run_dir / "approval.json"
    if not ap_f.exists():
        raise Refused("no approval recorded - run `guardian approve` first")
    ap = json.loads(ap_f.read_text(encoding="utf-8"))
    if ap["plan_hash"] != plan["plan_hash"] or plan_hash(plan["actions"]) != plan["plan_hash"]:
        raise Refused("plan changed after approval - approval is void, approve again")
    if not ap["approved_actions"]:
        raise Refused("the plan was rejected - nothing to apply")
    chosen = [a for a in plan["actions"] if a["id"] in ap["approved_actions"]]
    bad = [a["id"] for a in chosen if a["type"] not in ALLOWED]
    if bad:
        raise Refused(f"action types not on the allow-list: {bad}")
    if len(chosen) > MAX_ACTIONS:
        raise Refused(f"too many changes in one run ({len(chosen)} > {MAX_ACTIONS})")
    return ap


def _edit_json(path: Path, fn) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    fn(data)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _do(sb: Path, a: dict) -> str:
    p, t = a["params"], a["type"]
    if t in ("block", "escalate"):
        return "recorded (no file change)"
    if t == "npm_upgrade_direct":
        touched = 0
        for m in p["manifests"]:
            def f(d):
                nonlocal touched
                for sec in ("dependencies", "devDependencies", "optionalDependencies"):
                    if p["package"] in d.get(sec, {}):
                        d[sec][p["package"]] = p["to"]
                        touched += 1
            _edit_json(sb / m, f)
        if not touched:
            raise RuntimeError(f"{p['package']} not found in {p['manifests']}")
        return f"{p['package']} -> {p['to']} in {', '.join(p['manifests'])}"
    if t == "npm_override_transitive":
        for m in p["manifests"]:
            _edit_json(sb / m, lambda d: d.setdefault("overrides", {}).__setitem__(p["package"], p["to"]))
        return f"overrides.{p['package']} = {p['to']} in {', '.join(p['manifests'])}"
    if t == "npm_replace":
        for m in p["manifests"]:
            def f(d):
                for sec in ("dependencies", "devDependencies", "optionalDependencies"):
                    if p["package"] in d.get(sec, {}):
                        d[sec].pop(p["package"])
                        d[sec][p["with"]] = p["version"]
                        d[sec] = dict(sorted(d[sec].items()))
            _edit_json(sb / m, f)
        changed = 0
        pat = re.compile(r"""(['"])""" + re.escape(p["package"]) + r"""(['"/])""")
        for ref in {r.rsplit(":", 1)[0] for r in p.get("code_refs", [])}:
            fp = sb / ref
            if fp.exists():
                txt = fp.read_text(encoding="utf-8")
                new, n = pat.subn(lambda m: m.group(1) + p["with"] + m.group(2), txt)
                if n:
                    fp.write_text(new, encoding="utf-8")
                    changed += n
        return f"{p['package']} -> {p['with']}@{p['version']}; {changed} import statement(s) rewritten"
    if t == "npm_remove":
        for m in p["manifests"]:
            _edit_json(sb / m, lambda d: [d.get(s, {}).pop(p["package"], None) for s in ("dependencies", "devDependencies")])
        return f"removed {p['package']}"
    if t == "pypi_upgrade":
        n = 0
        for m in p["manifests"]:
            fp = sb / m
            lines = fp.read_text(encoding="utf-8").splitlines()
            for i, line in enumerate(lines):
                if re.match(rf"^\s*{re.escape(p['package'])}\s*([=<>~!]|$)", line, re.I):
                    lines[i], n = f"{p['package']}=={p['to']}", n + 1
            fp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        if not n:
            raise RuntimeError("requirement line not found")
        return f"{p['package']}=={p['to']}"
    if t == "docker_pin_digest":
        fp = sb / p["file"]
        txt = fp.read_text(encoding="utf-8")
        new, n = re.subn(rf"(?<![\w./:-]){re.escape(p['image'])}(?![\w.:/@-])", f"{p['image']}@{p['digest']}", txt, count=1)
        if not n:
            raise RuntimeError(f"image reference {p['image']} not found in {p['file']}")
        fp.write_text(new, encoding="utf-8")
        return f"{p['file']}: {p['image']} pinned to {p['digest'][:19]}..."
    if t == "action_pin_sha":
        fp = sb / p["file"]
        txt = fp.read_text(encoding="utf-8")
        new, n = re.subn(rf"(uses:\s*['\"]?){re.escape(p['action'])}@{re.escape(p['ref'])}(['\"]?)",
                         lambda m: f"{m.group(1)}{p['action']}@{p['sha']}{m.group(2)} # {p['ref']}", txt)
        if not n:
            raise RuntimeError("uses: line not found")
        fp.write_text(new, encoding="utf-8")
        return f"{p['action']}@{p['ref']} -> {p['sha'][:12]} ({n} place(s))"
    raise RuntimeError(f"no handler for {t}")



def progress(run_dir: Path, stage: str, **kw) -> None:
    """Live progress for the monitor page: runs/<repo>/progress.json, rewritten after every step."""
    f = run_dir / "progress.json"
    try:
        cur = json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}
    except (OSError, ValueError):
        cur = {}
    if stage == "start":
        cur = {"stage": "apply", "started": time.strftime("%H:%M:%S"), "plan_hash": kw.get("plan_hash", ""),
               "actions": {a: {"status": "pending"} for a in kw.get("actions", [])}, "lockfiles": [], "events": []}
    else:
        cur["stage"] = stage
        if "action" in kw:
            cur.setdefault("actions", {}).setdefault(kw["action"], {}).update(
                {"status": kw.get("status", ""), "detail": kw.get("detail", ""), "at": time.strftime("%H:%M:%S")})
        if "lockfile" in kw:
            cur.setdefault("lockfiles", []).append(kw["lockfile"])
    if kw.get("event"):
        cur.setdefault("events", []).append(f"{time.strftime('%H:%M:%S')}  {kw['event']}")
    f.write_text(json.dumps(cur, indent=1), encoding="utf-8")

def run(run_dir: Path, dry_run: bool = False, log=print) -> dict:
    plan = json.loads((run_dir / "plan.json").read_text(encoding="utf-8"))
    trail = run_dir / "audit.jsonl"
    try:
        ap = preflight(run_dir, plan)
    except Refused as e:
        audit.log(trail, "apply_refused", {"reason": str(e)})
        log(f"[apply] REFUSED: {e}")
        raise
    chosen = [a for a in plan["actions"] if a["id"] in ap["approved_actions"]]
    if dry_run:
        log(f"[apply] dry run - would apply {len(chosen)} action(s): " + ", ".join(a["id"] for a in chosen))
        return {"dry_run": True, "actions": [a["id"] for a in chosen]}
    src = Path(plan["repo_path"])
    sb = run_dir / "sandbox" / src.name
    if sb.exists():
        shutil.rmtree(sb, onerror=lambda f, p, e: (os.chmod(p, 0o700), f(p)))
    progress(run_dir, "start", plan_hash=plan["plan_hash"], actions=[a["id"] for a in chosen],
             event=f"approval by {ap['operator']} verified (plan {plan['plan_hash'][:12]}); copying sandbox")
    log(f"[apply] sandbox copy -> {sb}")
    shutil.copytree(src, sb, ignore=COPY_IGNORE)
    _git(sb, "init", "-q", "-b", "main")
    _git(sb, "add", "-A")
    _git(sb, "commit", "-q", "-m", "baseline (scanned state)")
    branch = f"guardian/remediation-{plan['plan_hash'][:8]}"
    _git(sb, "checkout", "-q", "-b", branch)
    results, touched_npm = [], set()
    for a in chosen:
        if (run_dir / "STOP").exists():
            log("[apply] kill switch activated mid-run - stopping")
            results.append({"id": a["id"], "status": "skipped", "detail": "kill switch"})
            progress(run_dir, "apply", action=a["id"], status="skipped", detail="kill switch", event=f"{a['id']} skipped: kill switch")
            continue
        progress(run_dir, "apply", action=a["id"], status="running", event=f"{a['id']} applying {a['type']}")
        try:
            detail = _do(sb, a)
            results.append({"id": a["id"], "type": a["type"], "status": "applied", "detail": detail})
            touched_npm |= set(a["params"].get("manifests", [])) if a["type"].startswith("npm_") else set()
            progress(run_dir, "apply", action=a["id"], status="applied", detail=detail, event=f"{a['id']} applied: {detail}")
            log(f"[apply] {a['id']} {detail}")
        except Exception as e:
            results.append({"id": a["id"], "type": a["type"], "status": "failed", "detail": str(e)})
            progress(run_dir, "apply", action=a["id"], status="failed", detail=str(e), event=f"{a['id']} FAILED: {e}")
            log(f"[apply] {a['id']} FAILED: {e}")
    lock_results = []
    npm = str(NPM) if NPM.exists() else shutil.which("npm")
    if touched_npm:
        progress(run_dir, "lockfiles", event="regenerating lockfiles with --ignore-scripts")
    for m in sorted(touched_npm):
        d = (sb / m).parent
        r = subprocess.run([npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
                            "--legacy-peer-deps"], cwd=d, capture_output=True, text=True)
        lock_results.append({"manifest": m, "ok": r.returncode == 0,
                             "output": (r.stderr or r.stdout).strip().splitlines()[-5:]})
        progress(run_dir, "lockfiles", lockfile={"manifest": m, "ok": r.returncode == 0},
                 event=f"lockfile {m}: {'resolved OK (no scripts run)' if r.returncode == 0 else 'FAILED'}")
        log(f"[apply] lockfile for {m}: {'resolved OK' if r.returncode == 0 else 'FAILED'}")
    _git(sb, "add", "-A")
    msg = "Guardian remediation\n\n" + "\n".join(f"{r['id']}: {r['detail']}" for r in results if r["status"] == "applied") + \
          f"\n\nPlan: {plan['plan_hash']}\nApproved-by: {ap['operator']} ({ap['channel']}, {ap['time']})"
    _git(sb, "commit", "-q", "--allow-empty", "-m", msg)
    patch = _git(sb, "diff", "main", branch, "--", ".", ":(exclude)*package-lock.json")
    (run_dir / "remediation.patch").write_text(patch, encoding="utf-8")
    full = _git(sb, "diff", "--stat", "main", branch)
    out = {"schema": "guardian.apply/v1", "plan_hash": plan["plan_hash"], "sandbox": str(sb), "branch": branch,
           "results": results, "lockfiles": lock_results, "diffstat": full,
           "rollback": f"discard the sandbox, or: git -C \"{sb}\" checkout main", "approved_by": ap["operator"]}
    (run_dir / "apply.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    progress(run_dir, "applied", event=f"remediation.patch written on branch {branch}; next: validate (rescan)")
    audit.log(trail, "apply_done", {"branch": branch, "applied": [r["id"] for r in results if r["status"] == "applied"],
                                    "failed": [r["id"] for r in results if r["status"] == "failed"]})
    return out
