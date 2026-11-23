"""Stage 5 - Validate: build, test and rescan the remediated sandbox, then compare before vs after.

Checks (each recorded with its output):
  resolve   lockfiles regenerated without conflicts (from apply)
  install   npm ci --ignore-scripts / pip install --dry-run   (optional: --install)
  test      a project test command, e.g. "npm test"           (optional: --test-cmd)
  rescan    full Guardian scan of the sandbox with the original SBOM as baseline
Verdict:
  verified  every targeted finding is gone, no new critical/high finding, all checks passed
  partial   some targeted findings remain or an optional check failed
  failed    new critical/high findings or a required check failed -> roll back
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

from .. import audit
from ..model import SEVERITY_RANK
from ..pipeline import NPM, run as scan


def _key(f: dict) -> tuple:
    cd = f.get("component_detail") or {}
    return (f["rule"], cd.get("name") or f["title"], f["data"].get("vuln_id", "") or "")


def _run(cmd, cwd: Path, timeout: int) -> dict:
    t0 = time.time()
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, shell=isinstance(cmd, str))
        return {"ok": r.returncode == 0, "exit_code": r.returncode, "seconds": round(time.time() - t0, 1),
                "output": ((r.stdout or "") + (r.stderr or "")).strip().splitlines()[-15:]}
    except subprocess.TimeoutExpired:
        return {"ok": False, "exit_code": None, "seconds": timeout, "output": [f"timed out after {timeout}s"]}


def run(run_dir: Path, install: bool = False, test_cmd: str = "", timeout: int = 900, log=print) -> dict:
    ap = json.loads((run_dir / "apply.json").read_text(encoding="utf-8"))
    plan = json.loads((run_dir / "plan.json").read_text(encoding="utf-8"))
    before = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    sb = Path(ap["sandbox"])
    trail = run_dir / "audit.jsonl"
    checks = {"resolve": {"ok": all(l["ok"] for l in ap["lockfiles"]) if ap["lockfiles"] else True,
                          "detail": ap["lockfiles"] or "no npm manifests changed"}}
    npm = str(NPM) if NPM.exists() else shutil.which("npm")
    if install:
        for l in ap["lockfiles"]:
            d = (sb / l["manifest"]).parent
            log(f"[validate] npm ci --ignore-scripts in {l['manifest']} (may take a few minutes)")
            checks[f"install:{l['manifest']}"] = _run([npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund",
                                                       "--legacy-peer-deps"], d, timeout)
    if test_cmd:
        log(f"[validate] running tests: {test_cmd}")
        checks["test"] = _run(test_cmd, sb, timeout)

    log("[validate] rescanning the remediated sandbox")
    after_root = run_dir / "after"
    out = scan(str(sb), after_root, offline=False, baseline=run_dir / "sbom.cdx.json", gen_locks=False,
               log=lambda m: None)
    after = json.loads((out / "findings.json").read_text(encoding="utf-8"))

    b = {_key(f): f for f in before["findings"]}
    a = {_key(f): f for f in after["findings"]}
    resolved = [b[k] for k in b if k not in a]
    remaining = [b[k] for k in b if k in a]
    new = [a[k] for k in a if k not in b and not a[k]["rule"].startswith("diff.")]
    approved = set(json.loads((run_dir / "approval.json").read_text(encoding="utf-8"))["approved_actions"])
    applied = {r["id"] for r in ap["results"] if r["status"] == "applied"}
    by_id = {f["id"]: f for f in before["findings"]}
    per_action = []
    for act in plan["actions"]:
        if act["id"] not in approved:
            continue
        targets = [by_id[i] for i in act["finding_ids"] if i in by_id]
        gone = [t for t in targets if _key(t) not in a]
        still = [a[_key(t)] for t in targets if _key(t) in a]
        remaining_detail = [{"finding": s["title"], "now_via": " > ".join((s.get("component_detail") or {}).get("dependency_path", [])[1:]),
                             "follow_up": "the same advisory is still present through a dependency of the upgraded "
                                          "package - raise that parent to a newer major or override it, then re-validate"}
                            for s in still]
        per_action.append({"id": act["id"], "type": act["type"], "applied": act["id"] in applied,
                           "targeted": len(targets), "resolved": len(gone), "remaining": remaining_detail,
                           "status": ("n/a (no file change)" if act["type"] in ("block", "escalate") else
                                      "verified" if targets and len(gone) == len(targets) else
                                      "partial" if gone else "not resolved")})
    new_bad = [f for f in new if SEVERITY_RANK[f["severity"]] >= 3]
    required_ok = checks["resolve"]["ok"] and all(v.get("ok", True) for k, v in checks.items())
    fixable = [p for p in per_action if p["status"] != "n/a (no file change)"]
    if new_bad or not checks["resolve"]["ok"]:
        verdict = "failed"
    elif fixable and all(p["status"] == "verified" for p in fixable) and required_ok:
        verdict = "verified"
    else:
        verdict = "partial"

    def sev_count(fs):
        return {s: sum(f["severity"] == s for f in fs) for s in ("critical", "high", "medium", "low")}

    res = {"schema": "guardian.validation/v1", "verdict": verdict, "checks": checks, "per_action": per_action,
           "before": {"components": before["summary"]["components"], "findings": len(before["findings"]),
                      "by_severity": sev_count(before["findings"])},
           "after": {"components": after["summary"]["components"], "findings": len(after["findings"]),
                     "by_severity": sev_count(after["findings"])},
           "resolved": [{"id": f["id"], "title": f["title"], "severity": f["severity"]} for f in resolved],
           "new_findings": [{"title": f["title"], "severity": f["severity"], "rule": f["rule"]} for f in new],
           "sbom_changes": {k: len(v) for k, v in (after.get("changes") or {}).items() if isinstance(v, list)},
           "sbom_changes_detail": after.get("changes"),
           "after_report": str(out / "guardian.html"),
           "rollback": ap["rollback"] if verdict == "failed" else "not needed"}
    (run_dir / "validation.json").write_text(json.dumps(res, indent=1, default=str), encoding="utf-8")
    audit.log(trail, "validate_done", {"verdict": verdict, "resolved": len(resolved), "new": len(new)})
    log(f"[validate] verdict: {verdict.upper()} - resolved {len(resolved)} findings, {len(new)} new, "
        f"critical {res['before']['by_severity']['critical']} -> {res['after']['by_severity']['critical']}, "
        f"high {res['before']['by_severity']['high']} -> {res['after']['by_severity']['high']}")
    return res
