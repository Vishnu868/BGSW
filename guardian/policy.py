"""Policy-as-code (stretch goal): a CI gate that blocks unsafe components or builds.

Rules live in config/policy.json (data, reviewable in PRs). `guardian policy <repo>` exits 1 on any
violation, so it can run as a required CI check.
"""
from __future__ import annotations

import json
from pathlib import Path

from .model import SEVERITY_RANK

DEFAULT = Path(__file__).resolve().parents[1] / "config" / "policy.json"


def evaluate(run_dir: Path, policy_file: Path = DEFAULT) -> dict:
    pol = json.loads(policy_file.read_text(encoding="utf-8"))
    doc = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    violations = []
    allow_scripts = set(pol.get("allowed_install_scripts", []))
    deny = set(pol.get("denied_packages", []))
    for f in doc["findings"]:
        cd = f.get("component_detail") or {}
        prod = not cd.get("dev_only", False)
        name = cd.get("name", "")
        if f["category"] in ("1.1", "1.2") and SEVERITY_RANK[f["severity"]] >= SEVERITY_RANK[pol["max_vuln_severity_production"]] + 1 and prod:
            violations.append(("vulnerability-in-production", f))
        if f["category"] == "1.3" and pol.get("block_typosquats", True):
            violations.append(("suspected-typosquat-or-malicious", f))
        if f["rule"].startswith("diff.tampered") or f["rule"] in ("lockfile.untrusted-registry", "lockfile.integrity-conflict"):
            violations.append(("lockfile-integrity", f))
        if f["rule"] == "packages.install-script" and name not in allow_scripts and pol.get("block_unlisted_install_scripts"):
            violations.append(("install-script-not-allow-listed", f))
        if f["rule"] == "cicd.unpinned-action" and f["severity"] == "high" and pol.get("require_sha_pinned_third_party_actions", True):
            violations.append(("unpinned-third-party-action", f))
        if f["rule"] == "container.unpinned" and pol.get("require_image_digests"):
            violations.append(("unpinned-container-image", f))
        if name in deny:
            violations.append(("denied-package", f))
    out = {"policy": str(policy_file), "passed": not violations, "violations": [
        {"rule": r, "finding": f["id"], "severity": f["severity"], "title": f["title"]} for r, f in violations]}
    (run_dir / "policy.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    return out
