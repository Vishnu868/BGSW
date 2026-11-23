"""Symbolic rules: hard constraints that no agent can override."""
from __future__ import annotations

from ..detect.osv import vkey

VERDICTS = {"confirmed_risk", "likely_false_positive", "needs_human_review"}
EXPLOITABLE = {"yes", "no", "unknown"}
SPECIALIST_ACTIONS = {"upgrade", "replace", "pin", "remove", "block", "escalate", "accept"}
REMEDIATION_ACTIONS = {
    "npm_upgrade_direct": "Upgrade a direct npm dependency in package.json",
    "npm_override_transitive": "Force a safe version of a transitive npm dependency (package.json overrides)",
    "npm_replace": "Replace a package (e.g. typosquat -> genuine) in package.json and its import statements",
    "npm_remove": "Remove an unused direct npm dependency",
    "pypi_upgrade": "Pin a Python requirement to a fixed version",
    "docker_pin_digest": "Pin a container base image to its sha256 digest",
    "action_pin_sha": "Pin a GitHub Action to a full commit SHA",
    "block": "Block the change/component (policy deny, no file change)",
    "escalate": "Escalate for security review (no automatic change)",
}
REQUIRED_PARAMS = {
    "npm_upgrade_direct": ("package", "to"), "npm_override_transitive": ("package", "to"),
    "npm_replace": ("package", "with", "version"), "npm_remove": ("package",), "pypi_upgrade": ("package", "to"),
    "docker_pin_digest": ("file", "image", "digest"), "action_pin_sha": ("file", "action", "ref", "sha"),
    "block": (), "escalate": (),
}
MAX_SCORE_ADJUST = 20          # how far the lead agent may move the symbolic score
REVIEW_CONFIDENCE = 0.6        # below this -> human review
BAND = [(80, "P1", "fix now"), (60, "P2", "fix this sprint"), (35, "P3", "plan"), (0, "P4", "accept / monitor")]


def band(score: float) -> tuple[str, str]:
    for lo, p, label in BAND:
        if score >= lo:
            return p, label
    return "P4", "accept / monitor"


def major(v: str) -> int:
    k = vkey(v)
    return k[0] if k else 0


def compatibility(cur: str, target: str) -> dict:
    if not cur or not target:
        return {"level": "unknown", "reason": "version information incomplete"}
    if major(target) > major(cur):
        return {"level": "major", "reason": f"major version change {cur} -> {target}: breaking API changes likely, run full tests"}
    if major(cur) == 0 and vkey(target)[:2] > vkey(cur)[:2]:
        return {"level": "major", "reason": f"{cur} -> {target}: in 0.x versions a minor bump may break the API (semver), run full tests"}
    if vkey(target)[:2] > vkey(cur)[:2]:
        return {"level": "minor", "reason": f"minor version change {cur} -> {target}"}
    return {"level": "patch", "reason": f"patch-level change {cur} -> {target}"}


def version_ok(target: str, need: str, published: list[str] | None) -> tuple[bool, str]:
    if published is not None and target not in published:
        return False, f"version {target} does not exist in the registry"
    if need and vkey(target) < vkey(need):
        return False, f"version {target} is below the fixed version {need}"
    return True, ""
