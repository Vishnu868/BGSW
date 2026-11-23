"""Category 1.7 - GitHub Actions workflows: unpinned actions, token permissions, risky triggers, script injection."""
from __future__ import annotations

import re

from ..model import Component, Finding, Graph

USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)")
SHA = re.compile(r"^[0-9a-f]{40}$")
FIRST_PARTY = ("actions/", "github/")
# untrusted, attacker-controllable event fields used inside ${{ }} (script injection)
INJECT = re.compile(r"\$\{\{\s*github\.(head_ref|event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages)"
                    r"[\w.\[\]*]*\.(title|body|head_ref|ref|label|message|name|email|default_branch))", re.I)


def scan(graph: Graph, inv, repo_id: str) -> list[Finding]:
    out: list[Finding] = []
    repo = inv.repo
    for wf in inv.workflows:
        rel = wf.relative_to(repo).as_posix()
        text = wf.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        has_perms = re.search(r"^permissions:", text, re.M) is not None
        prt = re.search(r"\bpull_request_target\b", text) is not None
        run_indent = None
        for i, raw in enumerate(lines, 1):
            indent = len(raw) - len(raw.lstrip(" -"))
            if run_indent is not None and raw.strip() and indent <= run_indent:
                run_indent = None
            in_run = run_indent is not None or re.match(r"^\s*-?\s*run:", raw) is not None
            if re.match(r"^\s*-?\s*run:\s*[|>]", raw):
                run_indent = indent
            m = USES.match(raw)
            if m:
                ref = m.group(1)
                if ref.startswith("./"):
                    continue
                if ref.startswith("docker://"):
                    if "@sha256:" not in ref:
                        out.append(Finding("1.7", "medium", f"Workflow runs container '{ref}' without a digest pin",
                                           rule="cicd.unpinned-docker",
                                           evidence=[{"source": "workflow", "detail": raw.strip(), "file": rel, "line": i}],
                                           recommendation="Pin docker:// images by sha256 digest"))
                    continue
                action, _, version = ref.partition("@")
                cid = f"action:{action}@{version}"
                graph.add(Component(id=cid, name=action, version=version[:12], ecosystem="github-actions", kind="action"), dev=False)
                graph.link(repo_id, cid)
                if not SHA.match(version):
                    third = not action.startswith(FIRST_PARTY)
                    out.append(Finding("1.7", "high" if third else "medium",
                                       f"{'Third-party' if third else 'GitHub'} action {action} pinned to mutable ref '{version or '(none)'}'",
                                       component=cid, rule="cicd.unpinned-action",
                                       evidence=[{"source": "workflow", "detail": raw.strip(), "file": rel, "line": i}],
                                       recommendation=f"Pin {action} to a full commit SHA (keep the tag as a comment)"))
            if re.match(r"^\s*permissions:\s*write-all", raw):
                out.append(Finding("1.7", "high", f"Workflow grants write-all token permissions: {rel}", rule="cicd.write-all",
                                   evidence=[{"source": "workflow", "detail": raw.strip(), "file": rel, "line": i}],
                                   recommendation="Grant only the scopes each job needs (e.g. contents: read)"))
            if INJECT.search(raw) and in_run:
                out.append(Finding("1.7", "high", f"Possible script injection from untrusted event data in {rel}",
                                   rule="cicd.script-injection",
                                   evidence=[{"source": "workflow", "detail": raw.strip()[:200], "file": rel, "line": i}],
                                   recommendation="Pass the value through an env: variable and quote it in the script"))
            if prt and re.search(r"github\.event\.pull_request\.head\.(sha|ref)", raw):
                out.append(Finding("1.7", "high", f"pull_request_target checks out untrusted PR code in {rel}",
                                   rule="cicd.prt-checkout",
                                   evidence=[{"source": "workflow", "detail": raw.strip(), "file": rel, "line": i}],
                                   recommendation="Use pull_request, or never run code from the PR head with secrets available"))
        if not has_perms:
            out.append(Finding("1.7", "low", f"No top-level token permissions declared in {rel}", rule="cicd.default-permissions",
                               evidence=[{"source": "workflow", "detail": "GITHUB_TOKEN gets the repository default scopes", "file": rel}],
                               recommendation="Add `permissions: contents: read` at the top and widen per job"))
    return out
