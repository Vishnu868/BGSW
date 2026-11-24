"""Stage 6 - Publish: open a pull request on the scanned GitHub repository with the approved, validated fixes.

    python -m guardian pr <repo> [--dry-run] [--draft] [--yes] [--force]

What it does
  1. Checks: the scan came from GitHub; the plan was approved and not changed since (same SHA-256 hash); `apply`
     ran; `validate` did not fail (unless --force); the kill switch is off.
  2. Takes the sandbox's changes (only the approved actions, lockfiles included) and replays them on a new branch
     cut from the exact commit that was scanned, in a separate git worktree. The scanned clone is not touched.
  3. Shows the target repository, branch, changed files and PR text, and asks for a final yes (unless --yes).
  4. Pushes the branch: straight to the repository if your GitHub account may push there, otherwise to your fork
     (created with `gh repo fork` if needed), and opens the PR with `gh pr create`.
Needs the GitHub CLI logged in (`gh auth login`). Commits use your GitHub no-reply address, so a private e-mail
setting never blocks the push. --dry-run builds the branch and writes pr_preview.md, but pushes nothing.
Output: runs/<repo>/pr.json (+ audit trail entry); the PR description says what changed, why, and how it was checked.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from .. import audit
from .planner import plan_hash


class Refused(Exception):
    pass


def _run(args: list, cwd: Path | None = None, check: bool = True, input_: str | None = None) -> str:
    r = subprocess.run(args, cwd=cwd, capture_output=True, text=True, input=input_)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(str(a) for a in args[:4])}: {(r.stderr or r.stdout).strip()[:400]}")
    return r.stdout.strip()


def _gh(*args, check: bool = True) -> str:
    if not shutil.which("gh"):
        raise Refused("the GitHub CLI is not installed - install it (e.g. `sudo apt install gh`) and run `gh auth login`")
    return _run(["gh", *args], check=check)


def _load(run_dir: Path, name: str) -> dict | None:
    f = run_dir / name
    return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None


# ------------------------------------------------------------------------------------------------- checks ---
def preflight(run_dir: Path, force: bool = False) -> dict:
    doc, plan = _load(run_dir, "findings.json"), _load(run_dir, "plan.json")
    if (run_dir / "STOP").exists() or os.environ.get("GUARDIAN_KILL") == "1":
        raise Refused("kill switch is active (STOP file or GUARDIAN_KILL=1)")
    src = (doc or {}).get("repository", {}).get("source") or {}
    if src.get("type") != "github" or not src.get("commit"):
        raise Refused("this scan did not come from a GitHub repository - scan a GitHub link to get a pull request")
    if not plan:
        raise Refused("no plan - run `guardian plan` first")
    ap = _load(run_dir, "approval.json")
    if not ap or ap.get("plan_hash") != plan["plan_hash"] or plan_hash(plan["actions"]) != plan["plan_hash"]:
        raise Refused("no valid approval for the current plan - run `guardian approve` first")
    applied = _load(run_dir, "apply.json")
    if not applied or applied.get("plan_hash") != plan["plan_hash"]:
        raise Refused("the approved plan was not applied - run `guardian apply` first")
    if not any(r["status"] == "applied" and r.get("type") not in ("block", "escalate") for r in applied["results"]):
        raise Refused("no file was changed (only block/escalate actions) - nothing to put in a pull request")
    val = _load(run_dir, "validation.json")
    if not val:
        raise Refused("the fixes were not validated - run `guardian validate` first")
    if val["verdict"] == "failed" and not force:
        raise Refused("validation FAILED (new critical/high findings or a failed check) - fix the plan, "
                      "or pass --force to open the PR anyway")
    return {"doc": doc, "plan": plan, "approval": ap, "apply": applied, "validation": val, "source": src}


# ----------------------------------------------------------------------------------------------- PR text ---
def pr_text(ctx: dict, analysis: dict | None) -> tuple[str, str]:
    plan, ap, val, src = ctx["plan"], ctx["approval"], ctx["validation"], ctx["source"]
    applied = {r["id"]: r for r in ctx["apply"]["results"] if r["status"] == "applied"}
    acts = [a for a in plan["actions"] if a["id"] in applied]
    changes = [a for a in acts if a["type"] not in ("block", "escalate")]
    items = {i["id"]: i for i in (analysis or {}).get("items", [])}
    per = {p["id"]: p for p in val.get("per_action", [])}
    resolved = len(val.get("resolved") or []) or sum(p["resolved"] for p in per.values())
    title = (f"Security: fix {resolved or len(changes)} supply-chain "
             f"finding{'s' if (resolved or len(changes)) != 1 else ''} "
             f"({', '.join(sorted({a['priority'] for a in changes}))})")
    L = ["## What this changes", "",
         f"Automated, human-approved dependency fixes for `{src['full_name']}` at commit `{src['commit'][:12]}`, "
         f"found and checked by Software Supply Chain Guardian.", "",
         "| Fix | Change | Risk | Priority | Compatibility | Validation |", "|---|---|---|---|---|---|"]
    for a in changes:
        p = a["params"]
        what = (f"`{p.get('package', '')}` {p.get('from', '')} → {p.get('to', '')}" if p.get("to") else
                f"`{p.get('image') or p.get('action') or p.get('package', '')}`")
        L.append(f"| {a['id']} {a['type']} | {what.strip()} | {a['risk'][:90].replace('|', '/')} | {a['priority']} "
                 f"(score {a['score']}) | {a['compatibility']['level']} | {per.get(a['id'], {}).get('status', '-')} |")
    L += ["", "## Why", ""]
    for a in changes:
        it = items.get(a["risk_item"], {})
        n = it.get("neurosymbolic") or {}
        line = f"- **{a['id']}** {a['rationale']}"
        if n:
            line += f" Priority {n.get('priority')} with {n.get('confidence_label')} confidence: {n.get('why')}"
        L.append(line)
    other = [a for a in acts if a["type"] in ("block", "escalate")]
    if other:
        L += ["", "Not changed in this PR, need a human decision:"] + \
             [f"- {a['id']} {a['type']}: {a['risk'][:120]}" for a in other]
    L += ["", "## How it was checked", "",
          f"- Validation verdict: **{val['verdict']}**: {resolved} targeted finding(s) resolved, "
          f"{len(val.get('new_findings') or [])} new finding(s) after a full rescan "
          f"({val['before']['findings']} → {val['after']['findings']} findings in total)."]
    names = {"resolve": "lockfiles resolve", "test": "project tests"}
    for k, c in (val.get("checks") or {}).items():
        L.append(f"- {names.get(k, k.replace('install:', 'clean install of '))}: {'passed' if c.get('ok') else 'FAILED'}")
    L += [f"- Only allow-listed change types; lockfiles regenerated with `--ignore-scripts` (no package code ran).",
          f"- Approved by **{ap['operator']}** ({ap['channel']}, {ap['time']}) for plan `{plan['plan_hash'][:12]}`.",
          "", "## Before merging", "",
          "- Run the project's own test suite; major version changes are marked in the table.",
          "- Rollback: revert this PR.", "",
          "*Opened by Software Supply Chain Guardian. Findings are deterministic scanner evidence; priorities come from "
          "its neurosymbolic rules; AI agents only advised and were checked by a symbolic verifier.*"]
    return title, "\n".join(L) + "\n"


# ------------------------------------------------------------------------------------------------- branch ---
def _identity() -> tuple[str, str, str]:
    """(login, name, no-reply e-mail) of the logged-in GitHub account."""
    me = json.loads(_gh("api", "user"))
    return me["login"], me.get("name") or me["login"], f"{me['id']}+{me['login']}@users.noreply.github.com"


def build_branch(run_dir: Path, ctx: dict, title: str, ident: tuple[str, str, str]) -> dict:
    """Replay the sandbox's change on a branch cut from the scanned commit, in runs/<repo>/pr-worktree."""
    clone = Path(ctx["doc"]["repository"]["path"])
    sb, branch = Path(ctx["apply"]["sandbox"]), ctx["apply"]["branch"]
    patch = _run(["git", "-C", str(sb), "diff", "--binary", "main", branch]) + "\n"
    if not patch.strip():
        raise Refused("the sandbox branch has no file changes")
    wt = run_dir / "pr-worktree"
    _run(["git", "-C", str(clone), "worktree", "prune"], check=False)
    if wt.exists():
        _run(["git", "-C", str(clone), "worktree", "remove", "--force", str(wt)], check=False)
        shutil.rmtree(wt, ignore_errors=True)
    _run(["git", "-C", str(clone), "worktree", "add", "-q", "-f", "-B", branch, str(wt), ctx["source"]["commit"]])
    _run(["git", "apply", "--index", "--whitespace=nowarn", "-"], cwd=wt, input_=patch)
    login, name, email = ident
    _run(["git", "-c", f"user.name={name}", "-c", f"user.email={email}", "commit", "-q", "-m",
          f"{title}\n\nApplied by Software Supply Chain Guardian (plan {ctx['plan']['plan_hash'][:12]}, "
          f"approved by {ctx['approval']['operator']})."], cwd=wt)
    stat = _run(["git", "diff", "--stat", "HEAD~1", "HEAD"], cwd=wt)
    return {"worktree": str(wt), "branch": branch, "commit": _run(["git", "rev-parse", "HEAD"], cwd=wt), "diffstat": stat}


def push_target(src: dict, login: str, log) -> tuple[str, str]:
    """-> (git URL to push to, 'owner:branch' prefix owner). Your own push access first, else your fork."""
    perm = _gh("api", f"repos/{src['full_name']}", "--jq", ".permissions.push", check=False)
    if perm == "true":
        return f"https://github.com/{src['full_name']}.git", src["owner"]
    forks = _gh("api", f"repos/{src['full_name']}/forks", "--paginate", "--jq",
                f'.[] | select(.owner.login == "{login}") | .full_name', check=False).splitlines()
    if forks:
        fork = forks[0]
        _gh("repo", "sync", fork, "--source", src["full_name"], check=False)     # stale fork may lack the commit
    else:
        log(f"[pr] no push access to {src['full_name']} - forking it to {login}")
        _gh("repo", "fork", src["full_name"], "--clone=false", "--default-branch-only")
        fork = f"{login}/{src['name']}"
    return f"https://github.com/{fork}.git", fork.split("/")[0]


# ---------------------------------------------------------------------------------------------------- run ---
def run(run_dir: Path, dry_run: bool = False, draft: bool = False, yes: bool = False, force: bool = False,
        ask=input, log=print) -> dict:
    trail = run_dir / "audit.jsonl"
    try:
        ctx = preflight(run_dir, force)
    except Refused as e:
        audit.log(trail, "pr_refused", {"reason": str(e)})
        log(f"[pr] REFUSED: {e}")
        raise
    src = ctx["source"]
    title, body = pr_text(ctx, _load(run_dir, "analysis.json"))
    try:
        ident = _identity()
    except (Refused, RuntimeError, KeyError, ValueError):
        if not dry_run:
            raise Refused("the GitHub CLI is not logged in - run `gh auth login`") from None
        ident = ("you", "Guardian (dry run)", "guardian@localhost")
    try:
        br = build_branch(run_dir, ctx, title, ident)
    except RuntimeError as e:
        audit.log(trail, "pr_failed", {"stage": "branch", "error": str(e)})
        raise Refused(f"could not rebuild the change on {src['full_name']}@{src['commit'][:12]}: {e}") from None
    (run_dir / "pr_preview.md").write_text(f"# {title}\n\n{body}", encoding="utf-8")
    base = src.get("branch") or "main"
    log(f"[pr] target   : {src['url']} (base {base}, scanned commit {src['commit'][:12]})")
    log(f"[pr] branch   : {br['branch']} ({br['commit'][:12]})\n{br['diffstat']}")
    log(f"[pr] title    : {title}")
    log(f"[pr] text     : {run_dir / 'pr_preview.md'}")
    if dry_run:
        audit.log(trail, "pr_dry_run", {"branch": br["branch"], "commit": br["commit"]})
        log("[pr] dry run - nothing pushed")
        return {"dry_run": True, **br, "title": title}
    if not yes:
        ans = ask(f"Push this branch and open a pull request on {src['full_name']}? [y/N]: ").strip().lower()
        if ans not in ("y", "yes"):
            audit.log(trail, "pr_declined", {"branch": br["branch"]})
            log("[pr] not published")
            return {"published": False, **br}
    login = ident[0]
    remote, head_owner = push_target(src, login, log)
    try:
        _run(["git", "push", "-q", "--force-with-lease", remote, f"HEAD:refs/heads/{br['branch']}"], cwd=Path(br["worktree"]))
    except RuntimeError as e:
        audit.log(trail, "pr_failed", {"stage": "push", "error": str(e)})
        raise Refused(f"push to {remote} failed: {e}") from None
    head = br["branch"] if head_owner == src["owner"] else f"{head_owner}:{br['branch']}"
    existing = _gh("pr", "list", "--repo", src["full_name"], "--head", br["branch"], "--state", "open",
                   "--json", "url", "--jq", ".[0].url", check=False)
    if existing:
        url = existing
        log(f"[pr] updated the existing pull request {url}")
    else:
        args = ["pr", "create", "--repo", src["full_name"], "--base", base, "--head", head, "--title", title,
                "--body-file", str(run_dir / "pr_preview.md")] + (["--draft"] if draft else [])
        url = _gh(*args).splitlines()[-1]
        log(f"[pr] opened {url}")
    out = {"schema": "guardian.pr/v1", "url": url, "repository": src["full_name"], "base": base, "head": head,
           "commit": br["commit"], "title": title, "draft": draft, "plan_hash": ctx["plan"]["plan_hash"],
           "validation": ctx["validation"]["verdict"], "opened_by": login}
    (run_dir / "pr.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    audit.log(trail, "pr_opened", {k: out[k] for k in ("url", "repository", "head", "commit", "plan_hash")})
    return out
