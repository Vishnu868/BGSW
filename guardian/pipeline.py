"""Day 1 pipeline: discover -> detect -> report. Works on any local folder or git URL."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .discover import discover
from .model import CATEGORIES, SEVERITY_RANK, Component
from .report import html as html_report
from .report import sbom as sbom_out
from .report import text as text_report

ROOT = Path(__file__).resolve().parents[1]
NPM = ROOT / "tools" / "node" / "npm.cmd"


GITHUB = re.compile(r"^(?:https://github\.com/|git@github\.com:)([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")


def parse_github(url: str) -> tuple[str, str] | None:
    """'https://github.com/owner/repo(.git)' or 'git@github.com:owner/repo.git' -> (owner, repo); else None."""
    m = GITHUB.match((url or "").strip())
    return (m.group(1), m.group(2)) if m else None


def _git_out(repo: Path, *args) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ""


def fetch(target: str, workdir: Path) -> Path:
    """Local path -> itself. Git URL -> shallow clone into targets/ (read-only use).
    An existing clone of the same repository is refreshed to the remote's current commit, so a GitHub link always
    scans (and later opens its pull request against) what is on GitHub now."""
    if re.match(r"^(https?://|git@)", target):
        gh = parse_github(target)
        name = gh[1] if gh else re.sub(r"\.git$", "", target.rstrip("/").split("/")[-1])
        dest = workdir / name
        cur = parse_github(_git_out(dest, "remote", "get-url", "origin")) if dest.exists() else None
        if gh and cur and tuple(x.lower() for x in cur) != tuple(x.lower() for x in gh):
            dest = workdir / f"{gh[0]}-{gh[1]}"           # same repo name, different owner: keep both
        if not dest.exists():
            subprocess.run(["git", "clone", "--depth", "1", target, str(dest)], check=True)
        elif (dest / ".git").exists():
            r = subprocess.run(["git", "-C", str(dest), "fetch", "-q", "--depth", "1", "origin", "HEAD"],
                               capture_output=True, text=True)
            if r.returncode == 0:
                subprocess.run(["git", "-C", str(dest), "reset", "-q", "--hard", "FETCH_HEAD"], check=True)
        return dest
    p = Path(target).resolve()
    if not p.is_dir():
        raise SystemExit(f"not a folder or git URL: {target}")
    return p


def source_info(repo: Path) -> dict:
    """Where the scanned code came from: GitHub owner/name, branch and exact commit (empty for a plain folder).
    The pull-request step uses it to open the PR against the same repository and commit."""
    url = _git_out(repo, "remote", "get-url", "origin")
    gh = parse_github(url)
    if not gh:
        return {"type": "folder", "url": url}
    branch = _git_out(repo, "rev-parse", "--abbrev-ref", "HEAD")
    remote_head = _git_out(repo, "symbolic-ref", "--short", "refs/remotes/origin/HEAD")
    return {"type": "github", "url": f"https://github.com/{gh[0]}/{gh[1]}", "owner": gh[0], "name": gh[1],
            "full_name": f"{gh[0]}/{gh[1]}", "commit": _git_out(repo, "rev-parse", "HEAD"),
            "branch": remote_head.split("/", 1)[1] if remote_head.startswith("origin/") else (branch if branch != "HEAD" else "")}


def ensure_npm_locks(repo: Path, log) -> list[str]:
    """npm projects without a lockfile: resolve one with --ignore-scripts (no package code runs)."""
    made = []
    npm = str(NPM) if NPM.exists() else shutil.which("npm")
    if not npm:
        return made
    from .discover import walk
    for pj in walk(repo):
        if pj.name != "package.json" or (pj.parent / "package-lock.json").exists():
            continue
        if "dependencies" not in pj.read_text(encoding="utf-8", errors="replace"):
            continue
        log(f"  generating lockfile for {pj.relative_to(repo).as_posix()} (npm --package-lock-only --ignore-scripts)")
        r = subprocess.run([npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
                            "--legacy-peer-deps"], cwd=pj.parent, capture_output=True, text=True, shell=False)
        if r.returncode == 0:
            made.append(pj.relative_to(repo).as_posix())
    return made


def run(target: str, out_root: Path, offline: bool = False, baseline: Path | None = None,
        gen_locks: bool = True, scanners: str = "auto", images: bool = False, log=print) -> Path:
    """scanners: "auto" (dynamic: OSV first, then Trivy/Grype only where they add something - confirm OSV's flagged
    components, scan folders outside OSV coverage, full cross-check for small repos), "full" (all tools on the whole
    repository), "osv", or e.g. "osv,trivy,grype".
    images: also let Trivy scan the container base images named in Dockerfiles (downloads image layers)."""
    from .detect import cicd, container, lockfile, osv, packages
    from .detect import scanners as ext
    repo = fetch(target, ROOT / "targets")
    import os
    os.environ["GUARDIAN_OFFLINE"] = "1" if offline else "0"
    out = out_root / repo.name
    out.mkdir(parents=True, exist_ok=True)
    log(f"[1/4] Discover  {repo}")
    generated = ensure_npm_locks(repo, log) if gen_locks and not offline else []
    inv = discover(repo)
    g = inv.graph
    from .discover.resolve import expand
    n = expand(g, offline=offline)
    if n:
        log(f"      resolved {n} transitive components via deps.dev (no lockfile in those projects)")
    # one top node for the repository: projects, container images and CI actions hang under it
    repo_id = f"repo:{repo.name}"
    g.add(Component(id=repo_id, name=repo.name, version="", ecosystem="", kind="repository"), dev=False)
    for r in g.roots:
        g.link(repo_id, r)
    g.roots = [repo_id] + g.roots

    log(f"      {sum(c.kind == 'library' for c in g.nodes.values())} components, {len(g.edges)} edges, "
        f"{len(inv.dockerfiles)} Dockerfiles, {len(inv.workflows)} workflows")
    log("[2/4] Detect    vulnerabilities (OSV.dev)")
    findings, osv_status = osv.scan(g, offline=offline)
    log(f"      OSV: {osv_status['vulnerable_components']} vulnerable components, {osv_status['advisories']} advisories")
    # dynamic scanner selection: what Discover + OSV found decides which external scanner looks at what
    plan = ext.make_plan(g, repo, findings, scanners)
    for line in ext.describe(plan):
        log(f"      {line}")
    scanner_status = {"osv": "ok", "ran": ["osv"], "plan": {k: v for k, v in plan.items() if k != "flagged_ids"}}
    imgs = sorted({c.name for c in g.nodes.values() if c.kind == "container"}) if images else []
    if plan["steps"] or imgs:
        extra, scanner_status = ext.scan(g, repo, findings, repo_id, out / "scanners", offline=offline,
                                         plan=plan, images=imgs, log=log)
        findings += extra
    log("      supply-chain checks: packages, lockfiles, containers, CI/CD")
    findings += packages.scan(g, inv, offline=offline)
    findings += lockfile.scan(g, inv)
    findings += container.scan(g, inv, repo_id)
    findings += cicd.scan(g, inv, repo_id)
    findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], -float(f.data.get("cvss", 0) or 0), f.title))

    log("[3/4] Compare   with baseline")
    prev = baseline or (out / "sbom.cdx.json" if (out / "sbom.cdx.json").exists() else None)
    changes = lockfile.diff(prev, g) if prev else {}
    findings += lockfile.findings_from_changes(changes)
    findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], -float(f.data.get("cvss", 0) or 0), f.title))
    if prev and not baseline:
        shutil.copy(prev, out / "sbom.previous.cdx.json")

    log("[4/4] Report")
    meta = {"repo": repo.name, "path": str(repo), "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "osv_source": osv_status["source"], "osv": osv_status, "categories": CATEGORIES,
            "scanners": scanner_status,
            "ecosystems": sorted({c.ecosystem for c in g.nodes.values() if c.kind == "library"}),
            "files": {**inv.files_seen, "dockerfiles": [p.relative_to(repo).as_posix() for p in inv.dockerfiles],
                      "compose": [p.relative_to(repo).as_posix() for p in inv.compose_files],
                      "workflows": [p.relative_to(repo).as_posix() for p in inv.workflows]},
            "generated_lockfiles": generated, "source": source_info(repo)}
    (out / "sbom.cdx.json").write_text(json.dumps(sbom_out.cyclonedx(g, findings, meta), indent=1), encoding="utf-8")
    report = text_report.findings_json(g, findings, meta, changes)
    (out / "findings.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    (out / "report.txt").write_text(text_report.markdown(report), encoding="utf-8")
    page_data = html_report.build_data(g, findings, meta, changes)
    (out / "graph_data.json").write_text(json.dumps(page_data, default=str), encoding="utf-8")
    (out / "guardian.html").write_text(html_report.render(page_data), encoding="utf-8")
    log(text_report.console_summary(report))
    log(f"Outputs: {out}  (guardian.html, findings.json, report.txt, sbom.cdx.json)")
    return out
