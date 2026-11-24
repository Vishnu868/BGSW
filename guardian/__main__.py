"""Software Supply Chain Guardian - CLI

Day 1 (Eyes)            scan      <folder|git-url>   discover components, dependency graph, detect risks
Day 2 (Brain & Shield)  analyze   <repo>             5 agents + symbolic verifier: investigate, triage, critic
                        review    <repo>             human review queue (agents unsure or in disagreement)
                        business  <repo>             show / confirm the business facts (internet-facing, data)
                        plan      <repo>             safe remediation plan (allow-listed actions only)
                        approve   <repo> [--web]     human approval bound to the plan hash
                        apply     <repo>             apply approved actions in a sandbox branch (+ patch)
                        validate  <repo>             build/test/rescan, before-vs-after verdict (+ graph_diff.html)
                        diff      <repo>             visual dependency graph before vs after the fixes
                        report    <repo>             final Guardian report (JSON + MD + HTML)
                        pr        <repo>             open a pull request on the scanned GitHub repository
                        run       <github-link>      everything above in order, ending in a pull request
                                                     (approval and the final "open the PR?" stay interactive)
Extras                  policy    <repo>             policy-as-code gate (exit 1 on violation)
                        ui                           control panel in the browser: one button per step, live output
                        llm-check                    test the configured AI providers
<repo> is the run name, e.g. juice-shop (outputs live in runs/<repo>/).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .pipeline import ROOT, run as scan_run

RUNS = ROOT / "runs"


def _dir(name: str) -> Path:
    d = RUNS / name
    if not d.exists() and (RUNS / name / name).exists():
        d = RUNS / name / name
    if not (d / "findings.json").exists():
        raise SystemExit(f"no scan found in {d} - run `python -m guardian scan <target>` first")
    return d


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="guardian", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("target")
    s.add_argument("--out", default=str(RUNS))
    s.add_argument("--offline", action="store_true", help="use cached vulnerability/registry data only")
    s.add_argument("--baseline", help="earlier sbom.cdx.json to compare against (default: previous scan)")
    s.add_argument("--no-lockgen", action="store_true", help="do not generate missing npm lockfiles")
    s.add_argument("--scanners", default="auto", help='auto (dynamic: OSV first, then Trivy/Grype only where needed), full, osv, or "osv,trivy,grype"')
    s.add_argument("--images", action="store_true", help="also scan Docker base images with Trivy (downloads layers)")
    a = sub.add_parser("analyze")
    a.add_argument("repo")
    a.add_argument("--top", type=int, default=6, help="how many top risks the agents investigate (default 6)")
    a.add_argument("--offline", action="store_true")
    rv = sub.add_parser("review")
    rv.add_argument("repo")
    bz = sub.add_parser("business")
    bz.add_argument("repo")
    p = sub.add_parser("plan")
    p.add_argument("repo")
    p.add_argument("--max", type=int, default=8)
    p.add_argument("--include", default="P1,P2", help="priorities to remediate (default P1,P2)")
    p.add_argument("--offline", action="store_true")
    ap_ = sub.add_parser("approve")
    ap_.add_argument("repo")
    ap_.add_argument("--web", action="store_true", help="approve in the browser at http://127.0.0.1:8770")
    x = sub.add_parser("apply")
    x.add_argument("repo")
    x.add_argument("--dry-run", action="store_true")
    v = sub.add_parser("validate")
    v.add_argument("repo")
    v.add_argument("--install", action="store_true", help="also run npm ci --ignore-scripts (slow)")
    v.add_argument("--test-cmd", default="", help='e.g. "npm test" (run inside the sandbox)')
    df = sub.add_parser("diff")
    df.add_argument("repo")
    r = sub.add_parser("report")
    r.add_argument("repo")
    pr = sub.add_parser("pr", help="open a pull request on the scanned GitHub repository")
    pr.add_argument("repo")
    pr.add_argument("--dry-run", action="store_true", help="build the branch and pr_preview.md, push nothing")
    pr.add_argument("--draft", action="store_true", help="open the pull request as a draft")
    pr.add_argument("--yes", action="store_true", help="do not ask before pushing (the plan approval still applies)")
    pr.add_argument("--force", action="store_true", help="open it even if validation failed")
    po = sub.add_parser("policy")
    po.add_argument("repo")
    po.add_argument("--policy", default=str(ROOT / "config" / "policy.json"))
    sub.add_parser("llm-check")
    ui = sub.add_parser("ui")
    ui.add_argument("--port", type=int, default=8780)
    ui.add_argument("--no-browser", action="store_true")
    full = sub.add_parser("run", help="GitHub link -> scan, analyze, plan, approve, apply, validate, report, pull request")
    full.add_argument("target", help="GitHub link, e.g. https://github.com/owner/repo")
    full.add_argument("--no-pr", action="store_true", help="stop after the report (no pull request)")
    full.add_argument("--draft", action="store_true", help="open the pull request as a draft")
    full.add_argument("--top", type=int, default=6)
    full.add_argument("--web", action="store_true")
    full.add_argument("--install", action="store_true")
    full.add_argument("--test-cmd", default="")
    args = ap.parse_args(argv)

    if args.cmd == "scan":
        scan_run(args.target, Path(args.out), offline=args.offline,
                 baseline=Path(args.baseline) if args.baseline else None, gen_locks=not args.no_lockgen,
                 scanners=args.scanners, images=args.images)
    elif args.cmd == "analyze":
        from . import analyze
        analyze.run(_dir(args.repo), top=args.top, offline=args.offline)
    elif args.cmd == "review":
        from . import review
        review.run(_dir(args.repo))
    elif args.cmd == "business":
        from . import review
        review.business(_dir(args.repo))
    elif args.cmd == "plan":
        from .remediate import planner
        d = _dir(args.repo)
        planner.build(d, json.loads((d / "analysis.json").read_text(encoding="utf-8")), max_actions=args.max,
                      include=tuple(args.include.split(",")), offline=args.offline)
        print((d / "plan.txt").read_text(encoding="utf-8"))
    elif args.cmd == "approve":
        from .remediate import approval
        d = _dir(args.repo)
        plan = json.loads((d / "plan.json").read_text(encoding="utf-8"))
        rec = approval.web(d, plan) if args.web else approval.terminal(d, plan)
        print(f"[approve] {rec['decision']}: {rec['approved_actions']}")
    elif args.cmd == "apply":
        from .remediate import apply
        try:
            out = apply.run(_dir(args.repo), dry_run=args.dry_run)
        except apply.Refused:
            return 2
        if not args.dry_run:
            print(out["diffstat"])
    elif args.cmd == "validate":
        from . import validate
        validate.run(_dir(args.repo), install=args.install, test_cmd=args.test_cmd)
    elif args.cmd == "diff":
        from .report import diff
        diff.write(_dir(args.repo))
    elif args.cmd == "report":
        from .report import final
        final.build(_dir(args.repo))
    elif args.cmd == "pr":
        from .remediate import publish
        try:
            out = publish.run(_dir(args.repo), dry_run=args.dry_run, draft=args.draft, yes=args.yes, force=args.force)
        except publish.Refused:
            return 2
        if out.get("url"):
            print(out["url"])
    elif args.cmd == "policy":
        from . import policy
        res = policy.evaluate(_dir(args.repo), Path(args.policy))
        for v_ in res["violations"][:40]:
            print(f"  DENY {v_['rule']:<34} {v_['severity']:<8} {v_['title'][:90]}")
        print(f"policy {'PASSED' if res['passed'] else 'FAILED'}: {len(res['violations'])} violation(s)")
        return 0 if res["passed"] else 1
    elif args.cmd == "ui":
        from . import ui as panel
        panel.serve(args.port, open_browser=not args.no_browser)
    elif args.cmd == "llm-check":
        from .llm import check
        for row in check():
            print(json.dumps(row))
    elif args.cmd == "run":
        from . import analyze, validate
        from .remediate import apply, approval, planner
        from .report import final
        from .pipeline import parse_github
        if not parse_github(args.target):
            raise SystemExit("run needs a GitHub link, e.g. https://github.com/owner/repo "
                             "(to scan a local folder step by step, use `guardian scan <folder>`)")
        out = scan_run(args.target, RUNS)
        an = analyze.run(out, top=args.top)
        plan = planner.build(out, an)
        if not plan["actions"]:
            print("No actions to take.")
            final.build(out)
            return 0
        rec = approval.web(out, plan) if args.web else approval.terminal(out, plan)
        if rec["decision"] == "approved":
            apply.run(out)
            validate.run(out, install=args.install, test_cmd=args.test_cmd)
        final.build(out)
        if rec["decision"] == "approved" and not args.no_pr:
            from .remediate import publish
            try:
                res = publish.run(out, draft=args.draft)
            except publish.Refused:
                return 2
            if res.get("url"):
                print(f"Pull request: {res['url']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
