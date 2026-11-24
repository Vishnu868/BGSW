"""Is the fixed application still a working application?  (python -m guardian health <repo>)

The rescan (validate) proves the vulnerabilities are gone. This check answers the other question: did the upgrades break
the code that uses those packages? Major-version upgrades often rename or remove functions.

Layers, cheapest first (results in runs/<repo>/health.json, live events in progress.json):
  1. lockfiles   every changed manifest resolved with npm --package-lock-only --ignore-scripts (from apply.json)
  2. api         for every package a fix changed: find HOW the app's own source uses it (default import called as a
                 function, member calls like jwt.sign, named imports like { decode }); install the OLD and the NEW
                 version into a throw-away folder (npm install --ignore-scripts, so no package code runs at install);
                 load both in Node and check that everything the app uses still exists in the new version.
                 A used API that existed before and is missing now = a breaking change, reported with file:line.
  3. tests       optional: the application's own test command inside the sandbox (--test-cmd "npm test")
Verdict: working (all used APIs present) / needs code changes (breaking usages listed) / unknown (could not check).
Limits: static usage search + module surface check - not a full build or run of the application.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .. import audit
from ..pipeline import NPM
from ..remediate.apply import progress

SKIP = {"node_modules", ".git", "dist", "build", "coverage", ".angular", "vendor"}
EXT = (".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx")
PROBE = r"""
const [dir, ...pkgs] = process.argv.slice(2); const out = {};
const desc = m => { const t = typeof m, has = m && (t === 'object' || t === 'function');
  const d = has ? m.default : undefined;
  return {type: t, keys: has ? Object.keys(m) : [], esModule: !!(has && m.__esModule),
          defaultType: d === undefined ? null : typeof d,
          defaultKeys: d && (typeof d === 'object' || typeof d === 'function') ? Object.keys(d) : []}; };
(async () => {
  for (const p of pkgs) {
    try { out[p] = desc(require(require.resolve(p, {paths: [dir]}))); }
    catch (e) {
      try { const u = require('url').pathToFileURL(require.resolve(p, {paths: [dir]})).href; out[p] = desc(await import(u)); }
      catch (e2) { out[p] = {error: String((e2 && e2.message) || e2).split('\n')[0].slice(0, 200)}; }
    }
  }
  console.log(JSON.stringify(out));
})();
"""


def _files(root: Path):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP]
        for f in fn:
            if f.endswith(EXT) and not f.endswith(".d.ts"):
                yield Path(dp) / f


def usages(root: Path, pkg: str) -> list[dict]:
    """What the application's own code needs from `pkg`: callable default, members, named exports (with file:line)."""
    q = re.escape(pkg)
    pats = {
        "default": [re.compile(rf"import\s+(\w+)\s*(?:,\s*\{{[^}}]*\}})?\s+from\s+['\"]{q}['\"]"),
                    re.compile(rf"(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['\"]{q}['\"]\s*\)")],
        "namespace": [re.compile(rf"import\s+\*\s+as\s+(\w+)\s+from\s+['\"]{q}['\"]")],
        "named": [re.compile(rf"import\s+(?:\w+\s*,\s*)?\{{([^}}]*)\}}\s*from\s+['\"]{q}['\"]"),
                  re.compile(rf"(?:const|let|var)\s+\{{([^}}]*)\}}\s*=\s*require\(\s*['\"]{q}['\"]\s*\)")],
    }
    needs = []
    for f in _files(root):
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if pkg not in text:
            continue
        rel = f.relative_to(root).as_posix()
        lines = text.splitlines()

        def line_of(i):
            return text.count("\n", 0, i) + 1
        for kind in ("default", "namespace"):
            for rx in pats[kind]:
                for m in rx.finditer(text):
                    ident, at = m.group(1), line_of(m.start())
                    body = "\n".join(l for n, l in enumerate(lines, 1) if n != at)
                    if kind == "default":
                        for call in re.finditer(rf"(?<![\w./'\"-]){ident}\s*\(", text):
                            ln = line_of(call.start())
                            if ln != at:
                                needs.append({"need": "callable", "name": f"{ident}(...) - default export as a function",
                                              "as": ident, "where": f"{rel}:{ln}", "code": lines[ln - 1].strip()[:140]})
                    for mm in sorted({x for x in re.findall(rf"(?<![\w./'\"-]){ident}\.(\w+)", body)}):
                        pos = text.find(f"{ident}.{mm}", m.end())
                        ln = text.count("\n", 0, pos) + 1 if pos >= 0 else at
                        needs.append({"need": "member", "name": mm, "via": kind, "as": ident, "where": f"{rel}:{ln}",
                                      "code": lines[ln - 1].strip()[:140]})
        for rx in pats["named"]:
            for m in rx.finditer(text):
                at = line_of(m.start())
                for part in m.group(1).split(","):
                    name = part.strip().split(" as ")[0].split(":")[0].strip()
                    if re.fullmatch(r"\w+", name or ""):
                        needs.append({"need": "named", "name": name, "where": f"{rel}:{at}", "code": lines[at - 1].strip()[:140]})
    seen, out = set(), []
    for n in needs:
        k = (n["need"], n["name"], n["where"])
        if k not in seen:
            seen.add(k)
            out.append(n)
    return out


def _surface(info: dict | None) -> dict:
    """What `import X from` / `X.member` / `{ name }` resolve to (TypeScript esModuleInterop / Node semantics)."""
    if not info or info.get("error"):
        return {}
    default_is_fn = info["defaultType"] == "function" if info["esModule"] else info["type"] == "function"
    default_keys = set(info["defaultKeys"]) if info["esModule"] else set(info["keys"])
    if not info["esModule"] and info["defaultType"] == "function":       # module.exports.default = fn (babel style)
        default_is_fn = default_is_fn or True
    return {"default_callable": default_is_fn, "default_members": default_keys,
            "named": set(info["keys"]) | (set(info["defaultKeys"]) if not info["esModule"] else set())}


def _has(surface: dict, need: dict) -> bool | None:
    if not surface:
        return None
    if need["need"] == "callable":
        return surface["default_callable"]
    if need["need"] == "member":
        return need["name"] in (surface["named"] if need.get("via") == "namespace" else surface["default_members"] | surface["named"])
    return need["name"] in surface["named"]


def _install(specs: list[str], dest: Path, log) -> tuple[bool, str]:
    npm = str(NPM) if NPM.exists() else shutil.which("npm")
    if not npm or not specs:
        return False, "npm not available"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "package.json").write_text('{"name":"guardian-health-probe","private":true}', encoding="utf-8")
    r = subprocess.run([npm, "install", *specs, "--ignore-scripts", "--no-audit", "--no-fund", "--no-save",
                        "--legacy-peer-deps", "--loglevel=error"], cwd=dest, capture_output=True, text=True,
                       stdin=subprocess.DEVNULL, timeout=600)
    return r.returncode == 0, (r.stderr or r.stdout).strip()[-300:]


def _probe(dest: Path, names: list[str]) -> dict:
    node = shutil.which("node") or str(Path(str(NPM)).with_name("node.exe"))
    script = dest / "probe.js"
    script.write_text(PROBE, encoding="utf-8")
    r = subprocess.run([node, str(script), str(dest), *names], capture_output=True, text=True, stdin=subprocess.DEVNULL,
                       timeout=120)
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {n: {"error": (r.stderr or "probe failed").strip()[-200:]} for n in names}


def _typings(dest: Path, pkg: str) -> dict | None:
    """Packages that cannot load outside their framework (e.g. Angular libraries need @angular/core): read the exported
    names from their TypeScript declaration files instead."""
    root = dest / "node_modules" / pkg
    if not root.is_dir():
        return None
    names: set[str] = set()
    for f in list(root.rglob("*.d.ts"))[:400]:
        t = f.read_text(encoding="utf-8", errors="ignore")
        names |= set(re.findall(r"export\s+(?:declare\s+)?(?:abstract\s+)?(?:class|const|let|function|interface|type|enum)\s+(\w+)", t))
        for grp in re.findall(r"export\s*\{([^}]*)\}", t):
            names |= {p.strip().split(" as ")[-1].strip() for p in grp.split(",") if p.strip()}
    if not names:
        return None
    return {"type": "object", "keys": sorted(names), "esModule": True, "defaultType": None, "defaultKeys": [],
            "from": "type declarations (.d.ts)"}


def run(run_dir: Path, test_cmd: str = "", log=print) -> dict:
    ap = json.loads((run_dir / "apply.json").read_text(encoding="utf-8"))
    plan = json.loads((run_dir / "plan.json").read_text(encoding="utf-8"))
    sb = Path(ap["sandbox"])
    applied = {r["id"] for r in ap["results"] if r["status"] == "applied"}
    progress(run_dir, "health", event="health check: is the fixed application still working?")

    # 1. lockfiles
    locks = ap.get("lockfiles") or []
    lock_ok = all(l["ok"] for l in locks)
    log(f"[health] 1/3 lockfiles: {'all resolved' if lock_ok else 'FAILED'} ({len(locks)} manifest(s))")

    # 2. API compatibility of every changed package
    changes = []
    for a in plan["actions"]:
        if a["id"] not in applied:
            continue
        p = a["params"]
        if a["type"] in ("npm_upgrade_direct", "npm_override_transitive"):
            changes.append({"action": a["id"], "type": a["type"], "old_pkg": p["package"], "old": p.get("from", ""),
                            "new_pkg": p["package"], "new": p["to"]})
        elif a["type"] == "npm_replace":
            comps = {f["component"] for f in json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))["findings"]}
            old = next((c.rsplit("@", 1)[1] for c in comps if c.startswith(f"npm:{p['package']}@")), "")
            changes.append({"action": a["id"], "type": a["type"], "old_pkg": p["package"], "old": old,
                            "new_pkg": p["with"], "new": p["version"]})
    tmp = Path(tempfile.mkdtemp(prefix="guardian-health-"))
    log(f"[health] 2/3 API check for {len(changes)} changed package(s): installing old and new versions "
        f"(--ignore-scripts) into {tmp}")
    old_specs = [f"{c['old_pkg']}@{c['old']}" for c in changes if c["old"]]
    new_specs = [f"{c['new_pkg']}@{c['new']}" for c in changes]
    ok_old, msg_old = _install(old_specs, tmp / "old", log) if old_specs else (False, "")
    ok_new, msg_new = _install(new_specs, tmp / "new", log)
    old_info = _probe(tmp / "old", [c["old_pkg"] for c in changes if c["old"]]) if ok_old else {}
    new_info = _probe(tmp / "new", [c["new_pkg"] for c in changes]) if ok_new else {}
    for info, where in ((old_info, tmp / "old"), (new_info, tmp / "new")):
        for name, val in list(info.items()):
            if val.get("error"):
                info[name] = _typings(where, name) or val
    results, breaking_total = [], 0
    for c in changes:
        needs = usages(sb, c["new_pkg"])
        before = _surface(old_info.get(c["old_pkg"]))
        after = _surface(new_info.get(c["new_pkg"]))
        checks = []
        for n in needs:
            has_new, had_old = _has(after, n), _has(before, n)
            state = ("ok" if has_new else "unknown" if has_new is None else
                     "breaking" if had_old in (True, None) else "already missing before")
            checks.append({**n, "state": state})
        broken = [x for x in checks if x["state"] == "breaking"]
        breaking_total += len(broken)
        load_err = (new_info.get(c["new_pkg"]) or {}).get("error")
        status = ("not used directly by the app" if not needs else
                  "breaking" if broken else
                  "unknown" if any(x["state"] == "unknown" for x in checks) else "compatible")
        results.append({**c, "status": status, "uses": len(needs), "checks": checks, "load_error": load_err})
        label = (f"{c['old_pkg']} {c['old'] or '?'} -> {c['new_pkg']} {c['new']}" if c["old_pkg"] != c["new_pkg"]
                 else f"{c['new_pkg']} {c['old'] or '?'} -> {c['new']}")
        progress(run_dir, "health", event=f"{c['action']} {label}: {status}"
                 + (f" ({len(broken)} breaking usage(s))" if broken else ""))
        label = (f"{c['old_pkg']} {c['old'] or '?'} -> {c['new_pkg']} {c['new']}" if c["old_pkg"] != c["new_pkg"]
                 else f"{c['new_pkg']} {c['old'] or '?'} -> {c['new']}")
        log(f"[health]    {c['action']} {label}: {status.upper()}"
            + "".join(f"\n             - {x['name']} at {x['where']}: {x['code']}" for x in broken))
    shutil.rmtree(tmp, ignore_errors=True)

    # 3. optional application tests
    tests = None
    if test_cmd:
        log(f"[health] 3/3 running the application's tests: {test_cmd}")
        from . import tool_env
        r = subprocess.run(test_cmd, cwd=sb, shell=True, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=1800,
                           env=tool_env(), encoding="utf-8", errors="replace")
        tests = {"cmd": test_cmd, "ok": r.returncode == 0, "output": (r.stdout + r.stderr).strip().splitlines()[-15:]}
    else:
        log("[health] 3/3 application tests: not requested (add --test-cmd \"npm test\" for a full run)")

    unknown = any(r["status"] == "unknown" for r in results) or not ok_new
    verdict = ("needs code changes" if breaking_total or (tests and not tests["ok"]) or not lock_ok else
               "unknown" if unknown and not results else
               "working" if not unknown else "working (partly checked)")
    out = {"schema": "guardian.health/v1", "verdict": verdict, "lockfiles_ok": lock_ok, "lockfiles": locks,
           "packages": results, "breaking_usages": breaking_total, "tests": tests,
           "install": {"old": msg_old if not ok_old else "ok", "new": msg_new if not ok_new else "ok"},
           "limits": "static usage search + module surface check in Node; not a full build or run of the application"}
    (run_dir / "health.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    audit.log(run_dir / "audit.jsonl", "health", {"verdict": verdict, "breaking": breaking_total})
    progress(run_dir, "health_done", event=f"health verdict: {verdict.upper()}"
             + (f" - {breaking_total} usage(s) need a code change" if breaking_total else ""))
    log(f"[health] verdict: {verdict.upper()}" + (f" - {breaking_total} usage(s) need a code change before merging"
                                                 if breaking_total else ""))
    return out
