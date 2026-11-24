"""Control panel: run the whole Guardian flow from the browser, one button per step, with live output.

    python -m guardian ui            -> http://127.0.0.1:8780  (this computer only)

How it works
  * A small standard-library web server bound to 127.0.0.1 (nobody else on the network can reach it).
  * Every button maps to ONE fixed command from an allow-list below - the page cannot run anything else,
    and repository / target names are checked against the folders that really exist.
  * The command runs as a child process (python -m guardian ...); its output is read in raw chunks, so
    questions without a newline (business / review: "[c]onfirm / [r]eject / [s]kip:") appear immediately.
  * The page polls /api/output and shows the text live; the answer box writes a line to the process' stdin.
  * One command at a time (the free AI tiers are rate-limited, and steps depend on each other).
  * Result pages (dashboard, graph diff, report, plan.txt, analysis.txt) are served from runs/ read-only.
"""
from __future__ import annotations

import json
import mimetypes
import os
import re
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "runs"
NAME = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
INTERACTIVE = {"business", "review"}
GIT_URL = re.compile(r"^https://(github\.com|gitlab\.com)/[\w.-]+/[\w.-]+/?$")


def targets() -> list[dict]:
    out = []
    for base in ("targets", "fixtures"):
        for d in sorted((ROOT / base).glob("*")):
            if d.is_dir() and not d.name.endswith("-pr"):
                out.append({"label": f"{base}/{d.name}", "path": f"{base}/{d.name}", "repo": d.name})
    return out


def repos() -> list[str]:
    return sorted(d.name for d in RUNS.glob("*") if (d / "findings.json").exists()) if RUNS.exists() else []


def command(step: str, repo: str, target: str, offline: bool) -> list[str]:
    """The allow-list: step name -> exact argv. Anything else is refused."""
    py, g = sys.executable, [sys.executable, "-m", "guardian"]
    off = ["--offline"] if offline else []
    if step == "tests":
        return [py, "-m", "unittest", "discover", "-s", "tests"]
    if step == "llm_check":
        return g + ["llm-check"]
    if step == "backup":
        return [py, "scripts/backup_runs.py"]
    if step == "scan":
        if target not in {t["path"] for t in targets()} and not GIT_URL.match(target):
            raise ValueError("unknown target")
        return g + ["scan", target] + off
    if not NAME.match(repo or ""):
        raise ValueError("choose a repository")
    if step == "simulate_pr":
        if not (ROOT / "targets" / repo).is_dir():
            raise ValueError("simulate_pr needs a repository under targets/")
        return [py, "scripts/simulate_pr.py", f"targets/{repo}"]
    if step == "scan_pr":
        if not (ROOT / "targets" / f"{repo}-pr").is_dir():
            raise ValueError("run 'Simulate malicious PR' first")
        return g + ["scan", f"targets/{repo}-pr", "--baseline", f"runs/{repo}/sbom.cdx.json", "--no-lockgen"] + off
    if (RUNS / repo / "findings.json").exists() is False:
        raise ValueError("scan this repository first")
    simple = {"analyze": ["analyze", repo] + off, "business": ["business", repo], "review": ["review", repo],
              "plan": ["plan", repo] + off, "approve": ["approve", repo, "--web"], "apply": ["apply", repo],
              "validate": ["validate", repo], "diff": ["diff", repo], "report": ["report", repo],
              "policy": ["policy", repo], "health": ["health", repo]}
    if step not in simple:
        raise ValueError(f"unknown step {step}")
    return g + simple[step]


def sandbox_state(repo: str, file: str = "") -> dict:
    """Read-only view of the remediation sandbox (git): branch, changed files vs the scanned baseline, one file's diff.
    Includes edits not committed yet, so it updates live while apply is running."""
    root = RUNS / repo / "sandbox"
    dirs = [d for d in root.glob("*") if (d / ".git").exists()] if root.exists() else []
    if not dirs:
        return {"exists": False}
    sb = dirs[0]

    def git(*args, limit=400_000):
        r = subprocess.run(["git", "-C", str(sb), *args], capture_output=True, text=True, encoding="utf-8",
                           errors="replace", stdin=subprocess.DEVNULL, timeout=30)
        return r.stdout[:limit]
    branch = git("rev-parse", "--abbrev-ref", "HEAD").strip()
    files = []
    for line in git("diff", "--numstat", "main", "--").splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            files.append({"file": parts[2], "added": parts[0], "removed": parts[1]})
    out = {"exists": True, "path": str(sb), "branch": branch, "files": files,
           "commits": git("log", "--format=%h %s", "-5").strip().splitlines(),
           "stop": (RUNS / repo / "STOP").exists()}
    if file and any(f["file"] == file for f in files):           # only files that really changed - no path tricks
        out["file"] = file
        out["diff"] = git("diff", "main", "--", file, limit=200_000)
    return out


class Job:
    def __init__(self):
        self.lock = threading.Lock()
        self.proc: subprocess.Popen | None = None
        self.text, self.step, self.repo, self.started, self.code, self.history = "", "", "", 0.0, None, {}

    def start(self, step: str, argv: list[str], repo: str) -> None:
        with self.lock:
            if self.proc and self.proc.poll() is None:
                raise RuntimeError("another step is still running")
            env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
            self.text = f"$ {' '.join(Path(a).name if i == 0 else a for i, a in enumerate(argv))}\n"
            self.step, self.repo, self.started, self.code = step, repo, time.time(), None
            # only the steps that ask questions get an input pipe; tools such as grype read an inherited pipe as input
            stdin = subprocess.PIPE if step in INTERACTIVE else subprocess.DEVNULL
            self.proc = subprocess.Popen(argv, cwd=ROOT, env=env, stdin=stdin, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, bufsize=0)
        threading.Thread(target=self._read, args=(self.proc,), daemon=True).start()

    def _read(self, proc) -> None:
        dec = __import__("codecs").getincrementaldecoder("utf-8")("replace")
        while True:
            chunk = proc.stdout.read1(4096) if hasattr(proc.stdout, "read1") else os.read(proc.stdout.fileno(), 4096)
            if not chunk:
                break
            with self.lock:
                self.text += dec.decode(chunk).replace("\r\n", "\n")
        code = proc.wait()
        with self.lock:
            self.code = code
            self.text += f"\n[{'done' if code == 0 else 'exit code ' + str(code)} in {time.time() - self.started:.0f}s]\n"
            self.history[self.step] = {"code": code, "repo": self.repo, "at": time.strftime("%H:%M:%S")}

    def send(self, line: str) -> None:
        with self.lock:
            if not self.proc or self.proc.poll() is not None:
                raise RuntimeError("nothing is running")
            if self.proc.stdin is None:
                raise RuntimeError("this step does not ask questions")
            self.text += line + "\n"
            self.proc.stdin.write((line + "\n").encode())
            self.proc.stdin.flush()

    def stop(self) -> None:
        with self.lock:
            if self.proc and self.proc.poll() is None:
                if os.name == "nt":          # stop the whole tree (scanners, npm) - not only the python process
                    subprocess.run(["taskkill", "/T", "/F", "/PID", str(self.proc.pid)], capture_output=True)
                else:
                    self.proc.terminate()
                self.text += "\n[stopped by the user]\n"

    def state(self, since: int) -> dict:
        with self.lock:
            running = bool(self.proc and self.proc.poll() is None)
            return {"text": self.text[since:], "length": len(self.text), "running": running, "step": self.step,
                    "code": self.code, "history": self.history}


JOB = Job()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):          # keep the terminal quiet
        pass

    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj).encode())

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            return self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        if u.path == "/api/state":
            stops = {r: (RUNS / r / "STOP").exists() for r in repos()}
            return self._json({"repos": repos(), "targets": targets(), "stop": stops})
        if u.path == "/api/sandbox":
            q = parse_qs(u.query)
            repo = (q.get("repo") or [""])[0]
            if repo not in repos():
                return self._json({"error": "unknown repository"}, 400)
            return self._json(sandbox_state(repo, (q.get("file") or [""])[0]))
        if u.path == "/api/monitor":
            repo = (parse_qs(u.query).get("repo") or [""])[0]
            if repo not in repos():
                return self._json({"error": "unknown repository"}, 400)
            d = RUNS / repo

            def load(name):
                try:
                    return json.loads((d / name).read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    return None
            plan = load("plan.json")
            if plan:
                plan = {"plan_hash": plan.get("plan_hash"), "actions": [{k: a.get(k) for k in (
                    "id", "type", "params", "risk", "priority", "score", "finding_ids")} for a in plan.get("actions", [])]}
            return self._json({"plan": plan, "approval": load("approval.json"), "progress": load("progress.json"),
                               "apply": load("apply.json"), "validation": load("validation.json"), "health": load("health.json")})
        if u.path == "/api/output":
            since = int((parse_qs(u.query).get("since") or ["0"])[0] or 0)
            return self._json(JOB.state(since))
        if u.path.startswith("/runs/"):
            p = (RUNS / unquote(u.path[len("/runs/"):])).resolve()
            if RUNS.resolve() not in p.parents or not p.is_file():
                return self._send(404, b"not found", "text/plain")
            ctype = mimetypes.guess_type(p.name)[0] or "text/plain"
            if p.suffix in (".txt", ".jsonl", ".patch", ".md"):
                ctype = "text/plain"
            return self._send(200, p.read_bytes(), ctype + ("; charset=utf-8" if ctype.startswith("text") else ""))
        return self._send(404, b"not found", "text/plain")

    def do_POST(self):
        if self.headers.get("Origin") not in (None, f"http://127.0.0.1:{self.server.server_port}",
                                              f"http://localhost:{self.server.server_port}"):
            return self._json({"error": "cross-site request refused"}, 403)
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return self._json({"error": "bad request"}, 400)
        path = urlparse(self.path).path
        try:
            if path == "/api/run":
                argv = command(str(body.get("step", "")), str(body.get("repo", "")), str(body.get("target", "")),
                               bool(body.get("offline")))
                JOB.start(str(body["step"]), argv, str(body.get("repo", "")))
                return self._json({"ok": True})
            if path == "/api/input":
                JOB.send(str(body.get("text", ""))[:200])
                return self._json({"ok": True})
            if path == "/api/stop":
                JOB.stop()
                return self._json({"ok": True})
            if path == "/api/killswitch":
                repo = str(body.get("repo", ""))
                if repo not in repos():
                    raise ValueError("unknown repository")
                f = RUNS / repo / "STOP"
                if body.get("on"):
                    f.write_text("stop", encoding="utf-8")
                elif f.exists():
                    f.unlink()
                return self._json({"ok": True, "stop": f.exists()})
            if path == "/api/clear-approval":
                repo = str(body.get("repo", ""))
                if repo not in repos():
                    raise ValueError("unknown repository")
                (RUNS / repo / "approval.json").unlink(missing_ok=True)
                return self._json({"ok": True})
        except (ValueError, RuntimeError, KeyError) as e:
            return self._json({"error": str(e)}, 400)
        return self._json({"error": "not found"}, 404)


def serve(port: int = 8780, open_browser: bool = True) -> None:
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}"
    print(f"[ui] Guardian control panel: {url}  (this computer only; Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        JOB.stop()
        print("\n[ui] stopped")


PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Guardian control center</title>
<style>
:root{--bg:#f3f5f9;--card:#fff;--ink:#16202c;--muted:#5b6876;--line:#d5dbe3;--navy:#1e3a8a;--pink:#c8194e;--teal:#0e7c86;
--green:#1f7a3a;--amber:#d08a00;--purple:#6b3fa0;--chip:#eef1f5;--con:#0f1722}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 "Segoe UI",Roboto,Arial,sans-serif;background:var(--bg);color:var(--ink)}
header{display:flex;flex-wrap:wrap;gap:12px;align-items:center;padding:10px 20px;background:var(--card);border-bottom:1px solid var(--line)}
h1{margin:0;font-size:19px;margin-right:auto}h1 span{color:var(--pink)}
nav.tabs{display:flex;gap:2px;padding:0 20px;background:var(--card);border-bottom:1px solid var(--line);overflow-x:auto}
nav.tabs button{background:none;border:0;border-bottom:3px solid transparent;padding:10px 14px;color:var(--muted);font:inherit;cursor:pointer;white-space:nowrap;border-radius:0}
nav.tabs button.on{color:var(--ink);border-color:var(--pink);font-weight:600}
.page{display:none}.page.on{display:block}
select,input[type=text]{font:inherit;padding:6px 8px;border:1px solid var(--line);border-radius:8px;background:#fff;max-width:100%}
label.chk{display:flex;gap:6px;align-items:center;color:var(--muted)}
.wrap{display:grid;grid-template-columns:400px 1fr;gap:16px;padding:16px 20px}
.col{display:flex;flex-direction:column;gap:12px}
.group{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px}
.group h2{margin:0 0 8px;font-size:13px;letter-spacing:.06em;text-transform:uppercase}
.day1 h2{color:var(--navy)}.brain h2{color:var(--purple)}.shield h2{color:var(--pink)}.proof h2{color:var(--green)}.prep h2{color:var(--muted)}
.step{display:grid;grid-template-columns:28px 1fr auto;gap:8px;align-items:center;padding:6px 4px;border-top:1px solid #eef1f5}
.step:first-of-type{border-top:0}
.n{width:24px;height:24px;border-radius:50%;background:#e8ecf3;display:grid;place-items:center;font-size:12px;font-weight:600}
.step.ok .n{background:var(--green);color:#fff}.step.bad .n{background:var(--pink);color:#fff}.step.run .n{background:var(--amber);color:#fff}
.step b{display:block}.step small{color:var(--muted)}
button{font:inherit;border:0;border-radius:8px;padding:7px 12px;background:var(--navy);color:#fff;cursor:pointer;white-space:nowrap}
button:disabled{opacity:.45;cursor:not-allowed}button.alt{background:#e8ecf3;color:var(--ink)}button.warn{background:var(--pink)}button.go{background:var(--green)}
.tag{font-size:11px;font-weight:600;padding:1px 6px;border-radius:6px;margin-left:4px;vertical-align:1px}
.ai{background:#efe7fa;color:var(--purple)}.human{background:#fdeee0;color:#b4570c}.rules{background:#e6ecf8;color:var(--navy)}
.console{background:var(--con);color:#dfe6ee;border-radius:12px;padding:14px;font:13px/1.5 Consolas,monospace;white-space:pre-wrap;word-break:break-word;overflow:auto}
#out{height:calc(100vh - 330px);min-height:320px}.mini{height:220px}
.console a{color:#7fc4ff}.bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.links{display:flex;gap:8px;flex-wrap:wrap}.links a{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:5px 10px;color:var(--navy);text-decoration:none}
#status{color:var(--muted)}#answer{flex:1;min-width:160px}.stop-on{color:var(--pink);font-weight:600}
.pad{padding:16px 20px;display:flex;flex-direction:column;gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}
.card h3{margin:0 0 8px;font-size:15px}
.pipe{display:flex;gap:6px;flex-wrap:wrap}
.pipe span{padding:6px 12px;border-radius:999px;background:#e8ecf3;color:var(--muted);font-size:13px;font-weight:600}
.pipe span.done{background:#e4f4ea;color:var(--green)}.pipe span.now{background:var(--amber);color:#fff;animation:pulse 1.2s infinite}
@keyframes pulse{50%{opacity:.6}}
.kpis{display:flex;gap:10px;flex-wrap:wrap}.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:8px 14px;min-width:130px}
.kpi b{display:block;font-size:22px}.kpi small{color:var(--muted)}
table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid var(--line);padding:7px 8px;text-align:left;vertical-align:top;font-size:13px}
th{color:var(--muted);font-size:12px;font-weight:600}
.st{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;font-weight:600;color:#fff;background:#9aa4b1}
.st.pending{background:#9aa4b1}.st.running{background:var(--amber);animation:pulse 1.2s infinite}.st.applied,.st.compatible,.st.verified,.st.working{background:var(--green)}
.st.failed,.st.breaking{background:var(--pink)}.st.partial,.st.unknown{background:var(--amber)}.st.approved{background:var(--navy)}.st.na{background:#9aa4b1}
.verdict{font-size:20px;font-weight:700;padding:12px 16px;border-radius:12px;color:#fff}
.v-working{background:var(--green)}.v-needs{background:var(--pink)}.v-unknown{background:#7d8794}
.code{font:12px Consolas,monospace;background:var(--chip);border-radius:6px;padding:4px 8px;display:block;margin-top:3px;word-break:break-word}
.muted{color:var(--muted)}iframe{width:100%;height:calc(100vh - 150px);border:0;background:var(--card)}
.layers li{margin:4px 0}
.sbx{display:grid;grid-template-columns:340px 1fr;gap:14px}
.flist{max-height:calc(100vh - 330px);overflow:auto}.flist div{padding:6px 8px;border-radius:8px;cursor:pointer;font:12.5px Consolas,monospace;word-break:break-all}
.flist div:hover{background:var(--chip)}.flist div.sel{background:#e6ecf8;font-weight:600}.flist .add{color:var(--green)}.flist .del{color:var(--pink)}
.diff{font:12.5px/1.5 Consolas,monospace;white-space:pre;overflow:auto;max-height:calc(100vh - 330px);background:#fff;border:1px solid var(--line);border-radius:10px;padding:8px 0}
.diff div{padding:0 12px}.diff .a{background:#e6f6ea;color:#14532d}.diff .d{background:#fde8ec;color:#8b1235}.diff .h{background:#eef2fb;color:var(--navy);font-weight:600}.diff .m{color:var(--muted)}
@media (max-width:980px){.wrap,.sbx{grid-template-columns:1fr}#out{height:420px}}
</style></head><body>
<header><h1><span>Guardian</span> control center</h1>
<label>Repository <select id="repo"></select></label>
<label class="chk"><input type="checkbox" id="offline"> offline (cached data only)</label></header>
<nav class="tabs" id="tabs">
 <button data-p="steps" class="on">Run steps</button><button data-p="monitor">Live fix monitor</button>
 <button data-p="sandbox">Live sandbox</button><button data-p="health">App health</button><button data-p="diff">Graph before vs after</button>
 <button data-p="dash">Dashboard</button><button data-p="report">Final report</button></nav>

<section class="page on" id="p-steps"><div class="wrap">
 <div class="col" id="steps"></div>
 <div class="col">
  <div class="bar"><b id="title">Output</b><span id="status"></span><span style="flex:1"></span><button class="warn" id="stopBtn" disabled>Stop step</button></div>
  <div class="console" id="out">Press a button on the left. Steps run one at a time, in order; the output appears here live.</div>
  <div class="bar"><input type="text" id="answer" placeholder="answer a question (business / review) and press Enter" disabled>
   <button class="alt" data-a="c" disabled>c</button><button class="alt" data-a="r" disabled>r</button>
   <button class="alt" data-a="s" disabled>s</button><button class="alt" data-a="d" disabled>d</button><button id="sendBtn" disabled>Send</button></div>
  <div class="links" id="links"></div>
 </div></div></section>

<section class="page" id="p-monitor"><div class="pad">
 <div class="card"><div class="bar" style="justify-content:space-between"><h3 style="margin:0">Live fix monitor</h3>
  <span class="bar"><button data-run="approve">1 · Approve plan</button><button data-run="apply2" class="go">2 · Apply fixes</button>
  <button data-run="validate">3 · Validate (rescan)</button><button data-run="health">4 · Health check</button></span></div>
  <p class="muted" style="margin:6px 0 10px">Each approved fix appears here the moment it is applied in the sandbox, then verified by the rescan and checked for breaking API changes. Updates every second.</p>
  <div class="pipe" id="pipe"></div></div>
 <div class="kpis" id="kpis"></div>
 <div class="card"><h3>Approved fixes</h3><div style="overflow-x:auto"><table id="acts"></table></div></div>
 <div class="wrap" style="padding:0;grid-template-columns:1fr 1fr">
  <div class="card"><h3>Events</h3><div class="console mini" id="events"></div></div>
  <div class="card"><h3>Live output</h3><div class="console mini" id="out2"></div></div></div>
</div></section>

<section class="page" id="p-sandbox"><div class="pad">
 <div class="card"><div class="bar" style="justify-content:space-between"><h3 style="margin:0">Live sandbox</h3>
  <span class="bar"><button data-run="apply2" class="go">Apply fixes</button><a id="sbPatch" target="_blank" class="links"></a></span></div>
  <p class="muted" style="margin:6px 0 0">The sandbox is a copy of the repository on its own git branch. Every change the approved fixes make is shown
  here against the scanned original, live while Apply runs. The original repository is never touched; the result is remediation.patch.</p>
  <div class="kpis" id="sbInfo" style="margin-top:10px"></div></div>
 <div class="sbx"><div class="card"><h3>Changed files</h3><div class="flist" id="sbFiles"></div></div>
  <div class="card"><h3 id="sbTitle">Diff</h3><div class="diff" id="sbDiff"><div class="m">Select a file on the left.</div></div></div></div>
</div></section>

<section class="page" id="p-health"><div class="pad">
 <div class="card"><div class="bar" style="justify-content:space-between"><h3 style="margin:0">Is the fixed application still working?</h3>
  <button data-run="health">Run health check</button></div>
  <p class="muted" style="margin:6px 0 0">The rescan proves the vulnerabilities are gone (105 → 73 findings). This page checks the other side: did the upgrades break
  the code that uses those packages? For every changed package it finds how the app's own source uses it, installs the old and the new
  version (no install scripts run), loads both and checks that everything the app uses still exists.</p></div>
 <div id="verdict"></div>
 <div class="card"><h3>Checks</h3><ul class="layers" id="layers"></ul></div>
 <div class="card"><h3>Changed packages</h3><div style="overflow-x:auto"><table id="pk"></table></div></div>
 <div class="card"><h3>Live output</h3><div class="console mini" id="out3"></div></div>
</div></section>

<section class="page" id="p-diff"><iframe id="f-diff" title="Graph before vs after"></iframe></section>
<section class="page" id="p-dash"><iframe id="f-dash" title="Dashboard"></iframe></section>
<section class="page" id="p-report"><iframe id="f-report" title="Final report"></iframe></section>

<script>
const STEPS = [
 {g:"prep", t:"0 · Before you start", items:[
  ["tests","Run the automated tests","offline, under a second","rules"],
  ["llm_check","Check the AI providers","which AI answers (Groq / Gemini / Claude)","ai"]]},
 {g:"day1", t:"Day 1 · Eyes", items:[
  ["scan","Scan","Discover + OSV + dynamic Trivy/Grype + supply-chain checks","rules","target"],
  ["simulate_pr","Simulate a malicious PR","copy of the repo with 4 planted changes","rules"],
  ["scan_pr","Scan the PR against the baseline","catches tampering, mirror, install script, downgrade","rules"]]},
 {g:"brain", t:"Day 2 · Brain (prioritization)", items:[
  ["analyze","Analyze","rule scores + six agents + verifier","ai"],
  ["business","Business facts","confirm (c) / reject (r) / skip (s) each fact","human"],
  ["review","Review queue","cases the AI was unsure about","human"]]},
 {g:"shield", t:"Day 2 · Shield (remediation + approval)", items:[
  ["plan","Plan","allow-listed fixes, clean-tree check, plan hash","ai"],
  ["apply","Apply without approval","clears the old approval, then shows the refusal","rules"],
  ["approve","Approve in the browser","opens the approval page (127.0.0.1:8770)","human"],
  ["killswitch","Kill switch","STOP file on / off","rules"],
  ["apply2","Apply in the sandbox","watch it live in the Live fix monitor tab","rules"]]},
 {g:"proof", t:"Test and rescan · Report", items:[
  ["validate","Validate","full rescan, before vs after, verdict + graph diff","rules"],
  ["health","App health check","is the fixed app still working? (API compatibility)","rules"],
  ["diff","Graph before vs after","rebuild graph_diff.html","rules"],
  ["report","Final report","guardian_report.html","rules"],
  ["policy","Policy gate","CI gate (exit 1 = blocked)","rules"],
  ["backup","Backup results","zip of runs/ for the demo","rules"]]}];
const $ = s => document.querySelector(s), esc = s => String(s ?? "").replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
let state = {repos:[], targets:[], stop:{}}, since = 0, running = false, n = 0, page = "steps", fullText = "";
const tag = k => `<span class="tag ${k}">${k === "ai" ? "AI" : k === "human" ? "HUMAN" : "RULES"}</span>`;
$("#steps").innerHTML = STEPS.map(G => `<div class="group ${G.g}"><h2>${G.t}</h2>` + G.items.map(([id, name, what, kind, extra]) =>
  `<div class="step" id="s-${id}"><span class="n">${++n}</span><div><b>${name}${tag(kind)}</b><small>${what}</small>
   ${extra === "target" ? '<div style="margin-top:4px"><select id="target"></select></div>' : ""}</div>
   ${id === "killswitch" ? '<span><button data-k="1">On</button> <button class="alt" data-k="0">Off</button></span>'
                         : `<button data-step="${id}">Run</button>`}</div>`).join("") + "</div>").join("");
async function api(path, body) {
  const r = await fetch(path, body ? {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body)} : {});
  const j = await r.json(); if (!r.ok) throw new Error(j.error || r.status); return j;
}
const repo = () => $("#repo").value;
async function refresh() {
  state = await api("/api/state");
  const cur = repo() || "juice-shop";
  $("#repo").innerHTML = state.repos.map(r => `<option ${r === cur ? "selected" : ""}>${r}</option>`).join("") || "<option value=''>(scan first)</option>";
  const t = $("#target"), tv = t.value || "targets/juice-shop";
  t.innerHTML = state.targets.map(x => `<option value="${x.path}" ${x.path === tv ? "selected" : ""}>${x.label}</option>`).join("")
    + `<option value="url">GitHub link…</option>`;
  links();
}
function links() {
  const r = repo(); if (!r) return $("#links").innerHTML = "";
  const L = [["findings.json", "findings.json"], ["analysis.txt", "analysis.txt"], ["plan.txt", "plan.txt"], ["remediation.patch", "remediation.patch"],
             ["health.json", "health.json"], ["audit trail", "audit.jsonl"]];
  $("#links").innerHTML = L.map(([n, f]) => `<a href="/runs/${encodeURIComponent(r)}/${f}" target="_blank">${n}</a>`).join("")
    + ` <a href="/runs/${encodeURIComponent(r)}-pr/guardian.html" target="_blank">PR dashboard</a>`
    + ` <span id="ks" class="${state.stop[r] ? "stop-on" : ""}">${state.stop[r] ? "kill switch ON" : ""}</span>`;
}
$("#repo").addEventListener("change", () => { links(); frames(true); monitor(); });
function frames(force) {
  const r = encodeURIComponent(repo()); if (!r) return;
  [["#f-diff", "graph_diff.html"], ["#f-dash", "guardian.html"], ["#f-report", "guardian_report.html"]].forEach(([id, f]) => {
    const want = `/runs/${r}/${f}`; const el = $(id);
    if (force || el.dataset.src !== want) { el.dataset.src = want; if (page === id.slice(3) || force === "now") el.src = want + "?t=" + Date.now(); }
  });
}
document.querySelectorAll("#tabs button").forEach(b => b.onclick = () => {
  document.querySelectorAll("#tabs button,.page").forEach(x => x.classList.remove("on"));
  b.classList.add("on"); page = b.dataset.p; $("#p-" + page).classList.add("on");
  const fr = {diff: "#f-diff", dash: "#f-dash", report: "#f-report"}[page];
  if (fr) $(fr).src = `/runs/${encodeURIComponent(repo())}/${{diff: "graph_diff.html", dash: "guardian.html", report: "guardian_report.html"}[page]}?t=` + Date.now();
  if (page === "monitor" || page === "health") monitor();
  if (page === "sandbox") sandbox();
});
function setRunning(v) {
  running = v;
  document.querySelectorAll("[data-step],[data-k],[data-run]").forEach(b => b.disabled = v);
  ["#stopBtn", "#answer", "#sendBtn"].forEach(s => $(s).disabled = !v);
  document.querySelectorAll("[data-a]").forEach(b => b.disabled = !v);
}
async function run(step) {
  const real = step === "apply2" ? "apply" : step;
  let target = "";
  if (real === "scan") { target = $("#target").value;
    if (target === "url") { target = prompt("GitHub link, e.g. https://github.com/snyk-labs/nodejs-goof") || ""; if (!target) return; } }
  if (step === "apply") { try { await api("/api/clear-approval", {repo: repo()}); } catch (e) {} }
  try { await api("/api/run", {step: real, repo: real === "scan" ? "" : repo(), target, offline: $("#offline").checked}); }
  catch (e) { $("#out").textContent += `\n[not started: ${e.message}]\n`; return; }
  document.querySelectorAll(".step").forEach(s => { s.classList.remove("run"); delete s.dataset.last; });
  const el = $("#s-" + step); if (el) { el.classList.add("run"); el.dataset.last = "1"; }
  since = 0; fullText = ""; ["#out", "#out2", "#out3"].forEach(s => $(s).innerHTML = "");
  $("#title").textContent = el ? el.querySelector("b").firstChild.textContent : step;
  setRunning(true); poll();
}
const linkify = t => esc(t).replace(/(https?:\/\/[^\s)'"]+)/g, '<a href="$1" target="_blank">$1</a>');
async function poll() {
  const s = await api("/api/output?since=" + since); since = s.length;
  if (s.text) { fullText += s.text;
    for (const id of ["#out", "#out2", "#out3"]) { const o = $(id), bottom = o.scrollTop + o.clientHeight >= o.scrollHeight - 30;
      o.innerHTML = linkify(fullText); if (bottom || id !== "#out") o.scrollTop = o.scrollHeight; } }
  $("#status").textContent = s.running ? "running…" : (s.code === null ? "" : s.code === 0 ? "finished" : "finished with exit code " + s.code);
  if (s.running) return setTimeout(poll, 400);
  setRunning(false);
  const el = document.querySelector('.step[data-last="1"]');
  if (el) { el.classList.remove("run"); el.classList.add(s.code === 0 ? "ok" : "bad"); }
  refresh(); frames(true); monitor();
}
document.addEventListener("click", async e => {
  const b = e.target.closest("button"); if (!b) return;
  if (b.dataset.step) return run(b.dataset.step);
  if (b.dataset.run) return run(b.dataset.run);
  if (b.dataset.k !== undefined) { const r = await api("/api/killswitch", {repo: repo(), on: b.dataset.k === "1"});
    $("#out").textContent = `Kill switch ${r.stop ? "ON: runs/" + repo() + "/STOP created - apply will refuse" : "OFF: STOP file removed"}\n`;
    $("#s-killswitch").classList.add("ok"); return refresh(); }
  if (b.dataset.a) return send(b.dataset.a);
  if (b.id === "sendBtn") return send($("#answer").value);
  if (b.id === "stopBtn") return api("/api/stop", {});
});
async function send(t) { try { await api("/api/input", {text: t}); $("#answer").value = ""; } catch (e) {} }
$("#answer").addEventListener("keydown", e => { if (e.key === "Enter") send($("#answer").value); });

// ---------------- live fix monitor + health ----------------
const ST = s => `<span class="st ${esc((s || "pending").split(" ")[0].replace(/[^a-z]/g, ""))}">${esc(s || "pending")}</span>`;
const STAGES = [["approved", "Approved"], ["apply", "Applying fixes"], ["lockfiles", "Lockfiles"], ["applied", "Applied in sandbox"],
                ["validating", "Rescanning"], ["validated", "Verified"], ["health", "Health check"], ["health_done", "Health verdict"]];
async function monitor() {
  if (!repo()) return;
  let m; try { m = await api("/api/monitor?repo=" + encodeURIComponent(repo())); } catch (e) { return; }
  const stage = (m.progress || {}).stage, idx = STAGES.findIndex(s => s[0] === stage);
  const approvedNow = m.approval && m.plan && m.approval.plan_hash === m.plan.plan_hash;
  const sameRun = approvedNow && (m.progress || {}).plan_hash === m.plan.plan_hash;   // progress belongs to this approval
  $("#pipe").innerHTML = !approvedNow
    ? STAGES.map(([k, l]) => `<span>${l}</span>`).join("") + ` <span class="now">waiting for a human approval of plan ${esc(((m.plan || {}).plan_hash || "").slice(0, 12))}</span>`
    : STAGES.map(([k, l], i) => {
      const done = k === "approved" || (sameRun && idx >= 0 && (i < idx || (i === idx && /applied|validated|health_done/.test(stage))));
      const now = sameRun && idx === i && !done; return `<span class="${done ? "done" : now ? "now" : ""}">${done ? "✓ " : ""}${l}</span>`; }).join("");
  const at = k => STAGES.findIndex(s => s[0] === k);
  const showVerify = sameRun && idx >= at("validated"), showHealth = sameRun && idx >= at("health_done");
  const v = showVerify ? (m.validation || {}) : {}, b = (v.before || {}).by_severity || {}, a = (v.after || {}).by_severity || {};
  const prog = (m.progress || {}).actions || {};
  const nApplied = Object.values(prog).filter(x => x.status === "applied").length, nAll = (m.approval || {}).approved_actions ? m.approval.approved_actions.length : 0;
  $("#kpis").innerHTML = [[`${nApplied} / ${nAll || "-"}`, "fixes applied"],
    [v.before ? `${b.critical} → ${a.critical}` : "–", "critical findings"], [v.before ? `${b.high} → ${a.high}` : "–", "high findings"],
    [v.before ? `${v.before.findings} → ${v.after.findings}` : "–", "total findings"], [v.resolved ? v.resolved.length : "–", "resolved"],
    [v.new_findings ? v.new_findings.length : "–", "new problems"], [v.verdict ? v.verdict.toUpperCase() : "–", "rescan verdict"],
    [showHealth && m.health ? m.health.verdict.toUpperCase() : "–", "app health"]]
    .map(([x, l]) => `<div class="kpi"><b>${esc(x)}</b><small>${l}</small></div>`).join("");
  const per = showVerify ? Object.fromEntries((v.per_action || []).map(p => [p.id, p])) : {};
  const hp = showHealth ? Object.fromEntries(((m.health || {}).packages || []).map(p => [p.action, p])) : {};
  const appr = new Set(approvedNow ? m.approval.approved_actions : []);
  $("#acts").innerHTML = "<tr><th>Fix</th><th>What</th><th>Risk</th><th>Approval</th><th>Applied in sandbox</th><th>Rescan (findings)</th><th>App health</th></tr>"
    + ((m.plan || {}).actions || []).map(x => {
      const p = x.params || {}, what = x.type === "npm_replace" ? `${p.package} → ${p.with}@${p.version}` : x.type === "escalate" ? `${(x.risk || "").split(":")[1] || ""} → human decision`
        : `${p.package || ""} ${p.from || ""} → ${p.to || ""}`;
      const pr = prog[x.id] || {}, pa = per[x.id], h = hp[x.id];
      const verify = pa ? `${ST(pa.status.startsWith("n/a") ? "na" : pa.status)} ${pa.resolved}/${pa.targeted}` : "–";
      return `<tr><td><b>${x.id}</b><br><span class="muted">${esc(x.type)}</span></td><td>${esc(what)}</td>
        <td>${esc((x.risk || "").slice(0, 70))}<br><span class="muted">${esc(x.priority)} · ${esc(x.score)}</span></td>
        <td>${appr.has(x.id) ? ST("approved") : "–"}</td><td>${appr.has(x.id) ? ST(pr.status) : "–"}<br><span class="muted">${esc(pr.detail || "")}</span></td>
        <td>${verify}</td><td>${h ? ST(h.status === "not used directly by the app" ? "na" : h.status) + (h.status.startsWith("not used") ? " <span class='muted'>not used directly</span>" : "") : "–"}</td></tr>`; }).join("");
  $("#events").textContent = ((m.progress || {}).events || []).join("\n") || "No fixes applied yet. Approve the plan, then press 'Apply fixes'.";
  $("#events").scrollTop = $("#events").scrollHeight;
  // health page
  const H = m.health;
  if (!H) { $("#verdict").innerHTML = `<div class="verdict v-unknown">Not checked yet - press "Run health check" (after Apply)</div>`;
    $("#layers").innerHTML = ""; $("#pk").innerHTML = ""; return; }
  const cls = H.verdict.startsWith("working") ? "v-working" : H.verdict.startsWith("needs") ? "v-needs" : "v-unknown";
  $("#verdict").innerHTML = `<div class="verdict ${cls}">${H.verdict === "needs code changes" ? "✗ Needs code changes" : H.verdict.startsWith("working") ? "✓ " + esc(H.verdict) : esc(H.verdict)}
    ${H.breaking_usages ? `<span style="font-weight:400;font-size:15px"> - ${H.breaking_usages} place(s) in the app must be updated before merging</span>` : ""}</div>`;
  $("#layers").innerHTML = `<li>${H.lockfiles_ok ? "✅" : "❌"} <b>Lockfiles resolve</b> - ${H.lockfiles.length} changed manifest(s), resolved without running package scripts</li>
    <li>${H.breaking_usages ? "❌" : "✅"} <b>API compatibility</b> - every function the app uses from a changed package still exists in the new version</li>
    <li>${H.tests ? (H.tests.ok ? "✅" : "❌") : "➖"} <b>Application tests</b> - ${H.tests ? esc(H.tests.cmd) : "not run (python -m guardian health &lt;repo&gt; --test-cmd \"npm test\")"}</li>
    <li class="muted">Limits: ${esc(H.limits)}</li>`;
  $("#pk").innerHTML = "<tr><th>Fix</th><th>Package</th><th>Status</th><th>How the app uses it (file:line)</th></tr>"
    + H.packages.map(p => `<tr><td><b>${esc(p.action)}</b></td><td>${esc(p.old_pkg !== p.new_pkg ? p.old_pkg + " " + p.old + " → " + p.new_pkg + " " + p.new : p.new_pkg + " " + p.old + " → " + p.new)}</td>
      <td>${ST(p.status === "not used directly by the app" ? "na" : p.status)}${p.status.startsWith("not used") ? "<br><span class='muted'>not used directly by the app</span>" : ""}</td>
      <td>${p.checks.length ? p.checks.map(c => `${ST(c.state)} <b>${esc(c.name)}</b> <span class="muted">${esc(c.where)}</span><span class="code">${esc(c.code)}</span>`).join("")
        : "<span class='muted'>no direct import in the app's source</span>"}</td></tr>`).join("");
}
setInterval(() => { if (page === "monitor" || page === "health") monitor(); }, 1000);
// ---------------- live sandbox ----------------
let sbFile = "";
async function sandbox() {
  if (!repo()) return;
  let st; try { st = await api("/api/sandbox?repo=" + encodeURIComponent(repo()) + "&file=" + encodeURIComponent(sbFile)); } catch (e) { return; }
  if (!st.exists) { $("#sbInfo").innerHTML = '<div class="kpi"><b>no sandbox yet</b><small>approve the plan, then Apply</small></div>';
    $("#sbFiles").innerHTML = ""; $("#sbDiff").innerHTML = '<div class="m">Nothing applied yet.</div>'; return; }
  const add = st.files.reduce((n, f) => n + (+f.added || 0), 0), del = st.files.reduce((n, f) => n + (+f.removed || 0), 0);
  $("#sbInfo").innerHTML = [[st.branch, "sandbox branch"], [st.files.length, "files changed"], [`+${add} / -${del}`, "lines"],
    [st.stop ? "ON" : "off", "kill switch"], [(st.commits[0] || "").slice(0, 40), "latest commit"]]
    .map(([x, l]) => `<div class="kpi"><b style="font-size:16px">${esc(x)}</b><small>${l}</small></div>`).join("");
  $("#sbPatch").innerHTML = `<a href="/runs/${encodeURIComponent(repo())}/remediation.patch" target="_blank">remediation.patch</a>`;
  if (!sbFile && st.files.length) { sbFile = (st.files.find(f => f.file === "package.json") || st.files[0]).file; return sandbox(); }
  $("#sbFiles").innerHTML = st.files.map(f => `<div data-f="${esc(f.file)}" class="${f.file === sbFile ? "sel" : ""}">${esc(f.file)}
     <span class="add">+${esc(f.added)}</span> <span class="del">-${esc(f.removed)}</span></div>`).join("") || '<div class="m">no changes yet</div>';
  if (st.diff !== undefined) {
    $("#sbTitle").textContent = "Diff: " + st.file + "  (scanned original → sandbox)";
    $("#sbDiff").innerHTML = st.diff.split("\n").map(l => `<div class="${l.startsWith("@@") ? "h" : l.startsWith("+") && !l.startsWith("+++") ? "a"
      : l.startsWith("-") && !l.startsWith("---") ? "d" : "m"}">${esc(l) || " "}</div>`).join("");
  }
}
$("#sbFiles").addEventListener("click", e => { const d = e.target.closest("[data-f]"); if (d) { sbFile = d.dataset.f; sandbox(); } });
setInterval(() => { if (page === "sandbox") sandbox(); }, 1500);

refresh().then(() => { frames(); monitor();
  const want = location.hash.slice(1);                     // e.g. http://127.0.0.1:8780/#monitor opens that tab
  if (want) { const b = document.querySelector(`#tabs [data-p="${want}"]`); if (b) b.click(); } });
</script></body></html>"""
