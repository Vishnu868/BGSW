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
              "policy": ["policy", repo]}
    if step not in simple:
        raise ValueError(f"unknown step {step}")
    return g + simple[step]


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
<title>Guardian control panel</title>
<style>
:root{--bg:#f3f5f9;--card:#fff;--ink:#16202c;--muted:#5b6876;--line:#d5dbe3;--navy:#1e3a8a;--pink:#c8194e;--teal:#0e7c86;
--green:#1f7a3a;--amber:#d08a00;--purple:#6b3fa0}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 "Segoe UI",Roboto,Arial,sans-serif;background:var(--bg);color:var(--ink)}
header{display:flex;flex-wrap:wrap;gap:12px;align-items:center;padding:12px 20px;background:var(--card);border-bottom:1px solid var(--line)}
h1{margin:0;font-size:19px;margin-right:auto}h1 span{color:var(--pink)}
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
button:disabled{opacity:.45;cursor:not-allowed}button.alt{background:#e8ecf3;color:var(--ink)}button.warn{background:var(--pink)}
.tag{font-size:11px;font-weight:600;padding:1px 6px;border-radius:6px;margin-left:4px;vertical-align:1px}
.ai{background:#efe7fa;color:var(--purple)}.human{background:#fdeee0;color:#b4570c}.rules{background:#e6ecf8;color:var(--navy)}
.console{background:#0f1722;color:#dfe6ee;border-radius:12px;padding:14px;font:13px/1.5 Consolas,monospace;white-space:pre-wrap;
 word-break:break-word;height:calc(100vh - 290px);min-height:320px;overflow:auto}
.console a{color:#7fc4ff}.bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.links{display:flex;gap:8px;flex-wrap:wrap}.links a{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:5px 10px;
 color:var(--navy);text-decoration:none}.links a:hover{border-color:var(--navy)}
#status{color:var(--muted)}#answer{flex:1;min-width:160px}
.stop-on{color:var(--pink);font-weight:600}
@media (max-width:980px){.wrap{grid-template-columns:1fr}.console{height:420px}}
</style></head><body>
<header><h1><span>Guardian</span> control panel</h1>
<label>Repository <select id="repo"></select></label>
<label class="chk"><input type="checkbox" id="offline"> offline (cached data only)</label></header>
<div class="wrap">
<div class="col" id="steps"></div>
<div class="col">
 <div class="bar"><b id="title">Output</b><span id="status"></span><span style="flex:1"></span>
  <button class="warn" id="stopBtn" disabled>Stop step</button></div>
 <div class="console" id="out">Press a button on the left. Steps run one at a time, in order; the output appears here live.</div>
 <div class="bar"><input type="text" id="answer" placeholder="answer a question (business / review) and press Enter" disabled>
  <button class="alt" data-a="c" disabled>c</button><button class="alt" data-a="r" disabled>r</button>
  <button class="alt" data-a="s" disabled>s</button><button class="alt" data-a="d" disabled>d</button>
  <button id="sendBtn" disabled>Send</button></div>
 <div class="links" id="links"></div>
</div></div>
<script>
const STEPS = [
 {g:"prep", t:"0 · Before you start", items:[
  ["tests","Run the 45+ automated tests","offline, under a second","rules"],
  ["llm_check","Check the AI providers","which AI answers (Groq / Gemini / Claude)","ai"]]},
 {g:"day1", t:"Day 1 · Eyes", items:[
  ["scan","Scan","Discover + OSV + dynamic Trivy/Grype + supply-chain checks","rules", "target"],
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
  ["apply2","Apply in the sandbox","sandbox branch, lockfiles --ignore-scripts, patch","rules"]]},
 {g:"proof", t:"Test and rescan · Report", items:[
  ["validate","Validate","full rescan, before vs after, verdict + graph diff","rules"],
  ["diff","Graph before vs after","rebuild graph_diff.html","rules"],
  ["report","Final report","guardian_report.html","rules"],
  ["policy","Policy gate","CI gate (exit 1 = blocked)","rules"],
  ["backup","Backup results","zip of runs/ for the demo","rules"]]}];
const $ = s => document.querySelector(s), esc = s => s.replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
let state = {repos:[], targets:[], stop:{}}, since = 0, running = false, n = 0;
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
async function refresh() {
  state = await api("/api/state");
  const cur = $("#repo").value || "juice-shop";
  $("#repo").innerHTML = state.repos.map(r => `<option ${r === cur ? "selected" : ""}>${r}</option>`).join("") || "<option value=''>(scan first)</option>";
  const t = $("#target"), tv = t.value || "targets/juice-shop";
  t.innerHTML = state.targets.map(x => `<option value="${x.path}" ${x.path === tv ? "selected" : ""}>${x.label}</option>`).join("")
    + `<option value="url">GitHub link…</option>`;
  links();
}
function links() {
  const r = $("#repo").value; if (!r) return $("#links").innerHTML = "";
  const L = [["Dashboard", "guardian.html"], ["Graph before vs after", "graph_diff.html"], ["Final report", "guardian_report.html"],
    ["findings.json", "findings.json"], ["analysis.txt", "analysis.txt"], ["plan.txt", "plan.txt"], ["audit trail", "audit.jsonl"]];
  $("#links").innerHTML = L.map(([n, f]) => `<a href="/runs/${encodeURIComponent(r)}/${f}" target="_blank">${n}</a>`).join("")
    + (r ? ` <a href="/runs/${encodeURIComponent(r)}-pr/guardian.html" target="_blank">PR dashboard</a>` : "")
    + ` <span id="ks" class="${state.stop[r] ? "stop-on" : ""}">${state.stop[r] ? "kill switch ON" : ""}</span>`;
}
$("#repo").addEventListener("change", links);
function setRunning(v) {
  running = v;
  document.querySelectorAll("[data-step],[data-k]").forEach(b => b.disabled = v);
  ["#stopBtn", "#answer", "#sendBtn"].forEach(s => $(s).disabled = !v);
  document.querySelectorAll("[data-a]").forEach(b => b.disabled = !v);
}
async function run(step) {
  const real = step === "apply2" ? "apply" : step;
  let target = "";
  if (real === "scan") { target = $("#target").value;
    if (target === "url") { target = prompt("GitHub link, e.g. https://github.com/snyk-labs/nodejs-goof") || ""; if (!target) return; } }
  if (step === "apply") { try { await api("/api/clear-approval", {repo: $("#repo").value}); } catch (e) {} }
  try { await api("/api/run", {step: real, repo: real === "scan" ? "" : $("#repo").value, target, offline: $("#offline").checked}); }
  catch (e) { $("#out").textContent += `\n[not started: ${e.message}]\n`; return; }
  document.querySelectorAll(".step").forEach(s => s.classList.remove("run"));
  $("#s-" + step).classList.add("run"); $("#s-" + step).dataset.last = "1";
  document.querySelectorAll(".step").forEach(s => { if (s.id !== "s-" + step) delete s.dataset.last; });
  since = 0; $("#out").innerHTML = ""; $("#title").textContent = $("#s-" + step).querySelector("b").firstChild.textContent;
  setRunning(true); poll();
}
async function poll() {
  const s = await api("/api/output?since=" + since); since = s.length;
  if (s.text) { const o = $("#out"), bottom = o.scrollTop + o.clientHeight >= o.scrollHeight - 30;
    o.innerHTML += esc(s.text).replace(/(https?:\/\/[^\s)'"]+)/g, '<a href="$1" target="_blank">$1</a>');
    if (bottom) o.scrollTop = o.scrollHeight; }
  $("#status").textContent = s.running ? "running…" : (s.code === null ? "" : s.code === 0 ? "finished" : "finished with exit code " + s.code);
  if (s.running) return setTimeout(poll, 400);
  setRunning(false);
  const el = document.querySelector('.step[data-last="1"]');
  if (el) { el.classList.remove("run"); el.classList.add(s.code === 0 ? "ok" : "bad"); }
  refresh();
}
document.addEventListener("click", async e => {
  const b = e.target.closest("button"); if (!b) return;
  if (b.dataset.step) return run(b.dataset.step);
  if (b.dataset.k !== undefined) { const r = await api("/api/killswitch", {repo: $("#repo").value, on: b.dataset.k === "1"});
    $("#out").textContent = `Kill switch ${r.stop ? "ON: runs/" + $("#repo").value + "/STOP created - apply will refuse" : "OFF: STOP file removed"}\n`;
    $("#s-killswitch").classList.add("ok"); return refresh(); }
  if (b.dataset.a) return send(b.dataset.a);
  if (b.id === "sendBtn") return send($("#answer").value);
  if (b.id === "stopBtn") return api("/api/stop", {});
});
async function send(t) { try { await api("/api/input", {text: t}); $("#answer").value = ""; } catch (e) {} }
$("#answer").addEventListener("keydown", e => { if (e.key === "Enter") send($("#answer").value); });
refresh();
</script></body></html>"""
