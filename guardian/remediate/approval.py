"""Human approval gate. Nothing is changed without an explicit decision bound to the exact plan hash.

Two channels: terminal (type the first 8 characters of the plan hash) or a local web page
(http://127.0.0.1:8770, bound to localhost only). The decision is written to approval.json and the audit trail.
"""
from __future__ import annotations

import html
import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from .. import audit


def _record(run_dir: Path, plan: dict, approved: list[str], channel: str, note: str = "") -> dict:
    rejected = [a["id"] for a in plan["actions"] if a["id"] not in approved]
    rec = {"plan_hash": plan["plan_hash"], "approved_actions": approved, "rejected_actions": rejected,
           "operator": audit.operator(), "channel": channel, "note": note,
           "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "decision": "approved" if approved else "rejected"}
    (run_dir / "approval.json").write_text(json.dumps(rec, indent=1), encoding="utf-8")
    audit.log(run_dir / "audit.jsonl", "approval", rec)
    return rec


def terminal(run_dir: Path, plan: dict, ask=input, log=print) -> dict:
    log(f"\nPlan {plan['plan_hash'][:12]} - {len(plan['actions'])} proposed actions:")
    for a in plan["actions"]:
        p = a["params"]
        tgt = p.get("package") or p.get("image") or p.get("action") or p.get("component", "")
        log(f"  {a['id']} {a['type']:<24} {tgt} {p.get('to') or p.get('version') or (p.get('sha') or p.get('digest') or '')[:19]}"
            f"  [{a['priority']}, compat: {a['compatibility']['level']}]"
            + (f"\n        critic: {a['critic']['concern']}" if a.get("critic") and a["critic"].get("concern") else ""))
    log("\nApprove: type the first 8 characters of the plan hash to approve ALL,")
    log("         or 'A-01,A-03' to approve only some, or 'reject'.")
    ans = ask("> ").strip()
    if ans.lower() in ("", "reject", "no", "n"):
        return _record(run_dir, plan, [], "terminal", "rejected by operator")
    if ans == plan["plan_hash"][:8]:
        return _record(run_dir, plan, [a["id"] for a in plan["actions"]], "terminal")
    ids = [x.strip().upper() for x in ans.split(",")]
    valid = [a["id"] for a in plan["actions"] if a["id"] in ids]
    if not valid:
        log("Nothing recognised - treated as REJECT (safe default).")
    return _record(run_dir, plan, valid, "terminal")


def web(run_dir: Path, plan: dict, port: int = 8770, log=print) -> dict:
    done: dict = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            rows = "".join(
                f"<tr><td><input type=checkbox name=a value='{a['id']}' {'checked' if a['type'] not in ('escalate',) else ''}></td>"
                f"<td>{a['id']}</td><td><b>{html.escape(a['type'])}</b><br><small>{html.escape(json.dumps(a['params'])[:180])}</small></td>"
                f"<td>{html.escape(a['risk'][:90])}<br><small>{a['priority']} · score {a['score']}</small></td>"
                f"<td>{html.escape(a['rationale'])}<br><small>compat: {html.escape(a['compatibility']['reason'])}<br>"
                f"rollback: {html.escape(a['rollback'])}</small>"
                + (f"<br><small><i>Agents' verdict: {html.escape(str(a['ai_inference'].get('risk_summary')))}</i></small>" if a.get('ai_inference') else "")
                + (f"<br><small><b>Critic:</b> {'agrees' if a['critic']['agree'] else 'DISAGREES'} {html.escape(a['critic'].get('concern', ''))}</small>" if a.get('critic') else "")
                + (f"<br><small>Planner agent: {html.escape(a['planner']['source'])}, {html.escape(a['planner']['status'])}</small>" if a.get('planner') else "")
                + "</td></tr>" for a in plan["actions"])
            body = f"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Guardian approval</title><style>body{{font:14px system-ui;margin:20px;background:#f6f7f9;color:#16202c}}
table{{border-collapse:collapse;background:#fff;width:100%}}td,th{{border-bottom:1px solid #ddd;padding:8px;vertical-align:top;text-align:left}}
button{{font:inherit;padding:8px 16px;margin:12px 8px 0 0;border-radius:6px;border:1px solid #999;cursor:pointer}}
.ok{{background:#1f7a3a;color:#fff}}.no{{background:#9e0f2e;color:#fff}}code{{background:#eee;padding:2px 5px}}</style></head><body>
<h2>Remediation approval - {html.escape(plan['repository'])}</h2>
<p>Plan hash <code>{plan['plan_hash']}</code>. Changes are applied only in a sandbox copy, never pushed or merged.</p>
<form method=post><table><tr><th></th><th>ID</th><th>Action</th><th>Risk</th><th>Why / impact</th></tr>{rows}</table>
<input type=hidden name=hash value="{plan['plan_hash']}"><p>Note: <input name=note size=60></p>
<button class=ok name=decision value=approve>Approve selected</button><button class=no name=decision value=reject>Reject all</button></form></body></html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body.encode())

        def do_POST(self):
            q = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode())
            if q.get("hash", [""])[0] != plan["plan_hash"]:
                self.send_response(409)
                self.end_headers()
                self.wfile.write(b"Plan changed - reload the page")
                return
            approved = q.get("a", []) if q.get("decision", [""])[0] == "approve" else []
            done["rec"] = _record(run_dir, plan, approved, "web", q.get("note", [""])[0])
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"<p style='font:16px system-ui'>Recorded: <b>{done['rec']['decision']}</b> "
                             f"({len(approved)} actions). You can close this tab.</p>".encode())
            threading.Thread(target=srv.shutdown, daemon=True).start()

    srv = HTTPServer(("127.0.0.1", port), H)
    log(f"[approve] open http://127.0.0.1:{port} to review and approve the plan (waiting...)")
    srv.serve_forever()
    return done.get("rec") or _record(run_dir, plan, [], "web", "server stopped without a decision")
