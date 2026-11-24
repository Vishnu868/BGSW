"""Before vs after dependency graph (after apply + validate): what changed, coloured, with the action that caused it.

Inputs : runs/<repo>/graph_data.json                (scan of the original repository = BEFORE)
         runs/<repo>/after/<repo>/graph_data.json   (validate's rescan of the remediated sandbox = AFTER)
         runs/<repo>/plan.json                      (which approved action changed which package)
Output : runs/<repo>/graph_diff.html  (self-contained, works offline)  +  graph_diff.json

Packages are matched by ecosystem + name (not version), so jsonwebtoken 0.4.0 and 9.0.3 are the same package.
Status of every package:
  fixed       had findings before, none after (upgraded, replaced or its subtree removed)
  upgraded    same package, different version (no findings before)
  removed     in the graph before, gone after (e.g. a vulnerable subtree that the upgrade dropped)
  added       new after the fix (e.g. dependencies of the new version, the genuine package of a typosquat)
  replaced    typosquat swapped for the genuine package (npm_replace action)
  remaining   still has findings after the fix (e.g. escalated: no fixed version exists)
  new_issue   a finding that did not exist before (a fix that created a problem)
  unchanged   not shown in the focus view (only on the path to a change)
"""
from __future__ import annotations

import json
from pathlib import Path

from .html import ASSET

SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1}
STATUS = ["new_issue", "remaining", "replaced", "fixed", "upgraded", "removed", "added"]


def _key(n: dict) -> str:
    if n.get("kind") == "library":
        return f"{n.get('eco', '')}:{n.get('name', '')}"
    return n["id"].split("@")[0] if n.get("kind") == "library" else n["id"]


def _load(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def _worst(fs: list) -> str:
    return max(fs, key=lambda s: SEV.get(s, 0)) if fs else ""


def build(run_dir: Path) -> dict:
    before = _load(run_dir / "graph_data.json")
    after_dirs = [p for p in (run_dir / "after").glob("*/graph_data.json")]
    if not after_dirs:
        raise FileNotFoundError("no after-scan found: run `guardian validate <repo>` first")
    after = _load(after_dirs[0])
    plan = _load(run_dir / "plan.json") if (run_dir / "plan.json").exists() else {"actions": []}

    def index(g):
        nodes, f_by = {}, {}
        for f in g["findings"]:
            if f.get("rule", "").startswith("diff."):   # "changed since baseline" notes describe the fix itself
                continue
            f_by.setdefault(f.get("component", ""), []).append(f)
        for n in g["nodes"]:
            k = _key(n)
            fs = f_by.get(n["id"], [])
            cur = nodes.get(k)
            entry = {"id": n["id"], "name": n.get("name", ""), "version": n.get("version", ""), "kind": n.get("kind", ""),
                     "eco": n.get("eco", ""), "direct": n.get("direct", False), "dev": n.get("dev", False),
                     "path": n.get("path", []),
                     "findings": [{"sev": f["severity"], "title": f["title"], "cat": f["category"]} for f in fs]}
            if cur is None:
                nodes[k] = entry
            else:                                  # several versions of one package: keep a list
                cur.setdefault("others", []).append(entry)
        return nodes

    B, A = index(before), index(after)
    id2key_b = {n["id"]: _key(n) for n in before["nodes"]}
    id2key_a = {n["id"]: _key(n) for n in after["nodes"]}

    # which approved action touched which package
    act_by: dict[str, str] = {}
    replaced: dict[str, str] = {}
    for a in plan.get("actions", []):
        p = a.get("params", {})
        if p.get("package"):
            act_by[p["package"]] = a["id"]
        if a.get("type") == "npm_replace" and p.get("with"):
            act_by[p["with"]] = a["id"]
            replaced[p.get("package", "")] = p["with"]

    def versions(e):
        return sorted({e["version"]} | {o["version"] for o in e.get("others", [])}) if e else []

    def all_f(e):
        return (e["findings"] + [f for o in e.get("others", []) for f in o["findings"]]) if e else []

    pkgs = {}
    for k in set(B) | set(A):
        b, a = B.get(k), A.get(k)
        e = b or a
        if e["kind"] not in ("library", "container", "ci-action", "action"):
            continue
        fb, fa = all_f(b), all_f(a)
        tb, ta = {f["title"].split(":")[0] for f in fb}, {f["title"].split(":")[0] for f in fa}
        name = e["name"]
        if b and not a:
            status = "fixed" if fb else "removed"
            if name in replaced:
                status = "replaced"
        elif a and not b:
            status = "new_issue" if fa else "added"
        elif ta - tb:
            status = "new_issue"
        elif fa:
            status = "remaining"
        elif fb:
            status = "fixed"
        elif versions(b) != versions(a):
            status = "upgraded"
        else:
            status = "unchanged"
        pkgs[k] = {"key": k, "name": name, "eco": e["eco"], "kind": e["kind"], "status": status,
                   "before": versions(b), "after": versions(a), "direct": bool((a or b)["direct"]),
                   "dev": bool((a or b)["dev"]),
                   "before_findings": fb, "after_findings": fa, "worst_before": _worst([f["sev"] for f in fb]),
                   "worst_after": _worst([f["sev"] for f in fa]), "action": act_by.get(name, ""),
                   "replaced_by": replaced.get(name, ""),
                   "path": [id2key_b.get(i, i) for i in (b or a)["path"]] if b else [id2key_a.get(i, i) for i in a["path"]]}

    changed = {k for k, v in pkgs.items() if v["status"] != "unchanged"}
    focus = set(changed)
    on_path: set = set()
    for k in changed:
        focus.update(p for p in pkgs[k]["path"])
        if pkgs[k]["status"] != "remaining":
            on_path.update(p for p in pkgs[k]["path"] if p != k)
    for k in on_path:                       # ancestors of a change stay visible even if their own status is hidden
        if k in pkgs:
            pkgs[k]["on_path"] = True
    roots = {id2key_b.get(r, r) for r in before.get("roots", [])} | {id2key_a.get(r, r) for r in after.get("roots", [])}
    focus |= roots
    names = {}
    for g, i2k in ((before, id2key_b), (after, id2key_a)):
        for n in g["nodes"]:
            names.setdefault(i2k[n["id"]], n.get("name", n["id"]))
    eb = {(id2key_b.get(s, s), id2key_b.get(t, t)) for s, t in before["edges"]}
    ea = {(id2key_a.get(s, s), id2key_a.get(t, t)) for s, t in after["edges"]}
    edges = []
    for s, t in eb | ea:
        if s in focus and t in focus and s != t:
            edges.append({"from": s, "to": t, "kind": "both" if (s, t) in eb and (s, t) in ea else
                          ("before" if (s, t) in eb else "after")})
    nodes = []
    for k in focus:
        if k in pkgs:
            nodes.append(pkgs[k])
        else:
            nodes.append({"key": k, "name": names.get(k, k), "status": "context", "kind": "project",
                          "before": [], "after": [], "before_findings": [], "after_findings": [], "action": ""})

    def sev_count(g):
        c = {s: 0 for s in SEV}
        for f in g["findings"]:
            c[f["severity"]] = c.get(f["severity"], 0) + 1
        return c

    counts = {s: sum(1 for v in pkgs.values() if v["status"] == s) for s in STATUS}
    data = {"repo": before["meta"].get("repo", run_dir.name),
            "before": {"components": sum(1 for n in before["nodes"] if n.get("kind") == "library"),
                       "findings": len(before["findings"]), "sev": sev_count(before)},
            "after": {"components": sum(1 for n in after["nodes"] if n.get("kind") == "library"),
                      "findings": len(after["findings"]), "sev": sev_count(after)},
            "counts": counts, "nodes": nodes, "edges": edges,
            "actions": [{"id": a["id"], "type": a["type"], "params": a.get("params", {})} for a in plan.get("actions", [])]}
    return data


def write(run_dir: Path, log=print) -> Path:
    data = build(run_dir)
    (run_dir / "graph_diff.json").write_text(json.dumps(data, indent=1), encoding="utf-8")
    html = PAGE.replace("/*__VIS__*/", ASSET.read_text(encoding="utf-8")).replace("__DATA__", json.dumps(data))
    out = run_dir / "graph_diff.html"
    out.write_text(html, encoding="utf-8")
    c = data["counts"]
    log(f"[diff] graph before vs after: fixed {c['fixed']}, upgraded {c['upgraded']}, replaced {c['replaced']}, "
        f"removed {c['removed']}, added {c['added']}, remaining {c['remaining']}, new issues {c['new_issue']} -> {out}")
    return out


PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Graph before vs after</title>
<style>
:root{--bg:#f6f8fb;--card:#fff;--ink:#16202c;--muted:#5b6876;--line:#d5dbe3;--navy:#1e3a8a}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 "Segoe UI",Roboto,Arial,sans-serif;background:var(--bg);color:var(--ink)}
header{padding:14px 20px;background:var(--card);border-bottom:1px solid var(--line)}
h1{margin:0;font-size:20px}h1 span{color:#c8194e}.sub{color:var(--muted);margin-top:2px}
.tiles{display:flex;gap:10px;flex-wrap:wrap;padding:12px 20px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px;min-width:150px}
.tile b{display:block;font-size:22px}.tile small{color:var(--muted)}
.legend{display:flex;gap:14px;flex-wrap:wrap;padding:0 20px 8px;align-items:center}
.legend label{display:flex;gap:6px;align-items:center;cursor:pointer;user-select:none}
.dot{width:14px;height:14px;border-radius:50%;display:inline-block;border:2px solid transparent}
main{display:grid;grid-template-columns:1fr 360px;gap:12px;padding:0 20px 20px}
#net{height:640px;background:var(--card);border:1px solid var(--line);border-radius:10px}
aside{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;height:640px;overflow:auto}
aside h3{margin:0 0 6px}.pill{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:12px}
table{width:100%;border-collapse:collapse;margin:0 20px 30px;width:calc(100% - 40px);background:var(--card)}
th,td{border:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}th{background:#eef2f7}
.f{font-size:12px;color:var(--muted)}.sev-critical{color:#8b0f2a;font-weight:600}.sev-high{color:#d9442b;font-weight:600}
@media (max-width:900px){main{grid-template-columns:1fr}aside{height:auto}}
</style></head><body>
<header><h1><span>Dependency graph</span> before vs after the approved fixes</h1>
<div class="sub" id="sub"></div></header>
<div class="tiles" id="tiles"></div>
<div class="legend" id="legend"></div>
<main><div id="net"></div><aside id="side"><h3>Click a package</h3><p class="f">The view shows every package that changed,
plus its path from the project. Packages are matched by name, so a version change is one node.</p></aside></main>
<table id="tbl"></table>
<script>/*__VIS__*/</script>
<script>
const D = __DATA__;
const COL = {fixed:"#1f7a3a", upgraded:"#1e3a8a", replaced:"#0e7c86", removed:"#9aa4b1", added:"#6b3fa0",
             remaining:"#d08a00", new_issue:"#c8194e", context:"#5b6876"};
const LBL = {fixed:"fixed (vulnerable before, clean now)", upgraded:"upgraded (new version)", replaced:"replaced (typosquat -> genuine)",
             removed:"removed (dropped with the old version)", added:"added (new dependency)", remaining:"still vulnerable",
             new_issue:"NEW problem after the fix", context:"project / path"};
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
$("#sub").textContent = `${D.repo}: before = original scan, after = rescan of the remediated sandbox (validate). `
  + `Approved actions: ${D.actions.map(a => a.id).join(", ") || "none"}.`;
const t = (h, b, a, s) => `<div class="tile"><small>${h}</small><b>${b} &rarr; ${a}</b><small>${s || ""}</small></div>`;
$("#tiles").innerHTML = t("components", D.before.components, D.after.components)
  + t("findings", D.before.findings, D.after.findings)
  + t("critical", D.before.sev.critical, D.after.sev.critical) + t("high", D.before.sev.high, D.after.sev.high)
  + Object.entries(D.counts).map(([k, v]) => `<div class="tile"><small>${LBL[k]}</small><b style="color:${COL[k]}">${v}</b></div>`).join("");
const shown = new Set(Object.keys(COL).filter(k => k !== "remaining"));   // untouched-but-vulnerable: off by default
$("#legend").innerHTML = Object.keys(COL).map(k => `<label><input type="checkbox" ${shown.has(k) ? "checked" : ""} data-k="${k}">
  <span class="dot" style="background:${k === "removed" ? "#fff" : COL[k]};border-color:${COL[k]}${k === "removed" ? ";border-style:dashed" : ""}"></span>${LBL[k]}</label>`).join("")
  + `<span style="margin-left:12px">Lines:</span>
     <span><b style="color:#2563eb">━━</b> link kept</span>
     <span><b style="color:#f97316">╍╍</b> link only before (dropped)</span>
     <span><b style="color:#a21caf">━━</b> new link after the fix</span>`;
const ver = n => n.before.length || n.after.length
  ? (n.before.join(",") || "-") + (n.before.join() === n.after.join() ? "" : " → " + (n.after.join(",") || "gone")) : "";
function nodeOf(n) {
  const c = COL[n.status] || COL.context;
  const big = n.status === "context" ? 14 : (n.before_findings.length || n.after_findings.length ? 18 : 11);
  return {id: n.key, label: n.name + (ver(n) ? "\n" + ver(n) : "") + (n.action ? "  [" + n.action + "]" : ""),
          shape: n.status === "context" ? "box" : "dot", size: big,
          color: {background: n.status === "removed" ? "#ffffff" : c, border: c, highlight: {background: c, border: "#16202c"}},
          shapeProperties: {borderDashes: n.status === "removed" ? [4, 3] : false}, borderWidth: n.status === "removed" ? 2 : 1,
          font: {size: 16, color: n.status === "removed" ? "#5b6876" : "#16202c", multi: false, background: "rgba(255,255,255,0.8)"},
          scaling: {label: {enabled: true, min: 12, max: 20, drawThreshold: 1}},
          hidden: !shown.has(n.status) && !n.on_path};
}
const nodes = new vis.DataSet(D.nodes.map(nodeOf));
// bright, thick lines: blue = link kept, orange dashed = link only before (dropped), violet = new link after the fix
const ECOL = {both: "#2563eb", before: "#f97316", after: "#a21caf"};
const edges = new vis.DataSet(D.edges.map((e, i) => ({id: i, from: e.from, to: e.to, arrows: {to: {enabled: true, scaleFactor: 0.6}},
  dashes: e.kind === "before" ? [8, 6] : false, color: {color: ECOL[e.kind], highlight: "#16202c", hover: "#16202c", opacity: 1},
  width: 4, hoverWidth: 2, selectionWidth: 3})));
const net = new vis.Network($("#net"), {nodes, edges}, {
  layout: {improvedLayout: D.nodes.length < 400},
  physics: {solver: "forceAtlas2Based", forceAtlas2Based: {gravitationalConstant: -60, springLength: 110},
            stabilization: {iterations: 250}}, interaction: {hover: true}});
net.once("stabilizationIterationsDone", () => net.setOptions({physics: false}));
document.querySelectorAll("#legend input").forEach(cb => cb.addEventListener("change", () => {
  cb.checked ? shown.add(cb.dataset.k) : shown.delete(cb.dataset.k);
  nodes.update(D.nodes.map(n => ({id: n.key, hidden: !shown.has(n.status) && !n.on_path})));
}));
const byKey = Object.fromEntries(D.nodes.map(n => [n.key, n]));
const fl = fs => fs.length ? "<ul>" + fs.map(f => `<li class="sev-${f.sev}">${esc(f.sev)}: ${esc(f.title)}</li>`).join("") + "</ul>" : "<p class='f'>none</p>";
function side(n) {
  const act = D.actions.find(a => a.id === n.action);
  $("#side").innerHTML = `<h3>${esc(n.name)}</h3><span class="pill" style="background:${COL[n.status]}">${esc(LBL[n.status])}</span>
    <p><b>Version:</b> ${esc(ver(n) || "-")}${n.replaced_by ? "<br><b>Replaced by:</b> " + esc(n.replaced_by) : ""}</p>
    ${act ? `<p><b>Caused by approved action ${act.id}</b> (${esc(act.type)})<br><span class="f">${esc(JSON.stringify(act.params))}</span></p>` :
      (n.status === "removed" || n.status === "added" || n.status === "fixed") ? "<p class='f'>Changed as a consequence of an upgrade of the package that brings it in (see the path).</p>" : ""}
    <p><b>Path from the project:</b><br><span class="f">${(n.path || []).map(k => esc((byKey[k] || {name: k}).name)).join(" &rarr; ")}</span></p>
    <p><b>Findings before (${n.before_findings.length})</b></p>${fl(n.before_findings)}
    <p><b>Findings after (${n.after_findings.length})</b></p>${fl(n.after_findings)}`;
}
net.on("click", p => { if (p.nodes.length && byKey[p.nodes[0]]) side(byKey[p.nodes[0]]); });
const order = ["new_issue", "remaining", "replaced", "fixed", "upgraded", "removed", "added"];
const rows = D.nodes.filter(n => order.includes(n.status)).sort((a, b) => order.indexOf(a.status) - order.indexOf(b.status) || a.name.localeCompare(b.name));
$("#tbl").innerHTML = "<tr><th>Status</th><th>Package</th><th>Version before &rarr; after</th><th>Findings before &rarr; after</th><th>Action</th></tr>"
  + rows.map(n => `<tr><td><span class="pill" style="background:${COL[n.status]}">${n.status.replace("_", " ")}</span></td>
    <td>${esc(n.name)}${n.direct ? " <span class='f'>(direct)</span>" : ""}</td><td>${esc(ver(n))}</td>
    <td>${n.before_findings.length} &rarr; ${n.after_findings.length}</td><td>${esc(n.action)}</td></tr>`).join("");
</script></body></html>"""
