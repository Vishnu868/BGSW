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
    names, kinds = {}, {}
    for g, i2k in ((before, id2key_b), (after, id2key_a)):
        for n in g["nodes"]:
            names.setdefault(i2k[n["id"]], n.get("name", n["id"]))
            kinds.setdefault(i2k[n["id"]], n.get("kind", ""))
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
            nodes.append({"key": k, "name": names.get(k, k), "status": "context", "kind": kinds.get(k, "application"),
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
:root{--bg:#f6f7f9;--panel:#fff;--ink:#16202c;--muted:#5b6876;--line:#dfe3e8;--accent:#1f4e9c;--chip:#eef1f5;
--fixed:#1f9d55;--upgraded:#2f6db5;--replaced:#0e9aa7;--removed:#8a97a6;--added:#9b4dca;--remaining:#e89b0c;--newi:#d9432b;--ctx:#7d93ab}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0f141a;--panel:#171e26;--ink:#e6ebf0;--muted:#9aa8b6;--line:#2a3440;
 --accent:#7fb0ff;--chip:#222c37;--fixed:#34c47a;--upgraded:#5d97dd;--replaced:#2cc4cf;--removed:#9aa8b6;--added:#c07af0;--ctx:#6f8499}}
:root[data-theme=dark]{--bg:#0f141a;--panel:#171e26;--ink:#e6ebf0;--muted:#9aa8b6;--line:#2a3440;--accent:#7fb0ff;--chip:#222c37;
 --fixed:#34c47a;--upgraded:#5d97dd;--replaced:#2cc4cf;--removed:#9aa8b6;--added:#c07af0;--ctx:#6f8499}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{padding:16px 20px 8px;display:flex;flex-wrap:wrap;gap:12px;align-items:baseline;justify-content:space-between}
h1{font-size:20px;margin:0}h1 small{color:var(--muted);font-weight:400;font-size:13px;margin-left:8px}
.tiles{display:flex;flex-wrap:wrap;gap:10px;padding:0 20px 12px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:8px 14px;min-width:110px}
.tile b{display:block;font-size:20px;font-variant-numeric:tabular-nums}.tile span{color:var(--muted);font-size:12px}
nav{display:flex;gap:4px;padding:0 20px;border-bottom:1px solid var(--line)}
nav button{background:none;border:0;border-bottom:2px solid transparent;padding:8px 12px;color:var(--muted);font:inherit;cursor:pointer}
nav button.on{color:var(--ink);border-color:var(--accent);font-weight:600}
.tab{display:none;padding:12px 20px 20px}.tab.on{display:block}
.controls{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:10px}
input[type=search]{font:inherit;padding:5px 8px;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--ink)}
.legend{display:flex;flex-wrap:wrap;gap:12px;font-size:12px;color:var(--muted);margin-bottom:10px;align-items:center}
.legend label{display:flex;gap:5px;align-items:center;cursor:pointer;color:var(--muted)}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;vertical-align:-1px;border:2px solid transparent}
.split{display:grid;grid-template-columns:1fr 380px;gap:12px}
#net{height:72vh;background:var(--panel);border:1px solid var(--line);border-radius:10px}
#side{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px;height:72vh;overflow:auto}
.pill{display:inline-block;font-size:11px;font-weight:700;text-transform:uppercase;padding:1px 8px;border-radius:999px;color:#fff}
.chip{display:inline-block;background:var(--chip);border-radius:6px;padding:1px 7px;font-size:12px;margin:2px 4px 2px 0}
.path{font-family:ui-monospace,Consolas,monospace;font-size:12px;background:var(--chip);border-radius:6px;padding:6px 8px;word-break:break-word}
.muted{color:var(--muted)}h3{margin:0 0 6px}h4{margin:12px 0 4px;font-size:13px}
ul{margin:4px 0;padding-left:18px}li{font-size:12px;margin:2px 0}
.sev-critical{color:#e0455f;font-weight:600}.sev-high{color:#f0673f;font-weight:600}.sev-medium{color:var(--remaining)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:7px 10px;word-break:break-word;border-bottom:1px solid var(--line);vertical-align:top;font-size:13px}
th{color:var(--muted);font-weight:600;font-size:12px}tr.click{cursor:pointer}tr.click:hover{background:var(--chip)}
.tablewrap{overflow-x:auto}
@media (max-width:900px){.split{grid-template-columns:1fr}#net{height:60vh}#side{height:auto}header,.tiles,nav,.tab{padding-left:16px;padding-right:16px}}
</style></head><body>
<header><h1>Software Supply Chain Guardian <small id="repo"></small></h1><div class="muted">dependency graph before vs after the approved fixes</div></header>
<div class="tiles" id="tiles"></div>
<nav id="nav"><button data-t="graph" class="on">Graph before vs after</button><button data-t="table">Changed packages</button></nav>
<section class="tab on" id="t-graph">
 <div class="controls"><input type="search" id="find" placeholder="Find package (e.g. jsonwebtoken), Enter"><span class="muted" id="shown"></span></div>
 <div class="legend" id="legend"></div>
 <div class="split"><div id="net"></div><aside id="side"><h3>Click a package</h3><p class="muted">The view shows every package that
 changed, plus its path from the project. Packages are matched by name, so a version change is one node.</p></aside></div>
</section>
<section class="tab" id="t-table"><div class="tablewrap"><table id="tbl"></table></div></section>
<script>/*__VIS__*/</script>
<script>
const D = __DATA__;
const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const VAR = {fixed:"--fixed", upgraded:"--upgraded", replaced:"--replaced", removed:"--removed", added:"--added",
             remaining:"--remaining", new_issue:"--newi", context:"--ctx"};
const COL = Object.fromEntries(Object.entries(VAR).map(([k, v]) => [k, css(v)]));
const LBL = {fixed:"fixed (vulnerable before, clean now)", upgraded:"upgraded (new version)", replaced:"replaced (typosquat → genuine)",
             removed:"removed (dropped with the old version)", added:"added (new dependency)", remaining:"still vulnerable",
             new_issue:"NEW problem after the fix", context:"project / path"};
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
$("#repo").textContent = D.repo + " · approved actions " + (D.actions.map(a => a.id).join(", ") || "none");
const T = (a, b, s) => `<div class="tile"><b>${a} → ${b}</b><span>${s}</span></div>`;
const C = k => `<div class="tile"><b style="color:${COL[k]}">${D.counts[k]}</b><span>${k.replace("_", " ")}</span></div>`;
$("#tiles").innerHTML = T(D.before.components, D.after.components, "components") + T(D.before.findings, D.after.findings, "total findings")
  + T(D.before.sev.critical, D.after.sev.critical, "critical findings") + T(D.before.sev.high, D.after.sev.high, "high findings")
  + ["fixed", "upgraded", "replaced", "removed", "added", "remaining", "new_issue"].map(C).join("");
document.querySelectorAll("#nav button").forEach(b => b.onclick = () => {
  document.querySelectorAll("#nav button,.tab").forEach(x => x.classList.remove("on"));
  b.classList.add("on"); $("#t-" + b.dataset.t).classList.add("on"); });
const shown = new Set(Object.keys(COL).filter(k => k !== "remaining"));
const ECOL = {both: "#3b82f6", before: "#f97316", after: "#c026d3"};
$("#legend").innerHTML = Object.keys(COL).map(k => `<label><input type="checkbox" ${shown.has(k) ? "checked" : ""} data-k="${k}">
  <span class="dot" style="background:${k === "removed" ? "transparent" : COL[k]};border-color:${COL[k]}${k === "removed" ? ";border-style:dashed" : ""}"></span>${LBL[k]}</label>`).join("")
  + `<span>★ project</span><span>■ container image</span><span>◆ CI action</span>`
  + `<span>Lines: <b style="color:${ECOL.both}">━━</b> kept · <b style="color:${ECOL.before}">╍╍</b> only before (dropped) · <b style="color:${ECOL.after}">━━</b> new after the fix</span>`;
const ver = n => n.before.length || n.after.length
  ? (n.before.join(",") || "-") + (n.before.join() === n.after.join() ? "" : " → " + (n.after.join(",") || "gone")) : "";
const shapeOf = n => ["repository", "application"].includes(n.kind) ? "star" : n.kind === "container" ? "square"
  : ["action", "ci-action"].includes(n.kind) ? "diamond" : "dot";
function nodeOf(n) {
  const c = COL[n.status] || COL.context, ctx = n.status === "context";
  const size = ctx ? 16 : (n.before_findings.length || n.after_findings.length ? 13 : 8);
  return {id: n.key, label: n.name + (ver(n) ? "\n" + ver(n) : "") + (n.action ? "  [" + n.action + "]" : ""),
          shape: shapeOf(n), size,
          color: {background: n.status === "removed" ? css("--panel") : c, border: c, highlight: {background: c, border: css("--ink")}},
          shapeProperties: {borderDashes: n.status === "removed" ? [4, 3] : false}, borderWidth: n.status === "removed" ? 2 : 1,
          font: {size: 15, color: css("--ink"), strokeWidth: 3, strokeColor: css("--panel")},
          scaling: {label: {enabled: true, min: 11, max: 18, drawThreshold: 1}},
          hidden: !shown.has(n.status) && !n.on_path};
}
const nodes = new vis.DataSet(D.nodes.map(nodeOf));
const edges = new vis.DataSet(D.edges.map((e, i) => ({id: i, from: e.from, to: e.to, arrows: {to: {enabled: true, scaleFactor: 0.5}},
  dashes: e.kind === "before" ? [8, 6] : false, color: {color: ECOL[e.kind], highlight: css("--ink"), hover: css("--ink"), opacity: 1},
  width: 3, hoverWidth: 2, selectionWidth: 3})));
const net = new vis.Network($("#net"), {nodes, edges}, {
  layout: {improvedLayout: D.nodes.length < 400},
  physics: {solver: "forceAtlas2Based", forceAtlas2Based: {gravitationalConstant: -70, springLength: 110}, stabilization: {iterations: 250}},
  interaction: {hover: true}});
net.once("stabilizationIterationsDone", () => net.setOptions({physics: false}));
const count = () => $("#shown").textContent = `${nodes.get({filter: n => !n.hidden}).length} packages · ${D.edges.length} links shown`;
count();
function reveal(status) {
  if (shown.has(status)) return;
  shown.add(status); document.querySelector(`#legend [data-k="${status}"]`).checked = true;
  nodes.update(D.nodes.map(x => ({id: x.key, hidden: !shown.has(x.status) && !x.on_path}))); count();
}
document.querySelectorAll("#legend input").forEach(cb => cb.addEventListener("change", () => {
  cb.checked ? shown.add(cb.dataset.k) : shown.delete(cb.dataset.k);
  nodes.update(D.nodes.map(n => ({id: n.key, hidden: !shown.has(n.status) && !n.on_path}))); count(); }));
const byKey = Object.fromEntries(D.nodes.map(n => [n.key, n]));
const fl = fs => fs.length ? "<ul>" + fs.map(f => `<li class="sev-${f.sev}">${esc(f.sev)}: ${esc(f.title)}</li>`).join("") + "</ul>" : "<p class='muted'>none</p>";
function side(n) {
  const act = D.actions.find(a => a.id === n.action);
  $("#side").innerHTML = `<h3>${esc(n.name)}</h3><span class="pill" style="background:${COL[n.status]}">${esc(LBL[n.status])}</span>
    <h4>Version</h4><div class="chip">${esc(ver(n) || "-")}</div>${n.replaced_by ? `<div class="chip">replaced by ${esc(n.replaced_by)}</div>` : ""}
    ${act ? `<h4>Caused by approved action ${act.id}</h4><div class="chip">${esc(act.type)}</div><div class="path">${esc(JSON.stringify(act.params))}</div>` :
      ["removed", "added", "fixed"].includes(n.status) ? "<h4>Why it changed</h4><p class='muted'>Consequence of upgrading the package that brings it in (see the path).</p>" : ""}
    <h4>Dependency path</h4><div class="path">${(n.path || []).map(k => esc((byKey[k] || {name: k}).name)).join(" → ")}</div>
    <h4>Findings before (${n.before_findings.length})</h4>${fl(n.before_findings)}
    <h4>Findings after (${n.after_findings.length})</h4>${fl(n.after_findings)}`;
}
function go(n) { reveal(n.status); net.selectNodes([n.key]); net.focus(n.key, {scale: 1.2, animation: true}); side(n); }
net.on("click", p => { if (p.nodes.length && byKey[p.nodes[0]]) side(byKey[p.nodes[0]]); });
$("#find").addEventListener("keydown", e => { if (e.key !== "Enter") return;
  const q = e.target.value.trim().toLowerCase(), n = D.nodes.find(x => x.name.toLowerCase().includes(q)); if (n) go(n); });
const order = ["new_issue", "remaining", "replaced", "fixed", "upgraded", "removed", "added"];
const rows = D.nodes.filter(n => order.includes(n.status)).sort((a, b) => order.indexOf(a.status) - order.indexOf(b.status) || a.name.localeCompare(b.name));
$("#tbl").innerHTML = "<tr><th>Status</th><th>Package</th><th>Version before → after</th><th>Findings before → after</th><th>Action</th></tr>"
  + rows.map(n => `<tr class="click" data-k="${esc(n.key)}"><td><span class="pill" style="background:${COL[n.status]}">${n.status.replace("_", " ")}</span></td>
    <td>${esc(n.name)}${n.direct ? " <span class='muted'>(direct)</span>" : ""}</td><td>${esc(ver(n))}</td>
    <td>${n.before_findings.length} → ${n.after_findings.length}</td><td>${esc(n.action)}</td></tr>`).join("");
$("#tbl").addEventListener("click", e => { const tr = e.target.closest("tr.click"); if (!tr) return;
  document.querySelector('#nav [data-t="graph"]').click(); go(byKey[tr.dataset.k]); });
</script></body></html>"""
