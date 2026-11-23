"""Machine-readable findings.json + human-readable report.txt + console summary."""
from __future__ import annotations

from collections import Counter

from ..model import CATEGORIES, SEVERITY_RANK


def findings_json(graph, findings, meta: dict, changes: dict) -> dict:
    libs = [c for c in graph.nodes.values() if c.kind == "library"]
    paths, intro = graph.shortest_paths(), graph.introduced_by()
    items = []
    for i, f in enumerate(findings, 1):
        d = f.to_dict()
        d["id"] = f"F-{i:03d}"
        c = graph.nodes.get(f.component)
        if c:
            d["component_detail"] = {"name": c.name, "version": c.version, "ecosystem": c.ecosystem, "kind": c.kind,
                                     "direct": c.direct, "dev_only": c.dev, "purl": c.purl,
                                     "dependency_path": [graph.nodes[p].name + ("@" + graph.nodes[p].version if graph.nodes[p].version else "")
                                                         for p in paths.get(c.id, [])],
                                     "introduced_by": sorted(graph.nodes[x].name for x in intro.get(c.id, set()) if x != c.id)}
        d["evidence_type"] = "verified"     # produced by a deterministic check; AI inference is added on Day 2
        items.append(d)
    return {
        "schema": "guardian.findings/v1",
        "repository": meta,
        "summary": {
            "components": len(libs), "direct": sum(c.direct for c in libs), "transitive": sum(not c.direct for c in libs),
            "production": sum(not c.dev for c in libs), "dev_only": sum(c.dev for c in libs),
            "container_images": sum(c.kind == "container" for c in graph.nodes.values()),
            "ci_actions": sum(c.kind == "action" for c in graph.nodes.values()),
            "edges": len(graph.edges),
            "findings_by_severity": dict(Counter(f.severity for f in findings)),
            "findings_by_category": {k: sum(f.category == k for f in findings) for k in CATEGORIES},
        },
        "changes": changes,
        "limitations": graph.notes,
        "findings": items,
    }


def markdown(r: dict) -> str:
    s, m = r["summary"], r["repository"]
    out = [f"# Guardian report - {m['repo']}", "",
           f"Scanned {m['scanned_at']} · vulnerability source: {m['osv_source']} · ecosystems: {', '.join(m['ecosystems'])}", "",
           "## What is in the application", "",
           f"- **{s['components']} components** ({s['direct']} direct, {s['transitive']} transitive; "
           f"{s['production']} production, {s['dev_only']} dev-only), {s['edges']} dependency edges",
           f"- {s['container_images']} container images, {s['ci_actions']} CI actions", "",
           "## What appears risky", "", "| Category | Findings |", "|---|---|"]
    out += [f"| {k} {CATEGORIES[k]} | {v} |" for k, v in s["findings_by_category"].items()]
    ch = r.get("changes") or {}
    out += ["", "## What changed", ""]
    if ch.get("baseline"):
        out += [f"Since baseline {ch['baseline']}: {len(ch['added'])} added, {len(ch['removed'])} removed, "
                f"{len(ch['changed'])} version changes, **{len(ch['tampered'])} integrity/source changes**"]
    else:
        out += ["First scan - this SBOM is now the baseline for the next comparison."]
    out += ["", "## Top findings", "", "| ID | Severity | Cat. | Finding | Path / evidence | Recommendation |", "|---|---|---|---|---|---|"]
    top = sorted(r["findings"], key=lambda f: -SEVERITY_RANK[f["severity"]])[:40]
    for f in top:
        cd = f.get("component_detail") or {}
        ev = " > ".join(cd.get("dependency_path", [])[-4:]) or "; ".join(e["detail"] for e in f["evidence"][:1])
        out.append(f"| {f['id']} | {f['severity']} | {f['category']} | {f['title'].replace('|', '/')} | {ev.replace('|', '/')} | "
                   f"{f['recommendation'].replace('|', '/')} |")
    if r["limitations"]:
        out += ["", "## Limitations", ""] + [f"- {n}" for n in r["limitations"]]
    return "\n".join(out) + "\n"


def console_summary(r: dict) -> str:
    s = r["summary"]
    sev = s["findings_by_severity"]
    lines = [f"  {s['components']} components ({s['direct']} direct / {s['transitive']} transitive), {s['edges']} edges",
             "  findings: " + ", ".join(f"{k} {sev.get(k, 0)}" for k in ("critical", "high", "medium", "low", "info")),
             "  by category: " + ", ".join(f"{k}:{v}" for k, v in s["findings_by_category"].items())]
    return "\n".join(lines)
