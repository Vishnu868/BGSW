"""Self-contained interactive dashboard: dependency graph + findings + inventory (+ agent verdicts after analyze).
Works offline. The page data is also saved as graph_data.json so later stages can re-render it."""
from __future__ import annotations

import json
from pathlib import Path

from ..model import SEVERITY_RANK

ASSET = Path(__file__).with_name("assets") / "vis-network.min.js"
TEMPLATE = Path(__file__).with_name("template.html")


def build_data(graph, findings, meta: dict, changes: dict | None = None) -> dict:
    paths = graph.shortest_paths()
    intro = graph.introduced_by()
    by_comp: dict[str, list[int]] = {}
    for i, f in enumerate(findings):
        if f.component:
            by_comp.setdefault(f.component, []).append(i)
    nodes = []
    for cid, c in graph.nodes.items():
        fi = by_comp.get(cid, [])
        sev = max((findings[i].severity for i in fi), key=lambda s: SEVERITY_RANK[s], default="")
        nodes.append({"id": cid, "name": c.name, "version": c.version, "eco": c.ecosystem, "kind": c.kind,
                      "direct": c.direct, "dev": c.dev, "exact": c.exact, "sev": sev, "f": fi,
                      "install": c.install_script, "resolved": c.resolved, "purl": c.purl,
                      "manifests": sorted(c.manifests), "path": paths.get(cid, []),
                      "via": sorted(graph.nodes[d].name for d in intro.get(cid, set()) if d != cid)[:12]})
    return {"meta": meta, "nodes": nodes, "edges": sorted(graph.edges), "roots": graph.roots,
            "findings": [f.to_dict() for f in findings], "notes": graph.notes, "changes": changes or {},
            "analysis": None}


def analysis_view(a: dict) -> dict:
    """Compact agent results keyed by component id (for the graph side panel and the Agents / Review tabs)."""
    by_key = {}
    for it in a["items"]:
        case = a["cases"].get(it["id"])
        by_key[it["key"]] = {"id": it["id"], "priority": it["priority"], "score": it["score"], "base_score": it["base_score"],
                             "headline": it["headline"], "reachability": it["reachability"]["status"],
                             "ai": it.get("ai"), "triage_reason": it.get("triage_reason"),
                             "case": case}
    return {"llm": a["llm"], "counts": a["counts"], "agents": a["agents"], "summary": a["summary"],
            "review_queue": a["review_queue"], "by_key": by_key}


def render(data: dict) -> str:
    blob = json.dumps(data, default=str).replace("</", "<\\/")
    page = TEMPLATE.read_text(encoding="utf-8")
    return (page.replace("/*__VIS__*/", ASSET.read_text(encoding="utf-8"))
                .replace("__DATA__", blob)
                .replace("__TITLE__", f"Guardian - {data['meta'].get('repo', '')}"))


def build(graph, findings, meta: dict, changes: dict | None = None) -> str:
    return render(build_data(graph, findings, meta, changes))
