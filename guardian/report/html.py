"""Self-contained interactive dashboard: dependency graph + findings + inventory (works offline)."""
from __future__ import annotations

import json
from pathlib import Path

from ..model import SEVERITY_RANK

ASSET = Path(__file__).with_name("assets") / "vis-network.min.js"
TEMPLATE = Path(__file__).with_name("template.html")


def build(graph, findings, meta: dict, changes: dict | None = None) -> str:
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
    data = {"meta": meta, "nodes": nodes, "edges": sorted(graph.edges), "roots": graph.roots,
            "findings": [f.to_dict() for f in findings], "notes": graph.notes, "changes": changes or {}}
    blob = json.dumps(data).replace("</", "<\\/")
    html = TEMPLATE.read_text(encoding="utf-8")
    return (html.replace("/*__VIS__*/", ASSET.read_text(encoding="utf-8"))
                .replace("__DATA__", blob)
                .replace("__TITLE__", f"Guardian - {meta.get('repo', '')}"))
