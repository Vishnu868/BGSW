"""Fill in transitive dependencies for projects that have no lockfile (requirements.txt, pom.xml)
using Google's deps.dev resolver. These versions are what a fresh install would resolve today,
so they are marked as resolved, not locked."""
from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..model import Component, Graph, component_id

CACHE = Path(__file__).resolve().parents[2] / ".cache" / "depsdev"
SYSTEM = {"PyPI": "pypi", "Maven": "maven", "npm": "npm", "crates.io": "cargo"}
ECO = {"PYPI": "PyPI", "MAVEN": "Maven", "NPM": "npm", "CARGO": "crates.io"}


def _fetch(eco: str, name: str, version: str, offline: bool):
    key = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{eco}_{name}_{version}")
    f = CACHE / f"{key}.json"
    if f.exists():
        return json.loads(f.read_text(encoding="utf-8"))
    if offline:
        return None
    url = (f"https://api.deps.dev/v3/systems/{SYSTEM[eco]}/packages/{urllib.parse.quote(name, safe='')}"
           f"/versions/{urllib.parse.quote(version, safe='')}:dependencies")
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "supply-chain-guardian/0.1"}),
                                    timeout=20) as r:
            data = json.loads(r.read())
    except Exception:
        data = {"nodes": [], "edges": [], "error": "unavailable"}
    CACHE.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(data), encoding="utf-8")
    return data


def expand(graph: Graph, offline: bool = False) -> int:
    kids = graph.children()
    todo = [c for c in graph.nodes.values()
            if c.kind == "library" and c.direct and c.exact and c.ecosystem in ("PyPI", "Maven")
            and not kids.get(c.id)]
    if not todo:
        return 0
    with ThreadPoolExecutor(12) as ex:
        results = list(ex.map(lambda c: _fetch(c.ecosystem, c.name, c.version, offline), todo))
    added = 0
    for c, data in zip(todo, results):
        if not data or not data.get("nodes"):
            continue
        ids = []
        for n in data["nodes"]:
            vk = n["versionKey"]
            eco = ECO.get(vk["system"], c.ecosystem)
            name = vk["name"].lower() if eco == "PyPI" else vk["name"]
            cid = component_id(eco, name, vk["version"])
            if n.get("relation") == "SELF":
                ids.append(c.id)
                continue
            before = cid in graph.nodes
            graph.add(Component(id=cid, name=name, version=vk["version"], ecosystem=eco,
                                manifests=set(c.manifests) | {"resolved:deps.dev"}), dev=c.dev)
            added += not before
            ids.append(cid)
        for e in data.get("edges", []):
            graph.link(ids[e["fromNode"]], ids[e["toNode"]])
    if added:
        graph.notes.append(f"{added} transitive components for lockfile-less projects were resolved with deps.dev "
                           "(versions a fresh install would get today, not pinned by a lockfile)")
    return added
