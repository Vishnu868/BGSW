"""Adapters for Maven (pom.xml), Go (go.mod) and consuming an existing CycloneDX SBOM."""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ..model import Component, Graph, component_id

PURL_ECO = {"npm": "npm", "pypi": "PyPI", "maven": "Maven", "golang": "Go", "cargo": "crates.io",
            "gem": "RubyGems", "nuget": "NuGet", "composer": "Packagist"}


def _root(manifest: Path, repo: Path, graph: Graph, eco: str, label: str = "") -> tuple[str, str]:
    rel = manifest.relative_to(repo).as_posix()
    root_id = f"app:{rel}"
    graph.add_root(Component(id=root_id, name=f"{label or repo.name} ({rel})", version="", ecosystem=eco,
                             manifests={rel}))
    return rel, root_id


def parse_pom(pom: Path, repo: Path, graph: Graph) -> dict:
    tree = ET.parse(pom)
    ns = {"m": tree.getroot().tag.split("}")[0].strip("{")} if tree.getroot().tag.startswith("{") else {}
    p = "m:" if ns else ""
    root = tree.getroot()

    def text(el, tag):
        x = el.find(p + tag, ns)
        return x.text.strip() if x is not None and x.text else ""

    props = {}
    pe = root.find(p + "properties", ns)
    if pe is not None:
        for child in pe:
            props[child.tag.split("}")[-1]] = (child.text or "").strip()
    props["project.version"] = text(root, "version") or text(root.find(p + "parent", ns) or root, "version")

    def sub(v):
        return re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), v or "")

    managed = {}
    for d in root.findall(f"{p}dependencyManagement/{p}dependencies/{p}dependency", ns):
        managed[f"{text(d, 'groupId')}:{text(d, 'artifactId')}"] = sub(text(d, "version"))

    rel, root_id = _root(pom, repo, graph, "Maven", text(root, "artifactId"))
    unresolved = 0
    for d in root.findall(f"{p}dependencies/{p}dependency", ns):
        ga = f"{sub(text(d, 'groupId'))}:{sub(text(d, 'artifactId'))}"
        ver = sub(text(d, "version")) or managed.get(ga, "")
        exact = bool(ver) and "${" not in ver
        unresolved += not exact
        c = graph.add(Component(id=component_id("Maven", ga, ver or "?"), name=ga, version=ver or "?",
                                ecosystem="Maven", direct=True, manifests={rel}, exact=exact),
                      dev=text(d, "scope") in ("test", "provided"))
        graph.link(root_id, c.id)
    graph.notes.append(f"{rel}: pom.xml - direct dependencies only ({unresolved} versions inherited from a parent/BOM); "
                       "consume an SBOM (mvn cyclonedx:makeBom) for the full tree")
    return {"manifest": rel}


def parse_gomod(gomod: Path, repo: Path, graph: Graph) -> dict:
    rel, root_id = _root(gomod, repo, graph, "Go")
    in_block = False
    for line in gomod.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        if in_block or s.startswith("require "):
            parts = s.replace("require ", "").split()
            if len(parts) >= 2:
                indirect = "// indirect" in s
                c = graph.add(Component(id=component_id("Go", parts[0], parts[1]), name=parts[0], version=parts[1],
                                        ecosystem="Go", direct=not indirect, manifests={rel}), dev=False)
                graph.link(root_id, c.id)
    graph.notes.append(f"{rel}: go.mod - indirect modules attached to the root (run `go mod graph` for exact edges)")
    return {"manifest": rel}


def parse_cyclonedx(sbom: Path, repo: Path, graph: Graph) -> dict:
    data = json.loads(sbom.read_text(encoding="utf-8"))
    rel, root_id = _root(sbom, repo, graph, "SBOM", data.get("metadata", {}).get("component", {}).get("name", ""))
    ref_to_id = {}
    meta_ref = data.get("metadata", {}).get("component", {}).get("bom-ref")
    if meta_ref:
        ref_to_id[meta_ref] = root_id
    for comp in data.get("components", []):
        purl = comp.get("purl", "")
        m = re.match(r"pkg:([^/]+)/", purl)
        eco = PURL_ECO.get(m.group(1), m.group(1)) if m else "generic"
        name = comp.get("name", "")
        if comp.get("group"):
            name = f"{comp['group']}:{name}" if eco == "Maven" else f"{comp['group']}/{name}"
        c = graph.add(Component(id=component_id(eco, name, comp.get("version", "")), name=name,
                                version=comp.get("version", ""), ecosystem=eco, manifests={rel},
                                kind="library" if comp.get("type", "library") == "library" else comp.get("type")),
                      dev=comp.get("scope") == "excluded")
        ref_to_id[comp.get("bom-ref", purl or c.id)] = c.id
    has_child = set()
    for dep in data.get("dependencies", []):
        a = ref_to_id.get(dep.get("ref"))
        for b in dep.get("dependsOn", []):
            if a and b in ref_to_id:
                graph.link(a, ref_to_id[b])
                has_child.add(ref_to_id[b])
    for cid in ref_to_id.values():
        if cid != root_id and (cid not in has_child):
            graph.nodes[cid].direct = True
            graph.link(root_id, cid)
    return {"manifest": rel}
