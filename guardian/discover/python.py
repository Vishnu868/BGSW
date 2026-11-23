"""Python adapter: poetry.lock, Pipfile.lock, requirements*.txt."""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from ..model import Component, Graph, component_id

REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _root(manifest: Path, repo: Path, graph: Graph) -> tuple[str, str]:
    rel = manifest.relative_to(repo).as_posix()
    root_id = f"app:{rel}"
    graph.add_root(Component(id=root_id, name=f"{repo.name} ({rel})", version="", ecosystem="PyPI",
                             manifests={rel}))
    return rel, root_id


def parse_requirements(manifest: Path, repo: Path, graph: Graph) -> dict:
    rel, root_id = _root(manifest, repo, graph)
    facts = {"manifest": rel, "unpinned": []}
    dev = any(k in manifest.name.lower() for k in ("dev", "test", "lint", "doc"))
    for lineno, raw in enumerate(manifest.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = REQ_LINE.match(line.split(";", 1)[0])
        if not m:
            continue
        name, spec = norm(m.group(1)), m.group(3).strip()
        pin = re.match(r"^===?\s*([^\s,]+)$", spec)
        if pin:
            ver, exact = pin.group(1), True
        else:
            low = re.search(r"\d+(\.\d+)*", spec)
            ver, exact = (low.group(0) if low else ""), False
            facts["unpinned"].append({"name": name, "spec": spec or "(any)", "line": lineno})
        c = graph.add(Component(id=component_id("PyPI", name, ver or "*"), name=name, version=ver or "*",
                                ecosystem="PyPI", direct=True, manifests={rel}, exact=exact), dev=dev)
        graph.link(root_id, c.id)
    graph.notes.append(f"{rel}: requirements file - transitive dependencies not listed (no lockfile)")
    return facts


def parse_poetry(lock: Path, repo: Path, graph: Graph) -> dict:
    rel, root_id = _root(lock, repo, graph)
    data = tomllib.loads(lock.read_text(encoding="utf-8"))
    pkgs = {norm(p["name"]): p for p in data.get("package", [])}
    ids = {}
    for n, p in pkgs.items():
        dev = p.get("category", "main") != "main" and "main" not in p.get("groups", ["main"])
        ids[n] = graph.add(Component(id=component_id("PyPI", n, p["version"]), name=n, version=p["version"],
                                     ecosystem="PyPI", manifests={rel}), dev=dev).id
    for n, p in pkgs.items():
        for dep in p.get("dependencies", {}):
            if norm(dep) in ids:
                graph.link(ids[n], ids[norm(dep)])
    direct = set()
    pyproject = lock.with_name("pyproject.toml")
    if pyproject.exists():
        pp = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        poetry = pp.get("tool", {}).get("poetry", {})
        direct |= {norm(k) for k in poetry.get("dependencies", {})}
        for grp in poetry.get("group", {}).values():
            direct |= {norm(k) for k in grp.get("dependencies", {})}
        for d in pp.get("project", {}).get("dependencies", []):
            m = REQ_LINE.match(d)
            if m:
                direct.add(norm(m.group(1)))
    child_set = {b for _, b in graph.edges}
    for n, cid in ids.items():
        if n in direct or (not direct and cid not in child_set):
            graph.nodes[cid].direct = True
            graph.link(root_id, cid)
    return {"manifest": rel, "lockfile": rel}


def parse_pipfile_lock(lock: Path, repo: Path, graph: Graph) -> dict:
    rel, root_id = _root(lock, repo, graph)
    data = json.loads(lock.read_text(encoding="utf-8"))
    for section, dev in (("default", False), ("develop", True)):
        for name, meta in data.get(section, {}).items():
            ver = meta.get("version", "").lstrip("=")
            c = graph.add(Component(id=component_id("PyPI", norm(name), ver), name=norm(name), version=ver,
                                    ecosystem="PyPI", direct=True, manifests={rel}), dev=dev)
            graph.link(root_id, c.id)
    graph.notes.append(f"{rel}: Pipfile.lock has no edges - all packages attached to the project root")
    return {"manifest": rel, "lockfile": rel}
