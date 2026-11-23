"""npm adapter: package-lock.json (v1, v2, v3) or bare package.json -> dependency graph."""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..model import Component, Graph, component_id

DEP_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies")


def _name_from_path(path: str) -> str:
    return path.rsplit("node_modules/", 1)[-1]


def parse(manifest: Path, repo: Path, graph: Graph) -> dict:
    """Add one npm project to the graph. Returns facts the detectors use (lock path, sync issues)."""
    rel = manifest.relative_to(repo).as_posix()
    pkg = json.loads(manifest.read_text(encoding="utf-8"))
    label = pkg.get("name") or manifest.parent.name
    root_id = f"app:{rel}"
    graph.add_root(Component(id=root_id, name=f"{label} ({rel})", version=pkg.get("version", ""),
                             ecosystem="npm", manifests={rel}))
    declared = {**pkg.get("dependencies", {}), **pkg.get("optionalDependencies", {})}
    declared_dev = pkg.get("devDependencies", {})

    lock_path = manifest.with_name("package-lock.json")
    if not lock_path.exists():
        lock_path = manifest.with_name("npm-shrinkwrap.json")
    facts = {"manifest": rel, "lockfile": None, "declared": declared, "declared_dev": declared_dev,
             "lock_root_deps": {}, "missing": []}
    if not lock_path.exists():
        _from_manifest_only(rel, root_id, declared, declared_dev, graph)
        graph.notes.append(f"{rel}: no lockfile - only direct dependencies with declared ranges are known")
        return facts

    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    facts["lockfile"] = lock_path.relative_to(repo).as_posix()
    if "packages" in lock:
        _parse_v2(lock["packages"], rel, root_id, graph, facts)
    else:
        _parse_v1(lock.get("dependencies", {}), rel, root_id, declared, declared_dev, graph, facts)
    return facts


def _from_manifest_only(rel, root_id, declared, declared_dev, graph):
    for deps, dev in ((declared, False), (declared_dev, True)):
        for name, rng in deps.items():
            ver = _lowest_version(rng)
            c = graph.add(Component(id=component_id("npm", name, ver or rng), name=name, version=ver or rng,
                                    ecosystem="npm", direct=True, manifests={rel}, exact=False), dev=dev)
            graph.link(root_id, c.id)


def _lowest_version(rng: str) -> str:
    m = re.search(r"\d+(\.\d+){0,2}", rng or "")
    return m.group(0) if m else ""


def _parse_v2(pk: dict, rel: str, root_id: str, graph: Graph, facts: dict) -> None:
    def resolve(base: str, dep: str):
        while True:
            cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
            if cand in pk:
                meta = pk[cand]
                if meta.get("link"):          # workspace symlink -> real folder
                    target = meta.get("resolved", "")
                    return (target, pk.get(target, {})) if target in pk else (None, None)
                return cand, meta
            if not base:
                return None, None
            i = base.rfind("/node_modules/")
            base = base[:i] if i != -1 else ""

    def node_for(path: str, meta: dict) -> str:
        if path == "":
            return root_id
        name = meta.get("name") or _name_from_path(path)
        ver = meta.get("version", "")
        cid = component_id("npm", name, ver)
        graph.add(Component(id=cid, name=name, version=ver, ecosystem="npm", manifests={rel},
                            resolved=meta.get("resolved", ""), integrity=meta.get("integrity", ""),
                            install_script=bool(meta.get("hasInstallScript"))),
                  dev=bool(meta.get("dev") or meta.get("devOptional")))
        return cid

    root_meta = pk.get("", {})
    facts["lock_root_deps"] = {**root_meta.get("dependencies", {}), **root_meta.get("optionalDependencies", {}),
                               **root_meta.get("devDependencies", {})}
    seen = set()
    stack = [""]
    while stack:
        path = stack.pop()
        if path in seen:
            continue
        seen.add(path)
        meta = pk.get(path, {})
        me = node_for(path, meta)
        fields = DEP_FIELDS + (("devDependencies",) if path == "" or not path.startswith("node_modules") else ())
        for f in fields:
            for dep in meta.get(f, {}):
                cpath, cmeta = resolve(path, dep)
                if cpath is None:
                    if f == "dependencies":
                        facts["missing"].append(f"{path or '(root)'} -> {dep}")
                    continue
                child = node_for(cpath, cmeta)
                if path == "":
                    graph.nodes[child].direct = True
                graph.link(me, child)
                stack.append(cpath)


def _parse_v1(deps: dict, rel, root_id, declared, declared_dev, graph: Graph, facts: dict) -> None:
    def add(name, meta):
        cid = component_id("npm", name, meta.get("version", ""))
        graph.add(Component(id=cid, name=name, version=meta.get("version", ""), ecosystem="npm",
                            manifests={rel}, resolved=meta.get("resolved", ""),
                            integrity=meta.get("integrity", "")), dev=bool(meta.get("dev")))
        return cid

    def find(name, scopes):
        for scope in reversed(scopes):
            if name in scope:
                return scope[name]
        return None

    def walk(scope: dict, scopes: list):
        for name, meta in scope.items():
            me = add(name, meta)
            inner = meta.get("dependencies", {})
            chain = scopes + [inner]
            for req in meta.get("requires", {}):
                m = find(req, chain)
                if m is None:
                    facts["missing"].append(f"{name} -> {req}")
                    continue
                graph.link(me, add(req, m))
            walk(inner, chain)

    walk(deps, [deps])
    for name in list(declared) + list(declared_dev):
        if name in deps:
            cid = add(name, deps[name])
            graph.nodes[cid].direct = True
            graph.link(root_id, cid)
        else:
            facts["missing"].append(f"(root) -> {name}")
    facts["lock_root_deps"] = {**declared, **declared_dev}
