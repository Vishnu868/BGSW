"""Stage 1 - Discover: find every manifest/lockfile/Dockerfile/workflow and build the dependency graph."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from ..model import Graph
from . import npm, others, python

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build", ".tox",
             "vendor", "bower_components", ".next", "target", "site-packages"}


@dataclass
class Inventory:
    repo: Path
    graph: Graph = field(default_factory=Graph)
    projects: list = field(default_factory=list)   # facts returned by each adapter
    dockerfiles: list = field(default_factory=list)
    compose_files: list = field(default_factory=list)
    workflows: list = field(default_factory=list)
    files_seen: dict = field(default_factory=dict)  # manifest type -> [paths]


def walk(repo: Path):
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            yield Path(dirpath) / f


def discover(repo: Path) -> Inventory:
    repo = repo.resolve()
    inv = Inventory(repo=repo)
    found: dict[str, list[Path]] = {}
    for p in walk(repo):
        n = p.name.lower()
        rel = p.relative_to(repo).as_posix()
        if n == "package.json":
            found.setdefault("npm", []).append(p)
        elif n == "poetry.lock":
            found.setdefault("poetry", []).append(p)
        elif n == "pipfile.lock":
            found.setdefault("pipfile", []).append(p)
        elif n.startswith("requirements") and n.endswith(".txt"):
            found.setdefault("requirements", []).append(p)
        elif n == "pom.xml":
            found.setdefault("maven", []).append(p)
        elif n == "go.mod":
            found.setdefault("go", []).append(p)
        elif n.endswith((".cdx.json", "bom.json")) or n == "sbom.json":
            found.setdefault("cyclonedx", []).append(p)
        elif n == "dockerfile" or n.startswith("dockerfile.") or n.endswith(".dockerfile") or n == "containerfile":
            inv.dockerfiles.append(p)
        elif ("compose" in n) and n.endswith((".yml", ".yaml")):
            inv.compose_files.append(p)
        elif "/.github/workflows/" in f"/{rel}" and n.endswith((".yml", ".yaml")):
            inv.workflows.append(p)

    # a Python dir with a real lockfile does not also need its requirements parsed
    py_locked = {p.parent for p in found.get("poetry", []) + found.get("pipfile", [])}
    adapters = [
        ("npm", npm.parse), ("poetry", python.parse_poetry), ("pipfile", python.parse_pipfile_lock),
        ("requirements", python.parse_requirements), ("maven", others.parse_pom), ("go", others.parse_gomod),
        ("cyclonedx", others.parse_cyclonedx),
    ]
    for kind, fn in adapters:
        for path in sorted(found.get(kind, [])):
            if kind == "requirements" and path.parent in py_locked:
                continue
            try:
                facts = fn(path, repo, inv.graph)
                facts["type"] = kind
                inv.projects.append(facts)
            except Exception as e:  # one broken manifest must not stop the scan
                inv.graph.notes.append(f"{path.relative_to(repo).as_posix()}: could not parse ({e})")
    inv.files_seen = {k: [p.relative_to(repo).as_posix() for p in v] for k, v in found.items()}
    return inv
