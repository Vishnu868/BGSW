"""Core data model: components, the dependency graph, and findings."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from urllib.parse import quote

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

CATEGORIES = {
    "1.1": "Vulnerable direct dependency",
    "1.2": "Vulnerable transitive dependency",
    "1.3": "Typosquatted or malicious package",
    "1.4": "Suspicious package update or install script",
    "1.5": "Untrusted container image or artifact",
    "1.6": "Unexpected lockfile or dependency change",
    "1.7": "Unpinned or unsafe CI/CD component",
}

PURL_TYPE = {"npm": "npm", "PyPI": "pypi", "Maven": "maven", "Go": "golang",
             "crates.io": "cargo", "RubyGems": "gem", "NuGet": "nuget", "Packagist": "composer"}


@dataclass
class Component:
    id: str
    name: str
    version: str
    ecosystem: str
    kind: str = "library"          # library | application | container | action
    direct: bool = False
    dev: bool = True               # becomes False once any production path reaches it
    manifests: set = field(default_factory=set)
    resolved: str = ""
    integrity: str = ""
    install_script: bool = False
    exact: bool = True             # False when the version is only a declared range
    sources: set = field(default_factory=set)      # every download URL seen across lockfiles
    integrities: set = field(default_factory=set)  # every integrity hash seen across lockfiles

    @property
    def purl(self) -> str:
        t = PURL_TYPE.get(self.ecosystem)
        if not t or self.kind != "library":
            return ""
        if t == "maven" and ":" in self.name:
            g, a = self.name.split(":", 1)
            return f"pkg:maven/{g}/{a}@{self.version}"
        name = quote(self.name, safe="/") if t != "npm" else self.name.replace("@", "%40", 1)
        return f"pkg:{t}/{name}@{self.version}"

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "version": self.version, "ecosystem": self.ecosystem,
                "kind": self.kind, "direct": self.direct, "dev": self.dev, "exact": self.exact,
                "manifests": sorted(self.manifests), "resolved": self.resolved,
                "integrity": self.integrity, "install_script": self.install_script, "purl": self.purl}


def component_id(ecosystem: str, name: str, version: str) -> str:
    return f"{ecosystem}:{name}@{version}"


@dataclass
class Finding:
    category: str                  # key of CATEGORIES
    severity: str                  # critical | high | medium | low | info
    title: str
    component: str = ""            # Component.id, or "" for repo-level findings
    evidence: list = field(default_factory=list)   # [{"source":..., "detail":..., "file":..., "line":...}]
    rule: str = ""                 # which detector produced it, e.g. "osv", "docker.unpinned-digest"
    recommendation: str = ""
    data: dict = field(default_factory=dict)       # machine-readable extras (vuln id, fixed version, ...)

    def to_dict(self) -> dict:
        return {"category": self.category, "category_name": CATEGORIES[self.category],
                "severity": self.severity, "title": self.title, "component": self.component,
                "rule": self.rule, "evidence": self.evidence,
                "recommendation": self.recommendation, "data": self.data}


class Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, Component] = {}
        self.edges: set[tuple[str, str]] = set()
        self.roots: list[str] = []
        self.notes: list[str] = []   # honest limitations discovered while parsing

    def add(self, comp: Component, dev: bool | None = None) -> Component:
        cur = self.nodes.get(comp.id)
        if comp.resolved:
            comp.sources.add(comp.resolved)
        if comp.integrity:
            comp.integrities.add(comp.integrity)
        if cur is None:
            self.nodes[comp.id] = cur = comp
        else:
            cur.direct |= comp.direct
            cur.manifests |= comp.manifests
            cur.install_script |= comp.install_script
            cur.resolved = cur.resolved or comp.resolved
            cur.integrity = cur.integrity or comp.integrity
            cur.sources |= comp.sources
            cur.integrities |= comp.integrities
        if dev is not None:
            cur.dev = cur.dev and dev
        return cur

    def add_root(self, comp: Component) -> None:
        comp.kind, comp.dev = "application", False
        self.add(comp)
        if comp.id not in self.roots:
            self.roots.append(comp.id)

    def link(self, parent: str, child: str) -> None:
        if parent != child:
            self.edges.add((parent, child))

    # ---- queries -----------------------------------------------------------
    def children(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for a, b in self.edges:
            out.setdefault(a, []).append(b)
        return out

    def shortest_paths(self) -> dict[str, list[str]]:
        """One shortest root -> node path per node (BFS over all roots)."""
        kids = self.children()
        prev: dict[str, str | None] = {}
        q = deque()
        for r in self.roots:
            prev[r] = None
            q.append(r)
        while q:
            n = q.popleft()
            for c in sorted(kids.get(n, [])):
                if c not in prev:
                    prev[c] = n
                    q.append(c)
        paths = {}
        for n in prev:
            p, cur = [], n
            while cur is not None:
                p.append(cur)
                cur = prev[cur]
            paths[n] = p[::-1]
        return paths

    def introduced_by(self) -> dict[str, set[str]]:
        """For every node: the set of direct dependencies that pull it in."""
        kids = self.children()
        out: dict[str, set[str]] = {}
        for d in (n for n, c in self.nodes.items() if c.direct):
            seen, stack = {d}, [d]
            while stack:
                n = stack.pop()
                out.setdefault(n, set()).add(d)
                for c in kids.get(n, []):
                    if c not in seen:
                        seen.add(c)
                        stack.append(c)
        return out
