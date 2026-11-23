"""More ecosystems: Ruby (Gemfile.lock), PHP (composer.lock), C#/.NET (NuGet), Maven parent/BOM resolution."""
from __future__ import annotations

import json
import os
import re
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

from ..model import Component, Graph, component_id


def _root(manifest: Path, repo: Path, graph: Graph, eco: str) -> tuple[str, str]:
    rel = manifest.relative_to(repo).as_posix()
    root_id = f"app:{rel}"
    graph.add_root(Component(id=root_id, name=f"{repo.name} ({rel})", version="", ecosystem=eco, manifests={rel}))
    return rel, root_id


# ------------------------------------------------------------------ Ruby -----
def parse_gemfile_lock(lock: Path, repo: Path, graph: Graph) -> dict:
    """Gemfile.lock: 4-space lines are gems 'name (version)', 6-space lines their dependencies; DEPENDENCIES = direct."""
    rel, root_id = _root(lock, repo, graph, "RubyGems")
    specs, deps, direct, section, cur = {}, {}, [], "", None
    for line in lock.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith(" "):
            section = line.strip()
            continue
        if section in ("GEM", "GIT", "PATH"):
            m4 = re.match(r"^    (\S+) \(([^)]+)\)$", line)
            m6 = re.match(r"^      (\S+)", line)
            if m4:
                name, ver = m4.group(1), m4.group(2).split("-")[0]
                if name not in specs:
                    specs[name], deps[name] = ver, []
                cur = name
            elif m6 and cur:
                deps[cur].append(m6.group(1))
        elif section == "DEPENDENCIES":
            m = re.match(r"^  ([^\s!]+)", line)
            if m:
                direct.append(m.group(1))
    ids = {n: graph.add(Component(id=component_id("RubyGems", n, v), name=n, version=v, ecosystem="RubyGems",
                                  manifests={rel}), dev=False).id for n, v in specs.items()}
    for n, ds in deps.items():
        for d in ds:
            if d in ids:
                graph.link(ids[n], ids[d])
    for d in direct:
        if d in ids:
            graph.nodes[ids[d]].direct = True
            graph.link(root_id, ids[d])
    return {"manifest": rel, "lockfile": rel}


# ------------------------------------------------------------------- PHP -----
def parse_composer_lock(lock: Path, repo: Path, graph: Graph) -> dict:
    rel, root_id = _root(lock, repo, graph, "Packagist")
    data = json.loads(lock.read_text(encoding="utf-8"))
    cj = lock.with_name("composer.json")
    req = json.loads(cj.read_text(encoding="utf-8")) if cj.exists() else {}
    direct = set(req.get("require", {})) | set(req.get("require-dev", {}))
    ids, reqs = {}, {}
    for section, dev in (("packages", False), ("packages-dev", True)):
        for p in data.get(section, []):
            ver = str(p.get("version", "")).lstrip("v")
            c = graph.add(Component(id=component_id("Packagist", p["name"], ver), name=p["name"], version=ver,
                                    ecosystem="Packagist", manifests={rel}, resolved=(p.get("dist") or {}).get("url", "")),
                          dev=dev)
            ids[p["name"]], reqs[p["name"]] = c.id, [r for r in p.get("require", {}) if "/" in r]
    for n, rs in reqs.items():
        for r in rs:
            if r in ids:
                graph.link(ids[n], ids[r])
    child = {b for _, b in graph.edges}
    for n, cid in ids.items():
        if n in direct or (not direct and cid not in child):
            graph.nodes[cid].direct = True
            graph.link(root_id, cid)
    return {"manifest": rel, "lockfile": rel}


# --------------------------------------------------- Maven parent / BOM -----
MAVEN_CACHE = Path(__file__).resolve().parents[2] / ".cache" / "maven"
LOCAL_POMS: dict = {}


def parse_xml(text):
    if not text:
        return None
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        return None


def index_local_poms(repo: Path) -> None:
    """Multi-module projects: child POMs inherit from parents inside the repository."""
    for lp in repo.rglob("pom.xml"):
        if any(x in lp.parts for x in ("node_modules", "target", ".git")):
            continue
        r = parse_xml(lp.read_text(encoding="utf-8", errors="replace"))
        if r is None:
            continue
        ns = {"m": r.tag.split("}")[0].strip("{")} if r.tag.startswith("{") else {}
        px = "m:" if ns else ""
        g = r.find(px + "groupId", ns)
        if g is None:
            g = r.find(f"{px}parent/{px}groupId", ns)
        a = r.find(px + "artifactId", ns)
        if g is not None and a is not None and g.text and a.text:
            LOCAL_POMS[(g.text.strip(), a.text.strip())] = r


def pom_from_central(g: str, a: str, v: str):
    f = MAVEN_CACHE / f"{g}_{a}_{v}.pom"
    if f.exists():
        return parse_xml(f.read_text(encoding="utf-8"))
    if os.environ.get("GUARDIAN_OFFLINE") == "1" or not v or "${" in v:
        return None
    url = f"https://repo1.maven.org/maven2/{g.replace('.', '/')}/{a}/{v}/{a}-{v}.pom"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "supply-chain-guardian/0.3"}),
                                    timeout=20) as r:
            text = r.read().decode("utf-8", errors="replace")
    except Exception:
        return None
    MAVEN_CACHE.mkdir(parents=True, exist_ok=True)
    f.write_text(text, encoding="utf-8")
    return parse_xml(text)


def effective(root, depth: int = 0) -> tuple[dict, dict]:
    """(properties, managed versions) of a POM, including its parent chain and imported BOMs (like Maven does)."""
    if root is None or depth > 8:
        return {}, {}
    ns = {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
    px = "m:" if ns else ""

    def t(el, name):
        x = el.find(px + name, ns) if el is not None else None
        return x.text.strip() if x is not None and x.text else ""

    props, managed = {}, {}
    par = root.find(px + "parent", ns)
    if par is not None:
        pg, pa, pv = t(par, "groupId"), t(par, "artifactId"), t(par, "version")
        pp, pm = effective(LOCAL_POMS.get((pg, pa)) or pom_from_central(pg, pa, pv), depth + 1)
        props.update(pp)
        managed.update(pm)
        props["project.parent.version"] = props["project.version"] = pv
    pe = root.find(px + "properties", ns)
    if pe is not None:
        for c in pe:
            props[c.tag.split("}")[-1]] = (c.text or "").strip()
    if t(root, "version"):
        props["project.version"] = t(root, "version")

    def sub(v):
        for _ in range(6):
            nv = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), v or "")
            if nv == v:
                break
            v = nv
        return v

    for d in root.findall(f"{px}dependencyManagement/{px}dependencies/{px}dependency", ns):
        g, a, v = sub(t(d, "groupId")), sub(t(d, "artifactId")), sub(t(d, "version"))
        if t(d, "scope") == "import" and t(d, "type") == "pom":
            _, bm = effective(LOCAL_POMS.get((g, a)) or pom_from_central(g, a, v), depth + 1)
            for k, val in bm.items():
                managed.setdefault(k, val)
        elif v and "${" not in v:
            managed[f"{g}:{a}"] = v
    return props, managed


# ---------------------------------------------------------------- C# / .NET --
def parse_nuget(manifest: Path, repo: Path, graph: Graph) -> dict:
    """packages.lock.json (exact, with edges) > *.csproj PackageReference > packages.config (direct only)."""
    rel, root_id = _root(manifest, repo, graph, "NuGet")
    name = manifest.name.lower()
    if name == "packages.lock.json":
        data = json.loads(manifest.read_text(encoding="utf-8-sig"))
        ids, deps = {}, {}
        for framework, pkgs in (data.get("dependencies") or {}).items():
            for n, meta in pkgs.items():
                ver = meta.get("resolved", "")
                if not ver or meta.get("type") == "Project":
                    continue
                c = graph.add(Component(id=component_id("NuGet", n, ver), name=n, version=ver, ecosystem="NuGet",
                                        manifests={rel}, integrity=meta.get("contentHash", "")), dev=False)
                ids[n.lower()] = c.id
                deps.setdefault(c.id, set()).update(k.lower() for k in (meta.get("dependencies") or {}))
                if meta.get("type") == "Direct":
                    c.direct = True
                    graph.link(root_id, c.id)
        for cid, ds in deps.items():
            for d in ds:
                if d in ids:
                    graph.link(cid, ids[d])
        return {"manifest": rel, "lockfile": rel}
    root = parse_xml(manifest.read_text(encoding="utf-8-sig", errors="replace"))
    if root is None:
        return {"manifest": rel}
    found = 0
    for el in root.iter():
        tag = el.tag.split("}")[-1]
        if tag == "PackageReference":
            n = el.get("Include") or el.get("Update")
            v = el.get("Version") or next((c.text for c in el if c.tag.split("}")[-1] == "Version"), "")
        elif tag == "package":
            n, v = el.get("id"), el.get("version")
        else:
            continue
        if not n or not v:
            continue
        v = v.strip("[]() ").split(",")[0].strip()
        c = graph.add(Component(id=component_id("NuGet", n, v), name=n, version=v, ecosystem="NuGet", direct=True,
                                manifests={rel}), dev=False)
        graph.link(root_id, c.id)
        found += 1
    graph.notes.append(f"{rel}: NuGet {manifest.name} - {found} direct packages (no packages.lock.json, so no transitive edges)")
    return {"manifest": rel}
