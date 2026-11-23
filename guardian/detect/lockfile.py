"""Category 1.6 - lockfile hygiene, manifest/lockfile drift, and "what changed" versus a baseline SBOM."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from ..model import Finding, Graph
from .osv import vkey

TRUSTED_REGISTRIES = {"registry.npmjs.org", "registry.yarnpkg.com"}


def scan(graph: Graph, inv) -> list[Finding]:
    out: list[Finding] = []
    for p in inv.projects:
        t, manifest = p.get("type"), p.get("manifest")
        if t == "npm":
            if not p.get("lockfile"):
                out.append(Finding("1.6", "medium", f"No lockfile for {manifest}: installs are not reproducible",
                                   rule="lockfile.missing",
                                   evidence=[{"source": "file", "detail": "package-lock.json not found", "file": manifest}],
                                   recommendation="Commit a lockfile and install with `npm ci` so every build gets the same versions"))
                continue
            declared = {**p["declared"], **p["declared_dev"]}
            lock_root = p.get("lock_root_deps", {})
            drift = [f"{n}: package.json '{declared[n]}' vs lockfile '{lock_root.get(n, 'absent')}'"
                     for n in declared if lock_root and lock_root.get(n) != declared[n]]
            drift += [f"{n}: in lockfile only" for n in lock_root if n not in declared]
            if drift:
                out.append(Finding("1.6", "medium", f"Lockfile out of sync with {manifest} ({len(drift)} entries)",
                                   rule="lockfile.drift",
                                   evidence=[{"source": "drift", "detail": d, "file": p["lockfile"]} for d in drift[:10]],
                                   recommendation="Regenerate the lockfile from package.json and review the diff"))
            if p.get("missing"):
                out.append(Finding("1.6", "medium", f"Lockfile references packages it does not contain ({len(p['missing'])})",
                                   rule="lockfile.unresolved",
                                   evidence=[{"source": "unresolved", "detail": m, "file": p["lockfile"]} for m in p["missing"][:10]],
                                   recommendation="Regenerate the lockfile; a hand-edited lockfile is a supply-chain red flag"))
        if t == "requirements" and p.get("unpinned"):
            names = p["unpinned"]
            out.append(Finding("1.6", "low", f"{len(names)} unpinned Python requirement(s) in {manifest}",
                               rule="lockfile.unpinned-python",
                               evidence=[{"source": "requirement", "detail": f"{u['name']} {u['spec']}", "file": manifest, "line": u["line"]}
                                         for u in names[:10]],
                               recommendation="Pin exact versions (==) or use a lockfile (pip-tools / poetry) with hashes"))

    sha1_only = []
    for c in graph.nodes.values():
        if c.kind != "library" or c.ecosystem != "npm" or not c.sources:
            continue
        if len(c.integrities) > 1:
            out.append(Finding("1.6", "high", f"{c.name}@{c.version} has different integrity hashes in different lockfiles",
                               component=c.id, rule="lockfile.integrity-conflict",
                               evidence=[{"source": "integrity", "detail": i} for i in sorted(c.integrities)],
                               recommendation="The same version must have one tarball - find which lockfile was altered"))
        for src in sorted(c.sources):
            out += _source_checks(c, src)
        if not c.integrity and any(urlparse(x).scheme in ("http", "https") for x in c.sources):
            out.append(Finding("1.6", "medium", f"{c.name}@{c.version} has no integrity hash in the lockfile",
                               component=c.id, rule="lockfile.no-integrity",
                               evidence=[{"source": "integrity", "detail": "missing"}],
                               recommendation="Regenerate the lockfile so npm can verify the download"))
        if c.integrity.startswith("sha1-"):
            sha1_only.append(f"{c.name}@{c.version}")
    if sha1_only:
        out.append(Finding("1.6", "low", f"{len(sha1_only)} packages pinned only by weak SHA-1 integrity",
                           rule="lockfile.sha1", evidence=[{"source": "integrity", "detail": ", ".join(sha1_only[:15])}],
                           recommendation="Regenerate the lockfile with a current npm to get sha512 hashes"))
    return out


def _source_checks(c, resolved: str) -> list[Finding]:
    out = []
    u = urlparse(resolved)
    if resolved.startswith(("git+", "git:", "github:")) or u.scheme in ("git", "git+ssh", "git+https"):
        out.append(Finding("1.6", "medium", f"{c.name} is installed straight from a git repository",
                           component=c.id, rule="lockfile.git-source",
                           evidence=[{"source": "resolved", "detail": resolved}],
                           recommendation="Prefer a published, versioned release from the registry"))
    elif u.scheme == "http":
        out.append(Finding("1.6", "high", f"{c.name} is downloaded over plain HTTP", component=c.id,
                           rule="lockfile.insecure-url", evidence=[{"source": "resolved", "detail": resolved}],
                           recommendation="Use the HTTPS registry URL"))
    elif u.scheme == "https" and u.hostname not in TRUSTED_REGISTRIES:
        out.append(Finding("1.6", "high", f"{c.name} resolves to an unexpected host: {u.hostname}", component=c.id,
                           rule="lockfile.untrusted-registry", evidence=[{"source": "resolved", "detail": resolved}],
                           recommendation="Confirm this registry is approved; otherwise restore the official registry URL"))
    return out


# ------------------------------------------------------------ baseline diff ---
def _load_baseline(path: Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    comps = {}
    for c in data.get("components", []):
        props = {p["name"]: p["value"] for p in c.get("properties", [])}
        if c.get("type") != "library":
            continue
        comps[c["bom-ref"]] = {"name": props.get("guardian:name", c.get("name")), "version": c.get("version", ""),
                               "eco": props.get("guardian:ecosystem", ""), "integrity": props.get("guardian:integrity", ""),
                               "resolved": props.get("guardian:resolved", ""),
                               "install_script": props.get("guardian:install_script") == "true"}
    return {"when": data.get("metadata", {}).get("timestamp", str(path)), "components": comps}


def diff(baseline_path: Path, graph: Graph) -> dict:
    base = _load_baseline(baseline_path)
    old = base["components"]
    new = {cid: c for cid, c in graph.nodes.items() if c.kind == "library"}
    old_names = {(v["eco"], v["name"]): k for k, v in old.items()}
    new_names = {(c.ecosystem, c.name): cid for cid, c in new.items()}
    added, removed, changed, tampered = [], [], [], []
    for cid, c in new.items():
        if cid in old:
            o = old[cid]
            now = {"integrity": " ".join(sorted(c.integrities)), "resolved": " ".join(sorted(c.sources))}
            for fld in ("integrity", "resolved"):
                if o[fld] and now[fld] and o[fld] != now[fld]:
                    gone = set(o[fld].split()) - set(now[fld].split())
                    new = set(now[fld].split()) - set(o[fld].split())
                    tampered.append({"id": cid, "name": c.name, "version": c.version, "field": fld,
                                     "old": " ".join(sorted(gone)) or "(previous value still present)", "new": " ".join(sorted(new))})
            if c.install_script and not o["install_script"]:
                tampered.append({"id": cid, "name": c.name, "version": c.version, "field": "install script",
                                 "old": "none", "new": "added"})
        elif (c.ecosystem, c.name) in old_names:
            o = old[old_names[(c.ecosystem, c.name)]]
            changed.append({"id": cid, "name": c.name, "old": o["version"], "new": c.version,
                            "install_script_added": c.install_script and not o["install_script"]})
        else:
            added.append({"id": cid, "name": c.name, "version": c.version, "direct": c.direct,
                          "install_script": c.install_script})
    for k, o in old.items():
        if k not in new and (o["eco"], o["name"]) not in new_names:
            removed.append({"id": k, "name": o["name"], "version": o["version"]})
    return {"baseline": base["when"], "added": added, "removed": removed, "changed": changed, "tampered": tampered}


def findings_from_changes(ch: dict) -> list[Finding]:
    if not ch or not ch.get("baseline"):
        return []
    out = []
    for t in ch["tampered"]:
        out.append(Finding("1.6", "critical" if t["field"] == "integrity" else "high",
                           f"{t['name']}@{t['version']}: {t['field']} changed without a version change",
                           component=t["id"], rule="diff.tampered",
                           evidence=[{"source": "baseline", "detail": f"{t['field']}: {t['old']}"},
                                     {"source": "now", "detail": f"{t['field']}: {t['new']}"}],
                           recommendation="Treat as possible tampering: restore the baseline lockfile entry and investigate who changed it"))
    for a in ch["added"]:
        if a["direct"] or a["install_script"]:
            out.append(Finding("1.4" if a["install_script"] else "1.6", "high" if a["install_script"] else "medium",
                               f"New {'direct ' if a['direct'] else ''}dependency since baseline: {a['name']}@{a['version']}"
                               + (" (runs an install script)" if a["install_script"] else ""),
                               component=a["id"], rule="diff.added",
                               evidence=[{"source": "baseline", "detail": "not present"}],
                               recommendation="Confirm this addition was intended and reviewed"))
    for c in ch["changed"]:
        if vkey(c["new"]) < vkey(c["old"]):
            out.append(Finding("1.6", "medium", f"{c['name']} downgraded {c['old']} -> {c['new']}",
                               component=c["id"], rule="diff.downgrade",
                               evidence=[{"source": "baseline", "detail": c["old"]}, {"source": "now", "detail": c["new"]}],
                               recommendation="Downgrades can re-introduce fixed vulnerabilities - confirm the reason"))
        if c["install_script_added"]:
            out.append(Finding("1.4", "high", f"{c['name']} {c['old']} -> {c['new']} added an install script",
                               component=c["id"], rule="diff.install-script-added",
                               evidence=[{"source": "update", "detail": f"{c['old']} -> {c['new']}"}],
                               recommendation="Diff the two versions (npm diff) before accepting the update"))
    return out
