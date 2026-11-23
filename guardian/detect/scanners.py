"""Independent cross-check with Trivy and Grype (open-source scanners by Aqua Security and Anchore).

OSV (osv.py) stays the primary source: it is queried per graph node, so every finding has a dependency path.
Trivy and Grype scan the same repository on their own (their own package discovery, their own databases).
Their results are matched to our findings by package + version + vulnerability id (including aliases):

  * same issue found       -> the OSV finding gets "confirmed by Trivy / Grype" evidence
  * issue only they found  -> a new finding (rule "trivy"/"grype"), still linked to our graph node when we have it
  * package we cannot read -> (e.g. C#/NuGet without our reader, C/C++ Conan, Rust) a node is added under the repo
                              so the package is visible, marked "discovered by Trivy/Grype"
"Confirmed by N of M" only counts the scanners that support that ecosystem AND actually ran (no fake 3/3).
Both tools are optional: if a binary is missing the scan continues with the others.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from ..model import Component, Finding, SEVERITY_RANK, component_id

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / ".cache"
PURL_ECO = {"npm": "npm", "pypi": "PyPI", "maven": "Maven", "golang": "Go", "gem": "RubyGems", "composer": "Packagist",
            "nuget": "NuGet", "conan": "ConanCenter", "cargo": "crates.io", "pub": "Pub", "hex": "Hex",
            "swift": "SwiftURL", "cocoapods": "CocoaPods", "deb": "Debian", "apk": "Alpine", "rpm": "RPM"}
# Which scanner can analyse which ecosystem (used for the honest "N of M" consensus)
SUPPORT = {
    "npm": {"osv", "trivy", "grype"}, "PyPI": {"osv", "trivy", "grype"}, "Maven": {"osv", "trivy", "grype"},
    "Go": {"osv", "trivy", "grype"}, "RubyGems": {"osv", "trivy", "grype"}, "Packagist": {"osv", "trivy", "grype"},
    "NuGet": {"osv", "trivy", "grype"}, "crates.io": {"trivy", "grype"}, "ConanCenter": {"trivy", "grype"},
    "Pub": {"trivy", "grype"}, "Hex": {"trivy", "grype"}, "SwiftURL": {"trivy", "grype"},
    "CocoaPods": {"trivy", "grype"}, "Debian": {"trivy", "grype"}, "Alpine": {"trivy", "grype"}, "RPM": {"trivy", "grype"},
}
SEV = {"critical": "critical", "high": "high", "medium": "medium", "moderate": "medium", "low": "low",
       "negligible": "low", "unknown": "medium"}
NAMES = {"osv": "OSV", "trivy": "Trivy", "grype": "Grype"}


def binary(tool: str) -> str | None:
    exe = ROOT / "tools" / tool / (tool + (".exe" if os.name == "nt" else ""))
    return str(exe) if exe.exists() else shutil.which(tool)


def parse_purl(purl: str) -> tuple[str, str, str]:
    """pkg:npm/%40scope/name@1.2.3 -> (ecosystem, name, version)"""
    from urllib.parse import unquote
    if not purl.startswith("pkg:"):
        return "", "", ""
    body = purl[4:].split("?")[0].split("#")[0]
    typ, _, rest = body.partition("/")
    name_part, _, version = rest.rpartition("@")
    name = unquote(name_part)
    eco = PURL_ECO.get(typ, typ)
    if eco == "Maven" and "/" in name:
        name = name.replace("/", ":", 1)
    if eco == "PyPI":
        name = name.lower().replace("_", "-")
    return eco, name, unquote(version)


# ------------------------------------------------------------------ runners ---
def run_trivy(target: str, out_file: Path, offline: bool, image: bool = False) -> tuple[list[dict], str]:
    exe = binary("trivy")
    if not exe:
        return [], "not installed"
    cmd = [exe, "image" if image else "fs", "--scanners", "vuln", "--format", "json", "--quiet",
           "--cache-dir", str(CACHE / "trivy"), "--output", str(out_file)]
    if offline:
        cmd += ["--skip-db-update", "--offline-scan"]
    r = subprocess.run(cmd + [target], capture_output=True, text=True, timeout=900)
    if r.returncode != 0 or not out_file.exists():
        return [], f"failed: {(r.stderr or r.stdout).strip()[-200:]}"
    data = json.loads(out_file.read_text(encoding="utf-8"))
    res = []
    for block in data.get("Results") or []:
        for v in block.get("Vulnerabilities") or []:
            purl = (v.get("PkgIdentifier") or {}).get("PURL", "")
            eco, name, ver = parse_purl(purl)
            res.append({"scanner": "trivy", "id": v.get("VulnerabilityID", ""), "aliases": v.get("VendorIDs") or [],
                        "eco": eco or block.get("Type", ""), "name": name or v.get("PkgName", ""),
                        "version": ver or v.get("InstalledVersion", ""), "purl": purl,
                        "severity": SEV.get(str(v.get("Severity", "")).lower(), "medium"),
                        "fixed": (v.get("FixedVersion") or "").split(",")[0].strip(), "file": block.get("Target", ""),
                        "title": v.get("Title") or ""})
    return res, f"ok ({len(res)} results)"


def run_grype(target: str, out_file: Path, offline: bool) -> tuple[list[dict], str]:
    exe = binary("grype")
    if not exe:
        return [], "not installed"
    env = dict(os.environ, GRYPE_DB_CACHE_DIR=str(CACHE / "grype"), GRYPE_CHECK_FOR_APP_UPDATE="false")
    if offline:
        env.update(GRYPE_DB_AUTO_UPDATE="false", GRYPE_DB_VALIDATE_AGE="false")
    r = subprocess.run([exe, target, "-o", "json", "--file", str(out_file), "-q"], capture_output=True, text=True,
                       timeout=900, env=env)
    if r.returncode != 0 or not out_file.exists():
        return [], f"failed: {(r.stderr or r.stdout).strip()[-200:]}"
    data = json.loads(out_file.read_text(encoding="utf-8"))
    res = []
    for m in data.get("matches") or []:
        v, a = m.get("vulnerability", {}), m.get("artifact", {})
        purl = a.get("purl", "")
        eco, name, ver = parse_purl(purl)
        fix = (v.get("fix") or {}).get("versions") or []
        locs = a.get("locations") or [{}]
        res.append({"scanner": "grype", "id": v.get("id", ""),
                    "aliases": [x.get("id") for x in m.get("relatedVulnerabilities") or [] if x.get("id")],
                    "eco": eco or a.get("type", ""), "name": name or a.get("name", ""),
                    "version": ver or a.get("version", ""), "purl": purl,
                    "severity": SEV.get(str(v.get("severity", "")).lower(), "medium"),
                    "fixed": fix[0] if fix else "", "file": locs[0].get("path", ""), "title": v.get("description", "")[:120]})
    return res, f"ok ({len(res)} results)"


# ------------------------------------------------------------------ merging ---
def _words(text: str) -> set:
    import re
    return {w for w in re.findall(r"[a-z0-9]+", (text or "").lower()) if len(w) > 3 and not w.startswith(("cve", "ghsa", "nswg"))}


def _key(eco: str, name: str, version: str) -> tuple:
    return (eco, name.lower(), version.lstrip("v"))


def scan(graph, repo: Path, findings: list[Finding], repo_id: str, out_dir: Path, offline: bool = False,
         use: tuple = ("trivy", "grype"), images: list[str] | None = None, log=print) -> tuple[list[Finding], dict]:
    out_dir.mkdir(parents=True, exist_ok=True)
    status = {"osv": "ok"}
    results: list[dict] = []
    for tool in use:
        t0 = time.time()
        fn = run_trivy if tool == "trivy" else run_grype
        target = str(repo) if tool == "trivy" else f"dir:{repo}"
        try:
            res, st = fn(target, out_dir / f"{tool}.json", offline)
        except Exception as e:  # a broken external tool must never stop the scan
            res, st = [], f"failed: {e}"
        status[tool] = st + (f", {time.time() - t0:.0f}s" if res else "")
        results += res
        log(f"      {NAMES[tool]}: {status[tool]}")
    for img in images or []:
        res, st = run_trivy(img, out_dir / f"trivy-image-{abs(hash(img)) % 10**8}.json", offline, image=True)
        for r in res:
            r["image"] = img
        results += res
        status[f"trivy image {img}"] = st
    ran = {"osv"} | {t for t in use if str(status.get(t, "")).startswith("ok")}

    # index our graph + OSV findings
    by_key = {}
    for cid, c in graph.nodes.items():
        if c.kind == "library":
            by_key[_key(c.ecosystem, c.name, c.version)] = cid
    osv_by_comp: dict[str, list[Finding]] = {}
    for f in findings:
        if f.rule == "osv":
            osv_by_comp.setdefault(f.component, []).append(f)
            f.data["scanners"] = ["osv"]
    new: dict[tuple, Finding] = {}
    for r in results:
        ids = {r["id"], *r["aliases"]} - {""}
        if r.get("image"):
            cid = f"container:{r['image']}"
            if cid not in graph.nodes:
                graph.add(Component(id=cid, name=r["image"], version="", ecosystem="docker", kind="container"), dev=False)
                graph.link(repo_id, cid)
        else:
            cid = by_key.get(_key(r["eco"], r["name"], r["version"]))
        if cid is None:                       # an ecosystem our readers do not cover
            cid = component_id(r["eco"] or "other", r["name"], r["version"])
            graph.add(Component(id=cid, name=r["name"], version=r["version"], ecosystem=r["eco"] or "other",
                                manifests={f"discovered by {NAMES[r['scanner']]}: {r['file']}"}), dev=False)
            graph.link(repo_id, cid)
            by_key[_key(r["eco"], r["name"], r["version"])] = cid
            graph.notes.append(f"{r['name']}@{r['version']} ({r['eco']}) discovered only by {NAMES[r['scanner']]} "
                               f"in {r['file']} - no dependency edges for this ecosystem")
        match = next((f for f in osv_by_comp.get(cid, []) if ids & ({f.data.get("vuln_id")} | set(f.data.get("aliases", [])))), None)
        how = ""
        if match is None:
            # same bug published under another id without an alias link (e.g. old NSWG-ECO-17 = CVE-2015-9235):
            # same package + same fixed version + mostly the same title words -> it is the same issue
            words = _words(r["title"])
            for f in osv_by_comp.get(cid, []):
                fw = _words(f.title)
                same_fix = r["fixed"] and r["fixed"] == f.data.get("fixed")
                overlap = len(words & fw) / max(1, min(len(words), len(fw))) if words and fw else 0
                if overlap >= 0.6 and (same_fix or overlap >= 0.9):
                    match, how = f, f"; matched by package, fixed version and title (different id: {r['id']})"
                    break
        line = {"source": NAMES[r["scanner"]], "detail": f"also reported {r['id']} ({r['severity']}"
                                                        + (f", fixed in {r['fixed']}" if r["fixed"] else "") + ")" + how}
        if match:
            if r["scanner"] not in match.data["scanners"]:
                match.data["scanners"].append(r["scanner"])
                match.evidence.append(line)
            continue
        k = (cid, frozenset(ids))
        prev = next((f for (c, s), f in new.items() if c == cid and s & ids), None)
        if prev:
            if r["scanner"] not in prev.data["scanners"]:
                prev.data["scanners"].append(r["scanner"])
                prev.evidence.append(line)
            if SEVERITY_RANK[r["severity"]] > SEVERITY_RANK[prev.severity]:
                prev.severity = r["severity"]
            continue
        c = graph.nodes[cid]
        cat = "1.5" if r.get("image") else ("1.1" if c.direct else "1.2")
        where = f" in image {r['image']}" if r.get("image") else ""
        new[k] = Finding(
            category=cat, severity=r["severity"],
            title=f"{r['id']}: {r['name']}@{r['version']}{where} - {r['title'][:80] or 'reported by ' + NAMES[r['scanner']]}",
            component=cid, rule=r["scanner"],
            evidence=[{"source": NAMES[r["scanner"]], "detail": f"reported {r['id']} ({r['severity']}) in {r['file'] or r.get('image', '')}"},
                      {"source": "note", "detail": "not in OSV's answer for this package - check the advisory before acting"}],
            recommendation=(f"Upgrade {r['name']} to {r['fixed']} or later" if r["fixed"] else
                            f"No fixed version published - replace or mitigate {r['name']}") +
                           (f" (rebuild on a newer {r['image']} base image)" if r.get("image") else ""),
            data={"vuln_id": r["id"], "aliases": sorted(ids - {r["id"]}), "fixed": r["fixed"], "scanners": [r["scanner"]],
                  "cve": next((x for x in sorted(ids) if x.startswith("CVE-")), "")})
    out = list(new.values())
    for f in out:
        c = graph.nodes.get(f.component)
        if c is not None and any(m.startswith("discovered by") for m in c.manifests):
            f.evidence.append({"source": "note", "detail": "direct or transitive unknown: only an external scanner saw this package"})
    for f in findings + out:
        if "scanners" not in f.data:
            continue
        c = graph.nodes.get(f.component)
        eco = c.ecosystem if c is not None else ""
        support = set(SUPPORT.get(eco, {"trivy", "grype"}))
        # Trivy/Grype read NuGet only from packages.lock.json / *.deps.json, not from .csproj / packages.config
        if eco == "NuGet" and c is not None and not any(m.endswith("packages.lock.json") for m in c.manifests):
            support -= {"trivy", "grype"}
        if c is not None and any(m.startswith("discovered by") for m in c.manifests):
            support.discard("osv")
        appl = sorted((support | ({"osv"} if f.rule == "osv" else set())) & ran)
        f.data["applicable_scanners"] = appl
        f.data["scanners"] = sorted(set(f.data["scanners"]))
        f.evidence.append({"source": "consensus", "detail": f"confirmed by {len(f.data['scanners'])} of {len(appl)} "
                           f"applicable scanners ({', '.join(NAMES[s] for s in f.data['scanners'])})"})
    status["ran"] = sorted(ran)
    status["results"] = {t: sum(1 for r in results if r["scanner"] == t) for t in use}
    return out, status
