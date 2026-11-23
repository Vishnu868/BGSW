"""CycloneDX 1.5 JSON SBOM (components, dependency graph, vulnerabilities)."""
from __future__ import annotations

import base64
import uuid
from datetime import datetime, timezone

HASH_ALG = {"sha512": "SHA-512", "sha384": "SHA-384", "sha256": "SHA-256", "sha1": "SHA-1"}


def _hashes(integrity: str) -> list:
    out = []
    for part in (integrity or "").split():
        alg, _, b64 = part.partition("-")
        if alg in HASH_ALG:
            try:
                out.append({"alg": HASH_ALG[alg], "content": base64.b64decode(b64).hex()})
            except Exception:
                pass
    return out


def cyclonedx(graph, findings, meta: dict) -> dict:
    comps = []
    for cid, c in graph.nodes.items():
        if c.kind in ("repository", "application"):
            continue
        props = [{"name": "guardian:name", "value": c.name}, {"name": "guardian:ecosystem", "value": c.ecosystem},
                 {"name": "guardian:direct", "value": str(c.direct).lower()},
                 {"name": "guardian:dev", "value": str(c.dev).lower()},
                 {"name": "guardian:install_script", "value": str(c.install_script).lower()},
                 {"name": "guardian:integrity", "value": " ".join(sorted(c.integrities))},
                 {"name": "guardian:resolved", "value": " ".join(sorted(c.sources))},
                 {"name": "guardian:manifests", "value": ",".join(sorted(c.manifests))}]
        comp = {"type": {"library": "library", "container": "container", "action": "application"}.get(c.kind, "library"),
                "bom-ref": cid, "name": c.name, "version": c.version, "scope": "excluded" if c.dev else "required",
                "properties": props}
        if c.purl:
            comp["purl"] = c.purl
        h = _hashes(c.integrity)
        if h:
            comp["hashes"] = h
        comps.append(comp)
    deps: dict[str, list] = {}
    for a, b in graph.edges:
        deps.setdefault(a, []).append(b)
    vulns = {}
    for f in findings:
        if f.rule != "osv":
            continue
        vid = f.data["vuln_id"]
        v = vulns.setdefault(vid, {"id": vid, "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vid}"},
                                   "ratings": [{"score": f.data.get("cvss"), "severity": f.severity, "method": "CVSSv31"}],
                                   "description": f.title, "affects": []})
        v["affects"].append({"ref": f.component})
        if f.data.get("fixed"):
            v["recommendation"] = f"Upgrade to {f.data['fixed']}"
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                     "tools": {"components": [{"type": "application", "name": "supply-chain-guardian", "version": "0.1"}]},
                     "component": {"type": "application", "bom-ref": graph.roots[0], "name": meta["repo"]}},
        "components": comps,
        "dependencies": [{"ref": k, "dependsOn": sorted(v)} for k, v in sorted(deps.items())],
        "vulnerabilities": list(vulns.values()),
    }
