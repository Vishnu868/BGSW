"""Read-only tools the agents can call. Each one is a query on the symbolic fact store (guardian.neurosymbolic.facts)."""
from __future__ import annotations

DOCS = {
    "item_details": "()  - the risk item, its findings, deterministic evidence and symbolic score",
    "dependency_paths": "()  - how the component enters the app: path, direct parents, dev-only",
    "code_usage": "(package)  - where the application imports a package (file:line)",
    "advisory": "(vuln_id)  - advisory summary, details, affected ranges, fixed versions",
    "exploit_intel": "()  - EPSS probability and CISA KEV status for the item's CVEs",
    "registry_info": "(package, version)  - npm metadata: source repo, maintainers, publisher, install scripts",
    "registry_versions": "(package)  - published versions of a package",
    "compare_downloads": "(package, other)  - weekly downloads of two packages (typosquat check)",
    "baseline_change": "()  - what changed for this component since the previous scan",
    "file_lines": "(file, line)  - lines of a repository file (Dockerfile, workflow, manifest)",
    "dependency_tree": "(package, version)  - resolved dependency tree of a published version (deps.dev)",
    "safe_upgrade": "(package)  - smallest-impact version >= fixed whose own dependency tree has no known CVE",
    "list_files": "(contains)  - repository files whose path contains the text (max 60), e.g. 'route', 'model'",
    "search_repo": "(text)  - lines in the repository containing the text (max 20 hits, file:line + line)",
    "read_lines": "(file, line)  - a few lines around file:line",
}


class Toolbox:
    docs = DOCS

    def __init__(self, facts, item: dict):
        self.f, self.item = facts, item
        cd = item.get("component") or {}
        self.name, self.version, self.eco = cd.get("name", ""), cd.get("version", ""), cd.get("ecosystem", "npm") or "npm"
        self.fids = item.get("finding_ids", [])

    def run(self, name: str, args: dict):
        fn = getattr(self, "t_" + name, None)
        if fn is None:
            return {"error": f"unknown tool '{name}'"}
        try:
            return fn(**{k: v for k, v in (args or {}).items() if isinstance(k, str)})
        except TypeError as e:
            return {"error": f"bad arguments: {e}"}
        except Exception as e:  # a tool failure is evidence too, never a crash
            return {"error": f"tool failed: {e}"}

    def _findings(self):
        return [self.f.findings[i] for i in self.fids if i in self.f.findings]

    def t_item_details(self):
        it = self.item
        return {"risk_item": {k: it.get(k) for k in ("id", "headline", "severity", "category", "rule", "base_score",
                                                       "base_priority", "factors", "max_fixed", "reachability")},
                "component": it.get("component"),
                "findings": [{"id": f["id"], "title": f["title"], "rule": f["rule"], "evidence": f["evidence"][:6],
                              "data": {k: v for k, v in f["data"].items() if k in ("vuln_id", "cve", "cvss", "fixed", "aliases",
                                                                                   "claimed_repo", "maintainers", "scripts")}}
                             for f in self._findings()]}

    def t_dependency_paths(self):
        cd = self.item.get("component") or {}
        return {"path": cd.get("dependency_path"), "introduced_by": cd.get("introduced_by"),
                "direct": cd.get("direct"), "dev_only": cd.get("dev_only")}

    def t_code_usage(self, package: str = ""):
        return self.f.code_usage(package or self.name, self.eco)

    def t_advisory(self, vuln_id: str = ""):
        ids = [f["data"].get("vuln_id") for f in self._findings() if f["data"].get("vuln_id")]
        vid = vuln_id or (ids[0] if ids else "")
        if vid not in ids:
            return {"error": f"advisory {vid or '(none)'} is not part of this item", "known_ids": ids}
        return self.f.advisory(vid)

    def t_exploit_intel(self):
        cves = sorted({f["data"].get("cve") for f in self._findings() if f["data"].get("cve")})
        return self.f.exploit_intel(cves) if cves else {"note": "no CVE ids for this item"}

    def t_registry_info(self, package: str = "", version: str = ""):
        return self.f.registry_info(package or self.name, version or self.version, self.eco)

    def t_registry_versions(self, package: str = ""):
        vs = self.f.versions(package or self.name, self.eco)
        return {"error": "versions unavailable"} if vs is None else {"package": package or self.name, "latest": vs[-1] if vs else None,
                                                                    "count": len(vs), "recent": vs[-15:]}

    def t_compare_downloads(self, package: str = "", other: str = ""):
        return self.f.downloads([package or self.name, other])

    def t_baseline_change(self):
        return self.f.baseline_changes(self.item.get("key", ""))

    def t_file_lines(self, file: str = "", line: int | None = None):
        if not file:
            ev = [e for f in self._findings() for e in f["evidence"] if e.get("file")]
            if not ev:
                return {"error": "no file in this item's evidence"}
            file, line = ev[0]["file"], ev[0].get("line")
        return self.f.file_lines(file, line)

    def t_dependency_tree(self, package: str = "", version: str = ""):
        t = self.f.tree(package or self.name, version or self.version, self.eco)
        return {"error": "tree unavailable"} if t is None else {"package": package or self.name, "version": version or self.version,
                                                                "dependencies": [f"{n['name']}@{n['version']}" for n in t][:60]}

    def t_list_files(self, contains: str = ""):
        from ..analyze.business import _files
        hits = [p.relative_to(self.f.repo).as_posix() for p in _files(self.f.repo)
                if contains.lower() in p.relative_to(self.f.repo).as_posix().lower()]
        return {"contains": contains, "files": hits[:60], "total": len(hits)}

    def t_search_repo(self, text: str = ""):
        from ..analyze.business import _files
        if len(text) < 3:
            return {"error": "search text must have at least 3 characters"}
        hits = []
        for p in _files(self.f.repo):
            try:
                for i, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines()[:4000], 1):
                    if text.lower() in line.lower() and len(line) < 400:
                        hits.append(f"{p.relative_to(self.f.repo).as_posix()}:{i}: {line.strip()[:140]}")
                        if len(hits) >= 20:
                            return {"text": text, "hits": hits, "truncated": True}
            except OSError:
                continue
        return {"text": text, "hits": hits}

    def t_read_lines(self, file: str = "", line: int = 1):
        return self.f.file_lines(file, int(line or 1), context=4)

    def t_safe_upgrade(self, package: str = ""):
        return self.f.safe_upgrade(package or self.name, self.item.get("max_fixed") or "", self.eco, self.version)
