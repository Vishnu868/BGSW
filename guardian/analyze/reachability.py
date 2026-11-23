"""Is a dependency actually used by the application's own code? (static import search, evidence = file:line)

Status per component:
  imported            direct dependency imported/required in source            (evidence: file:line)
  used-in-scripts     only referenced by package.json scripts / config (build tool)
  not-imported        direct dependency never referenced -> possibly unused
  via-used-parent     transitive; at least one direct dependency that pulls it in is imported
  via-unused-parent   transitive; none of the direct dependencies that pull it in are imported
  unknown             ecosystem not analysed (e.g. Maven/Go) or no source found
This is import-level reachability, not call-graph analysis: "imported" means the package is loaded,
not that the vulnerable function is called. The report says so.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

SRC_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".py"}
SKIP = {"node_modules", ".git", "dist", "build", ".angular", "coverage", "__pycache__", ".venv", "venv", "vendor"}
JS_IMPORT = re.compile(r"""(?:require\s*\(\s*|from\s+|import\s*\(\s*|import\s+)['"]((?:@[\w.-]+/)?[\w.-]+)(?:/[^'"]*)?['"]""")
PY_IMPORT = re.compile(r"^\s*(?:from\s+([\w]+)[\w.]*\s+import|import\s+([\w]+))", re.M)
PY_MODULE = {"beautifulsoup4": "bs4", "pyyaml": "yaml", "pillow": "PIL", "scikit-learn": "sklearn",
             "python-dateutil": "dateutil", "psycopg2-binary": "psycopg2", "djangorestframework": "rest_framework",
             "pyjwt": "jwt", "python-dotenv": "dotenv", "opencv-python": "cv2", "pycryptodome": "Crypto",
             "django-cors-headers": "corsheaders", "pyopenssl": "OpenSSL", "attrs": "attr", "protobuf": "google"}


class Index:
    def __init__(self, repo: Path):
        self.repo = repo
        self.js: dict[str, list] = {}     # package -> [(file, line)]
        self.py: dict[str, list] = {}     # module  -> [(file, line)]
        self.scripts_text = ""
        self.files = 0
        for dirpath, dirnames, filenames in os.walk(repo):
            dirnames[:] = [d for d in dirnames if d not in SKIP]
            for fn in filenames:
                p = Path(dirpath) / fn
                if fn == "package.json":
                    try:
                        pkg = json.loads(p.read_text(encoding="utf-8"))
                        self.scripts_text += " " + json.dumps(pkg.get("scripts", {}))
                    except Exception:
                        pass
                if p.suffix not in SRC_EXT:
                    continue
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                self.files += 1
                rel = p.relative_to(repo).as_posix()
                if p.suffix == ".py":
                    for m in PY_IMPORT.finditer(text):
                        mod = (m.group(1) or m.group(2)).lower()
                        self.py.setdefault(mod, []).append((rel, text.count("\n", 0, m.start()) + 1))
                else:
                    for m in JS_IMPORT.finditer(text):
                        self.js.setdefault(m.group(1), []).append((rel, text.count("\n", 0, m.start()) + 1))

    def uses(self, name: str, eco: str) -> list:
        if eco == "npm":
            return self.js.get(name, [])
        if eco == "PyPI":
            mod = PY_MODULE.get(name, name.replace("-", "_")).lower()
            return self.py.get(mod, [])
        return []


def analyse(findings_doc: dict, repo: Path) -> dict[str, dict]:
    """component id -> {"status", "evidence": [...], "detail"}"""
    idx = Index(repo)
    comps = {}
    for f in findings_doc["findings"]:
        cd = f.get("component_detail")
        if cd and f["component"]:
            comps[f["component"]] = cd
    out: dict[str, dict] = {}
    direct_status: dict[str, str] = {}

    def direct(name: str, eco: str) -> dict:
        if eco not in ("npm", "PyPI"):
            return {"status": "unknown", "evidence": [], "detail": f"import analysis not implemented for {eco}"}
        hits = idx.uses(name, eco)
        if hits:
            return {"status": "imported", "evidence": [f"{a}:{b}" for a, b in hits[:8]],
                    "detail": f"imported in {len(hits)} place(s)"}
        if re.search(rf"(?<![\w@/-]){re.escape(name.split('/')[-1])}(?![\w-])", idx.scripts_text):
            return {"status": "used-in-scripts", "evidence": ["package.json scripts"], "detail": "used as a build/test tool"}
        return {"status": "not-imported", "evidence": [], "detail": f"no import found in {idx.files} source files"}

    for cid, cd in comps.items():
        eco = cd["ecosystem"]
        if cd["kind"] != "library":
            continue
        if cd["direct"]:
            out[cid] = direct(cd["name"], eco)
            continue
        parents = cd.get("introduced_by") or []
        if not parents or eco not in ("npm", "PyPI"):
            out[cid] = {"status": "unknown", "evidence": [], "detail": "no direct parent recorded"}
            continue
        used = []
        for p in parents:
            st = direct_status.setdefault(p, direct(p, eco)["status"])
            if st in ("imported", "used-in-scripts"):
                used.append(p)
        out[cid] = ({"status": "via-used-parent", "evidence": used[:5],
                     "detail": f"pulled in by {', '.join(used[:3])}, which the app uses"} if used else
                    {"status": "via-unused-parent", "evidence": parents[:5],
                     "detail": f"only pulled in by {', '.join(parents[:3])}, which the app never imports"})
    out["_meta"] = {"source_files": idx.files}
    return out
