"""Categories 1.3 (typosquatted / malicious) and 1.4 (install scripts) - package reputation checks.

Signals (no package-specific rules):
  * name is 1-2 edits away from a well-known package (offline list in data/)
  * npm registry metadata: the package's declared source repo has a *different but near-identical* name
    (typosquat / "starjacking"), single maintainer, very low downloads
  * install scripts (preinstall/install/postinstall) and dangerous patterns inside them
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..model import Finding, Graph

DATA = Path(__file__).resolve().parents[1] / "data"
CACHE = Path(__file__).resolve().parents[2] / ".cache" / "registry"
RISKY_SCRIPT = re.compile(r"curl\s|wget\s|\|\s*(ba)?sh|powershell|node\s+-e|eval\(|base64|child_process|https?://", re.I)


def popular(eco: str) -> set[str]:
    f = DATA / f"popular_{eco.lower()}.txt"
    if not f.exists():
        return set()
    return {l.strip() for l in f.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")}


def distance(a: str, b: str, limit: int = 3) -> int:
    """Damerau-Levenshtein (optimal string alignment), with early exit above `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2, prev = None, list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = ca != cb
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def _bare(name: str) -> str:
    return name.split("/")[-1].lower()


def _flat(name: str) -> str:
    return re.sub(r"[-_.]", "", _bare(name))


def _scope(name: str) -> str:
    return name.split("/")[0] if name.startswith("@") else ""


def lookalike(name: str, known: set[str]) -> str | None:
    """A known package whose name is 1-2 edits from `name`. Scoped names are only compared with
    scoped names (so '@x/core' is not 'cors'), and the scope itself is compared too ('@angu1ar/core')."""
    if name in known:
        return None
    n = name.lower()
    for k in known:
        if bool(_scope(k)) != bool(_scope(name)) or k.lower() == n:
            continue
        if _flat(k) == _flat(name) and _scope(k) == _scope(name):   # cross-env vs crossenv
            return k
        limit = 1 if len(k) <= 8 else 2
        if len(n) >= 5 and distance(n, k.lower(), limit) <= limit:
            return k
    return None


def _get(url: str, cache_key: str, offline: bool):
    f = CACHE / (re.sub(r"[^A-Za-z0-9_.@-]", "_", cache_key) + ".json")
    if f.exists():
        return json.loads(f.read_text(encoding="utf-8"))
    if offline:
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "supply-chain-guardian/0.1",
                                                   "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
    except Exception:
        return None
    CACHE.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(data), encoding="utf-8")
    return data


def _npm_meta(c, offline):
    return _get(f"https://registry.npmjs.org/{urllib.parse.quote(c.name, safe='@')}/{c.version}",
                f"npm_{c.name}_{c.version}", offline)


def _repo_name(meta: dict) -> str:
    repo = meta.get("repository") or {}
    url = repo.get("url", "") if isinstance(repo, dict) else str(repo)
    m = re.search(r"github\.com[/:]([^/]+)/([^/#?]+?)(?:\.git)?(?:[/#?].*)?$", url)
    return f"{m.group(1)}/{m.group(2)}" if m else ""


def _downloads(names: list[str], offline: bool) -> dict[str, int]:
    out = {}
    unscoped = [n for n in names if not n.startswith("@")]
    for i in range(0, len(unscoped), 100):
        chunk = unscoped[i:i + 100]
        d = _get("https://api.npmjs.org/downloads/point/last-week/" + ",".join(chunk),
                 "dl_" + hashlib.md5(",".join(chunk).encode()).hexdigest(), offline) or {}
        if len(chunk) == 1 and "downloads" in d:
            d = {chunk[0]: d}
        for n, v in d.items():
            if isinstance(v, dict) and "downloads" in v:
                out[n] = v["downloads"]
    return out


def scan(graph: Graph, inv, offline: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    libs = [c for c in graph.nodes.values() if c.kind == "library"]
    known = {eco: popular(eco) for eco in {c.ecosystem for c in libs}}

    # --- look-alike names, confirmed by adoption (a real typosquat has far fewer users) -----
    flagged = set()
    pairs = [(c, k) for c in libs if (k := lookalike(c.name, known.get(c.ecosystem, set())))]
    npm_names = sorted({x for c, k in pairs if c.ecosystem == "npm" for x in (c.name, k)})
    pair_dl = _downloads(npm_names, offline) if npm_names else {}
    for c, k in pairs:
        mine, theirs = pair_dl.get(c.name), pair_dl.get(k)
        ev = [{"source": "name similarity", "detail": f"'{c.name}' vs '{k}' (edit distance {distance(c.name.lower(), k.lower())})"}]
        if mine is not None and theirs:
            if mine >= 0.25 * theirs or mine >= 1_000_000:   # established in its own right -> not a squat
                continue
            ev.append({"source": "npm downloads (last week)",
                       "detail": f"{c.name}: {mine:,} vs {k}: {theirs:,} ({mine / theirs:.1%})"})
            sev = "high"
        else:
            ev.append({"source": "adoption", "detail": "download counts unavailable - name match only"})
            sev = "medium"
        flagged.add(c.id)
        findings.append(Finding(
            category="1.3", severity=sev if c.direct else ("medium" if sev == "high" else "low"),
            title=f"Possible typosquat: '{c.name}' looks like popular package '{k}'",
            component=c.id, rule="packages.lookalike-name", evidence=ev,
            recommendation=f"Confirm '{c.name}' is intended; if '{k}' was meant, replace it and audit machines that installed it",
            data={"lookalike_of": k, "downloads": mine, "lookalike_downloads": theirs}))

    # --- online: npm registry reputation for direct deps + anything with an install script ---
    npm_check = [c for c in libs if c.ecosystem == "npm" and c.exact and (c.direct or c.install_script)]
    with ThreadPoolExecutor(16) as ex:
        metas = dict(zip([c.id for c in npm_check], ex.map(lambda c: _npm_meta(c, offline), npm_check)))
    dls = _downloads(sorted({c.name for c in npm_check if c.direct}), offline)

    for c in npm_check:
        meta = metas.get(c.id)
        if not meta:
            continue
        repo = _repo_name(meta)
        repo_bare = repo.split("/")[-1].lower() if repo else ""
        b = _bare(c.name)
        maint = [m.get("name") for m in meta.get("maintainers", []) if isinstance(m, dict)]
        owner = repo.split("/")[0].lower() if repo else ""
        publisher = {str(x).lower() for x in maint} | {str((meta.get("_npmUser") or {}).get("name", "")).lower()}
        # name ~ repo but not equal, and the repo owner is NOT among the people who publish the package
        if c.direct and repo_bare and repo_bare != b and _flat(repo_bare) != _flat(b) \
                and distance(b, repo_bare, 2) <= 2                 and not any(p and len(p) >= 4 and (p in owner or owner in p) for p in publisher) \
                and not repo_bare.rstrip("s") == b and not repo_bare.endswith(("." + b, "-" + b, "js" + b)):
            ev = [{"source": "npm registry", "detail": f"package '{c.name}' declares source repository github.com/{repo}"},
                  {"source": "name mismatch", "detail": f"'{b}' vs repository '{repo_bare}' (edit distance {distance(b, repo_bare)})"},
                  {"source": "maintainers", "detail": ", ".join(maint) or "unknown"}]
            if c.name in dls:
                ev.append({"source": "weekly downloads", "detail": f"{dls[c.name]:,}"})
            if c.id not in flagged:
                findings.append(Finding(
                    category="1.3", severity="high",
                    title=f"Typosquat / starjacking: '{c.name}' claims to be built from '{repo}'",
                    component=c.id, rule="packages.repo-name-mismatch", evidence=ev,
                    recommendation=f"Replace with the genuine package '{repo_bare}' (if that was intended) after review; "
                                   "do not trust stars/README borrowed from another repo",
                    data={"claimed_repo": repo, "maintainers": maint, "weekly_downloads": dls.get(c.name)}))
                flagged.add(c.id)
        if c.direct and c.name in dls and dls[c.name] < 1000 and c.id not in flagged:
            findings.append(Finding(
                category="1.3", severity="low", title=f"Low-adoption direct dependency: {c.name} ({dls[c.name]:,} downloads/week)",
                component=c.id, rule="packages.low-downloads",
                evidence=[{"source": "npm downloads API", "detail": f"{dls[c.name]:,} downloads last week"},
                          {"source": "source repository", "detail": repo or "none declared"}],
                recommendation="Review the package source and maintainer before trusting it"))
        if c.install_script:
            scripts = {k: v for k, v in (meta.get("scripts") or {}).items() if k in ("preinstall", "install", "postinstall")}
            risky = {k: v for k, v in scripts.items() if RISKY_SCRIPT.search(v)}
            findings.append(Finding(
                category="1.4", severity="high" if risky else "low",
                title=(f"Install script with risky command in {c.name}@{c.version}" if risky
                       else f"Package runs code at install time: {c.name}@{c.version}"),
                component=c.id, rule="packages.install-script",
                evidence=[{"source": "package-lock.json", "detail": "hasInstallScript: true"}] +
                         [{"source": f"scripts.{k}", "detail": v[:200]} for k, v in scripts.items()],
                recommendation=("Block with --ignore-scripts and review the script before allowing it" if risky
                                else "Expected for native/binary packages; keep installs on --ignore-scripts by default "
                                     "and allow-list this package explicitly"),
                data={"scripts": scripts}))
    # install scripts for packages we could not fetch metadata for
    for c in libs:
        if c.install_script and not metas.get(c.id):
            findings.append(Finding(category="1.4", severity="low",
                                    title=f"Package runs code at install time: {c.name}@{c.version}", component=c.id,
                                    rule="packages.install-script",
                                    evidence=[{"source": "lockfile", "detail": "hasInstallScript: true"}],
                                    recommendation="Review before allowing install scripts"))
    return findings
