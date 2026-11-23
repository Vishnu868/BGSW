"""One-time setup after cloning: portable Node.js (checksum-verified) + the demo target repositories.

    python scripts/setup.py            # node + targets
    python scripts/setup.py --no-node  # only clone targets (if npm is already installed)
    python scripts/setup.py --scanners # also download Trivy + Grype (official GitHub releases, checksum-verified)

Node.js is only used to generate missing npm lockfiles with --ignore-scripts (no package code runs).
"""
from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "juice-shop": "https://github.com/juice-shop/juice-shop",          # npm (server + Angular)   - main demo
    "NodeGoat": "https://github.com/OWASP/NodeGoat",                   # npm
    "crAPI": "https://github.com/OWASP/crAPI",                         # npm + Go + Python microservices
    "WebGoat": "https://github.com/WebGoat/WebGoat",                   # Maven (parent/BOM resolution)
    "railsgoat": "https://github.com/OWASP/railsgoat",                 # Ruby (Gemfile.lock)
    "spring-petclinic-microservices": "https://github.com/spring-petclinic/spring-petclinic-microservices",
    "nodejs-goof": "https://github.com/snyk-labs/nodejs-goof",
    "pygoat": "https://github.com/adeyosemanputra/pygoat",
}


def get_node() -> None:
    dest = ROOT / "tools" / "node"
    if dest.exists():
        print(f"node already present: {dest}")
        return
    if sys.platform != "win32":
        print("Non-Windows: install Node.js LTS with your package manager (npm must be on PATH).")
        return
    lts = next(v for v in json.load(urllib.request.urlopen("https://nodejs.org/dist/index.json")) if v["lts"])
    ver = lts["version"]
    name = f"node-{ver}-win-x64.zip"
    sums = urllib.request.urlopen(f"https://nodejs.org/dist/{ver}/SHASUMS256.txt").read().decode()
    expected = next(l.split()[0] for l in sums.splitlines() if l.endswith(" " + name))
    print(f"downloading {name} ...")
    data = urllib.request.urlopen(f"https://nodejs.org/dist/{ver}/{name}").read()
    if hashlib.sha256(data).hexdigest() != expected:
        raise SystemExit("checksum mismatch - aborting")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        z.extractall(ROOT / "tools")
    (ROOT / "tools" / f"node-{ver}-win-x64").rename(dest)
    print(f"node {ver} installed in {dest} (checksum OK)")


def get_scanners() -> None:
    """Latest Trivy (aquasecurity/trivy) and Grype (anchore/grype) Windows builds into tools/, checksum-verified."""
    for repo, tool, marker in (("aquasecurity/trivy", "trivy", "windows-64bit.zip"),
                               ("anchore/grype", "grype", "windows_amd64.zip")):
        dest = ROOT / "tools" / tool
        if dest.exists():
            print(f"{tool} already present")
            continue
        rel = json.load(urllib.request.urlopen(f"https://api.github.com/repos/{repo}/releases/latest"))
        asset = next(a for a in rel["assets"] if a["name"].endswith(marker))
        sums = next(a for a in rel["assets"] if a["name"].endswith("checksums.txt"))
        expected = next(l.split()[0] for l in urllib.request.urlopen(sums["browser_download_url"]).read().decode().splitlines()
                        if l.endswith(" " + asset["name"]))
        print(f"downloading {asset['name']} ...")
        data = urllib.request.urlopen(asset["browser_download_url"]).read()
        if hashlib.sha256(data).hexdigest() != expected:
            raise SystemExit(f"{tool}: checksum mismatch - aborting")
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            z.extractall(dest)
        print(f"{tool} {rel['tag_name']} installed in {dest} (checksum OK)")


def get_targets() -> None:
    (ROOT / "targets").mkdir(exist_ok=True)
    for name, url in TARGETS.items():
        d = ROOT / "targets" / name
        if d.exists():
            print(f"{name} already cloned")
            continue
        subprocess.run(["git", "clone", "--depth", "1", url, str(d)], check=True)


if __name__ == "__main__":
    if "--no-node" not in sys.argv:
        get_node()
    if "--scanners" in sys.argv:
        get_scanners()
    get_targets()
    print("done - next: python -m guardian scan targets/juice-shop")
