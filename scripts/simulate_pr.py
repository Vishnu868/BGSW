"""Make a LOCAL copy of an npm project and apply a 'suspicious pull request' to its lockfile, so the
Guardian's change detection can be demonstrated. Nothing is published or installed.

    python scripts/simulate_pr.py targets/juice-shop        -> targets/juice-shop-pr
    python -m guardian scan targets/juice-shop-pr --baseline runs/juice-shop/sbom.cdx.json --no-lockgen

Changes applied (packages are picked generically from the lockfile, not by name):
  1. integrity hash of an existing package swapped (same version, different tarball)
  2. resolved URL of another package pointed at a non-official registry
  3. a new dependency added that runs an install script
  4. one package downgraded to an older version
"""
from __future__ import annotations

import base64
import hashlib
import json
import shutil
import sys
from pathlib import Path

IGNORE = shutil.ignore_patterns("node_modules", ".git", "screenshots", "*.png", "*.jpg", "*.gif", "*.mp4", "*.pdf")


def main(src: str) -> None:
    src_p = Path(src).resolve()
    dst = src_p.with_name(src_p.name + "-pr")
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src_p, dst, ignore=IGNORE)
    lock_f = dst / "package-lock.json"
    lock = json.loads(lock_f.read_text(encoding="utf-8"))
    pk = lock["packages"]
    regular = [k for k, v in pk.items() if k.startswith("node_modules/") and "/node_modules/" not in k[13:]
               and v.get("integrity", "").startswith("sha512-") and not v.get("dev")]
    a, b, c = regular[3], regular[7], regular[11]
    log = []

    fake = base64.b64encode(hashlib.sha512(b"tampered tarball").digest()).decode()
    log.append(f"1. {a}: integrity {pk[a]['integrity'][:20]}... -> sha512-{fake[:12]}...")
    pk[a]["integrity"] = "sha512-" + fake

    old = pk[b]["resolved"]
    pk[b]["resolved"] = old.replace("https://registry.npmjs.org/", "https://npm-mirror.example-cdn.net/")
    log.append(f"2. {b}: resolved -> {pk[b]['resolved']}")

    name = "node-telemetry-helper"
    pk[f"node_modules/{name}"] = {"version": "1.0.3", "resolved": f"https://registry.npmjs.org/{name}/-/{name}-1.0.3.tgz",
                                  "integrity": "sha512-" + base64.b64encode(hashlib.sha512(name.encode()).digest()).decode(),
                                  "hasInstallScript": True, "license": "MIT"}
    pk[""].setdefault("dependencies", {})[name] = "^1.0.3"
    pkg_f = dst / "package.json"
    pkg = json.loads(pkg_f.read_text(encoding="utf-8"))
    pkg.setdefault("dependencies", {})[name] = "^1.0.3"
    pkg_f.write_text(json.dumps(pkg, indent=2), encoding="utf-8")
    log.append(f"3. added direct dependency {name}@1.0.3 with an install script")

    ver = pk[c]["version"]
    parts = ver.split(".")
    if parts[0].isdigit() and int(parts[0]) > 0:
        pk[c]["version"] = f"{int(parts[0]) - 1}.0.0"
        log.append(f"4. {c}: {ver} -> {pk[c]['version']} (downgrade)")

    lock_f.write_text(json.dumps(lock, indent=2), encoding="utf-8")
    print(f"Simulated PR written to {dst}")
    print("\n".join("   " + x for x in log))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "targets/juice-shop")
