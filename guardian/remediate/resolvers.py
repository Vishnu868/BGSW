"""Look up the immutable identifiers a safe fix pins to (read-only public APIs, no credentials):
  * container image tag -> sha256 digest (OCI distribution API, anonymous token)
  * GitHub Action tag/branch -> full commit SHA (GitHub REST API, unauthenticated)
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

ACCEPT = ", ".join(["application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.docker.distribution.manifest.v2+json", "application/vnd.oci.image.manifest.v1+json"])


def _split_image(ref: str) -> tuple[str, str, str]:
    ref = ref.split("@", 1)[0]
    name, tag = (ref.rsplit(":", 1) if ":" in ref.rsplit("/", 1)[-1] else (ref, "latest"))
    first = name.split("/", 1)[0]
    if "." in first or ":" in first or first == "localhost":
        registry, path = first, name.split("/", 1)[1]
    else:
        registry, path = "registry-1.docker.io", name if "/" in name else f"library/{name}"
    return registry, path, tag


def image_digest(ref: str, timeout: int = 20) -> str:
    registry, path, tag = _split_image(ref)
    url = f"https://{registry}/v2/{path}/manifests/{tag}"
    headers = {"Accept": ACCEPT, "User-Agent": "supply-chain-guardian/0.2"}
    for _ in range(2):
        req = urllib.request.Request(url, headers=headers, method="HEAD")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                d = r.headers.get("Docker-Content-Digest", "")
                if d:
                    return d
                raise RuntimeError("registry did not return a digest")
        except urllib.error.HTTPError as e:
            if e.code != 401 or "Authorization" in headers:
                raise RuntimeError(f"registry HTTP {e.code}") from None
            auth = e.headers.get("WWW-Authenticate", "")
            realm = re.search(r'realm="([^"]+)"', auth)
            service = re.search(r'service="([^"]+)"', auth)
            scope = re.search(r'scope="([^"]+)"', auth)
            if not realm:
                raise RuntimeError("registry needs credentials") from None
            q = "&".join(f"{k}={v.group(1)}" for k, v in (("service", service), ("scope", scope)) if v)
            tok = json.loads(urllib.request.urlopen(f"{realm.group(1)}?{q}", timeout=timeout).read())
            headers["Authorization"] = f"Bearer {tok.get('token') or tok.get('access_token')}"
    raise RuntimeError("could not resolve digest")


def action_sha(action: str, ref: str, timeout: int = 20) -> str:
    owner_repo = "/".join(action.split("/")[:2])
    req = urllib.request.Request(f"https://api.github.com/repos/{owner_repo}/commits/{ref}",
                                 headers={"Accept": "application/vnd.github.sha", "User-Agent": "supply-chain-guardian/0.2"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            sha = r.read().decode().strip()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"GitHub HTTP {e.code}") from None
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise RuntimeError("unexpected response from GitHub")
    return sha
