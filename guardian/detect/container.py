"""Category 1.5 - container images and artifacts (Dockerfile + compose files)."""
from __future__ import annotations

import re

from ..model import Component, Finding, Graph

# Base-image majors that are past end-of-life (data, not per-repo rules). Update as runtimes age out.
EOL = {"node": 22, "python": (3, 10), "golang": (1, 24), "openjdk": 17}

DL_PIPE = re.compile(r"(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z)?sh\b", re.I)


def _image_parts(ref: str):
    digest = ref.split("@", 1)[1] if "@" in ref else ""
    base = ref.split("@", 1)[0]
    last = base.rsplit("/", 1)[-1]
    tag = last.split(":", 1)[1] if ":" in last else ""
    name = base[: len(base) - len(tag) - 1] if tag else base
    return name, tag, digest


def _eol(name: str, tag: str) -> str:
    short = name.rsplit("/", 1)[-1]
    nums = [int(x) for x in re.findall(r"\d+", tag.split("-")[0])[:2]]
    if not nums or short not in EOL:
        return ""
    limit = EOL[short]
    if isinstance(limit, int):
        return f"{short} {nums[0]} is end-of-life (supported: {limit}+)" if nums[0] < limit else ""
    have = tuple(nums + [0])[:2]
    return f"{short} {'.'.join(map(str, have))} is end-of-life" if have < limit else ""


def _image_findings(ref: str, where: dict, node_id: str) -> list[Finding]:
    name, tag, digest = _image_parts(ref)
    out = []
    ev = [{"source": "image reference", "detail": ref, **where}]
    if not digest:
        sev = "high" if tag in ("", "latest") else "medium"
        out.append(Finding("1.5", sev,
                           f"Container image '{ref}' uses a {'floating latest tag' if sev == 'high' else 'mutable tag'} (no digest pin)",
                           component=node_id, rule="container.unpinned", evidence=ev,
                           recommendation=f"Pin by digest: {name}:{tag or 'TAG'}@sha256:<digest> (and let a bot update it)"))
    e = _eol(name, tag)
    if e:
        out.append(Finding("1.5", "medium", f"End-of-life base image: {ref}", component=node_id, rule="container.eol",
                           evidence=ev + [{"source": "runtime support", "detail": e}],
                           recommendation="Move to a supported runtime version"))
    return out


def scan(graph: Graph, inv, repo_id: str) -> list[Finding]:
    out: list[Finding] = []
    repo = inv.repo

    def node(ref: str) -> str:
        cid = f"container:{ref}"
        name, tag, digest = _image_parts(ref)
        graph.add(Component(id=cid, name=ref, version=tag or digest[:19], ecosystem="docker", kind="container"), dev=False)
        graph.link(repo_id, cid)
        return cid

    for df in inv.dockerfiles:
        rel = df.relative_to(repo).as_posix()
        lines = df.read_text(encoding="utf-8", errors="replace").splitlines()
        args, stages, users, last_from = {}, set(), [], 0
        for i, raw in enumerate(lines, 1):
            line = raw.strip()
            m = re.match(r"ARG\s+(\w+)=(\S+)", line, re.I)
            if m:
                args[m.group(1)] = m.group(2).strip("\"'")
            m = re.match(r"FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", line, re.I)
            if m:
                ref = re.sub(r"\$\{?(\w+)\}?", lambda x: args.get(x.group(1), x.group(0)), m.group(1))
                last_from, users = i, []
                if m.group(2):
                    stages.add(m.group(2).lower())
                if ref.lower() in stages or ref == "scratch":
                    continue
                out += _image_findings(ref, {"file": rel, "line": i}, node(ref))
            m = re.match(r"USER\s+(\S+)", line, re.I)
            if m:
                users.append(m.group(1))
            if DL_PIPE.search(line):
                out.append(Finding("1.5", "high", f"Remote script piped into a shell in {rel}", rule="container.curl-pipe-sh",
                                   evidence=[{"source": "Dockerfile", "detail": line[:200], "file": rel, "line": i}],
                                   recommendation="Download, verify a checksum/signature, then execute"))
            if re.match(r"ADD\s+https?://", line, re.I):
                out.append(Finding("1.5", "medium", f"ADD from a remote URL without checksum in {rel}", rule="container.remote-add",
                                   evidence=[{"source": "Dockerfile", "detail": line[:200], "file": rel, "line": i}],
                                   recommendation="Use ADD --checksum=sha256:... or download and verify explicitly"))
        if last_from and (not users or users[-1] in ("root", "0", "0:0")):
            out.append(Finding("1.5", "medium", f"Final image in {rel} runs as root", rule="container.root-user",
                               evidence=[{"source": "Dockerfile", "detail": "no non-root USER in the final stage",
                                          "file": rel, "line": last_from}],
                               recommendation="Add a non-root USER to the final stage"))

    for cf in inv.compose_files:
        rel = cf.relative_to(repo).as_posix()
        for i, raw in enumerate(cf.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            m = re.match(r"\s*image:\s*['\"]?([^'\"\s#]+)", raw)
            if m and "${" not in m.group(1):
                out += _image_findings(m.group(1), {"file": rel, "line": i}, node(m.group(1)))
            if re.match(r"\s*privileged:\s*true", raw):
                out.append(Finding("1.5", "high", f"Privileged container in {rel}", rule="container.privileged",
                                   evidence=[{"source": "compose", "detail": raw.strip(), "file": rel, "line": i}],
                                   recommendation="Remove privileged mode; grant only the capabilities needed"))
    return out
