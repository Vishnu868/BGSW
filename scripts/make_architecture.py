"""Render the architecture diagram: docs/architecture.svg (+ PNG via headless Chrome/Edge).

    python scripts/make_architecture.py
"""
from __future__ import annotations

import shutil
import subprocess
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
W, H = 1800, 1060
STYLE = {  # stroke, fill, tag
    "engine": ("#1f4e9c", "#e8f0fc", "deterministic engine"),
    "agent": ("#6b3fa0", "#f1eafa", "AI agent"),
    "human": ("#c2580a", "#fdf0e4", "human decision"),
    "data": ("#5b6876", "#f4f5f7", "data / output"),
    "ext": ("#1f7a3a", "#e9f6ee", "external public data"),
}
out: list[str] = []


def box(x, y, w, h, kind, title, lines, tag=True):
    stroke, fill, label = STYLE[kind]
    dash = ' stroke-dasharray="6 4"' if kind == "data" else ""
    out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{fill}" stroke="{stroke}" stroke-width="2"{dash}/>')
    out.append(f'<text x="{x + 16}" y="{y + 30}" class="t" fill="{stroke}">{escape(title)}</text>')
    if tag and w >= 300:
        out.append(f'<text x="{x + w - 14}" y="{y + 28}" class="tag" text-anchor="end" fill="{stroke}">{escape(label)}</text>')
    for i, line in enumerate(lines):
        cls = "l b" if line.startswith("!") else "l"
        out.append(f'<text x="{x + 16}" y="{y + 58 + i * 21}" class="{cls}">{escape(line.lstrip("!"))}</text>')


def arrow(d, label="", lx=0, ly=0, dashed=False, color="#3d4a5c"):
    da = ' stroke-dasharray="7 5"' if dashed else ""
    out.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="2.2"{da} marker-end="url(#ah)"/>')
    if label:
        out.append(f'<text x="{lx}" y="{ly}" class="al">{escape(label)}</text>')


def band(y, h, title, sub):
    out.append(f'<rect x="30" y="{y}" width="1440" height="{h}" rx="16" fill="#fafbfd" stroke="#d5dbe3"/>')
    out.append(f'<text x="50" y="{y + 24}" class="bt">{escape(title)}</text>')
    out.append(f'<text x="290" y="{y + 24}" class="bs">{escape(sub)}</text>')


def build() -> str:
    out.clear()
    out.append('<text x="30" y="44" class="h">Software Supply Chain Guardian — architecture</text>')
    lx = 30
    for k in ("engine", "agent", "human", "data", "ext"):
        s, f, label = STYLE[k]
        out.append(f'<rect x="{lx}" y="62" width="22" height="16" rx="4" fill="{f}" stroke="{s}" stroke-width="2"/>')
        out.append(f'<text x="{lx + 30}" y="75" class="lg">{label}</text>')
        lx += 60 + len(label) * 8
    # ---- band 1: Day 1 eyes
    band(96, 262, "DAY 1 · EYES", "python -m guardian scan <repo>  →  what is in the app, what changed, what is risky")
    box(50, 134, 200, 210, "data", "Any repository", ["local folder or git URL", "read-only clone", "", "missing npm lockfile?", "generated with", "--ignore-scripts", "(no package code runs)"], tag=False)
    box(290, 134, 360, 210, "engine", "1 · DISCOVER", ["find manifests · lockfiles ·", "Dockerfiles · CI workflows", "adapters: npm lockfile v1–v3 ·", "Python · Maven · Go · Ruby · PHP", "deps.dev fills lockfile-less trees", "!→ dependency graph + paths"])
    box(690, 134, 420, 210, "engine", "2 · DETECT", ["osv.py        1.1/1.2 CVEs · CVSS · fixed version", "packages.py   1.3 typosquat · 1.4 install scripts", "lockfile.py   1.6 tamper · registry · diff", "container.py  1.5 digest pin · EOL · root", "cicd.py       1.7 unpinned actions · injection", "!every finding carries evidence"])
    box(1150, 134, 300, 210, "data", "Day 1 outputs", ["!guardian.html", "interactive dependency graph", "findings.json  (evidence)", "sbom.cdx.json  (CycloneDX 1.5,", "  next scan's baseline)", "report.md"], tag=False)
    arrow("M250 239 L286 239")
    arrow("M650 239 L686 239")
    arrow("M1110 239 L1146 239")
    # ---- band 2: brain
    band(384, 286, "DAY 2 · BRAIN", "python -m guardian analyze <repo>  →  5 agents + neurosymbolic verifier")
    box(50, 424, 290, 230, "engine", "3 · SYMBOLIC PRIOR", ["reachability: imported?", "  (file:line)", "EPSS + CISA KEV", "explainable base score", "CVSS · dev-only · direct", "!→ P1–P4 prior"], tag=False)
    box(370, 424, 540, 230, "agent", "FIVE AGENTS · shared case file", ["!1 Orchestrator & Triage (lead): routes cases, final priority", "!2 Vulnerability Analyst: is the CVE exploitable in this app?", "!3 Supply-Chain Forensics: fakes · scripts · tampering · CI", "!4 Remediation Planner: safest fix (in PLAN and VALIDATE)", "!5 Critic: independent second opinion → review queue", "read-only tools · ≤5 steps each · Claude → Gemini → Groq → rules"])
    box(940, 424, 270, 230, "engine", "NEUROSYMBOLIC VERIFIER", ["facts: graph · OSV ·", "registry · deps.dev", "rules: allow-list · semver", "· version exists · ±20", "!no cited evidence → reject", "!conf < 0.6 → human review"], tag=False)
    box(1240, 424, 210, 230, "data", "analysis.json", ["final priorities", "agent case files", "verifier notes", "human review queue", "guardian.html", "(agents tab)"], tag=False)
    arrow("M1300 344 L1300 372 L195 372 L195 420", "findings.json", 640, 366)
    arrow("M340 539 L366 539")
    arrow("M910 520 L936 520")
    arrow("M940 556 L914 556")
    arrow("M640 424 L640 415 L1345 415 L1345 420", "verified verdicts", 980, 399)
    # ---- band 3: shield
    band(696, 266, "DAY 2 · SHIELD", "plan → approve → apply → validate → report   (nothing changes without a human yes)")
    box(50, 736, 240, 212, "engine", "4 · PLAN", ["rule proposal →", "Planner agent →", "verifier → Critic", "9 allow-listed actions", "fix's own tree checked", "!plan = SHA-256 hash"])
    box(320, 736, 230, 212, "human", "5 · APPROVE", ["review queue (optional)", "approval bound to", "the plan hash", "plan edited → void", "!no yes → no change"])
    box(580, 736, 260, 212, "engine", "6 · APPLY (sandbox)", ["copy + git branch", "edit package.json /", "FROM / uses: lines", "lockfiles --ignore-scripts", "kill switch: STOP file", "!→ remediation.patch"])
    box(870, 736, 280, 212, "engine", "7 · VALIDATE", ["lockfile resolve", "(+ npm ci / tests)", "rescan, before vs after", "Planner agent: next fix", "!verified · partial · failed"])
    box(1180, 736, 270, 212, "data", "REPORT + POLICY", ["!guardian_report.html", "evidence → agents →", "approval → result →", "remaining risk", "policy.json gate", "(exit 1 blocks CI)"], tag=False)
    arrow("M1345 654 L1345 684 L245 684 L245 732", "analysis.json", 640, 678)
    arrow("M290 842 L316 842")
    arrow("M550 842 L576 842")
    arrow("M840 842 L866 842")
    arrow("M1150 842 L1176 842")
    # ---- audit strip
    out.append('<rect x="30" y="980" width="1440" height="52" rx="12" fill="#f4f5f7" stroke="#5b6876" stroke-dasharray="6 4" stroke-width="2"/>')
    out.append('<text x="50" y="1012" class="l"><tspan class="b">audit.jsonl</tspan> — append-only trail: every stage, every agent call (provider, model, outcome — never keys), review decisions, the approval, every change</text>')
    # ---- external column
    s, f, _ = STYLE["ext"]
    out.append(f'<rect x="1500" y="96" width="270" height="936" rx="16" fill="#f7fbf8" stroke="{s}" stroke-width="2"/>')
    out.append(f'<text x="1518" y="124" class="t" fill="{s}">Public data (read-only)</text>')
    out.append('<text x="1518" y="146" class="lg">cached in .cache/ → offline demo</text>')
    ext = [("OSV.dev", "CVEs for every ecosystem"), ("deps.dev", "resolve transitive deps"),
           ("npm registry", "metadata · downloads · versions"), ("PyPI JSON", "published versions"),
           ("FIRST EPSS", "exploit probability"), ("CISA KEV", "exploited in the wild"),
           ("OCI registries", "image → sha256 digest"), ("GitHub API", "action tag → commit SHA"),
           ("Maven Central", "parent POMs · BOMs")]
    for i, (t, d) in enumerate(ext):
        y = 162 + i * 96
        out.append(f'<rect x="1516" y="{y}" width="238" height="80" rx="10" fill="{f}" stroke="{s}" stroke-width="1.5"/>')
        out.append(f'<text x="1530" y="{y + 32}" class="t2" fill="{s}">{escape(t)}</text>')
        out.append(f'<text x="1530" y="{y + 57}" class="l">{escape(d)}</text>')
    arrow("M1500 230 L1474 230", dashed=True, color=s)
    arrow("M1500 540 L1474 540", dashed=True, color=s)
    arrow("M1500 842 L1474 842", dashed=True, color=s)
    body = "\n".join(out)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" font-family="Segoe UI, Roboto, Helvetica, Arial, sans-serif">
<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="#3d4a5c"/></marker>
<style>.h{{font-size:30px;font-weight:700;fill:#16202c}}.t{{font-size:18px;font-weight:700}}.t2{{font-size:17px;font-weight:700}}
.tag{{font-size:12px;font-weight:600;letter-spacing:.3px}}.l{{font-size:14.5px;fill:#25303d}}.b{{font-weight:700}}
.bt{{font-size:15px;font-weight:800;fill:#5b6876;letter-spacing:1px}}.bs{{font-size:13.5px;fill:#5b6876}}.lg{{font-size:14px;fill:#3d4a5c}}
.al{{font-size:13px;fill:#3d4a5c;font-style:italic}}</style></defs>
<rect width="{W}" height="{H}" fill="#ffffff"/>
{body}
</svg>'''


def browser() -> str | None:
    for p in (r"C:\Program Files\Google\Chrome\Application\chrome.exe",
              r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
              shutil.which("chrome") or "", shutil.which("msedge") or "", shutil.which("chromium") or ""):
        if p and Path(p).exists():
            return p
    return None


def main() -> None:
    docs = ROOT / "docs"
    docs.mkdir(exist_ok=True)
    svg = build()
    (docs / "architecture.svg").write_text(svg, encoding="utf-8")
    page = docs / "_architecture_render.html"
    page.write_text(f"<!doctype html><html><body style='margin:0'>{svg}</body></html>", encoding="utf-8")
    b = browser()
    if not b:
        print("SVG written; no Chrome/Edge found for PNG")
        return
    png = docs / "architecture.png"
    subprocess.run([b, "--headless=new", "--disable-gpu", "--hide-scrollbars", f"--window-size={W},{H}",
                    "--force-device-scale-factor=2", f"--screenshot={png}", page.as_uri()],
                   check=True, capture_output=True, timeout=60)
    page.unlink()
    print(f"wrote {docs / 'architecture.svg'} and {png}")


if __name__ == "__main__":
    main()
