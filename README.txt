SOFTWARE SUPPLY CHAIN GUARDIAN
Know what you build. Trust what you ship.

An agentic, neurosymbolic tool that analyses the software supply chain of any repository:
discover every component -> detect vulnerabilities and suspicious changes with evidence -> prioritise by technical
and business impact with six AI agents (every claim checked by a symbolic verifier) -> plan allow-listed fixes ->
human approval -> apply in a sandbox -> validate by rescanning -> report.

Architecture diagram: docs/architecture.png


SETUP (Windows, PowerShell)
---------------------------
  git clone https://github.com/Vishnu868/BGSW.git
  cd BGSW
  python scripts\setup.py            portable Node.js + demo repositories (checksum-verified)
  pip install -r requirements.txt    only needed for the Claude provider
  copy .env.example .env             then add an AI key (Gemini / Groq / Claude) - optional
  python -m unittest discover -s tests
Trivy and Grype are optional: put them in tools\trivy and tools\grype (or on PATH). Without them the scan
runs on OSV alone.


COMMANDS
--------
Day 1 - Eyes
  python -m guardian scan <folder | git URL> [--offline] [--scanners auto|full|osv|osv,trivy,grype] [--images]
  python -m http.server 8765 --directory runs      then open http://localhost:8765/<repo>/guardian.html
Day 2 - Brain
  python -m guardian analyze <repo> [--top 6]      business context + six agents + verifier
  python -m guardian business <repo>               confirm / reject business facts (human)
  python -m guardian review <repo>                 human review queue
Day 2 - Shield
  python -m guardian plan <repo>
  python -m guardian approve <repo> [--web]
  python -m guardian apply <repo> [--dry-run]
  python -m guardian validate <repo> [--install] [--test-cmd "npm test"]   (+ graph_diff.html)
  python -m guardian diff <repo>                   dependency graph before vs after the fixes
  python -m guardian report <repo>
  python -m guardian policy <repo>
Other
  python -m guardian run <folder | git URL>        the whole loop (approval still interactive)
  python -m guardian llm-check                     test the configured AI providers
  python scripts\simulate_pr.py targets\juice-shop local copy with a simulated malicious change
  python scripts\backup_runs.py                    freeze all demo results into a zip


PIPELINE
--------
1 Discover   guardian/discover/      readers for npm, Python, Maven (+parent/BOM), Go, Ruby, PHP, C#/.NET, CycloneDX;
                                     deps.dev for lockfile-less trees -> dependency graph
2 Detect     guardian/detect/        osv.py (OSV.dev, CVSS) + scanners.py (dynamic Trivy/Grype plan, consensus)
                                     packages.py (typosquat, install scripts), lockfile.py (tampering, diff),
                                     container.py (images), cicd.py (GitHub Actions)
3 Analyze    guardian/analyze/       reachability, EPSS + CISA KEV, business context (SSVC), base score
             guardian/agents/        six agents on a shared case file
             guardian/neurosymbolic/ facts + rules + verifier for every agent answer
4 Plan       guardian/remediate/planner.py    allow-listed actions, plan hash
5 Approve    guardian/remediate/approval.py   human approval bound to the plan hash
6 Apply      guardian/remediate/apply.py      sandbox git branch, kill switch, remediation.patch
7 Validate   guardian/validate/               rescan, before/after, next iteration
             guardian/report/diff.py          graph_diff.html: dependency graph before vs after, coloured
  Report     guardian/report/final.py, guardian/policy.py

The six agents
  1 Orchestrator & Triage (lead)  routes cases; final priority (max +/-20 vs the symbolic score, with a reason)
  2 Vulnerability Analyst         is the CVE exploitable in this application?
  3 Supply-Chain Forensics        typosquats, install scripts, tampering, containers, CI/CD
  4 Remediation Planner           safest allow-listed fix; next iteration after validation
  5 Critic / Reviewer             independent second opinion; disagreement -> human review
  6 Business Context              internet-facing? sensitive data? (every fact cites file:line)


DYNAMIC SCANNER SELECTION (--scanners auto, the default)
--------------------------------------------------------
Discover runs first, then OSV (one batched query per package). What they found decides what Trivy/Grype do,
and the console prints the plan with a reason for every step:
  confirm   large repository: Trivy + Grype check only the components OSV flagged, from our SBOM
            (exact resolved versions; seconds regardless of repository size)
  gap       folders with lockfiles outside OSV and our readers (Cargo.lock, conan.lock, pubspec.lock, mix.lock,
            Package.resolved, Podfile.lock, gradle.lockfile): Trivy + Grype scan only those folders
  full      small repository (< 200 components): full cross-check, it costs seconds
  skipped   whole-repository scans when every manifest is covered (printed with the reason)
--scanners full  = all tools on the whole repository (complete second opinion, slower)
--scanners osv   = OSV only.   --scanners osv,trivy = chosen tools on the whole repository.
Measured: Juice Shop 14 s -> 10 s, confirmed by all three 52 -> 56 of 57; WebGoat 24 s -> 7 s, 36 -> 134 of 134
(scanning our exact resolved versions works better than letting each scanner re-resolve the project).

LANGUAGE AND SCANNER COVERAGE
-----------------------------
Language          Files read by our Discover           OSV   Trivy  Grype  Status
JavaScript (npm)  package-lock.json / package.json     yes   yes    yes    full graph
Java (Maven)      pom.xml (+ parent/BOM, deps.dev)     yes   yes    yes    full graph
Python            requirements.txt (+ deps.dev)        yes   yes    yes    graph
Ruby              Gemfile.lock                         yes   yes    yes    full graph
Go                go.mod                               yes   yes    yes    basic (no exact edges)
PHP               composer.lock                        yes   yes    yes    basic
C# / .NET         packages.lock.json / .csproj         yes   lock   lock   basic (.csproj: OSV only)
Python Poetry/Pipenv  poetry.lock / Pipfile.lock       yes   yes    yes    basic (unit-tested only)
C / C++ (Conan)   - (found by Trivy/Grype)             -     yes    yes    scanners only, no edges
Rust              - (found by Trivy/Grype)             -     yes    yes    scanners only, no edges
Container OS pkgs --images (Trivy)                     -     yes    -      optional
"Confirmed by N of M" counts only scanners that support the ecosystem and actually ran.


TESTED ON (same code)
---------------------
OWASP Juice Shop (npm, 1,656 components), NodeGoat (npm), crAPI (npm + Go + Python), WebGoat (Maven),
RailsGoat (Ruby), Spring PetClinic Microservices (Maven, 9 modules), nodejs-goof, pygoat,
fixtures/supply-chain-lab (planted risks in all 7 categories), fixtures/polyglot-lab (C#, C/C++, Rust).


SAFETY, PRIVACY, RESPONSIBLE AI
-------------------------------
- Target code and install scripts are never executed (npm --package-lock-only --ignore-scripts).
- Network calls are read-only public data: OSV.dev, deps.dev, npm registry, PyPI, Maven Central, FIRST EPSS,
  CISA KEV, OCI registries (digests), GitHub API (action SHAs), Trivy/Grype databases, and the chosen AI provider.
- Sent to the AI: finding titles, package names/versions, dependency paths, advisory text, and short file excerpts
  (single lines up to 200 characters returned by read-only tools). Never whole source files, never keys.
- Keys only in .env (git-ignored); never printed or logged. The audit trail records provider/model/purpose only.
- Every agent answer passes the symbolic verifier; AI text is labelled inference, separate from verified evidence.
- Nothing changes without human approval bound to the plan hash; fixes only in a sandbox branch; kill switch:
  create runs/<repo>/STOP. Nothing is pushed, merged or published by the tool.


LIMITATIONS
-----------
- Reachability is import-level, not call-graph level.
- Python/Maven transitive versions come from deps.dev (what a fresh install would get), not a lockfile.
- Go, PHP, C#, Poetry, Pipenv readers are basic; C/C++ and Rust rely on Trivy/Grype.
- Validation = lockfile resolution + rescan + SBOM diff; container images are re-checked by Dockerfile rules
  (and Trivy with --images), not rebuilt.
