"""Offline regression tests: python -m unittest discover -s tests -v"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guardian.detect import cicd, container, lockfile, packages  # noqa: E402
from guardian.detect.osv import cvss3_score, fixed_version, severity_of  # noqa: E402
from guardian.discover import discover  # noqa: E402
from guardian.model import Component  # noqa: E402


def write(root: Path, rel: str, content) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
    return p


LOCK_V3 = {
    "name": "demo", "lockfileVersion": 3, "packages": {
        "": {"name": "demo", "dependencies": {"a": "^1.0.0"}, "devDependencies": {"t": "1.0.0"}},
        "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                           "integrity": "sha512-AAA=", "dependencies": {"b": "^2.0.0"}},
        "node_modules/b": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/b/-/b-2.0.0.tgz",
                           "integrity": "sha512-BBB="},
        "node_modules/a/node_modules/b": {"version": "1.5.0", "resolved": "https://evil.example.com/b-1.5.0.tgz",
                                          "integrity": "sha512-CCC=", "hasInstallScript": True},
        "node_modules/t": {"version": "1.0.0", "dev": True, "resolved": "https://registry.npmjs.org/t/-/t-1.0.0.tgz",
                           "integrity": "sha512-DDD="},
    }}


class DiscoverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_npm_v3_nested_resolution_and_scopes(self):
        write(self.tmp, "package.json", {"name": "demo", "dependencies": {"a": "^1.0.0"}, "devDependencies": {"t": "1.0.0"}})
        write(self.tmp, "package-lock.json", LOCK_V3)
        g = discover(self.tmp).graph
        self.assertIn(("npm:a@1.0.0", "npm:b@1.5.0"), g.edges)      # nested copy wins over hoisted
        self.assertTrue(g.nodes["npm:a@1.0.0"].direct)
        self.assertFalse(g.nodes["npm:b@1.5.0"].direct)
        self.assertTrue(g.nodes["npm:t@1.0.0"].dev)
        self.assertFalse(g.nodes["npm:a@1.0.0"].dev)
        self.assertTrue(g.nodes["npm:b@1.5.0"].install_script)
        path = g.shortest_paths()["npm:b@1.5.0"]
        self.assertEqual(path[-2:], ["npm:a@1.0.0", "npm:b@1.5.0"])
        self.assertEqual(g.introduced_by()["npm:b@1.5.0"], {"npm:a@1.0.0"})

    def test_npm_v1_lockfile(self):
        write(self.tmp, "package.json", {"name": "old", "dependencies": {"x": "1.0.0"}})
        write(self.tmp, "package-lock.json", {"lockfileVersion": 1, "dependencies": {
            "x": {"version": "1.0.0", "requires": {"y": "^1"}, "dependencies": {"y": {"version": "1.2.0"}}}}})
        g = discover(self.tmp).graph
        self.assertIn(("npm:x@1.0.0", "npm:y@1.2.0"), g.edges)

    def test_requirements_and_unpinned(self):
        write(self.tmp, "requirements.txt", "Django==3.2.0\nrequests>=2.0  # comment\n-r other.txt\n")
        inv = discover(self.tmp)
        self.assertIn("PyPI:django@3.2.0", inv.graph.nodes)
        self.assertFalse(inv.graph.nodes["PyPI:requests@2.0"].exact)
        self.assertEqual(inv.projects[0]["unpinned"][0]["name"], "requests")

    def test_pom_property_substitution(self):
        write(self.tmp, "pom.xml", """<project xmlns="http://maven.apache.org/POM/4.0.0"><artifactId>app</artifactId>
          <properties><log4j.version>2.14.1</log4j.version></properties><dependencies>
          <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId>
          <version>${log4j.version}</version></dependency></dependencies></project>""")
        g = discover(self.tmp).graph
        self.assertIn("Maven:org.apache.logging.log4j:log4j-core@2.14.1", g.nodes)


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_cvss_v3_formula(self):
        self.assertEqual(cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"), 5.4)

    def test_malicious_entry_is_critical(self):
        self.assertEqual(severity_of({"id": "MAL-2024-1"})[0], "critical")

    def test_fixed_version_picks_matching_range(self):
        v = {"affected": [{"package": {"name": "lodash"}, "ranges": [{"type": "SEMVER", "events": [
            {"introduced": "0"}, {"fixed": "4.17.12"}]}]}]}
        self.assertEqual(fixed_version(v, "lodash", "2.4.2"), "4.17.12")
        self.assertEqual(fixed_version(v, "lodash", "4.17.21"), "")

    def test_lookalike_rules(self):
        known = {"cross-env", "express", "@angular/core", "colors", "cors"}
        self.assertEqual(packages.lookalike("crossenv", known), "cross-env")
        self.assertEqual(packages.lookalike("expresss", known), "express")
        self.assertEqual(packages.lookalike("@angu1ar/core", known), "@angular/core")
        self.assertIsNone(packages.lookalike("@eslint/core", known))     # scoped vs unscoped 'cors'
        self.assertIsNone(packages.lookalike("express", known))

    def test_lockfile_untrusted_host_and_tamper_diff(self):
        write(self.tmp, "package.json", {"name": "demo", "dependencies": {"a": "^1.0.0"}, "devDependencies": {"t": "1.0.0"}})
        write(self.tmp, "package-lock.json", LOCK_V3)
        inv = discover(self.tmp)
        rules = {f.rule for f in lockfile.scan(inv.graph, inv)}
        self.assertIn("lockfile.untrusted-registry", rules)
        base = self.tmp / "base.cdx.json"
        from guardian.report.sbom import cyclonedx
        inv.graph.roots = list(inv.graph.roots)
        base.write_text(json.dumps(cyclonedx(inv.graph, [], {"repo": "demo"})))
        LOCK_V3["packages"]["node_modules/a"]["integrity"] = "sha512-ZZZ="
        write(self.tmp, "package-lock.json", LOCK_V3)
        LOCK_V3["packages"]["node_modules/a"]["integrity"] = "sha512-AAA="
        ch = lockfile.diff(base, discover(self.tmp).graph)
        self.assertEqual([t["name"] for t in ch["tampered"]], ["a"])
        self.assertEqual(lockfile.findings_from_changes(ch)[0].severity, "critical")

    def test_container_checks(self):
        write(self.tmp, "Dockerfile", "ARG V=18\nFROM node:${V} AS build\nRUN curl -s https://x.sh | bash\n"
                                      "FROM build\nFROM alpine\nCMD [\"x\"]\n")
        inv = discover(self.tmp)
        rules = [f.rule for f in container.scan(inv.graph, inv, "repo:x")]
        self.assertIn("container.curl-pipe-sh", rules)
        self.assertIn("container.root-user", rules)
        self.assertIn("container.eol", rules)                       # node 18 via ARG substitution
        sev = {f.title: f.severity for f in container.scan(inv.graph, inv, "repo:x") if f.rule == "container.unpinned"}
        self.assertEqual(sev["Container image 'alpine' uses a floating latest tag (no digest pin)"], "high")

    def test_cicd_checks(self):
        write(self.tmp, ".github/workflows/ci.yml", "on: pull_request_target\njobs:\n  b:\n    steps:\n"
              "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
              "      - uses: tj-actions/changed-files@v45\n"
              "      - uses: actions/setup-node@3d3c42e5aac5ba805825da76410c181273ba90b1\n"
              "      - run: |\n          echo \"${{ github.event.pull_request.title }}\"\n"
              "      - uses: some/action@v1\n        with:\n          branch: ${{ github.head_ref }}\n")
        inv = discover(self.tmp)
        fs = cicd.scan(inv.graph, inv, "repo:x")
        rules = [f.rule for f in fs]
        self.assertEqual(rules.count("cicd.unpinned-action"), 3)    # SHA-pinned setup-node is fine
        self.assertEqual(rules.count("cicd.script-injection"), 1)   # only the run: block, not with:
        self.assertIn("cicd.prt-checkout", rules)
        self.assertIn("cicd.default-permissions", rules)


if __name__ == "__main__":
    unittest.main()
