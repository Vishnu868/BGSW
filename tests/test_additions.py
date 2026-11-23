"""Tests for the scanner consensus, business context (SSVC), .NET reader, AI cache and per-agent models (offline)."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guardian import llm  # noqa: E402
from guardian.analyze import business  # noqa: E402
from guardian.detect import scanners  # noqa: E402
from guardian.discover import discover  # noqa: E402
from guardian.model import Component, Finding, Graph  # noqa: E402


def write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


class ScannerTests(unittest.TestCase):
    def test_parse_purl(self):
        self.assertEqual(scanners.parse_purl("pkg:npm/%40angular/core@17.0.1"), ("npm", "@angular/core", "17.0.1"))
        self.assertEqual(scanners.parse_purl("pkg:maven/org.yaml/snakeyaml@1.33"), ("Maven", "org.yaml:snakeyaml", "1.33"))
        self.assertEqual(scanners.parse_purl("pkg:conan/openssl@1.1.1k"), ("ConanCenter", "openssl", "1.1.1k"))

    def _graph(self):
        g = Graph()
        g.add(Component(id="repo:x", name="x", version="", ecosystem="", kind="repository"), dev=False)
        g.roots = ["repo:x"]
        g.add(Component(id="npm:jsonwebtoken@0.4.0", name="jsonwebtoken", version="0.4.0", ecosystem="npm", direct=True), dev=False)
        g.link("repo:x", "npm:jsonwebtoken@0.4.0")
        f = Finding("1.1", "critical", "CVE-2015-9235: jsonwebtoken@0.4.0 - Verification Bypass in jsonwebtoken",
                    component="npm:jsonwebtoken@0.4.0", rule="osv",
                    data={"vuln_id": "GHSA-c7hr-j4mj-j2w6", "aliases": ["CVE-2015-9235"], "fixed": "4.2.2"})
        return g, f

    def test_consensus_alias_title_match_and_new_ecosystem(self):
        g, f = self._graph()
        trivy = [
            {"scanner": "trivy", "id": "CVE-2015-9235", "aliases": [], "eco": "npm", "name": "jsonwebtoken", "version": "0.4.0",
             "purl": "", "severity": "critical", "fixed": "4.2.2", "file": "package-lock.json", "title": "Verification Bypass"},
            {"scanner": "trivy", "id": "NSWG-ECO-17", "aliases": [], "eco": "npm", "name": "jsonwebtoken", "version": "0.4.0",
             "purl": "", "severity": "high", "fixed": "4.2.2", "file": "package-lock.json", "title": "Verification Bypass in jsonwebtoken"},
            {"scanner": "trivy", "id": "CVE-2022-37434", "aliases": [], "eco": "ConanCenter", "name": "zlib", "version": "1.2.11",
             "purl": "", "severity": "critical", "fixed": "1.2.13", "file": "conan.lock", "title": "zlib overflow"}]
        grype = [{"scanner": "grype", "id": "GHSA-c7hr-j4mj-j2w6", "aliases": ["CVE-2015-9235"], "eco": "npm", "name": "jsonwebtoken",
                  "version": "0.4.0", "purl": "", "severity": "critical", "fixed": "4.2.2", "file": "", "title": ""}]
        with mock.patch.object(scanners, "run_trivy", return_value=(trivy, "ok (3 results)")), \
             mock.patch.object(scanners, "run_grype", return_value=(grype, "ok (1 results)")):
            new, status = scanners.scan(g, Path("."), [f], "repo:x", Path(tempfile.mkdtemp()), log=lambda *_: None)
        self.assertEqual(f.data["scanners"], ["grype", "osv", "trivy"])          # by id, by alias
        self.assertEqual(len([e for e in f.evidence if e["source"] == "Trivy"]), 1)  # NSWG duplicate merged, not new
        self.assertEqual(len(new), 1)                                           # only zlib is new
        self.assertIn("ConanCenter:zlib@1.2.11", g.nodes)                       # package we cannot read is still visible
        self.assertEqual(new[0].data["applicable_scanners"], ["grype", "trivy"])  # honest denominator: no OSV for Conan
        self.assertIn("confirmed by 3 of 3", f.evidence[-1]["detail"])


class BusinessTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        write(self.repo, "package.json", '{"name": "shop"}')
        write(self.repo, "server.js", "const app = express()\napp.listen(3000)\n")
        write(self.repo, "models/user.js", "module.exports = { email: String, password: String }\n")
        write(self.repo, "package-lock.json", '{"password-validator": "1.0.0"}')

    def test_rule_facts_cite_real_source_lines(self):
        ctx = business.rule_facts(self.repo, ["package.json"])
        kinds = {(f["fact"], str(f["value"])) for f in ctx["facts"]}
        self.assertIn(("internet_facing", "True"), kinds)
        self.assertIn(("data_class", "credentials"), kinds)
        self.assertTrue(all(not f["evidence"].startswith("package-lock") for f in ctx["facts"]))  # lockfiles are not evidence

    def test_agent_facts_verified(self):
        kept, notes = business.verify_agent_facts([
            {"fact": "data_class", "value": "credentials", "project": "package.json", "evidence": "models/user.js:1"},
            {"fact": "data_class", "value": "payment", "project": "package.json", "evidence": "models/user.js:1"},
            {"fact": "data_class", "value": "payment", "project": "package.json", "evidence": "nope.js:9"}], self.repo)
        self.assertEqual([f["value"] for f in kept], ["credentials"])            # the line does not mention payment
        self.assertEqual(len(notes), 2)

    def test_ssvc_decision(self):
        ctx = {"facts": [{"fact": "internet_facing", "value": True, "project": "package.json"},
                         {"fact": "data_class", "value": "credentials", "project": "package.json"},
                         {"fact": "data_class", "value": "payment", "project": "package.json"}]}
        item = {"component": {"dependency_path": ["shop", "shop (package.json)", "x@1"], "dev_only": False},
                "cve": "CVE-1", "reachability": {"status": "imported"}, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U"}
        rules = business.load_rules()
        self.assertEqual(business.decide(item, ctx, {"CVE-1"}, {}, rules)["decision"], "Act")       # exploited + open
        d = business.decide(item, ctx, set(), {}, rules)
        self.assertEqual((d["exposure"], d["human_impact"], d["decision"]), ("open", "very_high", "Attend"))
        dev = dict(item, component=dict(item["component"], dev_only=True))
        self.assertEqual(business.decide(dev, ctx, set(), {}, rules)["exposure"], "small")
        ctx["human"] = {"internet_facing:True:package.json": "rejected"}                         # human said no
        self.assertEqual(business.decide(item, ctx, set(), {}, rules)["exposure"], "controlled")


class DotnetTests(unittest.TestCase):
    def test_csproj_and_lockfile(self):
        repo = Path(tempfile.mkdtemp())
        write(repo, "a/App.csproj", '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>')
        write(repo, "b/packages.lock.json", json.dumps({"version": 1, "dependencies": {"net8.0": {
            "Serilog": {"type": "Direct", "resolved": "2.10.0", "dependencies": {"System.Memory": "4.5.0"}},
            "System.Memory": {"type": "Transitive", "resolved": "4.5.0"}}}}))
        write(repo, "b/B.csproj", '<Project><ItemGroup><PackageReference Include="Serilog" Version="2.10.0" /></ItemGroup></Project>')
        g = discover(repo).graph
        self.assertIn("NuGet:Newtonsoft.Json@12.0.1", g.nodes)
        self.assertIn(("NuGet:Serilog@2.10.0", "NuGet:System.Memory@4.5.0"), g.edges)
        self.assertFalse(g.nodes["NuGet:System.Memory@4.5.0"].direct)


class LlmTests(unittest.TestCase):
    def test_cache_and_per_agent_provider(self):
        class P:
            name, model, available, calls = "groq", "m1", True, 0

            def complete(self, system, user):
                P.calls += 1
                return '{"ok": true}'
        r = llm.Router.__new__(llm.Router)
        r.providers, r.audit, r.calls = [P()], None, []
        with tempfile.TemporaryDirectory() as d, mock.patch.object(llm, "CACHE", Path(d)):
            out1, m1 = r.ask_json("sys", "same question", "t")
            out2, m2 = r.ask_json("sys", "same question", "t")
        self.assertEqual(out1, out2)
        self.assertEqual(P.calls, 1)                    # second answer came from the cache
        self.assertTrue(m2.get("cached"))
        with mock.patch.dict(os.environ, {"CRITIC_PROVIDER": "", "CRITIC_MODEL": ""}):
            self.assertIs(r.for_agent("critic"), r)     # no override -> same router


if __name__ == "__main__":
    unittest.main()
