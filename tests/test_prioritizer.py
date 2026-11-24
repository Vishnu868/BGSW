"""Neurosymbolic Prioritizer (agent 6) tests: rule file, the three rule families + supply chain + blast radius,
gates, confidence, explanations and the hand-off from agents 1-5 (offline, no LLM)."""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guardian.neurosymbolic import prioritizer as P  # noqa: E402

R = P.load_rules()
SHOP = {"project": "package.json", "internet_facing": True, "internet_source": "rules", "internet_evidence": "src/server.js:3",
        "data": {"payment": "rules", "credentials": "rules"}, "data_evidence": {"payment": "src/db.js:4", "credentials": "src/db.js:4"},
        "known": True}
INTERNAL = dict(SHOP, internet_facing=False, internet_source=None, internet_evidence=None, data={}, data_evidence={})
NO_AGENTS = {"lead_triage": None, "vulnerability_analyst": None, "supply_chain_forensics": None, "critic": None}
VEC = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "C": "H", "I": "H", "A": "H"}


def facts(**kw):
    x = {"headline": "CVE-2099-1: pkg@1.0.0", "category": "1.2", "severity": "critical", "cvss": 9.8, "vector": dict(VEC),
         "cves": ["CVE-2099-1"], "kev": False, "epss": 0.2, "rules": ["osv"], "malicious": False, "repo_level": False,
         "reachability": "imported", "dev_only": False, "direct": False, "introduced_by": 1, "findings": 1, "projects": 1,
         "scanners": 1, "allow_listed_script": False, "fix_available": True, "agents": copy.deepcopy(NO_AGENTS),
         "business": copy.deepcopy(SHOP), "human_review": None, "agent_score": 80, "agent_priority": "P1"}
    agents = kw.pop("agents", {})
    x.update(kw)
    x["agents"].update(agents)
    return x


def ai(verdict, exploitable="unknown", conf=0.8, source="ai"):
    return {"source": source, "status": "accepted", "verdict": verdict, "exploitable_in_context": exploitable, "confidence": conf}


class RuleFile(unittest.TestCase):
    def test_shipped_rules_valid(self):
        self.assertEqual(R["schema"], "guardian.neurosymbolic_rules/v1")

    def test_validator(self):
        bad = copy.deepcopy(R)
        bad["weights"]["threat"] = 0.9
        with self.assertRaisesRegex(ValueError, "sum to"):
            P.validate(bad)
        bad = copy.deepcopy(R)
        bad["gates"]["human_dismissed"]["max_score"] = 70          # 70 is inside P2, not P4
        with self.assertRaisesRegex(ValueError, "not inside band P4"):
            P.validate(bad)


class RuleFamilies(unittest.TestCase):
    """1 severity/exploitability/exposure, 2 production use, 3 business loss."""

    def test_1_threat_exploitation_and_exposure(self):
        kev = P.dim_threat(facts(kev=True), R)
        internal = P.dim_threat(facts(business=copy.deepcopy(INTERNAL)), R)
        self.assertEqual(kev["parts"]["exploitability"], 100)
        self.assertEqual(kev["parts"]["exposure"], 100)
        self.assertEqual(internal["parts"]["exposure"], 50)
        self.assertGreater(kev["score"], internal["score"])
        low = P.dim_threat(facts(epss=0.001), R)                     # EPSS says exploitation is unlikely
        self.assertEqual(low["parts"]["exploitability"], 15)

    def test_1_analyst_not_exploitable_caps_exploitability(self):
        d = P.dim_threat(facts(agents={"vulnerability_analyst": ai("likely_false_positive", "no")}), R)
        self.assertEqual(d["parts"]["exploitability"], 30)

    def test_2_production_use(self):
        self.assertEqual(P.dim_production(facts(), R)["score"], 100)
        self.assertEqual(P.dim_production(facts(dev_only=True), R)["score"], 10)
        self.assertEqual(P.dim_production(facts(reachability="via-unused-parent"), R)["score"], 20)
        lookalike = facts(category="1.3", rules=["packages.lookalike-name"], reachability="not-imported")
        self.assertEqual(P.dim_production(lookalike, R)["score"], 80)          # installed counts, import does not matter
        script = facts(rules=["packages.install-script"], dev_only=True)
        self.assertEqual(P.dim_production(script, R)["score"], 50)              # still runs on dev machines and CI

    def test_3_business_loss(self):
        breach = P.dim_business_loss(facts(), R)
        self.assertEqual((breach["score"], breach["loss_class"]), (100, "catastrophic"))
        outage = P.dim_business_loss(facts(vector={"AV": "N", "C": "N", "I": "N", "A": "H"}), R)
        self.assertEqual((outage["score"], outage["loss_class"]), (70, "significant"))
        nodata = P.dim_business_loss(facts(business=copy.deepcopy(INTERNAL)), R)
        self.assertLess(nodata["score"], 50)
        # no CVSS vector: the assumed loss is scaled by the finding's own severity
        low_cfg = P.dim_business_loss(facts(vector={}, cvss=None, severity="low", category="1.7"), R)
        self.assertLess(low_cfg["score"], 30)


class Decisions(unittest.TestCase):
    def test_kev_in_production_internet_facing_is_p1(self):
        r = P.assess(facts(kev=True, agent_priority="P2", agent_score=65), R)
        self.assertEqual(r["priority"], "P1")
        self.assertIn("raised to P1", r["why"])

    def test_confirmed_malicious_is_p1_block_even_if_dev_only(self):
        r = P.assess(facts(malicious=True, dev_only=True, reachability="via-unused-parent", rules=["osv"]), R)
        self.assertEqual((r["priority"], r["actions"]), ("P1", ["block"]))
        self.assertGreaterEqual(r["score"], 95)

    def test_rule_fallback_verdicts_are_not_counted_as_confirmation(self):
        typo = dict(category="1.3", rules=["packages.lookalike-name"], cvss=None, vector={}, severity="high", cves=[], epss=None)
        echoed = P.assess(facts(**typo, agents={"supply_chain_forensics": ai("confirmed_risk", source="rules")}), R)
        confirmed = P.assess(facts(**typo, agents={"supply_chain_forensics": ai("confirmed_risk", source="ai")}), R)
        self.assertEqual(echoed["priority"], "P2")                       # unconfirmed look-alike: P2 + human review
        self.assertTrue(echoed["needs_review"])
        self.assertEqual(confirmed["priority"], "P1")                    # model + verifier confirmed it -> compromise

    def test_dev_only_unreachable_is_capped(self):
        r = P.assess(facts(dev_only=True, reachability="not-imported", agent_priority="P2"), R)
        self.assertEqual(r["priority"], "P4")

    def test_human_dismissal_is_final(self):
        r = P.assess(facts(kev=True, human_review="dismissed"), R)
        self.assertEqual(r["priority"], "P4")
        self.assertEqual(r["confidence"], 0.99)

    def test_agents_agree_false_positive_caps_at_p3(self):
        r = P.assess(facts(agents={"vulnerability_analyst": ai("likely_false_positive", "no"),
                                   "critic": {"source": "ai", "agree": True}}), R)
        self.assertEqual(r["priority"], "P3")

    def test_confidence_follows_evidence_and_disagreement(self):
        base = P.assess(facts(), R)
        disputed = P.assess(facts(agents={"critic": {"source": "ai", "agree": False, "concern": "only used in tests"}}), R)
        unknown = P.assess(facts(business={"project": "x", "internet_facing": False, "internet_source": None,
                                           "internet_evidence": None, "data": {}, "data_evidence": {}, "known": False},
                                 reachability="unknown", vector={}, cvss=None, epss=None, cves=[]), R)
        self.assertGreater(base["confidence"], disputed["confidence"])
        self.assertIn("Critic disagrees: only used in tests", disputed["flags"])
        self.assertLess(unknown["confidence"], base["confidence"])
        self.assertEqual(base["confidence_label"], "high")

    def test_lead_move_counts_at_half_strength(self):
        plain = P.assess(facts(), R)
        led = P.assess(facts(agents={"lead_triage": {"source": "ai", "delta": -20.0, "reason": "dev only in practice"}}), R)
        self.assertAlmostEqual(plain["score"] - led["score"], 10.0, places=1)

    def test_explanation_cites_every_dimension(self):
        r = P.assess(facts(), R)
        text = "\n".join(r["explanation"])
        for k in ("Threat", "Production use", "Business loss", "Blast radius"):
            self.assertIn(k, text)
        self.assertIn("src/db.js:4", text)                               # loss reasoning points at the evidence line
        self.assertNotIn("Supply-chain integrity", text)                 # not applicable to a plain CVE


class HandOff(unittest.TestCase):
    """Agents 1-5 -> prioritizer -> items re-ranked and case files updated."""

    def test_run_reprioritises_and_writes_case_entry(self):
        doc = {"findings": [{"id": "F-1", "rule": "osv", "category": "1.2", "severity": "critical",
                             "data": {"cve": "CVE-2099-1", "cvss": 9.8, "vuln_id": "GHSA-x"}}]}
        item = {"id": "R-001", "key": "npm:pkg@1.0.0", "headline": "CVE-2099-1: pkg@1.0.0", "category": "1.2",
                "severity": "critical", "rule": "osv", "finding_ids": ["F-1"], "score": 70.0, "base_score": 70.0,
                "priority": "P2", "triage_reason": None, "max_fixed": "1.0.1",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "reachability": {"status": "imported"}, "business": {"project": "package.json"},
                "component": {"name": "pkg", "direct": True, "dev_only": False, "kind": "library"}}
        ctx = {"facts": [{"fact": "internet_facing", "value": True, "project": "package.json", "evidence": "a.js:1", "source": "rules"},
                         {"fact": "data_class", "value": "payment", "project": "package.json", "evidence": "a.js:2", "source": "agent"}],
               "human": {}}
        cases = {"R-001": {"entries": [{"agent": "vulnerability_analyst", "source": "ai", "status": "accepted",
                                        "output": ai("confirmed_risk", "yes", 0.9)},
                                       {"agent": "critic", "source": "ai", "status": "accepted",
                                        "output": {"agree": True, "concern": ""}}]}}
        out = P.run([item], doc, {"kev": {"CVE-2099-1"}, "epss": {}}, ctx, cases, policy={}, log=lambda *_: None)
        self.assertEqual((item["agent_priority"], item["priority"]), ("P2", "P1"))
        self.assertEqual(out["raised"], 1)
        n = item["neurosymbolic"]
        self.assertEqual(n["inputs"]["business"]["data"], {"payment": "agent"})
        self.assertEqual(cases["R-001"]["entries"][-1]["agent"], "neurosymbolic_prioritizer")
        self.assertEqual(cases["R-001"]["final"]["priority"], "P1")


if __name__ == "__main__":
    unittest.main()
