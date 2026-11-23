"""Day 2 regression tests (offline): AI loop with a scripted model, evidence checker, scoring, safety gates."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guardian.analyze import agent, prioritize  # noqa: E402
from guardian.llm import extract_json  # noqa: E402
from guardian.remediate import apply, planner  # noqa: E402

ITEM = {"id": "R-001", "key": "npm:lodash@2.4.2", "headline": "CVE-2019-10744: lodash@2.4.2 - Prototype Pollution",
        "severity": "critical", "category": "1.2", "score": 91, "priority": "P1", "confidence": "high",
        "factors": [{"reason": "base: CVSS 9.1", "points": 91}], "fixed": "4.17.12", "max_fixed": "4.17.12",
        "finding_ids": ["F-001"], "rule": "osv", "recommendation": "Upgrade lodash",
        "reachability": {"status": "via-used-parent", "evidence": ["sanitize-html"], "detail": "via sanitize-html"},
        "component": {"name": "lodash", "version": "2.4.2", "ecosystem": "npm", "kind": "library", "direct": False,
                      "dev_only": False, "dependency_path": ["app", "sanitize-html@1.4.2", "lodash@2.4.2"],
                      "introduced_by": ["sanitize-html"]}}
DOC = {"findings": [{"id": "F-001", "title": ITEM["headline"], "rule": "osv", "category": "1.2", "severity": "critical",
                     "component": "npm:lodash@2.4.2", "evidence": [{"source": "osv", "detail": "Prototype Pollution"}],
                     "data": {"vuln_id": "GHSA-jf85-cpcp-j695", "cve": "CVE-2019-10744", "cvss": 9.1, "fixed": "4.17.12"},
                     "recommendation": "", "component_detail": ITEM["component"]}], "changes": {}}


class FakeRouter:
    enabled = True

    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    def ask_json(self, system, user, purpose):
        self.calls.append(user)
        return self.replies.pop(0), {"provider": "fake", "model": "scripted", "errors": []}


class AgentTests(unittest.TestCase):
    def test_tool_loop_and_checker_blocks_hallucinated_version(self):
        router = FakeRouter([
            {"tool": "dependency_paths", "args": {}, "why": "see how it enters"},
            {"final": {"verdict": "confirmed_risk", "exploitable_in_context": "yes", "risk_summary": "reachable",
                       "recommended_action": "upgrade", "target_version": "99.0.0", "confidence": 0.9,
                       "evidence_refs": ["E1", "E2", "E9"], "reasoning": "path shows use"}}])
        with mock.patch.object(agent, "published_versions", return_value=["4.17.12", "4.17.21"]):
            out = agent.investigate(ITEM, DOC, {}, {"kev": set(), "epss": {}}, Path("."), router, offline=True)
        r = out["result"]
        self.assertEqual(out["steps"][0]["tool"], "dependency_paths")
        self.assertEqual(r["evidence_refs"], ["E1", "E2"])                 # E9 never existed -> removed
        self.assertIsNone(r["target_version"])                             # 99.0.0 not in registry -> blocked
        self.assertTrue(any("hallucination" in n for n in out["checker_notes"]))
        self.assertLessEqual(r["confidence"], 0.5)
        self.assertEqual(r["verdict"], "needs_human_review")              # low confidence -> escalate

    def test_uncited_answer_is_escalated(self):
        router = FakeRouter([{"final": {"verdict": "confirmed_risk", "recommended_action": "upgrade",
                                        "confidence": 0.95, "evidence_refs": []}}])
        out = agent.investigate(ITEM, DOC, {}, {"kev": set(), "epss": {}}, Path("."), router, offline=True)
        self.assertEqual(out["result"]["verdict"], "needs_human_review")
        self.assertLessEqual(out["result"]["confidence"], 0.3)

    def test_unknown_tool_is_refused(self):
        t = agent.Tools(ITEM, DOC, {}, {"kev": set(), "epss": {}}, Path("."), True)
        self.assertIn("error", t.run("delete_repo", {}))

    def test_rules_fallback_when_no_llm(self):
        class Off:
            enabled = False
        out = agent.investigate(ITEM, DOC, {}, {"kev": set(), "epss": {}}, Path("."), Off(), offline=True)
        self.assertEqual(out["result"]["source"], "rules")
        self.assertEqual(out["result"]["recommended_action"], "upgrade")

    def test_extract_json_from_prose(self):
        self.assertEqual(extract_json('Sure! ```json\n{"a": {"b": 1}}\n``` done'), {"a": {"b": 1}})
        self.assertEqual(extract_json('noise {"x": "}"} tail'), {"x": "}"})


class ScoringTests(unittest.TestCase):
    def _score(self, dev=False, status="imported", kev=False, epss=None):
        d = json.loads(json.dumps(DOC))
        d["findings"][0]["component_detail"]["dev_only"] = dev
        reach = {"npm:lodash@2.4.2": {"status": status, "evidence": [], "detail": ""}}
        return prioritize.build_items(d, reach, {"CVE-2019-10744"} if kev else set(),
                                      {"CVE-2019-10744": epss} if epss else {})[0]

    def test_context_changes_priority(self):
        prod = self._score()
        dev = self._score(dev=True, status="via-unused-parent")
        self.assertGreater(prod["score"], dev["score"])
        self.assertEqual(prod["priority"], "P1")
        self.assertIn(dev["priority"], ("P3", "P4"))
        self.assertGreater(self._score(kev=True, epss={"epss": 0.9, "percentile": 0.99})["score"], prod["score"] - 0.1)


class SafetyGateTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.plan = {"plan_hash": "", "actions": [{"id": "A-01", "type": "npm_upgrade_direct", "params": {"package": "x"}}]}
        self.plan["plan_hash"] = planner.plan_hash(self.plan["actions"])

    def test_no_approval_refused(self):
        with self.assertRaises(apply.Refused):
            apply.preflight(self.d, self.plan)

    def test_plan_changed_after_approval_refused(self):
        (self.d / "approval.json").write_text(json.dumps({"plan_hash": self.plan["plan_hash"], "approved_actions": ["A-01"]}))
        self.plan["actions"][0]["params"]["package"] = "evil"            # tampered after approval
        with self.assertRaises(apply.Refused):
            apply.preflight(self.d, self.plan)

    def test_kill_switch(self):
        (self.d / "approval.json").write_text(json.dumps({"plan_hash": self.plan["plan_hash"], "approved_actions": ["A-01"]}))
        (self.d / "STOP").write_text("")
        with self.assertRaises(apply.Refused):
            apply.preflight(self.d, self.plan)

    def test_non_allowlisted_action_refused(self):
        self.plan["actions"][0]["type"] = "run_shell"
        self.plan["plan_hash"] = planner.plan_hash(self.plan["actions"])
        (self.d / "approval.json").write_text(json.dumps({"plan_hash": self.plan["plan_hash"], "approved_actions": ["A-01"]}))
        with self.assertRaises(apply.Refused):
            apply.preflight(self.d, self.plan)

    def test_valid_approval_passes(self):
        (self.d / "approval.json").write_text(json.dumps({"plan_hash": self.plan["plan_hash"], "approved_actions": ["A-01"],
                                                          "operator": "t"}))
        self.assertEqual(apply.preflight(self.d, self.plan)["approved_actions"], ["A-01"])


if __name__ == "__main__":
    unittest.main()
