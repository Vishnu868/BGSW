"""Day 2 regression tests (offline): the five agents with scripted models, the symbolic verifier, scoring, safety gates."""
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guardian.agents import orchestrator, roles  # noqa: E402
from guardian.agents.tools import Toolbox  # noqa: E402
from guardian.analyze import prioritize  # noqa: E402
from guardian.llm import extract_json  # noqa: E402
from guardian.neurosymbolic import rules, verifier  # noqa: E402
from guardian.remediate import apply, planner  # noqa: E402

COMP = {"name": "lodash", "version": "2.4.2", "ecosystem": "npm", "kind": "library", "direct": False, "dev_only": False,
        "dependency_path": ["app", "sanitize-html@1.4.2", "lodash@2.4.2"], "introduced_by": ["sanitize-html"]}
ITEM = {"id": "R-001", "key": "npm:lodash@2.4.2", "headline": "CVE-2019-10744: lodash@2.4.2 - Prototype Pollution",
        "severity": "critical", "category": "1.2", "score": 91, "priority": "P1", "base_score": 91, "base_priority": "P1",
        "confidence": "high", "factors": [{"reason": "base: CVSS 9.1", "points": 91}], "fixed": "4.17.12",
        "max_fixed": "4.17.12", "finding_ids": ["F-001"], "rule": "osv", "recommendation": "Upgrade lodash",
        "reachability": {"status": "via-used-parent", "evidence": ["sanitize-html"], "detail": "via sanitize-html"},
        "component": COMP}
TYPO = dict(ITEM, id="R-002", key="npm:ngy-cookie@6.0.1000", category="1.3", rule="packages.repo-name-mismatch",
            headline="Typosquat / starjacking: ngy-cookie", base_score=70, score=70, base_priority="P2", priority="P2",
            max_fixed="", finding_ids=["F-002"], component=dict(COMP, name="ngy-cookie", version="6.0.1000", direct=True))
DOC = {"repository": {"path": "."}, "changes": {}, "findings": [
    {"id": "F-001", "title": ITEM["headline"], "rule": "osv", "category": "1.2", "severity": "critical",
     "component": ITEM["key"], "evidence": [{"source": "osv", "detail": "Prototype Pollution"}],
     "data": {"vuln_id": "GHSA-jf85-cpcp-j695", "cve": "CVE-2019-10744", "cvss": 9.1, "fixed": "4.17.12"},
     "recommendation": "Upgrade lodash"},
    {"id": "F-002", "title": TYPO["headline"], "rule": "packages.repo-name-mismatch", "category": "1.3", "severity": "high",
     "component": TYPO["key"], "evidence": [{"source": "npm registry", "detail": "claims salemdar/ngx-cookie"}], "data": {}}]}


class FakeFacts:
    findings = {f["id"]: f for f in DOC["findings"]}
    intel = {"kev": set(), "epss": {}}

    def versions(self, name, eco="npm"):
        return ["4.17.12", "4.17.21"] if name == "lodash" else ["1.0.0"]

    def file_line_exists(self, ref):
        return False

    def code_usage(self, package, eco="npm"):
        return {"package": package, "imports": [], "count": 0}


class FakeRouter:
    """Scripted model: replies chosen by the agent name in the purpose string (thread-safe for parallel agents)."""
    enabled = True

    def __init__(self, script):
        self.script, self.lock, self.calls = {k: list(v) for k, v in script.items()}, threading.Lock(), []

    def ask_json(self, system, user, purpose):
        with self.lock:
            self.calls.append(purpose)
            for key, replies in self.script.items():
                if purpose.startswith(key) and replies:
                    return replies.pop(0), {"provider": "fake", "model": "scripted", "errors": []}
        return None, {"provider": "rule-based", "errors": ["no scripted reply"]}


class Off:
    enabled = False


class AgentEngineTests(unittest.TestCase):
    def test_specialist_loop_and_verifier_blocks_hallucinated_version(self):
        router = FakeRouter({"vulnerability_analyst": [
            {"tool": "dependency_paths", "args": {}, "why": "see how it enters"},
            {"final": {"verdict": "confirmed_risk", "exploitable_in_context": "yes", "risk_summary": "reachable",
                       "recommended_action": "upgrade", "target_version": "99.0.0", "confidence": 0.9,
                       "evidence_refs": ["E1", "E2", "E9"], "reasoning": "path shows use"}}]})
        res = orchestrator._specialist(roles.VULN_ANALYST, dict(ITEM), FakeFacts(), router)
        out = res["output"]
        self.assertEqual(res["steps"][0]["tool"], "dependency_paths")
        self.assertEqual(out["evidence_refs"], ["E1", "E2"])                 # E9 never existed
        self.assertIsNone(out["target_version"])                             # 99.0.0 not published
        self.assertTrue(any("hallucination" in n for n in res["verifier_notes"]))
        self.assertEqual(out["verdict"], "needs_human_review")              # confidence capped -> escalate
        self.assertEqual(out["source"], "ai")

    def test_agent_cannot_use_tools_outside_its_role(self):
        router = FakeRouter({"vulnerability_analyst": [
            {"tool": "registry_info", "args": {}, "why": "not my tool"},
            {"final": {"verdict": "confirmed_risk", "recommended_action": "upgrade", "confidence": 0.8, "evidence_refs": ["E1"]}}]})
        res = orchestrator._specialist(roles.VULN_ANALYST, dict(ITEM), FakeFacts(), router)
        self.assertEqual(res["steps"][0]["tool"], "registry_info")
        self.assertEqual(res["output"]["verdict"], "confirmed_risk")

    def test_rules_fallback_without_llm(self):
        res = orchestrator._specialist(roles.VULN_ANALYST, dict(ITEM), FakeFacts(), Off())
        self.assertEqual(res["output"]["source"], "rules")
        self.assertEqual(res["status"], "fallback")

    def test_toolbox_unknown_tool(self):
        self.assertIn("error", Toolbox(FakeFacts(), ITEM).run("delete_repo", {}))

    def test_extract_json_from_prose(self):
        self.assertEqual(extract_json('Sure! ```json\n{"a": {"b": 1}}\n``` done'), {"a": {"b": 1}})


class VerifierTests(unittest.TestCase):
    def test_routing_adds_required_specialist_and_critic_on_p1(self):
        cases = [dict(ITEM), dict(TYPO)]
        out, notes, st = verifier.routing({"routes": {"R-001": ["supply_chain_forensics"], "R-002": []}, "critic": []}, cases)
        self.assertIn("vulnerability_analyst", out["routes"]["R-001"])
        self.assertIn("supply_chain_forensics", out["routes"]["R-002"])
        self.assertIn("R-001", out["critic"])
        self.assertEqual(st, "corrected")

    def test_triage_bounds_and_reasons(self):
        out, notes, st = verifier.triage({"decisions": [{"id": "R-001", "final_score": 20, "reason": "not used"},
                                                        {"id": "R-002", "final_score": 95}]}, [dict(ITEM), dict(TYPO)])
        self.assertEqual(out["decisions"]["R-001"]["final_score"], 71.0)    # 91 - 20 max
        self.assertEqual(out["decisions"]["R-001"]["priority"], "P2")       # band recomputed, not trusted
        self.assertEqual(out["decisions"]["R-002"]["final_score"], 70.0)    # change without reason reverted

    def test_plan_proposal_rules(self):
        bad, notes, st = verifier.plan_proposal({"action_type": "run_shell", "params": {}}, {}, ITEM, FakeFacts(), set())
        self.assertEqual(st, "rejected")
        fake, notes, st = verifier.plan_proposal({"action_type": "npm_override_transitive",
                                                  "params": {"package": "lodash", "to": "5.0.0"}}, {}, ITEM, FakeFacts(), set())
        self.assertEqual(st, "rejected")
        ok, notes, st = verifier.plan_proposal({"action_type": "npm_override_transitive", "params": {"package": "lodash", "to": "4.17.21"},
                                                "evidence_refs": ["E1"], "confidence": 0.8}, {"E1": {}}, ITEM, FakeFacts(), set())
        self.assertEqual(st, "accepted")

    def test_critic_unknown_ids_dropped(self):
        out, notes, st = verifier.critic({"reviews": [{"id": "A-01", "agree": False, "concern": "x"}, {"id": "Z-9"}]}, {}, {"A-01"})
        self.assertEqual([r["id"] for r in out["reviews"]], ["A-01"])

    def test_semver_rules(self):
        self.assertEqual(rules.compatibility("0.2.24", "0.3.31")["level"], "major")
        self.assertEqual(rules.compatibility("4.17.4", "4.18.1")["level"], "minor")


class OrchestratorTests(unittest.TestCase):
    def test_agent_flow_with_critic_disagreement(self):
        router = FakeRouter({
            "lead_router": [{"final": {"routes": {"R-001": ["vulnerability_analyst"], "R-002": ["supply_chain_forensics"]},
                                       "critic": ["R-001"]}}],
            "vulnerability_analyst": [{"final": {"verdict": "confirmed_risk", "exploitable_in_context": "yes",
                                                 "recommended_action": "upgrade", "confidence": 0.8, "evidence_refs": ["E1"]}}],
            "supply_chain_forensics": [{"final": {"verdict": "confirmed_risk", "exploitable_in_context": "yes",
                                                  "recommended_action": "replace", "confidence": 0.85, "evidence_refs": ["E1"]}}],
            "lead_triage": [{"final": {"decisions": [{"id": "R-002", "final_score": 85, "reason": "typosquat confirmed"}],
                                       "summary": "two serious risks"}}],
            "critic": [{"final": {"reviews": [{"id": "R-001", "agree": False, "concern": "lodash is only used in tests"}],
                                  "evidence_refs": ["E1"]}},
                       {"final": {"reviews": [{"id": "R-002", "agree": True}], "evidence_refs": ["E1"]}}]})
        items = [dict(ITEM), dict(TYPO)]
        res = orchestrator.run(items, FakeFacts(), router, top=2, workers=2, log=lambda *_: None)
        self.assertEqual(len(res["agents"]), 7)
        self.assertIn("Neurosymbolic Prioritizer", [a["name"] for a in res["agents"]])
        self.assertEqual(items[1]["priority"], "P1")                        # 70 -> 85 by the lead, with reason
        self.assertEqual([q["id"] for q in res["review_queue"]], ["R-001"])  # critic disagreed -> human review
        agents_used = {e["agent"] for c in res["cases"].values() for e in c["entries"]}
        self.assertEqual(agents_used, {"lead_router", "vulnerability_analyst", "supply_chain_forensics", "lead_triage", "critic"})


class ScoringTests(unittest.TestCase):
    def _score(self, dev=False, status="imported"):
        d = json.loads(json.dumps(DOC))
        d["findings"] = d["findings"][:1]
        d["findings"][0]["component_detail"] = dict(COMP, dev_only=dev)
        return prioritize.build_items(d, {ITEM["key"]: {"status": status, "evidence": [], "detail": ""}}, set(), {})[0]

    def test_context_changes_priority(self):
        prod, dev = self._score(), self._score(dev=True, status="via-unused-parent")
        self.assertGreater(prod["score"], dev["score"])
        self.assertEqual(prod["base_priority"], "P1")
        self.assertIn(dev["priority"], ("P3", "P4"))


class SafetyGateTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.plan = {"plan_hash": "", "actions": [{"id": "A-01", "type": "npm_upgrade_direct", "params": {"package": "x"}}]}
        self.plan["plan_hash"] = planner.plan_hash(self.plan["actions"])

    def _approve(self):
        (self.d / "approval.json").write_text(json.dumps({"plan_hash": self.plan["plan_hash"], "approved_actions": ["A-01"],
                                                          "operator": "t"}))

    def test_no_approval_refused(self):
        with self.assertRaises(apply.Refused):
            apply.preflight(self.d, self.plan)

    def test_plan_changed_after_approval_refused(self):
        self._approve()
        self.plan["actions"][0]["params"]["package"] = "evil"
        with self.assertRaises(apply.Refused):
            apply.preflight(self.d, self.plan)

    def test_kill_switch(self):
        self._approve()
        (self.d / "STOP").write_text("")
        with self.assertRaises(apply.Refused):
            apply.preflight(self.d, self.plan)

    def test_non_allowlisted_action_refused(self):
        self.plan["actions"][0]["type"] = "run_shell"
        self.plan["plan_hash"] = planner.plan_hash(self.plan["actions"])
        self._approve()
        with self.assertRaises(apply.Refused):
            apply.preflight(self.d, self.plan)

    def test_valid_approval_passes(self):
        self._approve()
        self.assertEqual(apply.preflight(self.d, self.plan)["approved_actions"], ["A-01"])


if __name__ == "__main__":
    unittest.main()


class ClosingAnswerTest(unittest.TestCase):
    """Weaker models keep calling tools or drop the {"final": ...} wrapper; the engine still gets an answer."""

    class Script:
        enabled = True

        def __init__(self, replies):
            self.replies, self.calls = list(replies), []

        def ask_json(self, system, user, purpose):
            self.calls.append(purpose)
            return self.replies.pop(0), {"provider": "fake", "model": "m", "errors": []}

    class Box:
        docs = {"item_details": ""}

        def run(self, name, args):
            return {"ok": True}

    def _agent(self):
        from guardian.agents.base import Agent
        return Agent(name="vulnerability_analyst", title="Analyst", mission="m", output_format="{}",
                     tools=["item_details"], max_steps=2)

    def test_closing_call_after_step_limit(self):
        tool = {"tool": "item_details", "args": {}, "why": "look"}
        r = self.Script([tool, tool, {"final": {"verdict": "confirmed_risk", "evidence_refs": ["E2"]}}])
        out = self._agent().run(r, {"id": "R-1"}, self.Box(), "R-1")
        self.assertEqual(out["output"]["verdict"], "confirmed_risk")
        self.assertTrue(r.calls[-1].endswith("(closing)"))
        self.assertEqual(out["error"], "")

    def test_unwrapped_verdict_accepted(self):
        r = self.Script([{"verdict": "false_positive", "evidence_refs": ["E1"]}])
        out = self._agent().run(r, {"id": "R-1"}, self.Box(), "R-1")
        self.assertEqual(out["output"], {"verdict": "false_positive", "evidence_refs": ["E1"]})


class ReplacementVersionTest(unittest.TestCase):
    """A typosquat verdict's target version belongs to the genuine package, not to the fake one."""

    class F:
        V = {"ngy-cookie": ["6.0.1000"], "ngx-cookie": ["6.0.0", "6.0.1"]}

        def versions(self, p, eco="npm"):
            return self.V.get(p)

        def file_line_exists(self, ref):
            return True

    def _run(self, tv, looked_up="ngx-cookie"):
        from guardian.neurosymbolic import verifier
        ev = {"E1": {"tool": "case"}, "E2": {"tool": "registry_versions", "args": {"package": looked_up}}}
        out = {"verdict": "confirmed_risk", "exploitable_in_context": "yes", "recommended_action": "replace",
               "target_version": tv, "confidence": 0.9, "evidence_refs": ["E1", "E2"], "reasoning": "typosquat"}
        item = {"component": {"name": "ngy-cookie", "ecosystem": "npm"}, "max_fixed": ""}
        return verifier.specialist(out, ev, item, self.F())

    def test_real_replacement_version_accepted(self):
        out, notes, status = self._run("6.0.1")
        self.assertEqual((out["target_version"], status, notes), ("6.0.1", "accepted", []))

    def test_invented_replacement_version_blocked(self):
        out, notes, status = self._run("9.9.9")
        self.assertIsNone(out["target_version"])
        self.assertIn("hallucination blocked", notes[0])


class GraphDiffTest(unittest.TestCase):
    """Before vs after graph: packages matched by name; fixed / upgraded / removed / added / replaced / remaining."""

    def test_statuses(self):
        from guardian.report import diff
        d = Path(tempfile.mkdtemp())

        def node(name, ver, kind="library"):
            return {"id": f"npm:{name}@{ver}", "name": name, "version": ver, "kind": kind, "eco": "npm",
                    "direct": name in ("jwt", "fake"), "dev": False, "path": ["app:p", f"npm:{name}@{ver}"]}

        def finding(name, ver, title, rule="osv"):
            return {"component": f"npm:{name}@{ver}", "severity": "high", "title": title, "category": "1.1", "rule": rule}

        app = {"id": "app:p", "name": "p", "version": "", "kind": "application", "path": ["app:p"]}
        before = {"meta": {"repo": "x"}, "roots": ["app:p"],
                  "nodes": [app, node("jwt", "0.4.0"), node("jws", "0.2.6"), node("ms", "1.0.0"), node("fake", "1.0.0"),
                            node("old", "1.0.0"), node("bad", "1.0.0")],
                  "edges": [["app:p", "npm:jwt@0.4.0"], ["npm:jwt@0.4.0", "npm:jws@0.2.6"], ["app:p", "npm:fake@1.0.0"]],
                  "findings": [finding("jwt", "0.4.0", "CVE-1: jwt"), finding("jws", "0.2.6", "CVE-2: jws"),
                               finding("fake", "1.0.0", "Typosquat"), finding("bad", "1.0.0", "CVE-3: bad")]}
        after = {"meta": {"repo": "x"}, "roots": ["app:p"],
                 "nodes": [app, node("jwt", "9.0.3"), node("ms", "2.0.0"), node("real", "1.0.0"), node("bad", "1.0.0"),
                           node("newdep", "1.0.0")],
                 "edges": [["app:p", "npm:jwt@9.0.3"], ["npm:jwt@9.0.3", "npm:newdep@1.0.0"], ["app:p", "npm:real@1.0.0"]],
                 "findings": [finding("bad", "1.0.0", "CVE-3: bad"),
                              finding("real", "1.0.0", "New direct dependency since baseline", rule="diff.added")]}
        (d / "after" / "x").mkdir(parents=True)
        (d / "graph_data.json").write_text(json.dumps(before), encoding="utf-8")
        (d / "after" / "x" / "graph_data.json").write_text(json.dumps(after), encoding="utf-8")
        (d / "plan.json").write_text(json.dumps({"actions": [
            {"id": "A-01", "type": "npm_upgrade_direct", "params": {"package": "jwt", "from": "0.4.0", "to": "9.0.3"}},
            {"id": "A-02", "type": "npm_replace", "params": {"package": "fake", "with": "real", "version": "1.0.0"}}]}),
            encoding="utf-8")
        st = {n["name"]: n["status"] for n in diff.build(d)["nodes"]}
        self.assertEqual(st["jwt"], "fixed")          # vulnerable before, clean after (A-01)
        self.assertEqual(st["jws"], "fixed")          # dropped together with the old jwt
        self.assertEqual(st["ms"], "upgraded")
        self.assertEqual(st["fake"], "replaced")      # typosquat -> genuine (A-02)
        self.assertEqual(st["real"], "added")         # the change note diff.added is not a new problem
        self.assertEqual(st["bad"], "remaining")
        self.assertEqual(st["old"], "removed")
        self.assertEqual(st["newdep"], "added")
        self.assertTrue(diff.write(d, log=lambda *_: None).exists())


class ControlPanelTest(unittest.TestCase):
    """The browser panel only runs allow-listed commands for repositories that exist."""

    def test_allow_list(self):
        from guardian import ui
        self.assertEqual(ui.command("tests", "", "", False)[-3:], ["discover", "-s", "tests"])
        self.assertIn("--offline", ui.command("analyze", "juice-shop", "", True) if (ui.RUNS / "juice-shop" / "findings.json").exists()
                      else ["--offline"])
        for bad in [("rm", "juice-shop", ""), ("analyze", "../x", ""), ("analyze", "a;del *", ""),
                    ("scan", "", "C:/Windows"), ("scan", "", "https://evil.example/x/y")]:
            with self.assertRaises(ValueError):
                ui.command(bad[0], bad[1], bad[2], False)
        self.assertEqual(ui.command("scan", "", "https://github.com/snyk-labs/nodejs-goof", False)[-1],
                         "https://github.com/snyk-labs/nodejs-goof")
        self.assertEqual(ui.INTERACTIVE, {"business", "review", "pr"})   # only these get an input pipe (pr asks y/N)
