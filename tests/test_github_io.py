"""GitHub link in, pull request out, and the local Ollama provider (offline: GitHub is simulated with a local bare
repository, `gh` and the Ollama server are mocked)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guardian import llm, pipeline  # noqa: E402
from guardian.llm import providers  # noqa: E402
from guardian.remediate import publish  # noqa: E402
from guardian.remediate.planner import plan_hash  # noqa: E402

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main"]


def git(cwd, *args):
    return subprocess.run([*GIT, *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


class GitHubLinks(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(pipeline.parse_github("https://github.com/snyk-labs/nodejs-goof"), ("snyk-labs", "nodejs-goof"))
        self.assertEqual(pipeline.parse_github("https://github.com/a/b.git/"), ("a", "b"))
        self.assertEqual(pipeline.parse_github("git@github.com:a/b.git"), ("a", "b"))
        for bad in ("https://gitlab.com/a/b", "https://github.com/a", "https://github.com.evil.io/a/b", "/tmp/x"):
            self.assertIsNone(pipeline.parse_github(bad), bad)

    def test_source_info_of_a_clone(self):
        with tempfile.TemporaryDirectory() as t:
            git(t, "init", "-q")
            Path(t, "a.txt").write_text("x")
            git(t, "add", ".")
            git(t, "commit", "-qm", "c")
            git(t, "remote", "add", "origin", "https://github.com/acme/shop.git")
            s = pipeline.source_info(Path(t))
            self.assertEqual((s["type"], s["full_name"], s["branch"]), ("github", "acme/shop", "main"))
            self.assertEqual(len(s["commit"]), 40)
            git(t, "remote", "set-url", "origin", "https://gitlab.com/acme/shop.git")
            self.assertEqual(pipeline.source_info(Path(t))["type"], "folder")

    def test_run_needs_a_github_link(self):
        from guardian.__main__ import main
        with self.assertRaisesRegex(SystemExit, "needs a GitHub link"):
            main(["run", "fixtures/supply-chain-lab"])


class PullRequest(unittest.TestCase):
    """A scanned clone, an applied sandbox branch, an approval and a validation -> a branch + PR on 'GitHub'."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.remote = t / "github.git"                      # stands in for github.com/acme/shop
        git(t, "init", "-q", "--bare", str(self.remote))
        seed = t / "seed"
        seed.mkdir()
        git(seed, "init", "-q")
        (seed / "package.json").write_text('{"dependencies": {"lodash": "4.17.4"}}\n')
        git(seed, "add", ".")
        git(seed, "commit", "-qm", "app")
        git(seed, "push", "-q", str(self.remote), "main")
        self.clone = t / "targets" / "shop"                 # what `scan` cloned
        subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{self.remote}", str(self.clone)], check=True)
        commit = git(self.clone, "rev-parse", "HEAD")
        sb = t / "run" / "sandbox" / "shop"                 # what `apply` produced (no history, fresh main)
        sb.mkdir(parents=True)
        (sb / "package.json").write_text('{"dependencies": {"lodash": "4.17.4"}}\n')
        git(sb, "init", "-q")
        git(sb, "add", ".")
        git(sb, "commit", "-qm", "baseline")
        git(sb, "checkout", "-qb", "guardian/remediation-abcd1234")
        (sb / "package.json").write_text('{"dependencies": {"lodash": "4.17.21"}}\n')
        git(sb, "commit", "-qam", "fix")
        self.run_dir = t / "run"
        actions = [{"id": "A-01", "type": "npm_upgrade_direct", "params": {"package": "lodash", "from": "4.17.4", "to": "4.17.21"},
                    "risk": "CVE-2019-10744: lodash@4.17.4", "priority": "P1", "score": 90, "risk_item": "R-001",
                    "rationale": "upgrade to the fixed version", "compatibility": {"level": "patch", "reason": "patch"},
                    "finding_ids": ["F-1"]}]
        ph = plan_hash(actions)
        self.write("findings.json", {"repository": {"repo": "shop", "path": str(self.clone),
                                                    "source": {"type": "github", "full_name": "acme/shop", "owner": "acme",
                                                               "name": "shop", "url": "https://github.com/acme/shop",
                                                               "commit": commit, "branch": "main"}}, "findings": []})
        self.write("plan.json", {"plan_hash": ph, "actions": actions})
        self.write("approval.json", {"plan_hash": ph, "approved_actions": ["A-01"], "operator": "priths",
                                     "channel": "terminal", "time": "2026-11-24T10:00:00+00:00"})
        self.write("apply.json", {"plan_hash": ph, "sandbox": str(sb), "branch": "guardian/remediation-abcd1234",
                                  "results": [{"id": "A-01", "type": "npm_upgrade_direct", "status": "applied", "detail": "ok"}]})
        self.write("validation.json", {"verdict": "verified", "checks": {"resolve": {"ok": True}},
                                       "per_action": [{"id": "A-01", "resolved": 1, "status": "verified"}],
                                       "resolved": [{"id": "F-1"}], "new_findings": [],
                                       "before": {"findings": 3}, "after": {"findings": 2}})
        self.ident = mock.patch.object(publish, "_identity", return_value=("priths5", "Prithvi", "1+priths5@users.noreply.github.com"))
        self.ident.start()

    def tearDown(self):
        self.ident.stop()
        self.tmp.cleanup()

    def write(self, name, obj):
        (self.run_dir / name).write_text(json.dumps(obj))

    def test_refuses_without_valid_approval(self):
        self.write("approval.json", {"plan_hash": "other", "approved_actions": ["A-01"]})
        with self.assertRaisesRegex(publish.Refused, "no valid approval"):
            publish.run(self.run_dir, dry_run=True, log=lambda *_: None)

    def test_refuses_failed_validation_unless_forced(self):
        v = json.loads((self.run_dir / "validation.json").read_text())
        self.write("validation.json", dict(v, verdict="failed"))
        with self.assertRaisesRegex(publish.Refused, "validation FAILED"):
            publish.run(self.run_dir, dry_run=True, log=lambda *_: None)
        self.assertTrue(publish.run(self.run_dir, dry_run=True, force=True, log=lambda *_: None)["dry_run"])

    def test_refuses_a_folder_scan(self):
        d = json.loads((self.run_dir / "findings.json").read_text())
        d["repository"]["source"] = {"type": "folder"}
        self.write("findings.json", d)
        with self.assertRaisesRegex(publish.Refused, "GitHub"):
            publish.run(self.run_dir, dry_run=True, log=lambda *_: None)

    def test_dry_run_builds_branch_on_scanned_commit_and_pushes_nothing(self):
        before = git(self.clone, "status", "--porcelain")
        out = publish.run(self.run_dir, dry_run=True, log=lambda *_: None)
        wt = Path(out["worktree"])
        self.assertIn('"4.17.21"', (wt / "package.json").read_text())
        src_commit = json.loads((self.run_dir / "findings.json").read_text())["repository"]["source"]["commit"]
        self.assertEqual(git(wt, "rev-parse", "HEAD~1"), src_commit)            # parent = the scanned commit
        self.assertEqual(git(wt, "log", "-1", "--format=%ae"), "1+priths5@users.noreply.github.com")
        self.assertEqual(git(self.clone, "status", "--porcelain"), before)     # scanned clone untouched
        self.assertEqual(git(self.remote, "branch", "--list"), "* main")      # nothing pushed
        text = (self.run_dir / "pr_preview.md").read_text()
        self.assertIn("lodash", text)
        self.assertIn("Approved by **priths**", text)

    def test_declining_publishes_nothing(self):
        out = publish.run(self.run_dir, ask=lambda _: "n", log=lambda *_: None)
        self.assertFalse(out["published"])
        self.assertEqual(git(self.remote, "branch", "--list"), "* main")

    def test_publish_pushes_and_opens_pr(self):
        calls = []

        def fake_gh(*args, check=True):
            calls.append(args)
            if args[:2] == ("pr", "list"):
                return ""
            if args[:2] == ("pr", "create"):
                return "https://github.com/acme/shop/pull/7"
            return ""
        with mock.patch.object(publish, "push_target", return_value=(str(self.remote), "acme")), \
                mock.patch.object(publish, "_gh", side_effect=fake_gh):
            out = publish.run(self.run_dir, ask=lambda _: "y", log=lambda *_: None)
        self.assertEqual(out["url"], "https://github.com/acme/shop/pull/7")
        self.assertIn("guardian/remediation-abcd1234", git(self.remote, "branch", "--list"))
        create = next(c for c in calls if c[:2] == ("pr", "create"))
        self.assertIn("--base", create)
        self.assertEqual(create[create.index("--head") + 1], "guardian/remediation-abcd1234")
        self.assertNotIn("--draft", create)
        trail = (self.run_dir / "audit.jsonl").read_text()
        self.assertIn("pr_opened", trail)


class ControlPanel(unittest.TestCase):
    def test_pr_steps_are_allow_listed(self):
        from guardian import ui
        with tempfile.TemporaryDirectory() as t, mock.patch.object(ui, "RUNS", Path(t)):
            (Path(t) / "shop").mkdir()
            (Path(t) / "shop" / "findings.json").write_text("{}")
            self.assertEqual(ui.command("pr", "shop", "", False)[-2:], ["pr", "shop"])
            self.assertEqual(ui.command("pr_preview", "shop", "", False)[-3:], ["pr", "shop", "--dry-run"])
            with self.assertRaises(ValueError):
                ui.command("pr", "../shop", "", False)


class OllamaProvider(unittest.TestCase):
    def test_auto_chain_uses_ollama_not_groq(self):
        self.assertEqual(llm.ORDER, ["claude", "gemini", "ollama"])
        self.assertIn("groq", providers.PROVIDERS)                              # still selectable explicitly

    def test_request_shape_and_reply(self):
        seen = {}

        def fake_post(url, body, headers, timeout=120, retries=5):
            seen.update(url=url, body=body)
            return {"message": {"content": '{"final": {"ok": true}}'}, "done_reason": "stop"}
        with mock.patch.dict(os.environ, {"OLLAMA_MODEL": "qwen3:4b", "OLLAMA_HOST": "http://127.0.0.1:11434"}), \
                mock.patch.object(providers, "_post", side_effect=fake_post):
            out = providers.Ollama().complete("sys", "user")
        self.assertEqual(out, '{"final": {"ok": true}}')
        self.assertTrue(seen["url"].endswith("/api/chat"))
        self.assertEqual((seen["body"]["model"], seen["body"]["format"], seen["body"]["think"]), ("qwen3:4b", "json", False))

    def test_missing_model_says_how_to_pull_it(self):
        def fake_post(*a, **k):
            raise providers.ProviderError('HTTP 404: {"error":"model \\"qwen3:4b\\" not found, try pulling it first"}')
        with mock.patch.object(providers, "_post", side_effect=fake_post):
            with self.assertRaisesRegex(providers.ProviderError, "ollama pull"):
                providers.Ollama().complete("s", "u")

    def test_not_available_when_server_down(self):
        providers.Ollama._up.clear()
        with mock.patch.dict(os.environ, {"OLLAMA_HOST": "http://127.0.0.1:9"}):
            self.assertFalse(providers.Ollama().available)


if __name__ == "__main__":
    unittest.main()
