from __future__ import annotations

import json
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def invoke(argv: list[str], request: dict | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, input=json.dumps(request) if request is not None else None,
                          text=True, capture_output=True, timeout=20, check=False)


def git(*args: str, cwd: Path, input_text: str | None = None,
        env: dict[str, str] | None = None) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, input=input_text, text=True,
                            capture_output=True, check=True, timeout=20, env=env)
    return result.stdout.strip()


class E2EFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="rex-projects-e2e-fixture-")
        self.root = Path(self.temp.name)
        result = invoke([sys.executable, str(HERE / "create_local_git.py"), "--root", str(self.root / "git")])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.git_receipt = json.loads(result.stdout)
        self.remote = Path(self.git_receipt["remote"])
        self.seed = Path(self.git_receipt["seed_clone"])
        self.forge_db = self.root / "forge.sqlite"
        self.forge_argv = [sys.executable, str(HERE / "forge_fixture.py"), "--database", str(self.forge_db),
                           "--repository", "fixture/service", "--remote", str(self.remote),
                           "--required-check", "required-tests", "--required-approval-count", "1",
                           "--check-conclusion", "failure"]

    def tearDown(self) -> None:
        self.temp.cleanup()

    def forge(self, method: str, params: dict, operation_id: str | None = None,
              extra: list[str] | None = None) -> tuple[subprocess.CompletedProcess[str], dict | None]:
        request = {"schema_version": 1, "request_id": "fixture-request", "method": method, "params": params}
        if operation_id:
            request["operation_id"] = operation_id
        result = invoke([*self.forge_argv, *(extra or [])], request)
        payload = json.loads(result.stdout) if result.stdout.strip() else None
        return result, payload

    def test_forge_lost_merge_reply_recovers_and_checks_exact_head(self) -> None:
        base = self.git_receipt["initial_commit"]
        git("checkout", "-b", "factory/ticket-1", cwd=self.seed)
        (self.seed / "src").mkdir()
        (self.seed / "src" / "change.txt").write_text("fixture change\n", encoding="utf-8")
        git("add", "src/change.txt", cwd=self.seed)
        tree = git("write-tree", cwd=self.seed)
        commit_env = {**os.environ, "GIT_AUTHOR_NAME": "rex-projects fixture",
                      "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                      "GIT_COMMITTER_NAME": "rex-projects fixture",
                      "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
        head = git("commit-tree", tree, "-p", base, "-m", "feat: fixture change", cwd=self.seed, env=commit_env)
        git("update-ref", "HEAD", head, cwd=self.seed)
        git("push", "--set-upstream", "origin", "factory/ticket-1", cwd=self.seed)

        created, created_body = self.forge("pull_request.create", {
            "source_branch": "factory/ticket-1", "target_branch": "main", "expected_head_sha": head,
            "title": "feat: fixture change", "body": "Local acceptance fixture."}, "create-pr-1")
        self.assertEqual(created.returncode, 0, created.stderr)
        self.assertIsNotNone(created_body)
        pr = created_body["result"]
        self.assertEqual(pr["head_sha"], head)
        number = pr["number"]

        blocked, blocked_body = self.forge("pull_request.merge", {
            "number": number, "expected_head_sha": head, "required_checks": [],
            "required_approval_count": 0})
        self.assertEqual(blocked.returncode, 0, blocked.stderr)
        self.assertEqual(blocked_body["error"]["code"], "conflict")
        self.assertEqual(subprocess.run(["git", f"--git-dir={self.remote}", "rev-parse", "refs/heads/main"],
                                        check=True, text=True, capture_output=True).stdout.strip(), base)

        set_check, check_body = self.forge("fixture.check.set", {
            "number": number, "head_sha": head, "name": "required-tests", "conclusion": "success"})
        self.assertEqual(set_check.returncode, 0, set_check.stderr)
        self.assertEqual(check_body["result"]["conclusion"], "success")
        set_review, review_body = self.forge("fixture.review.set", {
            "number": number, "head_sha": head, "review_id": "human-review-1",
            "state": "approved", "actor": "fixture-human"})
        self.assertEqual(set_review.returncode, 0, set_review.stderr)

        merged_once, empty = self.forge("pull_request.merge", {
            "number": number, "expected_head_sha": head, "required_checks": ["required-tests"],
            "required_approval_count": 1}, "merge-pr-1", ["--drop-response-once", "merge-pr-1"])
        self.assertEqual(merged_once.returncode, 0, merged_once.stderr)
        self.assertIsNone(empty, "fault injection should lose the response after the local merge is durable")
        recovered, recovered_body = self.forge("pull_request.merge", {
            "number": number, "expected_head_sha": head, "required_checks": ["required-tests"],
            "required_approval_count": 1}, "merge-pr-1", ["--drop-response-once", "merge-pr-1"])
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertEqual(recovered_body["result"]["state"], "merged")
        actual_main = subprocess.run(["git", f"--git-dir={self.remote}", "rev-parse", "refs/heads/main"],
                                     check=True, text=True, capture_output=True).stdout.strip()
        self.assertEqual(actual_main, head)

    def test_deterministic_agent_is_finite_and_writes_expected_receipt(self) -> None:
        receipt = self.root / "agent-result.json"
        result = invoke([sys.executable, str(HERE / "deterministic_agent.py"), "--worktree", str(self.seed),
                         "--receipt", str(receipt), "--ticket-id", "fixture-42"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(receipt.read_text(encoding="utf-8"))["ticket_id"], "fixture-42")
        self.assertTrue((self.seed / "src/acceptance-fixture.txt").is_file())

    def test_operation_lost_reply_is_reconciled_and_observed(self) -> None:
        database = self.root / "operations.sqlite"
        argv = [sys.executable, str(HERE / "operations_fixture.py"), "--database", str(database),
                "--drop-response-once", "op-release-1"]
        params = {"operation_id": "op-release-1", "correlation_key": "ticket-42:release:sha-abc",
                  "action_id": "fixture.release", "target_id": "staging", "repository_id": "fixture/service",
                  "environment": "test", "source_sha": "a" * 40, "typed_parameters": {}}
        request = {"schema_version": 1, "request_id": "invoke-1", "method": "operation.invoke", "params": params}
        first = invoke(argv, request)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, "")

        replay = invoke(argv, request)
        self.assertEqual(replay.returncode, 0, replay.stderr)
        receipt = json.loads(replay.stdout)
        self.assertEqual(receipt["result"]["outcome"], "accepted")
        self.assertEqual(receipt["result"]["operation_id"], "op-release-1")

        find_request = {"schema_version": 1, "request_id": "find-1", "method": "operation.find",
                        "params": {"operation_id": "op-release-1", "correlation_key": params["correlation_key"]}}
        found = invoke(argv, find_request)
        self.assertEqual(json.loads(found.stdout)["result"]["outcome"], "found")
        wrong_identity = {"schema_version": 1, "request_id": "observe-wrong", "method": "operation.observe",
                          "params": {"operation_id": "op-release-1", "correlation_key": params["correlation_key"],
                                     "source_sha": "b" * 40}}
        mismatch = invoke(argv, wrong_identity)
        self.assertEqual(json.loads(mismatch.stdout)["error"]["code"], "conflict")
        observe_request = {"schema_version": 1, "request_id": "observe-1", "method": "operation.observe",
                           "params": {"operation_id": "op-release-1", "correlation_key": params["correlation_key"]}}
        observed = invoke(argv, observe_request)
        self.assertEqual(json.loads(observed.stdout)["result"]["status"], "succeeded")

    def test_rejects_existing_local_git_root(self) -> None:
        result = invoke([sys.executable, str(HERE / "create_local_git.py"), "--root", str(self.root / "git")])
        self.assertEqual(result.returncode, 2)
        self.assertIn("refusing to reuse existing fixture root", result.stderr)

    def test_preflight_does_not_treat_parent_usage_as_supported_surface(self) -> None:
        result = invoke([sys.executable, str(HERE / "preflight.py"), "--cli", "/bin/echo", "--json"])
        self.assertEqual(result.returncode, 4)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["result"], "UNSUPPORTED")
        self.assertFalse(receipt["full_flow_pass"])
        self.assertIn("human list", receipt["missing_commands"])

    def test_rex_receipt_sanitizer_removes_user_metadata(self) -> None:
        sys.path.insert(0, str(HERE))
        from run_rex_agent import sanitize_transcript

        directory = self.root / "transcript"
        directory.mkdir()
        path = directory / "001.json"
        path.write_text(json.dumps({"argv": ["rex", "whoami"], "stdout": json.dumps({
            "account": "private-user", "principal": {"uid": 501}, "home": str(Path.home()),
            "program": str(Path.home() / "bin" / "python"),
        })}), encoding="utf-8")
        sanitize_transcript(directory)
        receipt = json.loads(path.read_text(encoding="utf-8"))
        output = json.loads(receipt["stdout"])
        self.assertNotIn("account", output)
        self.assertNotIn("principal", output)
        self.assertNotIn("home", output)
        self.assertEqual(output["program"], "$HOME/bin/python")
        layout = directory / "session-create.json"
        layout.write_text(json.dumps({"command": [str(Path.home() / "bin" / "python")] }), encoding="utf-8")
        sanitize_transcript(directory)
        self.assertEqual(json.loads(layout.read_text(encoding="utf-8"))["command"], ["$HOME/bin/python"])

    def test_rex_runner_rejects_payload_digest_claim_without_matching_bytes(self) -> None:
        sys.path.insert(0, str(HERE))
        from deterministic_agent import CHANGE
        from run_rex_agent import ProbeError, verify_worker_output

        target = self.seed / "src/acceptance-fixture.txt"
        target.parent.mkdir()
        target.write_text(CHANGE, encoding="utf-8")
        receipt = {"ticket_id": "fixture-42", "outcome": "completed",
                   "content_sha256": hashlib.sha256(CHANGE.encode("utf-8")).hexdigest()}
        self.assertEqual(verify_worker_output(self.seed, "fixture-42", receipt), receipt["content_sha256"])
        target.write_text("different bytes\n", encoding="utf-8")
        with self.assertRaises(ProbeError):
            verify_worker_output(self.seed, "fixture-42", receipt)

    def test_rex_runner_skips_cleanup_before_identity_is_verified(self) -> None:
        sys.path.insert(0, str(HERE))
        from run_rex_agent import cleanup_owned_session

        class NoCallRex:
            calls = 0

            def call(self, *_args, **_kwargs):
                self.calls += 1
                raise AssertionError("must not query or mutate an unverified Rex server")

        rex = NoCallRex()
        result: dict[str, object] = {}
        cleanup_owned_session(rex, "unique-test-label", None, False, result)
        self.assertEqual(rex.calls, 0)
        self.assertIn("cleanup_skipped", result)

if __name__ == "__main__":
    unittest.main()
