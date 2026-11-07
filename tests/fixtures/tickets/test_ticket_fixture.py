"""Behavioral tests for the external command protocol, not private implementation calls."""

import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ADAPTER = Path(__file__).with_name("ticket_fixture.py")
STATUSES = ("triage", "backlog", "ready", "in_progress", "in_review", "done", "canceled")


class TicketCli:
    def __init__(self, folder):
        self.folder = Path(folder)
        self.db = self.folder / "ticket-service.sqlite"
        self.counter = 0

    def call(self, method, params, *, operation_id=None, scope_project="ext-project", fault=None):
        self.counter += 1
        request_id = f"req-{self.counter}"
        default_scope = {} if method == "adapter.describe" else {"scope": {"project": scope_project}}
        request = {"schema_version": 1, "request_id": request_id, "method": method,
                   "params": {**default_scope, **params}}
        if "scope" in params:
            request["params"] = dict(params)
        if operation_id is not None:
            request["operation_id"] = operation_id
        command = [sys.executable, str(ADAPTER), "--database", str(self.db),
                   "--namespace", "fixture/tenant-a", "--visibility-delay-seconds", "0.12"]
        if fault:
            command += ["--drop-create-response-once", fault]
        run = subprocess.run(command, input=json.dumps(request), text=True, capture_output=True, timeout=5)
        value = json.loads(run.stdout) if run.stdout else None
        if value is not None:
            if value["request_id"] != request_id:
                raise AssertionError(f"response did not correlate to {request_id}: {value}")
            return run, value
        return run, None

    def create(self, operation_id, key="new-feature", scope_project="ext-project"):
        return self.call("ticket.create", {"scope": {"project": scope_project}, "creation_key": key,
                          "title": "Implement feature", "body": "Acceptance: pass the fixture.",
                          "labels": ["fixture"], "status": "ready"}, operation_id=operation_id)

    def ticket(self, result):
        return result["result"]["ticket"]


class TicketFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.cli = TicketCli(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_capabilities_advertise_exact_normalized_status_set(self):
        _, response = self.cli.call("adapter.describe", {"schema_version": 1})
        self.assertEqual(set(response["result"]["status_values"]), set(STATUSES))
        self.assertTrue(response["result"]["capabilities"]["revision_support"])
        self.assertIn("ticket.resolve_duplicate", response["result"]["capabilities"]["supported_optional_methods"])

    def test_list_paginates_and_binds_cursor_to_scope_and_filters(self):
        for index in range(3):
            self.cli.create(f"create-{index}", key=f"feature-{index}")
        _, first = self.cli.call("ticket.list", {"scope": {"project": "ext-project"}, "page_size": 2,
                                                  "labels": ["fixture"]})
        first_result = first["result"]
        self.assertEqual(len(first_result["tickets"]), 2)
        self.assertEqual(first_result["applied_filters"]["labels"], ["fixture"])
        self.assertIsInstance(first_result["next_cursor"], str)
        _, second = self.cli.call("ticket.list", {"scope": {"project": "ext-project"}, "page_size": 2,
                                                   "labels": ["fixture"], "cursor": first_result["next_cursor"]})
        self.assertEqual(len(second["result"]["tickets"]), 1)
        _, wrong_scope = self.cli.call("ticket.list", {"scope": {"project": "other"},
                                                        "page_size": 2, "cursor": first_result["next_cursor"]},
                                       scope_project="other")
        self.assertEqual(wrong_scope["error"]["code"], "conflict")

    def test_revision_precondition_and_seven_status_round_trips(self):
        _, created = self.cli.create("create-status")
        ticket = self.cli.ticket(created)
        revision = ticket["revision"]
        for expected in STATUSES:
            _, updated = self.cli.call("ticket.update", {"scope": {"project": "ext-project"},
                                                          "ticket_id": ticket["id"],
                                                          "expected_revision": revision,
                                                          "patch": {"status": expected}},
                                       operation_id=f"status-{expected}")
            ticket = self.cli.ticket(updated)
            self.assertEqual(ticket["status"]["value"], expected)
            self.assertEqual(ticket["status"]["native_value"], updated["result"]["ticket"]["status"]["label"])
            revision = ticket["revision"]
        _, stale = self.cli.call("ticket.update", {"scope": {"project": "ext-project"},
                                                    "ticket_id": ticket["id"], "expected_revision": "rev-1",
                                                    "patch": {"title": "stale"}}, operation_id="stale")
        self.assertEqual(stale["error"]["code"], "conflict")

    def test_lost_create_reply_reconciles_by_operation_id_without_second_ticket(self):
        run, missing_reply = self.cli.call("ticket.create", {"scope": {"project": "ext-project"},
                                                              "creation_key": "lost-reply", "title": "One ticket",
                                                              "body": "Body"}, operation_id="create-lost",
                                           fault="create-lost")
        self.assertEqual(run.returncode, 0)
        self.assertIsNone(missing_reply)
        find_params = {"scope": {"project": "ext-project"}, "operation_id": "create-lost",
                       "method": "ticket.create", "stable_external_key": "lost-reply",
                       "subject": {"creation_key": "lost-reply"}}
        _, found = self.cli.call("operation.find", find_params, operation_id="find-lost")
        self.assertEqual(found["result"]["outcome"], "found")
        saved_id = found["result"]["matches"][0]["ticket_id"]
        _, retried = self.cli.call("ticket.create", {"scope": {"project": "ext-project"},
                                                       "creation_key": "lost-reply", "title": "One ticket",
                                                       "body": "Body"}, operation_id="create-lost")
        self.assertEqual(self.cli.ticket(retried)["id"], saved_id)
        _, listing = self.cli.call("ticket.list", {"scope": {"project": "ext-project"}})
        self.assertEqual(len(listing["result"]["tickets"]), 1)

    def test_eventual_index_never_reports_false_absence_and_duplicate_resolution_cancels(self):
        _, first = self.cli.create("create-a", "same-key")
        _, second = self.cli.create("create-b", "same-key")
        a, b = self.cli.ticket(first), self.cli.ticket(second)
        lookup = {"scope": {"project": "ext-project"}, "operation_id": "not-indexed-yet",
                  "method": "ticket.create", "stable_external_key": "same-key",
                  "subject": {"creation_key": "same-key"}}
        _, early = self.cli.call("operation.find", lookup, operation_id="lookup-early")
        self.assertEqual(early["result"]["outcome"], "unknown")
        time.sleep(0.14)
        _, visible = self.cli.call("operation.find", lookup, operation_id="lookup-late")
        self.assertEqual(visible["result"]["outcome"], "found")
        self.assertEqual(len(visible["result"]["matches"]), 2)
        _, resolved = self.cli.call("ticket.resolve_duplicate", {
            "scope": {"project": "ext-project"}, "duplicate_ticket_id": b["id"],
            "canonical_ticket_id": a["id"], "operation_key": "resolve-b", "reason": "same requested work",
        }, operation_id="resolve-b")
        self.assertEqual(resolved["result"]["duplicate"]["status"]["value"], "canceled")
        _, replay = self.cli.call("ticket.resolve_duplicate", {
            "scope": {"project": "ext-project"}, "duplicate_ticket_id": b["id"],
            "canonical_ticket_id": a["id"], "operation_key": "resolve-b", "reason": "same requested work",
        }, operation_id="resolve-b")
        self.assertEqual(replay["result"], resolved["result"])
        _, listing = self.cli.call("ticket.list", {"scope": {"project": "ext-project"}, "status": "canceled"})
        self.assertEqual([item["id"] for item in listing["result"]["tickets"]], [b["id"]])

    def test_mutations_are_project_scoped_and_replays_bind_parameters(self):
        _, created = self.cli.create("create-scoped")
        ticket_id = self.cli.ticket(created)["id"]
        _, outside = self.cli.call("ticket.get", {"scope": {"project": "other"}, "ticket_id": ticket_id},
                                   scope_project="other")
        self.assertEqual(outside["error"]["code"], "not_found")
        params = {"scope": {"project": "ext-project"}, "ticket_id": ticket_id,
                  "expected_revision": "rev-1", "patch": {"title": "Updated"}}
        _, updated = self.cli.call("ticket.update", params, operation_id="update-one")
        self.assertEqual(self.cli.ticket(updated)["revision"], "rev-2")
        changed = {**params, "patch": {"title": "Different request"}}
        _, conflict = self.cli.call("ticket.update", changed, operation_id="update-one")
        self.assertEqual(conflict["error"]["code"], "conflict")

    def test_comments_deduplicate_and_unknown_methods_are_typed(self):
        _, created = self.cli.create("create-comment")
        ticket = self.cli.ticket(created)
        comment = {"scope": {"project": "ext-project"}, "ticket_id": ticket["id"],
                   "comment_key": "same-comment", "body": "Duplicate of another ticket.", "references": []}
        _, one = self.cli.call("ticket.comment", comment, operation_id="comment-one")
        _, two = self.cli.call("ticket.comment", comment, operation_id="comment-one")
        self.assertEqual(two["result"]["comment"]["reference"], one["result"]["comment"]["reference"])
        _, unknown = self.cli.call("ticket.reopen", {"scope": {"project": "ext-project"}})
        self.assertEqual(unknown["error"]["code"], "unsupported")


if __name__ == "__main__":
    unittest.main()
