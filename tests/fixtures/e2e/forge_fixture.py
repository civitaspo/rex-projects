#!/usr/bin/env python3
"""Durable local Forge command fixture for isolated acceptance runs.

This is a protocol fixture, not a GitHub/Forgejo implementation. The only
merge executor it exposes is a guarded local fast-forward into the configured
bare remote. It never accesses a network service.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import subprocess
import sys
import time
from pathlib import Path


class FixtureError(Exception):
    def __init__(self, code: str, message: str, retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.retryable = retryable


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def git(remote: Path, *args: str) -> str:
    result = subprocess.run(["git", f"--git-dir={remote}", *args], capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise FixtureError("unavailable", f"local git operation failed: {result.stderr.strip()}", True)
    return result.stdout.strip()


def db_open(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=5000")
    db.executescript("""
      CREATE TABLE IF NOT EXISTS pull_requests (
        repository TEXT NOT NULL, number INTEGER NOT NULL, source_branch TEXT NOT NULL,
        target_branch TEXT NOT NULL, head_sha TEXT NOT NULL, base_sha TEXT NOT NULL,
        title TEXT NOT NULL, body TEXT NOT NULL, state TEXT NOT NULL,
        merge_sha TEXT, merge_strategy TEXT NOT NULL,
        PRIMARY KEY(repository, number), UNIQUE(repository, source_branch)
      );
      CREATE TABLE IF NOT EXISTS operation_receipts (
        operation_id TEXT PRIMARY KEY, method TEXT NOT NULL, request_digest TEXT NOT NULL,
        result_json TEXT NOT NULL, created_at REAL NOT NULL
      );
      CREATE TABLE IF NOT EXISTS faults (
        name TEXT PRIMARY KEY, value TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS checks (
        repository TEXT NOT NULL, number INTEGER NOT NULL, head_sha TEXT NOT NULL,
        name TEXT NOT NULL, conclusion TEXT NOT NULL,
        PRIMARY KEY(repository, number, head_sha, name)
      );
      CREATE TABLE IF NOT EXISTS reviews (
        repository TEXT NOT NULL, number INTEGER NOT NULL, head_sha TEXT NOT NULL,
        review_id TEXT NOT NULL, state TEXT NOT NULL, actor TEXT NOT NULL,
        PRIMARY KEY(repository, number, head_sha, review_id)
      );
      CREATE TABLE IF NOT EXISTS repository_policy (
        repository TEXT PRIMARY KEY, required_checks_json TEXT NOT NULL,
        required_approval_count INTEGER NOT NULL
      );
    """)
    return db


def fail(code: str, message: str, retryable: bool = False) -> None:
    raise FixtureError(code, message, retryable)


def check_request(request: object) -> dict:
    if not isinstance(request, dict):
        fail("invalid_request", "request must be a JSON object")
    if request.get("schema_version") != 1 or isinstance(request.get("schema_version"), bool):
        fail("unsupported", "only request schema version 1 is supported")
    if not isinstance(request.get("request_id"), str) or not request["request_id"]:
        fail("invalid_request", "request_id must be a nonempty string")
    if not isinstance(request.get("method"), str) or not isinstance(request.get("params"), dict):
        fail("invalid_request", "method and object params are required")
    if "operation_id" in request and (not isinstance(request["operation_id"], str) or not request["operation_id"]):
        fail("invalid_request", "operation_id must be a nonempty string")
    return request


def response(request: dict, result: object) -> dict:
    return {"schema_version": 1, "request_id": request["request_id"], "result": result}


def record_operation(db: sqlite3.Connection, request: dict, result: dict) -> None:
    operation_id = request.get("operation_id")
    if not operation_id:
        return
    db.execute("INSERT INTO operation_receipts VALUES(?,?,?,?,?)",
               (operation_id, request["method"], hashlib.sha256(canonical(request["params"]).encode()).hexdigest(), canonical(result), time.time()))


def maybe_replay(db: sqlite3.Connection, request: dict) -> dict | None:
    operation_id = request.get("operation_id")
    if not operation_id:
        return None
    row = db.execute("SELECT * FROM operation_receipts WHERE operation_id=?", (operation_id,)).fetchone()
    if row is None:
        return None
    expected = hashlib.sha256(canonical(request["params"]).encode()).hexdigest()
    if row["method"] != request["method"] or row["request_digest"] != expected:
        fail("conflict", "operation_id was already used for a different request")
    return json.loads(row["result_json"])


def maybe_drop(db: sqlite3.Connection, operation_id: str | None) -> bool:
    if operation_id is None:
        return False
    row = db.execute("SELECT value,consumed FROM faults WHERE name='drop_response'").fetchone()
    if row and row["value"] == operation_id and not row["consumed"]:
        db.execute("UPDATE faults SET consumed=1 WHERE name='drop_response'")
        return True
    return False


def branch_sha(remote: Path, branch: str) -> str:
    return git(remote, "rev-parse", f"refs/heads/{branch}")


def dispatch(db: sqlite3.Connection, request: dict, repository: str, remote: Path) -> dict:
    method, params = request["method"], request["params"]
    if method == "adapter.describe":
        return {"protocol_version": 1, "adapter_kind": "forge", "provider_instance": "fixture-local",
                "capabilities": ["repository.get", "pull_request.create", "pull_request.get",
                                 "pull_request.find_by_branch", "pull_request.checks", "pull_request.reviews",
                                 "pull_request.merge", "pull_request.merge_observe", "operation.find",
                                 "fixture.check.set", "fixture.review.set"],
                "merge_strategies": ["fast_forward"], "network": False}
    if method == "repository.get":
        return {"repository_id": repository, "remote": str(remote), "default_branch": params.get("default_branch", "main")}
    if method == "pull_request.create":
        required = ("source_branch", "target_branch", "expected_head_sha", "title", "body")
        if any(not isinstance(params.get(key), str) or not params[key] for key in required):
            fail("invalid_request", "create requires source_branch, target_branch, expected_head_sha, title, and body")
        head = branch_sha(remote, params["source_branch"])
        if head != params["expected_head_sha"]:
            fail("conflict", "remote source branch does not match expected_head_sha")
        existing = db.execute("SELECT * FROM pull_requests WHERE repository=? AND source_branch=?",
                              (repository, params["source_branch"])).fetchone()
        if existing:
            if existing["head_sha"] != head or existing["target_branch"] != params["target_branch"]:
                fail("conflict", "source branch already has a different pull request")
            row = existing
        else:
            base = branch_sha(remote, params["target_branch"])
            number = db.execute("SELECT COALESCE(MAX(number),0)+1 FROM pull_requests WHERE repository=?", (repository,)).fetchone()[0]
            db.execute("INSERT INTO pull_requests VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                       (repository, number, params["source_branch"], params["target_branch"], head, base,
                        params["title"], params["body"], "open", None, "fast_forward"))
            row = db.execute("SELECT * FROM pull_requests WHERE repository=? AND number=?", (repository, number)).fetchone()
            default_check = db.execute("SELECT value FROM faults WHERE name='check_conclusion'").fetchone()
            db.execute("INSERT OR IGNORE INTO checks VALUES(?,?,?,?,?)",
                       (repository, number, head, "fixture/default", default_check["value"] if default_check else "success"))
        return pr_json(row)
    if method in {"pull_request.get", "pull_request.checks", "pull_request.reviews", "pull_request.merge_observe"}:
        number = params.get("number")
        if not isinstance(number, int) or isinstance(number, bool):
            fail("invalid_request", "number must be an integer")
        row = db.execute("SELECT * FROM pull_requests WHERE repository=? AND number=?", (repository, number)).fetchone()
        if row is None:
            fail("not_found", f"pull request {number} was not found")
        if method == "pull_request.get":
            return pr_json(row)
        if method == "pull_request.checks":
            rows = db.execute("SELECT name,conclusion,head_sha FROM checks WHERE repository=? AND number=? ORDER BY name", (repository, number)).fetchall()
            return {"head_sha": row["head_sha"], "checks": [dict(check) for check in rows]}
        if method == "pull_request.reviews":
            rows = db.execute("SELECT review_id,state,actor,head_sha FROM reviews WHERE repository=? AND number=? ORDER BY review_id", (repository, number)).fetchall()
            return {"head_sha": row["head_sha"], "reviews": [dict(review) for review in rows]}
        return {"state": row["state"], "merge_sha": row["merge_sha"], "head_sha": row["head_sha"]}
    if method == "pull_request.find_by_branch":
        branch = params.get("source_branch")
        if not isinstance(branch, str) or not branch:
            fail("invalid_request", "source_branch is required")
        rows = db.execute("SELECT * FROM pull_requests WHERE repository=? AND source_branch=? ORDER BY number", (repository, branch)).fetchall()
        return {"pull_requests": [pr_json(row) for row in rows]}
    if method == "pull_request.merge":
        number = params.get("number")
        expected_head = params.get("expected_head_sha")
        if not isinstance(number, int) or isinstance(number, bool) or not isinstance(expected_head, str):
            fail("invalid_request", "number and expected_head_sha are required")
        row = db.execute("SELECT * FROM pull_requests WHERE repository=? AND number=?", (repository, number)).fetchone()
        if row is None:
            fail("not_found", f"pull request {number} was not found")
        actual_head = branch_sha(remote, row["source_branch"])
        if row["state"] == "merged":
            return {"state": "merged", "merge_sha": row["merge_sha"], "head_sha": row["head_sha"]}
        if actual_head != expected_head or row["head_sha"] != expected_head:
            fail("conflict", "head changed since merge decision")
        policy = db.execute("SELECT * FROM repository_policy WHERE repository=?", (repository,)).fetchone()
        configured_checks = json.loads(policy["required_checks_json"]) if policy else []
        required_checks = params.get("required_checks", [])
        if not isinstance(required_checks, list) or any(not isinstance(name, str) for name in required_checks):
            fail("invalid_request", "required_checks must be an array of names")
        required_checks = sorted(set(configured_checks) | set(required_checks))
        observed_checks = {item["name"]: item["conclusion"] for item in db.execute(
            "SELECT name,conclusion FROM checks WHERE repository=? AND number=? AND head_sha=?",
            (repository, number, expected_head)).fetchall()}
        blocked_checks = [name for name in required_checks if observed_checks.get(name) != "success"]
        if blocked_checks:
            fail("conflict", f"required checks are not successful for this head: {', '.join(blocked_checks)}")
        required_approvals = params.get("required_approval_count", 0)
        if not isinstance(required_approvals, int) or isinstance(required_approvals, bool) or required_approvals < 0:
            fail("invalid_request", "required_approval_count must be a nonnegative integer")
        if policy:
            required_approvals = max(required_approvals, policy["required_approval_count"])
        approvals = db.execute("SELECT COUNT(DISTINCT actor) FROM reviews WHERE repository=? AND number=? AND head_sha=? AND state='approved'",
                               (repository, number, expected_head)).fetchone()[0]
        if approvals < required_approvals:
            fail("conflict", f"required human approvals missing: {approvals}/{required_approvals}")
        # This fixture models the repository's declared merge instruction as a
        # local fast-forward. It refuses non-fast-forward histories.
        git(remote, "merge-base", "--is-ancestor", row["base_sha"], actual_head)
        git(remote, "update-ref", f"refs/heads/{row['target_branch']}", actual_head, row["base_sha"])
        db.execute("UPDATE pull_requests SET state='merged',merge_sha=? WHERE repository=? AND number=?",
                   (actual_head, repository, number))
        return {"state": "merged", "merge_sha": actual_head, "head_sha": actual_head, "strategy": "fast_forward"}
    if method in {"fixture.check.set", "fixture.review.set"}:
        number = params.get("number")
        head_sha = params.get("head_sha")
        row = db.execute("SELECT * FROM pull_requests WHERE repository=? AND number=?", (repository, number)).fetchone()
        if row is None:
            fail("not_found", "pull request was not found")
        if head_sha != row["head_sha"]:
            fail("conflict", "fixture evidence must name the current pull request head")
        if method == "fixture.check.set":
            name, conclusion = params.get("name"), params.get("conclusion")
            if not isinstance(name, str) or not name or conclusion not in {"success", "failure", "cancelled", "timed_out", "skipped", "neutral"}:
                fail("invalid_request", "check name or conclusion is invalid")
            db.execute("INSERT INTO checks VALUES(?,?,?,?,?) ON CONFLICT(repository,number,head_sha,name) DO UPDATE SET conclusion=excluded.conclusion",
                       (repository, number, head_sha, name, conclusion))
            result = {"number": number, "head_sha": head_sha, "name": name, "conclusion": conclusion}
        else:
            review_id, state, actor = params.get("review_id"), params.get("state"), params.get("actor")
            if not isinstance(review_id, str) or not review_id or state not in {"approved", "changes_requested", "commented", "dismissed"} or not isinstance(actor, str) or not actor:
                fail("invalid_request", "review_id, actor, or state is invalid")
            db.execute("INSERT INTO reviews VALUES(?,?,?,?,?,?) ON CONFLICT(repository,number,head_sha,review_id) DO UPDATE SET state=excluded.state,actor=excluded.actor",
                       (repository, number, head_sha, review_id, state, actor))
            result = {"number": number, "head_sha": head_sha, "review_id": review_id, "state": state, "actor": actor}
        return result
    if method == "operation.find":
        operation_id = params.get("operation_id")
        row = db.execute("SELECT * FROM operation_receipts WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None:
            return {"outcome": "absent", "operation_id": operation_id, "proof_scope": "fixture-local-sqlite", "observed_at_epoch_seconds": time.time()}
        return {"outcome": "found", "operation_id": operation_id, "method": row["method"], "receipt": json.loads(row["result_json"])}
    fail("unsupported", f"unsupported fixture method: {method}")


def pr_json(row: sqlite3.Row) -> dict:
    return {"repository_id": row["repository"], "number": row["number"],
            "source_branch": row["source_branch"], "target_branch": row["target_branch"],
            "head_sha": row["head_sha"], "base_sha": row["base_sha"], "title": row["title"],
            "body": row["body"], "state": row["state"], "merge_sha": row["merge_sha"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--remote", required=True, type=Path)
    parser.add_argument("--drop-response-once", metavar="OPERATION_ID")
    parser.add_argument("--check-conclusion", choices=["success", "failure", "cancelled", "timed_out"])
    parser.add_argument("--required-check", action="append", default=[])
    parser.add_argument("--required-approval-count", type=int, default=0)
    args = parser.parse_args()
    if args.required_approval_count < 0:
        parser.error("--required-approval-count must be nonnegative")
    remote = args.remote.expanduser().resolve(strict=True)
    if not (remote / "HEAD").is_file():
        parser.error("--remote must be a local bare Git repository")
    db = db_open(args.database.expanduser().absolute())
    if args.drop_response_once:
        db.execute("INSERT OR IGNORE INTO faults(name,value,consumed) VALUES('drop_response',?,0)", (args.drop_response_once,))
    if args.check_conclusion:
        # A default check can be recorded for PRs created after this setting.
        db.execute("INSERT OR IGNORE INTO faults(name,value,consumed) VALUES('check_conclusion',?,0)", (args.check_conclusion,))
    db.execute("INSERT OR IGNORE INTO repository_policy VALUES(?,?,?)",
               (args.repository, canonical(sorted(set(args.required_check))), args.required_approval_count))
    try:
        raw_request = sys.stdin.read(4 * 1024 * 1024 + 1)
        if len(raw_request) > 4 * 1024 * 1024:
            fail("invalid_request", "request exceeds the 4 MiB fixture limit")
        request = check_request(json.loads(raw_request, object_pairs_hook=unique_object))
        result = maybe_replay(db, request)
        if result is None:
            result = dispatch(db, request, args.repository, remote)
            record_operation(db, request, result)
        db.commit()
        if maybe_drop(db, request.get("operation_id")):
            db.commit()
            return 0
        print(json.dumps(response(request, result), sort_keys=True, separators=(",", ":")))
        return 0
    except (FixtureError, json.JSONDecodeError, sqlite3.Error, OSError, ValueError) as error:
        db.rollback()
        if isinstance(error, FixtureError):
            payload = {"schema_version": 1, "request_id": locals().get("request", {}).get("request_id", "invalid"),
                       "error": {"code": error.code, "message": str(error), "retryable": error.retryable}}
        else:
            payload = {"schema_version": 1, "request_id": locals().get("request", {}).get("request_id", "invalid"),
                       "error": {"code": "invalid_request", "message": str(error), "retryable": False}}
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
