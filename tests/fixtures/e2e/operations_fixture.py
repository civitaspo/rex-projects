#!/usr/bin/env python3
"""Durable local Operator fixture with reconciliable successful operations."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import time
import uuid
from pathlib import Path


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def open_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=5000")
    db.executescript("""
      CREATE TABLE IF NOT EXISTS operations (
        operation_id TEXT PRIMARY KEY, correlation_key TEXT UNIQUE NOT NULL,
        action_id TEXT NOT NULL, target_id TEXT NOT NULL, repository_id TEXT NOT NULL,
        environment TEXT NOT NULL, source_sha TEXT NOT NULL, status TEXT NOT NULL,
        external_run_id TEXT NOT NULL, request_digest TEXT NOT NULL, updated_at REAL NOT NULL
      );
      CREATE TABLE IF NOT EXISTS faults (
        name TEXT PRIMARY KEY, value TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0
      );
    """)
    return db


def fail(request_id: str, code: str, message: str, retryable: bool = False) -> dict:
    return {"schema_version": 1, "request_id": request_id,
            "error": {"code": code, "message": message, "retryable": retryable}}


def dispatch(db: sqlite3.Connection, request: dict) -> dict:
    method, params = request.get("method"), request.get("params")
    request_id = request.get("request_id", "invalid")
    if request.get("schema_version") != 1 or not isinstance(request_id, str) or not request_id or not isinstance(params, dict):
        raise ValueError("schema_version 1, request_id, and object params are required")
    if method == "adapter.describe":
        result = {"protocol_version": 1, "adapter_kind": "operations", "provider_instance": "fixture-local",
                  "capabilities": [{"action_id": "fixture.release", "parameter_schema": {"type": "object"},
                                    "selector_schema": {"type": "object"}, "supports_find": True,
                                    "supports_observe": True, "idempotency": "reconcile_by_correlation_key"}]}
    elif method == "operation.invoke":
        required = ["operation_id", "correlation_key", "action_id", "target_id", "repository_id", "environment", "source_sha"]
        if any(not isinstance(params.get(key), str) or not params[key] for key in required):
            raise ValueError("operation.invoke missing required identity fields")
        request_digest = hashlib.sha256(canonical(params).encode()).hexdigest()
        row = db.execute("SELECT * FROM operations WHERE correlation_key=?", (params["correlation_key"],)).fetchone()
        if row is None:
            run_id = "fixture-run-" + uuid.uuid5(uuid.NAMESPACE_URL, params["correlation_key"]).hex[:16]
            db.execute("INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                       (params["operation_id"], params["correlation_key"], params["action_id"], params["target_id"],
                        params["repository_id"], params["environment"], params["source_sha"], "running", run_id,
                        request_digest, time.time()))
            row = db.execute("SELECT * FROM operations WHERE operation_id=?", (params["operation_id"],)).fetchone()
        elif row["request_digest"] != request_digest:
            raise RuntimeError("operation correlation key was reused with different parameters")
        result = {"outcome": "accepted", "operation_id": row["operation_id"],
                  "correlation_key": row["correlation_key"], "external_reference": row["external_run_id"],
                  "receipt": {"provider_instance": "fixture-local", "simulated": True}}
    elif method in {"operation.find", "operation.observe"}:
        operation_id = params.get("operation_id")
        correlation = params.get("correlation_key")
        row = None
        if isinstance(operation_id, str):
            row = db.execute("SELECT * FROM operations WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None and isinstance(correlation, str):
            row = db.execute("SELECT * FROM operations WHERE correlation_key=?", (correlation,)).fetchone()
        if row is None:
            result = {"outcome": "absent", "operation_id": operation_id,
                      "correlation_key": correlation, "proof_scope": "fixture-local-sqlite",
                      "observed_at_epoch_seconds": time.time()}
        elif method == "operation.find":
            result = {"outcome": "found", "operation_id": row["operation_id"],
                      "correlation_key": row["correlation_key"], "action_id": row["action_id"],
                      "external_reference": row["external_run_id"], "status": row["status"]}
        else:
            db.execute("UPDATE operations SET status='succeeded',updated_at=? WHERE operation_id=?",
                       (time.time(), row["operation_id"]))
            row = db.execute("SELECT * FROM operations WHERE operation_id=?", (row["operation_id"],)).fetchone()
            result = {"provider_instance": "fixture-local", "external_run_id": row["external_run_id"],
                      "operation_id": row["operation_id"], "correlation_key": row["correlation_key"],
                      "action_id": row["action_id"], "target_id": row["target_id"],
                      "repository_id": row["repository_id"], "environment": row["environment"],
                      "source_sha": row["source_sha"], "observed_at_epoch_seconds": row["updated_at"],
                      "status": "succeeded", "evidence": [{"kind": "fixture", "digest": hashlib.sha256(row["external_run_id"].encode()).hexdigest()}],
                      "jobs": {"fixture": "succeeded"}}
    else:
        raise NotImplementedError(f"unsupported operation fixture method: {method}")
    return {"schema_version": 1, "request_id": request_id, "result": result}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--drop-response-once", metavar="OPERATION_ID")
    args = parser.parse_args()
    db = open_db(args.database.expanduser().absolute())
    if args.drop_response_once:
        db.execute("INSERT OR IGNORE INTO faults VALUES('drop_response',?,0)", (args.drop_response_once,))
    try:
        raw_request = sys.stdin.read(4 * 1024 * 1024 + 1)
        if len(raw_request) > 4 * 1024 * 1024:
            raise ValueError("request exceeds the 4 MiB fixture limit")
        request = json.loads(raw_request, object_pairs_hook=unique_object)
        payload = dispatch(db, request)
        db.commit()
        operation_id = request.get("params", {}).get("operation_id")
        fault = db.execute("SELECT value,consumed FROM faults WHERE name='drop_response'").fetchone()
        if fault and operation_id == fault["value"] and not fault["consumed"]:
            db.execute("UPDATE faults SET consumed=1 WHERE name='drop_response'")
            db.commit()
            return 0
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        db.rollback()
        print(json.dumps(fail(locals().get("request", {}).get("request_id", "invalid"),
                              "unsupported" if isinstance(error, NotImplementedError) else "invalid_request",
                              str(error)), sort_keys=True, separators=(",", ":")))
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
