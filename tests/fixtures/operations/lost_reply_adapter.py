#!/usr/bin/env python3
"""Deterministic fake remote operation API used by host runtime tests only."""

import json
import os
import sys
import tempfile


def read_state(path):
    try:
        with open(path, encoding="utf-8") as source:
            return json.load(source)
    except FileNotFoundError:
        return {"operations": {}, "invoke_calls": 0, "duplicate_invoke_calls": 0, "drop_reply_used": False}


def write_state(path, state):
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as target:
            json.dump(state, target, sort_keys=True)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def respond(request, result):
    print(json.dumps({"schema_version": 1, "request_id": request["request_id"], "result": result}, separators=(",", ":")))


def main():
    request = json.load(sys.stdin)
    method = request["method"]
    params = request["params"]
    state_path = sys.argv[1]
    drop_first_reply = "--drop-first-invoke-reply" in sys.argv[2:]
    state = read_state(state_path)
    operations = state["operations"]

    if method == "operation.invoke":
        operation_id = request["operation_id"]
        if operation_id in operations:
            state["duplicate_invoke_calls"] += 1
        else:
            state["invoke_calls"] += 1
            operations[operation_id] = {
                "correlation_key": params["correlation_key"],
                "action_id": params["action_id"],
                "target_id": params["target_id"],
                "repository_id": params["repository_id"],
                "environment": params["environment"],
                "source_sha": params["source_sha"],
                "external_reference": "fixture-run:" + params["correlation_key"],
            }
        should_drop = drop_first_reply and not state["drop_reply_used"]
        if should_drop:
            state["drop_reply_used"] = True
        write_state(state_path, state)
        if should_drop:
            return 19
        respond(request, {"outcome": "accepted", "external_reference": operations[operation_id]["external_reference"]})
        return 0

    operation_id = params["operation_id"] if method == "operation.find" else request["operation_id"]
    operation = operations.get(operation_id)
    if method == "operation.find":
        if operation is None:
            result = {
                "outcome": "absent",
                "operation_id": operation_id,
                "correlation_key": params["correlation_key"],
                "action_id": params["action_id"],
                "target_id": params["target_id"],
                "repository_id": params["repository_id"],
                "environment": params["environment"],
                "source_sha": params["source_sha"],
                "observed_at": "2026-11-07T00:00:00Z",
                "proof_scope": "fixture-authoritative-local-store",
            }
        else:
            result = {
                "outcome": "found",
                "operation_id": operation_id,
                "correlation_key": operation["correlation_key"],
                "action_id": operation["action_id"],
                "target_id": operation["target_id"],
                "repository_id": operation["repository_id"],
                "environment": operation["environment"],
                "source_sha": operation["source_sha"],
                "external_reference": operation["external_reference"],
            }
        respond(request, result)
        return 0

    if method == "operation.observe" and operation is not None:
        respond(request, {
            "provider_instance": "fixture-local",
            "external_run_id": operation["external_reference"],
            "operation_id": operation_id,
            "correlation_key": operation["correlation_key"],
            "action_id": operation["action_id"],
            "target_id": operation["target_id"],
            "repository_id": operation["repository_id"],
            "environment": operation["environment"],
            "source_sha": operation["source_sha"],
            "observed_at": "2026-11-07T00:00:01Z",
            "status": "succeeded",
            "evidence": [],
            "jobs": {},
        })
        return 0
    print("unsupported or unknown operation", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
