#!/usr/bin/env python3
"""Local protocol fixture. It never contacts a remote service or deploys."""

import json
import sys


def respond(request, result):
    return {"schema_version": 1, "request_id": request["request_id"], "result": result}


def main():
    request = json.load(sys.stdin)
    method = request["method"]
    params = request["params"]
    if method == "adapter.describe":
        result = {
            "protocol_version": 1,
            "adapter_kind": "operations",
            "capabilities": [
                {
                    "action_id": "fixture_echo",
                    "parameter_schema": {"type": "object"},
                    "selector_schema": {"type": "object"},
                    "supports_find": True,
                    "supports_observe": True,
                    "idempotency": "reconcile_by_find",
                }
            ],
        }
    elif method == "operation.invoke":
        result = {
            "outcome": "accepted",
            "external_reference": "fixture-run:" + params["correlation_key"],
            "receipt": {"simulated": True},
        }
    elif method == "operation.find":
        result = {
            "outcome": "absent",
            "observed_at": "2026-01-01T00:00:00Z",
            "proof_scope": "fixture-local-deterministic-store",
        }
    elif method == "operation.observe":
        result = {
            "provider_instance": "fixture-local",
            "external_run_id": params.get("external_reference") or "fixture-run",
            "action_id": params["action_id"],
            "target_id": params["target_id"],
            "repository_id": params["repository_id"],
            "environment": params["environment"],
            "source_sha": params["source_sha"],
            "observed_at": "2026-01-01T00:00:00Z",
            "status": "unknown",
            "evidence": [],
            "jobs": {},
        }
    else:
        print("unsupported method", file=sys.stderr)
        return 2
    print(json.dumps(respond(request, result), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
