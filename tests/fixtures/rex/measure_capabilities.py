#!/usr/bin/env python3
"""Measure repeated read-only Rex API description calls for PR0's local budget."""

from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import subprocess
import time
from pathlib import Path
from typing import Any


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, help="Explicit Rex server endpoint")
    parser.add_argument("--source-sha", required=True, help="Git SHA of the source under test")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument("--budget-ms", type=float, default=2000)
    args = parser.parse_args()
    if not 5 <= args.samples <= 100:
        parser.error("--samples must be between 5 and 100")

    whoami_run = subprocess.run(
        ["rex", "--server", args.server, "--autostart=false", "whoami", "--json"],
        capture_output=True, text=True, timeout=10, check=False,
    )
    if whoami_run.returncode:
        raise SystemExit(f"Rex whoami failed: {whoami_run.stderr.strip()}")
    whoami = json.loads(whoami_run.stdout)
    if whoami.get("endpoint") != args.server:
        raise SystemExit("refusing to measure a server other than the requested endpoint")

    rows: list[dict[str, Any]] = []
    for sample in range(1, args.samples + 1):
        started = time.perf_counter_ns()
        run = subprocess.run(
            ["rex", "--server", args.server, "--autostart=false", "api", "describe",
             "session.new_window", "--json"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        elapsed = (time.perf_counter_ns() - started) / 1_000_000
        try:
            value = json.loads(run.stdout)
            correct = (
                run.returncode == 0
                and value["name"] == "session.new_window"
                and "session_id" in value["input_schema"]["required"]
            )
        except (json.JSONDecodeError, KeyError, TypeError):
            correct = False
        rows.append({
            "sample": sample,
            "wall_ms": elapsed,
            "exit_code": run.returncode,
            "correct_response": correct,
            "stderr": run.stderr.strip(),
        })

    times = sorted(row["wall_ms"] for row in rows)
    p95 = times[math.ceil(0.95 * len(times)) - 1]
    report = {
        "source_sha": args.source_sha,
        "server_identity": {
            "endpoint": args.server,
            "instance_id": whoami.get("instance_id"),
            "rex_version": whoami.get("rex_version"),
        },
        "operation": "rex api describe session.new_window --json",
        "samples": rows,
        "sample_count": len(rows),
        "errors": sum(not row["correct_response"] for row in rows),
        "rex_cli_process_invocations": len(rows) + 1,
        "p50_ms": statistics.median(times),
        "p95_ms": p95,
        "range_ms": [min(times), max(times)],
        "budget_ms": args.budget_ms,
        "budget_pass": p95 <= args.budget_ms and all(row["correct_response"] for row in rows),
        "machine": {"cpu_count": os.cpu_count(), "load_average": os.getloadavg()},
        "scope": "Read-only local Rex capability query; not factory runtime throughput or an improvement comparison.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "samples"}, indent=2))
    return 0 if report["budget_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
