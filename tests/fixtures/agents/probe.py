#!/usr/bin/env python3
"""Write a run-local atomic request/receipt and report markers/access only."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

MARKERS = (
    "REX_PROJECTS_CONTEXT",
    "REX_PROJECTS_AGENT",
    "REX_PROJECTS_PROJECT_ID",
    "REX_PROJECTS_ROLE",
    "REX_PROJECTS_RUN_ID",
    "REX_PROJECTS_TICKET_RUN_ID",
)


def atomic_json(path: Path, data: object) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".probe-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def marker_presence() -> dict[str, bool]:
    return {name: bool(os.environ.get(name)) for name in MARKERS}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mailbox", required=True, type=Path)
    args = parser.parse_args()

    mailbox = args.mailbox.resolve()
    request = mailbox / "request.json"
    receipt = mailbox / "receipt.json"
    request_body = {"request_id": "pr0-provider-probe-1", "kind": "diagnostic", "payload": {"write": "receipt"}}
    atomic_json(request, request_body)

    child = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("probe_descendant.py"))],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    descendant_markers = json.loads(child.stdout) if child.returncode == 0 else {}

    sentinel_paths = json.loads(os.environ.get("REX_PROJECTS_PROBE_SENTINELS", "[]"))
    sentinel_observations = []
    for raw_path in sentinel_paths:
        candidate = Path(raw_path)
        try:
            with candidate.open("r+b"):
                result = "write-open-allowed"
        except PermissionError:
            result = "denied"
        except OSError as error:
            result = "error:" + type(error).__name__
        sentinel_observations.append({"kind": candidate.name, "result": result})

    decision_path = mailbox / "human-decision.json"
    human_guard = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("human_decision_guard.py")), str(decision_path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    human_decision = {
        "rejected": human_guard.returncode == 77,
        "state_unchanged": not decision_path.exists(),
    }

    outcome = {
        "markers": marker_presence(),
        "descendant_markers": descendant_markers,
        "mailbox": {"request_written": request.is_file(), "receipt_written": True},
        "sentinel_write_open": sentinel_observations,
        "human_decision_guard": human_decision,
    }
    atomic_json(receipt, outcome)
    print(json.dumps(outcome, sort_keys=True))
    markers_present = all(marker_presence().values())
    return 0 if child.returncode == 0 and human_guard.returncode == 77 and not decision_path.exists() and markers_present else 1


if __name__ == "__main__":
    raise SystemExit(main())
