#!/usr/bin/env python3
"""Prove fresh-list recovery after a lost Rex reply and a disconnected event stream."""

from __future__ import annotations

import argparse
import json
import secrets
import select
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any


class ProbeError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProbeError(message)


class Rex:
    def __init__(self, server: str, timeout: float):
        self.server = server
        self.timeout = timeout

    def call(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["rex", "--server", self.server, "--autostart=false", "--timeout", f"{self.timeout}s", *args],
            capture_output=True,
            text=True,
            timeout=self.timeout + 2,
            check=False,
        )
        if check and result.returncode != 0:
            raise ProbeError(f"Rex command failed ({result.returncode}): {args!r}: {result.stderr.strip()}")
        return result

    def api(self, method: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        argv = ["api", "call", method]
        if args is not None:
            argv.append(json.dumps(args, separators=(",", ":")))
        result = self.call(*argv)
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ProbeError(f"Rex returned invalid JSON for {method}") from error
        require(isinstance(value, dict), f"Rex returned a non-object for {method}")
        return value


def first_matching_session(rex: Rex, label: str) -> dict[str, str] | None:
    result = json.loads(rex.call("ls", "--json").stdout)
    sessions = result.get("sessions", []) if isinstance(result, dict) else result
    matches = [item for item in sessions if item.get("label") == label]
    require(len(matches) <= 1, f"fresh listing found duplicate fixture labels: {matches!r}")
    return matches[0] if matches else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, help="Explicit disposable Rex server endpoint")
    parser.add_argument("--expected-instance-id", required=True, help="Refuse to mutate another Rex instance")
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=8)
    args = parser.parse_args()
    if not 2 <= args.timeout_seconds <= 30:
        parser.error("--timeout-seconds must be between 2 and 30")

    args.artifacts.mkdir(parents=True, exist_ok=True)
    rex = Rex(args.server, args.timeout_seconds)
    nonce = secrets.token_hex(8)
    lost_reply_label = f"rex-projects-pr0-reply-{nonce}"
    session_id: str | None = None
    client: subprocess.Popen[bytes] | None = None
    receipt: dict[str, Any] = {"source_sha": args.source_sha, "scenarios": {}}
    try:
        whoami = json.loads(rex.call("whoami", "--json").stdout)
        require(whoami.get("endpoint") == args.server, "connected to an unexpected Rex endpoint")
        require(whoami.get("instance_id") == args.expected_instance_id,
                "connected to an unexpected Rex instance")
        receipt["server"] = {"instance_id": whoami["instance_id"], "version": whoami.get("rex_version")}

        layout = {
            "label": lost_reply_label,
            "initial_windows": [{
                "window_label": f"reply-{nonce}",
                "layout": {"block": {
                    "flavor": "com.superlogical.terminal.shell",
                    "label": f"reply-child-{nonce}",
                    "options": {
                        "shell": "none",
                        "login": False,
                        "command": ["/bin/sleep", "60"],
                        "exit": {"on_completion": False},
                    },
                }},
            }],
        }
        command = ["rex", "--server", args.server, "--autostart=false", "--timeout",
                   f"{args.timeout_seconds}s", "api", "call", "session.create",
                   json.dumps(layout, separators=(",", ":"))]
        client = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        require(client.stdout is not None and client.stderr is not None, "missing captured CLI streams")
        received = bytearray()
        read_error: list[BaseException] = []

        def truncate_reply() -> None:
            try:
                first_byte = client.stdout.read(1)
                received.extend(first_byte)
                client.stdout.close()
            except BaseException as error:
                read_error.append(error)

        reader = threading.Thread(target=truncate_reply, daemon=True)
        reader.start()
        return_code = client.wait(timeout=args.timeout_seconds + 2)
        reader.join(timeout=2)
        require(not reader.is_alive(), "reply-reader thread did not stop")
        require(not read_error, f"reply-reader failed: {read_error!r}")
        client.stderr.close()
        require(len(received) == 1, f"expected an intentionally truncated reply, received {len(received)} bytes")
        try:
            json.loads(received)
        except json.JSONDecodeError:
            pass
        else:
            raise ProbeError("the intentionally truncated reply was unexpectedly valid JSON")

        discovered = first_matching_session(rex, lost_reply_label)
        require(discovered is not None, "fresh listing did not find the session after the reply was truncated")
        session_id = discovered["session_id"]
        require(isinstance(session_id, str) and session_id.startswith("session:"),
                "fresh listing returned no full session ID")
        require(return_code == 0, f"Rex CLI returned {return_code} after writing only one response byte")
        require(first_matching_session(rex, lost_reply_label) == discovered,
                "reconciliation changed between fresh listings; do not retry the create")
        blocks = rex.api("session.list_blocks", {"session_id": session_id}).get("blocks", [])
        require(len(blocks) == 1 and blocks[0].get("label") == f"reply-child-{nonce}",
                f"reconciled session did not contain its one expected child block: {blocks!r}")
        receipt["scenarios"]["lost_create_reply"] = {
            "outcome": "PASS",
            "client_received_bytes": len(received),
            "client_exit_code": return_code,
            "server_resource_reconciled_by_unique_label": True,
            "no_create_retry": True,
            "matching_sessions": 1,
            "session_id": session_id,
            "block_id": blocks[0]["block_id"],
        }

        stream = subprocess.Popen(
            ["rex", "--server", args.server, "--autostart=false", "--timeout",
             f"{args.timeout_seconds}s", "events", "--session", session_id, "--json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        require(stream.stdout is not None and stream.stderr is not None, "missing event stream pipes")
        time.sleep(0.2)
        require(stream.poll() is None, "event stream exited before the server-side mutation")

        added_label = f"after-disconnect-{nonce}"
        added = rex.api("session.new_window", {
            "session_id": session_id,
            "focus": False,
            "window_label": f"window-{nonce}",
            "layout": {"block": {
                "flavor": "com.superlogical.terminal.shell",
                "label": added_label,
                "options": {
                    "shell": "none",
                    "login": False,
                    "command": ["/bin/sleep", "60"],
                    "exit": {"on_completion": False},
                },
            }},
        })
        expected_ids = (added.get("window_id"), added.get("block_ids", [None])[0])
        event_type = None
        event_deadline = time.monotonic() + args.timeout_seconds
        while time.monotonic() < event_deadline:
            readable, _, _ = select.select([stream.stdout], [], [], max(0, event_deadline - time.monotonic()))
            require(readable, "event stream did not receive the created-window event")
            event_line = stream.stdout.readline()
            require(event_line, "event stream ended before the created-window event")
            try:
                event = json.loads(event_line)
            except json.JSONDecodeError as error:
                raise ProbeError("event stream produced invalid JSON") from error
            identifiers = json.dumps(event)
            if any(identifier and identifier in identifiers for identifier in expected_ids):
                event_type = event.get("payload", {}).get("event", {}).get("type")
                break
        require(event_type is not None, "event stream ended without the new resource identity")
        require(stream.poll() is None, "event stream exited before the explicit disconnect")
        stream.terminate()
        stream.wait(timeout=3)
        stream.stdout.close()
        stream.stderr.close()

        fresh_blocks = rex.api("session.list_blocks", {"session_id": session_id}).get("blocks", [])
        matching = [item for item in fresh_blocks if item.get("label") == added_label]
        require(len(matching) == 1, f"fresh listing did not recover the block after stream disconnect: {fresh_blocks!r}")
        require(matching[0].get("block_id") == added.get("block_ids", [None])[0],
                "fresh listing block identity disagreed with the acknowledged create result")
        receipt["scenarios"]["event_stream_disconnect"] = {
            "outcome": "PASS",
            "created_resource_event_received": True,
            "event_type": event_type,
            "stream_exit_code": stream.returncode,
            "fresh_listing_found_block": True,
            "block_id": matching[0]["block_id"],
            "original_session_preserved": True,
        }
    except (ProbeError, subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as error:
        receipt["error"] = f"{type(error).__name__}: {error}"
    finally:
        if client is not None and client.poll() is None:
            client.terminate()
            try:
                client.wait(timeout=2)
            except subprocess.TimeoutExpired:
                client.kill()
                client.wait(timeout=2)
        if session_id is None:
            possible = first_matching_session(rex, lost_reply_label)
            if possible is not None:
                session_id = possible["session_id"]
        if session_id is not None:
            result = rex.call("kill", session_id, check=False)
            receipt["cleanup"] = {"session_id": session_id, "exit_code": result.returncode}
            after = first_matching_session(rex, lost_reply_label)
            receipt["cleanup"]["session_absent"] = after is None
        (args.artifacts / "result.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")

    print(json.dumps(receipt, indent=2))
    return 0 if "error" not in receipt and receipt.get("cleanup", {}).get("session_absent") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
