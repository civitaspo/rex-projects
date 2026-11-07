#!/usr/bin/env python3
"""Prove fresh-list recovery after a lost Rex reply and a disconnected event stream."""

from __future__ import annotations

import argparse
import json
import secrets
import queue
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


def event_fields(value: Any) -> tuple[str | None, str | None, str | None]:
    """Return event type, session ID, and label from Rex's JSON event envelope."""
    found_type = found_session = found_label = None

    def visit(item: Any) -> None:
        nonlocal found_type, found_session, found_label
        if isinstance(item, dict):
            if isinstance(item.get("type"), str) and item["type"] == "session_label_changed":
                found_type = item["type"]
            for key in ("session_id", "label"):
                candidate = item.get(key)
                if isinstance(candidate, str):
                    if key == "session_id":
                        found_session = candidate
                    else:
                        found_label = candidate
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    return found_type, found_session, found_label


def stop_stream(stream: subprocess.Popen[str] | None, reader: threading.Thread | None) -> dict[str, Any]:
    """Stop and reap the event CLI, even when the scenario fails early."""
    if stream is None:
        return {"started": False, "reaped": True, "pipes_closed": True}
    if stream.poll() is None:
        stream.terminate()
        try:
            stream.wait(timeout=2)
        except subprocess.TimeoutExpired:
            stream.kill()
            stream.wait(timeout=2)
    for pipe in (stream.stdout, stream.stderr):
        if pipe is not None and not pipe.closed:
            pipe.close()
    if reader is not None:
        reader.join(timeout=2)
    return {
        "started": True,
        "exit_code": stream.returncode,
        "reaped": stream.poll() is not None,
        "reader_stopped": reader is None or not reader.is_alive(),
        "pipes_closed": all(pipe is None or pipe.closed for pipe in (stream.stdout, stream.stderr)),
    }


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
    stream: subprocess.Popen[str] | None = None
    stream_reader: threading.Thread | None = None
    stream_events: queue.Queue[Any] = queue.Queue(maxsize=256)
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
            stderr=subprocess.DEVNULL,
            text=True,
        )
        require(stream.stdout is not None, "missing event stream pipe")

        def read_events() -> None:
            try:
                for line in stream.stdout:
                    try:
                        stream_events.put(json.loads(line), timeout=args.timeout_seconds)
                    except json.JSONDecodeError as error:
                        stream_events.put(error)
                        return
                    except queue.Full:
                        return
            except (OSError, ValueError) as error:
                try:
                    stream_events.put(error, timeout=1)
                except queue.Full:
                    pass

        stream_reader = threading.Thread(target=read_events, daemon=True)
        stream_reader.start()

        # A successful CLI connection is not proof that event delivery is active.
        # Repeatedly mutate only this fixture-owned session until its uniquely
        # labelled change is observed on the stream.
        readiness_label = f"rex-projects-ready-{nonce}"
        readiness_deadline = time.monotonic() + args.timeout_seconds
        ready = False
        attempt = 0
        while time.monotonic() < readiness_deadline and not ready:
            attempt += 1
            candidate = f"{readiness_label}-{attempt}"
            rex.api("session.set_label", {"session_id": session_id, "label": candidate})
            attempt_deadline = min(readiness_deadline, time.monotonic() + 0.25)
            while time.monotonic() < attempt_deadline:
                try:
                    item = stream_events.get(timeout=min(0.05, attempt_deadline - time.monotonic()))
                except queue.Empty:
                    if stream.poll() is not None:
                        raise ProbeError("event stream exited before positive readiness")
                    continue
                if isinstance(item, BaseException):
                    raise ProbeError(f"event stream reader failed: {item}")
                event_kind, event_session, event_label = event_fields(item)
                if event_kind == "session_label_changed" and event_session == session_id and event_label == candidate:
                    ready = True
                    break
        require(ready, "event stream did not observe a uniquely labelled session rename before timeout")
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
            try:
                event = stream_events.get(timeout=min(0.1, event_deadline - time.monotonic()))
            except queue.Empty:
                if stream.poll() is not None:
                    raise ProbeError("event stream ended before the created-window event")
                continue
            if isinstance(event, BaseException):
                raise ProbeError(f"event stream reader failed: {event}")
            identifiers = json.dumps(event)
            if any(identifier and identifier in identifiers for identifier in expected_ids):
                event_type = event.get("payload", {}).get("event", {}).get("type")
                break
        require(event_type is not None, "event stream ended without the new resource identity")
        require(stream.poll() is None, "event stream exited before the explicit disconnect")
        stream_cleanup = stop_stream(stream, stream_reader)
        require(stream_cleanup["reaped"] and stream_cleanup["reader_stopped"] and stream_cleanup["pipes_closed"],
                f"event stream cleanup failed: {stream_cleanup!r}")

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
            "stream_cleanup": stream_cleanup,
            "fresh_listing_found_block": True,
            "block_id": matching[0]["block_id"],
            "original_session_preserved": True,
        }
    except (ProbeError, subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as error:
        receipt["error"] = f"{type(error).__name__}: {error}"
    finally:
        if stream is not None:
            try:
                stream_cleanup = stop_stream(stream, stream_reader)
                receipt.setdefault("cleanup", {})["event_stream"] = stream_cleanup
            except (OSError, subprocess.TimeoutExpired) as error:
                receipt.setdefault("cleanup", {})["event_stream"] = {
                    "error": f"{type(error).__name__}: {error}",
                    "reaped": stream.poll() is not None,
                }
        if client is not None and client.poll() is None:
            client.terminate()
            try:
                client.wait(timeout=2)
            except subprocess.TimeoutExpired:
                client.kill()
                client.wait(timeout=2)
        if session_id is None:
            try:
                possible = first_matching_session(rex, lost_reply_label)
                if possible is not None:
                    session_id = possible["session_id"]
            except (ProbeError, subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as error:
                receipt.setdefault("cleanup", {})["session_reconciliation_error"] = (
                    f"{type(error).__name__}: {error}"
                )
        if session_id is not None:
            try:
                # The readiness probe temporarily renames the fixture session.
                # Restore its discoverable label before teardown and verify
                # absence by that original unique label after the kill.
                rex.api("session.set_label", {"session_id": session_id, "label": lost_reply_label})
                result = rex.call("kill", session_id, check=False)
                receipt.setdefault("cleanup", {}).update({"session_id": session_id, "exit_code": result.returncode})
                if result.returncode != 0:
                    receipt["cleanup"]["session_cleanup_error"] = result.stderr.strip()
                after = first_matching_session(rex, lost_reply_label)
                receipt["cleanup"]["session_absent"] = after is None
            except (ProbeError, subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as error:
                receipt.setdefault("cleanup", {})["session_cleanup_error"] = f"{type(error).__name__}: {error}"
        try:
            (args.artifacts / "result.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        except OSError as error:
            receipt.setdefault("cleanup", {})["receipt_write_error"] = f"{type(error).__name__}: {error}"

    print(json.dumps(receipt, indent=2))
    return 0 if "error" not in receipt and receipt.get("cleanup", {}).get("session_absent") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
