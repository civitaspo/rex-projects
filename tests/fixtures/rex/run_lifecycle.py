#!/usr/bin/env python3
"""Run the real Rex process lifecycle fixture against an explicit test server."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

FIXTURES = Path(__file__).resolve().parent


class ProbeError(RuntimeError):
    pass


class Rex:
    def __init__(self, server: str, timeout: float, transcript: Path):
        self.server = server
        self.timeout = timeout
        self.transcript = transcript
        self.counter = 0

    def call(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        self.counter += 1
        argv = ["rex", "--server", self.server, "--autostart=false", *args]
        result = subprocess.run(
            argv,
            text=True,
            capture_output=True,
            timeout=self.timeout,
            check=False,
        )
        entry = {
            "argv": argv,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        (self.transcript / f"{self.counter:03d}.json").write_text(
            json.dumps(entry, indent=2) + "\n", encoding="utf-8"
        )
        if check and result.returncode != 0:
            raise ProbeError(
                f"Rex command failed ({result.returncode}): {args!r}: {result.stderr.strip()}"
            )
        return result

    def api(self, session_id: str, method: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        encoded = json.dumps(args or {}, separators=(",", ":"))
        result = self.call("api", "call", "--session", session_id, method, encoded)
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ProbeError(f"Rex returned invalid JSON for {method}: {result.stdout!r}") from error
        if not isinstance(value, dict):
            raise ProbeError(f"Rex returned a non-object for {method}")
        return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProbeError(message)


def session_id_from(value: dict[str, Any]) -> str:
    session_id = value.get("session_id")
    if not isinstance(session_id, str) or not session_id.startswith("session:"):
        raise ProbeError(f"unexpected rex new response; no full session ID: {value!r}")
    return session_id


def block_ids_from_new(value: dict[str, Any]) -> tuple[str, str]:
    windows = value.get("initial_windows")
    if not isinstance(windows, list) or not windows:
        raise ProbeError(f"unexpected rex new response; initial_windows missing: {value!r}")
    blocks = windows[0].get("block_ids")
    if not isinstance(blocks, list) or not blocks or not isinstance(blocks[0], str):
        raise ProbeError(f"unexpected rex new response; initial block ID missing: {value!r}")
    return windows[0]["window_id"], blocks[0]


def wait_for_file(path: Path, seconds: float) -> dict[str, Any]:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        time.sleep(0.05)
    raise ProbeError(f"fixture did not become ready within {seconds:g}s: {path}")


def process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def process_state(rex: Rex, session_id: str, block_id: str) -> dict[str, Any]:
    return rex.api(session_id, "com.superlogical.terminal.process", {"block_id": block_id})


def wait_for_exit(rex: Rex, session_id: str, block_id: str, seconds: float) -> dict[str, Any]:
    deadline = time.monotonic() + seconds
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last = process_state(rex, session_id, block_id)
        if last.get("last_exit") is not None:
            return last
        time.sleep(0.05)
    raise ProbeError(f"process did not exit within {seconds:g}s: {last!r}")


def read_probe_output(rex: Rex, session_id: str, block_id: str) -> str:
    result = rex.call("capture", "--session", session_id, "--block", block_id, "--trim", "--unwrap")
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, help="Explicit disposable Rex server endpoint")
    parser.add_argument("--artifacts", required=True, type=Path, help="Directory for private receipts")
    parser.add_argument("--source-sha", required=True, help="Git SHA of the source under test")
    parser.add_argument("--expected-instance-id", help="Optional Rex instance ID guard before any mutation")
    parser.add_argument("--local-pid-namespace-confirmed", action="store_true",
                        help="Confirm this Rex server shares the local OS PID namespace used by os.kill checks")
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
    parser.add_argument("--ready-timeout-seconds", type=float, default=5.0)
    parser.add_argument("--hold-seconds", type=float, default=0.0, help="Keep the live ticket tab open for visual inspection")
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 60:
        parser.error("--timeout-seconds must be between 1 and 60")
    if not 1 <= args.ready_timeout_seconds <= 30:
        parser.error("--ready-timeout-seconds must be between 1 and 30")
    if not 0 <= args.hold_seconds <= 300:
        parser.error("--hold-seconds must be between 0 and 300")

    if not args.local_pid_namespace_confirmed:
        parser.error("--local-pid-namespace-confirmed is required because child PID checks use local os.kill")
    server_uri = urlparse(args.server)
    if server_uri.scheme != "unix" or not server_uri.path:
        parser.error("PID lifecycle checks require a local unix:// Rex endpoint")
    try:
        endpoint_mode = Path(server_uri.path).lstat().st_mode
    except OSError as error:
        parser.error(f"cannot inspect local Rex socket {server_uri.path!r}: {error}")
    if not stat.S_ISSOCK(endpoint_mode):
        parser.error("--server must name an existing local Unix socket")

    args.artifacts = args.artifacts.expanduser().resolve()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    transcripts = args.artifacts / "transcript"
    transcripts.mkdir(exist_ok=True)
    rex = Rex(args.server, args.timeout_seconds, transcripts)
    created_session: str | None = None
    session_label: str | None = None
    cleanup_error: str | None = None
    receipt: dict[str, Any] = {
        "source_sha": args.source_sha,
        "rex_server_endpoint": args.server,
        "local_pid_namespace_acknowledged": args.local_pid_namespace_confirmed,
        "observed_at_epoch_seconds": time.time(),
        "scenarios": {},
    }

    try:
        whoami = json.loads(rex.call("whoami", "--json").stdout)
        receipt["server_identity"] = {
            "endpoint": whoami.get("endpoint"),
            "instance_id": whoami.get("instance_id"),
            "host_id": whoami.get("host_id"),
            "rex_version": whoami.get("rex_version"),
        }
        require(whoami.get("endpoint") == args.server,
                f"connected endpoint does not exactly match requested disposable endpoint: {whoami.get('endpoint')!r}")
        if args.expected_instance_id:
            require(whoami.get("instance_id") == args.expected_instance_id,
                    "connected Rex instance does not match --expected-instance-id")

        nonce = secrets.token_hex(8)
        session_label = f"rex-projects-pr0-lifecycle-{nonce}"
        probe_lifetime = max(20, args.hold_seconds + args.ready_timeout_seconds
                             + args.timeout_seconds * 10 + 30)
        exact_args = ["space value", 'quote"value', "semi;literal", "dollar$(literal)"]
        argv_receipt = args.artifacts / "argv-receipt.json"
        argv_receipt.unlink(missing_ok=True)
        initial_layout = {
            "label": session_label,
            "initial_windows": [{
                "window_label": "PR0 lifecycle fixture",
                "layout": {
                    "block": {
                        "flavor": "com.superlogical.terminal.shell",
                        "label": "PR0 argv and exit probe",
                        "options": {
                            "shell": "none",
                            "login": False,
                            "command": [sys.executable, str(FIXTURES / "argv_exit_probe.py"),
                                        "37", str(argv_receipt), *exact_args],
                            "cwd": str(args.artifacts),
                            "exit": {"on_completion": False},
                        },
                    },
                },
            }],
        }
        layout_file = args.artifacts / "session-create.json"
        layout_file.write_text(json.dumps(initial_layout, indent=2) + "\n", encoding="utf-8")
        created = json.loads(rex.call("api", "call", "session.create", f"@{layout_file}").stdout)
        created_session = session_id_from(created)
        window_id, first_block = block_ids_from_new(created)
        receipt["created_session_id"] = created_session
        receipt["created_window_id"] = window_id
        receipt["created_block_ids"] = [first_block]

        first_exit = wait_for_exit(rex, created_session, first_block, args.ready_timeout_seconds)
        output = read_probe_output(rex, created_session, first_block)
        decoded = json.loads(argv_receipt.read_text(encoding="utf-8"))
        require(decoded["argv"] == exact_args, f"argv was altered: expected={exact_args!r}, actual={decoded['argv']!r}")
        require(decoded["exit_code"] == 37, f"fixture output exit code changed: {decoded!r}")
        require(first_exit.get("last_exit", {}).get("exit_code") == 37,
                f"Rex did not report the real nonzero child exit: {first_exit!r}")
        receipt["scenarios"]["argv_and_nonzero_exit"] = {
            "outcome": "PASS", "expected_argv": exact_args, "observed_output": decoded,
            "terminal_process": first_exit, "unwrapped_terminal_capture": output,
        }

        ready_file = args.artifacts / "waiting-child-ready.json"
        stop_file = args.artifacts / "waiting-child-stop"
        ready_file.unlink(missing_ok=True)
        stop_file.unlink(missing_ok=True)
        split = rex.api(created_session, "session.new_split", {
            "anchor_id": first_block,
            "direction": "horizontal",
            "side": "after",
            "focus": True,
            "layout": {
                "block": {
                    "flavor": "com.superlogical.terminal.shell",
                    "label": "PR0 bounded child",
                    "options": {
                        "shell": "none",
                        "login": False,
                        "command": [sys.executable, str(FIXTURES / "wait_probe.py"),
                                    "--ready-file", str(ready_file), "--stop-file", str(stop_file),
                                    "--timeout-seconds", str(probe_lifetime)],
                        "cwd": str(args.artifacts),
                        "exit": {"on_completion": False},
                    },
                },
            },
        })
        child_blocks = split.get("block_ids")
        require(isinstance(child_blocks, list) and child_blocks and isinstance(child_blocks[0], str),
                f"Rex returned no split block ID: {split!r}")
        wait_block = child_blocks[0]
        receipt["created_block_ids"].append(wait_block)
        child_ready = wait_for_file(ready_file, args.ready_timeout_seconds)
        child_pid = child_ready.get("pid")
        require(isinstance(child_pid, int), f"waiting child did not report its PID: {child_ready!r}")

        view = rex.api(created_session, "session.view")
        window_ids = [item.get("window_id") for item in view.get("windows", [])]
        require(window_id in window_ids, f"ticket tab disappeared from view: {view!r}")
        listed = rex.api(created_session, "session.list_blocks").get("blocks", [])
        in_window = [
            block.get("block_id") for block in listed
            if block.get("window_id") == window_id and block.get("placement") == "placed"
        ]
        require(first_block in in_window and wait_block in in_window,
                f"successive/concurrent role blocks are not in one ticket window: {listed!r}")

        rex.api(created_session, "session.focus_block", {"block_id": wait_block})
        focused = rex.api(created_session, "session.view")
        focused_window = next((item for item in focused.get("windows", [])
                               if item.get("window_id") == window_id), {})
        require(focused_window.get("focused_block_id") == wait_block,
                f"dashboard focus did not focus selected block: {focused!r}")
        zoom_on = rex.api(created_session, "session.zoom_block", {"block_id": wait_block, "zoom": True})
        require(zoom_on.get("zoomed") is True, f"zoom on failed: {zoom_on!r}")
        zoom_off = rex.api(created_session, "session.zoom_block", {"block_id": wait_block, "zoom": False})
        require(zoom_off.get("zoomed") is False, f"zoom off failed: {zoom_off!r}")
        receipt["scenarios"]["same_window_focus_zoom"] = {
            "outcome": "PASS", "window_id": window_id, "block_ids": in_window,
            "focused_block_id": focused_window.get("focused_block_id"),
            "zoom_on": zoom_on, "zoom_off": zoom_off,
        }
        receipt["scenarios"]["child_started"] = {"outcome": "PASS", "pid": child_pid, "block_id": wait_block}

        if args.hold_seconds:
            receipt["visual_inspection_hold_seconds"] = args.hold_seconds
            (args.artifacts / "live-session.json").write_text(
                json.dumps({"session_id": created_session, "window_id": window_id,
                            "block_ids": receipt["created_block_ids"], "child_pid": child_pid}, indent=2) + "\n",
                encoding="utf-8",
            )
            time.sleep(args.hold_seconds)

        stop_file.touch()
        child_exit = wait_for_exit(rex, created_session, wait_block, args.ready_timeout_seconds)
        require(child_exit.get("last_exit", {}).get("exit_code") == 0,
                f"stop marker did not end child cleanly: {child_exit!r}")
        receipt["scenarios"]["bounded_child_exit"] = {"outcome": "PASS", "process": child_exit}

        close_ready_file = args.artifacts / "block-close-child-ready.json"
        close_stop_file = args.artifacts / "block-close-child-stop"
        close_ready_file.unlink(missing_ok=True)
        close_stop_file.unlink(missing_ok=True)
        close_split = rex.api(created_session, "session.new_split", {
            "anchor_id": first_block,
            "direction": "vertical",
            "side": "before",
            "focus": True,
            "layout": {
                "block": {
                    "flavor": "com.superlogical.terminal.shell",
                    "label": "PR0 block-close child",
                    "options": {
                        "shell": "none",
                        "login": False,
                        "command": [sys.executable, str(FIXTURES / "wait_probe.py"),
                                    "--ready-file", str(close_ready_file),
                                    "--stop-file", str(close_stop_file),
                                    "--timeout-seconds", str(probe_lifetime)],
                        "cwd": str(args.artifacts),
                        "exit": {"on_completion": False},
                    },
                },
            },
        })
        close_blocks = close_split.get("block_ids")
        require(isinstance(close_blocks, list) and close_blocks and isinstance(close_blocks[0], str),
                f"Rex returned no block-close child ID: {close_split!r}")
        close_block = close_blocks[0]
        receipt["created_block_ids"].append(close_block)
        close_ready = wait_for_file(close_ready_file, args.ready_timeout_seconds)
        close_pid = close_ready.get("pid")
        require(isinstance(close_pid, int), f"block-close child did not report its PID: {close_ready!r}")
        require(process_alive(close_pid), f"block-close child PID {close_pid} exited before block.close")

        rex.api(created_session, "block.close", {"block_id": close_block})
        closed_blocks = rex.api(created_session, "session.list_blocks").get("blocks", [])
        require(all(item.get("block_id") != close_block for item in closed_blocks),
                f"closing the owned child block did not remove it: {closed_blocks!r}")
        deadline = time.monotonic() + args.ready_timeout_seconds
        while process_alive(close_pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        require(not process_alive(close_pid), f"block.close left child PID {close_pid} alive")
        receipt["scenarios"]["owned_block_close"] = {
            "outcome": "PASS", "block_id": close_block, "child_pid": close_pid,
            "was_alive_before_close": True, "alive_after_close": False,
        }

        session_child_ready = args.artifacts / "session-child-ready.json"
        session_child_stop = args.artifacts / "session-child-stop"
        session_child_ready.unlink(missing_ok=True)
        session_child_stop.unlink(missing_ok=True)
        session_split = rex.api(created_session, "session.new_split", {
            "anchor_id": first_block,
            "direction": "vertical",
            "side": "after",
            "focus": True,
            "layout": {
                "block": {
                    "flavor": "com.superlogical.terminal.shell",
                    "label": "PR0 session-destroy child",
                    "options": {
                        "shell": "none",
                        "login": False,
                        "command": [sys.executable, str(FIXTURES / "wait_probe.py"),
                                    "--ready-file", str(session_child_ready),
                                    "--stop-file", str(session_child_stop), "--timeout-seconds", str(probe_lifetime)],
                        "cwd": str(args.artifacts),
                        "exit": {"on_completion": False},
                    },
                },
            },
        })
        session_child_blocks = session_split.get("block_ids")
        require(isinstance(session_child_blocks, list) and session_child_blocks
                and isinstance(session_child_blocks[0], str),
                f"Rex returned no session-destroy child block: {session_split!r}")
        session_child_block = session_child_blocks[0]
        receipt["created_block_ids"].append(session_child_block)
        session_child = wait_for_file(session_child_ready, args.ready_timeout_seconds)
        session_child_pid = session_child.get("pid")
        require(isinstance(session_child_pid, int), f"session child did not report its PID: {session_child!r}")
        require(process_alive(session_child_pid),
                f"session child PID {session_child_pid} exited before session destruction")

        rex.call("kill", created_session)
        created_session = None
        deadline = time.monotonic() + args.ready_timeout_seconds
        while process_alive(session_child_pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        require(not process_alive(session_child_pid),
                f"Rex session destruction left child PID {session_child_pid} alive")
        receipt["scenarios"]["session_destroys_owned_child"] = {
            "outcome": "PASS", "child_pid": session_child_pid, "alive_after_session_destroy": False,
        }
        remaining = json.loads(rex.call("ls", "--json").stdout)
        sessions = remaining.get("sessions", []) if isinstance(remaining, dict) else remaining
        require(not any(item.get("session_id") == receipt["created_session_id"] for item in sessions),
                f"owned session remains after rex kill: {remaining!r}")
        receipt["scenarios"]["owned_session_cleanup"] = {"outcome": "PASS", "session_absent": True}
    except (ProbeError, subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as error:
        receipt["error"] = f"{type(error).__name__}: {error}"
    finally:
        if created_session is None and session_label is not None:
            try:
                listing = json.loads(rex.call("ls", "--json").stdout)
                sessions = listing.get("sessions", []) if isinstance(listing, dict) else listing
                matches = [item for item in sessions if item.get("label") == session_label]
                if len(matches) == 1 and isinstance(matches[0].get("session_id"), str):
                    created_session = matches[0]["session_id"]
                    receipt.setdefault("cleanup", {})["reconciled_after_lost_create_reply"] = True
                elif matches:
                    cleanup_error = f"ambiguous fixture session label matched {len(matches)} sessions"
                else:
                    receipt.setdefault("cleanup", {})["session_absent"] = True
            except (ProbeError, subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as error:
                cleanup_error = f"could not reconcile fixture session after create: {type(error).__name__}: {error}"
        if created_session is not None:
            try:
                rex.call("kill", created_session, check=False)
                receipt["cleanup_attempted_for_created_session"] = created_session
            except Exception as error:  # best effort, never target an unknown resource
                cleanup_error = f"{type(error).__name__}: {error}"
        receipt["cleanup_error"] = cleanup_error
        receipt["completed_at_epoch_seconds"] = time.time()
        final = args.artifacts / "result.json"
        final.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")

    print(json.dumps(receipt, indent=2))
    return 0 if not receipt.get("error") and not cleanup_error else 1


if __name__ == "__main__":
    raise SystemExit(main())
