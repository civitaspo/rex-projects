#!/usr/bin/env python3
"""Run the deterministic Worker payload in one disposable real Rex session."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

REX_FIXTURES = Path(__file__).resolve().parents[1] / "rex"
sys.path.insert(0, str(REX_FIXTURES))
from run_lifecycle import (  # noqa: E402
    ProbeError,
    Rex,
    block_ids_from_new,
    read_probe_output,
    session_id_from,
    wait_for_exit,
)

FIXTURE_DIR = Path(__file__).resolve().parent
from deterministic_agent import CHANGE  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProbeError(message)


def inside(root: Path, path: Path) -> Path:
    resolved = path.expanduser().resolve(strict=False)
    if resolved != root and root not in resolved.parents:
        raise ProbeError(f"fixture path is outside the explicit root: {resolved}")
    return resolved


def redact_user_metadata(value: object) -> object:
    if isinstance(value, dict):
        return {key: redact_user_metadata(item) for key, item in value.items()
                if key not in {"account", "principal", "home", "user", "user_id", "pid"}}
    if isinstance(value, list):
        return [redact_user_metadata(item) for item in value]
    if isinstance(value, str):
        return value.replace(str(Path.home()), "$HOME")
    return value


def sanitize_transcript(directory: Path) -> None:
    for path in directory.rglob("*.json"):
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if "argv" in entry and isinstance(entry.get("stdout"), str):
            for field in ("stdout", "stderr"):
                raw = entry.get(field)
                if not isinstance(raw, str):
                    continue
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                entry[field] = json.dumps(redact_user_metadata(parsed), sort_keys=True)
        path.write_text(json.dumps(redact_user_metadata(entry), indent=2) + "\n", encoding="utf-8")
        os.chmod(path, 0o600)


def verify_worker_output(worktree: Path, ticket_id: str, receipt: dict) -> str:
    require(receipt.get("ticket_id") == ticket_id,
            "Worker receipt is not bound to the requested fixture ticket")
    require(receipt.get("outcome") == "completed", "Worker did not complete")
    content = (worktree / "src/acceptance-fixture.txt").read_bytes()
    actual_digest = hashlib.sha256(content).hexdigest()
    expected_digest = hashlib.sha256(CHANGE.encode("utf-8")).hexdigest()
    require(actual_digest == expected_digest,
            "worktree file bytes differ from the deterministic fixture payload")
    require(receipt.get("content_sha256") == actual_digest,
            "Worker receipt digest does not match independently hashed file bytes")
    return actual_digest


def cleanup_owned_session(rex: Rex, session_label: str, session_id: str | None,
                          identity_verified: bool, result: dict[str, object]) -> None:
    if not identity_verified:
        result["cleanup_skipped"] = "Rex endpoint and instance identity were not verified"
        result["cleanup_error"] = "no cleanup request was sent to an unverified Rex server"
        return
    sessions = json.loads(rex.call("ls", "--json").stdout)
    sessions = sessions.get("sessions", []) if isinstance(sessions, dict) else sessions
    matches = [item for item in sessions if item.get("label") == session_label]
    if session_id is None and len(matches) == 1:
        session_id = matches[0].get("session_id")
        result["reconciled_session_after_create_reply_loss"] = True
    if session_id:
        rex.call("kill", session_id, check=False)
        result["cleanup_session_id"] = session_id
        after_kill = json.loads(rex.call("ls", "--json").stdout)
        after_sessions = after_kill.get("sessions", []) if isinstance(after_kill, dict) else after_kill
        if any(item.get("session_id") == session_id for item in after_sessions):
            result["cleanup_error"] = "owned fixture session remains after rex kill"
    elif matches:
        result["cleanup_error"] = "ambiguous fixture session label; left sessions untouched"
    else:
        result["cleanup_session_absent"] = True


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, help="Explicit disposable local Rex server endpoint")
    parser.add_argument("--expected-instance-id", required=True)
    parser.add_argument("--fixture-root", required=True, type=Path)
    parser.add_argument("--worktree", required=True, type=Path)
    parser.add_argument("--ticket-id", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-dirty", action="store_true",
                        help="Record that the fixture driver was run from a dirty source worktree")
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 60:
        parser.error("--timeout-seconds must be between 1 and 60")
    server_uri = urlparse(args.server)
    if server_uri.scheme != "unix" or not server_uri.path:
        parser.error("--server must be an explicit local unix:// endpoint")
    try:
        if not stat.S_ISSOCK(Path(server_uri.path).lstat().st_mode):
            parser.error("--server must name an existing Unix socket")
    except OSError as error:
        parser.error(f"cannot inspect --server socket: {error}")

    root = args.fixture_root.expanduser().resolve(strict=True)
    worktree = inside(root, args.worktree)
    require(worktree.is_dir() and (worktree / ".git").exists(),
            "--worktree must be an initialized Git working tree beneath --fixture-root")
    status = subprocess.run(["git", "status", "--porcelain"], cwd=worktree,
                            capture_output=True, text=True, timeout=10, check=False)
    require(status.returncode == 0 and not status.stdout.strip(),
            "deterministic Worker requires a clean disposable worktree")

    artifacts = root / "rex-agent-run"
    artifacts.mkdir(mode=0o700, exist_ok=False)
    os.chmod(artifacts, 0o700)
    transcript = artifacts / "transcript"
    transcript.mkdir(mode=0o700)
    receipt_path = inside(root, artifacts / "worker-receipt.json")
    layout_path = artifacts / "session-create.json"
    rex = Rex(args.server, args.timeout_seconds, transcript)
    session_label = f"rex-projects-e2e-worker-{secrets.token_hex(8)}"
    session_id: str | None = None
    identity_verified = False
    result: dict[str, object] = {
        "schema_version": 1,
        "source_sha": args.source_sha,
        "source_dirty": args.source_dirty,
        "rex_endpoint": args.server,
        "expected_instance_id": args.expected_instance_id,
        "session_label": session_label,
        "outcome": "INCOMPLETE",
        "full_project_flow_pass": False,
    }
    try:
        whoami = json.loads(rex.call("whoami", "--json").stdout)
        require(whoami.get("endpoint") == args.server, "Rex endpoint differs from the explicit test server")
        require(whoami.get("instance_id") == args.expected_instance_id,
                "Rex instance differs from --expected-instance-id")
        identity_verified = True
        create_layout = {
            "label": session_label,
            "initial_windows": [{
                "window_label": "E2E deterministic Worker",
                "layout": {"block": {
                    "flavor": "com.superlogical.terminal.shell",
                    "label": "Deterministic Worker fixture",
                    "options": {
                        "shell": "none", "login": False,
                        "command": [sys.executable, str(FIXTURE_DIR / "deterministic_agent.py"),
                                    "--worktree", str(worktree), "--receipt", str(receipt_path),
                                    "--ticket-id", args.ticket_id],
                        "cwd": str(worktree),
                        "exit": {"on_completion": False},
                    },
                }},
            }],
        }
        layout_path.write_text(json.dumps(create_layout, indent=2) + "\n", encoding="utf-8")
        os.chmod(layout_path, 0o600)
        created = json.loads(rex.call("api", "call", "session.create", f"@{layout_path}").stdout)
        session_id = session_id_from(created)
        window_id, block_id = block_ids_from_new(created)
        process = wait_for_exit(rex, session_id, block_id, args.timeout_seconds)
        require(process.get("last_exit", {}).get("exit_code") == 0,
                f"Rex did not report a successful Worker process exit: {process!r}")
        process_summary = {"last_exit": {"exit_code": process["last_exit"]["exit_code"]}}
        worker_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        actual_digest = verify_worker_output(worktree, args.ticket_id, worker_receipt)
        observed_head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=worktree,
                                       capture_output=True, text=True, timeout=10, check=False)
        require(observed_head.returncode == 0, "cannot observe fixture worktree HEAD")
        resulting_status = subprocess.run(["git", "status", "--porcelain"], cwd=worktree,
                                          capture_output=True, text=True, timeout=10, check=False)
        require(resulting_status.returncode == 0, "cannot observe fixture worktree changes")
        result.update({"outcome": "PASS", "session_id": session_id, "window_id": window_id,
                       "block_id": block_id, "process": process_summary,
                       "observed_content_sha256": actual_digest,
                       "worker_receipt": worker_receipt, "worktree_head": observed_head.stdout.strip(),
                       "worktree_status": resulting_status.stdout,
                       "terminal_capture": read_probe_output(rex, session_id, block_id),
                       "note": "Only the deterministic payload's real Rex transport passed; full Project flow is not claimed."})
    except (ProbeError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        try:
            cleanup_owned_session(rex, session_label, session_id, identity_verified, result)
        except Exception as error:
            result["cleanup_error"] = f"{type(error).__name__}: {error}"
        sanitize_transcript(transcript)
        result["completed_at_epoch_seconds"] = time.time()
        if result.get("cleanup_error"):
            result["outcome"] = "FAILED"
        result_path = artifacts / "result.json"
        result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        os.chmod(result_path, 0o600)

    print(json.dumps(result, indent=2))
    return 0 if result.get("outcome") == "PASS" and "cleanup_error" not in result else 1


if __name__ == "__main__":
    raise SystemExit(main())
