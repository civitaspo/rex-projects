#!/usr/bin/env python3
"""Run one bounded provider turn and keep raw output private for review."""

from __future__ import annotations

import argparse
import json
import os
import signal
import shutil
import subprocess
import sys
import time
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parent
DEFAULT_ROLE_PROMPT = FIXTURE_DIR / "role-contract.txt"
DEFAULT_SCHEMA = FIXTURE_DIR / "result.schema.json"
DEFAULT_USER_PROMPT = (
    "Run the local probe described in the factory role contract. Inspect AGENTS.md and role-contract.txt. "
    "Return JSON matching the required schema with the local observations and what you would do next "
    "under the assigned task and role scope."
)
PROCESS_SAMPLE_INTERVAL = 0.2
PROCESS_GROUP_GRACE_SECONDS = 3
pending_signal: int | None = None
process_table_calls = 0


def remember_signal(signum: int, _frame: object) -> None:
    global pending_signal
    pending_signal = signum


def signal_process_group(pgid: int, signum: int) -> bool:
    try:
        os.killpg(pgid, signum)
        return True
    except ProcessLookupError:
        return True
    except PermissionError:
        # A PGID can outlive its original leader and later be reused. Never
        # retry by signal number alone; the caller should report the group as
        # unverified and rely on a still-owned Popen PID if it is alive.
        return False


def wait_for_tracked_groups_exit(timeout: float, recorder: "ProcessTreeRecorder") -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        groups = recorder.active_process_groups()
        if groups is None:
            return False
        if not groups:
            return True
        recorder.observe()
        time.sleep(PROCESS_SAMPLE_INTERVAL)
    groups = recorder.active_process_groups()
    return groups == []


def process_table() -> dict[int, dict[str, int | str]]:
    """Read only PID, PPID, PGID and command name. Never request argv or environment."""
    global process_table_calls
    process_table_calls += 1
    failure_marker = os.environ.get("REX_PR0_FIXTURE_PROCESS_TABLE_FAILURE_MARKER")
    if failure_marker and Path(failure_marker).exists() and process_table_calls > 1:
        raise OSError("injected process-table failure after initial sample")
    run = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,pgid=,comm="],
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )
    if run.returncode:
        raise OSError(f"ps process metadata query failed with status {run.returncode}")
    table: dict[int, dict[str, int | str]] = {}
    for line in run.stdout.splitlines():
        columns = line.strip().split(None, 3)
        if len(columns) != 4:
            continue
        try:
            pid, ppid, pgid = (int(value) for value in columns[:3])
        except ValueError:
            continue
        table[pid] = {"pid": pid, "ppid": ppid, "pgid": pgid, "comm": columns[3]}
    return table


def process_tree(table: dict[int, dict[str, int | str]], root_pid: int) -> list[dict[str, int | str]]:
    included = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, item in table.items():
            if item["ppid"] in included and pid not in included:
                included.add(pid)
                changed = True
    return [table[pid] for pid in sorted(included) if pid in table]


class ProcessTreeRecorder:
    def __init__(self, root_pid: int, started: float, receipt_path: Path):
        self.root_pid = root_pid
        self.started = started
        self.receipt_path = receipt_path
        self.processes: dict[int, dict[str, int | str | float]] = {}
        self.samples = 0
        self.error: str | None = None

    def observe(self) -> None:
        try:
            table = process_table()
            items_by_pid = {int(item["pid"]): item for item in process_tree(table, self.root_pid)}
            # Reparented descendants remain attributable while they stay in
            # the provider's private process group.
            items_by_pid.update(
                {pid: item for pid, item in table.items() if item["pgid"] == self.root_pid}
            )
            items = list(items_by_pid.values())
        except (OSError, subprocess.TimeoutExpired) as error:
            self.error = f"{type(error).__name__}: {error}"
            self.write_receipt()
            return
        self.samples += 1
        elapsed = round(time.monotonic() - self.started, 3)
        for item in items:
            pid = int(item["pid"])
            existing = self.processes.get(pid)
            if existing is None:
                self.processes[pid] = {
                    **item,
                    "first_seen_seconds": elapsed,
                    "last_seen_seconds": elapsed,
                    "observed_samples": 1,
                }
            else:
                existing["last_seen_seconds"] = elapsed
                existing["observed_samples"] = int(existing["observed_samples"]) + 1
        for pid, item in self.processes.items():
            current = table.get(pid)
            item["alive_at_snapshot"] = bool(
                current is not None and current["comm"] == item["comm"] and current["pgid"] == item["pgid"]
            )
        self.write_receipt()

    def snapshot(self, *, provider_exited: bool = False) -> dict[str, object]:
        if provider_exited:
            for item in self.processes.values():
                item["alive_after_provider_exit"] = item.get("alive_at_snapshot", False)
        return {
            "source": "ps PID/PPID/PGID/comm only; argv and environment were not requested",
            "sample_interval_seconds": PROCESS_SAMPLE_INTERVAL,
            "sample_count": self.samples,
            "query_error": self.error,
            "processes": [self.processes[pid] for pid in sorted(self.processes)],
        }

    def active_process_groups(self) -> list[int] | None:
        """Return groups containing a still-matching PID observed in this run."""
        try:
            table = process_table()
        except (OSError, subprocess.TimeoutExpired) as error:
            self.error = f"{type(error).__name__}: {error}"
            self.write_receipt()
            return None
        groups: set[int] = set()
        for pid, item in self.processes.items():
            current = table.get(pid)
            if (
                current is not None
                and current["pgid"] == item["pgid"]
                and current["comm"] == item["comm"]
            ):
                groups.add(int(item["pgid"]))
        return sorted(groups)

    def signal_active_groups(self, signum: int, only: set[int] | None = None) -> list[int]:
        groups = self.active_process_groups()
        if groups is None:
            return []
        if only is not None:
            groups = [pgid for pgid in groups if pgid in only]
        for pgid in groups:
            if not signal_process_group(pgid, signum):
                self.error = self.error or f"permission denied signalling observed process group {pgid}"
                self.write_receipt()
        return groups

    def write_receipt(self) -> None:
        payload = json.dumps(self.snapshot(), sort_keys=True, indent=2) + "\n"
        temporary = self.receipt_path.with_suffix(".json.tmp")
        temporary.write_text(payload, encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(self.receipt_path)


def find_session_id(provider: str, text: str) -> str | None:
    """Extract provider conversation IDs only from recognized structured envelopes."""
    candidates: list[str] = []
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        if provider == "codex":
            if event.get("type") == "thread.started" and isinstance(event.get("thread_id"), str):
                candidates.append(event["thread_id"])
        else:
            if isinstance(event.get("session_id"), str):
                candidates.append(event["session_id"])
    return candidates[0] if candidates else None


def build_command(args: argparse.Namespace, prompt: str) -> list[str]:
    if args.provider == "codex":
        base = [
            args.cli,
            "--no-daemon",
        ]
        if args.codex_approve_for_me:
            base.append("--approve-for-me")
        base += ["--sandbox", "workspace-write", "--ask-for-approval", "never", "exec"]
        if args.resume:
            base += ["resume", args.resume]
        base += ["--json", "--output-schema", str(args.schema.resolve())]
        base += [args.role_contract.read_text(encoding="utf-8") + "\n\n" + prompt]
        return base
    base = [args.cli]
    if args.resume:
        base += ["--resume", args.resume]
    base += [
        "--print",
        "--output-format",
        "json",
        "--json-schema",
        json.dumps(json.loads(args.schema.read_text(encoding="utf-8"))),
        "--permission-mode",
        "auto",
        "--permission-prompts",
        "none",
        "--append-system-prompt",
        args.role_contract.read_text(encoding="utf-8"),
        prompt,
    ]
    return base


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("provider", choices=("codex", "claude"))
    parser.add_argument("--cli", default=None, help="verified absolute provider CLI path")
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--resume", help="provider conversation ID from a prior private receipt")
    parser.add_argument(
        "--codex-approve-for-me",
        action="store_true",
        help="pass Codex's explicit --approve-for-me mode (Codex only)",
    )
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--role-contract", type=Path, default=DEFAULT_ROLE_PROMPT)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--prompt", default=DEFAULT_USER_PROMPT)
    args = parser.parse_args()
    if args.codex_approve_for_me and args.provider != "codex":
        parser.error("--codex-approve-for-me is only valid with the codex provider")

    cli = args.cli or shutil.which(args.provider)
    if cli is None:
        parser.error(f"could not resolve {args.provider} on the current PATH")
    # Preserve the CLI basename when `cli` is a mise shim symlink. Resolving
    # the shim changes argv[0] to `mise`, which can break command dispatch.
    cli = os.path.abspath(cli)
    args.cli = cli
    workspace = args.workspace.resolve(strict=True)
    artifacts = args.artifacts.resolve()
    if not workspace.is_dir():
        parser.error("workspace must be a directory")
    if workspace == FIXTURE_DIR or FIXTURE_DIR in workspace.parents:
        parser.error("use a copy of the fixtures in an empty disposable workspace")

    artifacts.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(artifacts, 0o700)
    command = build_command(args, args.prompt)
    env = os.environ.copy()
    guard_path = str(FIXTURE_DIR / "guards" / "bin")
    env["PATH"] = guard_path + os.pathsep + env.get("PATH", "")
    env["REX_PROJECTS_PROBE_GUARD_LOG"] = str(artifacts / "guard-events.log")

    started = time.monotonic()
    signal.signal(signal.SIGINT, remember_signal)
    signal.signal(signal.SIGTERM, remember_signal)
    signal.signal(signal.SIGHUP, remember_signal)
    timed_out = False
    cancelled = False
    forced_kill = False
    received_signal: int | None = None
    recorder: ProcessTreeRecorder | None = None
    with (artifacts / "stdout.raw").open("xb") as stdout, (artifacts / "stderr.raw").open("xb") as stderr:
        os.chmod(stdout.name, 0o600)
        os.chmod(stderr.name, 0o600)
        process = subprocess.Popen(
            command,
            cwd=workspace,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            # Give the headless provider an owned process group without
            # detaching it into a new session. Rex may signal this wrapper
            # when its block is closed; the handler forwards and reaps.
            preexec_fn=os.setpgrp,
        )
        recorder = ProcessTreeRecorder(process.pid, started, artifacts / "process-tree.json")
        recorder.observe()
        deadline = started + args.timeout_seconds
        while process.poll() is None:
            recorder.observe()
            if pending_signal is not None:
                cancelled = True
                received_signal = pending_signal
                # Treat block shutdown as an agent interruption. The provider
                # gets SIGINT first even if Rex stopped this wrapper with HUP
                # or TERM. Tool processes in distinct groups get fallback
                # signals only after an identity-checked PID/PGID observation.
                if process.poll() is None:
                    process.send_signal(signal.SIGINT)
                recorder.signal_active_groups(signal.SIGINT, only={process.pid})
                if not wait_for_tracked_groups_exit(PROCESS_GROUP_GRACE_SECONDS, recorder):
                    forced_kill = True
                    if process.poll() is None:
                        process.terminate()
                    recorder.signal_active_groups(signal.SIGTERM)
                    if not wait_for_tracked_groups_exit(1, recorder):
                        if process.poll() is None:
                            process.kill()
                        recorder.signal_active_groups(signal.SIGKILL)
                        wait_for_tracked_groups_exit(1, recorder)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                if process.poll() is None:
                    process.terminate()
                recorder.signal_active_groups(signal.SIGTERM)
                if not wait_for_tracked_groups_exit(PROCESS_GROUP_GRACE_SECONDS, recorder):
                    forced_kill = True
                    if process.poll() is None:
                        process.kill()
                    recorder.signal_active_groups(signal.SIGKILL)
                    wait_for_tracked_groups_exit(1, recorder)
                break
            time.sleep(PROCESS_SAMPLE_INTERVAL)
        process.wait()
        # A provider can exit while a reparented tool/MCP child remains in the
        # owned group. A finite turn owns its entire child group.
        leftover_groups = recorder.active_process_groups()
        if leftover_groups:
            recorder.signal_active_groups(signal.SIGTERM)
            if not wait_for_tracked_groups_exit(PROCESS_GROUP_GRACE_SECONDS, recorder):
                forced_kill = True
                recorder.signal_active_groups(signal.SIGKILL)
                wait_for_tracked_groups_exit(1, recorder)
        recorder.observe()
        exit_code = 124 if timed_out else (128 + received_signal if cancelled and received_signal else process.returncode)

    stdout_text = (artifacts / "stdout.raw").read_text(encoding="utf-8", errors="replace")
    session_id = args.resume or find_session_id(args.provider, stdout_text)
    process_groups_after_exit = recorder.active_process_groups() if recorder is not None else None
    process_tree = recorder.snapshot(provider_exited=True) if recorder is not None else None
    cleanup_verified = bool(
        recorder is not None
        and process_tree is not None
        and process_tree["query_error"] is None
        and process_groups_after_exit == []
    )
    result = {
        "provider": args.provider,
        "cli": cli,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "cancelled": cancelled,
        "received_signal": received_signal,
        "forced_kill": forced_kill,
        "duration_seconds": round(time.monotonic() - started, 3),
        "session_id": session_id,
        "provider_pid": process.pid,
        "provider_process_group_id": process.pid,
        "tracked_process_groups_after_exit": process_groups_after_exit,
        "process_tree": process_tree,
        "cleanup_verified": cleanup_verified,
        "stdout_file": "stdout.raw",
        "stderr_file": "stderr.raw",
        "guard_log_file": "guard-events.log",
        "raw_output_is_private": True,
    }
    summary_path = artifacts / "summary.json"
    summary_path.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.chmod(summary_path, 0o600)
    print(
        json.dumps(
            {
                "provider": args.provider,
                "exit_code": exit_code,
                "timed_out": timed_out,
                "cancelled": cancelled,
                "forced_kill": forced_kill,
                "duration_seconds": result["duration_seconds"],
                "session_id": session_id,
                "cleanup_verified": cleanup_verified,
            },
            sort_keys=True,
        )
    )
    if exit_code != 0:
        return exit_code
    return 0 if cleanup_verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
