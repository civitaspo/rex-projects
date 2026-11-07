#!/usr/bin/env python3
"""Verify the launcher forwards cancellation to its owned provider group."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parent
RUNNER = FIXTURE_DIR / "run_probe.py"
FAKE_PROVIDER = FIXTURE_DIR / "cancel_group_child.py"


def process_table() -> dict[int, tuple[int, int, str]]:
    run = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,pgid=,comm="],
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )
    if run.returncode:
        raise RuntimeError("ps process metadata query failed")
    result: dict[int, tuple[int, int, str]] = {}
    for line in run.stdout.splitlines():
        parts = line.strip().split(None, 3)
        if len(parts) == 4:
            try:
                result[int(parts[0])] = (int(parts[1]), int(parts[2]), parts[3])
            except ValueError:
                continue
    return result


def wait_for_pids_to_exit(pids: set[int], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        live = set(process_table()) & pids
        if not live:
            return True
        time.sleep(0.1)
    return not (set(process_table()) & pids)



def cleanup_launcher_and_children(launcher: subprocess.Popen[bytes], owned_groups: set[int]) -> bool:
    observable = True
    try:
        table = process_table()
        descendants = {launcher.pid}
        changed = True
        while changed:
            changed = False
            for pid, (ppid, _pgid, _comm) in table.items():
                if ppid in descendants and pid not in descendants:
                    descendants.add(pid)
                    changed = True
        owned_groups.update(
            pgid for pid, (_ppid, pgid, _comm) in table.items()
            if pid in descendants and pgid != os.getpgrp()
        )
    except (OSError, subprocess.TimeoutExpired):
        observable = False

    if launcher.poll() is None:
        launcher.send_signal(signal.SIGINT)
        try:
            launcher.wait(timeout=3)
        except subprocess.TimeoutExpired:
            launcher.terminate()
            try:
                launcher.wait(timeout=1)
            except subprocess.TimeoutExpired:
                launcher.kill()
                launcher.wait(timeout=1)

    owned_groups.discard(os.getpgrp())
    for signum in (signal.SIGTERM, signal.SIGKILL):
        for pgid in owned_groups:
            try:
                os.killpg(pgid, signum)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + (0.5 if signum == signal.SIGTERM else 1)
        while time.monotonic() < deadline:
            try:
                live_groups = {item[1] for item in process_table().values()} & owned_groups
            except (OSError, subprocess.TimeoutExpired):
                return False
            if not live_groups:
                return observable
            time.sleep(0.1)
    try:
        return observable and not ({item[1] for item in process_table().values()} & owned_groups)
    except (OSError, subprocess.TimeoutExpired):
        return False


def main() -> int:
    valid_args = len(sys.argv) in {2, 3} and sys.argv[1] in {"SIGINT", "SIGTERM", "SIGHUP"}
    inject_query_failure = len(sys.argv) == 3 and sys.argv[2] == "--inject-ps-failure-after-first-sample"
    inject_receipt_failure = len(sys.argv) == 3 and sys.argv[2] == "--inject-receipt-write-failure"
    if not valid_args or (len(sys.argv) == 3 and not (inject_query_failure or inject_receipt_failure)):
        raise SystemExit(
            "usage: run_cancel_group_probe.py SIGINT|SIGTERM|SIGHUP "
            "[--inject-ps-failure-after-first-sample|--inject-receipt-write-failure]"
        )
    requested_signal = getattr(signal, sys.argv[1])
    with tempfile.TemporaryDirectory(prefix="rex-projects-pr0-cancel-") as temporary:
        root = Path(temporary)
        workspace = root / "workspace"
        artifacts = root / "artifacts"
        workspace.mkdir()
        ready_receipt = root / "child.json"
        failure_marker = root / "fail-process-table"
        env = os.environ.copy()
        env["REX_PR0_CANCEL_CHILD_RECEIPT"] = str(ready_receipt)
        if inject_query_failure:
            env["REX_PR0_FIXTURE_PROCESS_TABLE_FAILURE_MARKER"] = str(failure_marker)
        if inject_receipt_failure:
            env["REX_PR0_FIXTURE_RECEIPT_FAILURE_MARKER"] = str(failure_marker)
        with (root / "launcher.stdout").open("wb") as stdout, (root / "launcher.stderr").open("wb") as stderr:
            launcher = subprocess.Popen(
                [
                    sys.executable,
                    str(RUNNER),
                    "codex",
                    "--cli",
                    str(FAKE_PROVIDER),
                    "--workspace",
                    str(workspace),
                    "--artifacts",
                    str(artifacts),
                    "--timeout-seconds",
                    "60",
                ],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
            )
            owned_groups: set[int] = set()
            try:
                deadline = time.monotonic() + 10
                while not ready_receipt.exists() and launcher.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.1)
                if not ready_receipt.exists():
                    raise RuntimeError("fake provider did not publish its bounded ready receipt")

                child_receipt = json.loads(ready_receipt.read_text(encoding="utf-8"))
                expected_pids = {child_receipt["provider_pid"], child_receipt["tool_child_pid"]}
                process_receipt = artifacts / "process-tree.json"
                observation_deadline = time.monotonic() + 5
                while time.monotonic() < observation_deadline:
                    if process_receipt.exists():
                        tree = json.loads(process_receipt.read_text(encoding="utf-8"))
                        observed = {process["pid"] for process in tree["processes"]}
                        if expected_pids.issubset(observed):
                            break
                    time.sleep(0.1)
                else:
                    raise RuntimeError("launcher did not observe both fixture process IDs before cancellation")
                if inject_receipt_failure:
                    failure_marker.touch()
                    try:
                        launcher.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        raise RuntimeError("runner did not stop after its receipt write failed")
                    if not wait_for_pids_to_exit(expected_pids, 3):
                        live = {pid: process_table().get(pid) for pid in expected_pids if pid in process_table()}
                        raise RuntimeError(
                            "provider or tool child survived receipt write failure: "
                            + json.dumps(live, sort_keys=True)
                        )
                    print(json.dumps({
                        "receipt_write_failed": True,
                        "launcher_exited": True,
                        "cleanup_verified": True,
                        "known_child_pids": sorted(expected_pids),
                    }))
                    return 0
                if inject_query_failure:
                    failure_marker.touch()
                try:
                    os.kill(launcher.pid, requested_signal)
                    try:
                        launcher.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        raise RuntimeError("launcher did not forward cancellation within the bound")

                    summary_path = artifacts / "summary.json"
                    if not summary_path.exists():
                        raise RuntimeError(
                            "launcher exited without a receipt ("
                            f"status {launcher.returncode}); stderr={ (root / 'launcher.stderr').read_text(errors='replace')!r}"
                        )
                    summary = json.loads(summary_path.read_text(encoding="utf-8"))
                    if not summary["cancelled"] or summary["received_signal"] != requested_signal:
                        raise RuntimeError("launcher receipt did not record the delivered signal")
                    observed_pids = {process["pid"] for process in summary["process_tree"]["processes"]}
                    if not expected_pids.issubset(observed_pids):
                        raise RuntimeError("launcher did not record both provider and independent tool-child PIDs")
                    observed_groups = {process["pgid"] for process in summary["process_tree"]["processes"]}
                    if child_receipt["tool_child_pgid"] not in observed_groups:
                        raise RuntimeError("launcher did not record the tool child's independent process group")
                    if inject_query_failure:
                        if summary["cleanup_verified"] or summary["tracked_process_groups_after_exit"] is not None:
                            raise RuntimeError("process-table failure was incorrectly reported as verified cleanup")
                        if not summary["process_tree"]["query_error"]:
                            raise RuntimeError("injected process-table failure was absent from the receipt")
                        if child_receipt["tool_child_pid"] not in process_table():
                            raise RuntimeError("injected failure did not leave the unobserved tool group for cleanup")
                        if launcher.returncode == 0:
                            raise RuntimeError("launcher succeeded despite inconclusive cleanup verification")
                    else:
                        if not summary["cleanup_verified"]:
                            raise RuntimeError(
                                "launcher did not verify that all tracked groups exited: "
                                + json.dumps(summary, sort_keys=True)
                            )
                        if not wait_for_pids_to_exit(expected_pids, 3):
                            raise RuntimeError("provider or tool-like child remained after cancellation")
                        if summary["tracked_process_groups_after_exit"] != []:
                            raise RuntimeError("launcher still observed a live tracked process group")
                    live_pids = set(process_table()) & expected_pids
                    print(json.dumps({
                        "cancelled": True,
                        "signal": sys.argv[1],
                        "provider_and_tool_child_pids_gone": not live_pids,
                        "live_pids_before_fixture_cleanup": sorted(live_pids),
                        "independent_tool_process_group_observed": child_receipt["tool_child_pgid"],
                        "tracked_process_groups_after_exit": summary["tracked_process_groups_after_exit"],
                        "cleanup_verified": summary["cleanup_verified"],
                    }))
                finally:
                    # This test owns both exact groups and must not leak its fake
                    # provider even when process inspection is unavailable.
                    for pgid in {child_receipt["provider_pgid"], child_receipt["tool_child_pgid"]}:
                        try:
                            os.killpg(pgid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
            finally:
                if ready_receipt.exists():
                    try:
                        receipt_for_cleanup = json.loads(ready_receipt.read_text(encoding="utf-8"))
                        owned_groups.update({receipt_for_cleanup["provider_pgid"], receipt_for_cleanup["tool_child_pgid"]})
                    except (OSError, json.JSONDecodeError, KeyError):
                        pass
                if not cleanup_launcher_and_children(launcher, owned_groups):
                    raise RuntimeError("fixture cleanup could not confirm all owned process groups exited")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
