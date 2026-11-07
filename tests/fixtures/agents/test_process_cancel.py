#!/usr/bin/env python3
"""Bounded local self-tests for provider-launcher cancellation forwarding."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import unittest
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parent
PROBE = FIXTURE_DIR / "run_cancel_group_probe.py"


def run_bounded(args: list[str], timeout: float = 18) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.send_signal(signal.SIGINT)
        try:
            stdout, stderr = process.communicate(timeout=6)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=2)
            raise AssertionError("cancellation fixture exceeded its bound and did not clean up")
        raise AssertionError(
            "cancellation fixture exceeded its bound; cleanup completed: " + (stderr or stdout)
        )
    return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)


class CancellationForwardingTests(unittest.TestCase):
    def assert_cancellation(self, signum: str) -> None:
        run = run_bounded([sys.executable, str(PROBE), signum])
        self.assertEqual(run.returncode, 0, run.stderr or run.stdout)
        report = json.loads(run.stdout)
        self.assertTrue(report["provider_and_tool_child_pids_gone"])
        self.assertTrue(report["cleanup_verified"])
        self.assertEqual(report["live_pids_before_fixture_cleanup"], [])

    def test_sigint_cleans_independent_tool_group(self) -> None:
        self.assert_cancellation("SIGINT")

    def test_sigterm_cleans_independent_tool_group(self) -> None:
        self.assert_cancellation("SIGTERM")

    def test_sighup_cleans_independent_tool_group(self) -> None:
        self.assert_cancellation("SIGHUP")

    def test_process_table_failure_makes_cleanup_inconclusive(self) -> None:
        run = run_bounded([sys.executable, str(PROBE), "SIGHUP", "--inject-ps-failure-after-first-sample"])
        self.assertEqual(run.returncode, 0, run.stderr or run.stdout)
        report = json.loads(run.stdout)
        self.assertFalse(report["provider_and_tool_child_pids_gone"])
        self.assertFalse(report["cleanup_verified"])
        self.assertTrue(report["live_pids_before_fixture_cleanup"])

    def test_receipt_write_failure_stops_provider_and_child(self) -> None:
        run = run_bounded([sys.executable, str(PROBE), "SIGINT", "--inject-receipt-write-failure"])
        self.assertEqual(run.returncode, 0, run.stderr or run.stdout)
        report = json.loads(run.stdout)
        self.assertTrue(report["receipt_write_failed"])
        self.assertTrue(report["launcher_exited"])
        self.assertTrue(report["cleanup_verified"])
        self.assertTrue(report["known_child_pids"])


if __name__ == "__main__":
    unittest.main()
