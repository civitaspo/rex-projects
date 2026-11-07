#!/usr/bin/env python3
"""Bounded local self-tests for provider-launcher cancellation forwarding."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parent
PROBE = FIXTURE_DIR / "run_cancel_group_probe.py"


class CancellationForwardingTests(unittest.TestCase):
    def assert_cancellation(self, signum: str) -> None:
        run = subprocess.run(
            [sys.executable, str(PROBE), signum],
            capture_output=True,
            text=True,
            timeout=18,
            check=False,
        )
        self.assertEqual(run.returncode, 0, run.stderr or run.stdout)

    def test_sigint_cleans_independent_tool_group(self) -> None:
        self.assert_cancellation("SIGINT")

    def test_sigterm_cleans_independent_tool_group(self) -> None:
        self.assert_cancellation("SIGTERM")

    def test_sighup_cleans_independent_tool_group(self) -> None:
        self.assert_cancellation("SIGHUP")

    def test_process_table_failure_makes_cleanup_inconclusive(self) -> None:
        run = subprocess.run(
            [sys.executable, str(PROBE), "SIGHUP", "--inject-ps-failure-after-first-sample"],
            capture_output=True,
            text=True,
            timeout=18,
            check=False,
        )
        self.assertEqual(run.returncode, 0, run.stderr or run.stdout)


if __name__ == "__main__":
    unittest.main()
