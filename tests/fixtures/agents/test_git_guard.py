from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parent
GIT_GUARD = FIXTURE_DIR / "guards" / "bin" / "git"


class GitGuardTests(unittest.TestCase):
    def test_push_after_global_options_is_denied_and_logged(self) -> None:
        for prefix in (["-C", "."], ["-c", "advice.pushUpdateRejected=false"]):
            with self.subTest(prefix=prefix), tempfile.TemporaryDirectory() as temporary:
                log = Path(temporary) / "guard.log"
                env = os.environ | {"REX_PROJECTS_PROBE_GUARD_LOG": str(log)}
                run = subprocess.run(
                    [str(GIT_GUARD), *prefix, "push"],
                    cwd=temporary,
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(run.returncode, 125)
                self.assertEqual(
                    log.read_text(encoding="utf-8"),
                    "git push denied by PR0 disposable fixture\n",
                )


    def test_global_options_are_preserved_for_allowed_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository with spaces"
            subprocess.run(["/usr/bin/git", "init", str(repository)], check=True, capture_output=True)
            run = subprocess.run(
                [str(GIT_GUARD), "-C", str(repository), "rev-parse", "--show-toplevel"],
                cwd=temporary, capture_output=True, text=True, check=False,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(Path(run.stdout.strip()).resolve(), repository.resolve())


if __name__ == "__main__":
    unittest.main()
