#!/usr/bin/env python3
"""Verify the host link utility's exact-destination, atomic no-replace contract."""
from __future__ import annotations

import concurrent.futures
import os
import subprocess
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory(prefix="rex-projects link ") as directory:
    root = Path(directory)
    source = root / "staging" / "rex-projects"
    source.parent.mkdir(mode=0o700)
    source.write_bytes(b"verified fixture executable\n")
    destination = root / "cache" / "rex-projects"
    destination.parent.mkdir(mode=0o700)

    def publish() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["link", str(source), str(destination)],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: publish(), range(8)))
    successes = [result for result in results if result.returncode == 0]
    failures = [result for result in results if result.returncode != 0]
    assert len(successes) == 1, f"expected one atomic publication winner: {results!r}"
    assert len(failures) == 7, f"existing destination must reject losers: {results!r}"
    assert destination.read_bytes() == source.read_bytes()
    assert os.stat(destination).st_ino == os.stat(source).st_ino

    target = root / "outside"
    target.write_text("preserve me", encoding="utf-8")
    symlink_destination = root / "symlink-winner"
    symlink_destination.symlink_to(target)
    symlink_result = subprocess.run(
        ["link", str(source), str(symlink_destination)],
        check=False,
        capture_output=True,
        text=True,
        timeout=2,
    )
    assert symlink_result.returncode != 0
    assert symlink_destination.is_symlink()
    assert target.read_text(encoding="utf-8") == "preserve me"

    directory_destination = root / "directory-winner"
    directory_destination.mkdir()
    directory_result = subprocess.run(
        ["link", str(source), str(directory_destination)],
        check=False,
        capture_output=True,
        text=True,
        timeout=2,
    )
    assert directory_result.returncode != 0
    assert directory_destination.is_dir()

print("link exact-destination no-replace contract passed")
