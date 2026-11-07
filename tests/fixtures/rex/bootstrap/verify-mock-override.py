#!/usr/bin/env python3
"""Exercise copy, digest, argv and version/protocol checks against a mock CLI."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
source = root / "mock-rex-projects-cli.py"
snapshot = root / "cache" / "probe with spaces" / "rex-projects"
snapshot.parent.mkdir(parents=True, exist_ok=True)
shutil.copyfile(source, snapshot)
snapshot.chmod(0o755)
expected = hashlib.sha256(source.read_bytes()).hexdigest()
observed = hashlib.sha256(snapshot.read_bytes()).hexdigest()
result = subprocess.run(
    [str(snapshot), "version", "--json"],
    check=False,
    capture_output=True,
    text=True,
    timeout=3,
)
metadata = json.loads(result.stdout)
checks = {
    "mock_only": True,
    "absolute_snapshot_path": str(snapshot),
    "path_contains_spaces": " " in str(snapshot),
    "sha256": observed,
    "digest_matches": observed == expected,
    "probe_exit_code": result.returncode,
    "version_matches_fixture": metadata.get("version") == "0.1.0-dev.fixture",
    "target_matches_fixture": metadata.get("target") == "darwin-aarch64",
    "protocol_matches_fixture": metadata.get("protocol_version") == 1,
    "bootstrap_schema_matches_fixture": metadata.get("bootstrap_schema") == 1,
}
print(json.dumps(checks, indent=2, sort_keys=True))
if not all(value is True for key, value in checks.items() if isinstance(value, bool)):
    raise SystemExit(1)
