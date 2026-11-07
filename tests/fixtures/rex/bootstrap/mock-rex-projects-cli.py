#!/usr/bin/env python3
"""PR0 fixture only; this is not a rex-projects CLI implementation."""
import json
import sys

if sys.argv[1:] != ["version", "--json"]:
    print("fixture accepts only: version --json", file=sys.stderr)
    raise SystemExit(2)
print(json.dumps({
    "name": "rex-projects",
    "version": "0.1.0-dev.fixture",
    "target": "aarch64-apple-darwin",
    "cli_protocol": 1,
    "database_schema": 1,
    "source_revision": "0123456789abcdef0123456789abcdef01234567",
    "dirty": False,
}, sort_keys=True))
