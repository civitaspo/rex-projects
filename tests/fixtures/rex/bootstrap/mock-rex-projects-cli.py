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
    "target": "darwin-aarch64",
    "protocol_version": 1,
    "bootstrap_schema": 1,
}, sort_keys=True))
