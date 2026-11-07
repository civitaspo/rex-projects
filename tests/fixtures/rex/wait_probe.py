#!/usr/bin/env python3
"""Stay alive until the parent asks this fixture to stop via a marker file."""

import argparse
import json
import os
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--stop-file", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=20.0)
    args = parser.parse_args()

    args.ready_file.write_text(json.dumps({"pid": os.getpid()}), encoding="utf-8")
    deadline = time.monotonic() + args.timeout_seconds
    while not args.stop_file.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    if args.stop_file.exists():
        print(json.dumps({"pid": os.getpid(), "stopped": True}), flush=True)
        return 0
    print(json.dumps({"pid": os.getpid(), "stopped": False}), flush=True)
    return 124


if __name__ == "__main__":
    raise SystemExit(main())
