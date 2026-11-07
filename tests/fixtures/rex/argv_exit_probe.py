#!/usr/bin/env python3
"""Emit exact argv for the Rex process-boundary fixture, then exit on request."""

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: argv_exit_probe.py EXIT_CODE RECEIPT_FILE [ARG ...]", file=sys.stderr)
        return 64

    try:
        exit_code = int(sys.argv[1], 10)
    except ValueError:
        print("EXIT_CODE must be an integer", file=sys.stderr)
        return 64
    if not 0 <= exit_code <= 255:
        print("EXIT_CODE must be between 0 and 255", file=sys.stderr)
        return 64

    receipt = {"argv": sys.argv[3:], "exit_code": exit_code}
    receipt_path = Path(sys.argv[2])
    temporary_path = receipt_path.with_suffix(receipt_path.suffix + ".tmp")
    temporary_path.write_text(json.dumps(receipt) + "\n", encoding="utf-8")
    temporary_path.replace(receipt_path)
    print(json.dumps(receipt), flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
