#!/usr/bin/env python3
"""Disposable host-command test double that refuses marked Agent calls."""

import json
import os
import sys
from pathlib import Path


def main() -> int:
    if os.environ.get("REX_PROJECTS_AGENT") == "1":
        print(json.dumps({"accepted": False, "reason": "marked-agent"}))
        return 77
    Path(sys.argv[1]).write_text('{"approved":true}\n', encoding="utf-8")
    print(json.dumps({"accepted": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
