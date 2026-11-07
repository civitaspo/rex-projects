#!/usr/bin/env python3
"""Report whether a rex-projects CLI exposes the acceptance command surface."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

MANIFEST = Path(__file__).with_name("manifest.json")


def probe(cli: Path, command: list[str], timeout: float,
          required_options: list[str]) -> dict[str, object]:
    try:
        result = subprocess.run([str(cli), *command], capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"available": False, "reason": "help probe timed out", "argv": command}
    output = result.stdout + result.stderr
    # Clap can print a parent usage line for an unknown command, so require the
    # exact command prefix and the options needed by this acceptance driver.
    expected = "Usage: rex-projects " + " ".join(command[:-1])
    usage_lines = [line.strip() for line in output.splitlines() if line.lstrip().startswith("Usage:")]
    matched_usage = any(line.startswith(expected) for line in usage_lines)
    missing_options = [option for option in required_options if option not in output]
    available = matched_usage and not missing_options
    return {"available": available, "exit_code": result.returncode, "argv": command,
            "expected_usage_prefix": expected, "usage_lines": usage_lines,
            "missing_options": missing_options,
            "diagnostic": output[-1000:] if not available else ""}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True, type=Path, help="Built rex-projects executable")
    parser.add_argument("--timeout-seconds", type=float, default=5.0)
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable receipt")
    args = parser.parse_args()
    if not 0.1 <= args.timeout_seconds <= 30:
        parser.error("--timeout-seconds must be between 0.1 and 30")
    try:
        cli = args.cli.expanduser().resolve(strict=True)
    except OSError as error:
        parser.error(f"cannot resolve --cli: {error}")
    if not cli.is_file() or not cli.stat().st_mode & 0o111:
        parser.error("--cli must be an executable file")

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    required = manifest.get("required_cli")
    if not isinstance(required, dict):
        parser.error("manifest required_cli must be an object")
    commands = {name: probe(cli, [*spec["argv"], "--help"], args.timeout_seconds, spec["options"])
                for name, spec in required.items()}
    missing = [name for name, result in commands.items() if not result["available"]]
    receipt = {
        "schema_version": 1,
        "result": "UNSUPPORTED" if missing else "COMMAND_SURFACE_AVAILABLE",
        "cli": str(cli),
        "commands": commands,
        "missing_commands": missing,
        "full_flow_pass": False,
        "note": "Command discovery is not runtime acceptance evidence.",
    }
    if args.json:
        print(json.dumps(receipt, sort_keys=True))
    else:
        print(json.dumps(receipt, indent=2, sort_keys=True))
    return 4 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
