#!/usr/bin/env python3
"""Report factory marker presence only; never print marker values."""

import json
import os


def main() -> None:
    names = (
        "REX_PROJECTS_CONTEXT",
        "REX_PROJECTS_AGENT",
        "REX_PROJECTS_PROJECT_ID",
        "REX_PROJECTS_ROLE",
        "REX_PROJECTS_RUN_ID",
        "REX_PROJECTS_TICKET_RUN_ID",
    )
    print(json.dumps({name: bool(os.environ.get(name)) for name in names}, sort_keys=True))


if __name__ == "__main__":
    main()
