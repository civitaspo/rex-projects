#!/usr/bin/env python3
"""Disposable fake provider with a tool-like child in the same process group."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

receipt_path = Path(os.environ["REX_PR0_CANCEL_CHILD_RECEIPT"])
child = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(120)"],
    preexec_fn=os.setpgrp,
)
receipt = {
    "provider_pid": os.getpid(),
    "provider_pgid": os.getpgrp(),
    "tool_child_pid": child.pid,
    "tool_child_pgid": os.getpgid(child.pid),
}
temporary = receipt_path.with_suffix(".tmp")
temporary.write_text(json.dumps(receipt), encoding="utf-8")
temporary.replace(receipt_path)
while True:
    time.sleep(1)
