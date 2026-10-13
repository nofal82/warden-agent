#!/usr/bin/env python3
"""PostToolUse helper: run gofmt on any Go file an agent just wrote.

Never blocks. If gofmt is missing or fails, it stays silent; CI's lint step is
the real gate.
"""
import json
import shutil
import subprocess
import sys


def main() -> None:
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)
    path = (data.get("tool_input") or {}).get("file_path", "")
    if path.endswith(".go") and shutil.which("gofmt"):
        try:
            subprocess.run(["gofmt", "-w", path], capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            pass
    sys.exit(0)


if __name__ == "__main__":
    main()
