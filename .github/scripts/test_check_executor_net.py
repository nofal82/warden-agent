#!/usr/bin/env python3
"""Self-test for check_executor_net.py (executor-ipc AC2a).

The check must pass on the clean fixture and on a module with no executor
packages, and fail on the violating fixture with every expected reason.

Usage: python3 .github/scripts/test_check_executor_net.py
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CHECK = os.path.join(HERE, "check_executor_net.py")
FIXTURES = os.path.join(HERE, "testdata", "executor_net")

# Each must appear in the violating fixture's report.
EXPECTED = [
    "forbidden package net/http ",
    "forbidden package crypto/tls ",  # transitive, through internal/other
    "forbidden package example.com/fixture/api/proto/warden/agentapi/v1 ",
    "bad.go:18: net.Dial dials out",
    "bad.go:21: net.LookupHost resolves names",
    'bad.go:30: net.Listen( with a network other than the literal "unix"',
    "bad.go:33: net.Listen listener function used as a value",
    "bad.go:35: syscall.Socket raw socket call",
    "bad.go:35: syscall.AF_INET network address family",
    "3 listener call sites, at most 2 allowed",
    'alias.go:3: imports "net" as n',
]


def run(root: str) -> tuple:
    out = subprocess.run([sys.executable, CHECK, "--root", root],
                         capture_output=True, text=True, timeout=300,
                         check=False)
    return out.returncode, out.stdout + out.stderr


def main() -> int:
    failures = []

    code, out = run(os.path.join(FIXTURES, "clean"))
    if code != 0:
        failures.append("clean fixture should pass:\n" + out)

    code, out = run(os.path.join(FIXTURES, "violating"))
    if code != 1:
        failures.append(f"violating fixture should exit 1, got {code}:\n{out}")
    for want in EXPECTED:
        if want not in out:
            failures.append(f"violating fixture report lacks {want!r}")
    if "errNoDial" in out or "ipc.go" in out:
        failures.append("clean code leaked into the violating report")

    with tempfile.TemporaryDirectory() as empty:
        with open(os.path.join(empty, "go.mod"), "w", encoding="utf-8") as fh:
            fh.write("module example.com/empty\n\ngo 1.22\n")
        code, out = run(empty)
        if code != 0:
            failures.append("module without executor packages should pass:\n"
                            + out)

    if failures:
        print("check_executor_net self-test FAILED:")
        for f in failures:
            print("  " + f)
        return 1
    print("check_executor_net self-test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
