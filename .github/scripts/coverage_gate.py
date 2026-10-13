#!/usr/bin/env python3
"""CI gate: enforce minimum statement coverage for selected package paths.

Thresholds live in .github/coverage.json, e.g.
  {"internal/executor/": 90}
A path prefix with no Go code yet is skipped, so the gate can be committed
before the code exists.
Usage: python3 .github/scripts/coverage_gate.py coverage.out
"""
import json
import re
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: coverage_gate.py coverage.out")
        return 2
    try:
        with open(".github/coverage.json", encoding="utf-8") as fh:
            thresholds = json.load(fh)
    except (OSError, json.JSONDecodeError):
        thresholds = {}
    if not thresholds:
        print("coverage_gate: no thresholds configured")
        return 0

    # mode line, then: path/file.go:startLine.col,endLine.col numStatements count
    line_re = re.compile(r"^(.+?):\d+\.\d+,\d+\.\d+ (\d+) (\d+)$")
    totals = {p: [0, 0] for p in thresholds}  # prefix -> [covered, total]
    with open(sys.argv[1], encoding="utf-8") as fh:
        for line in fh:
            m = line_re.match(line.strip())
            if not m:
                continue
            path, stmts, count = m.group(1), int(m.group(2)), int(m.group(3))
            for prefix in thresholds:
                if f"/{prefix}" in f"/{path}" or path.startswith(prefix):
                    totals[prefix][1] += stmts
                    if count > 0:
                        totals[prefix][0] += stmts

    failed = False
    for prefix, minimum in thresholds.items():
        covered, total = totals[prefix]
        if total == 0:
            print(f"coverage_gate: {prefix} has no code yet, skipped")
            continue
        pct = 100.0 * covered / total
        status = "OK" if pct >= minimum else "FAIL"
        failed |= pct < minimum
        print(f"coverage_gate: {prefix} {pct:.1f}% (minimum {minimum}%) {status}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
