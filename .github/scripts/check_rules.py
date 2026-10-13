#!/usr/bin/env python3
"""CI gate: repeat the local hook rules over every tracked file.

Hooks only run inside Claude Code sessions. This script runs in CI on every
pull request, so a rule can never be bypassed by editing outside Claude Code.

Fails (exit 1) on:
  * anything that looks like a real secret
  * Go code that starts a shell or raw process
  * "os/exec" imported outside .claude/hooks/policy.json exec_allowed_paths
Usage: python3 .github/scripts/check_rules.py
"""
import fnmatch
import json
import re
import subprocess
import sys

SECRET_PATTERNS = [
    (r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", "private key"),
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key"),
    (r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "GitHub token"),
    (r"\bsk-ant-[A-Za-z0-9_\-]{20,}", "Anthropic API key"),
    (r"\bxox[baprs]-[A-Za-z0-9\-]{10,}", "Slack token"),
    (r"(?i)\bAccountKey=[A-Za-z0-9+/=]{40,}", "Azure storage key"),
]
SHELL_PATTERNS = [
    r'exec\.Command(Context)?\(\s*([A-Za-z_][A-Za-z0-9_]*\s*,\s*)?"(/usr)?(/bin/)?(ba|z|da|k)?sh"',
    r"\b(syscall|unix)\.(Exec|ForkExec|StartProcess)\(",
    r"\bos\.StartProcess\(",
]
# Files allowed to contain the patterns above as data (the rule definitions).
SELF_EXEMPT = {
    ".github/scripts/check_rules.py",
    ".claude/hooks/guard_code.py",
    ".claude/hooks/test_hooks.py",
}


def tracked_files() -> list:
    # Tracked plus new untracked (not ignored) files, so `make rules` catches
    # problems before the first commit too.
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        capture_output=True, text=True, check=True,
    )
    return [f for f in out.stdout.splitlines() if f]


def main() -> int:
    try:
        with open(".claude/hooks/policy.json", encoding="utf-8") as fh:
            allowed_exec = json.load(fh).get("exec_allowed_paths", [])
    except (OSError, json.JSONDecodeError):
        allowed_exec = []

    problems = []
    for path in tracked_files():
        if path in SELF_EXEMPT:
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable
        for pat, what in SECRET_PATTERNS:
            for m in re.finditer(pat, text):
                line = text.count("\n", 0, m.start()) + 1
                problems.append(f"{path}:{line}: looks like a real {what}")
        if path.endswith(".go"):
            for pat in SHELL_PATTERNS:
                for m in re.finditer(pat, text):
                    line = text.count("\n", 0, m.start()) + 1
                    problems.append(f"{path}:{line}: starts a shell or raw process")
            if re.search(r'"os/exec"', text) and not any(
                fnmatch.fnmatch(path, p) for p in allowed_exec
            ):
                problems.append(f'{path}: imports "os/exec" outside {allowed_exec or "nowhere"}')

    for p in problems:
        print(f"RULE VIOLATION: {p}")
    if problems:
        print(f"\n{len(problems)} violation(s). See CLAUDE.md, section Forbidden.")
        return 1
    print("check_rules: no violations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
