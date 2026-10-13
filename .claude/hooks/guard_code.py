#!/usr/bin/env python3
"""PreToolUse guard for Edit/Write: enforce Warden's non-negotiable code rules.

Blocks (exit 2, reason on stderr, fed back to the agent):
  1. Edits to the guardrails themselves (.claude/, CLAUDE.md, .github/,
     .golangci.yml, Makefile) unless Nofal starts Claude Code
     with WARDEN_ALLOW_GUARDRAIL_EDITS=1.
  2. Anything that looks like a real secret (private keys, cloud/API tokens).
  3. Go code that launches a shell (sh/bash/zsh/dash, with or without -c).
  4. Go code importing "os/exec" outside the paths allowed in policy.json.
Rules live here and in .claude/hooks/policy.json; CI repeats checks 2-4 so a
missed hook can never let a violation merge.
"""
import fnmatch
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

GUARDRAIL_PATTERNS = [
    ".claude/*",          # hooks, settings, subagents, skills
    "CLAUDE.md",
    ".github/*",          # CI, rule checker, PR template, CODEOWNERS
    ".golangci.yml",      # lint configuration
    "Makefile",           # `make *` is pre-approved, so its targets are guarded
]

SECRET_PATTERNS = [
    (r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", "a private key"),
    (r"\bAKIA[0-9A-Z]{16}\b", "an AWS access key"),
    (r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "a GitHub token"),
    (r"\bsk-ant-[A-Za-z0-9_\-]{20,}", "an Anthropic API key"),
    (r"\bxox[baprs]-[A-Za-z0-9\-]{10,}", "a Slack token"),
    (r"(?i)\bAccountKey=[A-Za-z0-9+/=]{40,}", "an Azure storage key"),
]

SHELL_PATTERNS = [
    # exec.Command("sh", ...) / exec.CommandContext(ctx, "/bin/bash", ...)
    r'exec\.Command(Context)?\(\s*([A-Za-z_][A-Za-z0-9_]*\s*,\s*)?"(/usr)?(/bin/)?(ba|z|da|k)?sh"',
    r"\b(syscall|unix)\.(Exec|ForkExec|StartProcess)\(",
    r"\bos\.StartProcess\(",
]


def block(msg: str) -> None:
    print(f"BLOCKED by guard_code: {msg}", file=sys.stderr)
    sys.exit(2)


def load_policy() -> dict:
    try:
        with open(os.path.join(HERE, "policy.json"), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {"exec_allowed_paths": []}


def rel_path(file_path: str, project_dir: str) -> str:
    """Path relative to the repository root, also inside git worktrees."""
    fp = os.path.normpath(file_path.replace("\\", "/")).replace("\\", "/")
    # A worktree is a full checkout: take the path after .../worktrees/<name>/
    m = re.search(r"/worktrees/[^/]+/(.+)$", fp)
    if m:
        return m.group(1)
    pd = os.path.normpath(project_dir.replace("\\", "/")).replace("\\", "/").rstrip("/") + "/"
    if pd != "/" and fp.startswith(pd):
        return fp[len(pd):]
    for marker in ("/warden-agent/", "/warden/"):
        if marker in fp:
            return fp.split(marker, 1)[1]
    return fp.lstrip("/")


def new_text(tool_input: dict) -> str:
    """Collect the text being written, whatever the tool's field names are."""
    parts = []
    for key, val in tool_input.items():
        if key in ("file_path", "old_string", "notebook_path"):
            continue
        if isinstance(val, str):
            parts.append(val)
        elif isinstance(val, list):  # e.g. a list of edits
            for item in val:
                if isinstance(item, dict):
                    parts.extend(
                        v for k, v in item.items() if k != "old_string" and isinstance(v, str)
                    )
    return "\n".join(parts)


def main() -> None:
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    tool_input = data.get("tool_input") or {}
    file_path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
    if not file_path:
        sys.exit(0)
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR", data.get("cwd", ""))

    # 0. Stay inside this repository (sibling repos are read-only from here).
    fp = os.path.normpath(file_path.replace("\\", "/")).replace("\\", "/")
    pd = os.path.normpath(project_dir.replace("\\", "/")).replace("\\", "/").rstrip("/") + "/"
    home_claude = os.path.expanduser("~/.claude/")
    if (
        os.path.isabs(fp)
        and pd != "/"
        and not fp.startswith(pd)
        and not re.search(r"/worktrees/[^/]+/", fp)
        and not fp.startswith(home_claude)
        and not fp.startswith("/tmp/")
    ):
        block(
            f"'{file_path}' is outside this repository. Other repositories are "
            "read-only from here; open a session in that repository instead."
        )

    rel = rel_path(file_path, project_dir)
    text = new_text(tool_input)

    # 1. Guardrails
    if os.environ.get("WARDEN_ALLOW_GUARDRAIL_EDITS") != "1":
        for pat in GUARDRAIL_PATTERNS:
            if fnmatch.fnmatch(rel, pat):
                block(
                    f"'{rel}' is a guardrail file. Agents may not change it. "
                    "Describe the change you want in the PR and Nofal will make it."
                )

    # 2. Secrets
    for pat, what in SECRET_PATTERNS:
        if re.search(pat, text):
            block(
                f"the content looks like {what}. Never write real secrets; "
                "use an obvious fake such as FAKE-SECRET-123 in tests."
            )

    if not rel.endswith(".go"):
        sys.exit(0)

    # 3. Shells
    for pat in SHELL_PATTERNS:
        if re.search(pat, text):
            block(
                "Go code must never start a shell or raw process. Executor "
                "primitives call a fixed binary path with validated arguments."
            )

    # 4. os/exec location
    if re.search(r'"os/exec"', text):
        allowed = load_policy().get("exec_allowed_paths", [])
        if not any(fnmatch.fnmatch(rel, pat) for pat in allowed):
            where = ", ".join(allowed) if allowed else "nowhere in this repository"
            block(f'"os/exec" may only be imported in: {where}. File: {rel}')

    sys.exit(0)


if __name__ == "__main__":
    main()
