#!/usr/bin/env python3
"""PreToolUse guard: keep agents off `main` and away from history-rewriting git.

Blocks (exit 2, reason on stderr, which Claude Code feeds back to the agent):
  * Edit/Write while the repository's current branch is main or master
  * `git commit` while on main/master, or with --no-verify / -n
  * `git push` that is forced (--force, -f in any flag cluster,
    --force-with-lease, --force-if-includes, +refspec), that targets
    main/master (as a branch name or a refspec destination), that uses
    --no-verify, or that runs while on main/master
The git command line is tokenised, so branch names and commit messages that
merely contain words like "push", "main" or "-n" are not blocked.
Empty repositories (no commits yet) are allowed so the very first commit can
be made.
"""
import json
import os
import re
import shlex
import subprocess
import sys

PROTECTED = {"main", "master"}
# git global options that take a separate value
GLOBAL_OPTS_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}


def block(msg: str) -> None:
    print(f"BLOCKED by guard_branch: {msg}", file=sys.stderr)
    sys.exit(2)


def git(cwd: str, *args: str) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", cwd, *args], capture_output=True, text=True, timeout=10
        )
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def branch_state(cwd: str):
    """Return (branch, on_protected) for the repository at cwd."""
    has_commits = bool(git(cwd, "rev-parse", "--verify", "-q", "HEAD"))
    branch = git(cwd, "rev-parse", "--abbrev-ref", "HEAD")
    return branch, has_commits and branch in PROTECTED


def split_commands(cmd: str):
    """Split a shell command line into simple commands (token lists).

    Heredoc bodies are dropped: they are data (e.g. commit messages), not
    commands.
    """
    # Remove heredoc bodies: <<'EOF' ... EOF  /  <<EOF ... EOF  /  <<-EOF
    cmd = re.sub(
        r"<<-?\s*(['\"]?)(\w+)\1[^\n]*\n.*?\n\s*\2\s*(\n|$)",
        "\n",
        cmd,
        flags=re.S,
    )
    cmd = cmd.replace("\\\n", " ")  # line continuations
    seps = set(";&|()\n")
    try:
        # Newlines separate commands unless they are inside quotes.
        lexer = shlex.shlex(cmd, posix=True, punctuation_chars=";&|()\n")
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        # Unbalanced quotes: fall back to a coarse split so we still check.
        tokens = re.split(r"[ \t]+|(?=[;&|\n])|(?<=[;&|\n])", cmd)
    commands, current = [], []
    for tok in tokens:
        if not tok:
            continue
        if set(tok) <= seps:
            if current:
                commands.append(current)
            current = []
        else:
            current.append(tok)
    if current:
        commands.append(current)
    return commands


def parse_git(tokens):
    """If tokens are a git invocation return (repo_dir_or_None, subcommand, args)."""
    # skip env assignments and common wrappers
    i = 0
    wrappers = ("command", "time", "nice", "timeout", "env", "sudo", "nohup", "exec")
    while i < len(tokens) and (re.match(r"^\w+=", tokens[i]) or tokens[i] in wrappers):
        prev = tokens[i]
        i += 1
        # skip wrapper options (sudo -u x, env -i, timeout 30)
        while i < len(tokens) and prev in ("sudo", "env", "timeout", "nice") and (
            tokens[i].startswith("-") or re.match(r"^\d", tokens[i])
        ):
            i += 2 if tokens[i] in ("-u", "-g", "-n") and prev in ("sudo", "nice") else 1
    if i >= len(tokens) or os.path.basename(tokens[i]) != "git":
        return None
    i += 1
    repo_dir = None
    while i < len(tokens) and tokens[i].startswith("-"):
        opt = tokens[i]
        if opt in GLOBAL_OPTS_WITH_VALUE:
            if opt == "-C" and i + 1 < len(tokens):
                repo_dir = tokens[i + 1]
            if opt == "-c" and i + 1 < len(tokens) and tokens[i + 1].lower().startswith("core.hookspath"):
                block("overriding core.hooksPath skips checks and is not allowed.")
            i += 2
            continue
        if opt.startswith("--git-dir=") or opt.startswith("--work-tree="):
            i += 1
            continue
        i += 1
    if i >= len(tokens):
        return None
    return repo_dir, tokens[i], tokens[i + 1:]


def option_tokens(args, stop_after_value=("-m", "-F", "--message", "--file", "-C", "-c", "--author", "--date")):
    """Yield option tokens, skipping values of options that take one and stopping at --."""
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a == "--":
            return
        if a in stop_after_value:
            skip = True
            continue
        if a.startswith("-"):
            yield a


def positional_tokens(args, value_opts=("-o", "--push-option", "--repo", "--receive-pack", "--exec")):
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a in value_opts:
            skip = True
            continue
        if not a.startswith("-"):
            yield a


def check_commit(args, on_protected, branch):
    for opt in option_tokens(args):
        if opt == "--no-verify":
            block("--no-verify is not allowed; fix the failing check instead.")
        # Short-flag clusters such as -an. Options that carry an attached value
        # (-u<mode>, -m<msg>, -F<file>, -C/-c<commit>, -S<key>) are skipped.
        if (
            re.fullmatch(r"-[A-Za-z]+", opt)
            and not opt.startswith(("-u", "-m", "-F", "-C", "-c", "-S", "-t"))
            and "n" in opt[1:]
        ):
            block("`git commit -n` skips checks and is not allowed.")
    if on_protected:
        block(f"committing on '{branch}' is not allowed; create a branch first.")


def check_push(args, on_protected, branch):
    for opt in option_tokens(args):
        if opt in ("--force", "--no-verify", "--mirror", "--delete") or opt.startswith(
            ("--force-with-lease", "--force-if-includes")
        ):
            block(f"`git push {opt}` is not allowed.")
        if re.fullmatch(r"-[A-Za-z]+", opt) and ("f" in opt[1:] or "d" in opt[1:]):
            block("force or delete pushes are not allowed.")
    positionals = list(positional_tokens(args))
    refspecs = positionals[1:]  # first positional is the remote
    for spec in refspecs:
        if spec.startswith("+"):
            block("force pushes (+refspec) are not allowed.")
        dest = spec.split(":", 1)[1] if ":" in spec else spec
        dest = dest.removeprefix("refs/heads/")
        if dest in PROTECTED or spec.startswith(":"):
            block("pushing to main/master (or deleting a branch) is not allowed; open a pull request.")
    if on_protected:
        block(f"you are on '{branch}'; push from a feature branch.")


def main() -> None:
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)  # never break the session on malformed input

    tool = data.get("tool_name", "")
    tool_input = data.get("tool_input") or {}
    cwd = data.get("cwd") or "."

    if tool in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        repo = os.path.dirname(path) if os.path.isabs(path) and os.path.isdir(os.path.dirname(path)) else cwd
        branch, on_protected = branch_state(repo)
        if on_protected:
            block(
                f"the repository is on '{branch}'. Create a branch first, e.g. "
                "`git switch -c <issue-number>-<short-name>`, then retry."
            )
        sys.exit(0)

    if tool != "Bash":
        sys.exit(0)

    cur = cwd  # follows `cd` within one compound command
    for tokens in split_commands(tool_input.get("command", "")):
        if tokens and tokens[0] in ("cd", "pushd"):
            dest = os.path.expanduser(tokens[1]) if len(tokens) > 1 else os.path.expanduser("~")
            cur = os.path.normpath(os.path.join(cur, dest))
            continue
        parsed = parse_git(tokens)
        if not parsed:
            continue
        repo_dir, sub, args = parsed
        if repo_dir:
            repo_dir = os.path.expanduser(repo_dir)
            target = os.path.normpath(os.path.join(cur, repo_dir))
        else:
            target = cur
        branch, on_protected = branch_state(target)
        if sub == "commit":
            check_commit(args, on_protected, branch)
        elif sub == "push":
            check_push(args, on_protected, branch)

    sys.exit(0)


if __name__ == "__main__":
    main()
