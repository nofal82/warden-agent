#!/usr/bin/env python3
"""Self-test for the Claude Code guard hooks. Run with `make hooks-test`.

Each case feeds a hook the JSON Claude Code would send and checks the exit
code: 0 = allowed, 2 = blocked. Run in a throwaway git repo so branch checks
are realistic.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE_KEY = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIfake\n"
SHELL_GO = 'package x\nimport "os/exec"\nfunc f() { exec.Command("' + 'sh", "-c", "id") }\n'
EXEC_GO = 'package x\nimport "os/exec"\nfunc f() { exec.Command("/usr/bin/systemctl", "restart", "nginx") }\n'


def run(hook, payload, project, env_extra=None):
    env = dict(os.environ, CLAUDE_PROJECT_DIR=project)
    env.pop("WARDEN_ALLOW_GUARDRAIL_EDITS", None)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, hook)],
        input=json.dumps(payload), capture_output=True, text=True, env=env,
    )
    return proc.returncode


def main() -> int:
    policy = json.load(open(os.path.join(HERE, "policy.json")))
    allowed = policy.get("exec_allowed_paths", [])
    exec_ok_file = allowed[0].replace("*", "run.go") if allowed else None

    failures = 0
    with tempfile.TemporaryDirectory() as repo:
        def git(*a):
            subprocess.run(["git", "-C", repo, *a], check=True, capture_output=True)
        git("init", "-q", "-b", "main")
        git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "init")

        def edit(rel, content, tool="Write"):
            key = "content" if tool == "Write" else "new_string"
            return {"tool_name": tool, "cwd": repo,
                    "tool_input": {"file_path": os.path.join(repo, rel), key: content}}

        def bash(cmd):
            return {"tool_name": "Bash", "cwd": repo, "tool_input": {"command": cmd}}

        cases = [
            # (description, hook, payload, expected exit, extra env)
            ("edit on main is blocked", "guard_branch.py", edit("a.go", "package a"), 2, None),
            ("commit on main is blocked", "guard_branch.py", bash("git commit -m x"), 2, None),
            ("creating branch named *commit* on main is allowed", "guard_branch.py", bash("git switch -c 12-commit-signing"), 0, None),
            ("creating branch named *push* on main is allowed", "guard_branch.py", bash("git checkout -b 7-push-metrics"), 0, None),
            ("pull on main is allowed", "guard_branch.py", bash("git switch main && git pull --ff-only"), 0, None),
        ]
        for desc, hook, payload, want, extra in cases:
            failures += check(desc, run(hook, payload, repo, extra), want)

        git("switch", "-q", "-c", "1-test")
        cases = [
            ("edit on a feature branch is allowed", "guard_branch.py", edit("a.go", "package a"), 0, None),
            ("commit on a feature branch is allowed", "guard_branch.py", bash("git add . && git commit -m 'feat: x'"), 0, None),
            ("commit -n is blocked", "guard_branch.py", bash("git commit -n -m x"), 2, None),
            ("--no-verify is blocked", "guard_branch.py", bash("git commit --no-verify -m x"), 2, None),
            ("push to main is blocked", "guard_branch.py", bash("git push origin main"), 2, None),
            ("refspec push to main is blocked", "guard_branch.py", bash("git push origin HEAD:main"), 2, None),
            ("force push is blocked", "guard_branch.py", bash("git push --force origin 1-test"), 2, None),
            ("+refspec force push is blocked", "guard_branch.py", bash("git push origin +1-test"), 2, None),
            ("normal push of branch is allowed", "guard_branch.py", bash("git push -u origin 1-test"), 0, None),
            ("chained push to main is blocked", "guard_branch.py", bash("make test && git push origin main"), 2, None),
            ("push to main on a new line is blocked", "guard_branch.py", bash("git status\ngit push origin main"), 2, None),
            ("refs/heads/main destination is blocked", "guard_branch.py", bash("git push origin feat:refs/heads/main"), 2, None),
            ("-uf force push is blocked", "guard_branch.py", bash("git push -uf origin 1-test"), 2, None),
            ("branch delete push is blocked", "guard_branch.py", bash("git push origin :old-branch"), 2, None),
            ("commit message with -n is allowed", "guard_branch.py", bash('git commit -m "Add -n dry-run flag"'), 0, None),
            ("commit message mentioning push to main is allowed", "guard_branch.py",
             bash("git commit -m \"$(cat <<'EOF'\nfeat: refuse pushes\n\ngit push origin main is refused by policy\nEOF\n)\""), 0, None),
            ("quoted multi-line message is allowed", "guard_branch.py",
             bash('git commit -m "line one\ngit push --force origin main"'), 0, None),
            ("git log -n is allowed", "guard_branch.py", bash("git log -n 5 --oneline"), 0, None),
            ("commit -am is allowed", "guard_branch.py", bash("git commit -am 'fix: x'"), 0, None),
            ("commit -uno is allowed", "guard_branch.py", bash("git commit -uno -m 'fix: x'"), 0, None),
            ("env git push --force is blocked", "guard_branch.py", bash("env git push --force origin 1-test"), 2, None),
            ("core.hooksPath override is blocked", "guard_branch.py", bash("git -c core.hooksPath=/dev/null commit -m x"), 2, None),
            ("shell in Go is blocked", "guard_code.py", edit("internal/x/x.go", SHELL_GO), 2, None),
            ("shell in Go via Edit is blocked", "guard_code.py", edit("internal/x/x.go", SHELL_GO, "Edit"), 2, None),
            ("private key is blocked", "guard_code.py", edit("testdata/k.txt", FAKE_KEY), 2, None),
            ("os/exec outside allowed path is blocked", "guard_code.py", edit("internal/agent/run.go", EXEC_GO), 2, None),
            ("CLAUDE.md edit is blocked", "guard_code.py", edit("CLAUDE.md", "x"), 2, None),
            ("hook edit is blocked", "guard_code.py", edit(".claude/hooks/guard_code.py", "x"), 2, None),
            ("workflow edit is blocked", "guard_code.py", edit(".github/workflows/ci.yml", "x"), 2, None),
            ("Makefile edit is blocked", "guard_code.py", edit("Makefile", "x"), 2, None),
            ("subagent edit is blocked", "guard_code.py", edit(".claude/agents/security-reviewer.md", "x"), 2, None),
            ("ForkExec in Go is blocked", "guard_code.py", edit("internal/x/y.go", "package x\nfunc f() { syscall.ForkExec(p, a, nil) }\n"), 2, None),
            ("guardrail edit allowed with override", "guard_code.py", edit("CLAUDE.md", "x"), 0, {"WARDEN_ALLOW_GUARDRAIL_EDITS": "1"}),
            ("edit outside the repo is blocked", "guard_code.py",
             {"tool_name": "Write", "cwd": repo, "tool_input": {"file_path": "/etc/passwd", "content": "x"}}, 2, None),
            ("normal Go edit is allowed", "guard_code.py", edit("internal/agent/run.go", "package agent\n"), 0, None),
            ("fake secret string is allowed", "guard_code.py", edit("x_test.go", 'const s = "FAKE-SECRET-123"'), 0, None),
            ("injection string as test data is allowed", "guard_code.py", edit("x_test.go", 'var bad = "; sh -c id"'), 0, None),
        ]
        if exec_ok_file:
            cases.append(("os/exec in allowed path is allowed", "guard_code.py", edit(exec_ok_file, EXEC_GO), 0, None))
            wt = os.path.join(repo, ".claude", "worktrees", "wt1", exec_ok_file)
            cases.append(("os/exec in allowed path inside a worktree is allowed", "guard_code.py",
                          {"tool_name": "Write", "cwd": repo, "tool_input": {"file_path": wt, "content": EXEC_GO}}, 0, None))
        for desc, hook, payload, want, extra in cases:
            failures += check(desc, run(hook, payload, repo, extra), want)

        # A second repository still on main: -C must be judged by ITS branch.
        with tempfile.TemporaryDirectory() as other:
            subprocess.run(["git", "-C", other, "init", "-q", "-b", "main"], check=True)
            subprocess.run(["git", "-C", other, "-c", "user.email=t@t", "-c", "user.name=t",
                            "commit", "-q", "--allow-empty", "-m", "init"], check=True)
            failures += check("git -C <repo on main> commit is blocked",
                              run("guard_branch.py", bash(f"git -C {other} commit -m x"), repo), 2)
            failures += check("cd <repo on main> && git commit is blocked",
                              run("guard_branch.py", bash(f"cd {other} && git commit -m x"), repo), 2)
            home = os.path.expanduser("~")
            if other.startswith(home + os.sep):
                failures += check("git -C ~/<repo on main> commit is blocked",
                                  run("guard_branch.py", bash("git -C ~" + other[len(home):] + " commit -m x"), repo), 2)
            failures += check("editing a file in a repo on main is blocked",
                              run("guard_branch.py", {"tool_name": "Write", "cwd": repo,
                                  "tool_input": {"file_path": os.path.join(other, "x.go"), "content": "x"}}, repo), 2)

    print(f"\n{'FAIL' if failures else 'OK'}: {failures} failing hook test(s)")
    return 1 if failures else 0


def check(desc, got, want):
    ok = got == want
    print(f"{'PASS' if ok else 'FAIL'}  {desc} (exit {got}, want {want})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
