#!/usr/bin/env python3
"""CI gate for executor-ipc AC2a (R2, R2a): the executor has no network.

Scope: every Go package under internal/executor/ and cmd/warden-executor/
(non-test files; tests may dial the executor's own Unix socket as a client).

Fails (exit 1) when:
  * `go list -deps` (GOOS=linux, CGO_ENABLED=0, as shipped) shows a package
    on the R2a list: net/http and net/http/..., net/rpc and net/rpc/...,
    net/smtp, crypto/tls, google.golang.org/grpc/..., google.golang.org/genproto/...,
    or the module's api/proto/warden/agentapi/v1 (warden.agentapi.v1)
  * the source dials (net.Dial*, net.Dialer, raw connect), resolves names
    (net.Lookup*, net.Resolver, net.Resolve{TCP,UDP,IP}Addr), or opens a
    socket other than the R1 listeners (net.ListenTCP/UDP/IP/Packet/...,
    net.ListenConfig, net.File*, syscall/unix Socket/Bind/Connect, AF_INET*)
  * net.Listen / net.ListenUnix is called with a network other than the
    literal "unix", used as a value, or appears at more than two call sites
    (R1: the agent socket and the root socket)
  * "net", "syscall" or "golang.org/x/sys/unix" is imported under another
    name (an alias would hide the calls from this scan)
  * `go list` itself fails (the check never passes on an error)

Usage: python3 .github/scripts/check_executor_net.py [--root DIR]
"""
import argparse
import os
import re
import subprocess
import sys

SCAN_DIRS = ("internal/executor", "cmd/warden-executor")
MAX_LISTENERS = 2  # R1: agent socket and root socket

FORBIDDEN_EXACT = {"net/smtp", "crypto/tls"}
FORBIDDEN_TREES = (
    "net/http",
    "net/rpc",
    "google.golang.org/grpc",
    "google.golang.org/genproto",
)
AGENTAPI_SUFFIX = "/api/proto/warden/agentapi/v1"

SOURCE_RULES = [
    (r"\bnet\.(Dial\w*|Dialer)\b", "dials out (R2)"),
    (r"\bnet\.(Lookup\w*|Resolver|DefaultResolver|Resolve(TCP|UDP|IP)Addr)\b",
     "resolves names (R2a)"),
    (r"\bnet\.(Listen(TCP|UDP|IP|Packet|MulticastUDP|Unixgram|Config)|"
     r"File(Listener|Conn|PacketConn))\b",
     "opens a socket other than the two R1 unix listeners (R2)"),
    (r"\b(syscall|unix)\.(Socket|Socketpair|Connect|Bind|Listen)\b",
     "raw socket call (R2: no third socket)"),
    (r"\b(syscall|unix)\.AF_INET6?\b", "network address family (R2)"),
    (r"\bnet\.(Listen|ListenUnix)\b(?!\s*\()",
     "listener function used as a value; call it directly with \"unix\""),
]
LISTEN_CALL = re.compile(r"\bnet\.(Listen|ListenUnix)\s*\(")
ALIASED_IMPORT = re.compile(
    r'(?<![\w.])([A-Za-z_]\w*|\.)\s+"(net|syscall|golang\.org/x/sys/unix)"')


def forbidden(pkg: str, module: str) -> bool:
    if pkg in FORBIDDEN_EXACT:
        return True
    if any(pkg == t or pkg.startswith(t + "/") for t in FORBIDDEN_TREES):
        return True
    api = module + AGENTAPI_SUFFIX
    return pkg == api or pkg.startswith(api + "/")


def read_module(root: str) -> str:
    with open(os.path.join(root, "go.mod"), encoding="utf-8") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "module":
                return parts[1].strip('"')
    raise ValueError("go.mod has no module line")


def package_dirs(root: str) -> list:
    """Directories holding non-test Go files, skipping what Go ignores."""
    found = []
    for base in SCAN_DIRS:
        top = os.path.join(root, base)
        for dirpath, dirnames, filenames in os.walk(top):
            dirnames[:] = sorted(d for d in dirnames
                                 if d != "testdata" and d[0] not in "._")
            if any(f.endswith(".go") and not f.endswith("_test.go")
                   for f in filenames):
                found.append(os.path.relpath(dirpath, root))
    return sorted(found)


def blank(src: str) -> tuple:
    """Return (code with comments removed, same with string bodies blanked).

    Both keep every offset, so a match in the blanked text can be read back
    in the first. Text inside strings and comments is never matched.
    """
    nocomment, blanked = [], []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            pad = " " * (j - i)
            nocomment.append(pad)
            blanked.append(pad)
            i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            pad = "".join(ch if ch == "\n" else " " for ch in src[i:j])
            nocomment.append(pad)
            blanked.append(pad)
            i = j
        elif c in "\"'`":
            j = i + 1
            while j < n and src[j] != c:
                if c != "`" and src[j] == "\\":
                    j += 1
                j += 1
            j = min(j + 1, n)
            lit = src[i:j]
            nocomment.append(lit)
            blanked.append(c + "".join(ch if ch == "\n" else " "
                                       for ch in lit[1:-1]) + lit[-1:])
            i = j
        else:
            nocomment.append(c)
            blanked.append(c)
            i += 1
    return "".join(nocomment), "".join(blanked)


def scan_source(root: str, dirs: list) -> tuple:
    problems, listeners = [], []
    for d in dirs:
        for name in sorted(os.listdir(os.path.join(root, d))):
            if not name.endswith(".go") or name.endswith("_test.go"):
                continue
            rel = os.path.join(d, name)
            with open(os.path.join(root, rel), encoding="utf-8") as fh:
                code, blanked = blank(fh.read())

            def where(pos: int) -> str:
                return f"{rel}:{code.count(chr(10), 0, pos) + 1}"

            for m in ALIASED_IMPORT.finditer(code):
                if m.group(1) != "import":
                    problems.append(f"{where(m.start())}: imports "
                                    f'"{m.group(2)}" as {m.group(1)} (R2a)')
            for pattern, why in SOURCE_RULES:
                for m in re.finditer(pattern, blanked):
                    problems.append(f"{where(m.start())}: {m.group(0)} {why}")
            for m in LISTEN_CALL.finditer(blanked):
                listeners.append(where(m.start()))
                arg = code[m.end():].lstrip()
                if not arg.startswith('"unix"'):
                    problems.append(f"{where(m.start())}: {m.group(0)} with a "
                                    'network other than the literal "unix" (R2a)')
    if len(listeners) > MAX_LISTENERS:
        problems.append(f"{len(listeners)} listener call sites, at most "
                        f"{MAX_LISTENERS} allowed (R1): {', '.join(listeners)}")
    return problems, listeners


def check_deps(root: str, dirs: list, module: str) -> list:
    env = dict(os.environ, GOOS="linux", CGO_ENABLED="0", GOFLAGS="")
    out = subprocess.run(
        ["go", "list", "-deps", "-f", "{{.ImportPath}}"]
        + ["./" + d for d in dirs],
        cwd=root, env=env, capture_output=True, text=True, timeout=300,
        check=False,
    )
    if out.returncode != 0:
        return ["go list -deps failed:\n" + out.stderr.strip()]
    return [f"executor depends on forbidden package {p} (R2a)"
            for p in out.stdout.split() if forbidden(p, module)]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=".", help="module root (default .)")
    args = ap.parse_args()
    root = os.path.abspath(args.root)
    module = read_module(root)
    dirs = package_dirs(root)
    if not dirs:
        print("executor-net: no executor Go packages yet; nothing to check")
        return 0
    problems = check_deps(root, dirs, module)
    src_problems, listeners = scan_source(root, dirs)
    problems += src_problems
    if problems:
        print("executor-net: AC2a violations:")
        for p in problems:
            print("  " + p)
        return 1
    print(f"executor-net: ok ({len(dirs)} packages, "
          f"{len(listeners)} unix listener call sites)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
