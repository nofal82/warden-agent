#!/usr/bin/env python3
"""Mutation check of the contract tests: break the real .proto, prove a test fails.

Each mutation edits one .proto file in a temporary copy of the repository,
regenerates the Go code with the pinned protoc and plugins
(api/proto/warden/v1/README.md), runs the contract tests and requires every
named test to fail. A mutation that no named test catches is a gap in the
contract tests. The repository itself is never modified.

It reproduces the deliberate breaks of PR #13 that its description records
and adds the checks of PR #16 (redaction R5 class table, R14/R15, enums,
option-derived rules). Run from the repository root, with protoc-gen-go and
protoc-gen-go-grpc on PATH:

    python3 api/proto/mutation_check.py --protoc /path/to/protoc/bin/protoc

The include directory is taken from the protoc release layout
(<release>/include, next to bin/). Exit status 0 means every mutation was
caught. Developer tool only: it is not part of any shipped binary, and it
runs its tools with argument lists, never a shell.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

PROTOC_VERSION = "libprotoc 36.2"
PLUGIN_VERSIONS = {
    "protoc-gen-go": "v1.36.12",
    "protoc-gen-go-grpc": "1.6.2",
}
PACKAGES = ["./api/proto/warden/v1/", "./api/proto/warden/agentapi/v1/"]
V1 = "api/proto/warden/v1/"
AGENTAPI = "api/proto/warden/agentapi/v1/"
TIMEOUT = 600  # seconds, per tool run

# (id, what it breaks, file, old text, new text, tests that must fail).
# old must occur exactly once in the file. An entry "build:<file>" instead
# of a test name means the test package must fail to compile in <file>: a
# check made by the Go type system (TestOptionalGoTypes uses the Go type
# of every optional field, so dropping optional breaks the build there).
MUTATIONS = [
    # PR #13's recorded breaks.
    ("hello-limit", "Hello's size limit changed tenfold",
     AGENTAPI + "stream.proto",
     "message Hello {\n  option (warden.v1.max_message_bytes) = 512;",
     "message Hello {\n  option (warden.v1.max_message_bytes) = 5120;",
     ["TestGoldenOptionsAgentapi"]),
    ("drop-optional", "optional dropped from an allow-listed field",
     V1 + "executor.proto",
     "optional int32 exit_status = 11;", "int32 exit_status = 11;",
     ["build:presence_test.go"]),
    ("class-changed", "a redaction class changed (LogEvent.extract E_TEXT to X)",
     AGENTAPI + "telemetry.proto",
     "(warden.v1.redact_class) = REDACT_FIELD_CLASS_E_TEXT",
     "(warden.v1.redact_class) = REDACT_FIELD_CLASS_X",
     ["TestGoldenOptionsAgentapi", "TestClassTableGenerated"]),
    ("class-removed", "a redaction class removed (LogEvent.extract)",
     AGENTAPI + "telemetry.proto",
     "(warden.v1.max_bytes) = 4096,\n    (warden.v1.redact_class) = REDACT_FIELD_CLASS_E_TEXT",
     "(warden.v1.max_bytes) = 4096",
     ["TestRedactClassInR5Scope", "TestClassTableGenerated"]),
    ("exempt-bounded", "an exempt field given max_bytes (EnvelopeDelivery.signed_envelope)",
     AGENTAPI + "stream.proto",
     "bytes signed_envelope = 1;",
     "bytes signed_envelope = 1 [(warden.v1.max_bytes) = 65536];",
     ["TestBoundOptions"]),
    ("status-field-31", "field 31 added to ExecutorStatusBody (an M2 field)",
     V1 + "executor.proto",
     "  uint64 result_sequence = 30;\n}",
     "  uint64 result_sequence = 30;\n  bytes boot_id = 31 [(warden.v1.redact_class) = REDACT_FIELD_CLASS_X];\n}",
     ["TestGoldenOptionsNewV1"]),
    ("extra-end-reason", "an extra EndReason value",
     AGENTAPI + "errors.proto",
     "END_REASON_DUPLICATE_IDENTITY = 18;",
     "END_REASON_DUPLICATE_IDENTITY = 18;\n  END_REASON_PROBE = 19;",
     ["TestAgentapiEnumValues"]),
    ("connect-not-bidi", "Connect made non-bidirectional",
     AGENTAPI + "service.proto",
     "rpc Connect(stream AgentMessage) returns (stream ControlMessage);",
     "rpc Connect(stream AgentMessage) returns (ControlMessage);",
     ["TestServices"]),
    ("fifth-optional", "a fifth optional field in warden.agentapi.v1",
     AGENTAPI + "outbox.proto",
     "  uint32 received_size = 2",
     "  optional uint32 received_size = 2",
     ["TestOptionalAllowListAgentapi"]),
    ("beside-oneof", "a field placed beside a oneof (AgentMessage)",
     AGENTAPI + "stream.proto",
     "    HealthReport health = 4;\n  }\n}",
     "    HealthReport health = 4;\n  }\n  uint32 probe = 5;\n}",
     ["TestGoldenOptionsAgentapi"]),
    # PR #16: redaction R5, R14/R15, enums, option-derived rules.
    ("unclassified-in-variant",
     "an unclassified string inside a PrimitiveResult variant (DbSession, through the DbQueryData oneof)",
     V1 + "primitive_result.proto",
     "  uint64 transaction_age_seconds = 9;",
     "  uint64 transaction_age_seconds = 9;\n  string probe_unclassified = 10;",
     ["TestClassTableGenerated", "TestRedactClassInR5Scope"]),
    ("unclassified-in-body", "an unclassified string inside an executor body (ExecutorStatusBody)",
     V1 + "executor.proto",
     "  uint64 result_sequence = 30;\n}",
     "  uint64 result_sequence = 30;\n  string probe_unclassified = 99;\n}",
     ["TestClassTableGenerated", "TestRedactClassInR5Scope"]),
    ("class-on-inbound", "a redaction class on a control-plane-to-agent field (EndDetail)",
     AGENTAPI + "errors.proto",
     "EndReason reason = 1 [(warden.v1.required) = true];",
     "EndReason reason = 1 [(warden.v1.required) = true, (warden.v1.redact_class) = REDACT_FIELD_CLASS_X];",
     ["TestClassTableGenerated"]),
    ("string-in-health", "a string with class X nested in HealthReport (RedactDropCount)",
     AGENTAPI + "stream.proto",
     "  uint64 dropped = 2 [(warden.v1.max_uint) = 1099511627776];",
     "  uint64 dropped = 2 [(warden.v1.max_uint) = 1099511627776];\n"
     "  string probe = 3 [(warden.v1.max_bytes) = 8, (warden.v1.redact_class) = REDACT_FIELD_CLASS_X];",
     ["TestStructuralOnlyMessages"]),
    ("stale-class-table", "a classified field added without regenerating classtable_gen.go",
     V1 + "primitive_result.proto",
     "  uint64 transaction_age_seconds = 9;",
     "  uint64 transaction_age_seconds = 9;\n"
     "  string probe_classified = 10 [(warden.v1.redact_class) = REDACT_FIELD_CLASS_T_NAME];",
     ["TestClassTableGenerated"]),
    ("unit-id-no-pattern", "the pattern dropped from LogEvent.unit_id (the agent must refuse, not crash)",
     AGENTAPI + "telemetry.proto",
     '    (warden.v1.pattern) = "^[A-Za-z0-9][A-Za-z0-9:_.@-]{0,240}\\\\.service$",\n',
     "",
     ["TestGoldenOptionsAgentapi", "TestCheckRulesOnContract", "TestValidUnitID"]),
    ("extra-engine", "an extra Engine value",
     V1 + "typed_request.proto",
     "ENGINE_MONGODB = 3;",
     "ENGINE_MONGODB = 3;\n  ENGINE_PROBE = 4;",
     ["TestPreM1EnumValues"]),
]


def run(args, cwd, env=None):
    return subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True,
                          timeout=TIMEOUT, check=False)


def check_tools(protoc):
    out = run([protoc, "--version"], ".").stdout.strip()
    if out != PROTOC_VERSION:
        sys.exit(f"protoc reports {out!r}, want {PROTOC_VERSION!r}")
    for tool, want in PLUGIN_VERSIONS.items():
        path = shutil.which(tool)
        if path is None:
            sys.exit(f"{tool} not on PATH")
        got = run([path, "--version"], ".").stdout.strip()
        if not got.endswith(want):
            sys.exit(f"{tool} reports {got!r}, want version {want}")


def copy_repo(dst):
    files = run(["git", "ls-files", "-z"], ".").stdout.split("\0")
    for f in filter(None, files):
        if not os.path.isfile(f):
            continue  # deleted in the working tree
        os.makedirs(os.path.join(dst, os.path.dirname(f)), exist_ok=True)
        shutil.copy2(f, os.path.join(dst, f))


def generate(root, protoc, include):
    protos = sorted(
        os.path.join(d, f)
        for d in (V1, AGENTAPI)
        for f in os.listdir(os.path.join(root, d)) if f.endswith(".proto")
    )
    return run([protoc, "-I", "api/proto", "-I", include,
                "--go_out=.", "--go_opt=module=github.com/nofal82/warden-agent",
                "--go-grpc_out=.", "--go-grpc_opt=module=github.com/nofal82/warden-agent",
                *protos], root)


def snapshot(root):
    """Contents of every .proto and .pb.go of the contract, for restoring."""
    out = {}
    for d in (V1, AGENTAPI):
        for f in os.listdir(os.path.join(root, d)):
            if f.endswith(".proto") or f.endswith(".pb.go"):
                with open(os.path.join(root, d, f), encoding="utf-8") as fh:
                    out[d + f] = fh.read()
    return out


def restore(root, snap):
    for d in (V1, AGENTAPI):
        for f in os.listdir(os.path.join(root, d)):
            if (f.endswith(".proto") or f.endswith(".pb.go")) and d + f not in snap:
                os.remove(os.path.join(root, d, f))
    for path, text in snap.items():
        with open(os.path.join(root, path), "w", encoding="utf-8") as fh:
            fh.write(text)


def failed_tests(output):
    return set(re.findall(r"^\s*--- FAIL: (\w+)", output, re.MULTILINE))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--protoc", required=True, help="path to the pinned protoc binary")
    ap.add_argument("--only", help="run only the mutation with this id")
    args = ap.parse_args()
    protoc = os.path.abspath(args.protoc)
    include = os.path.join(os.path.dirname(os.path.dirname(protoc)), "include")
    if not os.path.isfile(os.path.join(include, "google/protobuf/descriptor.proto")):
        sys.exit(f"no google/protobuf/descriptor.proto under {include}")
    check_tools(protoc)

    root = tempfile.mkdtemp(prefix="warden-mutation-")
    try:
        copy_repo(root)
        snap = snapshot(root)
        gen = generate(root, protoc, include)
        if gen.returncode != 0:
            sys.exit("baseline generation failed:\n" + gen.stderr)
        if snapshot(root) != snap:
            sys.exit("baseline: regenerated code differs from the committed .pb.go files")
        base = run(["go", "test", "-count=1", *PACKAGES], root)
        if base.returncode != 0:
            sys.exit("baseline: contract tests fail before any mutation:\n" + base.stdout[-4000:])
        print("baseline: regenerated code matches, contract tests pass")

        missed = []
        for mid, what, path, old, new, want in MUTATIONS:
            if args.only and mid != args.only:
                continue
            restore(root, snap)
            full = os.path.join(root, path)
            with open(full, encoding="utf-8") as fh:
                text = fh.read()
            if text.count(old) != 1:
                missed.append(mid)
                print(f"SETUP  {mid}: the text to replace occurs {text.count(old)} times in {path}")
                continue
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(text.replace(old, new))
            gen = generate(root, protoc, include)
            if gen.returncode != 0:
                missed.append(mid)
                print(f"SETUP  {mid}: protoc rejected the mutation:\n{gen.stderr}")
                continue
            tests = [t for t in want if not t.startswith("build:")]
            builds = [t[len("build:"):] for t in want if t.startswith("build:")]
            res = run(["go", "test", "-count=1", "-run", "^(" + "|".join(tests or ["NONE"]) + ")$", *PACKAGES], root)
            output = res.stdout + res.stderr
            failed = failed_tests(output)
            failed.update("build:" + f for f in builds
                          if "[build failed]" in output and re.search(re.escape(f) + r":\d+", output))
            absent = [t for t in want if t not in failed]
            if res.returncode == 0 or absent:
                missed.append(mid)
                print(f"MISSED {mid}: {what}; not failing: {', '.join(absent) or '(go test passed)'}")
            else:
                print(f"caught {mid}: {what} -> {', '.join(sorted(failed))}")
        restore(root, snap)
        if missed:
            print(f"\n{len(missed)} mutation(s) not caught: {', '.join(missed)}")
            return 1
        print("\nevery mutation was caught")
        return 0
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
