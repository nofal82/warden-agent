---
name: new-typed-primitive
description: How to add or change a typed primitive in warden-executor (for example service.restart, file.delete_by_age, db.terminate_session) — spec check, attack tests first, typed request, validator, fixed implementation, fuzzing, security-critical PR. Use for any work under internal/executor/.
argument-hint: "[primitive name, e.g. service.restart]"
---

# New or changed typed primitive: $ARGUMENTS

Every primitive change is **security-critical**. Follow all steps.

## 1. Confirm it is in the catalog
Open `~/cloudvertex/warden/specs/` and find the typed action catalog entry for
`$ARGUMENTS`. It must define: parameters with types and limits, allowed
targets, timeout, idempotency behaviour, rollback, and result fields.
If the primitive or any of these is missing, stop and ask Nofal. Never invent
a primitive.

## 2. Attack tests first
Delegate to the `attack-test-writer` subagent with the catalog entry. Commit
the failing tests before writing any implementation.

## 3. Implement in this shape

```
internal/executor/primitives/<area>/<name>.go
  type <Name>Request struct { ... }          // typed fields only, no free strings for commands
  func (r <Name>Request) Validate(inv Inventory) error
  func <Name>(ctx context.Context, r <Name>Request) (Result, error)
```

Rules:
- `Validate` runs before anything else and rejects by default. Allow-lists,
  not deny-lists.
- Paths: `filepath.Clean`, then `filepath.EvalSymlinks`, then check the
  resolved path is inside an allowed root. Open with flags that avoid
  following symlinks where possible, and re-check after open to close
  check-then-use gaps.
- Names (services, units, containers, databases, users): strict regular
  expression AND present in the discovered inventory passed in.
- Numbers, sizes, durations, counts: explicit minimum and maximum.
- Process execution: `exec.CommandContext(ctx, "/absolute/path/to/binary", args...)`
  where every element of `args` comes from validated fields. Never a shell,
  never string concatenation into one argument, and pass `--` before
  positional values when the binary supports it.
- Always a `context` timeout. Always idempotent: running twice equals running
  once. Return a structured `Result` (what changed, before/after state).
- Databases: use the engine adapter; parameterised SQL, typed MongoDB
  commands (no `$where`, no operators taken from input).
- No network imports anywhere in the executor.

## 4. Verify
- `make ci` and `make fuzz-short` (raise `FUZZTIME=2m` before opening the PR).
- Coverage for `internal/executor/` stays at or above 90%.
- Add the lab scenarios for the playbooks that use this primitive (in the
  `warden` repository, separate PR).

## 5. Pull request
Label `security-critical`. In the description, include the attacker's view:
what someone controlling the input could try, and which line stops each
attempt. Run `spec-checker`, `security-reviewer` and `pr-walkthrough`.
