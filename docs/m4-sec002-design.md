# M4 SEC-002 Design Gate

## Decision

M4 v0 will use **non-bypassable brokered workspace access**, not a writable host-shadow mount inside the untrusted agent container.

The untrusted agent process receives:

- an ephemeral scratch filesystem that is not a Mirage protected workspace;
- no real repository mount;
- no Mirage shadow-directory mount;
- no host credentials;
- no Docker socket;
- no direct outbound network;
- one narrowly scoped Mirage capability channel for supported filesystem operations.

The trusted Mirage worker remains outside the agent runtime and exclusively owns the shadow transaction.

```text
Untrusted agent container
        |
        | typed capability request
        v
Mirage broker / gateway     [trusted]
        |
        | contract + limits + audit
        v
Mirage shadow transaction   [trusted-owned]
        |
        | freeze + verify + commit binding
        v
Real workspace
```

## Why this is the M4 v0 choice

A normal writable bind mount would let an agent call `open`, `write`, `rename`, or shell utilities directly against the shadow. Those operations would bypass M3's Effect Event path unless Mirage added a kernel/filesystem interception mechanism. Merely putting that mount inside rootless Docker would isolate the host but would **not** make filesystem effects observable to Mirage.

For the competition prototype, the narrow brokered model gives a provable boundary without pretending that Docker itself provides effect mediation.

## M4 invariants

1. The untrusted process cannot name or open the real workspace.
2. The untrusted process cannot name or open Mirage's transaction-owned shadow directory.
3. Supported protected filesystem reads/writes can occur only through the trusted capability broker.
4. The broker enforces the immutable Effect Contract before protected I/O.
5. Every successful mediated WRITE records the SHA-256 identity of the resulting managed-file bytes.
6. Verification approves effect sequences; commit derives mutation authority from those approved effects.
7. Immediately before commit, the frozen shadow identity must match the result identity of the final approved WRITE.
8. If no WRITE was approved, commit is a real no-op and must not replace the protected file.
9. The runtime is frozen/stopped before verification and remains unable to mutate protected shadow state through commit.
10. Direct sandbox network egress is disabled; future approved network access is brokered separately.

## Shell semantics for M4 v0

Shell execution is allowed only against the container's disposable scratch filesystem. It does not grant access to the protected repository or Mirage shadow.

This means M4 v0 is intentionally not yet a drop-in `mirage run codex` implementation. The milestone proves the hostile-process trust boundary first. A later milestone may evaluate a brokered filesystem mount (for example FUSE), stronger sandbox runtimes, or independently reconciled workspace mechanisms for compatibility with agents that require ordinary POSIX filesystem access.

## Defense in depth

Even though M4 v0 forces protected writes through mediation, Mirage still performs a final shadow/effect reconciliation before commit:

```text
final approved WRITE result digest
             ==
validated frozen shadow digest
```

A mismatch rejects the run. This protects against trusted adapter bugs, accidental out-of-band shadow mutation, and future runtime integration mistakes.

## Resource bounds

Before the hostile process is enabled, the trusted runtime must enforce bounded resource use. M3.5 establishes initial hard limits for:

- managed-file bytes;
- filesystem write payload bytes;
- virtual resource-path bytes;
- Effect Events per run.

M4 must additionally add process-level limits for wall time, CPU, memory, process count, and output volume at the sandbox boundary.

## Explicitly deferred

M4 v0 does not claim:

- transparent arbitrary POSIX workspace access;
- syscall-complete filesystem auditing;
- FUSE correctness;
- kernel-level provenance tracking;
- arbitrary multi-file repository transactions;
- protection from a compromised Mirage host/kernel.

Those are separate engineering problems and must not be smuggled into M4 under a vague "Docker sandbox" label.

## M4 implementation may begin only when

- M3.5 commit/effect binding tests are green;
- trusted resource-limit tests are green;
- Linux race/symlink CI is green;
- the runtime design preserves the no-real/no-shadow-mount invariant above.
