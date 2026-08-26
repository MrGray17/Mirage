# Pre-M4 Security Guarantees

This document records the precise guarantees of the pre-M4 runtime hardening line and narrows any broader wording elsewhere in the architecture. It is intentionally limited to claims the current implementation can prove.

## TIME-001 — trusted run time

Each run owns one trusted wall-clock authority and remembers the greatest UTC instant that Mirage has actually observed during that run.

- Equal observations are valid.
- An observation earlier than the greatest previously observed instant is a structured rollback failure.
- A rollback failure makes the run non-committable and fails closed.
- Once Mirage has observed the contract expiry instant or a later instant, a later backward reading cannot make that contract valid again during the same run.

This is not a claim that Mirage knows true global time. A clock jump or freeze that occurs entirely between Mirage observations cannot be detected merely from local observations. The guard establishes monotonicity of **observed** trusted time, not global clock correctness.

## EVT-001 — event-time ownership and audit failure

Adapters cannot choose Effect Event timestamps. The trusted event log assigns run identity, actor identity, sequence, event ID, and UTC timestamp using the run's shared trusted clock.

A successfully timestamped mediated filesystem request produces exactly one Effect Event describing allowed success, allowed failure, or denied/blocked behavior.

If the trusted time authority fails or rolls backward before an event can be appended, Mirage records a run-level audit-integrity failure instead of fabricating an event timestamp. The operation returns an error, the run is made non-committable, and shadow state is discarded or left only for explicit cleanup retry if cleanup itself fails.

Therefore the security invariant is not "an Effect Event always exists under every failure." It is:

> A mediated operation must either produce canonical audit evidence or make the run non-committable.

Canonical Effect Events must contain a non-zero UTC timestamp. A zero/uninitialized timestamp is invalid canonical evidence.

## SEC-001 — filesystem object acquisition

For the current single-file filesystem prototype, Mirage opens the workspace through Go `os.Root`, inspects `README.md`, opens the resource relative to that root without truncating it first, verifies that the opened handle is a regular file and still corresponds to the named regular entry, and revalidates the named entry after reads/writes.

This closes the original separated `Lstat -> ReadFile/Open` race on the mediated path and detects the tested type/symlink replacement races before use.

It does **not** provide complete hostile-filesystem containment. Residual limitations include:

- a non-cooperating actor replacing the named entry after validation but before or during I/O;
- hard-link, mount, bind-mount, special-filesystem, and platform-specific behavior outside the current guarantees;
- metadata-preserving in-place races;
- the M2 final revalidation-to-rename race.

A post-validation path replacement may allow Mirage to touch the already-open shadow handle before final validation detects that the named entry changed. Such detection must make the run non-committable; Mirage does not claim that no shadow mutation occurred in this residual race window.

## SEC-002 — M4 non-bypass requirement

SEC-001 is not SEC-002.

Before an actual untrusted coding-agent process is treated as secure, M4 must prove one of the following for every security-relevant filesystem effect:

1. the effect is forced through Mirage mediation, or
2. the effect is independently observed and reconciled by trusted Mirage code before verification/commit.

Simply mounting the shadow workspace writable into a container and trusting the agent to call Mirage APIs is insufficient. M4 must prevent or detect direct OS-level bypass of the effect-observation path.

## Evidence gate before M4 implementation

The repository must run its Go security suite on Linux with Go 1.24, including race detection and symlink-capable filesystem tests. Windows-local skips are reported as skips and are not treated as evidence that those cases passed.
