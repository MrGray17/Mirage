# Pre-M4 Security Guarantees

This document records the precise guarantees of the pre-M4 runtime hardening line and narrows any broader wording elsewhere in the architecture. It is intentionally limited to claims the current implementation can prove.

## AUTH-001 — verified effect to commit binding

An `APPROVED` verifier status is necessary but no longer sufficient to replace the real managed file.

At verification, the run freezes the final shadow content identity, compares it with the transaction baseline, and derives whether the verifier actually approved a successful filesystem `WRITE` for `/workspace/README.md` from `ApprovedEffects` plus the canonical event stream.

- If the final shadow differs from baseline, a successful filesystem `WRITE` for that managed resource must be among the verifier-approved effects. Otherwise the run is rejected as `shadow.unobserved_mutation`.
- If the final shadow equals baseline, the final diff is empty. The run finalizes by deleting the shadow and marking the transaction committed **without replacing the real `README.md`**, even if an allowed write event occurred but ultimately produced no state change.
- For a non-empty authorized mutation, the frozen shadow identity is passed into the transaction commit path.
- Immediately before any real replacement, the transaction rereads the bounded shadow and requires its identity to equal the verification snapshot.
- A post-verification shadow change is `ErrShadowChanged`, discards the compromised shadow, and makes the run `REJECTED`.

For the current single-file contract, write authority is resource-scoped rather than content-scoped. This hardening does not claim to detect a hostile process that bypasses mediation before verification after at least one legitimate approved write. That remains part of SEC-002.

## DOS-001 — trusted-process resource budgets

The pre-M4 prototype has explicit fail-closed budgets:

- managed `README.md` content: at most 4 MiB;
- in-memory Effect Events: at most 1024 per run;
- virtual resource identifier: at most 4096 bytes.

Baseline creation, shadow reads, real-state revalidation, and commit staging use bounded reads/writes. Oversized mediated writes are blocked and recorded. Once the event budget is exhausted, the gateway refuses to execute another mediated operation; the audit-integrity failure immediately rejects the run.

These are prototype budgets, not production sizing claims. M4 must additionally bound process memory/CPU/PIDs, request-body parsing, runtime duration, and output/log volume at the sandbox/control-plane boundary.

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

If the trusted time authority fails, rolls backward, or the bounded in-memory event stream cannot accept another event, Mirage records a run-level audit-integrity failure instead of fabricating evidence. The operation returns an error, the run is made non-committable immediately, and shadow state is discarded or left only for explicit cleanup retry if cleanup itself fails.

Therefore the security invariant is not "an Effect Event always exists under every failure." It is:

> A mediated operation must either produce canonical audit evidence or make the run non-committable.

Canonical Effect Events must contain a non-zero UTC timestamp. A zero/uninitialized timestamp is invalid canonical evidence.

## SEC-001 — filesystem object acquisition

For the current single-file filesystem prototype, Mirage opens the workspace through Go `os.Root`, inspects `README.md`, opens the resource relative to that root without truncating it first, verifies that the opened handle is a regular file and still corresponds to the named regular entry, and revalidates the named entry after reads/writes.

This closes the original separated `Lstat -> ReadFile/Open` race on the mediated path and detects the tested type/symlink replacement races before use.

These operations are safer object acquisition, not complete hostile-filesystem containment. Residual limitations include:

- a non-cooperating actor replacing the named entry after validation but before or during I/O;
- hard-link, mount, bind-mount, special-filesystem, and platform-specific behavior outside the current guarantees;
- metadata-preserving in-place races;
- the M2 final real-state revalidation-to-rename race;
- a workspace root is still represented by a host pathname rather than a durable resource handle across the entire transaction lifetime.

A post-validation path replacement may allow Mirage to touch the already-open shadow handle before final validation detects that the named entry changed. Such detection must make the run non-committable; Mirage does not claim that no shadow mutation occurred in this residual race window.

## SEC-002 — M4 non-bypass requirement

AUTH-001 is not SEC-002. Final-state commit binding prevents a clean no-write audit stream from committing a changed shadow, and post-verification changes are detected. It does **not** prove that every effect of an actual hostile process was observed.

Before an actual untrusted coding-agent process is treated as secure, M4 must prove one of the following for every security-relevant filesystem effect:

1. the effect is forced through Mirage mediation, or
2. the effect is independently observed and reconciled by trusted Mirage code before verification/commit.

Simply mounting the shadow workspace writable into a container and trusting the agent to call Mirage APIs is insufficient. M4 must prevent or detect direct OS-level bypass of the effect-observation path.

## Evidence gate before M4 implementation

The repository must run its Go security suite on Linux with Go 1.24, including race detection and symlink-capable filesystem tests. Windows-local skips are reported as skips and are not treated as evidence that those cases passed. The Linux evidence suite additionally contains a non-skippable capability test so an unsuitable CI filesystem cannot silently masquerade as proof.
