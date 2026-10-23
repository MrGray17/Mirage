# Crash-safe local commit journal

This document describes the initial durable-journal increment for MIRAGE's existing narrow real-filesystem commit path. It does not claim a general multi-file transaction manager.

## Goal and boundary

MIRAGE must distinguish a commit that definitely did not happen from one whose outcome cannot be determined safely after interruption. Most importantly, recovery must never blindly repeat an authorized mutation: the real workspace may already have changed.

This journal is stored on the trusted host, outside the agent's disposable workspace. It records transaction metadata only. It does not store file contents, secrets, model prompts, tool output, or a complete receipt.

The journal checksum detects accidental or unauthorized record modification only when the expected checksum is retained alongside the record. It is not a digital signature, does not identify the record's author, and does not protect against a compromised host or trusted MIRAGE process.

## Commit protocol

The current single-file commit engine retains its independent rooted path checks, exact target revalidation, authority callback, and atomic replacement. The journal adds durable checkpoints around that existing boundary:

~~~text
verified authority + immutable one-file plan
               |
               v
PREPARED record written atomically
file fsync -> rename -> journal-directory fsync
               |
               v
existing target and staging checks
final lifecycle-owned authority check
               |
               v
APPLYING intent written atomically and durably
file fsync -> rename -> journal-directory fsync
               |
               v
atomic target replacement
               |
               v
target parent directory fsync
               |
               v
COMMITTED record written atomically and durably
file fsync -> rename -> journal-directory fsync
~~~

The intent is recorded immediately before the target rename. MIRAGE does not write the intended target bytes into the journal. The durable intent contains enough identity and digest metadata to inspect the transaction later, but it is not a reusable authorization token and cannot re-authorize a new commit.

If the operation fails before the APPLYING intent is durably established, the operation is marked `ABORTED` where possible. If an error occurs after the APPLYING intent, or if the target was replaced but the final completion record cannot be persisted, MIRAGE reports `ErrOutcomeUncertain` and places the lifecycle in `RECOVERY_REQUIRED`. It does not automatically retry.

## Journal record

Each transaction record contains:

- journal schema version and deterministic transaction ID;
- immutable plan hash, run-manifest hash, authority hash, and real-baseline identity;
- absolute workspace path and observed filesystem device/inode identity;
- canonical resource path, before/after SHA-256 digests, and original permission mode;
- state, outcome label, bounded reason text, and UTC creation/update timestamps;
- checksum over the canonical JSON payload.

Record files are written with private permissions through a temporary file, file sync, atomic rename, and journal-directory sync. The journal directory is restricted to the user's account. A process lock serializes journal operations across MIRAGE processes; concurrent recovery returns a busy error while a live transaction holds the lock.

The journal is bounded to 1 MiB per record and 4096 records during recovery scanning. Records are retained as audit evidence; automatic pruning is deliberately not part of this increment. Reaching the limit is an operational condition to handle explicitly, not a reason to delete unresolved records casually.

## Recovery command

Run from Linux or the configured WSL2 backend:

~~~bash
mirage recover
~~~

An explicit journal directory is available for tests and diagnostics:

~~~bash
mirage recover --journal-dir /path/to/transactions
~~~

The command reads and validates pending records, verifies the workspace still has the same filesystem identity, inspects the exact target as a supported regular file, and compares its observed digest and mode with the journal. It does not load or re-run model output. It does not invoke the commit engine, reconstruct file contents, replay a write, or automatically repair the workspace.

| Current journal state | Observed condition | Recovery classification |
|---|---|---|
| `PREPARED` | Target matches recorded before digest and mode; workspace identity matches | `ABORTED`, outcome `NOT_COMMITTED` |
| `APPLYING` | Target matches recorded before digest and mode; workspace identity matches | `BEFORE_STATE_OBSERVED`, outcome `BEFORE_STATE_OBSERVED_ATTRIBUTION_UNCERTAIN` |
| `APPLYING` | Target matches recorded after digest and mode; workspace identity matches | `AFTER_STATE_OBSERVED`, outcome `AFTER_STATE_OBSERVED_ATTRIBUTION_UNCERTAIN` |
| Any pending state | Workspace identity, target mode, target type, or digest cannot be safely matched | `RECOVERY_REQUIRED` |
| `COMMITTED` or `ABORTED` | Terminal record with valid checksum | Not a pending transaction |

`AFTER_STATE_OBSERVED` remains visible on subsequent recovery runs rather than disappearing from the unresolved list. The operator must inspect this outcome. The fact that the target currently has the planned after digest does not by itself prove who produced that state.

A matching before-state is sufficient to classify a PREPARED transaction as not committed because durable commit intent was never recorded. After APPLYING is durable, however, a matching before-state is reported as BEFORE_STATE_OBSERVED_ATTRIBUTION_UNCERTAIN: a non-cooperating host writer might have restored those bytes after the commit rename. Likewise, an observed after-state does not prove MIRAGE produced it. If the target diverges from both recorded states, or the workspace path now resolves to a different directory, MIRAGE refuses to infer an outcome.

## Failure semantics

### Crash before `PREPARED` is durable

No commit is allowed to proceed until `Begin` has completed the durable record write. Without a durable prepared record, the commit engine must stop before staging or replacement.

### Crash after `PREPARED` but before `APPLYING`

Recovery observes the real target. A matching recorded before-state is classified as `NOT_COMMITTED`; no mutation is replayed.

### Crash after durable `APPLYING` but before target rename

A matching before-state is classified as `NOT_COMMITTED`. The recovery logic does not attempt the rename again.

### Crash after target rename but before directory sync or `COMMITTED`

The target's durability or completion evidence may be uncertain. If recovery sees the planned after-state, it records `AFTER_STATE_OBSERVED_ATTRIBUTION_UNCERTAIN`; otherwise it records `RECOVERY_REQUIRED`. It never treats the planned after digest alone as a reason to repeat the commit.

### Crash after `COMMITTED` is durably persisted

The durable journal has a terminal commit record. A missing receipt is still possible if the process crashed before receipt construction/persistence. This first increment does not reconstruct receipts from journal records; evidence recovery is separate follow-on work.

### Corrupt, missing, or replaced evidence

Malformed/checksum-invalid records fail closed. A record is not silently repaired or ignored. An unavailable workspace, a replaced workspace path, a non-regular target, a mode mismatch, or a digest mismatch prevents a definitive classification. Recovery never mutates the workspace to make the record fit.

## Integration points

- `internal/runtime/realcommit/journal.go` owns journal format, durable record writes, cross-process locking, and conservative recovery classification.
- `internal/runtime/realcommit/journal_lock_unix.go` uses an exclusive non-blocking file lock on Unix; the native Windows frontend routes this command to the Linux/WSL backend.
- `internal/runtime/realcommit/plan.go` persists intent before atomic replacement, syncs the target parent directory after rename, and persists `COMMITTED` afterward.
- `internal/runtime/lifecycle.go` surfaces uncertain local-commit outcomes as `RECOVERY_REQUIRED`.
- The CLI exposes `mirage recover`, and the product coding-agent and deterministic demo paths use the default per-user journal directory.

## Guarantees and non-guarantees

This increment provides durable metadata checkpoints and conservative state classification for the supported one-existing-file content replacement. It is designed to prevent accidental blind retries and to avoid claiming that a transaction definitely committed when recovery cannot establish that fact.

It does **not** provide:

- general multi-file atomicity, rollback, or recovery;
- reconstruction of a receipt that was never durably written;
- a signed receipt, signed journal, or hash-chained audit log;
- protection against a compromised kernel, host filesystem, rootless Docker daemon, or MIRAGE control plane;
- universal syscall history or perfect attribution of arbitrary concurrent host writes;
- elimination of the existing final revalidation-to-replacement race against a non-cooperating host process;
- automatic cleanup/pruning of old transaction records.

The checksum is a consistency check, not cryptographic provenance. A valid journal record is evidence about MIRAGE's own transaction protocol under the stated trusted-host model, not an external attestation.

## Validation expectations

Unit tests cover successful journaled replacement, abort before replacement when authority is denied, interrupted intent with before-state preserved, observed after-state with uncertain attribution, workspace path replacement, lock contention, checksum corruption, and CLI behavior.

Before this feature is treated as a release guarantee, the full Go CI suite must pass. The opt-in rootless-Docker gate and real Windows/WSL acceptance must also be run on their supported target environments. Those integration tests are not replaced by the journal unit tests.
