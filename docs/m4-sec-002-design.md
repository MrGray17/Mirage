# M4 SEC-002 — Non-Bypassable Runtime Design

> Status: approved design. M4.1 implements lifecycle, hostile-fixture launch,
> isolation checks, and process-tree stop proof. M4.2 implements bounded tree
> snapshots, authoritative normalized reconciliation, contract verification,
> and immutable plan identity. M4.3 implements the first narrow real-workspace
> commit: exactly one authorized content modification of one existing regular
> file.

## M4.1 implementation boundary

The first runtime slice is intentionally non-committable:

- `mirage run hostile-fixture` prepares a disposable M4.1 workspace containing
  only a bounded, race-checked copy of `README.md`; it does not yet snapshot a
  repository tree.
- The launcher accepts only a local Linux rootless Docker daemon reporting
  seccomp, cgroup v2 with the systemd driver, and delegated `cpu`, `memory`, and
  `pids` controllers; it also requires a preloaded digest-pinned image and an
  explicitly marked disposable workspace that does not overlap the real
  workspace. Controller delegation is established independently from trusted
  host evidence in the current user's systemd service `cgroup.controllers`
  file, not inferred from requested container limits.
- The hostile process runs as a numeric non-root UID/GID with a read-only root
  filesystem, no network, private PID/IPC/cgroup namespaces, all capabilities
  dropped, a strictly revalidated enabled `no-new-privileges` value, and bounded
  CPU, memory, PIDs, file descriptors, shared memory, temporary storage,
  runtime duration, and Docker log output.
- The launcher explicitly requests Docker's `seccomp=builtin` profile and
  rejects the effective container configuration unless that exact non-
  unconfined profile is present alongside `no-new-privileges`.
- Image-defined healthchecks are disabled and the inspected healthcheck must be
  exactly `NONE`, so no image-defined healthcheck executes alongside the
  trusted fixture command during M4.1.
- The system temporary root and real workspace are resolved physically and
  checked for overlap before any disposable file or directory is created.
- Docker's effective container configuration is inspected before start. A
  mismatch aborts startup and removes the untrusted container if removal can be
  proven.
- The runtime enters `FROZEN` only after `SIGKILL`, Docker wait, and an inspected
  state showing no running, paused, or restarting process and PID zero.
- Because no trusted tree scanner or normalized diff exists yet, every M4.1 run
  is rejected after freeze. The real workspace is never mounted or committed.

The current live attack/reconciliation test is opt-in and requires a Linux
rootless Docker host plus a preloaded image containing `/bin/sh` and `wget`:

```text
MIRAGE_M42_INTEGRATION=1
MIRAGE_HOSTILE_IMAGE=<repository@sha256:digest>
go test -race -count=1 ./internal/runtime/docker
```

Point-in-time M4.1 evidence: on 2026-08-27 the live test passed on WSL2 Linux
with rootless Docker Engine 29.5.3, Go 1.24.4, and the preloaded Linux/amd64
image `docker.io/library/busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0`.
This records one known fixture-image contract; it does not turn the opt-in test
into a continuously exercised CI guarantee.

Passing unit tests proves lifecycle and Docker-policy construction. It does not
substitute for the opt-in live containment test.

The live fixture reports probe readiness separately from probe outcome. The
integration test rejects an image without `wget` instead of treating a missing
network probe as evidence of containment. The inspected `NetworkMode=none`
remains the authoritative network-isolation control; the attempted request is
supplemental attack evidence.

The writable bind-mounted workspace does not yet have a hard storage quota.
That is acceptable only for the fixed, trusted M4.1 fixture, which performs
bounded overwrites. A hard writable-workspace budget is required before Mirage
runs arbitrary agent code.

## M4.2 implementation boundary

M4.2 replaces the single-file disposable input with a bounded repository-tree
snapshot and makes the frozen tree authoritative for mutation truth:

- source preparation excludes `.git`, `.env` variants, the Mirage marker, and
  common SSH/cloud/package-manager credential locations; it accepts only
  independent regular files and directories and rejects source symlinks, hard
  links, special objects, setuid/setgid/sticky mode bits, and any unresolved
  `.mirage-commit-*` staging artifact from an earlier run;
- the scanner uses Go 1.24 rooted traversal, `Lstat`, opened-handle identity
  checks, and before/after stability checks. It never opens symlinks as content;
- snapshots are capped at 4,096 entries, depth 32, 4 MiB per file, and 32 MiB
  total regular-file content, with a 4,096-byte canonical resource limit;
- the exact physical disposable tree, after writable permission normalization
  and marker creation, becomes the baseline. Source executable files become
  mode `0777`, other source files `0666`, and directories `0777` so the fixed
  numeric non-root sandbox user can edit them;
- final reconciliation scans without exclusions and classifies `CREATE`,
  `MODIFY`, `DELETE`, `MODE_CHANGE`, `SYMLINK`, and `UNSUPPORTED`; rename is
  deliberately `DELETE` plus `CREATE`;
- on the supported Linux runtime, inode link counts reject even a hard-link
  alias whose other name is outside the scanned tree; within-tree aliases are
  also detected by opened-object identity. Final symlinks, hard links, special
  objects, workspace-root mode changes, and Mirage-marker changes are
  intrinsically rejected. Every other mutation must have exact contract
  `WRITE` authority;
- a canonical SHA-256 plan binds baseline identity, final identity, mutation
  metadata, content digests, and modes. A second authority hash binds that plan
  to the immutable contract hash;
- scanner/diff uncertainty moves the lifecycle to `FAILED`; an established
  contract or object-policy denial moves it to `REJECTED`; only a complete
  authorized plan reaches `VERIFIED`;
- M3 and M4 share one trusted-time implementation. Each hostile lifecycle owns
  one clock authority and observes it at creation and immediately before
  prepare, start, freeze, and reconciliation. Callers cannot supply a separate
  reconciliation timestamp. Any zero reading or observation earlier than the
  greatest prior observation fails the lifecycle closed as `FAILED`; on a
  freeze-time clock failure Mirage still invokes process-tree termination, but
  cannot enter `FROZEN` or become committable.

At the M4.2 boundary, Mirage still could not mutate the real repository:
`COMMITTED` was intentionally unreachable, and even an allowed hostile-fixture
plan was explicitly rejected after verification. M4.3 adds only the separately
reviewed single-file commit boundary below; multi-file commit remains deferred.

Point-in-time M4.2 evidence: on 2026-08-27 this test passed on WSL2 Linux with
rootless Docker Engine 29.5.3, Go 1.24.4, and
`docker.io/library/busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0`.
The live hostile process directly modified the allowed `README.md`, created a
forbidden file and symlink, spawned a child, and wrote until killed. Mirage
proved the process tree stopped, independently derived the final mutations,
reported the forbidden path and symlink as violations, rejected the run, left
the real workspace unchanged, and leaked no container or disposable workspace.
This remains developer-observed point-in-time evidence rather than continuous
CI coverage.

The exact scanner guarantee assumes M4.1's proven-stopped sandbox and a trusted
host. It narrows obvious check/use gaps but does not claim containment against a
concurrent privileged host process, bind-mount aliases, hostile mount changes,
filesystem-specific metadata behavior, SHA-256 compromise, or all Unicode
normalization aliases. Paths use exact UTF-8 bytes plus conservative
case-fold-collision rejection. Source exclusion is defense in depth, not secret
discovery: the trusted caller must not select a repository containing credentials
under novel names. Reconciliation observes frozen final state, not transient
syscalls that leave no final mutation.

## M4.3 single-file real commit boundary

M4.3 resolves the approved gates with the smallest real mutation slice:

- one immutable run manifest binds the contract, shared monotonic trusted
  clock, distinct real and disposable baseline identities, physical workspace
  identity and token, and normalized sandbox configuration before execution;
- contract v1 exact-path `WRITE` means only content `MODIFY` for this slice.
  Exactly one existing independent regular file must change. `CREATE`,
  `DELETE`, `MODE_CHANGE`, zero-change, multi-change, links, special objects,
  marker changes, and workspace-root mode changes are rejected;
- source permissions remain in a distinct real baseline. The real file's
  permission mode is used for replacement; normalized disposable `0666` or
  `0777` modes never flow back into reality;
- before precommit and again before apply, the complete supported real tree is
  compared with the real baseline, the shadow is compared with the verified
  final identity, and its plan hash is recomputed. The decision authority hash
  binds manifest + contract + shadow plan;
- the one target is acquired and checked again by digest, regular-file type,
  and real permission mode before staging and immediately before replacement.
  After all target and staging work, the lifecycle observes trusted time again
  and rechecks contract expiry plus manifest/decision/plan authority at the
  last possible point before rename. Callback failure removes staging and does
  not replace the target. Replacement uses a same-directory rename of the
  exact plan-bound bytes;
- observed real divergence becomes `CONFLICTED`; expiry or changed shadow/
  authority becomes `REJECTED`; acquisition uncertainty becomes `FAILED`.
  None of those paths replaces the real target. Within the supported M4.3
  state model, committed content is exactly the authorized bytes and the
  baseline Unix permission mode is preserved.

The exact supported metadata guarantee is content plus Unix permission mode
for one regular file. M4.3 does not preserve ownership, ACLs, xattrs, inode,
timestamps, sparse-file structure, or other metadata. It has no multi-file
atomicity, durable commit log, directory `fsync`, or crash recovery. Cleanup
failure can leave a Mirage-named staging artifact while leaving the target
unchanged, and is terminal `FAILED`; a later run refuses to prepare that real
workspace until the artifact is explicitly recovered or removed. Source and
commit-target setuid, setgid, and sticky bits are unsupported and rejected
rather than silently cleared.

Point-in-time M4.3 evidence: on 2026-08-27 the same pinned BusyBox image and
rootless Docker host passed both live stories. The hostile multi-mutation
fixture was contained and rejected with reality unchanged. A separate fixed
fixture modified only `README.md`, was frozen and reconciled to `VERIFIED`,
passed `PreCommit`, reached `COMMITTED`, changed only the real README contents,
preserved its real `0600` mode, and leaked no container or disposable
workspace. These opt-in results remain local point-in-time evidence until the
equivalent CI environment exists.

M4.3 assumes the host and Mirage process are trusted. Full-tree and target
checks plus same-directory rename narrow but do not eliminate races against a
non-cooperating host process. A host can change another file after the last
full-tree scan or race the target between final observation and rename. A
post-revalidation shadow write cannot change the immutable plan bytes being
applied, but violates the frozen-shadow assumption. This is not filesystem
compare-and-swap or hostile-host containment.

## 1. Security question

M4 introduces the first genuinely hostile process. The problem is not merely how to start an agent in Docker. The problem is:

> How can an untrusted coding-agent process use ordinary filesystem syscalls while Mirage still proves that every security-relevant effect is either physically contained, mediated, or independently observed before any real-world commit?

A writable container mounted directly on the real repository is forbidden. A writable shadow mounted into a container **without authoritative post-run reconciliation** is also insufficient because direct `open/write/rename/unlink` calls bypass the M3 Gateway event path.

## 2. Decision for the competition runtime

Use **isolated disposable workspace + authoritative post-run reconciliation**.

```text
trusted real repository
        |
        | bounded snapshot/copy
        v
transaction-owned disposable workspace
        |
        | mounted only into rootless sandbox
        v
untrusted coding agent
        |
        | arbitrary local filesystem syscalls
        v
shadow changes
        |
        | STOP/FREEZE sandbox first
        v
trusted Mirage tree scanner + normalized diff
        |
        | deterministic contract verification
        v
verified commit plan
        |
        | M2/M3 freshness + commit checks
        v
real repository
```

The Gateway remains authoritative for **brokered privileged capabilities** such as external APIs, network access, secrets, GitHub credentials, and future real-system reads/writes. It is not the sole source of truth for ordinary shadow-local file mutation once an actual process exists.

## 3. Why this satisfies SEC-002

### Shadow-local filesystem writes

The agent may bypass the M3 write API inside its disposable workspace. That is acceptable only because the event log is no longer trusted as the authoritative source of mutation truth. Mirage independently scans the frozen workspace and derives the normalized final diff.

A direct write, rename, delete, chmod, symlink creation, or new file must therefore either:

1. appear in the normalized diff, or
2. cause runtime-integrity verification to fail closed because Mirage cannot classify it safely.

Commit authority is derived from the verified diff, not from the agent's claimed tool history.

### Protected reads

Secrets, the real repository, host home directories, Docker socket, production credentials, and other protected host resources are **not mounted into the sandbox**. A hostile process cannot gain a secret merely by bypassing the Gateway because the secret is absent from its mount namespace and environment.

Reads of ordinary copied repository content are shadow-local and do not create real-world side effects. They do not need per-syscall mediation for the competition security invariant.

### External effects

Direct sandbox egress is default-deny. External reads/writes are exposed only through Mirage-owned broker/adapters outside the container. Credentials remain outside the sandbox. Irreversible writes remain deferred until commit.

## 4. Freeze-before-verify invariant

No final-state verification is valid while the hostile process can still mutate the workspace.

Required ordering:

```text
RUNNING
  -> stop/freeze agent process
  -> prove process tree is dead/frozen
  -> mark runtime FROZEN
  -> scan workspace
  -> derive normalized diff
  -> verify contract/policy
  -> hash/freeze commit plan
  -> commit or reject
```

If the runtime cannot prove the agent process tree is stopped, verification fails closed.

The current single-file `verifiedShadowIdentity` check remains a defense-in-depth guard against post-verification mutation. M4 generalizes it to a canonical tree/diff identity.

## 5. Sandbox requirements

Competition M4 uses rootless Docker only if all of these are enforced:

- unprivileged non-root container user;
- no Docker/Podman socket;
- no host home directory;
- no real repository writable mount;
- no host secrets or production credentials in environment/filesystem;
- read-only container root filesystem where practical;
- one transaction-owned writable workspace only;
- `no-new-privileges`;
- drop all Linux capabilities unless a measured requirement proves otherwise;
- default seccomp profile or stricter reviewed profile;
- no privileged mode;
- no host PID/IPC/network namespace;
- no device mounts;
- bounded memory, CPU, PIDs, output, and runtime duration;
- default-deny outbound network;
- deterministic cleanup of the disposable workspace after terminal state.

Failure to apply a required isolation control aborts runtime startup.

## 6. Workspace snapshot rules

M4 must stop copying one hard-coded file and introduce a bounded tree snapshot with explicit rules:

- copy only repository/workspace content that policy allows to enter the sandbox;
- never copy `.env`, SSH material, cloud credentials, host configuration, or unrelated host files;
- use `Lstat`/rooted traversal semantics; do not follow unreviewed symlinks;
- enforce total file count, per-file size, total byte, depth, and path-length budgets;
- reject unsupported special files;
- define hard-link handling explicitly;
- record the baseline identity used by later diff and freshness checks.

A malformed or unclassifiable tree fails closed.

## 7. Authoritative normalized diff

After freeze, Mirage derives a canonical diff from baseline -> final shadow.

At minimum classify:

```text
CREATE file
MODIFY file
DELETE file
RENAME (optional v0; may normalize as delete+create)
MODE change
SYMLINK create/change (deny by default in v0)
UNSUPPORTED object
```

Every mutation in the final commit plan must map to explicit Effect Contract authority.

Core M4 invariant:

```text
FinalShadowMutations == ReconciledMutations
CommittedMutations   subset-of VerifiedAuthorizedMutations
```

If the event stream and reconciled diff disagree, the diff wins for mutation truth and the discrepancy is itself runtime-integrity evidence. Mirage never grants authority merely because an agent/tool event said `ALLOW`.

## 8. What this design does not claim

Post-run reconciliation observes **final state**, not every transient shadow-local syscall. An agent could create a file and delete it before freeze without that transient write appearing in the final diff.

For v0 this is acceptable only because:

- shadow-local storage is disposable;
- protected host/real resources are absent;
- direct network is denied;
- irreversible capabilities are brokered externally.

If future product requirements demand forensic visibility into every transient local read/write attempt, evaluate FUSE, fanotify/eBPF, ptrace/seccomp-user-notification, or a dedicated virtual filesystem. Those mechanisms are not required to prove the competition transaction invariant and should not be adopted merely for architectural aesthetics.

## 9. Alternatives considered

### Force all file I/O through an RPC/tool gateway

Strong mediation, but breaks ordinary coding tools, shells, compilers, package managers, and agents that expect a normal filesystem. Rejected for M4 compatibility.

### FUSE-backed mediated workspace

Can provide path-level mediation/telemetry and strong non-bypass semantics when correctly deployed. Rejected for competition M4 because rootless/platform operational complexity is high and it expands the trusted filesystem implementation substantially.

### Syscall interception (`ptrace`, seccomp user notification, fanotify/eBPF)

Useful for later forensic or enforcement depth, but Linux-specific, subtle, and easy to overclaim. Rejected as the primary M4 mechanism.

### Writable disposable workspace + trust Gateway events only

Rejected. Direct syscalls bypass the Gateway and would make the event stream incomplete.

## 10. Required M4 security tests before acceptance

1. Agent writes a permitted file directly with shell redirection; reconciliation observes it.
2. Agent writes a forbidden path directly; diff verification rejects the run.
3. Agent changes a file after the last mediated event; reconciliation still sees the change.
4. Agent deletes/renames a protected path; run rejects.
5. Agent creates a symlink/special file; v0 rejects unless explicitly supported.
6. Agent attempts to read a host secret path; the resource is absent/inaccessible.
7. Agent attempts to access the real repository path; it is not mounted/reachable.
8. Agent attempts outbound TCP/HTTP; direct egress fails.
9. Agent attempts to access Docker socket; socket is absent.
10. Agent forks children and exits; Mirage must stop the entire process tree before verification.
11. Agent consumes excessive memory/CPU/PIDs/output/time; sandbox limit terminates the run and commit is impossible.
12. Shadow changes after verification snapshot; the future commit identity check rejects.
13. Safe direct filesystem changes produce a verified commit plan; the future commit slice applies it correctly.
14. Rejected runtime leaves the real repository byte-for-byte/state-equivalent under the supported metadata model.

## 11. Implementation sequence

Do not start with an AI SDK.

1. `Runtime` interface + explicit lifecycle/state machine.
2. Rootless Docker runtime that executes a tiny hostile fixture program.
3. Enforce mount/network/credential/resource isolation and prove with tests.
4. Freeze/stop process-tree proof.
5. Bounded workspace snapshot + normalized tree diff.
6. Contract verification over reconciled mutations.
7. Commit-plan identity + existing freshness/verified-shadow checks.
8. Only then plug in a real coding agent.

The success condition is not "Codex runs in Docker." It is:

> A hostile ordinary process can use a normal disposable workspace, yet no direct syscall can cause an unauthorized real-world mutation or bypass the evidence that commit authorization actually depends on.
