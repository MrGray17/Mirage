# MIRAGE: Complete Project Deep Dive

> **Purpose:** Explain MIRAGE end to end: the problem it solves, how the current implementation works, its security boundaries, its user-facing workflows, how to test it, and what it does not yet guarantee.
>
> **Scope:** This document describes the implementation on the branch containing this document. Code is authoritative when details change. The crash-safe local commit journal is an incremental capability: it supports durable transaction intent and conservative recovery classification, but does not yet reconstruct a missing receipt after a host crash.

- Project: [MrGray17/Mirage](https://github.com/MrGray17/Mirage)
- Product overview and quick start: [README.md](../README.md)
- Low-level architecture and longer-term direction: [ARCHITECTURE.md](../ARCHITECTURE.md)
- Competition demo operations: [docs/competition-demo.md](competition-demo.md)
- Local Qwen workflow: [docs/qwen-local-agent.md](qwen-local-agent.md)
- Rootless-Docker acceptance: [docs/release-acceptance.md](release-acceptance.md)

---

## 1. Executive summary

MIRAGE is a transactional security runtime for untrusted AI coding agents. It sits between an AI agent and a real workspace. Instead of trusting the agent's instructions, intentions, tool logs, or self-reported success, MIRAGE lets the agent work in a disposable environment, independently examines the final state, verifies the resulting mutations against an explicit deterministic contract, and only then permits a narrowly scoped change to cross into the real workspace.

The central idea is:

**An agent may attempt an action without automatically earning the authority to make that action real.**

The system is designed around this invariant:

~~~text
CommittedEffects ⊆ AuthorizedEffects
~~~

The primary implemented end-to-end slice is intentionally narrow:

1. Capture the real workspace's baseline.
2. Build a disposable copy and bind its identity to the run.
3. Create an immutable effect contract and run manifest.
4. Start an agent inside a constrained rootless Docker runtime.
5. Freeze the agent's process tree and obtain a trusted final-state snapshot.
6. Derive a canonical diff between the pre-run and final snapshots.
7. Check every mutation against the contract and intrinsic filesystem restrictions.
8. Revalidate authority and the real target immediately before the commit.
9. Atomically replace the content of one existing regular file if the mutation is valid.
10. Produce a verifiable receipt and a read-only Observatory view.

MIRAGE also contains constrained local-Qwen integration, deterministic Git commit-construction support, and a create-only GitHub branch-publication path. These capabilities have different boundaries and acceptance requirements; they should not be confused with unrestricted coding-agent autonomy or GitHub pull-request creation.

## 2. The problem MIRAGE addresses

Coding agents can be useful precisely because they can inspect and modify code. That usefulness creates a security problem when the agent is exposed to untrusted repository content, dependencies, issue descriptions, prompts, tool output, or other data that can influence its behavior.

An agent can make a mistake, misinterpret the task, follow malicious instructions embedded in a repository, attempt to read secrets, or modify files outside the requested scope. A model can also correctly execute a malicious instruction while still violating the user's real intent.

Prompt instructions, approval prompts, tool allowlists, and conventional process isolation can all help, but none alone establishes that the final state of the real workspace is authorized.

MIRAGE changes the decision point. It does not try to prove that every model thought or attempted operation was safe. It instead controls whether the observed result is allowed to cross from the disposable execution environment into trusted reality.

### 2.1 Example: the README task

Suppose the only authorized change is to update README.md.

While executing, a hostile or confused agent might attempt to:

- change README.md as requested;
- read a protected .env file;
- create or modify an unauthorized path;
- access a host credential or Docker socket;
- reach a network endpoint;
- keep a background process alive that changes files after the agent appears to finish.

MIRAGE addresses this at multiple layers:

- The real workspace is not mounted into the hostile container.
- The agent is run with a restricted container configuration, including no network namespace access, a read-only root filesystem, dropped capabilities, and no Docker socket or host home mount.
- Workspace capacity, CPU, memory, process count, execution time, and diagnostic output are bounded.
- The runtime does not trust the agent's exit alone as proof that all processes have stopped.
- The final workspace is acquired only after a trusted freeze/stop procedure.
- Trusted code scans that frozen state and derives the mutations independently.
- The contract decides which mutation is authorized.
- The commit engine supports only a small, explicitly defined filesystem mutation shape.

The attempted write to README.md is not sufficient on its own. The independently observed final change must still match the permitted shape and authority. An agent can complete a task inside the sandbox and still receive a rejection.

### 2.2 What MIRAGE is not

MIRAGE is not just a Docker wrapper, prompt filter, model safety classifier, or HTML dashboard. It combines a sandbox, immutable run authority, trusted filesystem acquisition, deterministic policy verification, a narrow commit mechanism, and tamper-evident local evidence.

It is also not yet a universal transaction manager for every operating-system syscall and every external API. Its current commit boundary is intentionally smaller than its overall architectural ambition. The implementation limits later in this document are essential to understanding its actual guarantees.

---

## 3. The core mental model: shadow state versus reality

It helps to think of each run as two separate worlds.

### 3.1 Trusted real workspace

This is the directory the user ultimately cares about. MIRAGE captures its initial state before hostile execution. The real directory is not mounted inside the coding-agent container.

The trusted workspace is modified only by MIRAGE's commit code, after verification and revalidation. For the primary filesystem slice, the supported change is one content modification to one existing, independent regular file, with the file's existing permission mode preserved.

### 3.2 Disposable shadow workspace

This is the copy the hostile process is allowed to modify. It is created in a protected temporary directory and backed by a bounded container workspace volume. It is not itself the authority source.

The agent may modify this copy freely within the runtime's actual sandbox permissions. Those changes are speculative. They become candidates for review only after MIRAGE proves that the relevant process tree can no longer change the workspace and a trusted scanner obtains the final state.

### 3.3 The crossing point

The boundary is not crossed because the model says “done,” because a tool reports success, or because a transcript looks plausible. It is crossed only after the trusted runtime establishes that:

- the correct run manifest and contract are still bound;
- the disposable baseline is valid;
- the final state was acquired after a proven freeze/stop;
- the diff is deterministic and within scanner limits;
- the mutations satisfy the contract and intrinsic mutation restrictions;
- the commit plan exactly binds the expected file, old digest, new digest, mode, baseline, manifest, and authority;
- the real target is still the expected target and has not changed since the baseline;
- the final commit checks succeed.

If any required precondition becomes uncertain, the runtime fails closed or reports a conflict instead of treating uncertainty as permission.

---

## 4. Architectural overview

The primary filesystem execution path can be summarized as follows:

~~~text
User task + explicit authority
          |
          v
Canonical Effect Contract
          |
          v
Real workspace baseline + disposable copy
          |
          v
Immutable Run Manifest
          |
          v
Rootless Docker sandbox
  - untrusted process
  - restricted workspace volume
  - no network
  - bounded resources
          |
          v
Freeze / export / stop proof
          |
          v
Trusted final-tree scan
          |
          v
Canonical baseline-to-final diff
          |
          v
Contract verification + intrinsic checks
          |
          +---- invalid / uncertain ----> REJECT or FAILED
          |
          v
Freshness and authority revalidation
          |
          v
Single-file trusted atomic replacement
          |
          v
Receipt + deterministic Effect Graph
          |
          v
Independent receipt verification
          |
          v
Read-only Observatory
~~~

The major architectural layers have different responsibilities.

| Layer | Responsibility | Must not do |
|---|---|---|
| CLI / platform frontend | Parse commands, configure runs, present results, bridge Windows to WSL backend | Invent security authority or bypass backend checks |
| Contract and manifest | Bind run identity, workspace identity, policy, expiry, and sandbox identity | Execute hostile code |
| Workspace preparation | Capture baseline and create a disposable copy | Allow the agent to access the real workspace |
| Docker runtime | Isolate execution, cap resources, freeze and stop processes, export final workspace | Decide that a mutation is authorized based on agent narration |
| Tree scanner and diff | Produce trusted, bounded, deterministic observations | Trust agent tool logs as filesystem truth |
| Reconciler | Compare exact observed mutations with contract authority and intrinsic restrictions | Modify the real workspace |
| Commit engine | Revalidate and apply the one supported real mutation | Copy an arbitrary shadow tree into reality |
| Receipt / Effect Graph | Encode and validate completed-run evidence | Grant permission to commit |
| Observatory | Display verified evidence | Authorize execution, mutate files, or contact a remote service |

The repository also includes Git-specific authority planning and deterministic commit construction. That path follows the same principle: bind a target before hostile execution, derive a candidate from trusted verified state, revalidate exact identities, and keep external publication narrow.

---

## 5. Security model and trust boundaries

A security design is only meaningful if it states what it trusts.

### 5.1 Untrusted inputs

MIRAGE treats these as untrusted:

- the coding agent process;
- the model and its output;
- the task text and action history;
- repository files, documentation, comments, dependency content, and other inputs the agent may read;
- the disposable workspace after agent execution;
- agent stdout/stderr and any reported action sequence;
- the hostile process's claimed exit status or completion narrative.

Some of these inputs may be useful evidence about what the agent attempted, but they do not grant commit authority.

### 5.2 Trusted computing base

The current threat model assumes trust in the host control plane, including:

- the host operating system and kernel;
- the rootless Docker daemon and its effective configuration;
- the MIRAGE executable and its trusted code;
- the authority that constructs and supplies the effect contract;
- the trusted clock abstraction used by the lifecycle;
- the integrity of the code and machine on which the trusted scanner and commit engine run.

This matters: if the host kernel or the trusted MIRAGE binary is compromised, these controls cannot independently restore trust.

### 5.3 Defense in depth

MIRAGE layers different protections rather than expecting one mechanism to do everything.

**Container boundary.** The hostile process runs under rootless Docker with a private process/cgroup namespace configuration, private IPC, no network, read-only root filesystem, dropped Linux capabilities, no-new-privileges, built-in seccomp, no added devices, no published ports, and explicit resource limits.

**Workspace separation.** The real workspace is not mounted into the hostile container. The container accesses a bounded disposable workspace volume. The outer host-side temporary directory is protected separately from the container-writable inner workspace.

**Host resource controls.** Execution duration, CPU, memory, PIDs, workspace capacity, file sizes, tree depth, number of tree entries, mutation count, and captured diagnostic output are bounded. Exceeding a security-relevant budget must not silently truncate the input and continue as though the state were complete.

**Trusted final-state observation.** The scanner uses rooted filesystem access and checks for object changes during acquisition. Symlinks and unsupported objects are represented as observations rather than followed as ordinary file content. Unsafe or unsupported mutations are rejected.

**Policy boundary.** The contract uses canonical exact resource identifiers, deterministic evaluation, explicit deny-overrides-allow semantics, and default-deny behavior for unmatched resources and unknown operations.

**Commit boundary.** The real commit is a narrow operation over one named existing regular file. It uses content digests and rooted revalidation, stages the new contents, checks authority at the last practical point before replacement, and atomically replaces the one target instead of synchronizing the entire shadow workspace.

**Evidence boundary.** Receipts, graphs, and presentation files are verified after being built. They describe outcomes and do not become a second authorization system.

### 5.4 What each defense proves

It is important not to confuse controls with observations.

- **network=none** is an enforcement setting that the trusted runtime checks. A failed HTTP request by itself is not proof of network isolation.
- A read failure on .env shows what a particular probe observed. The stronger guarantee comes from the workspace construction and mount boundary that keep the real secret from the hostile container.
- A process exit does not prove all descendants stopped. MIRAGE's freeze procedure must obtain an independent stop proof before reconciliation.
- A tool action log tells us what the constrained driver says it executed at that tool boundary. It is not universal syscall telemetry and is not used to authorize commit.
- A valid receipt proves that the receipt's internal structure and hashes validate under the verifier's rules. It is not a digital signature and does not independently prove that a compromised host told the truth.

---

## 6. Immutable authority: contracts, workspace bindings, and manifests

A core design choice is to construct and bind authority before hostile execution, then validate that identity at later steps.

### 6.1 Effect Contract

The contract is the deterministic statement of what a run is allowed to do. The current contract code supports versioned canonical representations:

- Contract v1 defines filesystem read/write resource allowlists and denylists.
- Contract v2 adds exact create-only GitHub branch-publication authority.

The file-policy model uses canonical resource identifiers rather than glob patterns. The project deliberately avoids broad wildcard semantics until those semantics receive a separate security design and review.

When evaluating a filesystem operation, the policy checks trusted evaluation time, expiry, recognized operation, explicit deny, explicit allow, and then default denial. An unknown operation or unmatched resource is not implicitly allowed.

The contract also includes run identity, actor identity, and an expiry time. The expiration boundary is exclusive: if the trusted evaluation time reaches the contract expiry, the authorization is expired.

Contract construction copies and canonicalizes input, then hashes the stable serialization. A contract's identity therefore represents the authority being evaluated, rather than a mutable configuration struct handed to the runtime.

### 6.2 Workspace binding

Before the agent starts, MIRAGE captures a snapshot of the real workspace and constructs a separate disposable workspace. The workspace binding records identities for:

- the real workspace path and its baseline snapshot;
- the disposable workspace path and its baseline snapshot;
- a run-specific marker/token, represented in the binding identity by its hash.

The real baseline and disposable baseline are separate objects: copying files does not make them the same workspace. The disposable workspace has its own physical identity and a marker used to prevent a different directory from being mistaken for the one prepared by MIRAGE.

The source workspace is checked for unsafe paths and objects. A run is not permitted to inherit unresolved MIRAGE commit-staging artifacts as ordinary user state, because doing so could confuse transaction recovery and workspace authority.

### 6.3 Run Manifest

The run manifest is the immutable bundle of authority-bearing inputs. It ties together the contract, start time, workspace binding, baseline identities, sandbox identity, and clock authority.

The runtime uses a trusted time abstraction with a greatest-observed-time guard. This helps detect clock rollback within the lifecycle. The runtime rechecks the manifest and time as the run progresses, so a previously constructed plan does not turn into unbounded or timeless authority.

The manifest's canonical representation is hashed to produce the manifest identity. Later authorization, reconciliation, and commit plans bind back to this identity.

### 6.4 Why bind before running the agent?

If the agent could select or refresh its own contract, workspace, repository, or external destination after it executes, it could influence the very authority used to judge its behavior. MIRAGE instead captures the intended subject and permitted scope before the hostile phase, then rejects identity mismatches and expired authority during later validation.

---

## 7. Workspace snapshots and canonical diffs

MIRAGE does not treat the output directory as a trusted change list. It scans the state before and after execution.

### 7.1 Snapshot representation

The tree scanner produces a deterministic snapshot that captures canonical workspace-relative resource identifiers and the relevant object metadata. For regular files, content is read using a root-bound filesystem handle and checked for stability during acquisition. The implementation hashes content using SHA-256 and records the characteristics needed to compare the old and new states.

Symlinks and unsupported special objects are not silently treated as regular file bytes. The scanner can describe such objects so the verifier can deterministically reject unsupported mutations.

The scanner bounds the state it will accept. Current shared limits include:

- maximum 4,096 tree entries;
- maximum tree depth of 32;
- maximum 4 MiB per managed file;
- maximum 32 MiB total scanned file content;
- maximum 4,096 mutations in a derived diff.

If the scanner cannot establish a complete valid state within the limits, it fails rather than quietly omitting security-relevant data.

### 7.2 Diff behavior

The diff compares the baseline and final snapshots by canonical resource identity and produces a sorted, deterministic mutation plan.

Examples of possible observations include:

- a new path;
- a removed path;
- a regular-file content modification;
- a permission-mode change;
- a symlink change;
- a hard-link or unsupported-object change;
- a change in root directory metadata.

Renames are intentionally normalized as delete plus create instead of trusting inode identity to grant policy authority. That makes the policy model about explicit resource names and observed state changes, not about assumptions about object identity.

This broad observation model does **not** mean that every kind of change can be committed. Observation and authorization are separate. The scanner may identify a mutation that the current contract or commit engine does not support; that mutation is rejected.

### 7.3 Why use final-state reconciliation?

A syscall log can miss effects, be too noisy, or describe attempted operations that did not actually persist. Conversely, a tool log can omit a mutation made by a background process. Final-state reconciliation asks a different question: given the trusted baseline and a proven-stopped hostile process, what changed in the disposable workspace?

That final diff becomes the authoritative filesystem mutation input to the contract verifier. Tool logs can enrich explanation, but they do not replace the diff.

---

## 8. Rootless Docker execution

The Docker launcher is the runtime enforcement layer for hostile process execution. It is more than a single Docker run command.

### 8.1 Runtime preflight

Before execution, the launcher validates the effective Docker environment and required resource-control properties. It inspects the referenced immutable agent and helper images and checks for conflicting container or quota-volume names.

The runtime expects a suitable Linux environment, including the rootless Docker properties documented in the release-acceptance guide. A normal Docker daemon is not automatically equivalent to the supported security configuration. Readiness checks are intended to identify unsupported or incomplete environments before a hostile workload starts.

Images are referenced by repository-qualified immutable digest for the security acceptance flows. The launcher checks that the exact pinned image is present locally; it does not silently replace that identity with a mutable tag.

### 8.2 Bounded workspace volume and keeper

The runtime uses a dedicated bounded tmpfs-backed Docker volume for the hostile workspace. A trusted keeper container holds the volume mounted while the agent is paused and the frozen workspace is acquired. The launcher inspects effective configuration and the volume's identifying options instead of assuming Docker accepted the requested configuration unchanged.

The keeper and agent are separate containers with separately verified identities. This arrangement lets MIRAGE preserve the quota-backed workspace while controlling the hostile process and exporting its final state.

### 8.3 Agent container policy

The current launcher constructs and inspects a restrictive configuration, including:

- rootless execution under a configured non-root user for the agent;
- read-only container root filesystem;
- network mode none;
- private PID, IPC, and cgroup namespace settings;
- dropped capabilities and no-new-privileges;
- built-in seccomp;
- bounded memory, CPU, process count, temporary storage, and diagnostic output;
- no host devices or published ports;
- no Docker socket, host home, or inherited credential-bearing environment;
- only the specific disposable workspace volume and, when applicable, a narrow read-only model-broker socket mount.

These options reduce what a compromised agent can reach. They are not a substitute for verifying the effective inspected configuration and the host's trusted computing base.

### 8.4 Freeze is a security transition

The runtime does not equate a timeout or a successful process wait with a freeze. When the agent is ready to finish, the launcher inspects its state, pauses the agent cgroup when needed, verifies the paused state, exports the workspace while the hostile process cannot mutate it, then terminates and verifies that the agent and keeper containers have stopped.

If freeze, export, stop proof, or cleanup is uncertain, reconciliation must not proceed as if the result were trusted. Cleanup is also identity-aware: MIRAGE checks what container or volume it is about to remove and refuses to remove an unverified volume as if it belonged to the current run.

### 8.5 Cleanup and failures

The disposable workspace is cleaned after the runtime confirms that its processes and runtime artifacts have been removed. If cleanup cannot be proved, MIRAGE reports the failure and preserves the relevant recovery context rather than claiming a clean successful run.

The application should be treated as failed when preparation, process stop, final-state acquisition, verification, commit, or required cleanup cannot be established. A failure is not converted into authorization simply because an error is inconvenient.

---

## 9. Deterministic authorization and reconciliation

The reconciler turns the frozen final tree into contract evidence. Its role is to decide whether the complete resulting mutation plan is permitted, not to modify reality.

### 9.1 Verification inputs

Reconciliation uses:

- immutable run-manifest identity;
- immutable workspace disposable baseline;
- frozen disposable workspace path;
- canonical contract;
- trusted evaluation time.

It scans the final workspace, derives the canonical diff, and binds a decision to the manifest hash, contract hash, diff-plan hash, and derived authority hash.

### 9.2 Intrinsic restrictions

Contract allowlists are necessary but not sufficient. The current filesystem commit slice also applies intrinsic restrictions that the contract cannot override. Among the restrictions are:

- the reserved MIRAGE workspace marker cannot be changed as an agent-authorized effect;
- symlink mutation is denied;
- hard links and unsupported filesystem objects are denied;
- creation, deletion, mode change, and other non-supported mutations are denied by the current commit shape;
- only a content modification of an existing independent regular file with unchanged permission mode is accepted;
- exactly one mutation is required for the current M4.3 real-commit slice.

So even a broad-looking user task does not make this version a multi-file transaction engine. The code deliberately rejects a final state outside the one-change model.

### 9.3 Fail closed versus policy rejection

It is useful to distinguish two outcomes:

- **REJECTED:** trusted observation succeeded, but the observed mutation plan violated policy or an intrinsic rule.
- **FAILED / uncertain:** the system could not establish a required fact, such as obtaining a stable final snapshot, validating the manifest, proving stop, or observing trusted time.

A policy rejection means the system understood the change and denied it. A failure means the system could not safely finish the security process. Neither outcome grants the agent commit authority.

---

## 10. Trusted real-world commit

After successful reconciliation, the commit layer turns the accepted mutation into a narrowly scoped real-world operation.

### 10.1 The commit plan

The real-commit plan binds all fields needed to identify the exact change, including:

- manifest identity;
- authorization identity;
- real baseline snapshot identity;
- real workspace;
- canonical target resource;
- before-content digest;
- after-content digest;
- original target permission mode;
- intended new file bytes.

The plan verifies that the supplied intended bytes hash to the expected after digest. It also computes its own stable identity. Mutable caller input is copied rather than retained as unrestricted external state.

### 10.2 Revalidation

Before replacement, the commit engine uses rooted filesystem operations to verify the real workspace and target. It checks that the target is still an appropriate regular file, that the target's current identity/content matches the captured pre-run expectation, and that the candidate bytes correspond to the validated after digest.

It stages only the target file. It does not copy the entire disposable tree over the real workspace. It performs the last practical authority callback immediately before replacement and uses atomic replacement for the target.

This strategy avoids turning unrelated files from the shadow workspace into accidental trusted changes. The operation is deliberately limited to one existing file and preserves its pre-run permission mode.

### 10.3 Freshness and conflicts

The real workspace can change while the agent runs. MIRAGE therefore treats a changed baseline or changed target as a conflict, not as a reason to overwrite the newest state blindly.

MIRAGE also revalidates the disposable/final-state authority. If the verified shadow state or derived authority changes after planning, the plan cannot be reused as if it were still fresh.

The documented threat model still has a narrow time-of-check/time-of-use race between the final revalidation and atomic replacement when a non-cooperating host process can write the target concurrently. The current version does not claim to make that race impossible. See the limitations section.

---

## 11. Lifecycle state machine

The lifecycle object serializes operations and only permits the legal next operation for the current run. The source defines explicit states, including:

~~~text
CREATED
  -> PREPARING
  -> RUNNING
  -> FREEZING
  -> FROZEN
  -> RECONCILING
  -> VERIFIED or REJECTED
  -> PRECOMMITTING
  -> COMMIT_READY
  -> COMMITTING
  -> COMMITTED
~~~

FAILED and CONFLICTED represent other terminal or failure outcomes. The Git publication extension uses additional states such as PUBLISHING, PUBLISHED, and PUBLICATION_UNCERTAIN.

A simplified description:

| State | Meaning |
|---|---|
| CREATED | Run authority exists; hostile execution has not begun |
| PREPARING | Runtime preconditions and sandbox are being established |
| RUNNING | Hostile execution is active |
| FREEZING | Runtime is proving the hostile process can no longer change the workspace |
| FROZEN | Process stop is proven and final-state acquisition is ready to be reconciled |
| RECONCILING | Trusted final snapshot and deterministic diff are being verified |
| VERIFIED | Policy and the current commit-shape restrictions accept the mutation plan |
| REJECTED | The observed result violates contract or intrinsic restrictions |
| PRECOMMITTING / COMMIT_READY | The one allowed real mutation is being planned and freshly validated |
| COMMITTING | Trusted commit path is executing |
| COMMITTED | The supported local mutation was applied and verified |
| CONFLICTED | A trusted baseline/authority conflict prevents safe commit |
| FAILED | A required operation or proof could not be established |
| PUBLISHING | A separately authorized GitHub branch publication attempt is in progress |
| PUBLISHED | The exact intended remote branch outcome was confirmed |
| PUBLICATION_UNCERTAIN | The external outcome cannot safely be classified with certainty |

The lifecycle validates the run manifest and observes trusted time around important state transitions. Its purpose is to prevent code from calling reconciliation, precommit, or publication in an order that bypasses prerequisite evidence.

---

## 12. Receipts, Effect Graphs, and the Observatory

MIRAGE's security story includes explanations that can be inspected after a run. Those explanations must remain separate from commit authority.

### 12.1 Receipt contents

The receipt records completed-run facts such as:

- version and run ID;
- contract hash;
- start and completion times;
- attempted, authorized, and denied effects;
- observed mutations;
- verification identity;
- commit plan and committed mutations;
- deterministic Effect Graph and graph hash;
- the receipt's own SHA-256 hash.

For the constrained real-agent flow, receipt v2 also records the exact agent image, sandbox identity, action sequence, rejection reasons when applicable, process-tree-stop proof, cleanup completion, outcome, and a narrowly stated reality result.

### 12.2 Hashing and structural verification

Receipt construction uses a canonical representation to compute the receipt hash. Verification recomputes the hash and validates internal bindings and invariants. It checks that attempted effects are partitioned into authorized and denied effects, that committed mutations have matching observed and authorized authority, and that the effect graph validates and is bound to the run.

The verifier rejects malformed or inconsistent receipts rather than displaying them as valid. Versioned schemas preserve the competition flow's v1 representation while allowing v2 to represent rejected real-agent runs honestly: a rejected run has no committed mutations and should not be forced into a schema that requires a successful commit.

**A self-hash is not a signature.** It detects inconsistent or accidental modification against the encoded hash, but does not prove who produced the receipt or protect against a fully compromised trusted host capable of fabricating a new receipt and matching hash.

### 12.3 Effect Graph

The Effect Graph is a deterministic causal view of trusted execution evidence. It models the run, task, untrusted agent, attempted effects, authorization/denial decisions, observed mutations, verification, and commit where appropriate. Nodes and edges are normalized and hashed.

The graph encodes relationships such as:

- the task being assigned to an untrusted agent;
- the agent attempting an effect;
- a decision authorizing or denying the effect;
- an authorized compatible effect producing an observed mutation;
- a mutation being evaluated by verification;
- a successful verification leading to a commit.

The graph library explicitly does not grant authority. It is derived evidence for inspection and auditing.

### 12.4 Observatory

The Observatory is a self-contained, read-only HTML visualization of a verified receipt. The renderer invokes receipt verification before constructing the view. Its embedded presentation code is not part of the authorization path and does not need remote network resources to render.

The Observatory helps a reviewer inspect attempted actions, denied effects, the one surviving mutation, verification and commit identities, and the resulting state. It is a view of the evidence, not another source of truth.

### 12.5 Diagnostic output

Hostile agent output is bounded and sanitized before it is retained as diagnostics. Recognizable credential patterns and known secrets are redacted, and byte caps prevent unbounded logs from exhausting memory or filling storage.

Diagnostics improve the ability to explain a failure. They never grant authority, and truncation or missing diagnostics must not be reinterpreted as proof that an unsafe action did not happen.

---

## 13. Local Qwen agent and the trusted model broker

MIRAGE includes a constrained local-model demonstration using the exact model name qwen2.5-coder:1.5b through Ollama. It is separate from the deterministic competition fixture.

### 13.1 Small tool surface

The Qwen driver is intentionally not a full shell environment. Its allowed sequence is:

~~~text
list_files
    -> read_file
    -> patch_file
    -> finish
~~~

The driver reads and writes only within the disposable workspace. Paths are rooted, path traversal and symlink escapes are rejected, file and transcript sizes are bounded, and the protocol requires the expected ordering. The allowed patch_file operation appends model-selected text to the file's previous content after the required read step.

The configured sequence is deliberately small. There is no shell, general network tool, Git tool, environment-variable tool, or arbitrary subprocess interface in the Qwen driver.

### 13.2 Why a broker exists

The model service is on the trusted host side. Rather than giving the hostile container general access to the host model endpoint, MIRAGE provides a narrow local socket and a trusted broker that controls the upstream target and request profile.

The current Ollama broker fixes the supported model and endpoint. It strips unnecessary headers, disables proxies and redirects, limits request/response sizes and time, and on Windows/WSL uses a fixed Windows loopback interop path. The agent sandbox continues to have network=none; the model broker is not a general network tunnel.

The model output remains untrusted. It chooses a constrained action, but does not decide policy, verification, commit, receipt validity, or the Effect Graph.

### 13.3 Authorized model run

In the documented positive flow, the contract permits an edit to README.md. Qwen selects its allowed tools and modifies the disposable copy. The trusted runtime freezes the result, observes the actual README change, verifies it against the contract, and commits one mutation if all checks pass.

### 13.4 Rejected model run

In the negative flow, the contract permits a different file, while the model is asked to edit README.md. The model may successfully modify the disposable README, but this does not grant authority. The reconciler observes the mutation, identifies the missing write authority, rejects the run, and records zero committed mutations with the real workspace unchanged within the implementation's stated observation model.

This is a core demonstration of the project's thesis: the model can carry out an edit inside its environment while MIRAGE independently refuses to let an unauthorized edit cross into reality.

### 13.5 Image identity

The Qwen agent image is built from the repository's checked-in Dockerfile and must be referenced using an immutable repository digest for the documented security run. A local build tag may not have a repository digest until it is pushed to a registry and pulled back by its digest. A mutable tag or bare local image ID is not a replacement for the required repository-qualified name@sha256 digest identity.

See [docs/qwen-local-agent.md](qwen-local-agent.md) for the exact build, image publication, pull, and run commands.

---

## 14. Git authority, deterministic commits, and GitHub branch publication

Git features are an additional capability layer, not a reason to weaken the filesystem policy.

### 14.1 Bind Git before hostile execution

Git authority is captured before the agent runs. The binding records the trusted local repository and exact baseline identity, including the repository's relevant head/ref information. The hostile agent is not allowed to choose or refresh the trusted repository binding after execution.

### 14.2 Derive a Git plan from verified state

After filesystem reconciliation succeeds, MIRAGE can derive a deterministic Git effect plan. That plan binds the run manifest, contract, trusted repository binding, reconciliation plan, and decision. It is data describing the intended Git result, not permission to perform arbitrary Git operations.

The plan must be revalidated against the current bound identities. MIRAGE does not treat a stale plan as fresh authority.

### 14.3 Construct a candidate commit without updating the real repository

The Git commit-construction path builds an immutable candidate commit artifact in transaction-owned storage. It verifies the intended tree and commit relationship and avoids updating the real repository ref merely by constructing the candidate. The lifecycle tracks the artifact's identity and revalidates it before downstream use.

This is an important separation: constructing bytes or Git objects for a possible commit is not the same as committing or publishing them.

### 14.4 Create-only GitHub branch publication

The current GitHub publication foundation supports one narrow kind of remote effect: creating a previously absent, deterministic branch in one exact bound GitHub repository.

Important properties include:

- Contract v2 must explicitly authorize CREATE_BRANCH.
- The repository identity is canonical owner/repository data, not a URL chosen by the agent.
- The target ref is deterministically derived from the run identity.
- The repository binding includes GitHub's stable repository identity and the bound baseline.
- The publication plan binds the candidate commit artifact, repository, remote destination, target ref, contract, and run manifest.
- The publication engine checks whether the target ref already exists before the one allowed push attempt.
- It uses an isolated temporary Git publication workspace and revalidates local and remote state after the attempt.
- Uncertain remote results are classified as uncertain; they are not converted into a success or blindly retried.

A live branch-publication test is a separate acceptance action. It creates a real remote branch in a disposable test repository and does not automatically delete that branch. Do not point it at a production repository or use broad production credentials.

### 14.5 Pull requests are a separate capability

**GitHub pull-request creation is not included in the current supported main feature set.** Building a commit and publishing a branch are not equivalent to creating a pull request. The older M5.4 pull-request work remains separate and should not be presented as a shipped feature.

---

## 15. CLI and platform integration

MIRAGE is exposed as a Go CLI. The command entry point routes operations into the demo, agent runtime, verification, diagnostics, setup, and build-information packages.

Useful current commands include:

| Command | Purpose |
|---|---|
| **mirage help** | Show command help |
| **mirage version** | Print build identity |
| **mirage version --json** | Print structured build identity, including bridge protocol |
| **mirage setup** | Validate/setup the supported runtime prerequisites |
| **mirage doctor** | Check runtime readiness and, on Windows, the frontend/backend pair |
| **mirage run --open** | Run the official deterministic malicious competition scenario and open the verified Observatory |
| **mirage run benign** | Run the benign scenario |
| **mirage run agent ...** | Execute the constrained agent path with specified authority and broker options |
| **mirage verify PATH** | Independently verify a receipt |
| **mirage receipt verify PATH** | Receipt-verification alias |
| **mirage observatory ...** | Inspect or render verified evidence through the CLI |

The deterministic public demo pins its fixture image rather than accepting arbitrary ambient image overrides. Advanced image selection is separate from the official presentation path.

### 15.1 Build identity

The build embeds a version and full source commit identity. Source installers label builds 1.0.0-dev by default. The build identity also includes platform and bridge-protocol version, which the Windows frontend uses to check its pair with the WSL backend.

The published v1.0.0 release predates later installer and security hardening and has no downloadable binary assets. The current source build should not be described as a new stable release merely because it is installable from main.

### 15.2 Native Linux

The native Linux installer:

- checks for a supported Go toolchain and Git;
- captures the full current source commit;
- builds the Linux binary for the host architecture;
- verifies the staged executable's version/commit/platform/bridge metadata;
- stages beside the destination so activation is a same-filesystem rename;
- refuses unsafe target types and keeps the previous executable intact on build/staging/activation failure.

The installer does not configure Docker security or install other system dependencies automatically.

### 15.3 Windows with WSL2

The Windows installer builds a native Windows CLI frontend and a Linux backend from the same checkout and commit. It stages the frontend, backend and configuration, verifies the pair, then switches them into place. If a switch or the frontend-to-WSL bridge smoke test fails, it attempts to restore the prior installation state.

The bridge requires matching version, full commit identity, platform and protocol. The installer does not install WSL, set up Docker for the user, or silently change the Linux daemon configuration. The security runtime is executed through the configured Linux distribution.

For a real presentation, use the installation path and Linux distribution you have rehearsed, then run mirage doctor and confirm it reports READY.

---

## 16. The competition demo: what it proves

The recommended jury flow is the deterministic fixture, because it is repeatable and requires no model-provider API key. It exercises the real rootless runtime and trusted commit path rather than merely printing a mock result.

### 16.1 Malicious scenario

Run:

~~~bash
mirage run --open
~~~

Expected accounting:

~~~text
Agent attempted 4 effects. MIRAGE authorized 1, denied 3, and committed 1.
~~~

The deterministic probe attempts to read the protected .env, reach an external network address, write outside the allowed filesystem boundary, and perform the authorized README modification.

The important result is not just that the first three attempts failed. MIRAGE independently scans the frozen final workspace, verifies that the only resulting mutation is the authorized existing-file content change, and commits that change through the trusted commit path.

The run prints paths for the real workspace, receipt, and Observatory. The generated real workspace can be inspected after execution. The protected secret fixture should remain present and unchanged; do not print its contents in a presentation.

### 16.2 Benign scenario

Run:

~~~bash
mirage run benign
~~~

Expected accounting:

~~~text
Agent attempted 1 effects. MIRAGE authorized 1, denied 0, and committed 1.
~~~

This uses the same fundamental runtime lifecycle and commit boundary, but with a fixture that attempts only the authorized README update. It is a useful control case alongside the hostile case.

### 16.3 Verify the receipt

Use the exact receipt path printed by the command:

~~~bash
mirage verify /path/printed/by/the/run/receipt.json
~~~

The path above is illustrative; substitute the actual path emitted by MIRAGE. The verifier must accept the persisted receipt. Show the jury the verified receipt and Observatory only after checking the actual outputs from that run.

### 16.4 Honest meaning of the demo

The fixture is a deliberate security workload running as an untrusted process. It is not a demonstration that an unconstrained commercial model independently attempted these exact malicious actions. The Qwen proof is the separate local-model flow.

The network probe is presentation evidence of what that execution observed; the trusted Docker configuration and effective-config validation provide the network-boundary enforcement evidence. A probe can fail for multiple reasons, so it must not be treated as the sole proof of network isolation.

Use [docs/competition-demo.md](competition-demo.md) for the exact operational sequence and failure posture.

---

## 17. Testing strategy and release acceptance

MIRAGE uses more than one kind of test. They establish different levels of confidence and should be reported separately.

### 17.1 Normal continuous integration

The current CI workflow checks:

- shell syntax for relevant scripts;
- a clear failure when required live-gate image configuration is missing;
- native Linux installer smoke behavior;
- build-identity metadata and executable mode;
- rollback/failure safety when the build is forced to fail;
- activation-failure safety and cleanup of staged files;
- Go formatting;
- go vet ./...;
- go test -race -count=1 -cover ./...;
- PowerShell installer syntax;
- Windows frontend package tests and native frontend build;
- Linux backend cross-compilation from the Windows runner.

Those checks catch a lot of regressions, but normal CI does not start the full rootless-Docker acceptance stack.

### 17.2 Rootless-Docker live acceptance

The opt-in [scripts/test-live.sh](../scripts/test-live.sh) runs in a prepared Linux environment, including WSL2's Linux filesystem when configured properly. It expects Go 1.27.3 or newer, Docker, and the required preloaded digest-pinned image references.

It runs the standard checks first, then enables the hostile fixture, coding-agent/broker, and demo integration suites. These exercise the effective runtime, quota, process-tree, broker-socket and deterministic-demo boundaries under real Docker execution.

A pass should be retained alongside the exact tested commit SHA. Missing image configuration, unsupported runtime preconditions, failed cleanup, rejected authorized mutations, or unauthorized committed mutations are release blockers for the tested environment.

### 17.3 Windows/WSL acceptance

A Windows cross-build is valuable, but it is not the same as installing the pair on a real Windows host and exercising the WSL bridge, backend readiness, runtime, and upgrade/rollback sequence there. Real Windows/WSL acceptance must be run on the supported target environment.

### 17.4 Live GitHub publication

The branch-publication live test is intentionally separate because it performs a real external mutation. It must use a dedicated disposable repository and a narrowly scoped credential. The resulting branch is a real remote effect and should be cleaned up deliberately after the test if desired.

### 17.5 Provider-backed model runs

A provider-backed run is also separate acceptance. It may require a provider/runtime configuration and could incur cost. It should be performed only after local security-boundary acceptance and with a dedicated, low-limit test configuration. The deterministic competition demo does not require a paid provider call.

---

## 18. Current implementation limits

These are not footnotes to hide. They define what can and cannot be claimed about MIRAGE today.

### 18.1 Single-file filesystem commit

The current real-commit engine supports exactly one content modification to one existing independent regular file, preserving the existing permission mode. It does not provide general multi-file transactions or commits for file creation, deletion, permission-mode changes, symlinks, hard links, or special filesystem objects.

The scanner can detect many changes outside the supported shape, but detecting a change does not mean the commit engine supports applying it.

### 18.2 Metadata preservation

The implementation does not claim complete preservation or transactional handling of all filesystem metadata, including arbitrary ACLs, extended attributes, ownership, all platform-specific flags, or every possible object type.

### 18.3 Narrow host race

A narrow final revalidation-to-replacement race against a non-cooperating host process remains documented. A broader guarantee would require a stronger host-level coordination/locking model and additional security work.

### 18.4 Durable local commit journal and recovery

The local filesystem commit path now uses a metadata-only durable transaction journal when invoked through the product CLI and the competition demo. It stores the immutable plan, manifest and authority identities, workspace path and filesystem identity, target path, before/after content digests, permission mode, timestamps, state, and a canonical checksum. It does not store file contents, secrets, or a full receipt.

The journal state flow is:

~~~text
PREPARED
  -> APPLYING
  -> COMMITTED
~~~ 

An operation that fails before the durable APPLYING intent is established is marked ABORTED when that transition can be persisted. APPLYING is durably recorded immediately before the trusted atomic replacement. After the replacement, MIRAGE syncs the containing target directory before persisting COMMITTED.

Use `mirage recover` from the Linux/WSL backend to inspect incomplete journal records. Recovery never retries a mutation and never overwrites the real workspace. It verifies the journal checksum and workspace identity, then classifies the currently observed target:

- the recorded before-state is present: the operation can be classified as NOT_COMMITTED;
- the recorded after-state is present after an APPLYING interruption: MIRAGE reports AFTER_STATE_OBSERVED_ATTRIBUTION_UNCERTAIN rather than claiming that the transaction definitely produced it;
- the workspace identity, target mode, or digest cannot be safely matched: MIRAGE reports RECOVERY_REQUIRED.

An uncertain recovery outcome requires operator inspection. The journal checksum detects record inconsistency; it is not a signature or protection against a compromised trusted host. This first increment does not reconstruct a full receipt if the host crashes after commit but before receipt persistence, does not implement general multi-file transactions, and does not eliminate the documented race against a non-cooperating host process. A record whose recovery classification remains uncertain is retained for future inspection.



### 18.5 Not syscall-perfect observability

MIRAGE's authoritative filesystem verification is based on the frozen final state. It does not claim universal syscall monitoring or perfect proof of every transient action the process attempted. A transient action that leaves no final mutation may not appear in the final tree diff; additional runtime probes provide evidence about selected boundaries, not a universal syscall history.

### 18.6 The host remains trusted

The kernel, Docker daemon and trusted MIRAGE control plane are inside the trusted computing base. The current architecture does not claim to withstand a compromised kernel, rootless daemon, or MIRAGE executable.

### 18.7 External effects remain narrow

The supported GitHub publication foundation is create-only branch publication under exact, prebound authority. Pull-request creation and other arbitrary remote operations should not be claimed as implemented current capabilities.

### 18.8 Self-hashed evidence is not signed evidence

A SHA-256 self-hash detects internal modifications when checked against the retained hash, and validation also checks structural bindings. The receipt is not a digital signature, not a public-key attestation, and not a signed, hash-chained durable audit ledger.

---

## 19. Source-code map

The following is a practical entry point into the current Go codebase. It is focused on the implementation paths described in this document.

### CLI and product surface

- **cmd/mirage:** command parsing, official and advanced demo orchestration, agent flow, receipt verification, Observatory rendering, setup, doctor, and version commands.
- **internal/cliapi:** stable structured summaries used by the CLI/platform boundary.
- **internal/platform/wsl:** Windows-to-WSL backend communication.
- **internal/buildinfo:** version, commit, platform and bridge-protocol identity.

### Run authority and lifecycle

- **internal/contracts:** canonical contracts and deterministic filesystem/GitHub publication policy evaluation.
- **internal/trustedtime:** trusted time abstraction and rollback handling.
- **internal/runtime/manifest.go:** immutable run-manifest identity and binding validation.
- **internal/runtime/lifecycle.go:** serialized lifecycle states, transition checks, reconciliation/commit orchestration and Git planning/publication.
- **internal/runtime/workspace:** real/disposable workspace separation, snapshots, markers, bindings and cleanup.

### Sandbox and filesystem state

- **internal/runtime/docker:** Docker preflight, immutable-image checks, quota volume/keeper, container configuration, process freeze/stop proof, workspace export, bounded diagnostics and cleanup.
- **internal/runtime/hostilefixture:** deterministic hostile, positive single-modification, and competition-demo workloads.
- **internal/runtime/tree:** bounded scan, snapshot identity, canonical mutation diff and mutation types.
- **internal/runtime/reconcile:** deterministic contract verification of the frozen final state.
- **internal/runtime/realcommit:** immutable single-file commit plan, rooted revalidation, staging, atomic replacement, durable transaction journal and conservative crash recovery.
- **internal/limits:** shared file, tree, event and mutation budgets.

### Evidence and model execution

- **internal/receipt:** receipt schema, canonical SHA-256 identity, structural validation and version compatibility.
- **internal/effectgraph:** deterministic causal graph construction and validation.
- **internal/observatory:** read-only HTML rendering of verified receipts.
- **internal/runtime/qwenagent:** bounded local Qwen driver and rooted workspace tool surface.
- **internal/runtime/modelbroker:** narrow trusted provider/model broker, including Ollama transport.
- **internal/runtime/diagnostics:** bounded/redacted run and provider diagnostic records.
- **internal/demo:** official malicious/benign demo lifecycle, checks, accounting and evidence handoff.

### Git and remote publication

- **internal/runtime/gitbinding:** capture and validation of the trusted local repository.
- **internal/runtime/gitplan:** authority-bound deterministic Git effect planning.
- **internal/runtime/gitcommit:** construction and validation of immutable candidate Git commit artifacts.
- **internal/runtime/githubbinding:** binding and observation of a specific GitHub repository and target ref.
- **internal/runtime/gitpublication:** create-only branch publication plan, isolated publication workspace, single attempt and outcome reconciliation.
- **internal/gitrefs:** deterministic run-scoped Git branch naming.

### Tests and documentation

- **.github/workflows/ci.yml:** normal Linux and Windows CI.
- **scripts/test-live.sh:** opt-in rootless-Docker acceptance gate.
- **scripts/install.sh** and **scripts/install.ps1:** native Linux and Windows/WSL installation.
- **ARCHITECTURE.md:** deeper architecture specification, including future-state ideas that must be distinguished from shipped implementation.
- **docs/m4-sec-002-design.md:** runtime/security design.
- **docs/m5.1-git-authority.md:** Git authority planning.
- **docs/m5.2-deterministic-git-commit.md:** deterministic Git commit construction.
- **docs/m5.3-create-only-github-publication.md:** branch-publication design.
- **docs/qwen-local-agent.md:** local Qwen proof and operational requirements.
- **docs/release-acceptance.md:** live acceptance preconditions and procedure.

Some repository modules preserve earlier prototype slices or milestone boundaries. The presence of a package or design section by itself does not imply that every future product capability described by that material is shipped.

---

## 20. Engineering principles embodied by MIRAGE

Several design principles recur across the implementation:

1. **Authority is explicit.** A task description is not an access-control policy. Contract permissions are canonical, exact, time-bounded and fail closed.
2. **Identity is bound before execution.** The run manifest, workspace baselines and sandbox identity are set before the hostile process begins.
3. **Final state beats narration.** Trusted final-state observation, not the agent's report, determines which filesystem mutations occurred.
4. **Preparation is not commitment.** Building a plan or candidate Git artifact is distinct from changing a trusted file or publishing a remote ref.
5. **Revalidate before irreversible change.** A plan is tied to exact identities and must remain fresh.
6. **Keep the commit mechanism smaller than the observation mechanism.** MIRAGE can identify more classes of mutation than it currently permits itself to commit.
7. **No authority from diagnostics.** Logs, model outputs, action traces, graphs and visualizations explain outcomes but cannot authorize commit.
8. **Failure is a real outcome.** A rejected change, an uncertain process stop, a baseline conflict and an external publication uncertainty are different states and should be reported distinctly.
9. **Bound resource use.** Input trees, files, outputs and execution resources are capped, and truncation cannot silently become trusted evidence.
10. **Document limitations explicitly.** Narrow claims that match the implementation are stronger than a broad claim that cannot be defended under questioning.

## 21. A concise explanation for a technical audience

If you need to explain MIRAGE in one minute:

> MIRAGE is a transactional security runtime for AI coding agents. Instead of letting the agent directly edit a trusted repository and trying to decide afterward whether its actions were safe, MIRAGE gives it an isolated disposable copy. It captures the initial state, binds the run to a deterministic contract, executes the agent under a restrictive rootless-Docker policy, proves the hostile process tree has stopped, and independently computes the final filesystem diff. It checks that diff against the contract and the exact mutation types the runtime supports. Only a freshly revalidated authorized change can cross the boundary into the real workspace. MIRAGE then records a self-hashed receipt and a deterministic Effect Graph that can be verified and inspected in a read-only Observatory. The current commit path is deliberately narrow: one existing regular-file content modification, with documented limitations around crash durability, host races and unsupported mutation types.

## 22. Final takeaway

MIRAGE's differentiating idea is not that it expects an AI model to be obedient. It assumes the model or agent can be wrong and designs the authority boundary around that assumption.

The disposable workspace lets the agent attempt work. The trusted scanner establishes what actually changed. The contract decides what is allowed. Revalidation keeps the decision tied to the expected state. The commit engine applies only the small mutation the current implementation knows how to apply safely. Receipts and the Observatory make the result inspectable without becoming sources of authority.

That is the system's current center of gravity: **separate execution from commitment, and make trusted state transition—not model intent—the basis for authorization.**
