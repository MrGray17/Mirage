# MIRAGE System Architecture

> **Status:** Architecture baseline v0.1  
> **Project type:** Transactional security runtime for autonomous AI agents  
> **Primary thesis:** Agents execute in a speculative shadow environment; only verified, authorized effects are allowed to cross into real systems.

---

## 1. Executive Summary

MIRAGE is a security and execution layer that sits between autonomous AI agents and real-world systems such as repositories, filesystems, APIs, databases, cloud services, and SaaS tools.

MIRAGE does **not** trust the agent, the model, the prompt, retrieved documents, third-party tools, or repository contents. It assumes an agent may be confused, manipulated by indirect prompt injection, buggy, over-permissioned, or malicious.

The system therefore separates **attempted execution** from **real-world commitment**.

An agent performs work inside an isolated shadow environment. MIRAGE mediates privileged operations, observes attempted and completed effects, compares those effects against an immutable **Effect Contract** plus organization policy, builds a deterministic commit plan, revalidates the real-world state, and then either:

- **COMMIT** — apply only the approved effects to real systems; or
- **REJECT** — discard the shadow execution and leave reality unchanged.

The core security invariant is:

```text
CommittedEffects ⊆ AuthorizedEffects
```

A stricter MIRAGE invariant is:

```text
No irreversible external effect occurs before verification and commit.
```

MIRAGE is therefore not merely a sandbox, firewall, prompt guardrail, or agent permission layer. It combines:

1. isolation,
2. capability mediation,
3. deterministic policy enforcement,
4. effect observation,
5. speculative execution,
6. transactional commit,
7. state revalidation,
8. tamper-evident audit receipts.

---

# 2. Product Definition

## 2.1 Problem

Modern AI agents are increasingly given real authority:

- filesystem access,
- shell execution,
- Git repositories,
- GitHub/GitLab,
- databases,
- cloud infrastructure,
- email,
- SaaS tools,
- internal APIs,
- credentials.

Most current controls are based on one or more of the following:

- natural-language instructions,
- system prompts,
- tool allowlists,
- broad OS permissions,
- post-hoc observability,
- model-based safety classifiers.

These controls are useful but insufficient because they rely heavily on predicting whether an individual action is safe before its full consequences are visible.

MIRAGE introduces a stronger abstraction:

> **Do not ask only whether an action is allowed. Verify whether the resulting state transition is allowed before making it real.**

## 2.2 Example

User intent:

```text
Update README installation instructions and open a pull request.
```

The agent is compromised by malicious repository content and attempts:

```text
READ   README.md
WRITE  README.md
READ   .env
POST   attacker.example
WRITE  .github/workflows/deploy.yml
CREATE GitHub pull request
```

MIRAGE may allow the agent to continue operating in shadow state while recording denied/forbidden attempts. The transaction is ultimately rejected because the observed execution does not satisfy the Effect Contract.

The real repository remains unchanged.

---

# 3. Design Principles

These are architectural laws. Implementations may change; these laws should not.

## Law 1 — The agent is untrusted

The model, agent framework, prompts, repository files, web content, tool responses, and retrieved documents are all treated as untrusted input.

## Law 2 — Authority lives outside the model

The model may request actions. It does not decide whether those actions are authorized.

## Law 3 — Privileged effects must be mediated

An agent must not possess unrestricted direct access to protected resources. Privileged operations cross a MIRAGE-controlled boundary.

## Law 4 — Irreversible effects are deferred

External writes that cannot be safely rolled back are simulated or represented as intents during shadow execution and are executed only during commit.

Examples:

- sending email,
- HTTP POST to external systems,
- creating a pull request,
- production deployment,
- cloud mutation,
- payment initiation.

## Law 5 — Verification is deterministic

LLMs may assist with contract drafting, explanation, classification, or UX. They must not be the final security enforcement mechanism.

## Law 6 — Reality changes only through the Commit Engine

No supported real-world mutation may bypass the commit path.

## Law 7 — Commit is conditional on fresh state

A verified shadow result may not be applied if relevant real-world state changed after the shadow snapshot unless the adapter can prove the operation remains valid.

## Law 8 — Failure is fail-closed

If MIRAGE cannot prove that a requested commit satisfies policy and preconditions, the transaction is rejected.

## Law 9 — Every security decision is reconstructable

A run must produce enough structured evidence to explain what was authorized, attempted, denied, observed, verified, and committed.

## Law 10 — No long-lived secret belongs inside the sandbox

Credentials are brokered by MIRAGE and should be short-lived and narrowly scoped.

---

# 4. Threat Model

## 4.1 Assets

MIRAGE protects:

- source code,
- secrets,
- credentials,
- production configuration,
- repositories,
- external APIs,
- cloud resources,
- database state,
- SaaS accounts,
- audit integrity.

## 4.2 Adversaries and failures in scope

MIRAGE is designed to tolerate:

- indirect prompt injection,
- malicious repository/document content,
- compromised or malicious agent logic,
- buggy agents,
- over-eager autonomous behavior,
- unauthorized secret access attempts,
- unauthorized network egress attempts,
- destructive filesystem/Git operations,
- stale-state races / TOCTOU,
- duplicate commit attempts,
- process crashes,
- partial external failures,
- replayed commit requests,
- malformed tool requests,
- path traversal and symlink confusion within supported adapters,
- malicious tool parameters,
- unexpected agent termination.

## 4.3 Trusted computing base

For v0/v1, the trusted computing base includes:

- MIRAGE API/control-plane code,
- policy evaluator,
- runtime supervisor,
- trusted adapters,
- effect collector,
- verifier,
- commit engine,
- signing subsystem,
- host kernel/container runtime,
- database integrity mechanisms.

## 4.4 Explicitly out of scope for v0

MIRAGE v0 does not claim protection against:

- a fully compromised MIRAGE host/root user,
- hypervisor/kernel zero-days,
- hardware/side-channel attacks,
- malicious MIRAGE administrators,
- covert channels encoded entirely inside explicitly permitted output,
- incorrect human-authored security policy,
- semantic business mistakes that are technically allowed by the contract,
- arbitrary unsupported external systems that bypass MIRAGE adapters.

These limits must be stated honestly in demos and documentation.

---

# 5. High-Level Architecture

```text
                            ┌──────────────────────┐
                            │   User / API Client  │
                            └──────────┬───────────┘
                                       │ task
                                       ▼
┌────────────────────────────────────────────────────────────────────┐
│                         CONTROL PLANE                              │
│                                                                    │
│  ┌──────────────┐  ┌────────────────┐  ┌───────────────────────┐ │
│  │ Run Service  │  │ Contract Engine│  │ Policy Engine         │ │
│  └──────┬───────┘  └────────┬───────┘  └──────────┬────────────┘ │
│         │                    │                     │              │
│         └────────────────────┴──────────────┬──────┘              │
│                                             ▼                     │
│                                  Immutable Run Manifest           │
└─────────────────────────────────────────────┬──────────────────────┘
                                              │
                                              ▼
┌────────────────────────────────────────────────────────────────────┐
│                       EXECUTION PLANE                              │
│                                                                    │
│        ┌─────────────── Isolated Shadow Runtime ───────────────┐   │
│        │                                                       │   │
│        │  ┌───────────┐        ┌──────────────────────────┐   │   │
│        │  │ AI Agent  │───────▶│ MIRAGE Capability Gate  │   │   │
│        │  └───────────┘        └────────────┬─────────────┘   │   │
│        │                                    │                 │   │
│        │       ┌────────────────────────────┼─────────────┐   │   │
│        │       ▼                            ▼             ▼   │   │
│        │ Filesystem                     Git/GitHub      Network│   │
│        │ Adapter                        Adapters        Adapter │   │
│        │       └────────────────────────────┬─────────────┘   │   │
│        │                                    ▼                 │   │
│        │                           Effect Collector           │   │
│        └────────────────────────────────────┬─────────────────┘   │
│                                             ▼                     │
│                                      Effect Event Stream          │
└─────────────────────────────────────────────┬──────────────────────┘
                                              │
                                              ▼
┌────────────────────────────────────────────────────────────────────┐
│                        VERIFICATION PLANE                          │
│                                                                    │
│   Event Stream → State Diff → Effect Graph → Policy Verification  │
│                                             │                      │
│                                ┌────────────┴─────────────┐        │
│                                ▼                          ▼        │
│                             APPROVE                     REJECT     │
└────────────────────────────────┬───────────────────────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────┐
│                          COMMIT PLANE                              │
│                                                                    │
│ Precondition Check → Commit Plan → Idempotent Apply → Verify       │
│                                              │                     │
│                                              ▼                     │
│                                        Effect Receipt              │
└──────────────────────────────────────────────┬─────────────────────┘
                                               │
                                               ▼
                                      ┌──────────────────┐
                                      │   Real Systems   │
                                      └──────────────────┘
```

---

# 6. Architectural Boundaries

MIRAGE is divided conceptually into four planes.

## 6.1 Control Plane

Responsibilities:

- create runs,
- resolve identity,
- resolve workspace,
- build Effect Contracts,
- load organization/resource policy,
- issue immutable run manifests,
- schedule runtimes,
- expose API and dashboard state.

The Control Plane does not directly execute agent code.

## 6.2 Execution Plane

Responsibilities:

- create isolated shadow environments,
- start/stop agent processes,
- prevent direct privileged access,
- mediate tools/resources,
- record effect events,
- maintain copy-on-write state,
- enforce network isolation.

## 6.3 Verification Plane

Responsibilities:

- canonicalize effect events,
- build final state diff,
- build effect graph,
- evaluate Effect Contract,
- evaluate organization/resource policy,
- detect forbidden attempts,
- produce a deterministic verification decision.

## 6.4 Commit Plane

Responsibilities:

- freeze approved execution,
- generate ordered commit plan,
- revalidate resource versions,
- prevent stale commits,
- apply supported mutations idempotently,
- verify post-state,
- produce signed receipt.

---

# 7. Effect Contract

The Effect Contract is MIRAGE's central abstraction.

It represents **what state transition is authorized**, not merely which tools are available.

## 7.1 Contract properties

A contract must be:

- immutable during a run,
- versioned,
- canonicalizable,
- hashable,
- policy-checkable,
- independently inspectable,
- explicit about denied classes of effects,
- bounded by expiration.

The M3 prototype constructs a private, immutable contract value from mutable
input, canonicalizes exact filesystem resource identifiers and rule ordering,
and assigns the canonical contract a SHA-256 identity. Mutation of the input
after construction cannot add authority or change that identity. M3 supports
exact resource matches only; it does not claim glob semantics. Deny rules take
precedence over allow rules, unmatched operations and resources default to
deny, and the expiration bound is exclusive.

## 7.2 Example

```yaml
version: mirage.contract/v1
run_subject:
  agent_id: coding-agent-17

objective:
  description: "Update installation instructions and open a PR"

workspace:
  repository: acme/api
  base_revision: 4b62f2a

filesystem:
  read:
    allow:
      - /workspace/**
    deny:
      - /workspace/**/.env
      - /workspace/**/.env.*
      - /home/**/.ssh/**

  write:
    allow:
      - /workspace/README.md
    deny:
      - /workspace/.github/**
      - /workspace/src/**

git:
  allow:
    - create_branch
    - create_commit
  deny:
    - force_push
    - rewrite_history

github:
  allow:
    - create_pull_request
  deny:
    - merge_pull_request
    - delete_repository

network:
  default: deny

secrets:
  read: deny
  export: deny

expiry: 2026-08-26T15:00:00Z
```

## 7.3 Contract creation

Recommended flow:

```text
Human Intent
    ↓
Optional LLM Contract Draft
    ↓
Schema Validation
    ↓
Organization Policy Expansion
    ↓
Human / Trusted Workflow Approval
    ↓
Canonical Contract
    ↓
Hash + Immutable Run Manifest
```

An LLM may propose a contract but cannot authorize itself.

## 7.4 Contract evaluation model

For a transaction to commit:

```text
ObservedEffects ⊆ AllowedEffects
AND
CommittedEffects ⊆ AllowedEffects
AND
DeniedCriticalAttempts = 0
AND
OrganizationPolicy = PASS
AND
ResourcePreconditions = FRESH
```

For v0, any forbidden secret access or forbidden external egress attempt rejects the full transaction.

M3 evaluates expiry when a mediated effect is requested, when the event stream
is verified, and immediately before an approved run enters commit. An allowed
event is independently re-evaluated against the immutable contract; the
verifier does not trust an event's `ALLOW` label as authorization evidence by
itself.

TIME-001 gives each run one trusted wall-clock authority. The mediated M3
coordinator and M4 hostile lifecycle use the same trusted-time implementation;
the current prototypes are separate coordinators. The M4.3 hostile lifecycle
binds one clock object into its immutable run manifest. It records the greatest UTC
wall time observed at run/lifecycle creation, effect authorization, event
append, runtime prepare, start, freeze, reconciliation, verification, and
commit where those stages exist. Equal readings are valid; an earlier reading
is a structured clock-rollback failure. The greatest time never moves backward,
the run fails closed, and wall-clock rollback cannot make an expired contract
valid again. A freeze-time clock failure still triggers process-tree
termination but cannot produce `FROZEN`. This is an intra-run monotonicity
guard, not a claim that the host clock is globally accurate.

---

# 8. Effect Model

Every meaningful interaction is represented as an Effect Event.

## 8.1 Canonical event

```text
EffectEvent {
  id
  sequence
  run_id
  actor_id
  adapter
  operation
  resource_type
  resource_id
  source
  destination
  classification
  phase
  decision
  outcome
  timestamp
  metadata
  previous_event_hash
  event_hash
}
```

M3 stores these events in an in-memory append-only log owned by the trusted run
coordinator. The log assigns run/actor identity, contiguous sequence numbers,
stable event IDs, and UTC timestamps, and returns defensive copies to callers.
Adapters describe the attempted operation, decision, outcome, and metadata;
they cannot supply the security-relevant event timestamp. The log obtains that
timestamp from the run's shared trusted clock, while policy authorization uses
the same clock authority.
Canonical JSON is deterministic. `previous_event_hash` and `event_hash` remain
empty until M7 implements and verifies the tamper-evident chain; M3 makes no
durability or cryptographic-integrity claim for the in-memory stream.

## 8.2 Example events

```text
001 READ   filesystem /workspace/README.md                  ALLOW SUCCESS
002 READ   filesystem /workspace/.env                       DENY  BLOCKED
003 POST   network    https://attacker.example/exfiltrate   DENY  BLOCKED
004 WRITE  filesystem /workspace/README.md                  ALLOW SUCCESS_SHADOW
005 CREATE github     pull_request                          ALLOW DEFERRED
```

Denied attempts remain permanently visible in the run history.

For M3, "permanently" means for the lifetime of the in-memory run object,
including after its shadow has been discarded. Durable persistence arrives in
a later milestone.

## 8.3 Effect classes

Each operation is classified into one execution strategy.

### A. SHADOW_LOCAL

Safe to execute fully inside the isolated shadow environment.

Examples:

- file writes,
- file deletion in overlay,
- local Git commit,
- generated artifacts.

### B. BROKERED_READ

Read from a real external resource through a trusted adapter while logging and enforcing policy.

Examples:

- fetching repository metadata,
- approved external GET,
- reading an issue.

### C. DEFERRED_EXTERNAL_WRITE

Do not execute against the real external system during shadow execution. Record an intent and optionally return a simulated response.

Examples:

- create pull request,
- send message,
- modify cloud resource,
- create ticket.

### D. DENIED

Not exposed to the agent or rejected immediately.

Examples:

- access real SSH keys,
- unrestricted network sockets,
- direct production credentials.

---

# 9. Effect Graph

MIRAGE converts the event stream into a causal graph for verification and human understanding.

Nodes represent:

- agents,
- files,
- secrets,
- processes,
- tools,
- API endpoints,
- repositories,
- deferred mutations,
- external systems.

Edges represent:

- READ,
- WRITE,
- CREATE,
- DELETE,
- EXECUTE,
- SEND,
- DERIVE,
- AUTHORIZE,
- BLOCK.

Example:

```text
untrusted README content
          │
          ▼
       AI Agent
       /      \
      ▼        ▼
 README.md    .env
   WRITE      READ ✗
               │
               ▼
        attacker.example
             POST ✗
```

The graph is a derived view; the append-only event stream remains the canonical audit source.

---

# 10. Shadow Runtime

## 10.1 v0 implementation

Use:

- rootless Docker containers,
- read-only base image,
- dedicated unprivileged user,
- copy-on-write workspace,
- no Docker socket,
- no host secrets mounted,
- minimal Linux capabilities,
- seccomp profile,
- AppArmor/SELinux where available,
- dedicated network namespace,
- default-deny outbound network.

The container is an implementation detail, not MIRAGE's product abstraction.

## 10.2 Production direction

Evaluate stronger isolation such as:

- gVisor,
- Kata Containers,
- Firecracker microVMs.

Do not adopt a microVM platform until the core transaction model is proven.

## 10.3 Runtime lifecycle

```text
CREATED
    ↓
PREPARING
    ↓
RUNNING
    ↓
FREEZING
    ↓
FROZEN
    ↓
RECONCILING
    ↓
VERIFIED
    ↓
PRECOMMITTING
    ↓
COMMIT_READY
    ↓
COMMITTING
    ↓
COMMITTED / CONFLICTED / REJECTED / FAILED
```

`FROZEN` is reachable only after the trusted sandbox backend proves the
untrusted process tree can no longer mutate the disposable workspace. M4.1
implements lifecycle through this freeze proof. M4.2 adds a bounded no-follow
tree scanner, canonical baseline-to-final mutations, exact contract
verification, and a plan identity bound to the contract. Acquisition
uncertainty becomes `FAILED`, established denial becomes `REJECTED`, and only a
fully authorized plan reaches `VERIFIED`. M4.3 adds the separately reviewed,
single-existing-file content commit described in section 11.5. All other
mutation shapes remain non-committable. The runtime is disposable. Durable
truth lives outside it.

---

# 11. Filesystem Shadowing

The first complete MIRAGE primitive is a copy-on-write filesystem transaction.

## 11.1 Snapshot

At run start MIRAGE records:

- base Git revision,
- relevant file hashes,
- workspace metadata,
- contract hash.

For the M2 single-file prototype, the baseline identity is the SHA-256 digest
of the real `README.md` contents observed when the shadow transaction begins.
This is content identity, not file-generation identity: an external rewrite
that produces identical bytes remains commit-compatible. Inode changes,
timestamps, ownership, and permission-only changes are not represented by this
prototype baseline.

The pre-M4 SEC-001 hardening opens each workspace through Go 1.24 `os.Root`.
Baseline creation, revalidation, and mediated shadow reads inspect the rooted
entry, open it relative to the root, bind the opened regular-file handle to the
still-named regular entry with `os.SameFile` before reading, and revalidate the
entry and stable size/mode/modification-time observations after reading. A
mediated shadow write opens without truncation, validates the opened handle
against the rooted entry before its first mutation, writes through that handle,
and revalidates the named entry afterward. Static or raced type/symlink changes
fail closed before Mirage reads from or writes through an unverified handle.

These operations are safer object acquisition, not complete hostile-filesystem
containment. `os.Root` prevents traversal outside the root but may follow
in-root symlinks; Mirage's handle/entry checks reject an entry that is observed
as a symlink before use. Hard-link substitution to the same object, mount or
bind-mount behavior, special-object replacement while an open is in progress,
metadata-preserving in-place races, and platform-specific filesystem behavior
remain explicit limitations. The final revalidation-to-rename race described
below also remains.

## 11.2 Shadow state

```text
BASE WORKSPACE (read-only)
          +
COPY-ON-WRITE OVERLAY
          =
AGENT VIEW
```

The agent may mutate only the overlay.

## 11.3 Final diff

At freeze time MIRAGE calculates a normalized diff:

```text
created files
modified files
deleted files
renames
permission changes
symlink changes
```

Normalization must prevent policy bypass through:

- `..` path traversal,
- symlinks,
- alternate path spellings,
- case-insensitive collisions where relevant,
- hidden files,
- mount escape attempts.

## 11.4 Reject

Delete the overlay. Real state remains untouched.

## 11.5 Commit

Apply only the approved normalized diff after resource preconditions are revalidated.

The M4.3 hostile-runtime slice binds the immutable contract, shared trusted
clock, real baseline, permission-normalized disposable baseline, physical
workspace identity, and normalized sandbox configuration into one run
manifest before hostile execution. Reconciliation authority binds that
manifest, the contract hash, and the verified shadow plan hash. Contract v1
`WRITE` is narrowed for this slice to exactly one content-only `MODIFY` of one
existing independent regular file. `CREATE`, `DELETE`, `MODE_CHANGE`, symlink,
hard-link, special-object, root-mode, marker, zero-change, and multi-change
plans cannot reach the real commit path. Source setuid, setgid, and sticky mode
bits are unsupported and rejected instead of being normalized away. A source
tree containing an unresolved `.mirage-commit-*` artifact also fails closed and
requires explicit recovery before a later run can start.

Before precommit and again immediately before apply, Mirage re-observes the
complete supported real tree against its distinct real baseline, re-observes
the disposable tree against the verified final identity, and recomputes the
shadow plan hash. The applier then independently reopens the one real target,
checks its content digest and real permission mode, creates a same-directory
staging file only inside the trusted commit phase, writes the exact plan-bound
bytes, restores the real baseline permission mode, and revalidates the target
again immediately before same-directory replacement. After that work, the
authority-bearing lifecycle observes trusted time and rechecks contract expiry,
manifest identity, decision authority, and real-plan binding at the last
possible point before rename. A real mismatch is
`CONFLICTED`; expired or changed authority/shadow evidence is `REJECTED`;
acquisition uncertainty is `FAILED`. These paths do not replace the target.

M4.3 preserves regular-file content and permission mode only. It does not
preserve or authorize ownership, ACLs, extended attributes, inode identity,
timestamps, sparse layout, or other filesystem metadata. It does not implement
multi-file atomicity, a durable commit journal, directory `fsync`, or crash
recovery. Cleanup failure can leave a Mirage-named staging artifact, although
the target remains unmodified; such a run is `FAILED` and never reported as
committed. A later workspace preparation rejects that unresolved artifact
rather than copying it into another sandbox.

The trusted-host assumption remains material. A non-cooperating host process
can still race the complete-tree scan, targeted revalidation, staging, and
final rename; shadow changes after the last revalidation cannot change the
already derived plan bytes, but can invalidate the claim that the shadow stayed
frozen. Same-directory rename provides an atomic directory-entry replacement
on the supported Linux filesystems, not an atomic compare-and-swap with the
earlier observations. M4.3 narrows these windows and binds what is applied; it
does not eliminate them.

M4.4 places arbitrary coding-agent execution on a hard-capped rootless-Docker
tmpfs volume instead of the legacy writable bind mount. A trusted keeper holds
the volume mounted while Mirage pauses and independently verifies the hostile
cgroup, copies the frozen final tree into the protected host-side disposable
directory through Docker's trusted archive path, then kills and proves both
container process trees stopped before reconciliation. The manifest binds the
exact agent image, argv, capacity, broker policy, and existing sandbox limits.

The optional model path is a trusted host broker exposed as a single read-only
mounted Unix-socket directory. Direct sandbox networking remains disabled and
no provider key enters the agent. Responses-provider adapters proxy only
bounded, exact-model requests; model output is untrusted and cannot authorize
effects. The per-run broker directory grants the sandbox traversal to the
known socket but neither listing nor write authority, and a local preflight
must succeed before the coding agent starts. M4.4 does not change the M4.3
commit shape: exactly one existing-file content modification is the only real
mutation supported.

Inside the trusted `ApplyCommit` phase, M2 prepares the replacement in the real
file's directory, then re-observes the real file immediately before
replacement. A content mismatch or a successfully observed type/shape change
(including absence, directory, or symlink replacement) moves the transaction
to terminal `CONFLICTED`, removes transaction-owned temporary state, and
preserves the externally written state.

If Mirage cannot establish current state because observation itself fails, it
returns a structured revalidation error, performs no target mutation, leaves
the transaction `ACTIVE`, and retains the shadow for retry or explicit
rejection. Uncertainty is not mislabeled as a conflict. Mirage does not create
commit-staging artifacts in the real workspace before `ApplyCommit`.

This is not an atomic filesystem compare-and-swap. A non-cooperating process
can still modify the destination after the final hash read and before Mirage's
rename. Same-directory rename makes the final directory-entry replacement
atomic on Unix filesystems that provide the usual rename guarantees, but it
does not bind that replacement to the earlier content comparison. Go does not
guarantee `os.Rename` atomicity on non-Unix platforms. M2 therefore narrows but
does not eliminate the final TOCTOU window.

Mirage reads through an open handle and verifies that the path still identifies
that regular file after the read; size, mode, and modification time must also
remain stable across the read. These checks still do not create an atomic
snapshot against an in-place writer that can preserve or race the observed
metadata.

The transaction's in-process mutex serializes calls on that transaction only.
It provides no protection from editors, Git, other Mirage processes, or other
external writers. M2 intentionally adds no advisory lock and makes no
cross-process locking claim.

---

# 12. Capability Gateway

The Capability Gateway is the trusted boundary between the agent and privileged tools.

The agent should see virtualized capabilities rather than direct credentials.

The M3 filesystem gateway is a narrow mediation prototype. It accepts virtual
workspace paths, canonicalizes relative and `/workspace/...` spellings,
rejects traversal and host-absolute paths, and supports only
`/workspace/README.md`. Every routed read or write produces one Effect Event:
allowed success, allowed failure, or denied/blocked. Invalid requested paths
are represented by a digest rather than being treated as trusted canonical
resource identifiers.

The M3 run coordinator freezes gateway access at verification, independently
checks the event stream, and grants `ApplyCommit` authority only after an
`APPROVED` decision. A denied attempt, malformed/inconsistent event, expired
contract, failed shadow effect, or incomplete event recording rejects the run
and discards its shadow. The M2 transaction remains the only component that can
mutate the real `README.md`.

M3 does **not** run an untrusted agent or prevent direct OS access to the shadow
path. Its observation claim covers operations routed through the gateway. The
pre-M4 acquisition hardening removes the obvious separated validation/read and
validation/write gaps on that route, subject to the filesystem limitations in
Section 11. It does not solve SEC-002: M4 must prevent an actual process from
bypassing mediation or must independently observe and reconcile all of that
process's security-relevant filesystem effects.

```text
Agent
  ↓
MIRAGE Capability Gateway
  ↓
Policy / Contract Check
  ↓
Adapter
  ↓
Shadow Result or Deferred Intent
```

## 12.1 MCP integration

For MCP-capable agents:

```text
Agent ↔ MIRAGE MCP Proxy ↔ Approved MCP/tool adapters
```

The MCP proxy must:

- expose only approved tools,
- validate schemas,
- enforce contract constraints,
- attach run identity,
- record every request/result,
- strip credentials,
- prevent direct bypass to real MCP servers.

## 12.2 Shell access

Shell execution is high risk.

In v0:

- shell runs only inside the sandbox,
- process runs as unprivileged user,
- direct network is disabled,
- host filesystem is not mounted writable,
- protected credentials do not exist in process environment.

---

# 13. Network Architecture

Network effects are special because data exfiltration cannot be rolled back.

## 13.1 Default

```text
sandbox direct egress = DENY
```

The agent has no unrestricted external network path.

## 13.2 Supported network operations

Approved network access is exposed through a MIRAGE HTTP/API adapter.

```text
Agent
  ↓
MIRAGE HTTP Tool
  ↓
Contract Check
  ↓
Broker / Adapter
  ↓
External Service
```

## 13.3 External writes

External writes are deferred until commit.

Shadow execution produces:

```text
DeferredEffect {
  operation
  destination
  normalized_request
  expected_response_shape
  preconditions
  idempotency_key
}
```

The sandbox receives a deterministic simulated response where practical.

## 13.4 External reads

External reads may be brokered in real time if the contract permits them and the result is treated as untrusted input.

---

# 14. Credentials and Identity

## 14.1 Rule

The agent process does not receive durable production credentials.

## 14.2 Credential flow

```text
Agent request
    ↓
MIRAGE Gateway
    ↓
Policy verifies operation
    ↓
Trusted adapter obtains/uses scoped credential
    ↓
Operation executed
```

## 14.3 Production credential strategy

Prefer:

- workload identity,
- OIDC,
- short-lived tokens,
- GitHub App installation tokens,
- cloud role assumption,
- Vault/KMS-backed secret broker.

For the hackathon MVP, a GitHub credential may be stored server-side for the trusted GitHub adapter, but must never be injected into the sandbox.

---

# 15. Policy Engine

Contracts describe per-run intent. Policies describe broader security rules.

## 15.1 Policy layers

```text
Platform Policy
      +
Organization Policy
      +
Resource Policy
      +
Run Effect Contract
      =
Effective Policy
```

Higher-level deny rules cannot be relaxed by lower layers.

## 15.2 Recommended implementation

Use a deterministic policy engine.

Preferred production candidate:

- Open Policy Agent / Rego.

For v0, a typed internal evaluator is acceptable if the rule surface is small and thoroughly tested.

## 15.3 Example rules

```text
DENY if resource.classification == SECRET
     and operation == READ
     and contract.secrets.read != ALLOW

DENY if effect.type == NETWORK_EGRESS
     and destination not in contract.network.allowlist

DENY if filesystem.write path not matched by contract.filesystem.write.allow
```

No LLM decides PASS/FAIL.

---

# 16. Verification Engine

Verification happens only after the runtime is frozen.

## 16.1 Inputs

- immutable contract,
- effective policy version,
- append-only event stream,
- normalized filesystem diff,
- deferred effects,
- effect graph,
- runtime integrity status.

## 16.2 Verification pipeline

```text
Freeze Agent
    ↓
Seal Event Stream
    ↓
Normalize Effects
    ↓
Build State Diff
    ↓
Build Effect Graph
    ↓
Evaluate Contract
    ↓
Evaluate Policy
    ↓
Check Critical Denied Attempts
    ↓
Produce VerificationDecision
```

## 16.3 Decision

```text
VerificationDecision {
  run_id
  status: APPROVED | REJECTED
  contract_hash
  policy_version
  violations[]
  approved_effects[]
  denied_attempts[]
  commit_plan_hash
}
```

This object is immutable once commit begins.

---

# 17. Commit Engine

The Commit Engine is the only component allowed to make supported shadow effects real.

It should be deliberately small, deterministic, and heavily tested.

## 17.1 Commit protocol

```text
1. Ensure run state == APPROVED
2. Acquire commit lease for run
3. Load immutable VerificationDecision
4. Revalidate real resource preconditions
5. Abort if stale/conflicted
6. Build deterministic ordered commit plan
7. Apply each effect using idempotency key
8. Persist each commit result durably
9. Verify post-state
10. Mark run COMMITTED
11. Generate receipt
12. Destroy shadow runtime
```

## 17.2 TOCTOU defense

At shadow start, adapters record preconditions such as:

- Git commit SHA,
- file content hash,
- API object version/ETag,
- database row version,
- resource generation ID.

Immediately before commit:

```text
CurrentRealVersion == SnapshotVersion
```

If false:

```text
run = CONFLICTED
commit = ABORT
```

Never silently overwrite newer state.

For the M2 local filesystem prototype, a regular-file "version" means a SHA-256
content digest. Successfully observed content or shape changes conflict.
Failures that prevent Mirage from establishing current state fail closed with
a distinct structured error while retaining active shadow state. The
implementation stages replacement bytes only within `ApplyCommit` and before
the final revalidation so the remaining interval between comparison and rename
is as small as the portable Go API reasonably permits. The staging file is
created in the destination directory; Mirage does not fall back to a
cross-filesystem copy/write path.

M2 does **not** claim atomic compare-and-replace semantics. Eliminating the
remaining external-writer race requires a stronger resource primitive or a
cooperative protocol whose guarantees are explicit for the target filesystem.

## 17.3 Idempotency

Every external mutation receives:

```text
idempotency_key = H(run_id || effect_id || adapter_version)
```

If a retry occurs after a crash, the adapter must return the previously committed result or prove that the operation has not occurred.

## 17.4 Partial commit failures

Cross-system atomic transactions are generally impossible.

Therefore adapters must classify effects as:

- atomic,
- idempotent,
- compensatable,
- non-compensatable.

The initial MVP must intentionally support only a narrow set of operations with understandable failure semantics.

Long-term MIRAGE may use a durable saga-style commit log for multi-system workflows.

---

# 18. Adapter Architecture

MIRAGE integrates with external systems through trusted adapters.

## 18.1 Adapter contract

Conceptually:

```text
interface EffectAdapter {
  name()
  validateRequest()
  prepareSnapshot()
  simulateOrExecuteShadow()
  normalizeEffect()
  buildPreconditions()
  buildCommitAction()
  commit()
  verifyCommit()
  compensateIfSupported()
}
```

## 18.2 v0 adapters

Only implement:

1. FilesystemAdapter
2. GitAdapter
3. GitHubAdapter
4. NetworkAdapter

## 18.3 Adapter trust rule

Adapters are security-critical code.

They must:

- reject unknown fields,
- normalize identifiers,
- never trust model-supplied paths blindly,
- avoid passing raw credentials into agent-visible responses,
- produce structured effect events,
- be covered by integration/security tests.

---

# 19. Run State Machine

A run must have one authoritative state.

```text
CREATED
   ↓
CONTRACTED
   ↓
PREPARING
   ↓
RUNNING
   ↓
FROZEN
   ↓
VERIFYING
   ↓
┌─────────────┐
▼             ▼
APPROVED    REJECTED
   │
   ▼
COMMITTING
   │
   ├───────────────┐
   ▼               ▼
COMMITTED       CONFLICTED
```

Terminal/failure states:

```text
REJECTED
COMMITTED
CONFLICTED
ABORTED
FAILED
EXPIRED
```

Transitions occur only through a dedicated domain state-machine function. Do not scatter state booleans throughout the codebase.

The M3 in-memory coordinator begins at `RUNNING` after contract and shadow
preparation succeed, then uses explicit `VERIFYING`, `APPROVED`, `COMMITTING`,
`REJECTED`, `COMMITTED`, `CONFLICTED`, `EXPIRED`, and `FAILED` transitions. `FAILED` is
non-committable; when rejection cleanup failed, only an explicit cleanup retry
is permitted. Earlier control-plane states and durable transition records are
deferred until those responsibilities exist.

---

# 20. Persistence Model

Use PostgreSQL as the primary durable store.

Do not add Redis/Kafka until required by measured load.

## 20.1 Core tables

### runs

```text
id
state
agent_id
contract_id
workspace_id
created_at
started_at
frozen_at
completed_at
failure_code
```

### contracts

```text
id
version
canonical_json
sha256
expires_at
created_at
```

### policy_versions

```text
id
version
canonical_policy
sha256
created_at
```

### effect_events

```text
id
run_id
sequence
adapter
operation
resource_type
resource_id
decision
outcome
metadata_json
prev_hash
event_hash
created_at
```

Unique constraint:

```text
(run_id, sequence)
```

### deferred_effects

```text
id
run_id
adapter
normalized_payload
preconditions
idempotency_key
status
```

### verification_decisions

```text
run_id
status
contract_hash
policy_hash
commit_plan_hash
violations_json
created_at
```

### commit_actions

```text
id
run_id
effect_id
ordinal
status
idempotency_key
external_reference
attempt_count
last_error
```

### receipts

```text
id
run_id
receipt_json
receipt_hash
signature
key_id
created_at
```

---

# 21. Tamper-Evident Event Chain

For the MVP, each event is hash-chained:

```text
event_hash = SHA256(
  previous_event_hash || canonical_event_payload
)
```

The final event hash is included in the Effect Receipt.

This detects modification/reordering of persisted event history when independently verified against the signed receipt.

Later, high-volume deployments may use Merkle structures or external transparency logs.

---

# 22. Effect Receipt

A successful commit produces a signed receipt.

Example:

```json
{
  "version": "mirage.receipt/v1",
  "run_id": "run_01J...",
  "agent_id": "coding-agent-17",
  "contract_hash": "sha256:...",
  "policy_hash": "sha256:...",
  "base_state_hash": "sha256:...",
  "event_chain_head": "sha256:...",
  "commit_plan_hash": "sha256:...",
  "result_state_hash": "sha256:...",
  "status": "COMMITTED",
  "committed_effects": [],
  "timestamp": "...",
  "key_id": "mirage-signing-key-1",
  "signature": "..."
}
```

Recommended signature algorithm:

- Ed25519.

Production signing keys should live in KMS/HSM-backed infrastructure rather than application configuration.

Do not claim that the receipt proves events outside MIRAGE's trust boundary. It proves integrity of MIRAGE-mediated evidence.

---

# 23. Public API

Use REST/JSON for the first external API.

Internal service boundaries may later use gRPC where justified.

## 23.1 Runs

```text
POST /v1/runs
GET  /v1/runs/:id
POST /v1/runs/:id/abort
```

## 23.2 Effects

```text
GET /v1/runs/:id/effects
GET /v1/runs/:id/effect-graph
GET /v1/runs/:id/diff
```

## 23.3 Verification

```text
GET  /v1/runs/:id/verification
POST /v1/runs/:id/commit
```

For an interactive approval configuration, `/commit` may require a human approval token. For autonomous policy, the Control Plane may invoke commit automatically after verification.

## 23.4 Receipts

```text
GET /v1/runs/:id/receipt
POST /v1/receipts/verify
```

---

# 24. Technology Baseline

The architecture should not become a tool-shopping exercise. Start with a small, boring stack.

## Core backend/runtime

**Go**

Reasons:

- strong concurrency model,
- static binaries,
- good networking/process tooling,
- mature container/cloud ecosystem,
- simpler operational footprint than a multi-runtime backend.

## Dashboard

**Next.js + TypeScript**

The dashboard is not part of the security boundary.

## Database

**PostgreSQL**

## Policy

v0: typed deterministic policy module.  
Later: evaluate **OPA/Rego** when policy complexity justifies it.

## Sandbox

v0: rootless Docker.  
Later: gVisor/Kata/Firecracker evaluation.

## Observability

**OpenTelemetry** conventions from day one; stdout/log files are acceptable locally.

## Cryptography

Use standard library / audited libraries only. Never implement custom cryptographic primitives.

---

# 25. Repository Layout

MIRAGE begins as a modular monolith plus isolated worker/runtime code.

Do **not** start with microservices.

```text
Mirage/
├── cmd/
│   ├── mirage-api/
│   ├── mirage-worker/
│   └── mirage-cli/
│
├── internal/
│   ├── domain/
│   │   ├── run/
│   │   ├── contract/
│   │   ├── effect/
│   │   ├── verification/
│   │   └── receipt/
│   │
│   ├── controlplane/
│   ├── runtime/
│   ├── gateway/
│   ├── policy/
│   ├── verifier/
│   ├── commit/
│   ├── audit/
│   ├── crypto/
│   └── storage/
│
├── adapters/
│   ├── filesystem/
│   ├── git/
│   ├── github/
│   └── network/
│
├── contracts/
│   ├── schemas/
│   └── examples/
│
├── web/
│   └── dashboard/
│
├── deploy/
│   ├── docker/
│   └── local/
│
├── examples/
│   ├── safe-agent/
│   └── compromised-agent/
│
├── tests/
│   ├── integration/
│   ├── e2e/
│   ├── security/
│   ├── failure/
│   └── fixtures/
│
├── ARCHITECTURE.md
├── README.md
└── go.mod
```

---

# 26. Code Architecture Rules

These rules exist specifically to prevent vibecoded spaghetti.

## 26.1 Domain logic stays framework-independent

HTTP handlers, database drivers, Docker clients, and GitHub SDKs must not contain core security decisions.

## 26.2 State changes use explicit domain transitions

No direct arbitrary mutation of run state.

## 26.3 Adapters own external-system semantics

GitHub-specific logic belongs in the GitHub adapter, not in the verifier or API layer.

## 26.4 Security decisions return structured reasons

Never return only `true/false` for policy decisions.

```text
Decision {
  allowed
  rule_id
  reason
  evidence
}
```

## 26.5 Event log is append-only

No update/delete API for historical Effect Events.

## 26.6 Commit code is isolated

Code capable of real-world mutation must be easy to locate and review.

## 26.7 No hidden fallback behavior

Unknown operation, unknown adapter, malformed contract, unavailable policy, stale resource, or integrity failure must reject.

## 26.8 No security-critical LLM call

The system must remain safe if every model response is adversarial.

---

# 27. Observability

Every run carries:

```text
run_id
agent_id
contract_id
trace_id
runtime_id
```

Every effect carries:

```text
effect_id
run_id
sequence
adapter
resource
policy_rule_id
```

## 27.1 Metrics

Track at minimum:

- runs started,
- runs approved,
- runs rejected,
- forbidden attempts,
- sandbox startup latency,
- verification latency,
- commit latency,
- commit conflicts,
- adapter errors,
- receipt-generation failures,
- runtime leaks/orphans.

## 27.2 Logs

Logs must never contain raw secrets.

Sensitive event metadata must be redacted or represented by hashes/classification labels.

## 27.3 Tracing

Trace:

```text
request
→ contract resolution
→ runtime allocation
→ agent execution
→ adapter calls
→ verification
→ commit
→ receipt
```

---

# 28. Failure Handling

## Runtime crashes

Mark run `FAILED`, discard shadow state, preserve audit events already durably recorded.

## Control Plane crash

Run state is recoverable from PostgreSQL. Runtime reconciliation detects orphaned workers.

## Commit Engine crash before mutation

Retry safely.

## Commit Engine crash after external mutation

Recover using durable commit-action log plus idempotency key; do not blindly replay.

## Database unavailable

Fail closed. Do not begin or commit security-sensitive transactions without durable state.

## Policy engine unavailable

Fail closed.

## Signing service unavailable

Do not mark transaction fully finalized as receipt-complete; production policy may choose to reject commit before mutation if signed audit proof is mandatory.

---

# 29. Security Test Matrix

Security tests are first-class product requirements.

## 29.1 Isolation tests

- agent cannot read host files,
- agent cannot access Docker socket,
- agent cannot become privileged,
- agent cannot access server environment secrets,
- agent cannot make direct external network connection,
- agent cannot mount host paths.

## 29.2 Filesystem policy tests

- allowed file write succeeds only in shadow,
- forbidden file read is blocked and logged,
- forbidden file write is blocked and logged,
- path traversal is rejected,
- symlink-based escape is rejected,
- hidden protected files remain protected,
- rejection leaves real workspace byte-for-byte unchanged.

## 29.3 Transaction tests

- real state never mutates before commit,
- safe diff commits correctly,
- rejected transaction commits nothing,
- stale base revision becomes `CONFLICTED`,
- duplicate commit request is idempotent,
- commit after expiry is rejected.

## 29.4 Network tests

- raw egress blocked,
- forbidden domain blocked,
- deferred POST not sent during shadow run,
- deferred request sent exactly once during commit,
- denied exfiltration attempt rejects run.

## 29.5 Audit tests

- event sequence cannot be reordered without hash-chain failure,
- event mutation invalidates receipt verification,
- contract mutation invalidates receipt verification,
- receipt signature verification succeeds for authentic receipt,
- forged receipt fails.

## 29.6 Prompt-injection demo test

A repository contains malicious instructions attempting to read `.env` and transmit it.

Expected behavior:

```text
agent attempts secret read
→ MIRAGE blocks
→ attempt recorded
→ transaction rejected
→ no external request occurs
→ real repository unchanged
```

---

# 30. End-to-End Competition Demo

The winning demo should prove the architecture, not merely display a dashboard.

## Scenario A — compromised agent

### User task

```text
Update README installation instructions and open a pull request.
```

### Hidden malicious repository instruction

The agent is induced to attempt unauthorized secret access and outbound transmission.

### Live visualization

```text
README.md             WRITE     ✓ allowed
.env                  READ      ✗ blocked
attacker.example      POST      ✗ blocked
GitHub PR             CREATE    deferred
```

### Result

```text
REALITY REJECTED

Reason:
- forbidden secret-read attempt
- forbidden external-egress attempt

Real repository changes: 0
External requests sent: 0
```

## Scenario B — clean agent

Same user task, safe execution.

```text
README.md             WRITE     ✓
Git branch            CREATE    ✓
Git commit            CREATE    ✓
GitHub PR             CREATE    deferred
```

Verifier passes.

Before commit, show that GitHub has not changed.

Press/trigger commit.

MIRAGE revalidates the base revision, applies the approved effects, creates the PR exactly once, then produces a signed receipt.

### Result

```text
REALITY COMMITTED ✓
```

This contrast is the entire thesis in under two minutes.

---

# 31. MVP Scope

The competition MVP supports exactly one compelling workflow.

## Supported

- one local Git repository,
- one agent at a time per run,
- rootless Docker sandbox,
- copy-on-write workspace,
- filesystem reads/writes,
- Git branch + commit,
- GitHub pull-request creation,
- default-deny network,
- one deterministic Effect Contract,
- effect event stream,
- effect graph,
- verification,
- commit/reject,
- signed receipt.

## Explicitly not in MVP

- Kubernetes,
- distributed scheduler,
- multi-region,
- Slack,
- email,
- AWS mutation,
- arbitrary database adapters,
- payments,
- browser automation,
- multi-agent transactions,
- custom hypervisor,
- blockchain,
- ML threat detection,
- advanced IAM product,
- generic plugin marketplace.

The prototype wins by proving one deep mechanism, not by displaying twenty shallow integrations.

---

# 32. Implementation Milestones

## M0 — Architecture and invariants

Done when:

- this architecture is accepted,
- threat model written,
- Effect Event schema fixed for v0,
- run state machine fixed for v0.

## M1 — Shadow filesystem transaction

Prove:

```text
real README = A
agent writes B
real remains A
shadow becomes B
REJECT → real A
COMMIT → real B
```

No AI required yet.

## M2 — Conflict-safe filesystem commit

- record the SHA-256 content baseline when the shadow transaction begins,
- revalidate real `README.md` content immediately before commit,
- stale content becomes terminal `CONFLICTED`,
- conflict preserves external state and cleans transaction-owned resources,
- document the residual non-atomic compare/rename race.

## M3 — Effect observation + contracts

- filesystem operations generate canonical Effect Events,
- contract allow/deny works deterministically,
- forbidden attempt rejects run.

The M3 vertical slice is intentionally limited to exact-match read/write rules
for the shadow `README.md`, an in-memory append-only event stream, deterministic
verification, and commit gating. It does not include Docker, AI execution,
external effects, persistence, event hash chaining, receipts, Git, GitHub, or
UI work.

Before M4, TIME-001 makes the shared trusted run clock fail closed on rollback,
EVT-001 moves event timestamp ownership into the trusted event system, and the
narrow SEC-001 pass binds rooted filesystem use to validated open handles. The
documented residual filesystem limitations and SEC-002 non-bypass design remain
M4 inputs, not solved claims.

## M4 — Isolated agent runtime

- run an actual coding agent in rootless sandbox,
- no direct external egress,
- no real credentials inside runtime,
- hard-cap the arbitrary agent's writable workspace,
- freeze and acquire authoritative final state before process-tree stop proof,
- real workspace protected,
- retain the M4.3 one-existing-file `MODIFY` commit boundary.

## M5 — Git + GitHub deferred commit

M5 is split so each new external authority receives a separate security review:

- **M5.1 — Git authority and immutable deferred plan:** bind one narrow trusted
  repository topology and derive data-only Git intent exclusively from VERIFIED
  reconciliation. No Git mutation or credential exists in this slice.
- **M5.2 — deterministic commit construction:** construct and independently
  verify the exact commit in transaction-owned Git state without altering the
  user's worktree or refs.
- **M5.3 — create-only remote branch:** push the exact verified commit with
  conflict/CAS protection and uncertain-result reconciliation.
- **M5.4 — GitHub pull request effect:** create one bounded PR with idempotency
  and explicit accounting when remote branch and PR outcomes differ.

## M6 — Repository TOCTOU + crash safety

- stale repository base rejects commit,
- duplicate commit does not duplicate PR,
- simulated crash after external apply recovers safely.

## M7 — Receipt + audit verification

- hash-chained events,
- signed receipt,
- receipt verification endpoint/CLI.

## M8 — Competition UI

Only after the engine works:

- run timeline,
- animated effect graph,
- contract view,
- shadow vs real diff,
- clear COMMIT / REJECT state,
- receipt view.

---

# 33. Production Evolution

Only after the core mechanism is validated.

## Stage 1 — Single-node developer product

```text
API + Worker + Postgres + Docker + GitHub
```

## Stage 2 — Multi-worker

```text
Control Plane
    ↓
Durable Queue
    ↓
Runtime Worker Pool
    ↓
Verification / Commit Workers
```

## Stage 3 — Enterprise isolation

- microVMs,
- workload identity,
- KMS signing,
- tenant isolation,
- centralized policy bundles,
- enterprise audit export.

## Stage 4 — General agent execution platform

Adapters for:

- cloud providers,
- databases,
- SaaS systems,
- enterprise internal APIs,
- multiple agent frameworks.

The invariant remains unchanged:

```text
agent → speculative execution → verified effects → commit
```

---

# 34. Important Non-Goals

MIRAGE is not:

- an AI antivirus,
- a prompt-injection classifier,
- an LLM safety fine-tune,
- a generic SOC dashboard,
- a replacement for IAM,
- a replacement for OS/container isolation,
- a generic workflow automation platform.

MIRAGE composes with those systems.

Its unique responsibility is:

> **Make autonomous-agent side effects transactional and verifiable before they alter reality.**

---

# 35. Architectural Decision Records to Create Next

As implementation begins, create ADRs for decisions that are expensive to reverse.

Recommended initial ADRs:

1. `ADR-001`: Go for the security-critical backend/runtime.
2. `ADR-002`: Modular monolith before microservices.
3. `ADR-003`: PostgreSQL as durable source of truth.
4. `ADR-004`: Rootless Docker for v0 runtime isolation.
5. `ADR-005`: Default-deny direct sandbox network.
6. `ADR-006`: External writes are deferred until commit.
7. `ADR-007`: Immutable Effect Contract per run.
8. `ADR-008`: Hash-chained Effect Events + Ed25519 receipts.
9. `ADR-009`: GitHub App/server-held credentials; no credential injection into agent.
10. `ADR-010`: Deterministic policy decisions; no LLM in enforcement path.

---

# 36. Engineering Review Checklist

Any major MIRAGE feature must answer all of these before merge:

### Trust

- Which side of the trust boundary is this code on?
- What input is attacker-controlled?

### Authority

- Does this accidentally give the agent new authority?
- Can the same capability be brokered instead?

### Mediation

- Can this effect bypass the Capability Gateway?
- Can the agent reach the real system directly?

### Transactionality

- Does anything irreversible occur before commit?
- What happens on rejection?

### Consistency

- What state was snapshotted?
- How is stale state detected?

### Crash safety

- What if the process dies immediately before this step?
- What if it dies immediately after this step?

### Idempotency

- What happens if the same operation is retried?

### Auditability

- What Effect Event proves this happened?
- Can a reviewer reconstruct the decision?

### Secrets

- Can a secret enter logs, traces, model context, or sandbox environment?

### Failure mode

- Does uncertainty fail closed?

---

# 37. Definition of "Real MIRAGE"

The project is not considered architecturally real until all of the following are demonstrated:

1. An untrusted agent is running inside a separately enforced runtime boundary.
2. The agent cannot directly mutate the real workspace.
3. Direct outbound network access is denied.
4. The agent does not possess the real GitHub credential.
5. Filesystem effects are observable as structured events.
6. A forbidden operation is physically blocked by trusted code outside the model.
7. A forbidden critical attempt causes transaction rejection.
8. Rejection leaves real state unchanged.
9. External GitHub mutation does not happen during shadow execution.
10. A clean run can be verified and committed.
11. Stale real state causes commit conflict rather than overwrite.
12. Repeating commit does not duplicate the external effect.
13. A signed receipt can be independently verified.

If any of these are faked by prompting the model to "behave safely," the implementation has violated the MIRAGE thesis.

---

# 38. One-Sentence Architecture

> **MIRAGE is a transactional security runtime in which untrusted AI agents execute speculatively inside an isolated, capability-mediated shadow environment, while deterministic policy, effect verification, state revalidation, idempotent commit, and signed receipts control which effects are permitted to become real.**
