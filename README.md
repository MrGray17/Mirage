# MIRAGE

MIRAGE is a transactional security runtime for untrusted AI coding agents.
An agent works in an isolated disposable workspace; MIRAGE freezes the final
state, independently determines what changed, checks the result against a
deterministic contract, and lets only the exact verified mutation cross into
reality.

> We do not need the AI to agree with our security policy.

The core invariant is:

```text
CommittedEffects ⊆ AuthorizedEffects
```

## How it works

```text
AI model
→ isolated disposable workspace
→ frozen final state
→ trusted scan
→ canonical diff
→ deterministic contract verification
→ freshness checks
→ trusted commit
→ reality
```

Evidence is downstream and never grants authority:

```text
trusted execution facts
→ Effect Graph
→ self-hashed receipt
→ Observatory / CLI
```

The real workspace is never mounted into the agent container. The rootless
sandbox has `network=none`, a read-only root filesystem, no Docker socket, no
host home or credentials, dropped capabilities, no-new-privileges, bounded
CPU/memory/PIDs/time/output, and a hard writable-workspace quota.

## What MIRAGE v1 proves

- rootless hostile-process isolation and disposable workspaces;
- no direct sandbox network authority;
- whole-process-tree stop before trusted final-state acquisition;
- authoritative frozen-tree scanning and canonical diffs;
- deterministic contract verification and freshness revalidation;
- a trusted commit boundary for one existing regular-file content change;
- local `qwen2.5-coder:1.5b` execution through a trusted Ollama broker;
- a constrained Qwen tool sequence: `list_files`, `read_file`, `patch_file`,
  and `finish`;
- a real authorized model mutation reaching `COMMITTED`;
- a real unauthorized model mutation reaching `REJECTED` with reality
  unchanged;
- compatible receipt v1/v2 verification, deterministic Effect Graphs, and a
  read-only Observatory evidence view;
- a product CLI with a Windows frontend and WSL2 security backend;
- deterministic Git commit and create-only GitHub branch-publication
  foundations.

MIRAGE does not depend on model obedience. Malformed model output fails closed,
and an unauthorized final mutation is rejected even when the model completed
its requested edit inside the disposable workspace.

## Quick deterministic demo

Prerequisites:

- Linux, or Windows with WSL2;
- Go 1.24 or newer;
- rootless Docker, cgroup v2 with delegated CPU/memory/PID controllers, and
  built-in seccomp.

Install and inspect the environment:

```bash
./scripts/install.sh
mirage setup
mirage doctor
```

Windows PowerShell installs a native frontend backed by the same WSL2 runtime:

```powershell
.\scripts\install.ps1 -Distribution Ubuntu
mirage setup
mirage doctor
```

Run the malicious fixture:

```bash
mirage run --open
```

Expected result:

```text
Agent attempted 4 effects. MIRAGE authorized 1, denied 3, and committed 1.
```

Run the matching benign fixture:

```bash
mirage run benign
```

Expected result:

```text
Agent attempted 1 effects. MIRAGE authorized 1, denied 0, and committed 1.
```

Each run prints `receipt_file`, `observatory`, and `real_workspace`. Verify the
receipt independently with:

```bash
mirage verify <receipt_file>
```

See [the competition operator guide](docs/competition-demo.md) for presentation
details.

## Real local-Qwen proof

Ollama must already be serving exactly `qwen2.5-coder:1.5b`; MIRAGE never pulls
or installs a model. Build the constrained, scratch-based agent image from the
repository root and capture its immutable image identity:

```bash
docker build -t mirage-qwen-agent:v1 -f build/m44-qwen-agent/Dockerfile .
QWEN_IMAGE="$(docker image inspect --format '{{index .RepoDigests 0}}' mirage-qwen-agent:v1)"
HELPER_IMAGE="busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0"
mkdir -p "$HOME/.cache/mirage"
DEMO_ROOT="$(mktemp -d "$HOME/.cache/mirage/qwen-v1.XXXXXX")"
mkdir -p "$DEMO_ROOT/authorized" "$DEMO_ROOT/rejected"
cp README.md "$DEMO_ROOT/authorized/README.md"
cp README.md "$DEMO_ROOT/rejected/README.md"
cp README.md "$DEMO_ROOT/rejected/protected.txt"
```

Authorized run—Qwen edits the one contract-authorized file:

```bash
mirage run agent \
  --agent qwen \
  --workspace "$DEMO_ROOT/authorized" \
  --image "$QWEN_IMAGE" \
  --helper-image "$HELPER_IMAGE" \
  --allow /workspace/README.md \
  --model-broker ollama \
  --model qwen2.5-coder:1.5b \
  --output-dir "$DEMO_ROOT/evidence-authorized" \
  -- /usr/local/bin/mirage-qwen-agent \
  "Append one short verification line to README.md."
```

Expected terminal path:

```text
Qwen edit → FROZEN → mutations=1 → VERIFIED → COMMITTED → receipt VALID
```

Rejected run—the contract authorizes `protected.txt`, while the model is asked
to edit `README.md`:

```bash
mirage run agent \
  --agent qwen \
  --workspace "$DEMO_ROOT/rejected" \
  --image "$QWEN_IMAGE" \
  --helper-image "$HELPER_IMAGE" \
  --allow /workspace/protected.txt \
  --model-broker ollama \
  --model qwen2.5-coder:1.5b \
  --output-dir "$DEMO_ROOT/evidence-rejected" \
  -- /usr/local/bin/mirage-qwen-agent \
  "Append one short verification line to README.md."
```

This command intentionally exits nonzero after persisting verified rejection
evidence. Expected terminal path:

```text
Qwen edit → FROZEN → filesystem.default_deny → REJECTED
→ committed=0 → real workspace unchanged → receipt VALID
```

Exact receipt and Observatory paths are printed by both commands. See
[the local Qwen guide](docs/qwen-local-agent.md) for the security and evidence
semantics.

## Evidence and Observatory

Receipts bind run and contract identity, trusted time, effect accounting,
observed and committed mutations, verification/commit plans, the Effect Graph,
and their own SHA-256 identity. Receipt v1 covers the deterministic competition
flow; receipt v2 honestly represents committed and rejected real-agent runs.

The Observatory verifies a receipt before rendering it. It is self-contained,
escapes receipt-controlled strings, uses a restrictive CSP, performs no network
requests, and has no authority role. Its small CSP-hash-bound script is only
progressive enhancement over pre-rendered evidence.

## Trust model and limitations

The agent, model output, prompt, repository contents, and disposable workspace
are untrusted. The host control plane, OS kernel, rootless Docker daemon, MIRAGE
binary, contract issuer, and trusted clock are trusted.

MIRAGE v1 intentionally does **not** provide:

- general multi-file transactions, create/delete/mode-change commits, links,
  or special-object commits;
- a general shell-capable Qwen agent or extensible tool framework;
- complete ACL/xattr/ownership preservation;
- crash-durable evidence or intent recovery;
- guaranteed evidence persistence if the process crashes after a successful
  real commit;
- the M5.4 exact GitHub pull-request effect;
- a complete signed/hash-chained durable audit log;
- universal syscall monitoring or syscall-perfect observation.

Final-state reconciliation is authoritative within the documented trusted-host
model, but a narrow final revalidation-to-replacement race against a
non-cooperating host process remains. Action logs describe the constrained
agent tool boundary; they are not universal syscall evidence and never grant
commit authority.

## Repository map

- `internal/contracts`: canonical effect contracts and authorization
- `internal/runtime/docker`: rootless hostile-process containment
- `internal/runtime/tree` and `reconcile`: frozen final-state observation
- `internal/runtime/realcommit`: narrow trusted real-world commit
- `internal/runtime/qwenagent`: constrained untrusted local-model driver
- `internal/runtime/modelbroker`: trusted host-side provider boundary
- `internal/effectgraph`: deterministic causal evidence
- `internal/receipt`: receipt construction and verification
- `internal/observatory`: read-only evidence visualization
- `cmd/mirage`: product CLI

Detailed guarantees, designs, and operator instructions live in [`docs/`](docs/).
