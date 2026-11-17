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

## Install or upgrade MIRAGE v1

MIRAGE installs from a Git checkout and embeds the checkout's complete commit
identity in the binary. Install only from the commit you intend to run, and
verify the reported identity afterward.

**Release status:** the published [`v1.0.0` release](https://github.com/MrGray17/Mirage/releases/tag/v1.0.0)
predates the installer and security hardening on `main` and has no downloadable
binary assets. Source installs from `main` are deliberately labeled
`1.0.0-dev` and embed the exact 40-character source commit. They contain
post-`v1.0.0` changes, but are not a new stable release. The follow-up stable
release should wait for the documented rootless-Docker live gate and real
Windows/WSL install/upgrade acceptance to pass.

### Windows 11 with WSL2

Prerequisites:

- Git and Go 1.27.3 or newer on Windows;
- WSL2 with an Ubuntu distribution;
- rootless Docker inside Ubuntu, using cgroup v2, the `systemd` cgroup driver,
  delegated CPU/memory/PID controllers, and built-in seccomp.

From PowerShell in the repository root:

```powershell
git status --short
git pull --ff-only
.\scripts\install.ps1 -Distribution Ubuntu
```

`git status --short` should print nothing. The installer builds a native
Windows frontend and a Linux backend from the same source commit, installs them
under `%LOCALAPPDATA%\Mirage` and the selected WSL user's home, and records the
backend path in `%LOCALAPPDATA%\Mirage\config.json`. It does not install or
reconfigure WSL, Docker, Go, Git, or Ollama.

Open a new PowerShell window so the user PATH refreshes, then verify the exact
frontend/backend pair and prepare the pinned demo image:

```powershell
mirage version
mirage setup
mirage doctor
```

`mirage version` must report `mirage 1.0.0-dev`, a full 40-character lowercase Git
commit, bridge protocol 1, and `platform=windows`. `mirage doctor` checks that
the WSL backend has the same version, commit, and bridge protocol and must finish
with `READY`; do not run an agent if it reports `NOT READY`.

To upgrade later, fetch the desired clean source revision and rerun the same
PowerShell installer. Never update only the frontend or only the WSL backend;
the frontend intentionally refuses a mismatched commit identity.

### Native Linux

Prerequisites are Git, Go 1.27.3 or newer, and the same rootless-Docker security
properties listed above. From the repository root:

```bash
git status --short
git pull --ff-only
./scripts/install.sh
export PATH="$HOME/.local/bin:$PATH"
mirage version
mirage setup
mirage doctor
```

The status command should print nothing. `mirage version` must report version
`1.0.0-dev`, the checkout's complete commit identity, and `platform=linux`.

## Quick deterministic demo

After installation and a successful `mirage doctor`, run the malicious fixture:

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

## Quick local edit

After installing MIRAGE, starting Ollama, and making a digest-pinned Qwen image
available to rootless Docker, the normal editing command is intentionally short:

```bash
export MIRAGE_QWEN_IMAGE="ghcr.io/your-namespace/mirage-qwen-agent@sha256:<image-digest>"
mirage edit README.md "Add a concise verification section"
```

MIRAGE uses the current project directory, the local
`qwen2.5-coder:1.5b` model through the trusted Ollama broker, and a pinned
helper image. It shows the exact workspace and target file and asks for
confirmation before launching. Use `--yes` only when you deliberately want to
skip that prompt. On Windows, run the same command from PowerShell; the frontend
translates the current Windows directory into the configured WSL distribution.

This first local-agent workflow is deliberately scoped to **one existing
regular file per run**. The file path is the explicit authority boundary:
`mirage edit src/main.go "Add input validation"` cannot authorize changes to
other files. The Qwen driver has no shell, Git, or network tools, and the
sandbox remains network-disabled. Multi-file editing is not part of this v1
command.

Configure `MIRAGE_QWEN_IMAGE` once in your shell environment (or pass
`--image` to an individual command). The image must be referenced by its
immutable `name@sha256:digest`, never a mutable tag. The exact model and helper
image are fixed defaults; there is no silent model fallback.

## Real local-Qwen proof

Ollama must already be installed and serving exactly `qwen2.5-coder:1.5b`.
On Windows, leave Ollama running on Windows; MIRAGE reaches its loopback API
through the trusted WSL interop broker while the agent sandbox remains
`network=none`.

Prepare the model once:

```powershell
ollama pull qwen2.5-coder:1.5b
ollama list
```

From a clean Linux or WSL2 checkout with Go 1.27.3+, rootless Docker, and an
existing GHCR login that can publish to the configured package, run:

```bash
./scripts/test-qwen-local.sh
```

This one-command acceptance performs the full local proof:

1. Checks the rootless Docker environment and exact local Ollama model.
2. Builds the scratch-based Qwen agent from the current clean source commit,
   publishes it, and pulls it back by immutable digest.
3. Uses the easy `mirage edit` CLI to apply a two-operation batch to one
   disposable README, then checks the exact resulting bytes.
4. Attempts a deliberately unauthorized README edit under a contract that
   permits a different file, and verifies both real files remain unchanged.
5. Verifies both the committed and rejected receipts and preserves the run
   summaries, logs, receipts, and Observatory files for inspection.

The script reuses the existing rootless Docker configuration and GHCR login;
it never asks for a token. It prints the immutable `MIRAGE_QWEN_IMAGE` value
at the end. Set that value once in your trusted shell environment:

```bash
export MIRAGE_QWEN_IMAGE='ghcr.io/mrgray17/mirage-qwen-agent@sha256:<digest>'
mirage edit README.md "Add a concise verification section"
```

For PowerShell, persist the same value for future sessions:

```powershell
[Environment]::SetEnvironmentVariable(
  "MIRAGE_QWEN_IMAGE",
  "ghcr.io/mrgray17/mirage-qwen-agent@sha256:<digest>",
  "User"
)
```

The Windows frontend and WSL backend must be installed from the same source
commit. After installing or upgrading with `scripts/install.ps1`, open a new
PowerShell window and run `mirage version` and `mirage doctor`; the latter
must report `READY` before using `mirage edit` from Windows. The local
acceptance script validates the Linux/WSL product path; the final platform
release gate still includes a real PowerShell-to-WSL edit using the installed
frontend/backend pair.

See [the local Qwen guide](docs/qwen-local-agent.md) for detailed protocol,
security, evidence, and troubleshooting information.
 
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

For a full end-to-end explanation of the implementation, security model, lifecycle, evidence, CLI, testing strategy, and current limits, read the [MIRAGE Project Deep Dive](docs/PROJECT_DEEP_DIVE.md). Detailed guarantees, designs, and operator instructions live in [`docs/`](docs/).

The [release acceptance guide](docs/release-acceptance.md) documents the opt-in rootless-Docker integration gate that should pass before cutting a release.
