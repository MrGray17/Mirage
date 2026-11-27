# Local Qwen structured agent

MIRAGE includes a deliberately narrow local-model agent for validating
`qwen2.5-coder:1.5b` through Ollama. It is separate from the Codex agent and
does not change filesystem authorization or commit semantics.

The agent image contains one static binary in a scratch filesystem. It has no
shell, package manager, Git client, network client, or subprocess tool. The model actions are a bounded sequence. The trusted host passes one
relative `--target` path to the Qwen driver. The model can list and read only
that configured target; the schema does not offer any other workspace path:

```text
list_files (configured target only)
→ read_file (the exact target)
→ patch_file (append, exact search/replace, or bounded edit batch)
→ finish
```

Qwen proposes the edit, but it does not choose which file to inspect. The
driver applies the proposed change only to the preselected target inside
`/workspace`. Every `patch_file` action declares an explicit `mode`:
`append`, `replace`, or `batch`. Those modes have disjoint argument shapes,
and the driver rejects a mode/field mismatch. An action may append, perform one
exact replacement, or apply up to 16 exact replacements to that same file.
Each replacement requires a non-empty literal search string that matches
exactly once in the current UTF-8 content. Missing, duplicate, overlapping, non-UTF-8, and no-op
replacements fail closed; search is not a regular expression. Batch edits run
in order in memory and are written only after every edit succeeds and each
intermediate result remains within the existing write bound. A batch that
returns the file to its original contents is rejected. If a proposed action
fails local protocol validation, it is not executed; the model receives bounded
validation feedback and may try a corrected action within the existing step
limit. Three semantically identical rejected model actions stop the run early;
valid JSON actions are compared canonically so key order and whitespace do not
evade the cutoff. The last validation reason is included in the diagnostic.
This recovery never bypasses validation and does not retry
filesystem execution failures. This all-or-nothing guarantee applies to
validation and size failures; it does not make the underlying filesystem write
crash-atomic.
Append remains available for end-of-file insertions. Go's rooted filesystem operations reject absolute paths, traversal, and
symlink components, including links that resolve elsewhere inside the workspace. `.env` and `.git` are unavailable through the
driver, file and transcript sizes are bounded, and malformed or repeated
actions fail closed.

This sequence is intentionally not a general coding environment. It is a
bounded local coding loop: Qwen can append or make up to 16 exact, unique
replacements in one previously read existing file. Creating files, editing
multiple files, shell access, and arbitrary tool use remain outside this v1
integration's scope.

The fixed CLI limits are 16 model steps, 256 KiB per target-file read, 256 KiB
for the resulting write, 256 KiB per model response, and 512 KiB for the
action/history transcript. A batch is limited to 16 replacement operations.
The trusted host also applies its separate full-project snapshot and
reconciliation budgets; the one-file tool boundary does not replace that
whole-workspace integrity check.
MIRAGE's trusted frozen-tree scan, canonical diff, contract verifier, freshness
checks, and real commit engine remain the only authority over reality.

## Build

Build the image from the repository root. The builder base is pinned by digest
and the final image is scratch-based:

```bash
# Replace this with a repository in a registry you control (use a lowercase namespace).
QWEN_REPO="ghcr.io/your-github-username/mirage-qwen-agent"
QWEN_TAG="validation"
docker build -t "$QWEN_REPO:$QWEN_TAG" -f build/m44-qwen-agent/Dockerfile .
PUSH_OUTPUT="$(docker push "$QWEN_REPO:$QWEN_TAG" 2>&1)" || { printf '%s\n' "$PUSH_OUTPUT" >&2; exit 1; }
printf '%s\n' "$PUSH_OUTPUT"
QWEN_DIGEST="$(printf '%s\n' "$PUSH_OUTPUT" | sed -nE 's/.*[Dd]igest: (sha256:[0-9a-f]{64})([[:space:]].*)?$/\1/p' | tail -n 1)"
if [[ ! "$QWEN_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "Copy the immutable manifest digest from the successful push or registry and set QWEN_DIGEST." >&2
  exit 1
fi
QWEN_IMAGE="$QWEN_REPO@$QWEN_DIGEST"
docker pull "$QWEN_IMAGE"
```

A locally built tag often has no `RepoDigests` entry until it has been pushed or
pulled from a registry. Mirage requires a repository-qualified immutable
`name@sha256:digest` reference, so a plain local tag or image ID is not
accepted. Keep the registry reference private or public according to your
needs, and ensure the rootless Docker user can pull it.

## One-command local acceptance

From a clean Linux or WSL2 checkout, run:

```bash
./scripts/test-qwen-local.sh
```

The script uses the `rootless` Docker context and Buildx builder by default.
It automatically uses `~/.docker-wsl` when that directory exists and no
`DOCKER_CONFIG` is set. Override the context, builder, or registry repository
with `MIRAGE_DOCKER_CONTEXT`, `MIRAGE_DOCKER_BUILDER`, or
`MIRAGE_QWEN_REPO`. It expects an existing GHCR login with package write
permission; it never prompts for or stores a token.

The acceptance script checks the exact local Ollama model, builds and pushes a
commit-specific image without provenance attestations, pulls it back by its
immutable digest, and exercises the **easy CLI** on a disposable workspace.
It then runs a deliberate unauthorized-edit scenario, checks that both trusted
files remain byte-for-byte unchanged, and verifies the committed and rejected
receipts independently. Workspaces, summaries, logs, receipts, and Observatory
files are preserved under temporary directories in your home so failures can
be diagnosed rather than erased.

A successful run prints the image digest and the one-time environment
configuration for Bash and PowerShell. The script tests the Linux/WSL backend;
the final Windows release gate must still install the matching native
frontend/backend pair and repeat the short `mirage edit` workflow from
PowerShell.

## Easy CLI

For normal use, MIRAGE exposes the constrained Qwen workflow as one short
command:

```bash
mirage edit README.md "Add a concise verification section"
```

The command defaults to the current project directory, the pinned BusyBox
helper image, the local `qwen2.5-coder:1.5b` model, and the trusted Ollama
broker. It prints the project, target file, model, and sandbox network posture,
then asks for confirmation. Pass `--yes` to skip the prompt intentionally.
Useful options include `--workspace`, `--image`, `--helper-image`,
`--timeout`, `--format json`, `--output-dir`, and `--open`.

The first positional argument is the one existing regular file the contract
authorizes; the remaining arguments form the task. Paths must be relative to
the workspace, and symbolic links or paths escaping the workspace are refused.
A quick edit exposes one bounded batch of exact replacements to the local
model; append and the more flexible action schema remain available only
through the advanced command.
A single run still cannot create files or edit multiple files. The Qwen agent's
batch mode means multiple exact replacements **within that one file**, not a
multi-file transaction.

The official public Qwen runtime is a digest-pinned built-in default and
`mirage setup` pulls it before the first edit. Advanced users can set
`MIRAGE_QWEN_IMAGE` or pass `--image` per invocation to select a different
trusted build; an override must be an immutable `registry/name@sha256:digest`
reference. On Windows, the native frontend passes an explicit override to WSL
and translates the current Windows directory to its WSL path. No provider
credential is forwarded.

## Advanced Run

Ollama must already be serving the exact installed model on its standard local
endpoint. MIRAGE does not pull models. On native Linux, the trusted broker uses
`127.0.0.1:11434`. Under WSL, it invokes the fixed Windows `curl.exe` through
WSL's `/init` interop launcher to reach the same Windows loopback endpoint.
Proxy settings are not inherited, the endpoint and model are not selectable by
the sandbox, and no API key is used.

```bash
mirage run agent \
  --agent qwen \
  --workspace /trusted/test-workspace \
  --image mirage-qwen-agent@sha256:<built-image-digest> \
  --helper-image busybox@sha256:<approved-helper-digest> \
  --allow /workspace/README.md \
  --model-broker ollama \
  --model qwen2.5-coder:1.5b \
  -- /usr/local/bin/mirage-qwen-agent --target README.md \
  "Append one short verification line to README.md."
```

Successful and contract-rejected `--agent qwen` runs persist a versioned,
self-hashed receipt and a verified Observatory beside it under the MIRAGE run
cache by default. Use `--output-dir` to select a new evidence root, or the
create-only `--evidence-out` and `--observatory-out` paths for explicit files.
Evidence outputs must resolve outside the trusted real workspace; MIRAGE rejects
both direct paths and existing-parent symlink aliases into reality before the
sandbox launches.
`--format json` emits the structured `mirage.agent-run/v2` summary on stdout
while lifecycle progress remains on stderr.

Agent action evidence is deliberately separate from trusted filesystem truth.
The receipt records only the exact bounded `list_files`, `read_file`,
`patch_file`, and `finish` lines emitted after the constrained driver completes
each action. Those records explain what the agent did at its tool boundary;
they do not prove a mutation or grant authority. The frozen-tree scan supplies
observed mutations, reconciliation supplies authorization or rejection, and
only the existing real-commit engine can create a committed mutation record.

Receipt v1 remains the unchanged deterministic competition-demo format.
Real-agent evidence uses `mirage.execution-receipt/v2` because rejected runs
have zero committed mutations and cannot honestly satisfy v1's exactly-one-
commit invariant. A rejected Observatory shows the disposable mutation and
trusted rejection reason without rendering a trust-boundary, commit, or
reality-change stage.

V2 also binds the proven process-tree stop, completed cleanup, exact agent
image and sandbox identities, and a narrowly stated reality result. A committed
run records that the committed resource matched the trusted mutation digest. A
rejected run records that the M4-visible real baseline remained unchanged; it
does not claim observation of excluded host metadata or non-cooperating writes
outside MIRAGE's existing threat model.

The sandbox still runs rootless with `network=none`, a read-only root
filesystem, dropped capabilities, no-new-privileges, a hard workspace quota,
bounded CPU/memory/PIDs/time/output, no Docker socket, no host home or
credentials, and no real-workspace mount.

The local model is untrusted input. Its response and the driver action log are
diagnostic evidence only; neither can authorize verification or commit.

Receipt persistence is not reconstructed after a crash. The single-file commit
path uses a durable metadata journal, while a successful real commit followed
by an evidence I/O failure remains committed and is never retried or represented
as unchanged reality. Recovery classifies journaled target state conservatively
without replaying a mutation.

## Rejected proof

To demonstrate that MIRAGE does not depend on model obedience, prepare a fresh
workspace containing both `README.md` and `protected.txt`. Authorize only:

```text
/workspace/protected.txt
```

Then give the constrained agent a task that explicitly edits `README.md`. Keep
all other arguments identical to the command above, changing only:

```bash
--workspace /trusted/rejected-workspace \
--allow /workspace/protected.txt \
--output-dir /trusted/evidence-rejected \
-- /usr/local/bin/mirage-qwen-agent --target README.md \
"Append one short verification line to README.md."
```

MIRAGE should observe the disposable README mutation, report
`filesystem.default_deny`, persist a valid rejected v2 receipt and Observatory,
and exit nonzero with `committed=0`. Both real files must remain unchanged.
