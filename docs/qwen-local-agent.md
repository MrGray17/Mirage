# Local Qwen structured agent

MIRAGE includes a deliberately narrow local-model agent for validating
`qwen2.5-coder:1.5b` through Ollama. It is separate from the Codex agent and
does not change filesystem authorization or commit semantics.

The agent image contains one static binary in a scratch filesystem. It has no
shell, package manager, Git client, network client, or subprocess tool. The
only model actions are a bounded sequence:

```text
list_files
→ read_file (one rooted regular file)
→ patch_file (append to that same rooted file)
→ finish
```

Qwen chooses the file and appended text. The driver applies those choices only
inside `/workspace`. Go's rooted filesystem API rejects absolute paths,
traversal, and symlink escapes. `.env` and `.git` are unavailable through the
driver, file and transcript sizes are bounded, and malformed or repeated
actions fail closed.

This sequence is intentionally not a general coding environment. It is the
smallest reproducible agent loop needed to demonstrate a real local model edit.
MIRAGE's trusted frozen-tree scan, canonical diff, contract verifier, freshness
checks, and real commit engine remain the only authority over reality.

## Build

Build the image from the repository root. The builder base is pinned by digest
and the final image is scratch-based:

```bash
docker build -t mirage-qwen-agent:validation \
  -f build/m44-qwen-agent/Dockerfile .
docker image inspect mirage-qwen-agent:validation
```

Use the resulting `RepoDigests` value as `--image`; an unpinned tag is rejected
by the existing agent launcher.

## Run

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
  -- /usr/local/bin/mirage-qwen-agent \
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

Evidence persistence is deliberately not crash-durable in this milestone. A
successful real commit followed by an evidence I/O failure remains a committed
run whose CLI returns an error after already reporting `runtime=COMMITTED`; it
is never retried or represented as an unchanged reality. Durable journaling and
recovery belong to M6.
