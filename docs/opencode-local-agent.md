# Local OpenCode compatibility

MIRAGE can run the real OpenCode CLI as an untrusted coding-agent process while
keeping the existing M4.4 isolation and M4.3 single-file commit boundary. This
is a deliberately narrow compatibility slice, not a general OpenCode plugin.

The supported path is fixed to OpenCode `1.18.30` and the already-supported
local `qwen2.5-coder:1.5b` model through MIRAGE's trusted Ollama broker.
OpenCode receives neither an API credential nor the Ollama endpoint. The
pinned OpenCode/Bun process has a fixed 512 MiB cgroup memory ceiling; all
other existing PID, CPU, time, output, and workspace limits remain enforced.
An existing host OpenCode installation is not mounted into the sandbox and is
not part of this trust boundary; the image carries its own pinned copy.

```text
real workspace
    -> bounded disposable snapshot
    -> rootless OpenCode container (network=none)
    -> loopback-to-Unix-socket bridge
    -> trusted MIRAGE Ollama broker
    -> host-side Ollama / qwen2.5-coder:1.5b
    -> constrained in-sandbox README write adapter when the small model emits
       its tool call as structured text instead of a native tool call
    -> freeze and stop complete process tree
    -> authoritative final-tree scan
    -> contract reconciliation
    -> exactly one existing-file MODIFY or rejection
```

## Build the pinned agent image

From the MIRAGE repository root inside Linux or WSL:

```bash
docker build --pull=false \
  -t mirage-opencode-agent:v1 \
  build/m44-opencode-agent

OPENCODE_IMAGE="$(docker image inspect \
  --format '{{index .RepoDigests 0}}' \
  mirage-opencode-agent:v1)"

test -n "$OPENCODE_IMAGE"
printf '%s\n' "$OPENCODE_IMAGE"
```

The image build pins OpenCode `1.18.30` and its Node base image. MIRAGE still
requires the resulting local image reference to include an exact SHA-256
digest and refuses mutable tags at runtime.

The approved helper remains:

```text
busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0
```

## Run OpenCode

Ollama must already be serving exactly `qwen2.5-coder:1.5b` on the trusted
host. MIRAGE does not install or pull the model.

Prepare a bounded workspace with an existing regular `README.md`, then run:

```bash
mkdir -p "$HOME/.cache/mirage"
OPENCODE_ROOT="$(mktemp -d "$HOME/.cache/mirage/opencode.XXXXXX")"
printf '# OpenCode test\n' > "$OPENCODE_ROOT/README.md"
```

```bash
mirage run opencode \
  --workspace "$OPENCODE_ROOT" \
  --allow README.md \
  --task "Replace README.md with exactly: OpenCode edited this file through MIRAGE."
```

Expected trusted terminal path:

```text
RUNNING -> FROZEN -> VERIFIED mutations=1 -> COMMITTED
```

To demonstrate fail-closed behavior with the same real OpenCode process, reset
the test workspace and ask for an unauthorized path while the contract remains
README-only:

```bash
printf '# Protected reality\n' > "$OPENCODE_ROOT/README.md"
"$MIRAGE_BIN" run opencode \
  --workspace "$OPENCODE_ROOT" \
  --allow README.md \
  --task "Create /workspace/forbidden.txt and do not modify README.md."
```

This command must exit nonzero. The adapter rejects the unsupported path before
it can be written; MIRAGE freezes and destroys the sandbox without granting
commit authority, and the real workspace still contains only the original
`README.md`.

OpenCode is configured in the immutable entrypoint to use a broker-local
OpenAI-compatible chat endpoint. Its direct shell, web, external-directory,
subagent, MCP/plugin, LSP-download, sharing, snapshot, and auto-update surfaces
are disabled or denied. These controls reduce noise and attack surface, but
they are not trusted as the security boundary: OpenCode and its configuration
remain untrusted. Rootless containment, no real-workspace mount, process-tree
termination, the frozen final scan, deterministic reconciliation, freshness,
and the trusted commit engine enforce the real boundary.

The installed 1.5B model sometimes emits a valid `write` tool proposal as
structured text rather than using the provider's native tool-call field. The
in-sandbox compatibility adapter accepts exactly one bounded object with the
shape below and rejects every other tool, path, extra field, duplicate, NUL,
or oversized payload:

```json
{"name":"write","arguments":{"filePath":"/workspace/README.md","content":"..."}}
```

That adapter is part of the hostile sandbox, not trusted commit authority. It
can only attempt to change the disposable README. MIRAGE still decides from
the frozen final tree, and the CLI fixes OpenCode authority to exactly
`MODIFY /workspace/README.md`.

## Current evidence limitation

This compatibility path uses MIRAGE's generic hostile-agent lifecycle. It
prints trusted lifecycle and reconciliation facts, but it does not emit the
Qwen-specific v2 receipt or Observatory. Receipt v2 intentionally requires the
constrained Qwen action sequence; pretending arbitrary OpenCode events satisfy
that schema would weaken evidence integrity. A future agent-neutral receipt
version must be designed separately without changing v1/v2 canonical bytes.

OpenCode compatibility also does not authorize GitHub publication. The current
real commit remains exactly one authorized content modification to one existing
regular file. CREATE, DELETE, MODE_CHANGE, links, special files, multi-file
commit, and any final extra mutation are rejected.
