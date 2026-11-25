# Use Mirage from any coding-agent harness

Mirage exposes a local Model Context Protocol server over stdio. It uses the
same installed `mirage` executable and the same Windows-to-WSL security backend
as the interactive CLI. No provider credentials are passed to the server or
the Qwen sandbox.

## Prerequisites

Install Mirage, run `mirage setup`, start Ollama, and install the local model:

```text
mirage setup
ollama pull qwen2.5-coder:1.5b
mirage doctor
```

`mirage doctor` must report both `READY` and `EDIT READY`.

## Connect a harness

Any MCP client can start Mirage with this stdio command:

```text
mirage mcp
```

Common CLI registrations are:

```text
claude mcp add --transport stdio --scope user mirage -- mirage mcp
codex mcp add mirage -- mirage mcp
opencode mcp add mirage --global -- mirage mcp
```

Checked-in configuration examples are available under `integrations/`. A
portable Agent Plugins package for Codex-compatible clients is under
`integrations/agent-plugin/`, and a native Claude Code plugin package is under
`integrations/claude-plugin/`. OpenCode uses its native MCP configuration in
`integrations/opencode.jsonc`; no JavaScript shim is needed.

## Tools

### `mirage_doctor`

Read-only readiness check. Require `edit_ready: true` before editing.

### `mirage_edit_file`

Edits exactly one existing regular file. Inputs are `file`, `task`, optional
`workspace`, optional `output_dir`, and `approved`. The caller must set
`approved: true` only after the user authorized that exact file and task.

The tool returns a structured `mirage.agent-run/v2` result. A successful result
contains `outcome: COMMITTED`, `receipt_valid: true`, the receipt identity, and
paths to the receipt and verified Observatory.

### `mirage_verify_receipt`

Read-only independent verification of one receipt path.

## Security boundary

MCP is an invocation protocol, not the security boundary. Tool annotations help
clients present approvals, but Mirage does not trust them for enforcement.
Mirage validates the exact target, snapshots the project, runs local Qwen in a
rootless network-disabled sandbox, freezes the process tree, reconciles actual
filesystem effects, and commits only the one authorized content change.

The MCP server cannot transparently intercept a harness's separate built-in
write tools. To obtain Mirage guarantees, configure or instruct the harness to
use `mirage_edit_file` for the edit. Running a complete third-party CLI inside
Mirage remains the advanced `mirage run agent` path and requires a separately
built, digest-pinned, acceptance-tested agent image.

A verified policy rejection returns a structured `REJECTED` result over MCP, even though the direct CLI uses a nonzero exit. `COMMITTED_INCOMPLETE` means a real file replacement succeeded but a subsequent operation failed; inspect reality and evidence before retrying. The MCP `approved` field is a caller assertion, not independent proof of human consent. Only connect trusted harnesses that enforce explicit user approval.

Native Linux MCP edits propagate request cancellation to the runtime, preserve independent cleanup deadlines, and check cancellation before the final file replacement. A cancellation after replacement cannot undo it. Windows/WSL still requires a cooperative backend cancellation protocol; the frontend does not kill a mutating backend merely because the MCP request was canceled. Read-only WSL probes have bounded deadlines.
