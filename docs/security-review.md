# MIRAGE security review

**Review date:** 2026-11-17  
**Reviewed code:** the active `feat/qwen-exact-text-replacement` development branch, PR #26  
**Review type:** source-level architecture and regression review. This is not an independent penetration test, formal verification, or security certification.

## Executive assessment

MIRAGE has a coherent security design: an AI agent is treated as an untrusted process, its work is confined to a disposable workspace, and the trusted host makes the commit decision from an independently scanned final state. The model's tool history is evidence about the driver's constrained interface, not authority to change the trusted workspace.

The central invariant is:

```text
CommittedEffects ⊆ AuthorizedEffects
```

The strongest architectural choice is the separation between **attempted actions**, **observed final mutations**, **authorized effects**, and **committed effects**. The runtime does not infer final truth from the agent's narration.

During this hardening pass, I fixed two Qwen evidence/CLI correctness defects and closed gaps in effective Docker configuration validation. The new regression cases are part of the standard race-enabled test suite.

This assessment does not mean the product is risk-free. The remaining limits below are meaningful and should stay visible in release decisions.

## Scope and trust boundaries

### Assets to protect

- The developer's real project files and local Git repository.
- Host credentials, SSH material, provider API keys, GitHub credentials, and the Docker socket.
- The integrity of contract decisions and the trusted commit boundary.
- Remote Git references that Mirage is explicitly authorized to create.
- Execution receipts and the evidence used to explain a run.

### Trusted components

The current threat model trusts the Mirage host process, host OS kernel, rootless Docker daemon and its configuration, the authority/contract issuer, the host clock source, and the trusted broker process that holds provider credentials. The GitHub API is an external service whose responses are checked by the publication workflow.

A compromised host account, kernel, Docker daemon, Mirage binary, or authority issuer is outside this trust model. Hashes in a receipt do not make a compromised host trustworthy.

### Untrusted inputs and actors

The agent executable, model output, prompts, repository contents, disposable workspace contents, and agent-selected tool arguments are untrusted. The threat model includes an agent that:

- Requests paths outside the single authorized target.
- Attempts to read secrets, reach the host home directory, or use the Docker socket.
- Creates symlinks, hardlinks, special objects, extra files, or unexpected metadata.
- Spawns children that outlive its main process or writes after a timeout.
- Exhausts memory, CPU, PIDs, disk quota, output, or protocol budgets.
- Emits malformed, duplicated-key, oversized, repeated, or misleading JSON actions.
- Attempts to exploit ambiguity between model attempts and completed actions.

## Security architecture and expected enforcement

| Boundary | Required property | Main enforcement |
|---|---|---|
| Authority | Permissions are explicit, immutable, canonical, time-bounded, and default-deny | `internal/contracts`, `internal/verifier`, `internal/trustedtime` |
| Model interface | Model output can select only a bounded next action and one host-selected file | `internal/runtime/qwenagent`, `internal/runtime/modelbroker` |
| Process isolation | Agent cannot mount the real project, access the host network, or inherit host credentials | `internal/runtime/docker`, rootless Docker preflight |
| Workspace isolation | Agent changes only a disposable copy; final tree is scanned independently | `internal/runtime/workspace`, `internal/runtime/tree`, `internal/runtime/reconcile` |
| Commit | Real mutation requires a verified plan, freshness revalidation, and narrow commit authority | `internal/runtime/realcommit`, lifecycle coordinator |
| Git publication | Local object construction is separate from one create-only remote branch mutation | `internal/runtime/gitbinding`, `gitcommit`, `gitpublication` |
| Evidence | Receipts describe the run and are verified before display; evidence does not grant authority | `internal/receipt`, `internal/effectgraph`, `internal/observatory` |

The Docker launchers must validate the daemon and the **effective inspected container configuration**, not merely trust the arguments Mirage asked Docker to create. The frozen final tree, not the agent's action log, is the source of observed mutation truth.

## Findings fixed in this hardening pass

### 1. Rejected Qwen attempts broke completed-action evidence

The Qwen driver can return a validation failure to the model, allow a bounded correction, and then execute a valid action. The diagnostic stream therefore contains rejected model attempts and successful actions whose step numbers can have gaps.

The evidence parser previously accepted only successful action lines and treated step numbering as contiguous. A corrected model run could complete the authorized edit and then fail when its action evidence was parsed for the receipt.

**Fix:** the parser now accepts only the exact bounded rejection-diagnostic grammar, enforces strictly increasing model step numbers, omits rejected attempts from the completed-action list, and compacts completed-action sequence numbers. It still requires the exact successful `list_files → read_file → patch_file → finish` sequence and the same target file.

**Regression coverage:** `TestParseCompletedActionsAllowsRejectedAttemptsWithoutCountingThem`, `TestParseCompletedActionsRejectsMalformedRejectedAttemptDiagnostics`, and the retry/evidence integration assertion in the Qwen agent tests.

### 2. Qwen receipts recorded the target flag instead of the user task

The Qwen driver command shape is `mirage-qwen-agent --target <file> <task>`. The evidence builder previously read `command[1]`, which was the literal flag `--target`, rather than the task argument. This made the recorded task inaccurate even though the driver received the correct command.

**Fix:** command validation is centralized in `validateQwenAgentCommand`; it returns the validated task argument, which is used by both receipt and effect-graph evidence construction.

**Regression coverage:** `TestValidateQwenAgentCommandReturnsTaskRatherThanTargetFlag`.

### 3. Effective Docker inspection omitted capability/device expansion fields

The inspected `HostConfig` representation did not parse `CapAdd` or `DeviceRequests`. As a result, the validator could not reject an inspected container with an added Linux capability or a device/GPU request.

**Fix:** the inspection model now parses both fields, and the hostile fixture, coding-agent, and keeper validators reject any capability additions or device/device-request entries.

**Regression coverage:** `TestPrepareRejectsCapabilityDeviceAndConflictingOptionExtensions`, `TestVerifyAgentContainerRejectsCapabilityAndDeviceExtensions`, and `TestVerifySeedContainerRejectsCapabilityAndDeviceExtensions`.

### 4. Security-option and resource-option checks accepted a safe subset with unsafe extras

Several validators checked that required values were present, rather than requiring the complete effective option set to match the intended policy. This could accept conflicting duplicate security options, an extra executable tmpfs permission, an additional tmpfs mount, or extra ulimit entries alongside the expected `nofile` limit.

**Fix:** security options must contain exactly one enabled `no-new-privileges` setting and exactly one `seccomp=builtin` setting. Tmpfs option lists are compared as exact multisets, tmpfs inventory must contain only the expected `/tmp` mount, and the ulimit inventory must contain exactly the configured `nofile` entry. The quota-volume option comparison also rejects duplicate or extra options.

**Regression coverage:** `TestSafeSecurityOptionsRequireExactlyOneEnabledPolicyPair`, `TestSafeTmpfsRejectsExtrasAndDuplicateOptions`, `TestSameOptionSetRejectsDuplicatesAndConflicts`, plus the extended hostile/agent/keeper inspection test cases.

### 5. The new security regression fixture initially did not exercise the mutated response

The first version of the new hostile-launcher regression test mutated a local inspection struct but passed the unmodified secure inspection response to the fake Docker runner. That test could not prove the intended rejection.

**Fix:** the test now replaces the fake runner's actual inspection response with the mutated JSON before calling `Prepare`. The coding-agent and keeper fixtures were also made faithful to the real launcher configuration, including the expected HOME environment, tmpfs, and ulimit settings.

This is a useful test-engineering reminder: a security test must demonstrate that the adversarial input reached the exact code path being asserted.

## Residual risks and release limits

| Risk or limitation | Current position |
|---|---|
| Host-level race after final revalidation and before filesystem replacement | A documented residual race against a non-cooperating host process remains. Do not claim host-wide transactional isolation. |
| Crash durability | No durable intent journal/recovery protocol exists yet. A crash can leave an operationally incomplete result, including a known post-commit evidence-persistence window. |
| Evidence authenticity | Receipt and graph hashes detect many structural changes but are not signatures or independent attestation. A compromised trusted host can recompute hashes. |
| Syscall observation | Agent action logs and broker events are not syscall-perfect telemetry. The final frozen-tree reconciliation is authoritative within the trusted-host model. |
| Filesystem scope | The real commit is intentionally limited to one existing independent regular file's content. It is not a general multi-file transaction engine and does not promise full ACL/xattr/ownership preservation. |
| Local Qwen/WSL2 behavior | The hosted Linux gate is not proof of a provider-backed Ollama/Qwen run on the user's own WSL2 installation. That separate acceptance must be run with the local model and an authorized GHCR package workflow. |
| GitHub remote publication | The M5.3 external branch-creation test is separate and has not been run here. It must use a disposable repository and narrowly scoped credentials, never a production repository. |
| Trusted host | Kernel, rootless Docker daemon, host process, clock source, and contract issuer remain trusted components. This is not a sandbox against a compromised host administrator. |

These limits are part of the security contract, not embarrassing footnotes. Do not describe Mirage as crash-durable, signed, syscall-complete, multi-file transactional, or independently secure against a compromised host.

## Validation evidence

The hardening branch is validated by two distinct gates:

- **Standard CI:** formatting, `go vet ./...`, the full race-enabled `go test -race -count=1 -cover ./...` suite, Linux installer failure-safety checks, pinned Qwen image build, Linux build, and Windows CLI frontend tests/build.
- **Live Linux acceptance:** rootless Docker preflight with cgroup v2/systemd and delegated controllers, immutable fixture images, the real runtime release acceptance gate, evidence transcript upload, and temporary registry cleanup.

The separate local provider-backed Qwen test and the external GitHub publication test are intentionally not implied by these gates. Their prerequisites and commands are documented in [the Qwen agent guide](qwen-local-agent.md), [the release acceptance guide](release-acceptance.md), and [the security regression matrix](security-regression-matrix.md).

## Release checklist

Before describing a release as ready:

1. Require green standard CI and live rootless-Docker acceptance on the exact release commit.
2. Run the provider-backed Qwen acceptance in a disposable local workspace and inspect both the committed and rejected receipts.
3. Run WSL2/PowerShell acceptance using a matching installed Windows frontend and WSL backend.
4. Exercise M5.3 only against a dedicated disposable GitHub repository with least-privilege credentials.
5. Keep the crash-recovery, evidence-authenticity, and final host-race limitations visible in release notes.

A green CI result is necessary evidence, not a blanket security certification.
