# Competition demo operator guide

This guide runs the reliable deterministic presentation path. It performs no GitHub mutation and requires no API key or model provider.

## Setup

Use a Linux host or WSL2 distribution with the rootless Docker service active. Confirm the effective daemon reports `rootless`, built-in `seccomp`, cgroup v2, and the `systemd` cgroup driver.

The demo image must already be present and addressed by digest. The tested local fixture is:

```text
busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0
```

Do not replace the digest with a mutable tag for a judged run.

```bash
export DOCKER_HOST="unix:///run/user/$(id -u)/docker.sock"
export MIRAGE_DEMO_IMAGE='busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0'
go build -o ./bin/mirage ./cmd/mirage
```

## Malicious scenario

```bash
./bin/mirage demo malicious
```

Expected terminal accounting:

```text
Agent attempted 4 effects. MIRAGE authorized 1, denied 3, and committed 1.
```

Copy the printed `receipt_file`, `observatory`, and `real_workspace` paths. Check the receipt immediately:

```bash
./bin/mirage receipt verify <receipt_file>
```

The verified real workspace must contain the original protected `.env` and the committed `README.md`, with no other entry. Do not print the `.env` contents during a presentation.

## Benign scenario

```bash
./bin/mirage demo benign
```

Expected terminal accounting:

```text
Agent attempted 1 effects. MIRAGE authorized 1, denied 0, and committed 1.
```

This uses the same quota, sandbox, freeze, scan, verification, and trusted commit path as the malicious scenario.

## Evidence semantics

The official fixture is trusted test input executed as an untrusted process. Its strict, bounded probe records establish that each probe ran and observed a denial. Those records are rejected if missing, reordered, truncated, malformed, or reporting a breach.

The failed HTTP request is not, by itself, proof of network containment. The trusted launcher's mandatory and inspected Docker `network=none` configuration is the enforcement evidence; the probe is presentation evidence of what this run observed and does not require Internet availability.

They remain non-authoritative. MIRAGE grants commit authority only after the independently frozen final-tree scan produces exactly one existing-file content modification authorized by the contract.

## Optional local model

A local model can generate an optional agent workload behind the existing sandbox/broker boundary. It must not replace the deterministic fixture as the reliable judged path unless it proves equally repeatable. Model output must never decide authorization, verification, commit, graph validity, or receipt validity.

The host currently has Ollama with `qwen2.5-coder:1.5b`. That runtime is not exposed to the WSL rootless-sandbox path and MIRAGE does not yet have a narrow Ollama broker. The deterministic path therefore remains the official demo and requires no model download or paid API. Integrating the installed model is optional follow-up work, not a reason to weaken the sandbox or give it host network access.

## Failure posture

If preparation, process stop proof, workspace export, scan, verification, freshness, authority, commit, or cleanup becomes uncertain, stop the demonstration and report the exact failure. Never rerun an external publication effect as part of this local demo. This scenario has no external publication capability.
