# MIRAGE release acceptance

The normal CI workflow checks formatting, static analysis, race-enabled tests, and Windows/Linux builds. It does not run the opt-in rootless-Docker integration tests, because those require a prepared Linux environment and digest-pinned images.

Use this release gate on the Linux filesystem inside WSL2 or on a Linux host that has the supported **rootless Docker** configuration. The script runs the ordinary checks first, then explicitly enables the M4.2 hostile fixtures, M4.4 coding-agent/broker checks, and the real-runtime demo acceptance tests.

## Prepare the environment

1. Install Go 1.27.3 or newer.
2. Configure rootless Docker with cgroup v2, the systemd cgroup driver, delegated resource controllers, and built-in seccomp.
3. Pull the reviewed BusyBox fixture image used by the public demo, then use that exact immutable reference for the shell-based fixtures:

       export MIRAGE_HOSTILE_IMAGE='busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0'
       export MIRAGE_AGENT_IMAGE="$MIRAGE_HOSTILE_IMAGE"
       export MIRAGE_HELPER_IMAGE="$MIRAGE_HOSTILE_IMAGE"
       export MIRAGE_DEMO_IMAGE="$MIRAGE_HOSTILE_IMAGE"
       docker pull "$MIRAGE_HOSTILE_IMAGE"

4. The broker socket acceptance test also needs the real Codex agent image, whose entrypoint requires Node.js and the pinned Codex CLI. Build it from the checked-in Dockerfile and push it to a registry you control:

       docker build -t REGISTRY/OWNER/mirage-codex-agent:acceptance -f build/m44-codex-agent/Dockerfile .
       docker push REGISTRY/OWNER/mirage-codex-agent:acceptance

   Copy the immutable manifest digest printed by the push or shown by your registry, then set MIRAGE_CODEX_IMAGE to the full REGISTRY/OWNER/mirage-codex-agent@sha256:DIGEST reference and pull that exact reference:

       export MIRAGE_CODEX_IMAGE='REGISTRY/OWNER/mirage-codex-agent@sha256:DIGEST'
       docker pull "$MIRAGE_CODEX_IMAGE"

   Replace REGISTRY/OWNER and DIGEST with values from your own registry. A local image ID is not a substitute for a repository manifest digest; do not use a mutable tag for the test.

5. From a clean checkout of the exact commit intended for release, run the gate. Each image reference must end in @sha256: followed by 64 lowercase hexadecimal characters. The script validates the references and uses docker image inspect to verify that each image is present. It does not pull images or change Docker configuration.

## Run the gate

    git status --short
    go version
    ./scripts/test-live.sh

Use a clean checkout; git status --short should be empty before running the gate. A pass requires the standard Go checks, mirage doctor, the hostile-process and single-file commit tests, the real coding-agent containment/quota/process-tree tests, the broker socket permission tests, and both real-runtime demo scenarios to finish successfully.

Any missing image, unsupported Docker setup, skipped precondition, failed cleanup, rejected authorized mutation, or unauthorized committed mutation should be treated as a release blocker. Retain the complete terminal output with the tested commit SHA.

## Deliberately separate external-effect checks

The M5.3 live GitHub publication test creates a branch in a **real remote repository**. It is not run by scripts/test-live.sh and must be exercised only against a dedicated disposable test repository using a narrowly scoped token. The test branch is a real external effect and is not automatically deleted by the test.

When explicitly authorized and properly configured, run only that test with:

    MIRAGE_M53_LIVE=1 go test -race -count=1 -v -run '^TestM53LiveGitHubCreateOnlyPublication$' ./internal/runtime

Set MIRAGE_M53_TEST_REPO, MIRAGE_M53_TEST_REPO_ROOT, and MIRAGE_GITHUB_TOKEN first. Do not point it at a production repository. Do not put credentials in source control or paste them into logs.

A live provider-backed coding-agent run is a separate acceptance item because it uses an external service and may incur cost. Run only with a dedicated low-limit test credential and a throwaway workspace after the no-credential runtime gate passes. The gate itself requires no model-provider API key and makes no GitHub writes.
