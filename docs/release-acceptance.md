# MIRAGE release acceptance

The normal CI workflow checks formatting, static analysis, race-enabled tests, and Windows/Linux builds. It does not run the opt-in rootless-Docker integration tests, because those require a prepared Linux environment and digest-pinned images.

Use this release gate on the Linux filesystem inside WSL2 or on a Linux host that has the supported **rootless Docker** configuration. The script runs the ordinary checks first, then explicitly enables the M4.2 hostile fixtures, M4.4 coding-agent/broker checks, and the real-runtime demo acceptance tests.

## Prepare the environment

1. Install Go 1.27.3 or newer.
2. Configure rootless Docker with cgroup v2, the systemd cgroup driver, delegated resource controllers, and built-in seccomp.
3. Build or pull the required fixture/agent images using the reviewed project instructions. Use immutable image digests, never floating tags. Each image must already be present locally before running the gate.
4. From a clean checkout of the exact commit intended for release, set these environment variables to the corresponding locally available digest-pinned images:

   - MIRAGE_HOSTILE_IMAGE
   - MIRAGE_AGENT_IMAGE (optional; defaults to MIRAGE_HOSTILE_IMAGE)
   - MIRAGE_CODEX_IMAGE
   - MIRAGE_HELPER_IMAGE
   - MIRAGE_DEMO_IMAGE

Each image reference must end in @sha256: followed by 64 lowercase hexadecimal characters. The script validates the references and uses docker image inspect to verify that each image is present. It does not pull images or change Docker configuration.

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
