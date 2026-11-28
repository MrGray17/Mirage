# Release and artifact verification

MIRAGE releases are built from `v*` tags by GitHub Actions. Tags containing a
hyphen (for example, `v1.1.0-rc.1`) are published as prereleases. Each release contains
standalone Linux amd64, Linux arm64, and Windows amd64 binaries, a `SHA256SUMS`
file, and a CycloneDX JSON SBOM for each target.

## Verify a downloaded binary

Download the binary and `SHA256SUMS` from the same GitHub release, then verify
the checksum from that directory:

```sh
sha256sum --check SHA256SUMS --ignore-missing
```

Verify its GitHub build-provenance attestation against this repository:

```sh
gh attestation verify ./mirage_1.1.0_linux_amd64 --repo MrGray17/Mirage
```

The attestation proves which GitHub workflow and repository produced the
artifact. It does not make a compromised source tree or workflow trustworthy;
review the referenced commit and workflow when that distinction matters.

## Maintainer process

1. Merge only after the required CI and live acceptance gates pass.
2. Create and push an annotated `vMAJOR.MINOR.PATCH` tag at the accepted commit.
3. Wait for the `release` workflow to finish.
4. Verify one Linux and the Windows artifact from a fresh download using both
   checksum and `gh attestation verify`.
5. Confirm `mirage version --json` reports the tag version and full commit SHA.

The workflow can also be run manually. Manual runs build and attest development
artifacts but intentionally do not publish a GitHub release.
