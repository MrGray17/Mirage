package contracts_test

import (
	"errors"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
)

func TestContractIsImmutableAndCanonical(t *testing.T) {
	expires := time.Date(2026, 8, 26, 15, 0, 0, 123, time.FixedZone("test", 60*60))
	spec := contracts.Spec{
		Version:   contracts.VersionV1,
		RunID:     " run-17 ",
		ActorID:   " coding-agent-17 ",
		ExpiresAt: expires,
		Filesystem: contracts.FilesystemPolicy{
			Read: contracts.AccessRules{
				Allow: []string{"/workspace/README.md", "/workspace/docs/install.md"},
				Deny:  []string{"/workspace/.env"},
			},
			Write: contracts.AccessRules{Allow: []string{"/workspace/README.md"}},
		},
	}
	contract, err := contracts.New(spec)
	if err != nil {
		t.Fatalf("new contract: %v", err)
	}

	reordered, err := contracts.New(contracts.Spec{
		Version:   contracts.VersionV1,
		RunID:     "run-17",
		ActorID:   "coding-agent-17",
		ExpiresAt: expires.UTC(),
		Filesystem: contracts.FilesystemPolicy{
			Read: contracts.AccessRules{
				Allow: []string{"/workspace/docs/install.md", "/workspace/README.md"},
				Deny:  []string{"/workspace/.env"},
			},
			Write: contracts.AccessRules{Allow: []string{"/workspace/README.md"}},
		},
	})
	if err != nil {
		t.Fatalf("new reordered contract: %v", err)
	}
	if contract.Hash() != reordered.Hash() {
		t.Fatalf("canonical hashes differ: %s != %s", contract.Hash(), reordered.Hash())
	}
	if contract.Hash() != "sha256:a52d1d7cd8719a521fe7e5c96a1059c0daad0e8f63f696fb1fc6ae6717fd5a13" {
		t.Fatalf("v1 canonical hash changed: %s", contract.Hash())
	}
	if contract.RunID() != "run-17" || contract.ActorID() != "coding-agent-17" {
		t.Fatalf("identity = %q/%q", contract.RunID(), contract.ActorID())
	}
	if !contract.ExpiresAt().Equal(expires) || contract.ExpiresAt().Location() != time.UTC {
		t.Fatalf("expiry = %s, want equivalent UTC instant", contract.ExpiresAt())
	}

	// Mutating construction input cannot add authority or change the hash.
	originalHash := contract.Hash()
	spec.Filesystem.Read.Allow[0] = "/workspace/.env"
	spec.Filesystem.Write.Allow = append(spec.Filesystem.Write.Allow, "/workspace/.github/workflows/deploy.yml")
	if contract.Hash() != originalHash {
		t.Fatal("contract hash changed after construction input mutation")
	}
	decision := contract.EvaluateFilesystem(contracts.FilesystemRead, "/workspace/.env", expires.Add(-time.Minute))
	if decision.Allowed || decision.RuleID != "filesystem.explicit_deny" {
		t.Fatalf("decision = %+v, want explicit deny", decision)
	}
}

func TestContractV2AuthorizesOnlyExactGitHubCreateBranch(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	target := "refs/heads/mirage/run-bf9f6cfdef1dd1c62bf3afa7"
	contract, err := contracts.New(contracts.Spec{
		Version: contracts.VersionV2, RunID: "m52-artifact", ActorID: "agent", ExpiresAt: now.Add(time.Hour),
		Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{Allow: []string{"/workspace/README.md"}}},
		GitHub:     contracts.GitHubPublicationPolicy{RepositoryFullName: "MrGray17/Mirage-Test", TargetRef: target, Operation: contracts.GitHubCreateBranch},
	})
	if err != nil {
		t.Fatal(err)
	}
	if contract.Version() != contracts.VersionV2 || contract.GitHubPublication().RepositoryFullName != "mrgray17/mirage-test" {
		t.Fatalf("canonical v2 policy = %#v", contract.GitHubPublication())
	}
	if contract.Hash() != "sha256:fd907f9ea01f55e5e30ebf1dc8bacc0a936b64f7e27d3afdfe6e4c326aaad1fd" {
		t.Fatalf("v2 canonical hash changed: %s", contract.Hash())
	}
	allowed := contract.EvaluateGitHubPublication(contracts.GitHubCreateBranch, "MRGRAY17/MIRAGE-TEST", target, now)
	if !allowed.Allowed || allowed.RuleID != "github.exact_create_branch" {
		t.Fatalf("allowed = %#v", allowed)
	}
	for name, decision := range map[string]contracts.Decision{
		"wrong repository": contract.EvaluateGitHubPublication(contracts.GitHubCreateBranch, "mrgray17/other", target, now),
		"wrong ref":        contract.EvaluateGitHubPublication(contracts.GitHubCreateBranch, "mrgray17/mirage-test", "refs/heads/main", now),
		"update":           contract.EvaluateGitHubPublication("UPDATE_BRANCH", "mrgray17/mirage-test", target, now),
		"delete":           contract.EvaluateGitHubPublication("DELETE_BRANCH", "mrgray17/mirage-test", target, now),
		"tag":              contract.EvaluateGitHubPublication("CREATE_TAG", "mrgray17/mirage-test", target, now),
	} {
		if decision.Allowed {
			t.Fatalf("%s unexpectedly allowed: %#v", name, decision)
		}
	}
	v1 := newContract(t, now.Add(time.Hour), contracts.FilesystemPolicy{})
	if decision := v1.EvaluateGitHubPublication(contracts.GitHubCreateBranch, "mrgray17/mirage-test", target, now); decision.Allowed || decision.RuleID != "github.version_default_deny" {
		t.Fatalf("v1 publication = %#v", decision)
	}
	for name, earlier := range map[string]*contracts.Contract{"v1": v1, "v2": contract} {
		decision := earlier.EvaluateGitHubPullRequest(contracts.GitHubCreatePullRequest, "mrgray17/mirage-test", "refs/heads/main", target, contracts.PullRequestMetadataV1, now)
		if decision.Allowed || decision.RuleID != "github_pr.version_default_deny" {
			t.Fatalf("%s pull request = %#v", name, decision)
		}
	}
}

func TestContractV3CanonicalAuthorityAndExactEvaluation(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	target := "refs/heads/mirage/run-bf9f6cfdef1dd1c62bf3afa7"
	spec := contracts.Spec{
		Version: contracts.VersionV3, RunID: "m52-artifact", ActorID: "agent", ExpiresAt: now.Add(time.Hour),
		Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{Allow: []string{"/workspace/README.md"}}},
		GitHubV3: contracts.GitHubEffectsPolicy{
			RepositoryFullName: "MrGray17/Mirage-Test",
			Branch:             contracts.GitHubBranchPolicy{TargetRef: target, Operation: contracts.GitHubCreateBranch},
			PullRequest: contracts.GitHubPullRequestPolicy{
				BaseRef: "refs/heads/main", TargetRef: target,
				Operation: contracts.GitHubCreatePullRequest, MetadataPolicy: contracts.PullRequestMetadataV1,
			},
		},
	}
	contract, err := contracts.New(spec)
	if err != nil {
		t.Fatal(err)
	}
	if contract.Hash() != "sha256:28b1cdd5ac340a687a11452ee12e5628db6a89ba5ec9c6e558a5f13fd9be1651" {
		t.Fatalf("v3 canonical hash changed: %s", contract.Hash())
	}
	reordered := spec
	reordered.RunID = " m52-artifact "
	reordered.ActorID = " agent "
	reordered.ExpiresAt = spec.ExpiresAt.In(time.FixedZone("other", 2*60*60))
	reordered.Filesystem.Write.Allow = []string{"/workspace/README.md", "/workspace/README.md"}
	reorderedContract, err := contracts.New(reordered)
	if err != nil || reorderedContract.Hash() != contract.Hash() {
		t.Fatalf("v3 deterministic canonicalization: hash=%v err=%v", reorderedContract, err)
	}
	branch := contract.GitHubPublication()
	pr := contract.GitHubPullRequest()
	if branch.RepositoryFullName != "mrgray17/mirage-test" || branch.TargetRef != target || pr.BaseRef != "refs/heads/main" || pr.TargetRef != target || pr.MetadataPolicy != contracts.PullRequestMetadataV1 {
		t.Fatalf("canonical v3 policies branch=%#v pr=%#v", branch, pr)
	}
	if decision := contract.EvaluateGitHubPublication(contracts.GitHubCreateBranch, "MRGRAY17/MIRAGE-TEST", target, now); !decision.Allowed {
		t.Fatalf("v3 branch denied: %#v", decision)
	}
	if decision := contract.EvaluateGitHubPullRequest(contracts.GitHubCreatePullRequest, "MRGRAY17/MIRAGE-TEST", "refs/heads/main", target, contracts.PullRequestMetadataV1, now); !decision.Allowed || decision.RuleID != "github_pr.exact_create" {
		t.Fatalf("v3 PR denied: %#v", decision)
	}

	for name, decision := range map[string]contracts.Decision{
		"unknown operation": contract.EvaluateGitHubPullRequest("UPDATE_PULL_REQUEST", "mrgray17/mirage-test", "refs/heads/main", target, contracts.PullRequestMetadataV1, now),
		"wrong repository":  contract.EvaluateGitHubPullRequest(contracts.GitHubCreatePullRequest, "mrgray17/other", "refs/heads/main", target, contracts.PullRequestMetadataV1, now),
		"wrong base":        contract.EvaluateGitHubPullRequest(contracts.GitHubCreatePullRequest, "mrgray17/mirage-test", "refs/heads/release", target, contracts.PullRequestMetadataV1, now),
		"wrong head":        contract.EvaluateGitHubPullRequest(contracts.GitHubCreatePullRequest, "mrgray17/mirage-test", "refs/heads/main", target+"x", contracts.PullRequestMetadataV1, now),
		"wrong metadata":    contract.EvaluateGitHubPullRequest(contracts.GitHubCreatePullRequest, "mrgray17/mirage-test", "refs/heads/main", target, "agent-owned", now),
	} {
		if decision.Allowed {
			t.Fatalf("%s unexpectedly allowed: %#v", name, decision)
		}
	}

	// Construction inputs are copied; mutation cannot widen the contract.
	spec.GitHubV3.PullRequest.BaseRef = "refs/heads/release"
	if contract.GitHubPullRequest().BaseRef != "refs/heads/main" || contract.Hash() == "" {
		t.Fatal("v3 contract changed after construction input mutation")
	}
}

func TestContractV3RejectsMalformedOrAmbiguousAuthority(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	target := "refs/heads/mirage/run-bf9f6cfdef1dd1c62bf3afa7"
	valid := contracts.Spec{
		Version: contracts.VersionV3, RunID: "m52-artifact", ActorID: "agent", ExpiresAt: now.Add(time.Hour),
		GitHubV3: contracts.GitHubEffectsPolicy{
			RepositoryFullName: "owner/repo",
			Branch:             contracts.GitHubBranchPolicy{TargetRef: target, Operation: contracts.GitHubCreateBranch},
			PullRequest:        contracts.GitHubPullRequestPolicy{BaseRef: "refs/heads/main", TargetRef: target, Operation: contracts.GitHubCreatePullRequest, MetadataPolicy: contracts.PullRequestMetadataV1},
		},
	}
	tests := map[string]func(*contracts.Spec){
		"unknown branch operation": func(spec *contracts.Spec) { spec.GitHubV3.Branch.Operation = "UPDATE_BRANCH" },
		"unknown PR operation":     func(spec *contracts.Spec) { spec.GitHubV3.PullRequest.Operation = "MERGE_PULL_REQUEST" },
		"malformed base ref":       func(spec *contracts.Spec) { spec.GitHubV3.PullRequest.BaseRef = "main" },
		"tag base ref":             func(spec *contracts.Spec) { spec.GitHubV3.PullRequest.BaseRef = "refs/tags/main" },
		"unsafe base ref":          func(spec *contracts.Spec) { spec.GitHubV3.PullRequest.BaseRef = "refs/heads/a..b" },
		"mismatched target":        func(spec *contracts.Spec) { spec.GitHubV3.PullRequest.TargetRef += "x" },
		"same base and target":     func(spec *contracts.Spec) { spec.GitHubV3.PullRequest.BaseRef = target },
		"unknown metadata":         func(spec *contracts.Spec) { spec.GitHubV3.PullRequest.MetadataPolicy = "mirage.pr-metadata/v2" },
		"duplicate legacy policy": func(spec *contracts.Spec) {
			spec.GitHub = contracts.GitHubPublicationPolicy{RepositoryFullName: "owner/repo", TargetRef: target, Operation: contracts.GitHubCreateBranch}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			spec := valid
			mutate(&spec)
			if _, err := contracts.New(spec); !errors.Is(err, contracts.ErrInvalidContract) {
				t.Fatalf("error=%v, want ErrInvalidContract", err)
			}
		})
	}

	v2 := contracts.Spec{Version: contracts.VersionV2, RunID: "m52-artifact", ActorID: "agent", ExpiresAt: now.Add(time.Hour), GitHub: contracts.GitHubPublicationPolicy{RepositoryFullName: "owner/repo", TargetRef: target, Operation: contracts.GitHubCreateBranch}, GitHubV3: valid.GitHubV3}
	if _, err := contracts.New(v2); !errors.Is(err, contracts.ErrInvalidContract) {
		t.Fatalf("v2 accepted duplicate v3 policy: %v", err)
	}
}

func TestContractV2RejectsUntrustedGitHubDestinationForms(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	target := "refs/heads/mirage/run-bf9f6cfdef1dd1c62bf3afa7"
	for _, repository := range []string{"https://github.com/o/r", "git@github.com:o/r", "o/r/extra", "o/../r", "user@example.com/r", "o/r?x=1", "o/r#x", "o/r\x00", "/r", "o/"} {
		_, err := contracts.New(contracts.Spec{Version: contracts.VersionV2, RunID: "m52-artifact", ActorID: "agent", ExpiresAt: now.Add(time.Hour), GitHub: contracts.GitHubPublicationPolicy{RepositoryFullName: repository, TargetRef: target, Operation: contracts.GitHubCreateBranch}})
		if !errors.Is(err, contracts.ErrInvalidContract) {
			t.Fatalf("repository %q error = %v", repository, err)
		}
	}
	for _, targetRef := range []string{"refs/heads/main", "refs/tags/x", target + "x", "refs/heads/mirage/run-../../main"} {
		_, err := contracts.New(contracts.Spec{Version: contracts.VersionV2, RunID: "m52-artifact", ActorID: "agent", ExpiresAt: now.Add(time.Hour), GitHub: contracts.GitHubPublicationPolicy{RepositoryFullName: "owner/repo", TargetRef: targetRef, Operation: contracts.GitHubCreateBranch}})
		if !errors.Is(err, contracts.ErrInvalidContract) {
			t.Fatalf("target %q error = %v", targetRef, err)
		}
	}
}

func TestContractDenyOverridesAllowAndDefaultsClosed(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	contract := newContract(t, now.Add(time.Hour), contracts.FilesystemPolicy{
		Read: contracts.AccessRules{
			Allow: []string{"/workspace/README.md"},
			Deny:  []string{"/workspace/README.md"},
		},
	})

	denied := contract.EvaluateFilesystem(contracts.FilesystemRead, "/workspace/README.md", now)
	if denied.Allowed || denied.RuleID != "filesystem.explicit_deny" {
		t.Fatalf("deny override = %+v", denied)
	}
	defaultDenied := contract.EvaluateFilesystem(contracts.FilesystemWrite, "/workspace/README.md", now)
	if defaultDenied.Allowed || defaultDenied.RuleID != "filesystem.default_deny" {
		t.Fatalf("default decision = %+v", defaultDenied)
	}
	expired := contract.EvaluateFilesystem(contracts.FilesystemRead, "/workspace/README.md", now.Add(time.Hour))
	if expired.Allowed || expired.RuleID != "contract.expired" {
		t.Fatalf("expired decision = %+v", expired)
	}
	invalidTime := contract.EvaluateFilesystem(contracts.FilesystemRead, "/workspace/README.md", time.Time{})
	if invalidTime.Allowed || invalidTime.RuleID != "contract.invalid_time" {
		t.Fatalf("zero-time decision = %+v", invalidTime)
	}
}

func TestMalformedContractFailsClosed(t *testing.T) {
	valid := contracts.Spec{
		Version:   contracts.VersionV1,
		RunID:     "run-1",
		ActorID:   "agent-1",
		ExpiresAt: time.Date(2026, 8, 26, 13, 0, 0, 0, time.UTC),
	}
	tests := map[string]func(*contracts.Spec){
		"unknown version":       func(spec *contracts.Spec) { spec.Version = "mirage.contract/v2" },
		"missing run":           func(spec *contracts.Spec) { spec.RunID = "" },
		"missing actor":         func(spec *contracts.Spec) { spec.ActorID = "" },
		"missing expiry":        func(spec *contracts.Spec) { spec.ExpiresAt = time.Time{} },
		"noncanonical resource": func(spec *contracts.Spec) { spec.Filesystem.Read.Allow = []string{"README.md"} },
		"traversal resource":    func(spec *contracts.Spec) { spec.Filesystem.Read.Allow = []string{"/workspace/../.env"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			spec := valid
			mutate(&spec)
			if _, err := contracts.New(spec); !errors.Is(err, contracts.ErrInvalidContract) {
				t.Fatalf("error = %v, want ErrInvalidContract", err)
			}
		})
	}
}

func newContract(t *testing.T, expires time.Time, filesystem contracts.FilesystemPolicy) *contracts.Contract {
	t.Helper()
	contract, err := contracts.New(contracts.Spec{
		Version:    contracts.VersionV1,
		RunID:      "run-1",
		ActorID:    "agent-1",
		ExpiresAt:  expires,
		Filesystem: filesystem,
	})
	if err != nil {
		t.Fatalf("new contract: %v", err)
	}
	return contract
}
