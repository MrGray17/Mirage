package runtime

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/gitrefs"
	"github.com/MrGray17/Mirage/internal/runtime/githubbinding"
	"github.com/MrGray17/Mirage/internal/runtime/githubpullrequest"
	"github.com/MrGray17/Mirage/internal/runtime/gitpublication"
	"github.com/MrGray17/Mirage/internal/runtime/workspace"
)

// TestM54DisposableGitHubAcceptance is an explicit, credentialed acceptance
// test. It creates one branch and one pull request and never runs in normal CI.
func TestM54DisposableGitHubAcceptance(t *testing.T) {
	if os.Getenv("MIRAGE_M54_ACCEPTANCE") != "1" {
		t.Skip("set MIRAGE_M54_ACCEPTANCE=1 for the disposable-repository acceptance")
	}
	repositoryName := strings.TrimSpace(os.Getenv("MIRAGE_M54_TEST_REPO"))
	repositoryRoot := strings.TrimSpace(os.Getenv("MIRAGE_M54_TEST_REPO_ROOT"))
	token := os.Getenv("MIRAGE_GITHUB_TOKEN")
	if repositoryName == "" || repositoryRoot == "" || token == "" || token != strings.TrimSpace(token) {
		t.Fatal("MIRAGE_M54_TEST_REPO, MIRAGE_M54_TEST_REPO_ROOT, and one explicit host-only token are required")
	}
	canonicalRepository, err := contracts.CanonicalGitHubRepository(repositoryName)
	if err != nil {
		t.Fatal(err)
	}
	real, err := filepath.Abs(repositoryRoot)
	if err != nil || filepath.Clean(real) != real {
		t.Fatalf("invalid disposable repository root: %v", err)
	}
	if status := strings.TrimSpace(runLifecycleGit(t, real, "status", "--porcelain=v1", "--untracked-files=all")); status != "" {
		t.Fatalf("disposable repository must be clean: %q", status)
	}
	before, err := os.ReadFile(filepath.Join(real, "README.md"))
	if err != nil {
		t.Fatal(err)
	}

	readClient, err := githubbinding.NewHTTPClient(token)
	if err != nil {
		t.Fatal(err)
	}
	prClient, err := githubpullrequest.NewHTTPClient(token)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	repository, err := readClient.Repository(ctx, canonicalRepository)
	if err != nil {
		t.Fatal(err)
	}

	disposable, err := workspace.Prepare(real)
	if err != nil {
		t.Fatal(err)
	}
	cleaned := false
	defer func() {
		if !cleaned {
			_ = disposable.Cleanup()
		}
	}()
	binding, err := disposable.Binding()
	if err != nil {
		t.Fatal(err)
	}
	sandbox := &sandboxStub{real: binding.RealWorkspace(), disposable: binding.DisposableWorkspace(), token: binding.Token()}
	runID := fmt.Sprintf("m54-acceptance-%d", time.Now().UTC().UnixNano())
	targetRef := gitrefs.RunTarget(runID)
	now := time.Now().UTC()
	contract, err := contracts.New(contracts.Spec{
		Version: contracts.VersionV3, RunID: runID, ActorID: "m54-disposable-acceptance", ExpiresAt: now.Add(15 * time.Minute),
		Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{Allow: []string{"/workspace/README.md"}}},
		GitHubV3: contracts.GitHubEffectsPolicy{
			RepositoryFullName: canonicalRepository,
			Branch:             contracts.GitHubBranchPolicy{TargetRef: targetRef, Operation: contracts.GitHubCreateBranch},
			PullRequest: contracts.GitHubPullRequestPolicy{
				BaseRef: "refs/heads/main", TargetRef: targetRef,
				Operation: contracts.GitHubCreatePullRequest, MetadataPolicy: contracts.PullRequestMetadataV1,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := NewRunManifest(contract, binding, sandbox, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := NewBoundLifecycle(manifest)
	if err != nil {
		t.Fatal(err)
	}
	destroyed := false
	defer func() {
		if !destroyed {
			_ = lifecycle.Destroy(context.Background())
		}
	}()
	gitBinding, err := lifecycle.BindGitRepository()
	if err != nil {
		t.Fatal(err)
	}
	remoteBinding, err := lifecycle.BindGitHubRepository(ctx, canonicalRepository, readClient)
	if err != nil {
		t.Fatal(err)
	}
	if remoteBinding.RepositoryID() != repository.ID || remoteBinding.BaseRef() != gitBinding.HeadRef() || remoteBinding.BaseCommit() != gitBinding.HeadCommit() {
		t.Fatal("provider and local base authority differ")
	}

	runToStarted(t, lifecycle)
	authorized := append(append([]byte(nil), before...), []byte("\nMIRAGE M5.4 disposable pull-request acceptance.\n")...)
	if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), authorized, 0o600); err != nil {
		t.Fatal(err)
	}
	freezeAndVerify(t, lifecycle)
	if _, err := lifecycle.DeriveGitEffectPlan(); err != nil {
		t.Fatal(err)
	}
	artifact, err := lifecycle.ConstructGitCommitArtifact()
	if err != nil {
		t.Fatal(err)
	}
	publicationPlan, err := lifecycle.DeriveGitPublicationPlan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	publicationEngine, err := gitpublication.NewEngine(readClient, func() (string, error) {
		if os.Getenv("MIRAGE_GITHUB_TOKEN") != token {
			return "", gitpublication.ErrCredential
		}
		return token, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := lifecycle.PublishGitHub(ctx, publicationEngine)
	if err != nil || record == nil || record.Outcome() != gitpublication.OutcomePublished {
		t.Fatalf("publish exact branch: record=%#v err=%v", record, err)
	}
	if publicationPlan.TargetRef() != targetRef || publicationPlan.CommitOID() != artifact.CommitOID() {
		t.Fatal("published branch differs from the verified artifact")
	}

	plan, err := lifecycle.DeriveGitHubPullRequestPlan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	prEngine, err := githubpullrequest.NewEngine(prClient)
	if err != nil {
		t.Fatal(err)
	}
	ledger, establishErr := lifecycle.EstablishGitHubPullRequest(ctx, prEngine)
	if lifecycle.State() == StatePRCreationUncertain {
		ledger, establishErr = lifecycle.ReconcileGitHubPullRequest(prEngine)
	}
	if establishErr != nil || ledger == nil || lifecycle.State() != StatePREstablished || ledger.PullRequestOutcome() != githubpullrequest.OutcomeCreated || !ledger.TransportAcknowledged() || ledger.Causality() != githubpullrequest.CausalityMirageAcknowledged {
		t.Fatalf("establish exact pull request: state=%s ledger=%#v err=%v", lifecycle.State(), ledger, establishErr)
	}
	observation, err := prClient.ObserveExactPullRequest(ctx, plan)
	if err != nil || observation.Status != githubpullrequest.ObservationExact || observation.Exact == nil || observation.Exact.HeadOID() != artifact.CommitOID() {
		t.Fatalf("independent pull-request observation: observation=%#v err=%v", observation, err)
	}
	repeated, err := lifecycle.EstablishGitHubPullRequest(ctx, prEngine)
	if err != nil || repeated.Identity() != ledger.Identity() {
		t.Fatal("repeated lifecycle call did not return immutable terminal evidence")
	}

	after, err := os.ReadFile(filepath.Join(real, "README.md"))
	if err != nil || !bytes.Equal(after, before) {
		t.Fatal("external publication mutated the local disposable-repository checkout")
	}
	if err := lifecycle.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	destroyed = true
	if err := disposable.Cleanup(); err != nil {
		t.Fatal(err)
	}
	cleaned = true
	t.Logf("repository_id=%d target_ref=%s commit_oid=%s pull_request=%s ledger=%s", repository.ID, targetRef, artifact.CommitOID(), observation.Exact.URL(), ledger.Identity())
}
