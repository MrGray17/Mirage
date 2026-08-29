package runtime

import (
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
	"github.com/MrGray17/Mirage/internal/runtime/gitpublication"
	"github.com/MrGray17/Mirage/internal/runtime/workspace"
)

func TestM53LiveGitHubCreateOnlyPublication(t *testing.T) {
	if os.Getenv("MIRAGE_M53_LIVE") != "1" {
		t.Skip("set MIRAGE_M53_LIVE=1 for the explicit one-branch GitHub proof")
	}
	repositoryName := strings.TrimSpace(os.Getenv("MIRAGE_M53_TEST_REPO"))
	repositoryRoot := strings.TrimSpace(os.Getenv("MIRAGE_M53_TEST_REPO_ROOT"))
	token := strings.TrimSpace(os.Getenv("MIRAGE_GITHUB_TOKEN"))
	if repositoryName == "" || repositoryRoot == "" || token == "" {
		t.Fatal("MIRAGE_M53_TEST_REPO, MIRAGE_M53_TEST_REPO_ROOT, and MIRAGE_GITHUB_TOKEN are required; ambient credentials are forbidden")
	}
	canonicalRepository, err := contracts.CanonicalGitHubRepository(repositoryName)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	runID := fmt.Sprintf("m53-live-%d", now.UnixNano())
	real, err := filepath.Abs(repositoryRoot)
	if err != nil || filepath.Clean(real) != real {
		t.Fatalf("invalid dedicated live repository root: %v", err)
	}
	before, err := os.ReadFile(filepath.Join(real, "README.md"))
	if err != nil {
		t.Fatalf("dedicated live repository must contain README.md: %v", err)
	}
	disposable, err := workspace.Prepare(real)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = disposable.Cleanup() })
	binding, err := disposable.Binding()
	if err != nil {
		t.Fatal(err)
	}
	sandbox := &sandboxStub{real: binding.RealWorkspace(), disposable: binding.DisposableWorkspace(), token: binding.Token()}
	contract, err := contracts.New(contracts.Spec{Version: contracts.VersionV2, RunID: runID, ActorID: "m53-live", ExpiresAt: now.Add(10 * time.Minute), Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{Allow: []string{"/workspace/README.md"}}}, GitHub: contracts.GitHubPublicationPolicy{RepositoryFullName: canonicalRepository, TargetRef: gitrefs.RunTarget(runID), Operation: contracts.GitHubCreateBranch}})
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
	if _, err := lifecycle.BindGitRepository(); err != nil {
		t.Fatal(err)
	}
	client, err := githubbinding.NewHTTPClient(token)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	remote, err := lifecycle.BindGitHubRepository(ctx, canonicalRepository, client)
	if err != nil {
		t.Fatal(err)
	}
	runToStarted(t, lifecycle)
	authorized := append(append([]byte(nil), before...), []byte(fmt.Sprintf("\nMIRAGE M5.3 live publication proof %s\n", runID))...)
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
	plan, err := lifecycle.DeriveGitPublicationPlan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := gitpublication.NewEngine(client, func() (string, error) {
		current := strings.TrimSpace(os.Getenv("MIRAGE_GITHUB_TOKEN"))
		if current == "" || current != token {
			return "", gitpublication.ErrCredential
		}
		return current, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := lifecycle.PublishGitHub(ctx, engine)
	if err != nil {
		t.Fatal(err)
	}
	if record == nil || record.Outcome() != gitpublication.OutcomePublished || record.CommitOID() != artifact.CommitOID() || plan.CommitOID() != artifact.CommitOID() || lifecycle.State() != StatePublished {
		t.Fatalf("incomplete live evidence: record=%#v state=%s", record, lifecycle.State())
	}
	if strings.Contains(fmt.Sprintf("%#v %#v %#v", remote, plan, record), token) {
		t.Fatal("credential entered publication evidence")
	}
	t.Logf("repository_id=%d repository=%s target_ref=%s commit_oid=%s transport_acknowledged=%t reconciled=%t publication_record=%s", record.RepositoryID(), record.RepositoryFullName(), record.TargetRef(), record.CommitOID(), record.TransportAcknowledged(), record.ResolvedByReconciliation(), record.Identity())
	if err := lifecycle.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
}
