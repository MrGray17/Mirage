package gitplan

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/runtime/gitbinding"
	"github.com/MrGray17/Mirage/internal/runtime/reconcile"
	"github.com/MrGray17/Mirage/internal/runtime/tree"
)

const planManifest = "sha256:verified-manifest"

func TestPlanBindsExactVerifiedReconciliationAndTrustedRepository(t *testing.T) {
	fixture := newPlanFixture(t, "authorized\n", "../../refs/heads/main\nHEAD@{1}:evil")
	plan, err := New(fixture.spec())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Version() != Version || plan.ManifestHash() != planManifest || plan.ContractHash() != fixture.contract.Hash() || plan.RepositoryBindingHash() != fixture.repository.Identity() || plan.BaseCommit() != fixture.repository.HeadCommit() || plan.BaseTree() != fixture.repository.HeadTree() || plan.BaseRef() != "refs/heads/main" || plan.ReconciliationPlanHash() != fixture.plan.Hash() || plan.ReconciliationAuthority() != fixture.decision.AuthorityHash {
		t.Fatalf("incomplete plan binding: %#v", plan)
	}
	if !strings.HasPrefix(plan.TargetRef(), branchPrefix) || strings.Contains(plan.TargetRef(), "..") || strings.Contains(plan.TargetRef(), "HEAD") || strings.Contains(plan.TargetRef(), ":") {
		t.Fatalf("unsafe deterministic target ref %q", plan.TargetRef())
	}
	effects := plan.Effects()
	if len(effects) != 1 || effects[0].Resource != "/workspace/README.md" || effects[0].Operation != tree.OperationModify || effects[0].BeforeDigest == effects[0].AfterDigest || effects[0].BaseBlobOID == "" {
		t.Fatalf("effects = %#v", effects)
	}
	effects[0].Resource = "/workspace/forged"
	if plan.Effects()[0].Resource != "/workspace/README.md" {
		t.Fatal("caller mutated immutable plan effects")
	}
	if err := Revalidate(plan, planManifest, fixture.contract, fixture.repository, fixture.plan, fixture.decision, fixture.at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func TestPlanRejectsUnverifiedOrDeniedReconciliation(t *testing.T) {
	fixture := newPlanFixture(t, "authorized\n")
	spec := fixture.spec()
	spec.Decision = reconcile.Decision{}
	if _, err := New(spec); !errors.Is(err, ErrUnverified) {
		t.Fatalf("unverified plan = %v", err)
	}
	spec = fixture.spec()
	spec.Decision.Allowed = false
	if _, err := New(spec); !errors.Is(err, ErrUnverified) {
		t.Fatalf("denied plan = %v", err)
	}
	spec = fixture.spec()
	spec.RunID = "different-run"
	if _, err := New(spec); !errors.Is(err, ErrAuthorityChanged) {
		t.Fatalf("mismatched run identity = %v", err)
	}
}

func TestDifferentVerifiedMutationPlansHaveDifferentIdentities(t *testing.T) {
	first := newPlanFixture(t, "first authorized result\n")
	firstPlan, err := New(first.spec())
	if err != nil {
		t.Fatal(err)
	}
	secondTree, secondDecision := verifiedMutation(t, first.baseline, first.finalRoot, first.contract, "second authorized result\n", first.at)
	secondPlan, err := New(Spec{
		RunID: first.contract.RunID(), ManifestHash: planManifest, Contract: first.contract,
		Repository: first.repository, ReconciliationPlan: secondTree,
		Decision: secondDecision, CreatedAt: first.at,
	})
	if err != nil {
		t.Fatal(err)
	}
	if firstPlan.ReconciliationPlanHash() == secondPlan.ReconciliationPlanHash() || firstPlan.Identity() == secondPlan.Identity() {
		t.Fatal("different verified mutations shared Git plan identity")
	}
}

func TestRevalidationFailsClosedOnRepositoryOrAuthorityChange(t *testing.T) {
	fixture := newPlanFixture(t, "authorized\n")
	plan, err := New(fixture.spec())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("head changed", func(t *testing.T) {
		runGit(t, fixture.repository.Root(), "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "--allow-empty", "-m", "concurrent")
		if err := Revalidate(plan, planManifest, fixture.contract, fixture.repository, fixture.plan, fixture.decision, fixture.at.Add(time.Minute)); !errors.Is(err, ErrRepositoryChanged) {
			t.Fatalf("revalidate = %v", err)
		}
	})
}

func TestRevalidationRejectsChangedPlanAndExpiredContract(t *testing.T) {
	fixture := newPlanFixture(t, "authorized\n")
	plan, err := New(fixture.spec())
	if err != nil {
		t.Fatal(err)
	}
	otherPlan, otherDecision := verifiedMutation(t, fixture.baseline, fixture.finalRoot, fixture.contract, "other\n", fixture.at)
	if err := Revalidate(plan, planManifest, fixture.contract, fixture.repository, otherPlan, otherDecision, fixture.at.Add(time.Minute)); !errors.Is(err, ErrAuthorityChanged) {
		t.Fatalf("changed reconciliation = %v", err)
	}
	if err := Revalidate(plan, planManifest, fixture.contract, fixture.repository, fixture.plan, fixture.decision, fixture.contract.ExpiresAt()); !errors.Is(err, ErrContractExpired) {
		t.Fatalf("expired plan = %v", err)
	}
	if err := Revalidate(plan, planManifest, fixture.contract, fixture.repository, fixture.plan, fixture.decision, plan.CreatedAt().Add(-time.Nanosecond)); !errors.Is(err, ErrAuthorityChanged) {
		t.Fatalf("rolled-back plan time = %v", err)
	}
}

type planFixture struct {
	at         time.Time
	contract   *contracts.Contract
	repository *gitbinding.Binding
	baseline   *tree.Snapshot
	finalRoot  string
	plan       *tree.Plan
	decision   reconcile.Decision
}

func (f planFixture) spec() Spec {
	return Spec{
		RunID: f.contract.RunID(), ManifestHash: planManifest, Contract: f.contract,
		Repository: f.repository, ReconciliationPlan: f.plan,
		Decision: f.decision, CreatedAt: f.at,
	}
}

func newPlanFixture(t *testing.T, finalContents string, runIDs ...string) planFixture {
	t.Helper()
	at := time.Date(2026, 8, 28, 18, 0, 0, 0, time.UTC)
	repositoryRoot := initRepository(t)
	repository, err := gitbinding.Capture(repositoryRoot, planManifest, at)
	if err != nil {
		t.Fatal(err)
	}
	runID := "plan-run"
	if len(runIDs) == 1 {
		runID = runIDs[0]
	}
	contract, err := contracts.New(contracts.Spec{
		Version: contracts.VersionV1, RunID: runID, ActorID: "test-agent", ExpiresAt: at.Add(time.Hour),
		Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{Allow: []string{"/workspace/README.md"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	baselineRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(baselineRoot, "README.md"), []byte("before\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	baseline, err := tree.Scan(baselineRoot, tree.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	finalRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(finalRoot, "README.md"), []byte(finalContents), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, decision := verifiedMutation(t, baseline, finalRoot, contract, finalContents, at)
	return planFixture{at: at, contract: contract, repository: repository, baseline: baseline, finalRoot: finalRoot, plan: plan, decision: decision}
}

func verifiedMutation(t *testing.T, baseline *tree.Snapshot, finalRoot string, contract *contracts.Contract, contents string, at time.Time) (*tree.Plan, reconcile.Decision) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(finalRoot, "README.md"), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, decision, err := reconcile.Verify(planManifest, baseline, finalRoot, contract, at)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("fixture reconciliation denied: %#v", decision.Violations())
	}
	return plan, decision
}

func initRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	runGit(t, root, "init", "-b", "main")
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("before\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", "--", "README.md")
	runGit(t, root, "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "-m", "initial")
	return root
}

func runGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v (%s)", args, err, output)
	}
	return strings.TrimSpace(string(output))
}
