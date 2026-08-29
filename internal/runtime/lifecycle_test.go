package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/runtime/gitcommit"
	"github.com/MrGray17/Mirage/internal/runtime/gitplan"
	"github.com/MrGray17/Mirage/internal/runtime/realcommit"
	"github.com/MrGray17/Mirage/internal/runtime/tree"
	"github.com/MrGray17/Mirage/internal/runtime/workspace"
)

type sandboxStub struct {
	prepareErr error
	startErr   error
	freezeErr  error
	destroyErr error
	calls      []string
	identity   string
	real       string
	disposable string
	token      string
}

func (s *sandboxStub) Identity() string {
	if s.identity == "" {
		return "sandbox:test"
	}
	return s.identity
}

func (s *sandboxStub) BoundWorkspace() (string, string, string) {
	return s.real, s.disposable, s.token
}

func (s *sandboxStub) Prepare(context.Context) error {
	s.calls = append(s.calls, "prepare")
	return s.prepareErr
}

func (s *sandboxStub) Start(context.Context) error {
	s.calls = append(s.calls, "start")
	return s.startErr
}

func (s *sandboxStub) Freeze(context.Context) error {
	s.calls = append(s.calls, "freeze")
	return s.freezeErr
}

func (s *sandboxStub) Destroy(context.Context) error {
	s.calls = append(s.calls, "destroy")
	return s.destroyErr
}

func TestLifecycleRequiresStopProofBeforeFrozen(t *testing.T) {
	stub := &sandboxStub{}
	lifecycle, err := NewLifecycle(stub)
	if err != nil {
		t.Fatalf("new lifecycle: %v", err)
	}
	if lifecycle.State() != StateCreated {
		t.Fatalf("initial state = %s", lifecycle.State())
	}
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if lifecycle.State() != StatePreparing {
		t.Fatalf("prepared state = %s", lifecycle.State())
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if lifecycle.State() != StateRunning {
		t.Fatalf("running state = %s", lifecycle.State())
	}
	if err := lifecycle.Freeze(context.Background()); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if lifecycle.State() != StateFrozen {
		t.Fatalf("frozen state = %s", lifecycle.State())
	}
	if got := len(stub.calls); got != 3 {
		t.Fatalf("calls = %v", stub.calls)
	}
}

func TestLifecycleFreezeFailureIsNeverFrozen(t *testing.T) {
	stopErr := errors.New("stop proof unavailable")
	stub := &sandboxStub{freezeErr: stopErr}
	lifecycle, err := NewLifecycle(stub)
	if err != nil {
		t.Fatalf("new lifecycle: %v", err)
	}
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := lifecycle.Freeze(context.Background()); !errors.Is(err, stopErr) {
		t.Fatalf("freeze error = %v", err)
	}
	if lifecycle.State() != StateFailed {
		t.Fatalf("state = %s, want FAILED", lifecycle.State())
	}
	if _, err := lifecycle.Reconcile(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("reconcile error = %v", err)
	}
}

func TestLifecycleStartFailureCannotBeReconciled(t *testing.T) {
	startErr := errors.New("uncertain start")
	stub := &sandboxStub{startErr: startErr}
	lifecycle, err := NewLifecycle(stub)
	if err != nil {
		t.Fatalf("new lifecycle: %v", err)
	}
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := lifecycle.Start(context.Background()); !errors.Is(err, startErr) {
		t.Fatalf("start error = %v", err)
	}
	if lifecycle.State() != StateFailed {
		t.Fatalf("state = %s, want FAILED", lifecycle.State())
	}
	if _, err := lifecycle.Reconcile(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("reconcile error = %v", err)
	}
}

func TestLifecycleVerificationRequiresFrozenExactReconciliation(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	lifecycle, disposable := boundLifecycle(t, func() time.Time { return now }, now.Add(time.Hour), "/workspace/README.md")
	if _, err := lifecycle.Reconcile(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("early verify error = %v", err)
	}
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("after"), 0o666); err != nil {
		t.Fatal(err)
	}
	decision, err := lifecycle.Reconcile()
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("decision = %#v, violations = %#v", decision, decision.Violations())
	}
	if lifecycle.State() != StateVerified {
		t.Fatalf("state = %s, want VERIFIED", lifecycle.State())
	}
	plan, stored := lifecycle.Reconciliation()
	if plan == nil || len(plan.Mutations()) != 1 || stored.AuthorityHash != decision.AuthorityHash {
		t.Fatalf("stored reconciliation = %#v, %#v", plan, stored)
	}
}

func TestLifecyclePolicyDenialIsRejectedNotFailed(t *testing.T) {
	lifecycle, disposable := frozenLifecycle(t)
	if err := os.WriteFile(filepath.Join(disposable.Path(), "forbidden.txt"), []byte("hostile"), 0o644); err != nil {
		t.Fatal(err)
	}
	decision, err := lifecycle.Reconcile()
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed || lifecycle.State() != StateRejected {
		t.Fatalf("decision = %#v, state = %s", decision, lifecycle.State())
	}
}

func TestLifecycleScanUncertaintyFailsClosed(t *testing.T) {
	lifecycle, disposable := frozenLifecycle(t)
	if err := os.RemoveAll(disposable.Path()); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.Reconcile(); err == nil {
		t.Fatal("missing frozen workspace was reconciled")
	}
	if lifecycle.State() != StateFailed {
		t.Fatalf("state = %s, want FAILED", lifecycle.State())
	}
}

func TestLifecycleBindsGitBeforeHostileExecutionAndPlansOnlyAfterVerification(t *testing.T) {
	lifecycle, disposable, gitDir := boundGitLifecycle(t)
	before, err := tree.Scan(gitDir, tree.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := lifecycle.BindGitRepository()
	if err != nil {
		t.Fatal(err)
	}
	if binding.Root() != disposable.RealWorkspace() || binding.ManifestHash() == "" {
		t.Fatalf("binding = %#v", binding)
	}
	if _, err := os.Lstat(filepath.Join(disposable.Path(), ".git")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("real .git entered disposable workspace: %v", err)
	}
	if _, err := lifecycle.DeriveGitEffectPlan(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("unverified derivation = %v", err)
	}
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.BindGitRepository(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("late binding = %v", err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("verified Git proposal\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	freezeAndVerify(t, lifecycle)
	plan, err := lifecycle.DeriveGitEffectPlan()
	if err != nil {
		t.Fatal(err)
	}
	if plan == nil || plan.RepositoryBindingHash() != binding.Identity() || plan.TargetRef() == "refs/heads/main" || len(plan.Effects()) != 1 {
		t.Fatalf("Git plan = %#v", plan)
	}
	again, err := lifecycle.DeriveGitEffectPlan()
	if err != nil || again != plan || again.Identity() != plan.Identity() || again.CreatedAt() != plan.CreatedAt() {
		t.Fatalf("repeated derivation minted new authority: first=%p second=%p error=%v", plan, again, err)
	}
	if err := lifecycle.RevalidateGitEffectPlan(); err != nil {
		t.Fatal(err)
	}
	after, err := tree.Scan(gitDir, tree.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if before.Identity() != after.Identity() {
		t.Fatalf("M5.1 mutated real Git metadata: before=%s after=%s", before.Identity(), after.Identity())
	}
}

func TestLifecycleGitBindingRejectsM4BaselineGitBaseMismatch(t *testing.T) {
	lifecycle, disposable, _ := boundGitLifecycle(t)
	if err := os.WriteFile(filepath.Join(disposable.RealWorkspace(), "README.md"), []byte("outside commit after M4 baseline\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runLifecycleGit(t, disposable.RealWorkspace(), "add", "--", "README.md")
	runLifecycleGit(t, disposable.RealWorkspace(), "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "-m", "outside change")
	if _, err := lifecycle.BindGitRepository(); !errors.Is(err, ErrRealStateConflict) {
		t.Fatalf("binding mismatch = %v", err)
	}
	if lifecycle.State() != StateConflicted || lifecycle.GitRepositoryBinding() != nil {
		t.Fatalf("state=%s binding=%#v", lifecycle.State(), lifecycle.GitRepositoryBinding())
	}
}

func TestLifecycleGitPlanRejectsUntrackedM4Modify(t *testing.T) {
	now := time.Date(2026, 8, 28, 18, 0, 0, 0, time.UTC)
	real := lifecycleRealWorkspace(t)
	runLifecycleGit(t, real, "init", "-b", "main")
	writeLifecycleFile(t, real, "README.md", "tracked\n", 0o600)
	runLifecycleGit(t, real, "add", "--", "README.md")
	runLifecycleGit(t, real, "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "-m", "initial")
	writeLifecycleFile(t, real, "notes.txt", "untracked before\n", 0o600)
	disposable, err := workspace.Prepare(real)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := disposable.Cleanup(); err != nil {
			t.Errorf("cleanup disposable: %v", err)
		}
	})
	workspaceBinding, err := disposable.Binding()
	if err != nil {
		t.Fatal(err)
	}
	stub := &sandboxStub{real: workspaceBinding.RealWorkspace(), disposable: workspaceBinding.DisposableWorkspace(), token: workspaceBinding.Token()}
	manifest, err := NewRunManifest(lifecycleContract(t, now.Add(time.Hour), "/workspace/notes.txt"), workspaceBinding, stub, func() time.Time { return now })
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
	runToStarted(t, lifecycle)
	if err := os.WriteFile(filepath.Join(disposable.Path(), "notes.txt"), []byte("agent update\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	freezeAndVerify(t, lifecycle)
	if _, err := lifecycle.DeriveGitEffectPlan(); !errors.Is(err, gitplan.ErrUnsupportedEffect) {
		t.Fatalf("untracked Git effect = %v", err)
	}
	if lifecycle.State() != StateRejected || lifecycle.GitEffectPlan() != nil {
		t.Fatalf("state=%s plan=%#v", lifecycle.State(), lifecycle.GitEffectPlan())
	}
}

func TestLifecycleRejectsAgentCreatedShadowGitAsFilesystemMutation(t *testing.T) {
	lifecycle, disposable, _ := boundGitLifecycle(t)
	binding, err := lifecycle.BindGitRepository()
	if err != nil {
		t.Fatal(err)
	}
	runToStarted(t, lifecycle)
	if err := os.Mkdir(filepath.Join(disposable.Path(), ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(disposable.Path(), ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	decision, err := lifecycle.Reconcile()
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed || lifecycle.State() != StateRejected {
		t.Fatalf("shadow .git decision=%#v state=%s", decision, lifecycle.State())
	}
	if lifecycle.GitRepositoryBinding().Identity() != binding.Identity() || lifecycle.GitEffectPlan() != nil {
		t.Fatal("hostile shadow .git influenced trusted Git authority")
	}
	if _, err := lifecycle.DeriveGitEffectPlan(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("rejected state derived plan: %v", err)
	}
}

func TestLifecycleGitPlanRevalidationFailsOnConcurrentHeadChange(t *testing.T) {
	lifecycle, disposable, _ := boundGitLifecycle(t)
	if _, err := lifecycle.BindGitRepository(); err != nil {
		t.Fatal(err)
	}
	runToStarted(t, lifecycle)
	if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("verified Git proposal\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	freezeAndVerify(t, lifecycle)
	if _, err := lifecycle.DeriveGitEffectPlan(); err != nil {
		t.Fatal(err)
	}
	runLifecycleGit(t, disposable.RealWorkspace(), "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "--allow-empty", "-m", "concurrent head")
	if err := lifecycle.RevalidateGitEffectPlan(); !errors.Is(err, gitplan.ErrRepositoryChanged) {
		t.Fatalf("revalidation = %v", err)
	}
	if lifecycle.State() != StateConflicted {
		t.Fatalf("state = %s, want CONFLICTED", lifecycle.State())
	}
	if err := lifecycle.RevalidateGitEffectPlan(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("conflicted plan was retryable: %v", err)
	}
}

func TestLifecycleConstructsOneDeterministicGitArtifactWithoutTouchingReality(t *testing.T) {
	lifecycle, disposable, gitDir := preparedGitArtifactLifecycle(t, func() time.Time {
		return time.Date(2026, 8, 29, 2, 0, 0, 987654321, time.UTC)
	}, time.Date(2026, 8, 29, 3, 0, 0, 0, time.UTC))
	beforeGit, err := tree.Scan(gitDir, tree.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	beforeReal, err := lifecycle.manifest.workspace.ObserveReal()
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := lifecycle.ConstructGitCommitArtifact()
	if err != nil {
		t.Fatal(err)
	}
	if artifact == nil || lifecycle.State() != StateVerified || artifact.GitPlanIdentity() != lifecycle.GitEffectPlan().Identity() || artifact.BaseBlobOID() != lifecycle.GitEffectPlan().Effects()[0].BaseBlobOID || artifact.Resource() != "/workspace/README.md" {
		t.Fatalf("artifact=%#v state=%s", artifact, lifecycle.State())
	}
	again, err := lifecycle.ConstructGitCommitArtifact()
	if err != nil || again != artifact || again.Identity() != artifact.Identity() || again.CommitOID() != artifact.CommitOID() {
		t.Fatalf("repeated artifact = %p/%s, %v", again, again.Identity(), err)
	}
	if err := lifecycle.RevalidateGitCommitArtifact(); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.PreCommit(); !errors.Is(err, ErrInvalidTransition) || lifecycle.State() != StateVerified {
		t.Fatalf("direct commit path after Git artifact = %v, state=%s", err, lifecycle.State())
	}
	afterGit, err := tree.Scan(gitDir, tree.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	afterReal, err := lifecycle.manifest.workspace.ObserveReal()
	if err != nil {
		t.Fatal(err)
	}
	if beforeGit.Identity() != afterGit.Identity() || beforeReal.Identity() != afterReal.Identity() {
		t.Fatal("M5.2 changed real Git metadata or worktree state")
	}
	assertRealREADME(t, disposable, "before\n", 0o600)
	if err := lifecycle.CleanupGitCommitArtifact(); err != nil {
		t.Fatal(err)
	}
	if lifecycle.GitCommitArtifact() != nil {
		t.Fatal("cleaned artifact remains installed")
	}
	if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("cleaned lifecycle minted another artifact: %v", err)
	}
}

func TestLifecycleGitArtifactRejectsStaleRealityAndFrozenShadow(t *testing.T) {
	base := time.Date(2026, 8, 29, 2, 0, 0, 0, time.UTC)
	t.Run("HEAD before construction", func(t *testing.T) {
		lifecycle, disposable, _ := preparedGitArtifactLifecycle(t, func() time.Time { return base }, base.Add(time.Hour))
		runLifecycleGit(t, disposable.RealWorkspace(), "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "--allow-empty", "-m", "concurrent head")
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, gitplan.ErrRepositoryChanged) || lifecycle.State() != StateConflicted || lifecycle.GitCommitArtifact() != nil {
			t.Fatalf("stale HEAD = %v, state=%s artifact=%#v", err, lifecycle.State(), lifecycle.GitCommitArtifact())
		}
	})
	t.Run("HEAD during construction", func(t *testing.T) {
		lifecycle, disposable, _ := preparedGitArtifactLifecycle(t, func() time.Time { return base }, base.Add(time.Hour))
		lifecycle.afterGitConstruction = func() {
			runLifecycleGit(t, disposable.RealWorkspace(), "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "--allow-empty", "-m", "concurrent head")
		}
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, gitplan.ErrRepositoryChanged) || lifecycle.State() != StateConflicted || lifecycle.GitCommitArtifact() != nil {
			t.Fatalf("concurrent HEAD = %v, state=%s artifact=%#v", err, lifecycle.State(), lifecycle.GitCommitArtifact())
		}
	})
	t.Run("shadow before construction", func(t *testing.T) {
		lifecycle, disposable, _ := preparedGitArtifactLifecycle(t, func() time.Time { return base }, base.Add(time.Hour))
		if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("late shadow bytes\n"), 0o666); err != nil {
			t.Fatal(err)
		}
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, ErrShadowChanged) || lifecycle.State() != StateRejected || lifecycle.GitCommitArtifact() != nil {
			t.Fatalf("stale shadow = %v, state=%s artifact=%#v", err, lifecycle.State(), lifecycle.GitCommitArtifact())
		}
	})
	t.Run("shadow during construction", func(t *testing.T) {
		lifecycle, disposable, _ := preparedGitArtifactLifecycle(t, func() time.Time { return base }, base.Add(time.Hour))
		lifecycle.afterGitConstruction = func() {
			if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("late shadow bytes\n"), 0o666); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, ErrShadowChanged) || lifecycle.State() != StateRejected || lifecycle.GitCommitArtifact() != nil {
			t.Fatalf("concurrent shadow = %v, state=%s artifact=%#v", err, lifecycle.State(), lifecycle.GitCommitArtifact())
		}
	})
}

func TestLifecycleGitArtifactExpiryRollbackAndCleanupUncertaintyFailClosed(t *testing.T) {
	base := time.Date(2026, 8, 29, 2, 0, 0, 0, time.UTC)
	t.Run("expiry", func(t *testing.T) {
		current := base
		lifecycle, _, _ := preparedGitArtifactLifecycle(t, func() time.Time { return current }, base.Add(time.Minute))
		current = base.Add(time.Minute)
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, ErrContractExpired) || lifecycle.State() != StateRejected {
			t.Fatalf("expiry = %v, state=%s", err, lifecycle.State())
		}
	})
	t.Run("rollback", func(t *testing.T) {
		current := base
		lifecycle, _, _ := preparedGitArtifactLifecycle(t, func() time.Time { return current }, base.Add(time.Hour))
		current = base.Add(-time.Second)
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, ErrClockRollback) || lifecycle.State() != StateFailed {
			t.Fatalf("rollback = %v, state=%s", err, lifecycle.State())
		}
	})
	t.Run("cleanup dominates conflict", func(t *testing.T) {
		lifecycle, disposable, _ := preparedGitArtifactLifecycle(t, func() time.Time { return base }, base.Add(time.Hour))
		lifecycle.afterGitConstruction = func() {
			runLifecycleGit(t, disposable.RealWorkspace(), "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "--allow-empty", "-m", "concurrent head")
		}
		lifecycle.cleanupGitArtifact = func(artifact *gitcommit.Artifact) error {
			return errors.Join(artifact.Cleanup(), fmt.Errorf("%w: injected cleanup uncertainty", gitcommit.ErrCleanup))
		}
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, gitplan.ErrRepositoryChanged) || !errors.Is(err, gitcommit.ErrCleanup) || lifecycle.State() != StateFailed {
			t.Fatalf("cleanup conflict = %v, state=%s", err, lifecycle.State())
		}
		if lifecycle.GitCommitArtifact() != nil || lifecycle.gitCleanupArtifact == nil {
			t.Fatal("failed cleanup exposed authority or lost cleanup ownership")
		}
		lifecycle.cleanupGitArtifact = nil
		if err := lifecycle.CleanupGitCommitArtifact(); err != nil || lifecycle.gitCleanupArtifact != nil {
			t.Fatalf("cleanup retry = %v, retained=%#v", err, lifecycle.gitCleanupArtifact)
		}
	})
	t.Run("explicit cleanup uncertainty revokes artifact", func(t *testing.T) {
		lifecycle, _, _ := preparedGitArtifactLifecycle(t, func() time.Time { return base }, base.Add(time.Hour))
		if _, err := lifecycle.ConstructGitCommitArtifact(); err != nil {
			t.Fatal(err)
		}
		lifecycle.cleanupGitArtifact = func(artifact *gitcommit.Artifact) error {
			return errors.Join(artifact.Cleanup(), fmt.Errorf("%w: injected cleanup uncertainty", gitcommit.ErrCleanup))
		}
		if err := lifecycle.CleanupGitCommitArtifact(); !errors.Is(err, gitcommit.ErrCleanup) || lifecycle.State() != StateFailed || lifecycle.GitCommitArtifact() != nil || lifecycle.gitCleanupArtifact == nil {
			t.Fatalf("uncertain explicit cleanup = %v, state=%s valid=%#v recovery=%#v", err, lifecycle.State(), lifecycle.GitCommitArtifact(), lifecycle.gitCleanupArtifact)
		}
		lifecycle.cleanupGitArtifact = nil
		if err := lifecycle.CleanupGitCommitArtifact(); err != nil || lifecycle.gitCleanupArtifact != nil {
			t.Fatalf("explicit cleanup retry = %v, retained=%#v", err, lifecycle.gitCleanupArtifact)
		}
	})
}

func TestLifecycleRevokesInstalledGitArtifactOnLaterAuthorityFailure(t *testing.T) {
	base := time.Date(2026, 8, 29, 3, 0, 0, 0, time.UTC)
	t.Run("HEAD then repeat construction", func(t *testing.T) {
		lifecycle, disposable, _ := preparedGitArtifactLifecycle(t, func() time.Time { return base }, base.Add(time.Hour))
		if _, err := lifecycle.ConstructGitCommitArtifact(); err != nil {
			t.Fatal(err)
		}
		cleanupCalled := false
		lifecycle.cleanupGitArtifact = func(artifact *gitcommit.Artifact) error {
			cleanupCalled = true
			return artifact.Cleanup()
		}
		runLifecycleGit(t, disposable.RealWorkspace(), "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "--allow-empty", "-m", "later head")
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, gitplan.ErrRepositoryChanged) || lifecycle.State() != StateConflicted || lifecycle.GitCommitArtifact() != nil || lifecycle.gitArtifact != nil || lifecycle.gitCleanupArtifact != nil || !cleanupCalled {
			t.Fatalf("later HEAD = %v, state=%s valid=%#v installed=%#v recovery=%#v cleanup=%t", err, lifecycle.State(), lifecycle.GitCommitArtifact(), lifecycle.gitArtifact, lifecycle.gitCleanupArtifact, cleanupCalled)
		}
	})

	t.Run("shadow then repeat construction", func(t *testing.T) {
		lifecycle, disposable, _ := preparedGitArtifactLifecycle(t, func() time.Time { return base }, base.Add(time.Hour))
		if _, err := lifecycle.ConstructGitCommitArtifact(); err != nil {
			t.Fatal(err)
		}
		cleanupCalled := false
		lifecycle.cleanupGitArtifact = func(artifact *gitcommit.Artifact) error {
			cleanupCalled = true
			return artifact.Cleanup()
		}
		if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("later shadow\n"), 0o666); err != nil {
			t.Fatal(err)
		}
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, ErrShadowChanged) || lifecycle.State() != StateRejected || lifecycle.GitCommitArtifact() != nil || lifecycle.gitArtifact != nil || lifecycle.gitCleanupArtifact != nil || !cleanupCalled {
			t.Fatalf("later shadow = %v, state=%s valid=%#v installed=%#v recovery=%#v cleanup=%t", err, lifecycle.State(), lifecycle.GitCommitArtifact(), lifecycle.gitArtifact, lifecycle.gitCleanupArtifact, cleanupCalled)
		}
	})

	t.Run("contract expiry then repeat construction", func(t *testing.T) {
		current := base
		lifecycle, _, _ := preparedGitArtifactLifecycle(t, func() time.Time { return current }, base.Add(time.Minute))
		if _, err := lifecycle.ConstructGitCommitArtifact(); err != nil {
			t.Fatal(err)
		}
		cleanupCalled := false
		lifecycle.cleanupGitArtifact = func(artifact *gitcommit.Artifact) error {
			cleanupCalled = true
			return artifact.Cleanup()
		}
		current = base.Add(time.Minute)
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, ErrContractExpired) || lifecycle.State() != StateRejected || lifecycle.GitCommitArtifact() != nil || lifecycle.gitArtifact != nil || !cleanupCalled {
			t.Fatalf("later expiry = %v, state=%s valid=%#v installed=%#v cleanup=%t", err, lifecycle.State(), lifecycle.GitCommitArtifact(), lifecycle.gitArtifact, cleanupCalled)
		}
	})

	t.Run("clock rollback then artifact revalidation", func(t *testing.T) {
		current := base
		lifecycle, _, _ := preparedGitArtifactLifecycle(t, func() time.Time { return current }, base.Add(time.Hour))
		if _, err := lifecycle.ConstructGitCommitArtifact(); err != nil {
			t.Fatal(err)
		}
		cleanupCalled := false
		lifecycle.cleanupGitArtifact = func(artifact *gitcommit.Artifact) error {
			cleanupCalled = true
			return artifact.Cleanup()
		}
		current = base.Add(-time.Second)
		if err := lifecycle.RevalidateGitCommitArtifact(); !errors.Is(err, ErrClockRollback) || lifecycle.State() != StateFailed || lifecycle.GitCommitArtifact() != nil || lifecycle.gitArtifact != nil || !cleanupCalled {
			t.Fatalf("later rollback = %v, state=%s valid=%#v installed=%#v cleanup=%t", err, lifecycle.State(), lifecycle.GitCommitArtifact(), lifecycle.gitArtifact, cleanupCalled)
		}
	})

	t.Run("cleanup uncertainty dominates later conflict", func(t *testing.T) {
		lifecycle, disposable, _ := preparedGitArtifactLifecycle(t, func() time.Time { return base }, base.Add(time.Hour))
		if _, err := lifecycle.ConstructGitCommitArtifact(); err != nil {
			t.Fatal(err)
		}
		lifecycle.cleanupGitArtifact = func(artifact *gitcommit.Artifact) error {
			return errors.Join(artifact.Cleanup(), fmt.Errorf("%w: injected later cleanup uncertainty", gitcommit.ErrCleanup))
		}
		runLifecycleGit(t, disposable.RealWorkspace(), "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "--allow-empty", "-m", "later head")
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, gitplan.ErrRepositoryChanged) || !errors.Is(err, gitcommit.ErrCleanup) || lifecycle.State() != StateFailed || lifecycle.GitCommitArtifact() != nil || lifecycle.gitArtifact != nil || lifecycle.gitCleanupArtifact == nil {
			t.Fatalf("later cleanup uncertainty = %v, state=%s valid=%#v installed=%#v recovery=%#v", err, lifecycle.State(), lifecycle.GitCommitArtifact(), lifecycle.gitArtifact, lifecycle.gitCleanupArtifact)
		}
		lifecycle.cleanupGitArtifact = nil
		if err := lifecycle.CleanupGitCommitArtifact(); err != nil || lifecycle.gitCleanupArtifact != nil {
			t.Fatalf("later cleanup retry = %v, retained=%#v", err, lifecycle.gitCleanupArtifact)
		}
	})
}

func TestLifecycleClockRollbackBeforePrepareFailsClosed(t *testing.T) {
	base := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	stub := &sandboxStub{}
	lifecycle, err := NewLifecycleWithClock(stub, sequenceClock(t, base, base.Add(-time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Prepare(context.Background()); !errors.Is(err, ErrClockRollback) {
		t.Fatalf("prepare error = %v", err)
	}
	if lifecycle.State() != StateFailed || len(stub.calls) != 0 {
		t.Fatalf("state = %s, calls = %v", lifecycle.State(), stub.calls)
	}
}

func TestLifecycleClockRollbackBeforeStartFailsClosed(t *testing.T) {
	base := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	stub := &sandboxStub{}
	lifecycle, err := NewLifecycleWithClock(stub, sequenceClock(t, base, base.Add(time.Minute), base))
	if err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Start(context.Background()); !errors.Is(err, ErrClockRollback) {
		t.Fatalf("start error = %v", err)
	}
	if lifecycle.State() != StateFailed || len(stub.calls) != 1 || stub.calls[0] != "prepare" {
		t.Fatalf("state = %s, calls = %v", lifecycle.State(), stub.calls)
	}
}

func TestLifecycleClockRollbackBeforeFreezeStillStopsProcessTree(t *testing.T) {
	base := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	stub := &sandboxStub{}
	lifecycle, err := NewLifecycleWithClock(stub, sequenceClock(t,
		base,
		base.Add(time.Minute),
		base.Add(2*time.Minute),
		base.Add(time.Minute),
	))
	if err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Freeze(context.Background()); !errors.Is(err, ErrClockRollback) {
		t.Fatalf("freeze error = %v", err)
	}
	if lifecycle.State() != StateFailed {
		t.Fatalf("state = %s", lifecycle.State())
	}
	if len(stub.calls) != 3 || stub.calls[2] != "freeze" {
		t.Fatalf("rollback bypassed process-tree stop: %v", stub.calls)
	}
}

func TestLifecycleClockRollbackBeforeReconciliationCannotRevalidateExpiredContract(t *testing.T) {
	base := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	lifecycle, disposable := boundLifecycle(t, sequenceClock(t,
		base,
		base.Add(time.Minute),
		base.Add(2*time.Minute),
		base.Add(10*time.Minute),
		base.Add(3*time.Minute),
	), base.Add(5*time.Minute))
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = disposable
	if _, err := lifecycle.Reconcile(); !errors.Is(err, ErrClockRollback) {
		t.Fatalf("reconcile error = %v", err)
	}
	if lifecycle.State() != StateFailed {
		t.Fatalf("state = %s, want FAILED", lifecycle.State())
	}
	if plan, decision := lifecycle.Reconciliation(); plan != nil || decision.Allowed {
		t.Fatalf("rollback created reconciliation authority: plan=%#v decision=%#v", plan, decision)
	}
}

func TestLifecycleRejectsUnavailableClockAtCreation(t *testing.T) {
	if _, err := NewLifecycleWithClock(&sandboxStub{}, nil); !errors.Is(err, ErrTrustedTime) {
		t.Fatalf("nil clock error = %v", err)
	}
	if _, err := NewLifecycleWithClock(&sandboxStub{}, func() time.Time { return time.Time{} }); !errors.Is(err, ErrTrustedTime) {
		t.Fatalf("zero clock error = %v", err)
	}
}

func TestLifecycleRejectCannotHideRunningProcess(t *testing.T) {
	stub := &sandboxStub{}
	lifecycle, err := NewLifecycle(stub)
	if err != nil {
		t.Fatalf("new lifecycle: %v", err)
	}
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Reject(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("reject error = %v", err)
	}
	if lifecycle.State() != StateRunning {
		t.Fatalf("state = %s, want RUNNING", lifecycle.State())
	}
}

func TestLifecycleCommitsOneVerifiedContentChangeAndPreservesRealMode(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	lifecycle, disposable := boundLifecycle(t, func() time.Time { return now }, now.Add(time.Hour), "/workspace/README.md")
	runToStarted(t, lifecycle)
	if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("authorized update\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	freezeAndVerify(t, lifecycle)
	commitPlan, err := lifecycle.PreCommit()
	if err != nil {
		t.Fatalf("precommit: %v", err)
	}
	if commitPlan.ManifestHash() == "" || commitPlan.AuthorityHash() == "" || commitPlan.RealBaselineIdentity() == "" || commitPlan.RealMode() != 0o600 {
		t.Fatalf("incomplete real commit authority: %#v", commitPlan)
	}
	if err := lifecycle.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if lifecycle.State() != StateCommitted {
		t.Fatalf("state = %s, want COMMITTED", lifecycle.State())
	}
	realREADME := filepath.Join(disposable.RealWorkspace(), "README.md")
	contents, err := os.ReadFile(realREADME)
	if err != nil || string(contents) != "authorized update\n" {
		t.Fatalf("real contents = %q, %v", contents, err)
	}
	info, err := os.Lstat(realREADME)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("real mode = %v, %v", info, err)
	}
	entries, err := os.ReadDir(disposable.RealWorkspace())
	if err != nil || len(entries) != 1 || entries[0].Name() != "README.md" {
		t.Fatalf("real workspace entries = %v, %v", entries, err)
	}
}

func TestLifecycleRejectsRealChangeImmediatelyBeforeCommit(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	lifecycle, disposable := verifiedContentLifecycle(t, func() time.Time { return now }, now.Add(time.Hour))
	if _, err := lifecycle.PreCommit(); err != nil {
		t.Fatal(err)
	}
	realREADME := filepath.Join(disposable.RealWorkspace(), "README.md")
	if err := os.WriteFile(realREADME, []byte("external winner"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Commit(); !errors.Is(err, ErrRealStateConflict) {
		t.Fatalf("commit error = %v, want real-state conflict", err)
	}
	if lifecycle.State() != StateConflicted {
		t.Fatalf("state = %s, want CONFLICTED", lifecycle.State())
	}
	contents, err := os.ReadFile(realREADME)
	if err != nil || string(contents) != "external winner" {
		t.Fatalf("conflict overwrote reality: %q, %v", contents, err)
	}
}

func TestLifecycleRejectsShadowChangeAfterVerification(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	for _, afterPrecommit := range []bool{false, true} {
		name := "before precommit"
		if afterPrecommit {
			name = "immediately before commit"
		}
		t.Run(name, func(t *testing.T) {
			lifecycle, disposable := verifiedContentLifecycle(t, func() time.Time { return now }, now.Add(time.Hour))
			if afterPrecommit {
				if _, err := lifecycle.PreCommit(); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("shadow tamper"), 0o666); err != nil {
				t.Fatal(err)
			}
			var err error
			if afterPrecommit {
				err = lifecycle.Commit()
			} else {
				_, err = lifecycle.PreCommit()
			}
			if !errors.Is(err, ErrShadowChanged) {
				t.Fatalf("shadow tamper error = %v", err)
			}
			if lifecycle.State() != StateRejected {
				t.Fatalf("state = %s, want REJECTED", lifecycle.State())
			}
			assertRealREADME(t, disposable, "before", 0o600)
		})
	}
}

func TestLifecycleRejectsExpiredOrRolledBackClockBeforeCommit(t *testing.T) {
	base := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	t.Run("expired", func(t *testing.T) {
		current := base
		lifecycle, disposable := verifiedContentLifecycle(t, func() time.Time { return current }, base.Add(time.Minute))
		current = base.Add(2 * time.Minute)
		if _, err := lifecycle.PreCommit(); !errors.Is(err, ErrContractExpired) {
			t.Fatalf("precommit error = %v", err)
		}
		if lifecycle.State() != StateRejected {
			t.Fatalf("state = %s, want REJECTED", lifecycle.State())
		}
		assertRealREADME(t, disposable, "before", 0o600)
	})
	t.Run("rollback immediately before commit", func(t *testing.T) {
		current := base
		lifecycle, disposable := verifiedContentLifecycle(t, func() time.Time { return current }, base.Add(time.Hour))
		if _, err := lifecycle.PreCommit(); err != nil {
			t.Fatal(err)
		}
		current = base.Add(-time.Second)
		if err := lifecycle.Commit(); !errors.Is(err, ErrClockRollback) {
			t.Fatalf("commit error = %v", err)
		}
		if lifecycle.State() != StateFailed {
			t.Fatalf("state = %s, want FAILED", lifecycle.State())
		}
		assertRealREADME(t, disposable, "before", 0o600)
	})
}

func TestLifecycleRechecksTrustedTimeImmediatelyBeforeReplacement(t *testing.T) {
	base := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	t.Run("expires during apply", func(t *testing.T) {
		clock := sequenceClock(t,
			base,                    // manifest
			base,                    // prepare
			base,                    // start
			base,                    // freeze
			base,                    // reconcile
			base,                    // precommit
			base,                    // commit derivation
			base.Add(2*time.Minute), // immediately before rename
		)
		lifecycle, disposable := verifiedContentLifecycle(t, clock, base.Add(time.Minute))
		if _, err := lifecycle.PreCommit(); err != nil {
			t.Fatal(err)
		}
		if err := lifecycle.Commit(); !errors.Is(err, ErrContractExpired) {
			t.Fatalf("commit error = %v, want replacement-time expiry", err)
		}
		if lifecycle.State() != StateRejected {
			t.Fatalf("state = %s, want REJECTED", lifecycle.State())
		}
		assertRealREADME(t, disposable, "before", 0o600)
		assertNoLifecycleStaging(t, disposable.RealWorkspace())
	})
	t.Run("rolls back during apply", func(t *testing.T) {
		clock := sequenceClock(t,
			base,                   // manifest
			base,                   // prepare
			base,                   // start
			base,                   // freeze
			base,                   // reconcile
			base,                   // precommit
			base,                   // commit derivation
			base.Add(-time.Second), // immediately before rename
		)
		lifecycle, disposable := verifiedContentLifecycle(t, clock, base.Add(time.Hour))
		if _, err := lifecycle.PreCommit(); err != nil {
			t.Fatal(err)
		}
		if err := lifecycle.Commit(); !errors.Is(err, ErrClockRollback) {
			t.Fatalf("commit error = %v, want replacement-time rollback", err)
		}
		if lifecycle.State() != StateFailed {
			t.Fatalf("state = %s, want FAILED", lifecycle.State())
		}
		assertRealREADME(t, disposable, "before", 0o600)
		assertNoLifecycleStaging(t, disposable.RealWorkspace())
	})
}

func TestCommitFailureStateCleanupAndUncertaintyDominateSemanticOutcome(t *testing.T) {
	cleanup := fmt.Errorf("%w: remove staging", realcommit.ErrCleanup)
	for _, test := range []struct {
		name string
		err  error
	}{
		{
			name: "expired plus cleanup failure",
			err:  errors.Join(ErrContractExpired, cleanup),
		},
		{
			name: "conflict plus cleanup failure",
			err:  errors.Join(ErrRealStateConflict, cleanup),
		},
		{
			name: "conflict plus revalidation uncertainty",
			err:  errors.Join(realcommit.ErrConflict, realcommit.ErrRevalidation),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if state := commitFailureState(test.err); state != StateFailed {
				t.Fatalf("state = %s, want FAILED for %v", state, test.err)
			}
		})
	}
	if state := commitFailureState(ErrContractExpired); state != StateRejected {
		t.Fatalf("clean expiry state = %s, want REJECTED", state)
	}
	if state := commitFailureState(realcommit.ErrConflict); state != StateConflicted {
		t.Fatalf("clean conflict state = %s, want CONFLICTED", state)
	}
}

func TestLifecycleRejectsTwoFileCommitPlanWithoutTouchingReality(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	lifecycle, disposable := boundLifecycleWithSetup(t, func() time.Time { return now }, now.Add(time.Hour), func(t *testing.T, real string) {
		writeLifecycleFile(t, real, "README.md", "before", 0o600)
		writeLifecycleFile(t, real, "notes.txt", "notes before", 0o640)
	}, "/workspace/README.md", "/workspace/notes.txt")
	runToStarted(t, lifecycle)
	writeLifecycleFile(t, disposable.Path(), "README.md", "after", 0o666)
	writeLifecycleFile(t, disposable.Path(), "notes.txt", "notes after", 0o666)
	if err := lifecycle.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	decision, err := lifecycle.Reconcile()
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed || lifecycle.State() != StateRejected {
		t.Fatalf("decision = %#v, state = %s", decision, lifecycle.State())
	}
	assertRealREADME(t, disposable, "before", 0o600)
	contents, err := os.ReadFile(filepath.Join(disposable.RealWorkspace(), "notes.txt"))
	if err != nil || string(contents) != "notes before" {
		t.Fatalf("real notes = %q, %v", contents, err)
	}
}

func verifiedContentLifecycle(t *testing.T, now func() time.Time, expires time.Time) (*Lifecycle, *workspace.Disposable) {
	t.Helper()
	lifecycle, disposable := boundLifecycle(t, now, expires, "/workspace/README.md")
	runToStarted(t, lifecycle)
	if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("authorized update"), 0o666); err != nil {
		t.Fatal(err)
	}
	freezeAndVerify(t, lifecycle)
	return lifecycle, disposable
}

func runToStarted(t *testing.T, lifecycle *Lifecycle) {
	t.Helper()
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func freezeAndVerify(t *testing.T, lifecycle *Lifecycle) {
	t.Helper()
	if err := lifecycle.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	decision, err := lifecycle.Reconcile()
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed || lifecycle.State() != StateVerified {
		t.Fatalf("decision = %#v, state = %s", decision, lifecycle.State())
	}
}

func assertRealREADME(t *testing.T, disposable *workspace.Disposable, contents string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(disposable.RealWorkspace(), "README.md")
	observed, err := os.ReadFile(path)
	if err != nil || string(observed) != contents {
		t.Fatalf("real README = %q, %v", observed, err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != mode {
		t.Fatalf("real README mode = %v, %v", info, err)
	}
}

func assertNoLifecycleStaging(t *testing.T, root string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(root, workspace.CommitStagingPrefix+"*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("commit staging remains after denied replacement: %v", matches)
	}
}

func frozenLifecycle(t *testing.T) (*Lifecycle, *workspace.Disposable) {
	t.Helper()
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	lifecycle, disposable := boundLifecycle(t, func() time.Time { return now }, now.Add(time.Hour))
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	return lifecycle, disposable
}

func boundLifecycle(t *testing.T, now func() time.Time, expires time.Time, allow ...string) (*Lifecycle, *workspace.Disposable) {
	t.Helper()
	return boundLifecycleWithSetup(t, now, expires, func(t *testing.T, real string) {
		writeLifecycleFile(t, real, "README.md", "before", 0o600)
	}, allow...)
}

func boundLifecycleWithSetup(t *testing.T, now func() time.Time, expires time.Time, setup func(*testing.T, string), allow ...string) (*Lifecycle, *workspace.Disposable) {
	t.Helper()
	real := lifecycleRealWorkspace(t)
	setup(t, real)
	disposable, err := workspace.Prepare(real)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := disposable.Cleanup(); err != nil {
			t.Errorf("cleanup disposable: %v", err)
		}
	})
	binding, err := disposable.Binding()
	if err != nil {
		t.Fatal(err)
	}
	stub := &sandboxStub{
		real:       binding.RealWorkspace(),
		disposable: binding.DisposableWorkspace(),
		token:      binding.Token(),
	}
	manifest, err := NewRunManifest(lifecycleContract(t, expires, allow...), binding, stub, now)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := NewBoundLifecycle(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return lifecycle, disposable
}

func writeLifecycleFile(t *testing.T, root, relative, contents string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(root, relative)
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func lifecycleRealWorkspace(t *testing.T) string {
	t.Helper()
	base, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(base, ".mirage-lifecycle-real-")
	if err != nil {
		t.Fatal(err)
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(absolute); err != nil {
			t.Errorf("cleanup real fixture: %v", err)
		}
	})
	return absolute
}

func sequenceClock(t *testing.T, readings ...time.Time) func() time.Time {
	t.Helper()
	index := 0
	return func() time.Time {
		if index >= len(readings) {
			t.Fatalf("trusted clock read %d exceeds %d deterministic readings", index+1, len(readings))
		}
		reading := readings[index]
		index++
		return reading
	}
}

func lifecycleContract(t *testing.T, expires time.Time, allow ...string) *contracts.Contract {
	t.Helper()
	contract, err := contracts.New(contracts.Spec{
		Version:   contracts.VersionV1,
		RunID:     "lifecycle-test",
		ActorID:   "hostile-fixture",
		ExpiresAt: expires,
		Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{
			Allow: allow,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return contract
}

func boundGitLifecycle(t *testing.T) (*Lifecycle, *workspace.Disposable, string) {
	t.Helper()
	now := time.Date(2026, 8, 28, 18, 0, 0, 0, time.UTC)
	real := lifecycleRealWorkspace(t)
	runLifecycleGit(t, real, "init", "-b", "main")
	writeLifecycleFile(t, real, "README.md", "before\n", 0o600)
	runLifecycleGit(t, real, "add", "--", "README.md")
	runLifecycleGit(t, real, "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "-m", "initial")
	disposable, err := workspace.Prepare(real)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := disposable.Cleanup(); err != nil {
			t.Errorf("cleanup disposable: %v", err)
		}
	})
	binding, err := disposable.Binding()
	if err != nil {
		t.Fatal(err)
	}
	stub := &sandboxStub{real: binding.RealWorkspace(), disposable: binding.DisposableWorkspace(), token: binding.Token()}
	manifest, err := NewRunManifest(lifecycleContract(t, now.Add(time.Hour), "/workspace/README.md"), binding, stub, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := NewBoundLifecycle(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return lifecycle, disposable, filepath.Join(real, ".git")
}

func preparedGitArtifactLifecycle(t *testing.T, now func() time.Time, expires time.Time) (*Lifecycle, *workspace.Disposable, string) {
	t.Helper()
	real := lifecycleRealWorkspace(t)
	runLifecycleGit(t, real, "init", "-b", "main")
	writeLifecycleFile(t, real, "README.md", "before\n", 0o600)
	runLifecycleGit(t, real, "add", "--", "README.md")
	runLifecycleGit(t, real, "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "-m", "initial")
	disposable, err := workspace.Prepare(real)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := disposable.Cleanup(); err != nil {
			t.Errorf("cleanup disposable: %v", err)
		}
	})
	binding, err := disposable.Binding()
	if err != nil {
		t.Fatal(err)
	}
	stub := &sandboxStub{real: binding.RealWorkspace(), disposable: binding.DisposableWorkspace(), token: binding.Token()}
	manifest, err := NewRunManifest(lifecycleContract(t, expires, "/workspace/README.md"), binding, stub, now)
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
	runToStarted(t, lifecycle)
	if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("verified Git artifact\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	freezeAndVerify(t, lifecycle)
	if _, err := lifecycle.DeriveGitEffectPlan(); err != nil {
		t.Fatal(err)
	}
	return lifecycle, disposable, filepath.Join(real, ".git")
}

func runLifecycleGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v (%s)", args, err, output)
	}
	return strings.TrimSpace(string(output))
}
