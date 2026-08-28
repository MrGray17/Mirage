// Package runtime coordinates the lifecycle of an untrusted process sandbox
// through trusted frozen-tree reconciliation, the narrow M4.3 real commit,
// M5.1's read-only Git authority planning, and M5.2's transaction-only commit
// construction.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/MrGray17/Mirage/internal/runtime/gitbinding"
	"github.com/MrGray17/Mirage/internal/runtime/gitcommit"
	"github.com/MrGray17/Mirage/internal/runtime/gitplan"
	"github.com/MrGray17/Mirage/internal/runtime/realcommit"
	"github.com/MrGray17/Mirage/internal/runtime/reconcile"
	"github.com/MrGray17/Mirage/internal/runtime/tree"
	"github.com/MrGray17/Mirage/internal/trustedtime"
)

var (
	ErrInvalidRuntime    = errors.New("invalid hostile runtime")
	ErrInvalidTransition = errors.New("invalid hostile runtime transition")
	ErrTrustedTime       = trustedtime.ErrUnavailable
	ErrClockRollback     = trustedtime.ErrRollback
	ErrContractExpired   = errors.New("hostile run contract expired")
	ErrRealStateConflict = errors.New("real workspace baseline conflict")
	ErrShadowChanged     = errors.New("verified frozen shadow changed")
	ErrCommitAuthority   = errors.New("verified commit authority changed")
	ErrUnsupportedCommit = errors.New("unsupported M4.3 commit plan")
)

type ClockRollbackError = trustedtime.RollbackError

// State is the trusted lifecycle state of one hostile runtime.
type State uint8

const (
	StateCreated State = iota + 1
	StatePreparing
	StateRunning
	StateFreezing
	StateFrozen
	StateReconciling
	StateVerified
	StatePrecommitting
	StateCommitReady
	StateCommitting
	StateCommitted
	StateConflicted
	StateRejected
	StateFailed
)

func (s State) String() string {
	switch s {
	case StateCreated:
		return "CREATED"
	case StatePreparing:
		return "PREPARING"
	case StateRunning:
		return "RUNNING"
	case StateFreezing:
		return "FREEZING"
	case StateFrozen:
		return "FROZEN"
	case StateReconciling:
		return "RECONCILING"
	case StateVerified:
		return "VERIFIED"
	case StatePrecommitting:
		return "PRECOMMITTING"
	case StateCommitReady:
		return "COMMIT_READY"
	case StateCommitting:
		return "COMMITTING"
	case StateCommitted:
		return "COMMITTED"
	case StateConflicted:
		return "CONFLICTED"
	case StateRejected:
		return "REJECTED"
	case StateFailed:
		return "FAILED"
	default:
		return "UNKNOWN"
	}
}

// Sandbox is the narrow M4.1 process-isolation boundary. Freeze must return nil
// only after it has independently established that the sandbox process tree can
// no longer mutate the workspace.
type Sandbox interface {
	Identity() string
	BoundWorkspace() (realWorkspace, disposableWorkspace, token string)
	Prepare(context.Context) error
	Start(context.Context) error
	Freeze(context.Context) error
	Destroy(context.Context) error
}

// Lifecycle serializes sandbox actions with trusted state transitions.
type Lifecycle struct {
	mu                  sync.Mutex
	sandbox             Sandbox
	clock               *trustedtime.Clock
	state               State
	plan                *tree.Plan
	decision            reconcile.Decision
	manifest            *RunManifest
	commitPlan          *realcommit.Plan
	gitBinding          *gitbinding.Binding
	gitPlan             *gitplan.Plan
	gitArtifact         *gitcommit.Artifact
	gitArtifactIdentity string
	gitCleanupArtifact  *gitcommit.Artifact

	// Test-only fault points remain nil in production. They exercise the final
	// authority and cleanup rules without widening any public capability.
	afterGitConstruction func()
	cleanupGitArtifact   func(*gitcommit.Artifact) error
}

// BindGitRepository captures the exact trusted repository underlying the real
// workspace. It is permitted only before sandbox preparation, so hostile
// execution can never choose or refresh Git authority.
func (l *Lifecycle) BindGitRepository() (*gitbinding.Binding, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.require(StateCreated, "bind Git repository"); err != nil {
		return nil, err
	}
	if l.manifest == nil || l.manifest.identity == "" {
		return nil, fmt.Errorf("%w: Git authority requires a bound run manifest", ErrInvalidManifest)
	}
	if l.gitBinding != nil {
		return nil, fmt.Errorf("%w: Git repository is already bound", ErrInvalidTransition)
	}
	if err := l.validateManifest(); err != nil {
		return nil, err
	}
	if err := l.requireManifestRealBaseline(); err != nil {
		return nil, err
	}
	at, err := l.clock.Observe()
	if err != nil {
		return nil, fmt.Errorf("observe trusted time before Git binding: %w", err)
	}
	binding, err := gitbinding.Capture(l.manifest.workspace.RealWorkspace(), l.manifest.identity, at)
	if err != nil {
		return nil, fmt.Errorf("bind trusted Git repository: %w", err)
	}
	if err := l.requireManifestRealBaseline(); err != nil {
		return nil, err
	}
	l.gitBinding = binding
	return binding, nil
}

func NewLifecycle(sandbox Sandbox) (*Lifecycle, error) {
	return NewLifecycleWithClock(sandbox, time.Now)
}

// NewLifecycleWithClock constructs one hostile lifecycle with one wall-time
// authority. The injected source exists for deterministic security tests; all
// lifecycle observations share the same greatest-observed-time guard.
func NewLifecycleWithClock(sandbox Sandbox, now func() time.Time) (*Lifecycle, error) {
	if sandbox == nil {
		return nil, fmt.Errorf("%w: sandbox is required", ErrInvalidRuntime)
	}
	clock, err := trustedtime.New(now)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRuntime, err)
	}
	if _, err := clock.Observe(); err != nil {
		return nil, fmt.Errorf("%w: establish trusted start time: %w", ErrInvalidRuntime, err)
	}
	return &Lifecycle{sandbox: sandbox, clock: clock, state: StateCreated}, nil
}

// NewBoundLifecycle creates the authority-bearing M4.3 lifecycle. All later
// security operations derive their inputs exclusively from the manifest.
func NewBoundLifecycle(manifest *RunManifest) (*Lifecycle, error) {
	if manifest == nil || manifest.identity == "" || manifest.clock == nil || manifest.sandbox == nil {
		return nil, fmt.Errorf("%w: complete run manifest is required", ErrInvalidRuntime)
	}
	if err := manifest.validateSandbox(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRuntime, err)
	}
	return &Lifecycle{
		sandbox:  manifest.sandbox,
		clock:    manifest.clock,
		state:    StateCreated,
		manifest: manifest,
	}, nil
}

func (l *Lifecycle) State() State {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.state
}

// Prepare validates the isolation backend and creates, but does not start, the
// hostile sandbox. Success intentionally leaves the lifecycle PREPARING until
// Start proves the process was launched.
func (l *Lifecycle) Prepare(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.require(StateCreated, "prepare"); err != nil {
		return err
	}
	l.state = StatePreparing
	if err := l.validateManifest(); err != nil {
		l.state = StateFailed
		return err
	}
	if _, err := l.clock.Observe(); err != nil {
		l.state = StateFailed
		return fmt.Errorf("observe trusted time before prepare: %w", err)
	}
	if err := l.sandbox.Prepare(ctx); err != nil {
		l.state = StateFailed
		return fmt.Errorf("prepare hostile sandbox: %w", err)
	}
	return nil
}

// Start launches the hostile process. A failed or uncertain launch is terminal
// for authorization: callers may destroy the sandbox, but may not reconcile it.
func (l *Lifecycle) Start(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.require(StatePreparing, "start"); err != nil {
		return err
	}
	if err := l.validateManifest(); err != nil {
		l.state = StateFailed
		return err
	}
	if _, err := l.clock.Observe(); err != nil {
		l.state = StateFailed
		return fmt.Errorf("observe trusted time before start: %w", err)
	}
	if err := l.sandbox.Start(ctx); err != nil {
		l.state = StateFailed
		return fmt.Errorf("start hostile sandbox: %w", err)
	}
	l.state = StateRunning
	return nil
}

// Freeze stops the entire sandbox process tree and obtains the backend's stop
// proof. A failure can never be represented as FROZEN.
func (l *Lifecycle) Freeze(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.require(StateRunning, "freeze"); err != nil {
		return err
	}
	l.state = StateFreezing
	manifestErr := l.validateManifest()
	_, timeErr := l.clock.Observe()
	freezeErr := l.sandbox.Freeze(ctx)
	if manifestErr != nil || timeErr != nil || freezeErr != nil {
		l.state = StateFailed
		var trustedErr error
		if timeErr != nil {
			trustedErr = fmt.Errorf("observe trusted time before freeze: %w", timeErr)
		}
		var sandboxErr error
		if freezeErr != nil {
			sandboxErr = fmt.Errorf("freeze hostile sandbox: %w", freezeErr)
		}
		return errors.Join(manifestErr, trustedErr, sandboxErr)
	}
	l.state = StateFrozen
	return nil
}

// Reconcile is the only path from FROZEN to VERIFIED. Scanner or acquisition
// uncertainty is terminal FAILED; an established policy denial is REJECTED.
func (l *Lifecycle) Reconcile() (reconcile.Decision, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.require(StateFrozen, "reconcile"); err != nil {
		return reconcile.Decision{}, err
	}
	l.state = StateReconciling
	if l.manifest == nil {
		l.state = StateFailed
		return reconcile.Decision{}, fmt.Errorf("%w: reconciliation requires a bound run manifest", ErrInvalidManifest)
	}
	if err := l.validateManifest(); err != nil {
		l.state = StateFailed
		return reconcile.Decision{}, err
	}
	at, err := l.clock.Observe()
	if err != nil {
		l.state = StateFailed
		return reconcile.Decision{}, fmt.Errorf("observe trusted time before reconciliation: %w", err)
	}
	plan, decision, err := reconcile.Verify(
		l.manifest.identity,
		l.manifest.workspace.DisposableBaseline(),
		l.manifest.workspace.DisposableWorkspace(),
		l.manifest.contract,
		at,
	)
	if err != nil {
		l.state = StateFailed
		return reconcile.Decision{}, fmt.Errorf("reconcile hostile workspace: %w", err)
	}
	l.plan = plan
	l.decision = decision
	if decision.Allowed {
		l.state = StateVerified
	} else {
		l.state = StateRejected
	}
	return decision, nil
}

func (l *Lifecycle) validateManifest() error {
	if l.manifest == nil {
		return nil
	}
	if l.manifest.contract == nil || l.manifest.contract.Hash() != l.declaredContractHash() {
		return fmt.Errorf("%w: contract binding changed", ErrInvalidManifest)
	}
	if err := l.manifest.validateSandbox(); err != nil {
		return err
	}
	return nil
}

func (l *Lifecycle) declaredContractHash() string {
	if l.manifest == nil {
		return ""
	}
	return l.manifest.ContractHash()
}

// Reconciliation returns immutable plan and decision evidence, if scanning
// completed. The plan's contents are exposed only through defensive copies.
func (l *Lifecycle) Reconciliation() (*tree.Plan, reconcile.Decision) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.plan, l.decision
}

// DeriveGitEffectPlan creates immutable M5.1 data from the already-verified
// reconciliation. It neither mutates Git nor changes the runtime lifecycle.
func (l *Lifecycle) DeriveGitEffectPlan() (*gitplan.Plan, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.require(StateVerified, "derive Git effect plan"); err != nil {
		return nil, err
	}
	if l.manifest == nil || l.gitBinding == nil || l.plan == nil || !l.decision.Allowed {
		return nil, fmt.Errorf("%w: verified Git planning authority is incomplete", ErrCommitAuthority)
	}
	if err := l.validateManifest(); err != nil {
		return nil, err
	}
	at, err := l.clock.Observe()
	if err != nil {
		return nil, fmt.Errorf("observe trusted time before Git planning: %w", err)
	}
	if l.gitPlan != nil {
		if err := gitplan.Revalidate(l.gitPlan, l.manifest.identity, l.manifest.contract, l.gitBinding, l.plan, l.decision, at); err != nil {
			l.state = gitPlanFailureState(err)
			return nil, fmt.Errorf("revalidate existing deferred Git plan: %w", err)
		}
		return l.gitPlan, nil
	}
	plan, err := gitplan.New(gitplan.Spec{
		RunID:              l.manifest.RunID(),
		ManifestHash:       l.manifest.identity,
		Contract:           l.manifest.contract,
		Repository:         l.gitBinding,
		ReconciliationPlan: l.plan,
		Decision:           l.decision,
		CreatedAt:          at,
	})
	if err != nil {
		l.state = gitPlanFailureState(err)
		return nil, fmt.Errorf("derive deferred Git plan: %w", err)
	}
	l.gitPlan = plan
	return plan, nil
}

// RevalidateGitEffectPlan repeats repository, manifest, reconciliation, and
// trusted-time checks without regenerating stale authority.
func (l *Lifecycle) RevalidateGitEffectPlan() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.require(StateVerified, "revalidate Git effect plan"); err != nil {
		return err
	}
	if l.manifest == nil || l.gitBinding == nil || l.gitPlan == nil || l.plan == nil {
		return fmt.Errorf("%w: deferred Git plan is unavailable", ErrCommitAuthority)
	}
	if err := l.validateManifest(); err != nil {
		return err
	}
	at, err := l.clock.Observe()
	if err != nil {
		return fmt.Errorf("observe trusted time before Git plan revalidation: %w", err)
	}
	if err := gitplan.Revalidate(l.gitPlan, l.manifest.identity, l.manifest.contract, l.gitBinding, l.plan, l.decision, at); err != nil {
		l.state = gitPlanFailureState(err)
		return fmt.Errorf("revalidate deferred Git plan: %w", err)
	}
	return nil
}

func (l *Lifecycle) GitRepositoryBinding() *gitbinding.Binding {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.gitBinding
}

func (l *Lifecycle) GitEffectPlan() *gitplan.Plan {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.gitPlan
}

// ConstructGitCommitArtifact builds one deterministic candidate commit in
// transaction-owned storage. It neither updates nor writes any real Git state.
// Repeated calls revalidate and return the same immutable artifact.
func (l *Lifecycle) ConstructGitCommitArtifact() (*gitcommit.Artifact, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.require(StateVerified, "construct deterministic Git commit"); err != nil {
		return nil, err
	}
	if l.manifest == nil || l.gitBinding == nil || l.gitPlan == nil || l.plan == nil || !l.decision.Allowed {
		return nil, fmt.Errorf("%w: verified Git construction authority is incomplete", ErrCommitAuthority)
	}
	at, err := l.clock.Observe()
	if err != nil {
		l.state = StateFailed
		return nil, fmt.Errorf("observe trusted time before Git construction: %w", err)
	}
	freshPlan, err := l.revalidateGitConstructionAuthority(at)
	if err != nil {
		l.state = gitCommitFailureState(err)
		return nil, err
	}
	spec := l.gitCommitSpec(freshPlan, at)
	if l.gitArtifact != nil {
		if err := gitcommit.Revalidate(l.gitArtifact, spec); err != nil {
			return nil, l.discardGitArtifact(fmt.Errorf("revalidate existing Git commit artifact: %w", err))
		}
		return l.gitArtifact, nil
	}
	if l.gitArtifactIdentity != "" {
		return nil, fmt.Errorf("%w: lifecycle already minted and cleaned its Git commit artifact", ErrInvalidTransition)
	}

	artifact, err := gitcommit.Construct(spec)
	if err != nil {
		l.state = gitCommitFailureState(err)
		return nil, fmt.Errorf("construct deterministic Git commit: %w", err)
	}
	if l.afterGitConstruction != nil {
		l.afterGitConstruction()
	}
	finalAt, err := l.clock.Observe()
	if err != nil {
		return nil, l.discardSpecificGitArtifact(artifact, fmt.Errorf("observe trusted time after Git construction: %w", err))
	}
	finalPlan, err := l.revalidateGitConstructionAuthority(finalAt)
	if err != nil {
		return nil, l.discardSpecificGitArtifact(artifact, err)
	}
	if err := gitcommit.Revalidate(artifact, l.gitCommitSpec(finalPlan, finalAt)); err != nil {
		return nil, l.discardSpecificGitArtifact(artifact, fmt.Errorf("final Git commit artifact revalidation: %w", err))
	}
	l.gitArtifact = artifact
	l.gitArtifactIdentity = artifact.Identity()
	return artifact, nil
}

// RevalidateGitCommitArtifact proves that the existing transaction objects and
// every upstream authority are still current without regenerating authority.
func (l *Lifecycle) RevalidateGitCommitArtifact() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.require(StateVerified, "revalidate deterministic Git commit"); err != nil {
		return err
	}
	if l.gitArtifact == nil {
		return fmt.Errorf("%w: Git commit artifact is unavailable", ErrCommitAuthority)
	}
	at, err := l.clock.Observe()
	if err != nil {
		l.state = StateFailed
		return fmt.Errorf("observe trusted time before artifact revalidation: %w", err)
	}
	freshPlan, err := l.revalidateGitConstructionAuthority(at)
	if err != nil {
		return l.discardGitArtifact(err)
	}
	if err := gitcommit.Revalidate(l.gitArtifact, l.gitCommitSpec(freshPlan, at)); err != nil {
		return l.discardGitArtifact(fmt.Errorf("revalidate deterministic Git commit: %w", err))
	}
	return nil
}

func (l *Lifecycle) GitCommitArtifact() *gitcommit.Artifact {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.gitArtifact
}

// CleanupGitCommitArtifact explicitly destroys retained M5.2 transaction
// state. Cleanup uncertainty is terminal and never hidden by semantic errors.
func (l *Lifecycle) CleanupGitCommitArtifact() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	artifact := l.gitArtifact
	if artifact == nil {
		artifact = l.gitCleanupArtifact
	}
	if artifact == nil {
		return nil
	}
	if err := l.cleanupArtifact(artifact); err != nil {
		l.retainCleanupOnly(artifact)
		l.state = StateFailed
		return err
	}
	if l.gitArtifact == artifact {
		l.gitArtifact = nil
	}
	if l.gitCleanupArtifact == artifact {
		l.gitCleanupArtifact = nil
	}
	return nil
}

func (l *Lifecycle) revalidateGitConstructionAuthority(at time.Time) (*tree.Plan, error) {
	if l.manifest == nil || l.manifest.contract == nil || l.gitBinding == nil || l.gitPlan == nil || l.plan == nil || at.IsZero() {
		return nil, fmt.Errorf("%w: Git construction authority is incomplete", ErrCommitAuthority)
	}
	if err := l.validateManifest(); err != nil {
		return nil, err
	}
	if l.manifest.contract.ExpiredAt(at) {
		return nil, fmt.Errorf("%w: %s", ErrContractExpired, l.manifest.contract.ExpiresAt().Format(time.RFC3339Nano))
	}
	if err := gitplan.Revalidate(l.gitPlan, l.manifest.identity, l.manifest.contract, l.gitBinding, l.plan, l.decision, at); err != nil {
		return nil, fmt.Errorf("revalidate Git effect plan before construction: %w", err)
	}
	realNow, err := l.manifest.workspace.ObserveReal()
	if err != nil {
		return nil, fmt.Errorf("revalidate complete real baseline before Git construction: %w", err)
	}
	realBaseline := l.manifest.workspace.RealBaseline()
	if realBaseline == nil || realNow.Identity() != realBaseline.Identity() {
		return nil, fmt.Errorf("%w: M4 real baseline changed before Git construction", ErrRealStateConflict)
	}
	shadowNow, err := l.manifest.workspace.ObserveDisposable()
	if err != nil {
		return nil, fmt.Errorf("revalidate frozen shadow before Git construction: %w", err)
	}
	if shadowNow.Identity() != l.plan.FinalIdentity() {
		return nil, fmt.Errorf("%w: expected final %s, observed %s", ErrShadowChanged, l.plan.FinalIdentity(), shadowNow.Identity())
	}
	recomputed, err := tree.Diff(l.manifest.workspace.DisposableBaseline(), shadowNow)
	if err != nil {
		return nil, fmt.Errorf("recompute frozen Git construction plan: %w", err)
	}
	if recomputed.Hash() != l.plan.Hash() {
		return nil, fmt.Errorf("%w: verified and current reconciliation plans differ", ErrCommitAuthority)
	}
	if err := gitplan.Revalidate(l.gitPlan, l.manifest.identity, l.manifest.contract, l.gitBinding, recomputed, l.decision, at); err != nil {
		return nil, fmt.Errorf("revalidate current Git construction effect: %w", err)
	}
	return recomputed, nil
}

func (l *Lifecycle) gitCommitSpec(plan *tree.Plan, at time.Time) gitcommit.Spec {
	return gitcommit.Spec{
		ManifestHash: l.manifest.identity, Contract: l.manifest.contract, Repository: l.gitBinding,
		GitPlan: l.gitPlan, ReconciliationPlan: plan, Decision: l.decision, ObservedAt: at,
	}
}

func (l *Lifecycle) cleanupArtifact(artifact *gitcommit.Artifact) error {
	if l.cleanupGitArtifact != nil {
		return l.cleanupGitArtifact(artifact)
	}
	return artifact.Cleanup()
}

func (l *Lifecycle) retainCleanupOnly(artifact *gitcommit.Artifact) {
	if l.gitArtifact == artifact {
		l.gitArtifact = nil
	}
	l.gitCleanupArtifact = artifact
}

func (l *Lifecycle) discardSpecificGitArtifact(artifact *gitcommit.Artifact, cause error) error {
	cleanupErr := l.cleanupArtifact(artifact)
	if cleanupErr != nil {
		l.retainCleanupOnly(artifact)
	}
	result := errors.Join(cause, cleanupErr)
	l.state = gitCommitFailureState(result)
	return result
}

func (l *Lifecycle) discardGitArtifact(cause error) error {
	artifact := l.gitArtifact
	l.gitArtifact = nil
	return l.discardSpecificGitArtifact(artifact, cause)
}

func (l *Lifecycle) requireManifestRealBaseline() error {
	current, err := l.manifest.workspace.ObserveReal()
	if err != nil {
		l.state = StateFailed
		return fmt.Errorf("revalidate M4 real baseline for Git authority: %w", err)
	}
	expected := l.manifest.workspace.RealBaseline()
	if expected == nil || current.Identity() != expected.Identity() {
		l.state = StateConflicted
		return fmt.Errorf("%w: M4 real baseline changed before Git authority binding", ErrRealStateConflict)
	}
	return nil
}

// PreCommit derives the one explicit real-world mutation without applying it.
// It is safe to call only after authoritative frozen-tree verification.
func (l *Lifecycle) PreCommit() (*realcommit.Plan, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.require(StateVerified, "precommit"); err != nil {
		return nil, err
	}
	if l.gitArtifact != nil || l.gitArtifactIdentity != "" {
		return nil, fmt.Errorf("%w: lifecycle already selected the deferred Git path", ErrInvalidTransition)
	}
	l.state = StatePrecommitting
	plan, err := l.deriveRealCommitPlan()
	if err != nil {
		l.state = commitFailureState(err)
		return nil, err
	}
	l.commitPlan = plan
	l.state = StateCommitReady
	return plan, nil
}

// Commit repeats every authority and freshness check immediately before the
// first real mutation, then applies only the derived single-file plan.
func (l *Lifecycle) Commit() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.require(StateCommitReady, "commit"); err != nil {
		return err
	}
	l.state = StateCommitting
	fresh, err := l.deriveRealCommitPlan()
	if err != nil {
		l.state = commitFailureState(err)
		return err
	}
	if l.commitPlan == nil || fresh.Hash() != l.commitPlan.Hash() {
		l.state = StateRejected
		return fmt.Errorf("%w: precommit plan identity changed", ErrCommitAuthority)
	}
	if err := realcommit.Apply(fresh, func() error { return l.finalCommitAuthority(fresh) }); err != nil {
		l.state = commitFailureState(err)
		return fmt.Errorf("apply real commit plan: %w", err)
	}
	l.state = StateCommitted
	return nil
}

// finalCommitAuthority is called by the applier after all target and staging
// work and at the last possible point before the real directory entry changes.
func (l *Lifecycle) finalCommitAuthority(plan *realcommit.Plan) error {
	at, err := l.clock.Observe()
	if err != nil {
		return fmt.Errorf("observe trusted time immediately before replacement: %w", err)
	}
	if l.manifest == nil || l.manifest.contract == nil || l.manifest.contract.ExpiredAt(at) {
		return fmt.Errorf("%w: authority is not valid at replacement time", ErrContractExpired)
	}
	if err := l.validateManifest(); err != nil {
		return err
	}
	if l.plan == nil || !l.decision.BoundTo(l.manifest.identity, l.manifest.contractHash, l.plan.Hash()) {
		return fmt.Errorf("%w: final manifest, contract, plan, or authority hash mismatch", ErrCommitAuthority)
	}
	if plan == nil || plan.ManifestHash() != l.manifest.identity || plan.AuthorityHash() != l.decision.AuthorityHash || plan.RealBaselineIdentity() != l.manifest.RealBaselineIdentity() {
		return fmt.Errorf("%w: real commit plan binding changed", ErrCommitAuthority)
	}
	return nil
}

func (l *Lifecycle) RealCommitPlan() *realcommit.Plan {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.commitPlan
}

func (l *Lifecycle) deriveRealCommitPlan() (*realcommit.Plan, error) {
	if l.manifest == nil || l.plan == nil || !l.decision.Allowed {
		return nil, fmt.Errorf("%w: verified manifest decision is unavailable", ErrCommitAuthority)
	}
	if err := l.validateManifest(); err != nil {
		return nil, err
	}
	at, err := l.clock.Observe()
	if err != nil {
		return nil, fmt.Errorf("observe trusted precommit time: %w", err)
	}
	if l.manifest.contract.ExpiredAt(at) {
		return nil, fmt.Errorf("%w: %s", ErrContractExpired, l.manifest.contract.ExpiresAt().Format(time.RFC3339Nano))
	}
	if !l.decision.BoundTo(l.manifest.identity, l.manifest.contractHash, l.plan.Hash()) {
		return nil, fmt.Errorf("%w: manifest, contract, plan, or authority hash mismatch", ErrCommitAuthority)
	}

	realNow, err := l.manifest.workspace.ObserveReal()
	if err != nil {
		return nil, fmt.Errorf("revalidate complete real baseline: %w", err)
	}
	realBaseline := l.manifest.workspace.RealBaseline()
	if realNow.Identity() != realBaseline.Identity() {
		return nil, fmt.Errorf("%w: expected %s, observed %s", ErrRealStateConflict, realBaseline.Identity(), realNow.Identity())
	}

	shadowNow, err := l.manifest.workspace.ObserveDisposable()
	if err != nil {
		return nil, fmt.Errorf("revalidate frozen shadow: %w", err)
	}
	if shadowNow.Identity() != l.plan.FinalIdentity() {
		return nil, fmt.Errorf("%w: expected final %s, observed %s", ErrShadowChanged, l.plan.FinalIdentity(), shadowNow.Identity())
	}
	recomputed, err := tree.Diff(l.manifest.workspace.DisposableBaseline(), shadowNow)
	if err != nil {
		return nil, fmt.Errorf("recompute verified shadow plan: %w", err)
	}
	if recomputed.Hash() != l.plan.Hash() {
		return nil, fmt.Errorf("%w: expected plan %s, observed %s", ErrCommitAuthority, l.plan.Hash(), recomputed.Hash())
	}

	mutations := recomputed.Mutations()
	if len(mutations) != 1 {
		return nil, fmt.Errorf("%w: mutations=%d", ErrUnsupportedCommit, len(mutations))
	}
	mutation := mutations[0]
	if mutation.Operation != tree.OperationModify || mutation.BeforeKind != tree.KindFile || mutation.AfterKind != tree.KindFile || mutation.BeforeMode != mutation.AfterMode {
		return nil, fmt.Errorf("%w: %s %s", ErrUnsupportedCommit, mutation.Operation, mutation.Resource)
	}
	realEntry, ok := snapshotEntry(realBaseline, mutation.Resource)
	if !ok || realEntry.Kind != tree.KindFile {
		return nil, fmt.Errorf("%w: real baseline lacks existing regular file %s", ErrUnsupportedCommit, mutation.Resource)
	}
	disposableEntry, ok := snapshotEntry(l.manifest.workspace.DisposableBaseline(), mutation.Resource)
	if !ok || disposableEntry.Kind != tree.KindFile || disposableEntry.Digest != mutation.BeforeDigest {
		return nil, fmt.Errorf("%w: disposable baseline does not bind %s", ErrCommitAuthority, mutation.Resource)
	}
	if realEntry.Digest != mutation.BeforeDigest {
		return nil, fmt.Errorf("%w: real and disposable content baselines differ for %s", ErrCommitAuthority, mutation.Resource)
	}
	return realcommit.New(realcommit.Spec{
		ManifestHash:         l.manifest.identity,
		AuthorityHash:        l.decision.AuthorityHash,
		RealBaselineIdentity: realBaseline.Identity(),
		RealWorkspace:        l.manifest.workspace.RealWorkspace(),
		Resource:             mutation.Resource,
		BeforeDigest:         realEntry.Digest,
		AfterDigest:          mutation.AfterDigest,
		RealMode:             realEntry.Mode,
		Contents:             mutation.Content(),
	})
}

func snapshotEntry(snapshot *tree.Snapshot, resource string) (tree.Entry, bool) {
	if snapshot == nil {
		return tree.Entry{}, false
	}
	for _, entry := range snapshot.Entries() {
		if entry.Resource == resource {
			return entry, true
		}
	}
	return tree.Entry{}, false
}

func commitFailureState(err error) State {
	switch {
	case errors.Is(err, realcommit.ErrCleanup), errors.Is(err, realcommit.ErrRevalidation):
		return StateFailed
	case errors.Is(err, ErrRealStateConflict), errors.Is(err, realcommit.ErrConflict):
		return StateConflicted
	case errors.Is(err, ErrContractExpired), errors.Is(err, ErrShadowChanged), errors.Is(err, ErrCommitAuthority), errors.Is(err, ErrUnsupportedCommit):
		return StateRejected
	default:
		return StateFailed
	}
}

func gitPlanFailureState(err error) State {
	switch {
	case errors.Is(err, gitplan.ErrRepositoryChanged):
		return StateConflicted
	case errors.Is(err, gitplan.ErrAuthorityChanged), errors.Is(err, gitplan.ErrContractExpired), errors.Is(err, gitplan.ErrUnverified), errors.Is(err, gitplan.ErrUnsupportedEffect):
		return StateRejected
	default:
		return StateFailed
	}
}

func gitCommitFailureState(err error) State {
	switch {
	case errors.Is(err, gitcommit.ErrCleanup), errors.Is(err, gitcommit.ErrTransactionChanged):
		return StateFailed
	case errors.Is(err, ErrRealStateConflict), errors.Is(err, gitcommit.ErrRepositoryChanged), errors.Is(err, gitplan.ErrRepositoryChanged):
		return StateConflicted
	case errors.Is(err, ErrContractExpired), errors.Is(err, ErrShadowChanged), errors.Is(err, ErrCommitAuthority), errors.Is(err, gitcommit.ErrAuthorityChanged), errors.Is(err, gitcommit.ErrContentMismatch), errors.Is(err, gitplan.ErrContractExpired):
		return StateRejected
	default:
		return StateFailed
	}
}

// Reject is valid before execution, after freeze, during reconciliation, or
// after verification. It never implies that a running process was stopped.
func (l *Lifecycle) Reject() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch l.state {
	case StateCreated, StatePreparing, StateFrozen, StateReconciling, StateVerified, StateCommitReady:
		artifact := l.gitArtifact
		if artifact == nil {
			artifact = l.gitCleanupArtifact
		}
		if artifact != nil {
			if err := l.cleanupArtifact(artifact); err != nil {
				l.retainCleanupOnly(artifact)
				l.state = StateFailed
				return err
			}
			if l.gitArtifact == artifact {
				l.gitArtifact = nil
			}
			if l.gitCleanupArtifact == artifact {
				l.gitCleanupArtifact = nil
			}
		}
		l.state = StateRejected
		return nil
	default:
		return fmt.Errorf("%w: cannot reject in state %s", ErrInvalidTransition, l.state)
	}
}

// Destroy removes sandbox-owned runtime resources. It does not change the
// security lifecycle: cleanup success is not evidence of verification.
func (l *Lifecycle) Destroy(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state == StateRunning || l.state == StateFreezing {
		return fmt.Errorf("%w: cannot destroy an unproven running sandbox in state %s", ErrInvalidTransition, l.state)
	}
	var result error
	if err := l.sandbox.Destroy(ctx); err != nil {
		result = fmt.Errorf("destroy hostile sandbox: %w", err)
	}
	artifact := l.gitArtifact
	if artifact == nil {
		artifact = l.gitCleanupArtifact
	}
	if artifact != nil {
		if err := l.cleanupArtifact(artifact); err != nil {
			l.retainCleanupOnly(artifact)
			l.state = StateFailed
			result = errors.Join(result, err)
		} else {
			if l.gitArtifact == artifact {
				l.gitArtifact = nil
			}
			if l.gitCleanupArtifact == artifact {
				l.gitCleanupArtifact = nil
			}
		}
	}
	return result
}

func (l *Lifecycle) require(expected State, operation string) error {
	if l.state != expected {
		return fmt.Errorf("%w: cannot %s in state %s", ErrInvalidTransition, operation, l.state)
	}
	return nil
}
