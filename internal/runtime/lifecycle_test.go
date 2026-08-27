package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/runtime/tree"
)

type sandboxStub struct {
	prepareErr error
	startErr   error
	freezeErr  error
	destroyErr error
	calls      []string
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
	if _, err := lifecycle.Reconcile(nil, "", nil, time.Time{}); !errors.Is(err, ErrInvalidTransition) {
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
	if _, err := lifecycle.Reconcile(nil, "", nil, time.Time{}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("reconcile error = %v", err)
	}
}

func TestLifecycleVerificationRequiresFrozenExactReconciliation(t *testing.T) {
	stub := &sandboxStub{}
	lifecycle, err := NewLifecycle(stub)
	if err != nil {
		t.Fatalf("new lifecycle: %v", err)
	}
	if _, err := lifecycle.Reconcile(nil, "", nil, time.Time{}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("early verify error = %v", err)
	}
	workspace := t.TempDir()
	readme := filepath.Join(workspace, "README.md")
	if err := os.WriteFile(readme, []byte("before"), 0o644); err != nil {
		t.Fatal(err)
	}
	baseline, err := tree.Scan(workspace, tree.ScanOptions{})
	if err != nil {
		t.Fatal(err)
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
	if err := os.WriteFile(readme, []byte("after"), 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	contract := lifecycleContract(t, now.Add(time.Hour), "/workspace/README.md")
	decision, err := lifecycle.Reconcile(baseline, workspace, contract, now)
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
	lifecycle, workspace, baseline := frozenLifecycle(t)
	if err := os.WriteFile(filepath.Join(workspace, "forbidden.txt"), []byte("hostile"), 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	decision, err := lifecycle.Reconcile(baseline, workspace, lifecycleContract(t, now.Add(time.Hour)), now)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed || lifecycle.State() != StateRejected {
		t.Fatalf("decision = %#v, state = %s", decision, lifecycle.State())
	}
}

func TestLifecycleScanUncertaintyFailsClosed(t *testing.T) {
	lifecycle, workspace, baseline := frozenLifecycle(t)
	if err := os.RemoveAll(workspace); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	if _, err := lifecycle.Reconcile(baseline, workspace, lifecycleContract(t, now.Add(time.Hour)), now); err == nil {
		t.Fatal("missing frozen workspace was reconciled")
	}
	if lifecycle.State() != StateFailed {
		t.Fatalf("state = %s, want FAILED", lifecycle.State())
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

func frozenLifecycle(t *testing.T) (*Lifecycle, string, *tree.Snapshot) {
	t.Helper()
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), []byte("before"), 0o644); err != nil {
		t.Fatal(err)
	}
	baseline, err := tree.Scan(workspace, tree.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := NewLifecycle(&sandboxStub{})
	if err != nil {
		t.Fatal(err)
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
	return lifecycle, workspace, baseline
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
