package runtime

import (
	"context"
	"errors"
	"testing"
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
	if err := lifecycle.BeginReconciliation(); !errors.Is(err, ErrInvalidTransition) {
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
	if err := lifecycle.BeginReconciliation(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("reconcile error = %v", err)
	}
}

func TestLifecycleFutureSecurityTransitionsAreOrdered(t *testing.T) {
	stub := &sandboxStub{}
	lifecycle, err := NewLifecycle(stub)
	if err != nil {
		t.Fatalf("new lifecycle: %v", err)
	}
	if err := lifecycle.MarkVerified(); !errors.Is(err, ErrInvalidTransition) {
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
	if err := lifecycle.BeginReconciliation(); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.MarkVerified(); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.MarkCommitted(); err != nil {
		t.Fatal(err)
	}
	if lifecycle.State() != StateCommitted {
		t.Fatalf("state = %s", lifecycle.State())
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
