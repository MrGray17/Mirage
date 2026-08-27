// Package runtime coordinates the lifecycle of an untrusted process sandbox.
// It deliberately does not implement reconciliation or commit authority; M4.1
// stops at a proven-frozen disposable workspace.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrInvalidRuntime    = errors.New("invalid hostile runtime")
	ErrInvalidTransition = errors.New("invalid hostile runtime transition")
)

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
	StateCommitted
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
	case StateCommitted:
		return "COMMITTED"
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
	Prepare(context.Context) error
	Start(context.Context) error
	Freeze(context.Context) error
	Destroy(context.Context) error
}

// Lifecycle serializes sandbox actions with trusted state transitions.
type Lifecycle struct {
	mu      sync.Mutex
	sandbox Sandbox
	state   State
}

func NewLifecycle(sandbox Sandbox) (*Lifecycle, error) {
	if sandbox == nil {
		return nil, fmt.Errorf("%w: sandbox is required", ErrInvalidRuntime)
	}
	return &Lifecycle{sandbox: sandbox, state: StateCreated}, nil
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
	if err := l.sandbox.Freeze(ctx); err != nil {
		l.state = StateFailed
		return fmt.Errorf("freeze hostile sandbox: %w", err)
	}
	l.state = StateFrozen
	return nil
}

// BeginReconciliation is the M4.2 handoff point. No scanner is implemented in
// M4.1; this transition exists so later reconciliation cannot start before a
// proven freeze.
func (l *Lifecycle) BeginReconciliation() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.require(StateFrozen, "begin reconciliation"); err != nil {
		return err
	}
	l.state = StateReconciling
	return nil
}

// MarkVerified is reserved for the future trusted reconciler. M4.1 callers do
// not invoke it.
func (l *Lifecycle) MarkVerified() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.require(StateReconciling, "mark verified"); err != nil {
		return err
	}
	l.state = StateVerified
	return nil
}

func (l *Lifecycle) MarkCommitted() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.require(StateVerified, "mark committed"); err != nil {
		return err
	}
	l.state = StateCommitted
	return nil
}

// Reject is valid before execution, after freeze, during reconciliation, or
// after verification. It never implies that a running process was stopped.
func (l *Lifecycle) Reject() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch l.state {
	case StateCreated, StatePreparing, StateFrozen, StateReconciling, StateVerified:
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
	if err := l.sandbox.Destroy(ctx); err != nil {
		return fmt.Errorf("destroy hostile sandbox: %w", err)
	}
	return nil
}

func (l *Lifecycle) require(expected State, operation string) error {
	if l.state != expected {
		return fmt.Errorf("%w: cannot %s in state %s", ErrInvalidTransition, operation, l.state)
	}
	return nil
}
