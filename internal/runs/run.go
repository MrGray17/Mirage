// Package runs binds M3 contract verification to the authority to commit an M2
// shadow transaction. It is a deliberately small prototype coordinator, not
// the full control-plane/runtime state machine planned for M4 and later.
package runs

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/effects"
	filesystemgateway "github.com/MrGray17/Mirage/internal/gateway/filesystem"
	"github.com/MrGray17/Mirage/internal/runtime/shadowfs"
	"github.com/MrGray17/Mirage/internal/verifier"
)

var (
	ErrInvalidRun        = errors.New("invalid run")
	ErrInvalidTransition = errors.New("invalid run transition")
	ErrContractExpired   = errors.New("effect contract expired")
)

type State uint8

const (
	StateRunning State = iota + 1
	StateVerifying
	StateApproved
	StateCommitting
	StateRejected
	StateCommitted
	StateConflicted
	StateExpired
	StateFailed
)

func (s State) String() string {
	switch s {
	case StateRunning:
		return "RUNNING"
	case StateVerifying:
		return "VERIFYING"
	case StateApproved:
		return "APPROVED"
	case StateCommitting:
		return "COMMITTING"
	case StateRejected:
		return "REJECTED"
	case StateCommitted:
		return "COMMITTED"
	case StateConflicted:
		return "CONFLICTED"
	case StateExpired:
		return "EXPIRED"
	case StateFailed:
		return "FAILED"
	default:
		return "UNKNOWN"
	}
}

type Run struct {
	mu          sync.Mutex
	contract    *contracts.Contract
	events      *effects.Log
	filesystem  *filesystemgateway.Gateway
	transaction *shadowfs.Transaction
	now         func() time.Time
	state       State
	decision    *verifier.Decision
}

// Begin creates a mediated run backed by a fresh shadow transaction. The clock
// is a trusted control-plane dependency and must be monotonic enough for expiry
// enforcement; tests inject a fixed clock for deterministic behavior.
func Begin(realWorkspace string, contract *contracts.Contract, now func() time.Time) (*Run, error) {
	if contract == nil || now == nil {
		return nil, fmt.Errorf("%w: contract and clock are required", ErrInvalidRun)
	}
	startedAt := now()
	if startedAt.IsZero() {
		return nil, fmt.Errorf("%w: trusted clock returned zero time", ErrInvalidRun)
	}
	if contract.ExpiredAt(startedAt) {
		return nil, fmt.Errorf("%w: %s", ErrContractExpired, contract.ExpiresAt().Format(time.RFC3339Nano))
	}

	transaction, err := shadowfs.Begin(realWorkspace)
	if err != nil {
		return nil, fmt.Errorf("begin shadow transaction: %w", err)
	}
	cleanupOnFailure := func(cause error) (*Run, error) {
		return nil, errors.Join(cause, transaction.Reject())
	}

	eventLog, err := effects.NewLog(contract.RunID(), contract.ActorID())
	if err != nil {
		return cleanupOnFailure(fmt.Errorf("create effect log: %w", err))
	}
	filesystem, err := filesystemgateway.New(contract, eventLog, transaction.ShadowWorkspace(), now)
	if err != nil {
		return cleanupOnFailure(fmt.Errorf("create filesystem gateway: %w", err))
	}

	return &Run{
		contract:    contract,
		events:      eventLog,
		filesystem:  filesystem,
		transaction: transaction,
		now:         now,
		state:       StateRunning,
	}, nil
}

func (r *Run) State() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

func (r *Run) ContractHash() string { return r.contract.Hash() }

func (r *Run) Events() []effects.Event { return r.events.Events() }

func (r *Run) ReadFile(resource string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != StateRunning {
		return nil, fmt.Errorf("%w: cannot read in state %s", ErrInvalidTransition, r.state)
	}
	return r.filesystem.ReadFile(resource)
}

func (r *Run) WriteFile(resource string, contents []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != StateRunning {
		return fmt.Errorf("%w: cannot write in state %s", ErrInvalidTransition, r.state)
	}
	return r.filesystem.WriteFile(resource, contents)
}

// Verify freezes further mediated effects. A rejected decision destroys the
// shadow immediately; a cleanup failure leaves the run FAILED and permits only
// an explicit cleanup retry through Reject.
func (r *Run) Verify() (verifier.Decision, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != StateRunning {
		return verifier.Decision{}, fmt.Errorf("%w: cannot verify in state %s", ErrInvalidTransition, r.state)
	}
	if err := r.transition(StateVerifying); err != nil {
		return verifier.Decision{}, err
	}

	decision := verifier.Verify(r.contract, r.events.Events(), r.now())
	if auditErr := r.filesystem.AuditError(); auditErr != nil {
		decision.Status = verifier.StatusRejected
		decision.Violations = append(decision.Violations, verifier.Violation{
			RuleID:   "event.recording",
			Reason:   "effect stream integrity is incomplete",
			Evidence: auditErr.Error(),
		})
	}
	r.decision = decisionPointer(decision)

	if decision.Status == verifier.StatusRejected {
		if err := r.transition(StateFailed); err != nil {
			return cloneDecision(decision), err
		}
		if err := r.transaction.Reject(); err != nil {
			return cloneDecision(decision), fmt.Errorf("discard rejected run shadow: %w", err)
		}
		if err := r.transition(StateRejected); err != nil {
			return cloneDecision(decision), err
		}
		return cloneDecision(decision), nil
	}

	if err := r.transition(StateApproved); err != nil {
		return cloneDecision(decision), err
	}
	return cloneDecision(decision), nil
}

// ApplyCommit is available only after deterministic approval. M2 remains the
// sole package that mutates the real workspace.
func (r *Run) ApplyCommit() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != StateApproved || r.decision == nil || r.decision.Status != verifier.StatusApproved {
		return fmt.Errorf("%w: cannot commit in state %s", ErrInvalidTransition, r.state)
	}
	commitAt := r.now()
	if commitAt.IsZero() {
		return r.rejectBeforeCommit(fmt.Errorf("%w: trusted clock returned zero time", ErrInvalidRun), StateFailed)
	}
	if r.contract.ExpiredAt(commitAt) {
		return r.rejectBeforeCommit(
			fmt.Errorf("%w: %s", ErrContractExpired, r.contract.ExpiresAt().Format(time.RFC3339Nano)),
			StateExpired,
		)
	}
	if err := r.transition(StateCommitting); err != nil {
		return err
	}

	err := r.transaction.ApplyCommit()
	switch r.transaction.State() {
	case shadowfs.StateCommitted:
		if transitionErr := r.transition(StateCommitted); transitionErr != nil {
			return errors.Join(err, transitionErr)
		}
	case shadowfs.StateConflicted:
		if transitionErr := r.transition(StateConflicted); transitionErr != nil {
			return errors.Join(err, transitionErr)
		}
	case shadowfs.StateActive:
		// Revalidation uncertainty and pre-mutation failures remain retryable.
		if transitionErr := r.transition(StateApproved); transitionErr != nil {
			return errors.Join(err, transitionErr)
		}
	default:
		if transitionErr := r.transition(StateFailed); transitionErr != nil {
			return errors.Join(err, transitionErr)
		}
	}
	return err
}

func (r *Run) Reject() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != StateRunning && r.state != StateApproved && r.state != StateFailed {
		return fmt.Errorf("%w: cannot reject in state %s", ErrInvalidTransition, r.state)
	}
	if r.state != StateFailed {
		if err := r.transition(StateFailed); err != nil {
			return err
		}
	}
	if r.transaction.State() == shadowfs.StateRejected {
		return r.transition(StateRejected)
	}
	if err := r.transaction.Reject(); err != nil {
		return err
	}
	return r.transition(StateRejected)
}

func (r *Run) rejectBeforeCommit(cause error, terminal State) error {
	if err := r.transaction.Reject(); err != nil {
		transitionErr := r.transition(StateFailed)
		return errors.Join(cause, fmt.Errorf("discard non-committable shadow: %w", err), transitionErr)
	}
	if err := r.transition(terminal); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

func (r *Run) transition(next State) error {
	allowed := false
	switch r.state {
	case StateRunning:
		allowed = next == StateVerifying || next == StateFailed
	case StateVerifying:
		allowed = next == StateApproved || next == StateFailed
	case StateApproved:
		allowed = next == StateCommitting || next == StateExpired || next == StateFailed
	case StateCommitting:
		allowed = next == StateApproved || next == StateCommitted || next == StateConflicted || next == StateFailed
	case StateFailed:
		allowed = next == StateRejected
	}
	if !allowed {
		return fmt.Errorf("%w: %s to %s", ErrInvalidTransition, r.state, next)
	}
	r.state = next
	return nil
}

func decisionPointer(decision verifier.Decision) *verifier.Decision {
	copy := cloneDecision(decision)
	return &copy
}

func cloneDecision(decision verifier.Decision) verifier.Decision {
	decision.Violations = append([]verifier.Violation(nil), decision.Violations...)
	decision.ApprovedEffects = append([]uint64(nil), decision.ApprovedEffects...)
	decision.DeniedAttempts = append([]uint64(nil), decision.DeniedAttempts...)
	return decision
}
