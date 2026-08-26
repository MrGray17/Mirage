// Package verifier deterministically evaluates observed effects against the
// immutable run contract.
package verifier

import (
	"fmt"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/effects"
)

type Status string

const (
	StatusApproved Status = "APPROVED"
	StatusRejected Status = "REJECTED"
)

type Violation struct {
	Sequence uint64
	RuleID   string
	Reason   string
	Evidence string
}

type Decision struct {
	RunID           string
	Status          Status
	ContractHash    string
	Violations      []Violation
	ApprovedEffects []uint64
	DeniedAttempts  []uint64
}

// Verify rejects malformed streams, identity mismatches, temporal
// inconsistencies, expired contracts, effects the gateway incorrectly marked
// allowed, and every denied attempt.
func Verify(contract *contracts.Contract, events []effects.Event, at time.Time) Decision {
	decision := Decision{Status: StatusApproved}
	if contract == nil {
		decision.Status = StatusRejected
		decision.Violations = append(decision.Violations, Violation{
			RuleID: "contract.missing",
			Reason: "immutable effect contract is unavailable",
		})
		return decision
	}
	decision.RunID = contract.RunID()
	decision.ContractHash = contract.Hash()

	if at.IsZero() {
		decision.Violations = append(decision.Violations, Violation{
			RuleID: "contract.invalid_time",
			Reason: "trusted verification time is unavailable",
		})
	} else if contract.ExpiredAt(at) {
		decision.Violations = append(decision.Violations, Violation{
			RuleID:   "contract.expired",
			Reason:   "effect contract expired before verification",
			Evidence: contract.ExpiresAt().Format(time.RFC3339Nano),
		})
	}

	var previousEventTime time.Time
	for index, event := range events {
		if _, err := effects.CanonicalJSON(event); err != nil {
			decision.Violations = append(decision.Violations, Violation{
				Sequence: event.Sequence,
				RuleID:   "event.malformed",
				Reason:   "effect event is not canonical",
				Evidence: err.Error(),
			})
			continue
		}
		if !at.IsZero() && event.Timestamp.After(at.UTC()) {
			decision.Violations = append(decision.Violations, Violation{
				Sequence: event.Sequence,
				RuleID:   "event.future",
				Reason:   "effect event timestamp is later than verification time",
				Evidence: event.Timestamp.Format(time.RFC3339Nano),
			})
			continue
		}
		if !previousEventTime.IsZero() && event.Timestamp.Before(previousEventTime) {
			decision.Violations = append(decision.Violations, Violation{
				Sequence: event.Sequence,
				RuleID:   "event.time_order",
				Reason:   "effect event timestamps are not monotonic",
				Evidence: event.Timestamp.Format(time.RFC3339Nano),
			})
			continue
		}
		previousEventTime = event.Timestamp

		expectedSequence := uint64(index + 1)
		invalidIdentity := false
		if event.Sequence != expectedSequence || event.ID != fmt.Sprintf("%s:%020d", contract.RunID(), expectedSequence) {
			decision.Violations = append(decision.Violations, Violation{
				Sequence: event.Sequence,
				RuleID:   "event.sequence",
				Reason:   "effect event identity or sequence is not contiguous",
				Evidence: fmt.Sprintf("expected %s:%020d", contract.RunID(), expectedSequence),
			})
			invalidIdentity = true
		}
		if event.RunID != contract.RunID() || event.ActorID != contract.ActorID() {
			decision.Violations = append(decision.Violations, Violation{
				Sequence: event.Sequence,
				RuleID:   "event.identity",
				Reason:   "effect event identity does not match the contract",
				Evidence: event.RunID + "/" + event.ActorID,
			})
			invalidIdentity = true
		}
		if invalidIdentity {
			continue
		}
		if event.Adapter != effects.AdapterFilesystem {
			decision.Violations = append(decision.Violations, Violation{
				Sequence: event.Sequence,
				RuleID:   "adapter.unsupported",
				Reason:   "effect adapter is not supported by M3 verification",
				Evidence: event.Adapter,
			})
			continue
		}
		if event.ResourceType != effects.ResourceTypeFile ||
			event.Classification != effects.ClassShadowLocal ||
			event.Phase != effects.PhaseExecution {
			decision.Violations = append(decision.Violations, Violation{
				Sequence: event.Sequence,
				RuleID:   "event.classification",
				Reason:   "filesystem event has unsupported M3 classification",
				Evidence: event.ResourceType + "/" + event.Classification + "/" + event.Phase,
			})
			continue
		}
		if event.PreviousEventHash != "" || event.EventHash != "" {
			decision.Violations = append(decision.Violations, Violation{
				Sequence: event.Sequence,
				RuleID:   "event.integrity_fields",
				Reason:   "event hash fields must remain empty until M7 chain verification exists",
			})
			continue
		}

		contractDecision := contract.EvaluateFilesystem(
			contracts.FilesystemOperation(event.Operation),
			event.ResourceID,
			event.Timestamp,
		)
		if event.Decision == effects.DecisionDeny {
			decision.DeniedAttempts = append(decision.DeniedAttempts, event.Sequence)
			decision.Violations = append(decision.Violations, Violation{
				Sequence: event.Sequence,
				RuleID:   metadataOr(event, "rule_id", contractDecision.RuleID),
				Reason:   metadataOr(event, "reason", "forbidden effect was attempted"),
				Evidence: event.ResourceID,
			})
			continue
		}
		if !contractDecision.Allowed {
			decision.Violations = append(decision.Violations, Violation{
				Sequence: event.Sequence,
				RuleID:   contractDecision.RuleID,
				Reason:   "event was marked allowed but contract evaluation denies it",
				Evidence: event.ResourceID,
			})
			continue
		}
		if event.Outcome == effects.OutcomeFailed {
			decision.Violations = append(decision.Violations, Violation{
				Sequence: event.Sequence,
				RuleID:   "effect.failed",
				Reason:   "failed shadow effect leaves an unverified execution result",
				Evidence: event.ResourceID,
			})
			continue
		}
		expectedOutcome := effects.OutcomeSuccess
		if event.Operation == string(contracts.FilesystemWrite) {
			expectedOutcome = effects.OutcomeSuccessShadow
		}
		if event.Outcome != expectedOutcome {
			decision.Violations = append(decision.Violations, Violation{
				Sequence: event.Sequence,
				RuleID:   "effect.outcome",
				Reason:   "allowed effect has an outcome inconsistent with its operation",
				Evidence: string(event.Outcome),
			})
			continue
		}
		decision.ApprovedEffects = append(decision.ApprovedEffects, event.Sequence)
	}

	if len(decision.Violations) != 0 {
		decision.Status = StatusRejected
	}
	return decision
}

func metadataOr(event effects.Event, key, fallback string) string {
	if value := event.Metadata[key]; value != "" {
		return value
	}
	return fallback
}
