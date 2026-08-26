package verifier_test

import (
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/effects"
	"github.com/MrGray17/Mirage/internal/verifier"
)

func TestVerifierRejectsFutureEventTimestamp(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	contract := testContract(t, now.Add(time.Hour))
	log, err := effects.NewLog(contract.RunID(), contract.ActorID(), verifierClock(now.Add(time.Minute)))
	if err != nil {
		t.Fatalf("new log: %v", err)
	}
	if _, err := log.Append(filesystemReadAttempt()); err != nil {
		t.Fatalf("append event: %v", err)
	}

	decision := verifier.Verify(contract, log.Events(), now)
	if decision.Status != verifier.StatusRejected || len(decision.Violations) == 0 || decision.Violations[0].RuleID != "event.future" {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestVerifierRejectsDecreasingEventTimestamps(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	contract := testContract(t, now.Add(time.Hour))
	log, err := effects.NewLog(contract.RunID(), contract.ActorID(), verifierClock(now))
	if err != nil {
		t.Fatalf("new log: %v", err)
	}
	if _, err := log.Append(filesystemReadAttempt()); err != nil {
		t.Fatalf("append first event: %v", err)
	}
	if _, err := log.Append(filesystemReadAttempt()); err != nil {
		t.Fatalf("append second event: %v", err)
	}
	events := log.Events()
	events[1].Timestamp = now.Add(-time.Second)

	decision := verifier.Verify(contract, events, now.Add(time.Minute))
	if decision.Status != verifier.StatusRejected || len(decision.Violations) == 0 {
		t.Fatalf("decision = %+v", decision)
	}
	found := false
	for _, violation := range decision.Violations {
		if violation.RuleID == "event.time_order" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("violations = %+v, want event.time_order", decision.Violations)
	}
}

func filesystemReadAttempt() effects.Attempt {
	return effects.Attempt{
		Adapter:        effects.AdapterFilesystem,
		Operation:      "READ",
		ResourceType:   effects.ResourceTypeFile,
		ResourceID:     "/workspace/README.md",
		Classification: effects.ClassShadowLocal,
		Phase:          effects.PhaseExecution,
		Decision:       effects.DecisionAllow,
		Outcome:        effects.OutcomeSuccess,
	}
}
