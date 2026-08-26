package verifier_test

import (
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/effects"
	"github.com/MrGray17/Mirage/internal/verifier"
)

func TestVerifierReevaluatesGatewayDecisionAgainstContract(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	contract := testContract(t, now.Add(time.Hour))
	log, err := effects.NewLog(contract.RunID(), contract.ActorID())
	if err != nil {
		t.Fatalf("new log: %v", err)
	}
	_, err = log.Append(effects.Attempt{
		Adapter:        effects.AdapterFilesystem,
		Operation:      string(contracts.FilesystemRead),
		ResourceType:   effects.ResourceTypeFile,
		ResourceID:     "/workspace/.env",
		Classification: effects.ClassShadowLocal,
		Phase:          effects.PhaseExecution,
		Decision:       effects.DecisionAllow,
		Outcome:        effects.OutcomeSuccess,
		Timestamp:      now,
	})
	if err != nil {
		t.Fatalf("append forged allowed event: %v", err)
	}

	decision := verifier.Verify(contract, log.Events(), now)
	if decision.Status != verifier.StatusRejected || len(decision.Violations) != 1 {
		t.Fatalf("decision = %+v", decision)
	}
	if decision.Violations[0].RuleID != "filesystem.explicit_deny" {
		t.Fatalf("rule = %q", decision.Violations[0].RuleID)
	}
}

func TestDeniedAttemptRejectsEvenWhenContractWouldAllowResource(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	contract := testContract(t, now.Add(time.Hour))
	log, err := effects.NewLog(contract.RunID(), contract.ActorID())
	if err != nil {
		t.Fatalf("new log: %v", err)
	}
	_, err = log.Append(effects.Attempt{
		Adapter:        effects.AdapterFilesystem,
		Operation:      string(contracts.FilesystemRead),
		ResourceType:   effects.ResourceTypeFile,
		ResourceID:     "/workspace/README.md",
		Classification: effects.ClassShadowLocal,
		Phase:          effects.PhaseExecution,
		Decision:       effects.DecisionDeny,
		Outcome:        effects.OutcomeBlocked,
		Timestamp:      now,
		Metadata: map[string]string{
			"rule_id": "gateway.runtime_integrity",
			"reason":  "gateway refused unsafe acquisition",
		},
	})
	if err != nil {
		t.Fatalf("append denied event: %v", err)
	}

	decision := verifier.Verify(contract, log.Events(), now)
	if decision.Status != verifier.StatusRejected || len(decision.DeniedAttempts) != 1 {
		t.Fatalf("decision = %+v", decision)
	}
	if decision.Violations[0].RuleID != "gateway.runtime_integrity" {
		t.Fatalf("rule = %q", decision.Violations[0].RuleID)
	}
}

func TestFailedAllowedEffectRejectsUncertainShadowResult(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	contract := testContract(t, now.Add(time.Hour))
	log, err := effects.NewLog(contract.RunID(), contract.ActorID())
	if err != nil {
		t.Fatalf("new log: %v", err)
	}
	_, err = log.Append(effects.Attempt{
		Adapter:        effects.AdapterFilesystem,
		Operation:      string(contracts.FilesystemRead),
		ResourceType:   effects.ResourceTypeFile,
		ResourceID:     "/workspace/README.md",
		Classification: effects.ClassShadowLocal,
		Phase:          effects.PhaseExecution,
		Decision:       effects.DecisionAllow,
		Outcome:        effects.OutcomeFailed,
		Timestamp:      now,
	})
	if err != nil {
		t.Fatalf("append failed event: %v", err)
	}

	decision := verifier.Verify(contract, log.Events(), now)
	if decision.Status != verifier.StatusRejected || decision.Violations[0].RuleID != "effect.failed" {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestUnavailableTrustedTimeRejectsEmptyRun(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	contract := testContract(t, now.Add(time.Hour))
	decision := verifier.Verify(contract, nil, time.Time{})
	if decision.Status != verifier.StatusRejected || decision.Violations[0].RuleID != "contract.invalid_time" {
		t.Fatalf("decision = %+v", decision)
	}
}

func testContract(t *testing.T, expires time.Time) *contracts.Contract {
	t.Helper()
	contract, err := contracts.New(contracts.Spec{
		Version:   contracts.VersionV1,
		RunID:     "run-1",
		ActorID:   "agent-1",
		ExpiresAt: expires,
		Filesystem: contracts.FilesystemPolicy{
			Read: contracts.AccessRules{
				Allow: []string{"/workspace/README.md"},
				Deny:  []string{"/workspace/.env"},
			},
		},
	})
	if err != nil {
		t.Fatalf("new contract: %v", err)
	}
	return contract
}
