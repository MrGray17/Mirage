package effects_test

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/effects"
)

func TestLogIsAppendOnlyAndOwnsEventIdentity(t *testing.T) {
	at := time.Date(2026, 8, 26, 12, 0, 0, 0, time.FixedZone("test", 60*60))
	log, err := effects.NewLog("run-1", "agent-1", fixedClock(at))
	if err != nil {
		t.Fatalf("new log: %v", err)
	}
	metadata := map[string]string{"rule_id": "filesystem.explicit_allow"}
	event, err := log.Append(filesystemAttempt(effects.DecisionAllow, effects.OutcomeSuccess, metadata))
	if err != nil {
		t.Fatalf("append event: %v", err)
	}
	if event.Sequence != 1 || event.ID != "run-1:00000000000000000001" {
		t.Fatalf("event identity = %q sequence %d", event.ID, event.Sequence)
	}
	if event.RunID != "run-1" || event.ActorID != "agent-1" {
		t.Fatalf("event owner = %q/%q", event.RunID, event.ActorID)
	}
	if event.Timestamp.Location() != time.UTC || !event.Timestamp.Equal(at) {
		t.Fatalf("timestamp = %s, want equivalent UTC instant", event.Timestamp)
	}

	metadata["rule_id"] = "mutated input"
	event.Metadata["rule_id"] = "mutated return"
	snapshot := log.Events()
	if got := snapshot[0].Metadata["rule_id"]; got != "filesystem.explicit_allow" {
		t.Fatalf("stored metadata = %q", got)
	}
	snapshot[0].Metadata["rule_id"] = "mutated snapshot"
	if got := log.Events()[0].Metadata["rule_id"]; got != "filesystem.explicit_allow" {
		t.Fatalf("stored metadata after snapshot mutation = %q", got)
	}
}

func TestCanonicalJSONIsIndependentOfMetadataInsertionOrder(t *testing.T) {
	at := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	log, err := effects.NewLog("run-1", "agent-1", fixedClock(at))
	if err != nil {
		t.Fatalf("new log: %v", err)
	}
	event, err := log.Append(filesystemAttempt(effects.DecisionAllow, effects.OutcomeSuccess, map[string]string{
		"z": "last",
		"a": "first",
	}))
	if err != nil {
		t.Fatalf("append event: %v", err)
	}
	first, err := effects.CanonicalJSON(event)
	if err != nil {
		t.Fatalf("canonicalize event: %v", err)
	}
	event.Metadata = map[string]string{"a": "first", "z": "last"}
	second, err := effects.CanonicalJSON(event)
	if err != nil {
		t.Fatalf("canonicalize reordered event: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("canonical JSON differs:\n%s\n%s", first, second)
	}
}

func TestCanonicalJSONRejectsZeroTimestamp(t *testing.T) {
	at := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	log, err := effects.NewLog("run-1", "agent-1", fixedClock(at))
	if err != nil {
		t.Fatalf("new log: %v", err)
	}
	event, err := log.Append(filesystemAttempt(effects.DecisionAllow, effects.OutcomeSuccess, nil))
	if err != nil {
		t.Fatalf("append event: %v", err)
	}

	event.Timestamp = time.Time{}
	if _, err := effects.CanonicalJSON(event); !errors.Is(err, effects.ErrInvalidEvent) {
		t.Fatalf("error = %v, want ErrInvalidEvent", err)
	}
}

func TestLogRejectsStructurallyInvalidEvent(t *testing.T) {
	at := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	log, err := effects.NewLog("run-1", "agent-1", fixedClock(at))
	if err != nil {
		t.Fatalf("new log: %v", err)
	}
	attempt := filesystemAttempt(effects.DecisionDeny, effects.OutcomeSuccess, nil)
	if _, err := log.Append(attempt); !errors.Is(err, effects.ErrInvalidEvent) {
		t.Fatalf("error = %v, want ErrInvalidEvent", err)
	}
	if len(log.Events()) != 0 {
		t.Fatal("invalid event was appended")
	}
}

func TestConcurrentAppendsRemainContiguous(t *testing.T) {
	at := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	log, err := effects.NewLog("run-1", "agent-1", fixedClock(at))
	if err != nil {
		t.Fatalf("new log: %v", err)
	}
	const count = 32
	var wait sync.WaitGroup
	wait.Add(count)
	for index := 0; index < count; index++ {
		go func() {
			defer wait.Done()
			if _, appendErr := log.Append(filesystemAttempt(effects.DecisionAllow, effects.OutcomeSuccess, nil)); appendErr != nil {
				t.Errorf("append event: %v", appendErr)
			}
		}()
	}
	wait.Wait()
	for index, event := range log.Events() {
		if event.Sequence != uint64(index+1) {
			t.Fatalf("event %d sequence = %d", index, event.Sequence)
		}
	}
}

func filesystemAttempt(decision effects.Decision, outcome effects.Outcome, metadata map[string]string) effects.Attempt {
	return effects.Attempt{
		Adapter:        effects.AdapterFilesystem,
		Operation:      "READ",
		ResourceType:   effects.ResourceTypeFile,
		ResourceID:     "/workspace/README.md",
		Classification: effects.ClassShadowLocal,
		Phase:          effects.PhaseExecution,
		Decision:       decision,
		Outcome:        outcome,
		Metadata:       metadata,
	}
}

func fixedClock(at time.Time) func() (time.Time, error) {
	return func() (time.Time, error) { return at, nil }
}
