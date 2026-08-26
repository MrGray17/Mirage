package runs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/effects"
	filesystemgateway "github.com/MrGray17/Mirage/internal/gateway/filesystem"
	"github.com/MrGray17/Mirage/internal/limits"
	"github.com/MrGray17/Mirage/internal/runtime/shadowfs"
	"github.com/MrGray17/Mirage/internal/verifier"
)

func TestOversizedMediatedWriteIsBlockedAndRecorded(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	workspace := bindingWorkspace(t, []byte("real"))
	run := bindingRun(t, workspace, bindingContract(t, now.Add(time.Hour), true, true), now)

	payload := make([]byte, limits.MaxManagedFileBytes+1)
	if err := run.WriteFile("README.md", payload); !errors.Is(err, filesystemgateway.ErrDenied) {
		t.Fatalf("write error = %v, want ErrDenied", err)
	}
	events := run.Events()
	if len(events) != 1 || events[0].Decision != effects.DecisionDeny || events[0].Metadata["rule_id"] != "filesystem.resource_limit" {
		t.Fatalf("events = %+v", events)
	}
	decision, err := run.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if decision.Status != verifier.StatusRejected {
		t.Fatalf("status = %s, want REJECTED", decision.Status)
	}
	assertBindingContents(t, filepath.Join(workspace, "README.md"), []byte("real"))
}

func TestEventBudgetFailureRejectsRunImmediately(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	workspace := bindingWorkspace(t, []byte("real"))
	run := bindingRun(t, workspace, bindingContract(t, now.Add(time.Hour), true, false), now)

	for i := 0; i < limits.MaxEffectEventsPerRun; i++ {
		if _, err := run.events.Append(effects.Attempt{
			Adapter:        effects.AdapterFilesystem,
			Operation:      "READ",
			ResourceType:   effects.ResourceTypeFile,
			ResourceID:     filesystemgateway.ManagedResource,
			Classification: effects.ClassShadowLocal,
			Phase:          effects.PhaseExecution,
			Decision:       effects.DecisionAllow,
			Outcome:        effects.OutcomeSuccess,
		}); err != nil {
			t.Fatalf("prefill event %d: %v", i, err)
		}
	}

	if _, err := run.ReadFile("README.md"); !errors.Is(err, effects.ErrEventLimit) {
		t.Fatalf("read error = %v, want ErrEventLimit", err)
	}
	if run.State() != StateRejected {
		t.Fatalf("state = %s, want REJECTED", run.State())
	}
	decision, ok := run.Decision()
	if !ok || decision.Status != verifier.StatusRejected || !hasBindingViolation(decision, "event.recording") {
		t.Fatalf("decision = %+v ok=%v", decision, ok)
	}
	assertBindingContents(t, filepath.Join(workspace, "README.md"), []byte("real"))
}

func TestOversizedBaselineCannotEnterTrustedShadowRuntime(t *testing.T) {
	workspace := t.TempDir()
	path := filepath.Join(workspace, "README.md")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create README: %v", err)
	}
	if err := file.Truncate(limits.MaxManagedFileBytes + 1); err != nil {
		_ = file.Close()
		t.Fatalf("truncate README: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close README: %v", err)
	}

	_, err = shadowfs.Begin(workspace)
	if !errors.Is(err, shadowfs.ErrResourceLimit) || !errors.Is(err, shadowfs.ErrInvalidWorkspace) {
		t.Fatalf("begin error = %v, want ErrInvalidWorkspace + ErrResourceLimit", err)
	}
}
