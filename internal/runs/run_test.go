package runs_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/effects"
	filesystemgateway "github.com/MrGray17/Mirage/internal/gateway/filesystem"
	"github.com/MrGray17/Mirage/internal/runs"
	"github.com/MrGray17/Mirage/internal/runtime/shadowfs"
	"github.com/MrGray17/Mirage/internal/verifier"
)

func TestAllowedFilesystemEffectsVerifyAndCommit(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	workspace := newWorkspace(t, []byte("hello"))
	run := beginRun(t, workspace, allowREADMEContract(t, now.Add(time.Hour)), func() time.Time { return now })

	contents, err := run.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	if string(contents) != "hello" {
		t.Fatalf("read contents = %q", contents)
	}
	if err := run.WriteFile("/workspace/README.md", []byte("goodbye")); err != nil {
		t.Fatalf("write README: %v", err)
	}
	assertContents(t, filepath.Join(workspace, "README.md"), []byte("hello"))

	events := run.Events()
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	assertEvent(t, events[0], 1, "READ", effects.DecisionAllow, effects.OutcomeSuccess)
	assertEvent(t, events[1], 2, "WRITE", effects.DecisionAllow, effects.OutcomeSuccessShadow)

	decision, err := run.Verify()
	if err != nil {
		t.Fatalf("verify run: %v", err)
	}
	if decision.Status != verifier.StatusApproved || len(decision.ApprovedEffects) != 2 {
		t.Fatalf("decision = %+v", decision)
	}
	if run.State() != runs.StateApproved {
		t.Fatalf("state = %s, want APPROVED", run.State())
	}
	if err := run.WriteFile("README.md", []byte("late mutation")); !errors.Is(err, runs.ErrInvalidTransition) {
		t.Fatalf("post-verification write error = %v", err)
	}

	if err := run.ApplyCommit(); err != nil {
		t.Fatalf("commit run: %v", err)
	}
	if run.State() != runs.StateCommitted {
		t.Fatalf("state = %s, want COMMITTED", run.State())
	}
	assertContents(t, filepath.Join(workspace, "README.md"), []byte("goodbye"))
}

func TestForbiddenAttemptRejectsRunAndPreservesReality(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	workspace := newWorkspace(t, []byte("real README"))
	secretPath := filepath.Join(workspace, ".env")
	if err := os.WriteFile(secretPath, []byte("TOP_SECRET=value"), 0o600); err != nil {
		t.Fatalf("write real secret: %v", err)
	}
	run := beginRun(t, workspace, allowREADMEContract(t, now.Add(time.Hour)), func() time.Time { return now })

	if err := run.WriteFile("README.md", []byte("authorized shadow edit")); err != nil {
		t.Fatalf("write authorized README: %v", err)
	}
	if _, err := run.ReadFile(".env"); !errors.Is(err, filesystemgateway.ErrDenied) {
		t.Fatalf("secret read error = %v, want ErrDenied", err)
	}
	if err := run.ApplyCommit(); !errors.Is(err, runs.ErrInvalidTransition) {
		t.Fatalf("pre-verification commit error = %v, want ErrInvalidTransition", err)
	}
	assertContents(t, secretPath, []byte("TOP_SECRET=value"))
	assertContents(t, filepath.Join(workspace, "README.md"), []byte("real README"))

	events := run.Events()
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	assertEvent(t, events[1], 2, "READ", effects.DecisionDeny, effects.OutcomeBlocked)
	if events[1].Metadata["rule_id"] != "filesystem.explicit_deny" {
		t.Fatalf("denial rule = %q", events[1].Metadata["rule_id"])
	}

	decision, err := run.Verify()
	if err != nil {
		t.Fatalf("verify rejected run: %v", err)
	}
	if decision.Status != verifier.StatusRejected || len(decision.DeniedAttempts) != 1 || decision.DeniedAttempts[0] != 2 {
		t.Fatalf("decision = %+v", decision)
	}
	if run.State() != runs.StateRejected {
		t.Fatalf("state = %s, want REJECTED", run.State())
	}
	if err := run.ApplyCommit(); !errors.Is(err, runs.ErrInvalidTransition) {
		t.Fatalf("commit rejected run error = %v", err)
	}
	assertContents(t, filepath.Join(workspace, "README.md"), []byte("real README"))
	assertContents(t, secretPath, []byte("TOP_SECRET=value"))
	if len(run.Events()) != 2 {
		t.Fatal("denied attempt disappeared after rejection")
	}
}

func TestTraversalAttemptIsBlockedRecordedAndRejectsRun(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	workspace := newWorkspace(t, []byte("real"))
	run := beginRun(t, workspace, allowREADMEContract(t, now.Add(time.Hour)), func() time.Time { return now })

	if err := run.WriteFile("..\\outside.txt", []byte("escape")); !errors.Is(err, filesystemgateway.ErrDenied) {
		t.Fatalf("traversal error = %v, want ErrDenied", err)
	}
	event := run.Events()[0]
	assertEvent(t, event, 1, "WRITE", effects.DecisionDeny, effects.OutcomeBlocked)
	if event.Metadata["rule_id"] != "filesystem.invalid_resource" {
		t.Fatalf("rule = %q", event.Metadata["rule_id"])
	}
	if event.ResourceID == "..\\outside.txt" {
		t.Fatal("raw host-oriented traversal path was used as canonical resource ID")
	}
	decision, err := run.Verify()
	if err != nil {
		t.Fatalf("verify run: %v", err)
	}
	if decision.Status != verifier.StatusRejected {
		t.Fatalf("status = %s, want REJECTED", decision.Status)
	}
	assertContents(t, filepath.Join(workspace, "README.md"), []byte("real"))
}

func TestContractExpiryBeforeVerificationRejectsShadow(t *testing.T) {
	current := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	expires := current.Add(time.Minute)
	workspace := newWorkspace(t, []byte("real"))
	run := beginRun(t, workspace, allowREADMEContract(t, expires), func() time.Time { return current })
	if err := run.WriteFile("README.md", []byte("shadow")); err != nil {
		t.Fatalf("write README: %v", err)
	}
	current = expires

	decision, err := run.Verify()
	if err != nil {
		t.Fatalf("verify expired run: %v", err)
	}
	if decision.Status != verifier.StatusRejected || decision.Violations[0].RuleID != "contract.expired" {
		t.Fatalf("decision = %+v", decision)
	}
	assertContents(t, filepath.Join(workspace, "README.md"), []byte("real"))
}

func TestContractExpiryAfterApprovalBlocksCommit(t *testing.T) {
	current := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	expires := current.Add(time.Minute)
	workspace := newWorkspace(t, []byte("real"))
	run := beginRun(t, workspace, allowREADMEContract(t, expires), func() time.Time { return current })
	if err := run.WriteFile("README.md", []byte("shadow")); err != nil {
		t.Fatalf("write README: %v", err)
	}
	if decision, err := run.Verify(); err != nil || decision.Status != verifier.StatusApproved {
		t.Fatalf("verify = %+v, %v", decision, err)
	}
	current = expires

	if err := run.ApplyCommit(); !errors.Is(err, runs.ErrContractExpired) {
		t.Fatalf("commit error = %v, want ErrContractExpired", err)
	}
	if run.State() != runs.StateExpired {
		t.Fatalf("state = %s, want EXPIRED", run.State())
	}
	assertContents(t, filepath.Join(workspace, "README.md"), []byte("real"))
}

func TestApprovedRunStillUsesM2ConflictRevalidation(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	workspace := newWorkspace(t, []byte("A"))
	run := beginRun(t, workspace, allowREADMEContract(t, now.Add(time.Hour)), func() time.Time { return now })
	if err := run.WriteFile("README.md", []byte("B")); err != nil {
		t.Fatalf("write README: %v", err)
	}
	if decision, err := run.Verify(); err != nil || decision.Status != verifier.StatusApproved {
		t.Fatalf("verify = %+v, %v", decision, err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), []byte("C"), 0o600); err != nil {
		t.Fatalf("external write: %v", err)
	}

	if err := run.ApplyCommit(); !errors.Is(err, shadowfs.ErrStateConflict) {
		t.Fatalf("commit error = %v, want ErrStateConflict", err)
	}
	if run.State() != runs.StateConflicted {
		t.Fatalf("state = %s, want CONFLICTED", run.State())
	}
	assertContents(t, filepath.Join(workspace, "README.md"), []byte("C"))
}

func TestExpiredContractCannotStartRun(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	workspace := newWorkspace(t, []byte("real"))
	_, err := runs.Begin(workspace, allowREADMEContract(t, now), func() time.Time { return now })
	if !errors.Is(err, runs.ErrContractExpired) {
		t.Fatalf("error = %v, want ErrContractExpired", err)
	}
}

func TestUnavailableTrustedTimeCannotStartRun(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	workspace := newWorkspace(t, []byte("real"))
	_, err := runs.Begin(workspace, allowREADMEContract(t, now.Add(time.Hour)), func() time.Time { return time.Time{} })
	if !errors.Is(err, runs.ErrInvalidRun) {
		t.Fatalf("error = %v, want ErrInvalidRun", err)
	}
}

func allowREADMEContract(t *testing.T, expires time.Time) *contracts.Contract {
	t.Helper()
	contract, err := contracts.New(contracts.Spec{
		Version:   contracts.VersionV1,
		RunID:     "run-17",
		ActorID:   "coding-agent-17",
		ExpiresAt: expires,
		Filesystem: contracts.FilesystemPolicy{
			Read: contracts.AccessRules{
				Allow: []string{filesystemgateway.ManagedResource},
				Deny:  []string{"/workspace/.env"},
			},
			Write: contracts.AccessRules{Allow: []string{filesystemgateway.ManagedResource}},
		},
	})
	if err != nil {
		t.Fatalf("new contract: %v", err)
	}
	return contract
}

func beginRun(t *testing.T, workspace string, contract *contracts.Contract, now func() time.Time) *runs.Run {
	t.Helper()
	run, err := runs.Begin(workspace, contract, now)
	if err != nil {
		t.Fatalf("begin run: %v", err)
	}
	t.Cleanup(func() {
		if run.State() == runs.StateRunning || run.State() == runs.StateApproved || run.State() == runs.StateFailed {
			if err := run.Reject(); err != nil {
				t.Errorf("cleanup run: %v", err)
			}
		}
	})
	return run
}

func newWorkspace(t *testing.T, contents []byte) string {
	t.Helper()
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), contents, 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	return workspace
}

func assertContents(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != string(want) {
		t.Fatalf("contents = %q, want %q", got, want)
	}
}

func assertEvent(t *testing.T, event effects.Event, sequence uint64, operation string, decision effects.Decision, outcome effects.Outcome) {
	t.Helper()
	if event.Sequence != sequence || event.Operation != operation || event.Decision != decision || event.Outcome != outcome {
		t.Fatalf("event = %+v", event)
	}
	if event.ResourceID != filesystemgateway.ManagedResource && event.Decision == effects.DecisionAllow {
		t.Fatalf("allowed resource = %q", event.ResourceID)
	}
}
