package runs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	filesystemgateway "github.com/MrGray17/Mirage/internal/gateway/filesystem"
	"github.com/MrGray17/Mirage/internal/runtime/shadowfs"
	"github.com/MrGray17/Mirage/internal/verifier"
)

func TestReadOnlyApprovedRunFinalizesWithoutReplacingReality(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	workspace := bindingWorkspace(t, []byte("hello"))
	realREADME := filepath.Join(workspace, "README.md")
	before, err := os.Stat(realREADME)
	if err != nil {
		t.Fatalf("stat before run: %v", err)
	}

	run := bindingRun(t, workspace, bindingContract(t, now.Add(time.Hour), true, false), now)
	if _, err := run.ReadFile("README.md"); err != nil {
		t.Fatalf("read README: %v", err)
	}
	decision, err := run.Verify()
	if err != nil || decision.Status != verifier.StatusApproved {
		t.Fatalf("verify = %+v, %v", decision, err)
	}
	if err := run.ApplyCommit(); err != nil {
		t.Fatalf("finalize read-only run: %v", err)
	}

	after, err := os.Stat(realREADME)
	if err != nil {
		t.Fatalf("stat after run: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("read-only approved run physically replaced README.md")
	}
	assertBindingContents(t, realREADME, []byte("hello"))
}

func TestEmptyApprovedRunFinalizesWithoutReplacingReality(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	workspace := bindingWorkspace(t, []byte("hello"))
	realREADME := filepath.Join(workspace, "README.md")
	before, err := os.Stat(realREADME)
	if err != nil {
		t.Fatalf("stat before run: %v", err)
	}

	run := bindingRun(t, workspace, bindingContract(t, now.Add(time.Hour), false, false), now)
	decision, err := run.Verify()
	if err != nil || decision.Status != verifier.StatusApproved {
		t.Fatalf("verify = %+v, %v", decision, err)
	}
	if err := run.ApplyCommit(); err != nil {
		t.Fatalf("finalize empty run: %v", err)
	}

	after, err := os.Stat(realREADME)
	if err != nil {
		t.Fatalf("stat after run: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("empty approved run physically replaced README.md")
	}
}

func TestUnobservedShadowMutationWithoutApprovedWriteRejectsVerification(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	workspace := bindingWorkspace(t, []byte("real"))
	run := bindingRun(t, workspace, bindingContract(t, now.Add(time.Hour), true, false), now)

	if err := os.WriteFile(filepath.Join(run.transaction.ShadowWorkspace(), "README.md"), []byte("bypass"), 0o600); err != nil {
		t.Fatalf("direct shadow mutation: %v", err)
	}
	decision, err := run.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if decision.Status != verifier.StatusRejected {
		t.Fatalf("status = %s, want REJECTED", decision.Status)
	}
	if !hasBindingViolation(decision, "shadow.unobserved_mutation") {
		t.Fatalf("violations = %+v, want shadow.unobserved_mutation", decision.Violations)
	}
	if run.State() != StateRejected {
		t.Fatalf("state = %s, want REJECTED", run.State())
	}
	assertBindingContents(t, filepath.Join(workspace, "README.md"), []byte("real"))
}

func TestPostVerificationShadowMutationRejectsCommit(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	workspace := bindingWorkspace(t, []byte("real"))
	run := bindingRun(t, workspace, bindingContract(t, now.Add(time.Hour), true, true), now)

	if err := run.WriteFile("README.md", []byte("authorized")); err != nil {
		t.Fatalf("mediated write: %v", err)
	}
	decision, err := run.Verify()
	if err != nil || decision.Status != verifier.StatusApproved {
		t.Fatalf("verify = %+v, %v", decision, err)
	}
	if err := os.WriteFile(filepath.Join(run.transaction.ShadowWorkspace(), "README.md"), []byte("post-verify bypass"), 0o600); err != nil {
		t.Fatalf("post-verify mutation: %v", err)
	}

	if err := run.ApplyCommit(); !errors.Is(err, shadowfs.ErrShadowChanged) {
		t.Fatalf("commit error = %v, want ErrShadowChanged", err)
	}
	if run.State() != StateRejected {
		t.Fatalf("state = %s, want REJECTED", run.State())
	}
	assertBindingContents(t, filepath.Join(workspace, "README.md"), []byte("real"))
}

func bindingRun(t *testing.T, workspace string, contract *contracts.Contract, now time.Time) *Run {
	t.Helper()
	run, err := Begin(workspace, contract, func() time.Time { return now })
	if err != nil {
		t.Fatalf("begin run: %v", err)
	}
	t.Cleanup(func() {
		if run.State() == StateRunning || run.State() == StateApproved || run.State() == StateFailed {
			if err := run.Reject(); err != nil {
				t.Errorf("cleanup run: %v", err)
			}
		}
	})
	return run
}

func bindingContract(t *testing.T, expires time.Time, allowRead, allowWrite bool) *contracts.Contract {
	t.Helper()
	policy := contracts.FilesystemPolicy{}
	if allowRead {
		policy.Read.Allow = []string{filesystemgateway.ManagedResource}
	}
	if allowWrite {
		policy.Write.Allow = []string{filesystemgateway.ManagedResource}
	}
	contract, err := contracts.New(contracts.Spec{
		Version:    contracts.VersionV1,
		RunID:      "binding-run",
		ActorID:    "binding-agent",
		ExpiresAt:  expires,
		Filesystem: policy,
	})
	if err != nil {
		t.Fatalf("new contract: %v", err)
	}
	return contract
}

func bindingWorkspace(t *testing.T, contents []byte) string {
	t.Helper()
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), contents, 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	return workspace
}

func assertBindingContents(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != string(want) {
		t.Fatalf("contents = %q, want %q", got, want)
	}
}

func hasBindingViolation(decision verifier.Decision, ruleID string) bool {
	for _, violation := range decision.Violations {
		if violation.RuleID == ruleID {
			return true
		}
	}
	return false
}
