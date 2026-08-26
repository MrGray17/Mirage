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
	"github.com/MrGray17/Mirage/internal/securitylimits"
	"github.com/MrGray17/Mirage/internal/verifier"
)

func TestReadOnlyApprovedRunFinalizesWithoutRealMutation(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	workspace := internalWorkspace(t, []byte("A"))
	readme := filepath.Join(workspace, "README.md")
	run := internalBegin(t, workspace, internalContract(t, now.Add(time.Hour), true, false), now)

	before, err := os.Stat(readme)
	if err != nil {
		t.Fatalf("stat before: %v", err)
	}
	if _, err := run.ReadFile("README.md"); err != nil {
		t.Fatalf("read README: %v", err)
	}
	if err := os.Chmod(readme, 0o644); err != nil {
		t.Fatalf("external chmod: %v", err)
	}
	if decision, err := run.Verify(); err != nil || decision.Status != verifier.StatusApproved {
		t.Fatalf("verify = %+v, %v", decision, err)
	}
	if err := run.ApplyCommit(); err != nil {
		t.Fatalf("no-op commit: %v", err)
	}
	after, err := os.Stat(readme)
	if err != nil {
		t.Fatalf("stat after: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("read-only commit replaced the real README object")
	}
	if after.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %o, want externally updated 0644", after.Mode().Perm())
	}
	assertInternalContents(t, readme, []byte("A"))
}

func TestDirectShadowMutationWithoutApprovedWriteRejectsCommit(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	workspace := internalWorkspace(t, []byte("A"))
	run := internalBegin(t, workspace, internalContract(t, now.Add(time.Hour), false, false), now)
	if err := os.WriteFile(filepath.Join(run.transaction.ShadowWorkspace(), "README.md"), []byte("B"), 0o600); err != nil {
		t.Fatalf("direct shadow mutation: %v", err)
	}
	if decision, err := run.Verify(); err != nil || decision.Status != verifier.StatusApproved {
		t.Fatalf("verify = %+v, %v", decision, err)
	}
	if err := run.ApplyCommit(); !errors.Is(err, shadowfs.ErrCommitAuthorization) {
		t.Fatalf("commit error = %v, want ErrCommitAuthorization", err)
	}
	if run.State() != StateRejected {
		t.Fatalf("state = %s, want REJECTED", run.State())
	}
	assertInternalContents(t, filepath.Join(workspace, "README.md"), []byte("A"))
}

func TestApprovedWriteDigestRejectsPostVerificationShadowTamper(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	workspace := internalWorkspace(t, []byte("A"))
	run := internalBegin(t, workspace, internalContract(t, now.Add(time.Hour), false, true), now)
	if err := run.WriteFile("README.md", []byte("B")); err != nil {
		t.Fatalf("mediated write: %v", err)
	}
	if decision, err := run.Verify(); err != nil || decision.Status != verifier.StatusApproved {
		t.Fatalf("verify = %+v, %v", decision, err)
	}
	if err := os.WriteFile(filepath.Join(run.transaction.ShadowWorkspace(), "README.md"), []byte("C"), 0o600); err != nil {
		t.Fatalf("tamper frozen shadow: %v", err)
	}
	if err := run.ApplyCommit(); !errors.Is(err, shadowfs.ErrCommitAuthorization) {
		t.Fatalf("commit error = %v, want ErrCommitAuthorization", err)
	}
	assertInternalContents(t, filepath.Join(workspace, "README.md"), []byte("A"))
}

func TestOversizeWriteFailsBeforeShadowMutation(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	workspace := internalWorkspace(t, []byte("A"))
	run := internalBegin(t, workspace, internalContract(t, now.Add(time.Hour), false, true), now)
	payload := make([]byte, securitylimits.ManagedFileBytes+1)
	if err := run.WriteFile("README.md", payload); !errors.Is(err, filesystemgateway.ErrResourceLimit) {
		t.Fatalf("write error = %v, want ErrResourceLimit", err)
	}
	assertInternalContents(t, filepath.Join(run.transaction.ShadowWorkspace(), "README.md"), []byte("A"))
	decision, err := run.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if decision.Status != verifier.StatusRejected {
		t.Fatalf("decision = %+v, want REJECTED", decision)
	}
	assertInternalContents(t, filepath.Join(workspace, "README.md"), []byte("A"))
}

func internalContract(t *testing.T, expires time.Time, allowRead, allowWrite bool) *contracts.Contract {
	t.Helper()
	policy := contracts.FilesystemPolicy{}
	if allowRead {
		policy.Read.Allow = []string{filesystemgateway.ManagedResource}
	}
	if allowWrite {
		policy.Write.Allow = []string{filesystemgateway.ManagedResource}
	}
	contract, err := contracts.New(contracts.Spec{Version: contracts.VersionV1, RunID: "run-binding", ActorID: "agent-binding", ExpiresAt: expires, Filesystem: policy})
	if err != nil {
		t.Fatalf("new contract: %v", err)
	}
	return contract
}

func internalBegin(t *testing.T, workspace string, contract *contracts.Contract, now time.Time) *Run {
	t.Helper()
	run, err := Begin(workspace, contract, func() time.Time { return now })
	if err != nil {
		t.Fatalf("begin run: %v", err)
	}
	t.Cleanup(func() {
		state := run.State()
		if state == StateRunning || state == StateApproved || state == StateFailed {
			_ = run.Reject()
		}
	})
	return run
}

func internalWorkspace(t *testing.T, contents []byte) string {
	t.Helper()
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), contents, 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	return workspace
}

func assertInternalContents(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != string(want) {
		t.Fatalf("contents = %q, want %q", got, want)
	}
}
