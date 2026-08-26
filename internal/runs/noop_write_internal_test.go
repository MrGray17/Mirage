package runs

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/verifier"
)

func TestAuthorizedWriteWithNoFinalDiffDoesNotReplaceReality(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	workspace := bindingWorkspace(t, []byte("same"))
	realREADME := filepath.Join(workspace, "README.md")
	before, err := os.Stat(realREADME)
	if err != nil {
		t.Fatalf("stat before run: %v", err)
	}

	run := bindingRun(t, workspace, bindingContract(t, now.Add(time.Hour), true, true), now)
	if err := run.WriteFile("README.md", []byte("same")); err != nil {
		t.Fatalf("mediated no-op write: %v", err)
	}
	decision, err := run.Verify()
	if err != nil || decision.Status != verifier.StatusApproved {
		t.Fatalf("verify = %+v, %v", decision, err)
	}
	if err := run.ApplyCommit(); err != nil {
		t.Fatalf("finalize no-op write: %v", err)
	}

	after, err := os.Stat(realREADME)
	if err != nil {
		t.Fatalf("stat after run: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("empty final diff physically replaced README.md")
	}
}
