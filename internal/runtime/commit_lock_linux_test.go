//go:build linux

package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWorkspaceCommitLockRejectsIndependentAcquisition(t *testing.T) {
	dir := t.TempDir()
	first, err := acquireWorkspaceCommitLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := acquireWorkspaceCommitLock(dir); !errors.Is(err, ErrWorkspaceCommitBusy) {
		if second != nil {
			_ = second.Close()
		}
		_ = first.Close()
		t.Fatalf("second acquisition: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := acquireWorkspaceCommitLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
}

func TestLifecycleRejectsContendedWorkspaceCommitWithoutMutation(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	lifecycle, disposable := verifiedContentLifecycle(t, func() time.Time { return now }, now.Add(time.Hour))
	if _, err := lifecycle.PreCommit(); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(disposable.RealWorkspace(), "README.md")
	before, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := acquireWorkspaceCommitLock(disposable.RealWorkspace())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := lifecycle.Commit(); !errors.Is(err, ErrWorkspaceCommitBusy) || lifecycle.State() != StateConflicted {
		t.Fatalf("commit=%v state=%s", err, lifecycle.State())
	}
	after, err := os.ReadFile(target)
	if err != nil || string(after) != string(before) {
		t.Fatalf("contended commit changed reality: %q, %v", after, err)
	}
}
