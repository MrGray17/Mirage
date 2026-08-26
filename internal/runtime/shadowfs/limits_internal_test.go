package shadowfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/MrGray17/Mirage/internal/securitylimits"
)

func TestBeginRejectsOversizeManagedFileWithoutReadingUnboundedInput(t *testing.T) {
	workspace := t.TempDir()
	contents := make([]byte, securitylimits.ManagedFileBytes+1)
	if err := os.WriteFile(filepath.Join(workspace, managedFile), contents, 0o600); err != nil {
		t.Fatalf("write oversized README: %v", err)
	}
	_, err := Begin(workspace)
	if !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("error = %v, want ErrResourceLimit", err)
	}
}

func TestObserveManagedResourceRejectsOversizeReplacement(t *testing.T) {
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, managedFile), []byte("A"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	tx, err := Begin(workspace)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() {
		if tx.State() == StateActive {
			_ = tx.Reject()
		}
	}()
	contents := make([]byte, securitylimits.ManagedFileBytes+1)
	if err := os.WriteFile(filepath.Join(workspace, managedFile), contents, 0o600); err != nil {
		t.Fatalf("replace README: %v", err)
	}
	if err := tx.ApplyCommit(); !errors.Is(err, ErrResourceLimit) || !errors.Is(err, ErrRevalidation) {
		t.Fatalf("commit error = %v, want ErrRevalidation + ErrResourceLimit", err)
	}
	if tx.State() != StateActive {
		t.Fatalf("state = %s, want ACTIVE", tx.State())
	}
}
