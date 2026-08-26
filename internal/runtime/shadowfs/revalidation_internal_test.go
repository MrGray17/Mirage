package shadowfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestApplyCommitRevalidationFailureRetainsActiveShadow(t *testing.T) {
	realWorkspace := t.TempDir()
	realREADME := filepath.Join(realWorkspace, managedFile)
	if err := os.WriteFile(realREADME, []byte("A"), 0o600); err != nil {
		t.Fatalf("write real README: %v", err)
	}
	transaction, err := Begin(realWorkspace)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	t.Cleanup(func() {
		if transaction.State() == StateActive {
			if err := transaction.Reject(); err != nil {
				t.Errorf("cleanup active transaction: %v", err)
			}
		}
	})
	shadowREADME := filepath.Join(transaction.ShadowWorkspace(), managedFile)
	if err := os.WriteFile(shadowREADME, []byte("B"), 0o600); err != nil {
		t.Fatalf("write shadow README: %v", err)
	}

	observationFailure := errors.New("simulated observation failure")
	transaction.observeReal = func(string) (resourceObservation, error) {
		return resourceObservation{}, observationFailure
	}

	err = transaction.ApplyCommit()
	if !errors.Is(err, ErrRevalidation) {
		t.Fatalf("error = %v, want ErrRevalidation", err)
	}
	if !errors.Is(err, observationFailure) {
		t.Fatalf("error = %v, want underlying observation failure", err)
	}
	var revalidation *RevalidationError
	if !errors.As(err, &revalidation) {
		t.Fatalf("error = %v, want *RevalidationError", err)
	}
	if revalidation.Resource != managedFile {
		t.Fatalf("revalidation resource = %q, want %q", revalidation.Resource, managedFile)
	}
	if transaction.State() != StateActive {
		t.Fatalf("state = %s, want %s", transaction.State(), StateActive)
	}
	assertInternalFileContents(t, realREADME, []byte("A"))
	assertInternalFileContents(t, shadowREADME, []byte("B"))
	matches, globErr := filepath.Glob(filepath.Join(realWorkspace, ".mirage-readme-*"))
	if globErr != nil {
		t.Fatalf("find prepared commit files: %v", globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("prepared commit files remain after revalidation failure: %v", matches)
	}

	transaction.observeReal = observeManagedResource
	if err := transaction.ApplyCommit(); err != nil {
		t.Fatalf("retry commit after revalidation recovers: %v", err)
	}
	if transaction.State() != StateCommitted {
		t.Fatalf("state after retry = %s, want %s", transaction.State(), StateCommitted)
	}
	assertInternalFileContents(t, realREADME, []byte("B"))
}

func assertInternalFileContents(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != string(want) {
		t.Fatalf("contents of %s = %q, want %q", path, got, want)
	}
}
