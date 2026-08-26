package shadowfs_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/MrGray17/Mirage/internal/runtime/shadowfs"
)

func TestShadowWriteLeavesRealWorkspaceUnchanged(t *testing.T) {
	realWorkspace := newRealWorkspace(t, []byte("hello"))
	transaction := beginTransaction(t, realWorkspace)

	writeShadowREADME(t, transaction, []byte("goodbye"))

	assertFileContents(t, filepath.Join(realWorkspace, "README.md"), []byte("hello"))
	assertFileContents(t, filepath.Join(transaction.ShadowWorkspace(), "README.md"), []byte("goodbye"))
}

func TestRejectDiscardsShadowAndPreservesRealWorkspace(t *testing.T) {
	realWorkspace := newRealWorkspace(t, []byte("hello"))
	transaction := beginTransaction(t, realWorkspace)
	shadowWorkspace := transaction.ShadowWorkspace()
	writeShadowREADME(t, transaction, []byte("goodbye"))

	if err := transaction.Reject(); err != nil {
		t.Fatalf("reject transaction: %v", err)
	}

	if transaction.State() != shadowfs.StateRejected {
		t.Fatalf("state = %s, want %s", transaction.State(), shadowfs.StateRejected)
	}
	assertFileContents(t, filepath.Join(realWorkspace, "README.md"), []byte("hello"))
	assertPathMissing(t, shadowWorkspace)
}

func TestApplyCommitIsTheOnlyPointRealWorkspaceChanges(t *testing.T) {
	realWorkspace := newRealWorkspace(t, []byte("hello"))
	transaction := beginTransaction(t, realWorkspace)
	shadowWorkspace := transaction.ShadowWorkspace()
	writeShadowREADME(t, transaction, []byte("goodbye"))

	assertFileContents(t, filepath.Join(realWorkspace, "README.md"), []byte("hello"))
	if err := transaction.ApplyCommit(); err != nil {
		t.Fatalf("apply commit: %v", err)
	}

	if transaction.State() != shadowfs.StateCommitted {
		t.Fatalf("state = %s, want %s", transaction.State(), shadowfs.StateCommitted)
	}
	assertFileContents(t, filepath.Join(realWorkspace, "README.md"), []byte("goodbye"))
	assertPathMissing(t, shadowWorkspace)
}

func TestApplyCommitPreservesExactShadowBytes(t *testing.T) {
	testCases := map[string][]byte{
		"empty":     {},
		"multiline": []byte("# Mirage\n\ntransactional security runtime\n"),
		"binary":    {0x00, 0x01, 0xfe, 0xff},
	}

	for name, contents := range testCases {
		t.Run(name, func(t *testing.T) {
			realWorkspace := newRealWorkspace(t, []byte("hello"))
			transaction := beginTransaction(t, realWorkspace)
			writeShadowREADME(t, transaction, contents)

			if err := transaction.ApplyCommit(); err != nil {
				t.Fatalf("apply commit: %v", err)
			}
			assertFileContents(t, filepath.Join(realWorkspace, "README.md"), contents)
		})
	}
}

func TestTerminalTransactionsRejectFurtherTransitions(t *testing.T) {
	t.Run("commit after reject", func(t *testing.T) {
		transaction := beginTransaction(t, newRealWorkspace(t, []byte("hello")))
		if err := transaction.Reject(); err != nil {
			t.Fatalf("reject transaction: %v", err)
		}
		assertInvalidTransition(t, transaction.ApplyCommit())
	})

	t.Run("reject after commit", func(t *testing.T) {
		transaction := beginTransaction(t, newRealWorkspace(t, []byte("hello")))
		if err := transaction.ApplyCommit(); err != nil {
			t.Fatalf("apply commit: %v", err)
		}
		assertInvalidTransition(t, transaction.Reject())
	})

	t.Run("duplicate commit", func(t *testing.T) {
		transaction := beginTransaction(t, newRealWorkspace(t, []byte("hello")))
		if err := transaction.ApplyCommit(); err != nil {
			t.Fatalf("apply commit: %v", err)
		}
		assertInvalidTransition(t, transaction.ApplyCommit())
	})

	t.Run("duplicate reject", func(t *testing.T) {
		transaction := beginTransaction(t, newRealWorkspace(t, []byte("hello")))
		if err := transaction.Reject(); err != nil {
			t.Fatalf("reject transaction: %v", err)
		}
		assertInvalidTransition(t, transaction.Reject())
	})
}

func TestBeginFailsClosedForInvalidWorkspace(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		_, err := shadowfs.Begin("")
		if !errors.Is(err, shadowfs.ErrInvalidWorkspace) {
			t.Fatalf("error = %v, want ErrInvalidWorkspace", err)
		}
	})

	t.Run("missing README", func(t *testing.T) {
		_, err := shadowfs.Begin(t.TempDir())
		if !errors.Is(err, shadowfs.ErrInvalidWorkspace) {
			t.Fatalf("error = %v, want ErrInvalidWorkspace", err)
		}
	})

	t.Run("workspace is a file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "workspace")
		if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
			t.Fatalf("create workspace file: %v", err)
		}
		_, err := shadowfs.Begin(path)
		if !errors.Is(err, shadowfs.ErrInvalidWorkspace) {
			t.Fatalf("error = %v, want ErrInvalidWorkspace", err)
		}
	})
}

func TestBeginRejectsSymlinkREADME(t *testing.T) {
	root := t.TempDir()
	realWorkspace := filepath.Join(root, "real")
	if err := os.Mkdir(realWorkspace, 0o700); err != nil {
		t.Fatalf("create real workspace: %v", err)
	}
	outside := filepath.Join(root, "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatalf("create outside file: %v", err)
	}
	createSymlinkOrSkip(t, outside, filepath.Join(realWorkspace, "README.md"))

	_, err := shadowfs.Begin(realWorkspace)
	if !errors.Is(err, shadowfs.ErrUnsafeFile) {
		t.Fatalf("error = %v, want ErrUnsafeFile", err)
	}
	assertFileContents(t, outside, []byte("outside"))
}

func TestApplyCommitRejectsShadowSymlinkWithoutRealMutation(t *testing.T) {
	realWorkspace := newRealWorkspace(t, []byte("hello"))
	transaction := beginTransaction(t, realWorkspace)
	shadowREADME := filepath.Join(transaction.ShadowWorkspace(), "README.md")
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatalf("create outside file: %v", err)
	}
	if err := os.Remove(shadowREADME); err != nil {
		t.Fatalf("remove shadow README: %v", err)
	}
	createSymlinkOrSkip(t, outside, shadowREADME)

	err := transaction.ApplyCommit()
	if !errors.Is(err, shadowfs.ErrUnsafeFile) {
		t.Fatalf("error = %v, want ErrUnsafeFile", err)
	}
	if transaction.State() != shadowfs.StateActive {
		t.Fatalf("state = %s, want %s", transaction.State(), shadowfs.StateActive)
	}
	assertFileContents(t, filepath.Join(realWorkspace, "README.md"), []byte("hello"))
	assertFileContents(t, outside, []byte("outside"))
}

func TestApplyCommitRejectsNonRegularShadowEntryWithoutRealMutation(t *testing.T) {
	realWorkspace := newRealWorkspace(t, []byte("hello"))
	transaction := beginTransaction(t, realWorkspace)
	shadowREADME := filepath.Join(transaction.ShadowWorkspace(), "README.md")
	if err := os.Remove(shadowREADME); err != nil {
		t.Fatalf("remove shadow README: %v", err)
	}
	if err := os.Mkdir(shadowREADME, 0o700); err != nil {
		t.Fatalf("replace shadow README with directory: %v", err)
	}

	err := transaction.ApplyCommit()
	if !errors.Is(err, shadowfs.ErrUnsafeFile) {
		t.Fatalf("error = %v, want ErrUnsafeFile", err)
	}
	if transaction.State() != shadowfs.StateActive {
		t.Fatalf("state = %s, want %s", transaction.State(), shadowfs.StateActive)
	}
	assertFileContents(t, filepath.Join(realWorkspace, "README.md"), []byte("hello"))
}

func TestApplyCommitFailsClosedWhenShadowREADMEIsMissing(t *testing.T) {
	realWorkspace := newRealWorkspace(t, []byte("hello"))
	transaction := beginTransaction(t, realWorkspace)
	if err := os.Remove(filepath.Join(transaction.ShadowWorkspace(), "README.md")); err != nil {
		t.Fatalf("remove shadow README: %v", err)
	}

	if err := transaction.ApplyCommit(); err == nil {
		t.Fatal("apply commit succeeded with a missing shadow README")
	}
	if transaction.State() != shadowfs.StateActive {
		t.Fatalf("state = %s, want %s", transaction.State(), shadowfs.StateActive)
	}
	assertFileContents(t, filepath.Join(realWorkspace, "README.md"), []byte("hello"))
}

func TestRejectRemovesOnlyTransactionOwnedShadow(t *testing.T) {
	realWorkspace := newRealWorkspace(t, []byte("hello"))
	transaction := beginTransaction(t, realWorkspace)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("preserve me"), 0o600); err != nil {
		t.Fatalf("create outside file: %v", err)
	}

	if err := transaction.Reject(); err != nil {
		t.Fatalf("reject transaction: %v", err)
	}

	assertFileContents(t, filepath.Join(realWorkspace, "README.md"), []byte("hello"))
	assertFileContents(t, outside, []byte("preserve me"))
}

func beginTransaction(t *testing.T, realWorkspace string) *shadowfs.Transaction {
	t.Helper()
	transaction, err := shadowfs.Begin(realWorkspace)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	t.Cleanup(func() {
		if transaction.State() == shadowfs.StateActive {
			if err := transaction.Reject(); err != nil {
				t.Errorf("cleanup active transaction: %v", err)
			}
		}
	})
	return transaction
}

func newRealWorkspace(t *testing.T, contents []byte) string {
	t.Helper()
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), contents, 0o600); err != nil {
		t.Fatalf("write real README: %v", err)
	}
	return workspace
}

func writeShadowREADME(t *testing.T, transaction *shadowfs.Transaction, contents []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(transaction.ShadowWorkspace(), "README.md"), contents, 0o600); err != nil {
		t.Fatalf("write shadow README: %v", err)
	}
}

func assertFileContents(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != string(want) {
		t.Fatalf("contents of %s = %q, want %q", path, got, want)
	}
}

func assertPathMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat %s error = %v, want path not to exist", path, err)
	}
}

func assertInvalidTransition(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, shadowfs.ErrInvalidTransition) {
		t.Fatalf("error = %v, want ErrInvalidTransition", err)
	}
}

func createSymlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation is unavailable in this environment: %v", err)
	}
}
