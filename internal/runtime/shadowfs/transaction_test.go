package shadowfs_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
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
	assertNoPreparedCommitFiles(t, realWorkspace)
	if err := transaction.ApplyCommit(); err != nil {
		t.Fatalf("apply commit: %v", err)
	}

	if transaction.State() != shadowfs.StateCommitted {
		t.Fatalf("state = %s, want %s", transaction.State(), shadowfs.StateCommitted)
	}
	assertFileContents(t, filepath.Join(realWorkspace, "README.md"), []byte("goodbye"))
	assertPathMissing(t, shadowWorkspace)
	assertNoPreparedCommitFiles(t, realWorkspace)
}

func TestApplyCommitDetectsExternalModificationConflict(t *testing.T) {
	realWorkspace := newRealWorkspace(t, []byte("A"))
	transaction := beginTransaction(t, realWorkspace)
	shadowWorkspace := transaction.ShadowWorkspace()
	writeShadowREADME(t, transaction, []byte("B"))
	writeRealREADME(t, realWorkspace, []byte("C"))

	err := transaction.ApplyCommit()
	if !errors.Is(err, shadowfs.ErrStateConflict) {
		t.Fatalf("error = %v, want ErrStateConflict", err)
	}
	var conflict *shadowfs.StateConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want *StateConflict", err)
	}
	if conflict.Resource != "README.md" {
		t.Fatalf("conflict resource = %q, want README.md", conflict.Resource)
	}
	if conflict.ExpectedBaseline != contentIdentity([]byte("A")) {
		t.Fatalf("expected baseline = %q, want %q", conflict.ExpectedBaseline, contentIdentity([]byte("A")))
	}
	if conflict.ObservedCurrent != contentIdentity([]byte("C")) {
		t.Fatalf("observed current = %q, want %q", conflict.ObservedCurrent, contentIdentity([]byte("C")))
	}
	if transaction.State() != shadowfs.StateConflicted {
		t.Fatalf("state = %s, want %s", transaction.State(), shadowfs.StateConflicted)
	}
	assertFileContents(t, filepath.Join(realWorkspace, "README.md"), []byte("C"))
	assertPathMissing(t, shadowWorkspace)
}

func TestContentIdenticalExternalRewriteRemainsCommitCompatible(t *testing.T) {
	realWorkspace := newRealWorkspace(t, []byte("A"))
	transaction := beginTransaction(t, realWorkspace)
	writeShadowREADME(t, transaction, []byte("B"))

	// M2 uses content identity, not inode or file-generation identity.
	writeRealREADME(t, realWorkspace, []byte("A"))

	if err := transaction.ApplyCommit(); err != nil {
		t.Fatalf("apply commit after content-identical rewrite: %v", err)
	}
	if transaction.State() != shadowfs.StateCommitted {
		t.Fatalf("state = %s, want %s", transaction.State(), shadowfs.StateCommitted)
	}
	assertFileContents(t, filepath.Join(realWorkspace, "README.md"), []byte("B"))
}

func TestConflictNeverAppliesShadowContentsToRealWorkspace(t *testing.T) {
	realWorkspace := newRealWorkspace(t, []byte("baseline"))
	transaction := beginTransaction(t, realWorkspace)
	writeShadowREADME(t, transaction, []byte("shadow value that must not commit"))
	writeRealREADME(t, realWorkspace, []byte("external writer value"))

	if err := transaction.ApplyCommit(); !errors.Is(err, shadowfs.ErrStateConflict) {
		t.Fatalf("error = %v, want ErrStateConflict", err)
	}

	assertFileContents(t, filepath.Join(realWorkspace, "README.md"), []byte("external writer value"))
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
	t.Run("commit after conflict", func(t *testing.T) {
		realWorkspace := newRealWorkspace(t, []byte("A"))
		transaction := beginTransaction(t, realWorkspace)
		writeRealREADME(t, realWorkspace, []byte("C"))
		if err := transaction.ApplyCommit(); !errors.Is(err, shadowfs.ErrStateConflict) {
			t.Fatalf("create conflict: %v", err)
		}
		assertInvalidTransition(t, transaction.ApplyCommit())
		assertFileContents(t, filepath.Join(realWorkspace, "README.md"), []byte("C"))
	})

	t.Run("reject after conflict", func(t *testing.T) {
		realWorkspace := newRealWorkspace(t, []byte("A"))
		transaction := beginTransaction(t, realWorkspace)
		writeRealREADME(t, realWorkspace, []byte("C"))
		if err := transaction.ApplyCommit(); !errors.Is(err, shadowfs.ErrStateConflict) {
			t.Fatalf("create conflict: %v", err)
		}
		assertInvalidTransition(t, transaction.Reject())
		assertFileContents(t, filepath.Join(realWorkspace, "README.md"), []byte("C"))
	})

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

func TestApplyCommitTreatsMissingRealREADMEAsConflict(t *testing.T) {
	realWorkspace := newRealWorkspace(t, []byte("A"))
	transaction := beginTransaction(t, realWorkspace)
	shadowWorkspace := transaction.ShadowWorkspace()
	writeShadowREADME(t, transaction, []byte("B"))
	if err := os.Remove(filepath.Join(realWorkspace, "README.md")); err != nil {
		t.Fatalf("remove real README: %v", err)
	}

	err := transaction.ApplyCommit()
	if !errors.Is(err, shadowfs.ErrStateConflict) {
		t.Fatalf("error = %v, want ErrStateConflict", err)
	}
	var conflict *shadowfs.StateConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want *StateConflict", err)
	}
	if conflict.ObservedCurrent != "missing" {
		t.Fatalf("observed current = %q, want missing", conflict.ObservedCurrent)
	}
	if transaction.State() != shadowfs.StateConflicted {
		t.Fatalf("state = %s, want %s", transaction.State(), shadowfs.StateConflicted)
	}
	assertPathMissing(t, filepath.Join(realWorkspace, "README.md"))
	assertPathMissing(t, shadowWorkspace)
	assertNoPreparedCommitFiles(t, realWorkspace)
}

func TestApplyCommitTreatsRealREADMETypeReplacementAsConflict(t *testing.T) {
	realWorkspace := newRealWorkspace(t, []byte("A"))
	transaction := beginTransaction(t, realWorkspace)
	shadowWorkspace := transaction.ShadowWorkspace()
	writeShadowREADME(t, transaction, []byte("B"))
	realREADME := filepath.Join(realWorkspace, "README.md")
	if err := os.Remove(realREADME); err != nil {
		t.Fatalf("remove real README: %v", err)
	}
	if err := os.Mkdir(realREADME, 0o700); err != nil {
		t.Fatalf("replace real README with directory: %v", err)
	}

	err := transaction.ApplyCommit()
	if !errors.Is(err, shadowfs.ErrStateConflict) {
		t.Fatalf("error = %v, want ErrStateConflict", err)
	}
	var conflict *shadowfs.StateConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want *StateConflict", err)
	}
	if conflict.ObservedCurrent != "type:directory" {
		t.Fatalf("observed current = %q, want type:directory", conflict.ObservedCurrent)
	}
	if transaction.State() != shadowfs.StateConflicted {
		t.Fatalf("state = %s, want %s", transaction.State(), shadowfs.StateConflicted)
	}
	info, statErr := os.Stat(realREADME)
	if statErr != nil {
		t.Fatalf("stat real README replacement: %v", statErr)
	}
	if !info.IsDir() {
		t.Fatalf("real README replacement mode = %s, want directory", info.Mode())
	}
	assertPathMissing(t, shadowWorkspace)
	assertNoPreparedCommitFiles(t, realWorkspace)
}

func TestApplyCommitTreatsRealREADMESymlinkReplacementAsConflict(t *testing.T) {
	realWorkspace := newRealWorkspace(t, []byte("A"))
	transaction := beginTransaction(t, realWorkspace)
	shadowWorkspace := transaction.ShadowWorkspace()
	writeShadowREADME(t, transaction, []byte("B"))
	realREADME := filepath.Join(realWorkspace, "README.md")
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("external"), 0o600); err != nil {
		t.Fatalf("create outside file: %v", err)
	}
	if err := os.Remove(realREADME); err != nil {
		t.Fatalf("remove real README: %v", err)
	}
	createSymlinkOrSkip(t, outside, realREADME)

	err := transaction.ApplyCommit()
	if !errors.Is(err, shadowfs.ErrStateConflict) {
		t.Fatalf("error = %v, want ErrStateConflict", err)
	}
	var conflict *shadowfs.StateConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want *StateConflict", err)
	}
	if conflict.ObservedCurrent != "type:symlink" {
		t.Fatalf("observed current = %q, want type:symlink", conflict.ObservedCurrent)
	}
	if transaction.State() != shadowfs.StateConflicted {
		t.Fatalf("state = %s, want %s", transaction.State(), shadowfs.StateConflicted)
	}
	assertFileContents(t, outside, []byte("external"))
	assertPathMissing(t, shadowWorkspace)
	assertNoPreparedCommitFiles(t, realWorkspace)
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

func writeRealREADME(t *testing.T, realWorkspace string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(realWorkspace, "README.md"), contents, 0o600); err != nil {
		t.Fatalf("write real README: %v", err)
	}
}

func contentIdentity(contents []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(contents))
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

func assertNoPreparedCommitFiles(t *testing.T, realWorkspace string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(realWorkspace, ".mirage-readme-*"))
	if err != nil {
		t.Fatalf("find prepared commit files: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("prepared commit files remain after failed revalidation: %v", matches)
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
