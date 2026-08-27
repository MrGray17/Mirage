package realcommit

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestApplyReplacesOnlyContentAndPreservesRealMode(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "README.md")
	before := []byte("before")
	after := []byte("after\n")
	if err := os.WriteFile(target, before, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o600); err != nil {
		t.Fatal(err)
	}
	plan := newTestPlan(t, root, before, after, 0o600)

	if err := Apply(plan, allowReplace); err != nil {
		t.Fatalf("apply: %v", err)
	}
	contents, err := os.ReadFile(target)
	if err != nil || string(contents) != string(after) {
		t.Fatalf("contents = %q, err = %v", contents, err)
	}
	info, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want regular 0600", info.Mode())
	}
	assertNoStaging(t, root)
}

func TestApplyCallbackFailureLeavesTargetUnchangedAndCleansStaging(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "README.md")
	before := []byte("before")
	if err := os.WriteFile(target, before, 0o600); err != nil {
		t.Fatal(err)
	}
	plan := newTestPlan(t, root, before, []byte("authorized"), 0o600)
	authorityErr := errors.New("authority expired at replacement")
	called := false
	err := Apply(plan, func() error {
		called = true
		return authorityErr
	})
	if !called || !errors.Is(err, authorityErr) {
		t.Fatalf("callback called = %t, apply error = %v", called, err)
	}
	contents, readErr := os.ReadFile(target)
	if readErr != nil || string(contents) != string(before) {
		t.Fatalf("callback failure changed target: %q, %v", contents, readErr)
	}
	assertNoStaging(t, root)
}

func TestApplyReportsCleanupFailureAlongsideAuthorityDenial(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("directory permission cleanup failure requires Linux semantics")
	}
	root := t.TempDir()
	target := filepath.Join(root, "README.md")
	before := []byte("before")
	if err := os.WriteFile(target, before, 0o600); err != nil {
		t.Fatal(err)
	}
	plan := newTestPlan(t, root, before, []byte("authorized"), 0o600)
	authorityErr := errors.New("contract expired at replacement")
	err := Apply(plan, func() error {
		if err := os.Chmod(root, 0o500); err != nil {
			return fmt.Errorf("deny staging cleanup for test: %w", err)
		}
		return authorityErr
	})
	if restoreErr := os.Chmod(root, 0o700); restoreErr != nil {
		t.Fatal(restoreErr)
	}
	if !errors.Is(err, authorityErr) || !errors.Is(err, ErrCleanup) {
		t.Fatalf("apply error = %v, want authority denial plus cleanup failure", err)
	}
	contents, readErr := os.ReadFile(target)
	if readErr != nil || string(contents) != string(before) {
		t.Fatalf("cleanup failure changed target: %q, %v", contents, readErr)
	}
	matches, globErr := filepath.Glob(filepath.Join(root, ".mirage-commit-*.tmp"))
	if globErr != nil || len(matches) != 1 {
		t.Fatalf("orphan staging evidence = %v, %v", matches, globErr)
	}
}

func TestApplyRejectsChangedRealTargetWithoutMutation(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "README.md")
	before := []byte("before")
	after := []byte("authorized")
	if err := os.WriteFile(target, before, 0o600); err != nil {
		t.Fatal(err)
	}
	plan := newTestPlan(t, root, before, after, 0o600)
	if err := os.WriteFile(target, []byte("external change"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Apply(plan, allowReplace); !errors.Is(err, ErrConflict) {
		t.Fatalf("apply error = %v, want conflict", err)
	}
	contents, err := os.ReadFile(target)
	if err != nil || string(contents) != "external change" {
		t.Fatalf("conflict changed reality: %q, %v", contents, err)
	}
	assertNoStaging(t, root)
}

func TestApplyRejectsChangedRealModeWithoutMutation(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "README.md")
	before := []byte("before")
	if err := os.WriteFile(target, before, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o600); err != nil {
		t.Fatal(err)
	}
	plan := newTestPlan(t, root, before, []byte("authorized"), 0o600)
	if err := os.Chmod(target, 0o640); err != nil {
		t.Fatal(err)
	}

	if err := Apply(plan, allowReplace); !errors.Is(err, ErrConflict) {
		t.Fatalf("apply error = %v, want mode conflict", err)
	}
	contents, err := os.ReadFile(target)
	if err != nil || string(contents) != string(before) {
		t.Fatalf("mode conflict changed content: %q, %v", contents, err)
	}
	info, err := os.Lstat(target)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("mode conflict changed external mode: %v, %v", info, err)
	}
	assertNoStaging(t, root)
}

func TestApplyRejectsReplacedTargetTypeWithoutMutation(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "README.md")
	outside := filepath.Join(t.TempDir(), "outside.txt")
	before := []byte("before")
	if err := os.WriteFile(target, before, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan := newTestPlan(t, root, before, []byte("authorized"), 0o600)
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, target); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if err := Apply(plan, allowReplace); !errors.Is(err, ErrConflict) {
		t.Fatalf("apply error = %v, want observed type conflict", err)
	}
	contents, err := os.ReadFile(outside)
	if err != nil || string(contents) != "outside" {
		t.Fatalf("outside target changed: %q, %v", contents, err)
	}
	info, err := os.Lstat(target)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("replacement symlink changed: %v, %v", info, err)
	}
	assertNoStaging(t, root)
}

func TestApplyTreatsObservedDeletionAsConflict(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "README.md")
	before := []byte("before")
	if err := os.WriteFile(target, before, 0o600); err != nil {
		t.Fatal(err)
	}
	plan := newTestPlan(t, root, before, []byte("authorized"), 0o600)
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := Apply(plan, allowReplace); !errors.Is(err, ErrConflict) {
		t.Fatalf("apply error = %v, want observed deletion conflict", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted target was recreated: %v", err)
	}
	assertNoStaging(t, root)
}

func TestNewRejectsUnboundOrMismatchedContent(t *testing.T) {
	root := t.TempDir()
	valid := Spec{
		ManifestHash:         "sha256:manifest",
		AuthorityHash:        "sha256:authority",
		RealBaselineIdentity: "sha256:baseline",
		RealWorkspace:        root,
		Resource:             "/workspace/README.md",
		BeforeDigest:         digest([]byte("before")),
		AfterDigest:          digest([]byte("after")),
		RealMode:             0o600,
		Contents:             []byte("different"),
	}
	if _, err := New(valid); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("mismatched content error = %v", err)
	}
	valid.Contents = []byte("after")
	valid.ManifestHash = ""
	if _, err := New(valid); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("unbound authority error = %v", err)
	}
	valid.ManifestHash = "sha256:manifest"
	valid.Resource = "/workspace/../escape"
	if _, err := New(valid); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("unsafe resource error = %v", err)
	}
}

func newTestPlan(t *testing.T, root string, before, after []byte, mode uint32) *Plan {
	t.Helper()
	plan, err := New(Spec{
		ManifestHash:         "sha256:manifest",
		AuthorityHash:        "sha256:authority",
		RealBaselineIdentity: "sha256:baseline",
		RealWorkspace:        root,
		Resource:             "/workspace/README.md",
		BeforeDigest:         digest(before),
		AfterDigest:          digest(after),
		RealMode:             mode,
		Contents:             after,
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func digest(contents []byte) string {
	sum := sha256.Sum256(contents)
	return fmt.Sprintf("sha256:%x", sum)
}

func assertNoStaging(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".mirage-commit-") {
			t.Fatalf("commit staging artifact remains: %s", entry.Name())
		}
	}
}

func allowReplace() error { return nil }
