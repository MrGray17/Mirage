package filesystem

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteRegularFileRejectsTypeSwapBeforeMutation(t *testing.T) {
	workspace := t.TempDir()
	readme := filepath.Join(workspace, "README.md")
	if err := os.WriteFile(readme, []byte("original"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}

	err := writeRegularFileWithHook(workspace, []byte("must not write"), func() {
		if removeErr := os.Remove(readme); removeErr != nil {
			t.Fatalf("remove README in hook: %v", removeErr)
		}
		if mkdirErr := os.Mkdir(readme, 0o700); mkdirErr != nil {
			t.Fatalf("replace README with directory in hook: %v", mkdirErr)
		}
	})
	if !errors.Is(err, ErrUnsafeResource) {
		t.Fatalf("error = %v, want ErrUnsafeResource", err)
	}
	info, statErr := os.Lstat(readme)
	if statErr != nil || !info.IsDir() {
		t.Fatalf("README replacement = %v, %v; want directory", info, statErr)
	}
}

func TestWriteRegularFileRejectsSymlinkSwapWithoutTouchingTarget(t *testing.T) {
	workspace := t.TempDir()
	readme := filepath.Join(workspace, "README.md")
	if err := os.WriteFile(readme, []byte("original"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	target := filepath.Join(t.TempDir(), "target.txt")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	probe := filepath.Join(t.TempDir(), "symlink-probe")
	if err := os.Symlink(target, probe); err != nil {
		t.Skipf("symlink creation is unavailable in this environment: %v", err)
	}
	if err := os.Remove(probe); err != nil {
		t.Fatalf("remove symlink probe: %v", err)
	}

	err := writeRegularFileWithHook(workspace, []byte("must not write"), func() {
		if removeErr := os.Remove(readme); removeErr != nil {
			t.Fatalf("remove README in hook: %v", removeErr)
		}
		if symlinkErr := os.Symlink(target, readme); symlinkErr != nil {
			t.Fatalf("replace README with symlink in hook: %v", symlinkErr)
		}
	})
	if !errors.Is(err, ErrUnsafeResource) {
		t.Fatalf("error = %v, want ErrUnsafeResource", err)
	}
	contents, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("read target: %v", readErr)
	}
	if string(contents) != "outside" {
		t.Fatalf("target contents = %q, want outside", contents)
	}
}

func TestFinalValidationDetectsPostValidationPathReplacement(t *testing.T) {
	workspace := t.TempDir()
	readme := filepath.Join(workspace, "README.md")
	if err := os.WriteFile(readme, []byte("original"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}

	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer func() {
		if closeErr := root.Close(); closeErr != nil {
			t.Errorf("close root: %v", closeErr)
		}
	}()

	file, err := root.OpenFile("README.md", os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open README: %v", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			t.Errorf("close README: %v", closeErr)
		}
	}()

	openedInfo, err := file.Stat()
	if err != nil {
		t.Fatalf("stat opened README: %v", err)
	}
	if err := validateCurrentEntry(root, openedInfo); err != nil {
		t.Fatalf("initial validation: %v", err)
	}

	// Exercise the residual race window deliberately: the trusted handle has
	// already been validated, then another actor replaces the named entry before
	// the write. Some platforms do not permit removing an open file; those
	// platforms cannot execute this exact race and are covered by Linux CI.
	if err := os.Remove(readme); err != nil {
		t.Skipf("platform cannot replace an open file: %v", err)
	}
	if err := os.Mkdir(readme, 0o700); err != nil {
		t.Fatalf("replace README with directory: %v", err)
	}

	if err := file.Truncate(0); err != nil {
		t.Fatalf("truncate opened handle: %v", err)
	}
	if _, err := file.Write([]byte("shadow mutation")); err != nil {
		t.Fatalf("write opened handle: %v", err)
	}

	if err := validateCurrentEntry(root, openedInfo); !errors.Is(err, ErrUnsafeResource) {
		t.Fatalf("final validation error = %v, want ErrUnsafeResource", err)
	}
	info, err := os.Lstat(readme)
	if err != nil || !info.IsDir() {
		t.Fatalf("named README replacement = %v, %v; want directory", info, err)
	}
}
