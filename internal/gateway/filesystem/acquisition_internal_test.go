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
