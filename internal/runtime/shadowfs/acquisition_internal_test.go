package shadowfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadManagedFileRejectsTypeSwapBeforeRead(t *testing.T) {
	workspace := t.TempDir()
	readme := filepath.Join(workspace, managedFile)
	if err := os.WriteFile(readme, []byte("original"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}

	_, _, err := readManagedFileWithHook(workspace, func() {
		if removeErr := os.Remove(readme); removeErr != nil {
			t.Fatalf("remove README in hook: %v", removeErr)
		}
		if mkdirErr := os.Mkdir(readme, 0o700); mkdirErr != nil {
			t.Fatalf("replace README with directory in hook: %v", mkdirErr)
		}
	})
	if !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("error = %v, want ErrUnsafeFile", err)
	}
}

func TestObserveManagedResourceClassifiesTypeSwapBeforeRead(t *testing.T) {
	workspace := t.TempDir()
	readme := filepath.Join(workspace, managedFile)
	if err := os.WriteFile(readme, []byte("original"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}

	observation, err := observeManagedResourceWithHook(workspace, func() {
		if removeErr := os.Remove(readme); removeErr != nil {
			t.Fatalf("remove README in hook: %v", removeErr)
		}
		if mkdirErr := os.Mkdir(readme, 0o700); mkdirErr != nil {
			t.Fatalf("replace README with directory in hook: %v", mkdirErr)
		}
	})
	if err != nil {
		t.Fatalf("observe resource: %v", err)
	}
	if observation.identity != "type:directory" {
		t.Fatalf("identity = %q, want type:directory", observation.identity)
	}
}

func TestReadManagedFileRejectsSymlinkSwapBeforeRead(t *testing.T) {
	workspace := t.TempDir()
	readme := filepath.Join(workspace, managedFile)
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

	_, _, err := readManagedFileWithHook(workspace, func() {
		if removeErr := os.Remove(readme); removeErr != nil {
			t.Fatalf("remove README in hook: %v", removeErr)
		}
		if symlinkErr := os.Symlink(target, readme); symlinkErr != nil {
			t.Fatalf("replace README with symlink in hook: %v", symlinkErr)
		}
	})
	if !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("error = %v, want ErrUnsafeFile", err)
	}
}
