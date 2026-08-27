package workspace

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	runtimedocker "github.com/MrGray17/Mirage/internal/runtime/docker"
)

func TestPrepareCopiesOnlyBoundedREADMEIntoDisposableWorkspace(t *testing.T) {
	real := workspaceTestDir(t)
	if err := os.WriteFile(filepath.Join(real, managedFile), []byte("real contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, ".env"), []byte("SECRET=value"), 0o600); err != nil {
		t.Fatal(err)
	}

	disposable, err := Prepare(real)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	t.Cleanup(func() {
		if err := disposable.Cleanup(); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	contents, err := os.ReadFile(filepath.Join(disposable.Path(), managedFile))
	if err != nil {
		t.Fatalf("read disposable README: %v", err)
	}
	if string(contents) != "real contents" {
		t.Fatalf("contents = %q", contents)
	}
	if _, err := os.Lstat(filepath.Join(disposable.Path(), ".env")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(".env entered disposable workspace: %v", err)
	}
	marker, err := os.ReadFile(filepath.Join(disposable.Path(), runtimedocker.DisposableMarker))
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if string(marker) != disposable.Token() {
		t.Fatal("trusted disposable marker token mismatch")
	}
	if disposable.RealWorkspace() == disposable.Path() {
		t.Fatal("real workspace reused as disposable workspace")
	}
}

func TestPrepareRejectsSymlinkREADME(t *testing.T) {
	real := workspaceTestDir(t)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(real, managedFile)); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := Prepare(real); !errors.Is(err, ErrUnsafeSource) {
		t.Fatalf("prepare error = %v", err)
	}
}

func TestCleanupNeverTouchesReality(t *testing.T) {
	real := workspaceTestDir(t)
	realREADME := filepath.Join(real, managedFile)
	if err := os.WriteFile(realREADME, []byte("real"), 0o600); err != nil {
		t.Fatal(err)
	}
	disposable, err := Prepare(real)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	disposablePath := disposable.Path()
	if err := disposable.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(disposablePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("disposable path remains: %v", err)
	}
	contents, err := os.ReadFile(realREADME)
	if err != nil || string(contents) != "real" {
		t.Fatalf("real README changed: %q, %v", contents, err)
	}
}

func TestPrepareRejectsOverlappingPhysicalTempRootBeforeCreation(t *testing.T) {
	real := workspaceTestDir(t)
	if err := os.WriteFile(filepath.Join(real, managedFile), []byte("real"), 0o600); err != nil {
		t.Fatal(err)
	}
	unsafeTemp := filepath.Join(real, "temp")
	if err := os.Mkdir(unsafeTemp, 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := prepareAtTempRoot(real, unsafeTemp); !errors.Is(err, ErrUnsafeTemp) {
		t.Fatalf("prepare error = %v", err)
	}
	entries, err := os.ReadDir(unsafeTemp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("Prepare created entries under unsafe temp root: %v", entries)
	}
}

func workspaceTestDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp(".", ".mirage-workspace-test-")
	if err != nil {
		t.Fatalf("create workspace test directory: %v", err)
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		t.Fatalf("resolve workspace test directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(absolute); err != nil {
			t.Errorf("remove workspace test directory: %v", err)
		}
	})
	return absolute
}
