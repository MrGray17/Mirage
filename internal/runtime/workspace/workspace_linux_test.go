//go:build linux

package workspace

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareRejectsTMPDIRInsideRealityBeforeCreation(t *testing.T) {
	real := workspaceTestDir(t)
	if err := os.WriteFile(filepath.Join(real, "README.md"), []byte("real"), 0o600); err != nil {
		t.Fatal(err)
	}
	unsafeTemp := filepath.Join(real, "tmpdir")
	if err := os.Mkdir(unsafeTemp, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", unsafeTemp)

	if _, err := Prepare(real); !errors.Is(err, ErrUnsafeTemp) {
		t.Fatalf("prepare error = %v", err)
	}
	entries, err := os.ReadDir(unsafeTemp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("Prepare created entries under TMPDIR inside reality: %v", entries)
	}
}

func TestPrepareRejectsSymlinkedTempRootResolvingInsideReality(t *testing.T) {
	real := workspaceTestDir(t)
	if err := os.WriteFile(filepath.Join(real, "README.md"), []byte("real"), 0o600); err != nil {
		t.Fatal(err)
	}
	unsafeTemp := filepath.Join(real, "physical-temp")
	if err := os.Mkdir(unsafeTemp, 0o700); err != nil {
		t.Fatal(err)
	}
	linkParent := workspaceTestDir(t)
	linkedTemp := filepath.Join(linkParent, "linked-temp")
	if err := os.Symlink(unsafeTemp, linkedTemp); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if _, err := prepareAtTempRoot(real, linkedTemp); !errors.Is(err, ErrUnsafeTemp) {
		t.Fatalf("prepare error = %v", err)
	}
	entries, err := os.ReadDir(unsafeTemp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("Prepare created entries through unsafe temp symlink: %v", entries)
	}
}
