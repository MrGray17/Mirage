//go:build linux

package filesystem

import (
	"os"
	"path/filepath"
	"testing"
)

// This is an evidence-gate test, not product behavior. The Ubuntu security job
// must fail rather than silently skip if the filesystem cannot exercise the
// symlink and open-file replacement races that Linux CI exists to prove.
func TestLinuxEvidenceEnvironmentSupportsRequiredFilesystemSemantics(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatalf("create target: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Linux evidence environment cannot create symlink: %v", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatalf("remove symlink: %v", err)
	}

	path := filepath.Join(root, "open-file")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatalf("create open file: %v", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open file: %v", err)
	}
	defer file.Close()
	if err := os.Remove(path); err != nil {
		t.Fatalf("Linux evidence environment cannot unlink open file: %v", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("Linux evidence environment cannot replace unlinked path: %v", err)
	}
}
