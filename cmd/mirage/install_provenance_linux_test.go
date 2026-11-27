//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxInstallerRejectsDirtySourceBeforeBuild(t *testing.T) {
	repo := t.TempDir()
	script, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(repo, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	installer := filepath.Join(repo, "scripts", "install.sh")
	if err := os.WriteFile(installer, script, 0o755); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	git("init")
	git("add", ".")
	git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", "commit", "-m", "fixture")
	if err := os.WriteFile(filepath.Join(repo, "untracked.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	cmd := exec.Command("bash", installer)
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "requires a clean source checkout") {
		t.Fatalf("dirty checkout not rejected: %v: %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(home, ".local", "bin", "mirage")); !os.IsNotExist(err) {
		t.Fatalf("installation changed: %v", err)
	}
}
