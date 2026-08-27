package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunRequiresExplicitHostileFixtureCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(nil, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunRequiresPinnedImageInput(t *testing.T) {
	t.Setenv("MIRAGE_HOSTILE_IMAGE", "")
	var stdout, stderr bytes.Buffer
	if err := run([]string{"run", "hostile-fixture"}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "--image") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunRejectsUnsafeDurationBeforeWorkspaceCreation(t *testing.T) {
	t.Setenv("MIRAGE_HOSTILE_IMAGE", "example.invalid/image@sha256:"+strings.Repeat("0", 64))
	var stdout, stderr bytes.Buffer
	if err := run([]string{"run", "hostile-fixture", "--duration", "0s"}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "--duration") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunFailsClosedAndCleansWorkspaceOnNonLinuxHost(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("non-Linux fail-closed behavior")
	}
	real := mainTestWorkspace(t)
	if err := os.WriteFile(filepath.Join(real, "README.md"), []byte("real\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := m41TemporaryDirectories(t)
	image := "example.invalid/image@sha256:" + strings.Repeat("0", 64)
	var stdout, stderr bytes.Buffer
	err := run([]string{"run", "hostile-fixture", "--workspace", real, "--image", image, "--duration", "1s"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "requires a Linux Mirage host") {
		t.Fatalf("error = %v", err)
	}
	after := m41TemporaryDirectories(t)
	for path := range after {
		if _, existed := before[path]; !existed {
			t.Errorf("failed launch leaked disposable workspace %s", path)
		}
	}
}

func mainTestWorkspace(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp(".", ".mirage-main-test-")
	if err != nil {
		t.Fatalf("create main test workspace: %v", err)
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		t.Fatalf("resolve main test workspace: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(absolute); err != nil {
			t.Errorf("remove main test workspace: %v", err)
		}
	})
	return absolute
}

func m41TemporaryDirectories(t *testing.T) map[string]struct{} {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(os.TempDir(), "mirage-m41-*"))
	if err != nil {
		t.Fatalf("list M4.1 temporary directories: %v", err)
	}
	result := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		result[match] = struct{}{}
	}
	return result
}
