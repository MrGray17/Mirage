package docker_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	hostileruntime "github.com/MrGray17/Mirage/internal/runtime"
	runtimedocker "github.com/MrGray17/Mirage/internal/runtime/docker"
	"github.com/MrGray17/Mirage/internal/runtime/workspace"
)

func TestRootlessDockerContainsHostileFixture(t *testing.T) {
	if goruntime.GOOS != "linux" || os.Getenv("MIRAGE_M41_INTEGRATION") != "1" {
		t.Skip("set MIRAGE_M41_INTEGRATION=1 on a Linux rootless Docker host")
	}
	image := strings.TrimSpace(os.Getenv("MIRAGE_HOSTILE_IMAGE"))
	if image == "" {
		t.Fatal("MIRAGE_HOSTILE_IMAGE must name a preloaded digest-pinned image")
	}

	real, err := os.MkdirTemp(".", ".mirage-live-real-")
	if err != nil {
		t.Fatalf("create live real workspace: %v", err)
	}
	real, err = filepath.Abs(real)
	if err != nil {
		t.Fatalf("resolve live real workspace: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(real); err != nil {
			t.Errorf("remove live real workspace: %v", err)
		}
	})
	realREADME := filepath.Join(real, "README.md")
	if err := os.WriteFile(realREADME, []byte("trusted real contents\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	disposable, err := workspace.Prepare(real)
	if err != nil {
		t.Fatalf("prepare workspace: %v", err)
	}
	launcher, err := runtimedocker.New(runtimedocker.Config{
		Image:          image,
		ContainerName:  "mirage-live-" + disposable.Token()[:16],
		Workspace:      disposable.Path(),
		RealWorkspace:  disposable.RealWorkspace(),
		WorkspaceToken: disposable.Token(),
	})
	if err != nil {
		_ = disposable.Cleanup()
		t.Fatalf("new launcher: %v", err)
	}
	lifecycle, err := hostileruntime.NewLifecycle(launcher)
	if err != nil {
		_ = disposable.Cleanup()
		t.Fatalf("new lifecycle: %v", err)
	}

	cleaned := false
	t.Cleanup(func() {
		if cleaned {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := lifecycle.Destroy(ctx); err != nil {
			t.Errorf("sandbox cleanup failed; workspace retained at %s: %v", disposable.Path(), err)
			return
		}
		if err := disposable.Cleanup(); err != nil {
			t.Errorf("workspace cleanup: %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := lifecycle.Prepare(ctx); err != nil {
		cancel()
		t.Fatalf("prepare runtime: %v", err)
	}
	if err := lifecycle.Start(ctx); err != nil {
		cancel()
		t.Fatalf("start runtime: %v", err)
	}
	cancel()

	reportPath := filepath.Join(disposable.Path(), ".mirage-hostile-report")
	deadline := time.Now().Add(15 * time.Second)
	var report []byte
	for time.Now().Before(deadline) {
		report, _ = os.ReadFile(reportPath)
		if reportHasPrefix(report, "child_pid=") &&
			(reportHasLine(report, "network_probe=READY") || reportHasLine(report, "network_probe=UNAVAILABLE")) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	freezeCtx, cancelFreeze := context.WithTimeout(context.Background(), 30*time.Second)
	err = lifecycle.Freeze(freezeCtx)
	cancelFreeze()
	if err != nil {
		t.Fatalf("freeze runtime: %v", err)
	}
	if lifecycle.State() != hostileruntime.StateFrozen {
		t.Fatalf("state = %s", lifecycle.State())
	}

	report, err = os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read hostile report: %v", err)
	}
	requiredEvidence := []string{
		"readme_modify=attempted",
		"forbidden_create=attempted",
		"path_escape=blocked",
		"host_home_probe=READY",
		"host_home=absent",
		"dot_env=absent",
		"docker_socket=absent",
		"network_probe=READY",
		"network=BLOCKED",
		"symlink_create=attempted",
	}
	for _, evidence := range requiredEvidence {
		if !reportHasLine(report, evidence) {
			t.Errorf("hostile report lacks %q:\n%s", evidence, report)
		}
	}
	if reportHasLine(report, "network_probe=UNAVAILABLE") {
		t.Errorf("hostile image did not provide the required network probe:\n%s", report)
	}
	if !reportHasPrefix(report, "child_pid=") {
		t.Errorf("hostile report lacks a child process identity:\n%s", report)
	}
	if info, err := os.Lstat(filepath.Join(disposable.Path(), "hostile-link")); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("hostile symlink not present after freeze: %v", err)
	}
	if _, err := os.Stat(filepath.Join(disposable.Path(), "forbidden.txt")); err != nil {
		t.Errorf("forbidden mutation was not exercised: %v", err)
	}
	realContents, err := os.ReadFile(realREADME)
	if err != nil || string(realContents) != "trusted real contents\n" {
		t.Fatalf("hostile runtime changed reality: %q, %v", realContents, err)
	}
	if _, err := os.Stat(filepath.Clean(filepath.Join(disposable.Path(), "..", "..", "mirage-host-escape"))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path escape reached host filesystem: %v", err)
	}

	if err := lifecycle.Reject(); err != nil {
		t.Fatalf("reject frozen M4.1 runtime: %v", err)
	}
	destroyCtx, cancelDestroy := context.WithTimeout(context.Background(), 30*time.Second)
	if err := lifecycle.Destroy(destroyCtx); err != nil {
		cancelDestroy()
		t.Fatalf("destroy runtime: %v", err)
	}
	cancelDestroy()
	if err := disposable.Cleanup(); err != nil {
		t.Fatalf("cleanup workspace: %v", err)
	}
	cleaned = true
}

func reportHasLine(report []byte, wanted string) bool {
	for _, line := range strings.Split(strings.TrimSpace(string(report)), "\n") {
		if strings.TrimSpace(line) == wanted {
			return true
		}
	}
	return false
}

func reportHasPrefix(report []byte, prefix string) bool {
	for _, line := range strings.Split(strings.TrimSpace(string(report)), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			return true
		}
	}
	return false
}
