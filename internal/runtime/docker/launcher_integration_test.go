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

	"github.com/MrGray17/Mirage/internal/contracts"
	hostileruntime "github.com/MrGray17/Mirage/internal/runtime"
	runtimedocker "github.com/MrGray17/Mirage/internal/runtime/docker"
	"github.com/MrGray17/Mirage/internal/runtime/reconcile"
	"github.com/MrGray17/Mirage/internal/runtime/tree"
	"github.com/MrGray17/Mirage/internal/runtime/workspace"
)

func TestRootlessDockerContainsHostileFixture(t *testing.T) {
	if goruntime.GOOS != "linux" || os.Getenv("MIRAGE_M42_INTEGRATION") != "1" {
		t.Skip("set MIRAGE_M42_INTEGRATION=1 on a Linux rootless Docker host")
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
	contract, err := contracts.New(contracts.Spec{
		Version:   contracts.VersionV1,
		RunID:     "m42-live-hostile-fixture",
		ActorID:   "hostile-fixture",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
		Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{
			Allow: []string{"/workspace/README.md"},
		}},
	})
	if err != nil {
		_ = disposable.Cleanup()
		t.Fatalf("create fixture contract: %v", err)
	}
	workspaceBinding, err := disposable.Binding()
	if err != nil {
		_ = disposable.Cleanup()
		t.Fatalf("bind workspace: %v", err)
	}
	manifest, err := hostileruntime.NewRunManifest(contract, workspaceBinding, launcher, time.Now)
	if err != nil {
		_ = disposable.Cleanup()
		t.Fatalf("create run manifest: %v", err)
	}
	lifecycle, err := hostileruntime.NewBoundLifecycle(manifest)
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

	decision, err := lifecycle.Reconcile()
	if err != nil {
		t.Fatalf("reconcile frozen runtime: %v", err)
	}
	if decision.Allowed || lifecycle.State() != hostileruntime.StateRejected {
		t.Fatalf("hostile final tree was not rejected: decision=%#v state=%s", decision, lifecycle.State())
	}
	violations := decision.Violations()
	if !hasViolation(violations, "/workspace/forbidden.txt", "filesystem.v1_write_content_modify_only") {
		t.Errorf("forbidden direct write absent from violations: %#v", violations)
	}
	if !hasViolation(violations, "/workspace/hostile-link", "filesystem.symlink_denied") {
		t.Errorf("hostile symlink absent from violations: %#v", violations)
	}
	if !hasViolation(violations, "", "filesystem.single_modify_required") {
		t.Errorf("multi-mutation hostile plan absent from violations: %#v", violations)
	}
	plan, _ := lifecycle.Reconciliation()
	if plan == nil || !hasMutation(plan.Mutations(), "/workspace/README.md") {
		t.Fatalf("allowed README mutation absent from authoritative plan: %#v", plan)
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

func TestRootlessDockerCommitsOneVerifiedRealFile(t *testing.T) {
	if goruntime.GOOS != "linux" || os.Getenv("MIRAGE_M42_INTEGRATION") != "1" {
		t.Skip("set MIRAGE_M42_INTEGRATION=1 on a Linux rootless Docker host")
	}
	image := strings.TrimSpace(os.Getenv("MIRAGE_HOSTILE_IMAGE"))
	if image == "" {
		t.Fatal("MIRAGE_HOSTILE_IMAGE must name a preloaded digest-pinned image")
	}
	nativeRoot, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("resolve native Linux fixture root: %v", err)
	}
	if err := os.MkdirAll(nativeRoot, 0o700); err != nil {
		t.Fatalf("create native Linux fixture root: %v", err)
	}
	real, err := os.MkdirTemp(nativeRoot, ".mirage-live-commit-")
	if err != nil {
		t.Fatalf("create live real workspace: %v", err)
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
	if err := os.Chmod(realREADME, 0o600); err != nil {
		t.Fatal(err)
	}
	disposable, err := workspace.Prepare(real)
	if err != nil {
		t.Fatalf("prepare workspace: %v", err)
	}
	launcher, err := runtimedocker.New(runtimedocker.Config{
		Image:          image,
		ContainerName:  "mirage-live-commit-" + disposable.Token()[:16],
		Workspace:      disposable.Path(),
		RealWorkspace:  disposable.RealWorkspace(),
		WorkspaceToken: disposable.Token(),
		Fixture:        runtimedocker.FixtureSingleModify,
	})
	if err != nil {
		_ = disposable.Cleanup()
		t.Fatalf("new launcher: %v", err)
	}
	contract, err := contracts.New(contracts.Spec{
		Version:   contracts.VersionV1,
		RunID:     "m43-live-single-modify",
		ActorID:   "single-modify-fixture",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
		Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{
			Allow: []string{"/workspace/README.md"},
		}},
	})
	if err != nil {
		_ = disposable.Cleanup()
		t.Fatal(err)
	}
	binding, err := disposable.Binding()
	if err != nil {
		_ = disposable.Cleanup()
		t.Fatal(err)
	}
	manifest, err := hostileruntime.NewRunManifest(contract, binding, launcher, time.Now)
	if err != nil {
		_ = disposable.Cleanup()
		t.Fatal(err)
	}
	lifecycle, err := hostileruntime.NewBoundLifecycle(manifest)
	if err != nil {
		_ = disposable.Cleanup()
		t.Fatal(err)
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

	want := "authorized fixture update\n"
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		contents, _ := os.ReadFile(filepath.Join(disposable.Path(), "README.md"))
		if string(contents) == want {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	shadowContents, err := os.ReadFile(filepath.Join(disposable.Path(), "README.md"))
	if err != nil || string(shadowContents) != want {
		t.Fatalf("single-modify fixture did not finish: %q, %v", shadowContents, err)
	}
	freezeCtx, cancelFreeze := context.WithTimeout(context.Background(), 30*time.Second)
	err = lifecycle.Freeze(freezeCtx)
	cancelFreeze()
	if err != nil {
		t.Fatalf("freeze runtime: %v", err)
	}
	realBefore, err := os.ReadFile(realREADME)
	if err != nil || string(realBefore) != "trusted real contents\n" {
		t.Fatalf("reality changed before commit: %q, %v", realBefore, err)
	}
	decision, err := lifecycle.Reconcile()
	if err != nil || !decision.Allowed || lifecycle.State() != hostileruntime.StateVerified {
		t.Fatalf("reconcile decision=%#v state=%s error=%v", decision, lifecycle.State(), err)
	}
	if _, err := lifecycle.PreCommit(); err != nil {
		t.Fatalf("precommit: %v", err)
	}
	if err := lifecycle.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if lifecycle.State() != hostileruntime.StateCommitted {
		t.Fatalf("state = %s, want COMMITTED", lifecycle.State())
	}
	realAfter, err := os.ReadFile(realREADME)
	if err != nil || string(realAfter) != want {
		t.Fatalf("committed content = %q, %v", realAfter, err)
	}
	info, err := os.Lstat(realREADME)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("committed mode = %v, %v", info, err)
	}
	entries, err := os.ReadDir(real)
	if err != nil || len(entries) != 1 || entries[0].Name() != "README.md" {
		t.Fatalf("real workspace entries = %v, %v", entries, err)
	}
	destroyCtx, cancelDestroy := context.WithTimeout(context.Background(), 30*time.Second)
	if err := lifecycle.Destroy(destroyCtx); err != nil {
		cancelDestroy()
		t.Fatal(err)
	}
	cancelDestroy()
	if err := disposable.Cleanup(); err != nil {
		t.Fatal(err)
	}
	cleaned = true
}

func hasViolation(violations []reconcile.Violation, resource, ruleID string) bool {
	for _, violation := range violations {
		if violation.Resource == resource && violation.RuleID == ruleID {
			return true
		}
	}
	return false
}

func hasMutation(mutations []tree.Mutation, resource string) bool {
	for _, mutation := range mutations {
		if mutation.Resource == resource {
			return true
		}
	}
	return false
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
