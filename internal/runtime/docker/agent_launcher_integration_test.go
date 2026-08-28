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
	"github.com/MrGray17/Mirage/internal/runtime/workspace"
)

func TestRootlessCodingAgentUsesFrozenQuotaVolumeAndNarrowCommit(t *testing.T) {
	if goruntime.GOOS != "linux" || os.Getenv("MIRAGE_M44_INTEGRATION") != "1" {
		t.Skip("set MIRAGE_M44_INTEGRATION=1 on a Linux rootless Docker host")
	}
	image := strings.TrimSpace(os.Getenv("MIRAGE_AGENT_IMAGE"))
	if image == "" {
		image = strings.TrimSpace(os.Getenv("MIRAGE_HOSTILE_IMAGE"))
	}
	if image == "" {
		t.Fatal("MIRAGE_AGENT_IMAGE or MIRAGE_HOSTILE_IMAGE must name a preloaded digest-pinned image")
	}

	t.Run("one existing README modification commits", func(t *testing.T) {
		run := newLiveAgentRun(t, image, []string{"/bin/sh", "-c", "printf 'agent update\\n' > README.md"}, []string{"/workspace/README.md"})
		run.prepareStartWaitFreeze(t, true)
		decision, err := run.lifecycle.Reconcile()
		if err != nil || !decision.Allowed {
			t.Fatalf("reconcile decision=%#v error=%v", decision, err)
		}
		if _, err := run.lifecycle.PreCommit(); err != nil {
			t.Fatal(err)
		}
		if err := run.lifecycle.Commit(); err != nil {
			t.Fatal(err)
		}
		contents, err := os.ReadFile(filepath.Join(run.real, "README.md"))
		if err != nil || string(contents) != "agent update\n" {
			t.Fatalf("real README = %q, %v", contents, err)
		}
		entries, err := os.ReadDir(run.real)
		if err != nil || len(entries) != 2 {
			t.Fatalf("real entries = %v, %v", entries, err)
		}
	})

	t.Run("allowed edit plus extra file rejects", func(t *testing.T) {
		run := newLiveAgentRun(t, image, []string{"/bin/sh", "-c", "printf 'agent update\\n' > README.md; printf forbidden > forbidden.txt"}, []string{"/workspace/README.md"})
		run.prepareStartWaitFreeze(t, true)
		decision, err := run.lifecycle.Reconcile()
		if err != nil {
			t.Fatal(err)
		}
		if decision.Allowed || run.lifecycle.State() != hostileruntime.StateRejected {
			t.Fatalf("decision=%#v state=%s", decision, run.lifecycle.State())
		}
		run.assertRealityUnchanged(t)
	})

	t.Run("two authorized edits cannot widen single-file commit", func(t *testing.T) {
		run := newLiveAgentRun(t, image, []string{"/bin/sh", "-c", "printf first > README.md; printf second > SECOND.md"}, []string{"/workspace/README.md", "/workspace/SECOND.md"})
		run.prepareStartWaitFreeze(t, true)
		decision, err := run.lifecycle.Reconcile()
		if err != nil || decision.Allowed || run.lifecycle.State() != hostileruntime.StateRejected {
			t.Fatalf("reconcile decision=%#v state=%s error=%v", decision, run.lifecycle.State(), err)
		}
		run.assertRealityUnchanged(t)
	})

	t.Run("direct host secret network and Docker socket probes stay absent", func(t *testing.T) {
		script := "set -eu; test ! -e .env; test ! -e /host-home; test ! -e /root/.ssh; test ! -e /var/run/docker.sock; if wget -T 2 -q -O /tmp/network http://198.51.100.1/; then exit 41; fi; printf 'contained\\n' > README.md"
		run := newLiveAgentRun(t, image, []string{"/bin/sh", "-c", script}, []string{"/workspace/README.md"})
		run.prepareStartWaitFreeze(t, true)
		decision, err := run.lifecycle.Reconcile()
		if err != nil || !decision.Allowed {
			t.Fatalf("containment decision=%#v error=%v", decision, err)
		}
	})

	t.Run("workspace fill is capped and cannot commit", func(t *testing.T) {
		run := newLiveAgentRun(t, image, []string{"/bin/sh", "-c", "dd if=/dev/zero of=quota.bin bs=1048576 count=80"}, []string{"/workspace/README.md"})
		run.prepareStartWaitFreeze(t, false)
		if _, err := run.lifecycle.Reconcile(); err == nil || run.lifecycle.State() != hostileruntime.StateFailed {
			t.Fatalf("quota reconciliation error=%v state=%s", err, run.lifecycle.State())
		}
		run.assertRealityUnchanged(t)
	})

	t.Run("timeout with forked child freezes and rejects without commit", func(t *testing.T) {
		run := newLiveAgentRun(t, image, []string{"/bin/sh", "-c", "(while :; do sleep 1; done) & wait"}, []string{"/workspace/README.md"})
		run.prepareStart(t)
		waitCtx, cancelWait := context.WithTimeout(context.Background(), 300*time.Millisecond)
		waitErr := run.launcher.Wait(waitCtx)
		cancelWait()
		if waitErr == nil {
			t.Fatal("nonterminating agent unexpectedly completed")
		}
		run.freeze(t)
		if err := run.lifecycle.Reject(); err != nil || run.lifecycle.State() != hostileruntime.StateRejected {
			t.Fatalf("reject error=%v state=%s", err, run.lifecycle.State())
		}
		run.assertRealityUnchanged(t)
	})

	t.Run("late background write is present in frozen final truth", func(t *testing.T) {
		script := "(sleep 1; printf 'late final truth\\n' > README.md) & sleep 1000"
		run := newLiveAgentRun(t, image, []string{"/bin/sh", "-c", script}, []string{"/workspace/README.md"})
		run.prepareStart(t)
		time.Sleep(1500 * time.Millisecond)
		run.freeze(t)
		decision, err := run.lifecycle.Reconcile()
		if err != nil || !decision.Allowed {
			t.Fatalf("late-write decision=%#v error=%v", decision, err)
		}
		contents, err := os.ReadFile(filepath.Join(run.disposable.Path(), "README.md"))
		if err != nil || string(contents) != "late final truth\n" {
			t.Fatalf("frozen README = %q, %v", contents, err)
		}
		if err := run.lifecycle.Reject(); err != nil {
			t.Fatal(err)
		}
		run.assertRealityUnchanged(t)
	})

	t.Run("concurrent real change conflicts before replacement", func(t *testing.T) {
		run := newLiveAgentRun(t, image, []string{"/bin/sh", "-c", "printf 'agent update\\n' > README.md"}, []string{"/workspace/README.md"})
		run.prepareStartWaitFreeze(t, true)
		decision, err := run.lifecycle.Reconcile()
		if err != nil || !decision.Allowed {
			t.Fatalf("reconcile decision=%#v error=%v", decision, err)
		}
		if err := os.WriteFile(filepath.Join(run.real, "README.md"), []byte("concurrent real update\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := run.lifecycle.PreCommit(); !errors.Is(err, hostileruntime.ErrRealStateConflict) || run.lifecycle.State() != hostileruntime.StateConflicted {
			t.Fatalf("precommit error=%v state=%s", err, run.lifecycle.State())
		}
		contents, _ := os.ReadFile(filepath.Join(run.real, "README.md"))
		if string(contents) != "concurrent real update\n" {
			t.Fatalf("conflict path replaced reality: %q", contents)
		}
	})
}

type liveAgentRun struct {
	real       string
	disposable *workspace.Disposable
	launcher   *runtimedocker.AgentLauncher
	lifecycle  *hostileruntime.Lifecycle
	cleaned    bool
}

func newLiveAgentRun(t *testing.T, image string, command, allowed []string) *liveAgentRun {
	t.Helper()
	nativeRoot, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(nativeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	real, err := os.MkdirTemp(nativeRoot, ".mirage-m44-real-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "README.md"), []byte("trusted real contents\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "SECOND.md"), []byte("trusted second contents\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	disposable, err := workspace.Prepare(real)
	if err != nil {
		t.Fatal(err)
	}
	launcher, err := runtimedocker.NewAgent(runtimedocker.AgentConfig{
		AgentImage:     image,
		HelperImage:    image,
		ContainerName:  "mirage-m44-live-" + disposable.Token()[:16],
		Workspace:      disposable.Path(),
		RealWorkspace:  disposable.RealWorkspace(),
		WorkspaceToken: disposable.Token(),
		Command:        command,
	})
	if err != nil {
		t.Fatal(err)
	}
	contract, err := contracts.New(contracts.Spec{
		Version:   contracts.VersionV1,
		RunID:     "m44-live-" + disposable.Token()[:16],
		ActorID:   "coding-agent",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
		Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{
			Allow: allowed,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := disposable.Binding()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := hostileruntime.NewRunManifest(contract, binding, launcher, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := hostileruntime.NewBoundLifecycle(manifest)
	if err != nil {
		t.Fatal(err)
	}
	run := &liveAgentRun{real: real, disposable: disposable, launcher: launcher, lifecycle: lifecycle}
	t.Cleanup(func() {
		if run.cleaned {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := lifecycle.Destroy(ctx); err != nil {
			t.Errorf("destroy M4.4 runtime: %v", err)
			return
		}
		if err := disposable.Cleanup(); err != nil {
			t.Errorf("cleanup M4.4 workspace: %v", err)
		}
		if err := os.RemoveAll(real); err != nil {
			t.Errorf("cleanup M4.4 real fixture: %v", err)
		}
		run.cleaned = true
	})
	return run
}

func (run *liveAgentRun) prepareStartWaitFreeze(t *testing.T, wantSuccess bool) {
	t.Helper()
	run.prepareStart(t)
	waitCtx, cancelWait := context.WithTimeout(context.Background(), 15*time.Second)
	waitErr := run.launcher.Wait(waitCtx)
	cancelWait()
	if wantSuccess && waitErr != nil {
		t.Fatalf("agent wait: %v", waitErr)
	}
	if !wantSuccess && waitErr == nil {
		t.Fatal("hostile quota-fill command unexpectedly succeeded")
	}
	run.freeze(t)
}

func (run *liveAgentRun) prepareStart(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := run.lifecycle.Prepare(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := run.lifecycle.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
}

func (run *liveAgentRun) freeze(t *testing.T) {
	t.Helper()
	freezeCtx, cancelFreeze := context.WithTimeout(context.Background(), 30*time.Second)
	if err := run.lifecycle.Freeze(freezeCtx); err != nil {
		cancelFreeze()
		t.Fatal(err)
	}
	cancelFreeze()
}

func (run *liveAgentRun) assertRealityUnchanged(t *testing.T) {
	t.Helper()
	readme, err := os.ReadFile(filepath.Join(run.real, "README.md"))
	if err != nil || string(readme) != "trusted real contents\n" {
		t.Fatalf("real README changed: %q, %v", readme, err)
	}
	second, err := os.ReadFile(filepath.Join(run.real, "SECOND.md"))
	if err != nil || string(second) != "trusted second contents\n" {
		t.Fatalf("real SECOND changed: %q, %v", second, err)
	}
}
