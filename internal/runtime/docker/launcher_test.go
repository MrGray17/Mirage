package docker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeResponse struct {
	output []byte
	err    error
}

type fakeRunner struct {
	responses     []fakeResponse
	calls         [][]string
	captureOutput capturedCommandOutput
	captureErr    error
	captureCalls  [][]string
}

func (f *fakeRunner) Capture(_ context.Context, _ int, name string, args ...string) (capturedCommandOutput, error) {
	call := append([]string{name}, args...)
	f.captureCalls = append(f.captureCalls, call)
	return f.captureOutput, f.captureErr
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := append([]string{name}, args...)
	f.calls = append(f.calls, call)
	if len(f.responses) == 0 {
		return nil, errors.New("unexpected command")
	}
	response := f.responses[0]
	f.responses = f.responses[1:]
	return response.output, response.err
}

func TestDockerSubprocessEnvironmentScrubsHostCredentials(t *testing.T) {
	got := scrubCredentialEnvironment([]string{
		"PATH=/usr/bin",
		"DOCKER_HOST=unix:///run/user/1000/docker.sock",
		"DEEPSEEK_API_KEY=provider-secret",
		"OPENAI_API_KEY=other-secret",
		"GITHUB_TOKEN=repository-secret",
		"SSH_AUTH_SOCK=/run/user/1000/agent.sock",
	})
	if environmentValue(got, "PATH") != "/usr/bin" || environmentValue(got, "DOCKER_HOST") != "unix:///run/user/1000/docker.sock" {
		t.Fatalf("required host controls were removed: %v", got)
	}
	for _, name := range []string{"DEEPSEEK_API_KEY", "OPENAI_API_KEY", "GITHUB_TOKEN", "SSH_AUTH_SOCK"} {
		if environmentValue(got, name) != "" {
			t.Fatalf("credential-bearing environment %s survived scrub: %v", name, got)
		}
	}
}

func TestPrepareRequiresRootlessLinuxSeccompDaemon(t *testing.T) {
	config := dockerTestConfig(t)
	runner := &fakeRunner{responses: []fakeResponse{{
		output: []byte("rootless\n"),
	}, {
		output: []byte(`"unix:///run/user/1000/docker.sock"`),
	}, {
		output: mustJSON(t, daemonInfo{OSType: "linux", SecurityOptions: []string{"name=seccomp,profile=builtin"}}),
	}}}
	launcher, err := newWithRunner(config, runner)
	if err != nil {
		t.Fatalf("new launcher: %v", err)
	}
	if err := launcher.Prepare(context.Background()); !errors.Is(err, ErrIsolation) || !strings.Contains(err.Error(), "not rootless") {
		t.Fatalf("prepare error = %v", err)
	}
	if len(runner.calls) != 3 || runner.calls[2][1] != "info" {
		t.Fatalf("calls = %v", runner.calls)
	}
}

func TestPrepareRequiresEnforcedRootlessCgroupControllers(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*daemonInfo)
		wantReason string
	}{
		{
			name: "cgroup v1",
			mutate: func(info *daemonInfo) {
				info.CgroupVersion = "1"
			},
			wantReason: "cgroup v2",
		},
		{
			name: "non-systemd driver",
			mutate: func(info *daemonInfo) {
				info.CgroupDriver = "none"
			},
			wantReason: "systemd",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := dockerTestConfig(t)
			info := secureDaemonInfo()
			test.mutate(&info)
			runner := &fakeRunner{responses: []fakeResponse{
				{output: []byte("rootless\n")},
				{output: []byte(`"unix:///run/user/1000/docker.sock"`)},
				{output: mustJSON(t, info)},
			}}
			launcher, err := newWithRunner(config, runner)
			if err != nil {
				t.Fatalf("new launcher: %v", err)
			}
			if err := launcher.Prepare(context.Background()); !errors.Is(err, ErrIsolation) || !strings.Contains(err.Error(), test.wantReason) {
				t.Fatalf("prepare error = %v, want %q", err, test.wantReason)
			}
		})
	}
}

func TestPrepareRequiresEachDelegatedRootlessCgroupController(t *testing.T) {
	tests := []struct {
		name        string
		controllers []string
		wantReason  string
	}{
		{name: "cpu not delegated", controllers: []string{"memory", "pids"}, wantReason: `controller "cpu"`},
		{name: "memory not delegated", controllers: []string{"cpu", "pids"}, wantReason: `controller "memory"`},
		{name: "pids not delegated", controllers: []string{"cpu", "memory"}, wantReason: `controller "pids"`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := dockerTestConfig(t)
			runner := &fakeRunner{responses: []fakeResponse{
				{output: []byte("rootless\n")},
				{output: []byte(`"unix:///run/user/1000/docker.sock"`)},
				{output: mustJSON(t, secureDaemonInfo())},
			}}
			launcher, err := newWithRunner(config, runner)
			if err != nil {
				t.Fatalf("new launcher: %v", err)
			}
			launcher.delegatedControllers = func() ([]string, error) {
				return test.controllers, nil
			}
			if err := launcher.Prepare(context.Background()); !errors.Is(err, ErrIsolation) || !strings.Contains(err.Error(), test.wantReason) {
				t.Fatalf("prepare error = %v, want %q", err, test.wantReason)
			}
		})
	}
}

func TestPrepareFailsClosedWhenCgroupDelegationCannotBeEstablished(t *testing.T) {
	config := dockerTestConfig(t)
	runner := &fakeRunner{responses: []fakeResponse{
		{output: []byte("rootless\n")},
		{output: []byte(`"unix:///run/user/1000/docker.sock"`)},
		{output: mustJSON(t, secureDaemonInfo())},
	}}
	launcher, err := newWithRunner(config, runner)
	if err != nil {
		t.Fatalf("new launcher: %v", err)
	}
	launcher.delegatedControllers = func() ([]string, error) {
		return nil, errors.New("cgroup hierarchy unavailable")
	}
	if err := launcher.Prepare(context.Background()); !errors.Is(err, ErrIsolation) || !strings.Contains(err.Error(), "establish rootless cgroup") {
		t.Fatalf("prepare error = %v", err)
	}
}

func TestPrepareCreatesAndRevalidatesLockedDownContainer(t *testing.T) {
	config := dockerTestConfig(t)
	runner := securePrepareRunner(t, config)
	launcher, err := newWithRunner(config, runner)
	if err != nil {
		t.Fatalf("new launcher: %v", err)
	}
	if err := launcher.Prepare(context.Background()); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if len(runner.calls) != 7 {
		t.Fatalf("calls = %v", runner.calls)
	}
	create := runner.calls[5]
	required := [][]string{
		{"--pull", "never"},
		{"--user", defaultContainerUser},
		{"--read-only"},
		{"--network", "none"},
		{"--ipc", "private"},
		{"--cgroupns", "private"},
		{"--cap-drop", "ALL"},
		{"--security-opt", "no-new-privileges=true"},
		{"--security-opt", "seccomp=builtin"},
		{"--no-healthcheck"},
		{"--pids-limit", "64"},
		{"--memory", "268435456"},
		{"--memory-swap", "268435456"},
		{"--log-driver", "none"},
		{"--init"},
		{"--entrypoint", "/bin/sh"},
	}
	for _, sequence := range required {
		if !containsSequence(create, sequence) {
			t.Errorf("create arguments are missing %v: %v", sequence, create)
		}
	}
	if strings.Count(strings.Join(create, "\x00"), "type=bind,src=") != 1 {
		t.Fatalf("create command has unexpected bind mounts: %v", create)
	}
	for _, argument := range create {
		if strings.Contains(argument, ",rw,") {
			t.Fatalf("create command contains invalid bare rw mount field: %v", create)
		}
	}
	if containsSequence(create, []string{"--pid"}) {
		t.Fatalf("create command overrides Docker's private PID default: %v", create)
	}
}

func TestPrepareRemovesContainerWhenEffectiveIsolationDiffers(t *testing.T) {
	config := dockerTestConfig(t)
	inspect := secureContainerInspect(t, config)
	inspect.HostConfig.NetworkMode = "bridge"
	runner := &fakeRunner{responses: []fakeResponse{
		{output: []byte("rootless\n")},
		{output: []byte(`"unix:///run/user/1000/docker.sock"`)},
		{output: mustJSON(t, secureDaemonInfo())},
		{output: []byte(`"sha256:image"`)},
		{output: nil},
		{output: []byte("0123456789ab\n")},
		{output: mustJSON(t, inspect)},
		{output: []byte("0123456789ab\n")},
	}}
	launcher, err := newWithRunner(config, runner)
	if err != nil {
		t.Fatalf("new launcher: %v", err)
	}
	if err := launcher.Prepare(context.Background()); !errors.Is(err, ErrIsolation) {
		t.Fatalf("prepare error = %v", err)
	}
	last := runner.calls[len(runner.calls)-1]
	if !containsSequence(last, []string{"rm", "--force", "0123456789ab"}) {
		t.Fatalf("cleanup call = %v", last)
	}
}

func TestPrepareRejectsSharedPIDNamespace(t *testing.T) {
	config := dockerTestConfig(t)
	inspect := secureContainerInspect(t, config)
	inspect.HostConfig.PidMode = "host"
	runner := &fakeRunner{responses: []fakeResponse{
		{output: []byte("rootless\n")},
		{output: []byte(`"unix:///run/user/1000/docker.sock"`)},
		{output: mustJSON(t, secureDaemonInfo())},
		{output: []byte(`"sha256:image"`)},
		{output: nil},
		{output: []byte("0123456789ab\n")},
		{output: mustJSON(t, inspect)},
		{output: []byte("0123456789ab\n")},
	}}
	launcher, err := newWithRunner(config, runner)
	if err != nil {
		t.Fatalf("new launcher: %v", err)
	}
	if err := launcher.Prepare(context.Background()); !errors.Is(err, ErrIsolation) {
		t.Fatalf("prepare error = %v", err)
	}
}

func TestPrepareRejectsUnconfinedEffectiveSeccomp(t *testing.T) {
	config := dockerTestConfig(t)
	inspect := secureContainerInspect(t, config)
	inspect.HostConfig.SecurityOpt = []string{"no-new-privileges", "seccomp=unconfined"}
	runner := &fakeRunner{responses: []fakeResponse{
		{output: []byte("rootless\n")},
		{output: []byte(`"unix:///run/user/1000/docker.sock"`)},
		{output: mustJSON(t, secureDaemonInfo())},
		{output: []byte(`"sha256:image"`)},
		{output: nil},
		{output: []byte("0123456789ab\n")},
		{output: mustJSON(t, inspect)},
		{output: []byte("0123456789ab\n")},
	}}
	launcher, err := newWithRunner(config, runner)
	if err != nil {
		t.Fatalf("new launcher: %v", err)
	}
	if err := launcher.Prepare(context.Background()); !errors.Is(err, ErrIsolation) {
		t.Fatalf("prepare error = %v", err)
	}
	last := runner.calls[len(runner.calls)-1]
	if !containsSequence(last, []string{"rm", "--force", "0123456789ab"}) {
		t.Fatalf("cleanup call = %v", last)
	}
}

func TestPrepareRejectsDisabledEffectiveNoNewPrivileges(t *testing.T) {
	for _, disabled := range []string{"no-new-privileges=false", "no-new-privileges:false"} {
		t.Run(disabled, func(t *testing.T) {
			config := dockerTestConfig(t)
			inspect := secureContainerInspect(t, config)
			inspect.HostConfig.SecurityOpt = []string{disabled, "seccomp=builtin"}
			runner := &fakeRunner{responses: []fakeResponse{
				{output: []byte("rootless\n")},
				{output: []byte(`"unix:///run/user/1000/docker.sock"`)},
				{output: mustJSON(t, secureDaemonInfo())},
				{output: []byte(`"sha256:image"`)},
				{output: nil},
				{output: []byte("0123456789ab\n")},
				{output: mustJSON(t, inspect)},
				{output: []byte("0123456789ab\n")},
			}}
			launcher, err := newWithRunner(config, runner)
			if err != nil {
				t.Fatalf("new launcher: %v", err)
			}
			if err := launcher.Prepare(context.Background()); !errors.Is(err, ErrIsolation) {
				t.Fatalf("prepare error = %v", err)
			}
			last := runner.calls[len(runner.calls)-1]
			if !containsSequence(last, []string{"rm", "--force", "0123456789ab"}) {
				t.Fatalf("cleanup call = %v", last)
			}
		})
	}
}

func TestHasNoNewPrivilegesAcceptsOnlyEnabledForms(t *testing.T) {
	for _, enabled := range []string{
		"no-new-privileges",
		"no-new-privileges=true",
		"no-new-privileges:true",
	} {
		if !hasNoNewPrivileges([]string{enabled}) {
			t.Errorf("enabled form %q was rejected", enabled)
		}
	}
	for _, disabled := range []string{
		"no-new-privileges=false",
		"no-new-privileges:false",
		"no-new-privileges=",
	} {
		if hasNoNewPrivileges([]string{disabled}) {
			t.Errorf("disabled form %q was accepted", disabled)
		}
	}
}

func TestPrepareRejectsEnabledImageHealthcheck(t *testing.T) {
	config := dockerTestConfig(t)
	inspect := secureContainerInspect(t, config)
	inspect.Config.Healthcheck.Test = []string{"CMD-SHELL", "touch /workspace/healthcheck-ran"}
	runner := &fakeRunner{responses: []fakeResponse{
		{output: []byte("rootless\n")},
		{output: []byte(`"unix:///run/user/1000/docker.sock"`)},
		{output: mustJSON(t, secureDaemonInfo())},
		{output: []byte(`"sha256:image"`)},
		{output: nil},
		{output: []byte("0123456789ab\n")},
		{output: mustJSON(t, inspect)},
		{output: []byte("0123456789ab\n")},
	}}
	launcher, err := newWithRunner(config, runner)
	if err != nil {
		t.Fatalf("new launcher: %v", err)
	}
	if err := launcher.Prepare(context.Background()); !errors.Is(err, ErrIsolation) {
		t.Fatalf("prepare error = %v", err)
	}
}

func TestUncertainCreateRemainsDiscoverableForCleanup(t *testing.T) {
	config := dockerTestConfig(t)
	runner := &fakeRunner{responses: []fakeResponse{
		{output: []byte("rootless\n")},
		{output: []byte(`"unix:///run/user/1000/docker.sock"`)},
		{output: mustJSON(t, secureDaemonInfo())},
		{output: []byte(`"sha256:image"`)},
		{output: nil},
		{err: errors.New("client response lost")},
		{output: []byte("0123456789ab\n")},
		{output: []byte("0123456789ab\n")},
		{output: mustJSON(t, containerState{Status: "created", PID: 0})},
		{output: []byte("0123456789ab\n")},
	}}
	launcher, err := newWithRunner(config, runner)
	if err != nil {
		t.Fatalf("new launcher: %v", err)
	}
	if err := launcher.Prepare(context.Background()); err == nil {
		t.Fatal("uncertain create unexpectedly succeeded")
	}
	if err := launcher.Destroy(context.Background()); err != nil {
		t.Fatalf("cleanup uncertain create: %v", err)
	}
	last := runner.calls[len(runner.calls)-1]
	if !containsSequence(last, []string{"rm", "--force", "0123456789ab"}) {
		t.Fatalf("cleanup call = %v", last)
	}
}

func TestFreezeRequiresDockerStopProof(t *testing.T) {
	config := dockerTestConfig(t)
	runner := securePrepareRunner(t, config)
	runner.responses = append(runner.responses,
		fakeResponse{output: []byte("0123456789ab\n")},
		fakeResponse{output: mustJSON(t, containerState{Status: "running", Running: true, PID: 42})},
		fakeResponse{output: mustJSON(t, containerState{Status: "running", Running: true, PID: 42})},
		fakeResponse{output: []byte("0123456789ab\n")},
		fakeResponse{output: []byte("137\n")},
		fakeResponse{output: mustJSON(t, containerState{Status: "exited", PID: 0})},
		fakeResponse{output: []byte("0123456789ab\n")},
		fakeResponse{output: []byte("0123456789ab\n")},
	)
	launcher, err := newWithRunner(config, runner)
	if err != nil {
		t.Fatalf("new launcher: %v", err)
	}
	if err := launcher.Prepare(context.Background()); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := launcher.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := launcher.Freeze(context.Background()); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if err := launcher.Destroy(context.Background()); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if got := runner.calls[len(runner.calls)-3]; !containsSequence(got, []string{"inspect", "--format", "{{json .State}}", "0123456789ab"}) {
		t.Fatalf("stop proof call = %v", got)
	}
}

func TestFreezeFailsClosedWhenContainerStillRuns(t *testing.T) {
	config := dockerTestConfig(t)
	runner := securePrepareRunner(t, config)
	runner.responses = append(runner.responses,
		fakeResponse{output: []byte("0123456789ab\n")},
		fakeResponse{output: mustJSON(t, containerState{Status: "running", Running: true, PID: 42})},
		fakeResponse{output: mustJSON(t, containerState{Status: "running", Running: true, PID: 42})},
		fakeResponse{err: errors.New("kill failed")},
		fakeResponse{err: errors.New("wait failed")},
		fakeResponse{output: mustJSON(t, containerState{Status: "running", Running: true, PID: 42})},
	)
	launcher, err := newWithRunner(config, runner)
	if err != nil {
		t.Fatalf("new launcher: %v", err)
	}
	if err := launcher.Prepare(context.Background()); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := launcher.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := launcher.Freeze(context.Background()); !errors.Is(err, ErrStopUnproven) {
		t.Fatalf("freeze error = %v", err)
	}
}

func TestNewRejectsRealWorkspaceMountAndUnpinnedImage(t *testing.T) {
	config := dockerTestConfig(t)
	config.Workspace = config.RealWorkspace
	if _, err := New(config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("overlap error = %v", err)
	}

	config = dockerTestConfig(t)
	config.Image = "alpine:latest"
	if _, err := New(config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unpinned image error = %v", err)
	}
}

func TestLauncherIdentityBindsTheFixedFixture(t *testing.T) {
	config := dockerTestConfig(t)
	hostile, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Fixture = FixtureSingleModify
	singleModify, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if hostile.Identity() == singleModify.Identity() {
		t.Fatal("different trusted fixture commands share a sandbox identity")
	}
	config.Fixture = Fixture("ARBITRARY_COMMAND")
	if _, err := New(config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("arbitrary fixture error = %v", err)
	}
}

func securePrepareRunner(t *testing.T, config Config) *fakeRunner {
	t.Helper()
	return &fakeRunner{responses: []fakeResponse{
		{output: []byte("rootless\n")},
		{output: []byte(`"unix:///run/user/1000/docker.sock"`)},
		{output: mustJSON(t, secureDaemonInfo())},
		{output: []byte(`"sha256:image"`)},
		{output: nil},
		{output: []byte("0123456789ab\n")},
		{output: mustJSON(t, secureContainerInspect(t, config))},
	}}
}

func secureDaemonInfo() daemonInfo {
	return daemonInfo{
		OSType:          "linux",
		SecurityOptions: []string{"name=seccomp,profile=builtin", "name=rootless"},
		CgroupDriver:    "systemd",
		CgroupVersion:   "2",
	}
}

func secureContainerInspect(t *testing.T, config Config) containerInspect {
	t.Helper()
	normalized, err := normalizeConfig(config)
	if err != nil {
		t.Fatalf("normalize config: %v", err)
	}
	pids := normalized.PIDLimit
	var inspected containerInspect
	inspected.Config.User = normalized.ContainerUser
	inspected.Config.WorkingDir = containerWorkspacePath
	inspected.Config.Image = normalized.Image
	inspected.Config.Entrypoint = []string{"/bin/sh"}
	inspected.Config.Cmd = []string{"-c", fixtureScript(normalized.Fixture)}
	inspected.Config.Healthcheck = &struct {
		Test []string `json:"Test"`
	}{Test: []string{"NONE"}}
	inspected.HostConfig.ReadonlyRootfs = true
	inspected.HostConfig.NetworkMode = "none"
	inspected.HostConfig.PidMode = ""
	inspected.HostConfig.IpcMode = "private"
	inspected.HostConfig.CgroupnsMode = "private"
	inspected.HostConfig.CapDrop = []string{"ALL"}
	inspected.HostConfig.SecurityOpt = []string{"no-new-privileges", "seccomp=builtin"}
	inspected.HostConfig.PidsLimit = &pids
	inspected.HostConfig.Memory = normalized.MemoryBytes
	inspected.HostConfig.MemorySwap = normalized.MemoryBytes
	inspected.HostConfig.NanoCPUs = normalized.NanoCPUs
	init := true
	inspected.HostConfig.Init = &init
	inspected.HostConfig.ShmSize = 16 << 20
	inspected.HostConfig.Tmpfs = map[string]string{
		"/tmp": "rw,noexec,nosuid,nodev,size=16777216,mode=1777",
	}
	inspected.HostConfig.Ulimits = []dockerUlimit{{Name: "nofile", Soft: 256, Hard: 256}}
	inspected.HostConfig.RestartPolicy.Name = "no"
	inspected.HostConfig.LogConfig.Type = "none"
	inspected.Mounts = append(inspected.Mounts, struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
		Propagation string `json:"Propagation"`
	}{
		Type:        "bind",
		Source:      normalized.Workspace,
		Destination: containerWorkspacePath,
		RW:          true,
		Propagation: "rprivate",
	})
	return inspected
}

func dockerTestConfig(t *testing.T) Config {
	t.Helper()
	realWorkspace := dockerTestDir(t)
	disposableRoot := dockerTestDir(t)
	workspace := filepath.Join(disposableRoot, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatalf("create disposable workspace: %v", err)
	}
	token := "test-workspace-token"
	if err := os.WriteFile(filepath.Join(workspace, DisposableMarker), []byte(token), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	return Config{
		Image:          "example.invalid/mirage-fixture@sha256:" + strings.Repeat("0", 64),
		ContainerName:  "mirage-test-container",
		Workspace:      workspace,
		RealWorkspace:  realWorkspace,
		WorkspaceToken: token,
	}
}

func dockerTestDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp(".", ".mirage-docker-test-")
	if err != nil {
		t.Fatalf("create Docker test directory: %v", err)
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		_ = os.RemoveAll(directory)
		t.Fatalf("resolve Docker test directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(absolute); err != nil {
			t.Errorf("remove Docker test directory: %v", err)
		}
	})
	return absolute
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return encoded
}

func containsSequence(values, sequence []string) bool {
	if len(sequence) == 0 || len(sequence) > len(values) {
		return false
	}
	for start := 0; start <= len(values)-len(sequence); start++ {
		matched := true
		for offset := range sequence {
			if values[start+offset] != sequence[offset] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}
