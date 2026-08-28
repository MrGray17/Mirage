package docker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/MrGray17/Mirage/internal/runtime/diagnostics"
)

func TestAgentLauncherUsesQuotaVolumeAndExactArgv(t *testing.T) {
	config := agentTestConfig(t)
	launcher, err := NewAgent(config)
	if err != nil {
		t.Fatal(err)
	}
	arguments := launcher.agentCreateArguments()
	joined := strings.Join(arguments, "\x00")
	if strings.Contains(joined, config.Workspace) || strings.Contains(joined, config.RealWorkspace) {
		t.Fatalf("agent command exposes a host workspace: %v", arguments)
	}
	for _, required := range [][]string{
		{"--network", "none"},
		{"--read-only"},
		{"--cap-drop", "ALL"},
		{"--security-opt", "no-new-privileges=true"},
		{"--log-driver", "local"},
		{"--log-opt", "max-size=32768"},
		{"--log-opt", "max-file=1"},
		{"--entrypoint", "/usr/local/bin/coding-agent"},
		{config.AgentImage, "exec", "edit README.md"},
	} {
		if !containsSequence(arguments, required) {
			t.Errorf("agent create arguments are missing %v: %v", required, arguments)
		}
	}
	if !strings.Contains(joined, "type=volume,src="+launcher.volumeName+",dst=/workspace,volume-nocopy") {
		t.Fatalf("agent command lacks the hard-quota volume: %v", arguments)
	}
}

func TestAgentLauncherRejectsUnboundedOrAmbiguousCommands(t *testing.T) {
	config := agentTestConfig(t)
	config.Command = []string{"coding-agent"}
	if _, err := NewAgent(config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("relative command error = %v", err)
	}
	config = agentTestConfig(t)
	config.WorkspaceQuotaBytes = 1 << 20
	if _, err := NewAgent(config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("small quota error = %v", err)
	}
	config = agentTestConfig(t)
	config.AgentImage = "coding-agent:latest"
	if _, err := NewAgent(config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unpinned image error = %v", err)
	}
}

func TestAgentIdentityBindsCommandAndQuota(t *testing.T) {
	config := agentTestConfig(t)
	first, err := NewAgent(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Command = []string{"/usr/local/bin/coding-agent", "exec", "edit another file"}
	second, err := NewAgent(config)
	if err != nil {
		t.Fatal(err)
	}
	if first.Identity() == second.Identity() {
		t.Fatal("different agent argv vectors share an identity")
	}
	config = agentTestConfig(t)
	config.WorkspaceQuotaBytes = 96 << 20
	third, err := NewAgent(config)
	if err != nil {
		t.Fatal(err)
	}
	if first.Identity() == third.Identity() {
		t.Fatal("different workspace quotas share an identity")
	}
}

func TestCreateVolumeRequiresExactEffectiveTmpfsQuota(t *testing.T) {
	config := agentTestConfig(t)
	launcher, err := NewAgent(config)
	if err != nil {
		t.Fatal(err)
	}
	options := "size=67108864,mode=0777,nosuid,nodev"
	inspect := volumeInspect{
		Name:    launcher.volumeName,
		Driver:  "local",
		Options: map[string]string{"type": "tmpfs", "device": "tmpfs", "o": options},
		Labels:  map[string]string{"dev.mirage.workspace-token-sha256": hashText(config.WorkspaceToken)},
	}
	runner := &fakeRunner{responses: []fakeResponse{
		{output: []byte(launcher.volumeName + "\n")},
		{output: mustJSON(t, inspect)},
	}}
	launcher.runner = runner
	if err := launcher.createVolume(context.Background()); err != nil {
		t.Fatalf("create volume: %v", err)
	}
	if !containsSequence(runner.calls[0], []string{"--opt", "o=" + options}) {
		t.Fatalf("volume create lacks exact quota options: %v", runner.calls[0])
	}

	launcher, err = NewAgent(config)
	if err != nil {
		t.Fatal(err)
	}
	inspect.Options["o"] = "mode=0777,nosuid,nodev"
	launcher.runner = &fakeRunner{responses: []fakeResponse{
		{output: []byte(launcher.volumeName + "\n")},
		{output: mustJSON(t, inspect)},
	}}
	if err := launcher.createVolume(context.Background()); !errors.Is(err, ErrQuota) {
		t.Fatalf("missing effective size error = %v", err)
	}
}

func TestMountedQuotaCapacityMustMatchManifest(t *testing.T) {
	launcher, err := NewAgent(agentTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	launcher.seedID = "0123456789ab"
	launcher.runner = &fakeRunner{responses: []fakeResponse{{output: []byte("tmpfs 65536 0 65536 0% /workspace\n")}}}
	if err := launcher.verifyQuotaCapacity(context.Background()); err != nil {
		t.Fatalf("matching capacity: %v", err)
	}
	launcher.runner = &fakeRunner{responses: []fakeResponse{{output: []byte("tmpfs 131072 0 131072 0% /workspace\n")}}}
	if err := launcher.verifyQuotaCapacity(context.Background()); !errors.Is(err, ErrQuota) {
		t.Fatalf("larger effective capacity error = %v", err)
	}
}

func TestAgentFreezePausesExportsThenProvesAllProcessesDead(t *testing.T) {
	config := agentTestConfig(t)
	if err := os.WriteFile(filepath.Join(config.Workspace, "README.md"), []byte("baseline\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	launcher, err := NewAgent(config)
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{responses: []fakeResponse{
		{output: mustJSON(t, containerState{Status: "running", Running: true, PID: 42})},
		{output: []byte("agent\n")},
		{output: mustJSON(t, containerState{Status: "paused", Running: true, Paused: true, PID: 42})},
		{output: nil},
		{output: mustJSON(t, containerState{Status: "paused", Running: true, Paused: true, PID: 42})},
		{output: []byte("agent\n")},
		{output: []byte("137\n")},
		{output: mustJSON(t, containerState{Status: "exited", PID: 0, ExitCode: 137})},
		{output: mustJSON(t, containerState{Status: "running", Running: true, PID: 43})},
		{output: []byte("seed\n")},
		{output: []byte("137\n")},
		{output: mustJSON(t, containerState{Status: "exited", PID: 0, ExitCode: 137})},
	}}
	launcher.runner = runner
	launcher.prepared = true
	launcher.started = true
	launcher.containerID = "0123456789ab"
	launcher.seedID = "abcdef012345"
	if err := launcher.Freeze(context.Background()); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if !launcher.frozen {
		t.Fatal("launcher did not record frozen stop proof")
	}
	pauseIndex, copyIndex, firstKillIndex := -1, -1, -1
	for index, call := range runner.calls {
		switch {
		case containsSequence(call, []string{"pause", "0123456789ab"}):
			pauseIndex = index
		case containsSequence(call, []string{"cp", "abcdef012345:/workspace/.", config.Workspace}):
			copyIndex = index
		case containsSequence(call, []string{"kill", "--signal", "KILL", "0123456789ab"}):
			firstKillIndex = index
		}
	}
	if pauseIndex < 0 || copyIndex <= pauseIndex || firstKillIndex <= copyIndex {
		t.Fatalf("freeze/export/kill order is unsafe: %v", runner.calls)
	}
	if _, err := os.Lstat(filepath.Join(config.Workspace, "README.md")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("protected export target was not reset before copy: %v", err)
	}
}

func TestAgentWaitRejectsNonzeroExit(t *testing.T) {
	config := agentTestConfig(t)
	launcher, err := NewAgent(config)
	if err != nil {
		t.Fatal(err)
	}
	launcher.runner = &fakeRunner{responses: []fakeResponse{{output: []byte("17\n")}}}
	launcher.started = true
	launcher.containerID = "0123456789ab"
	if err := launcher.Wait(context.Background()); !errors.Is(err, ErrAgentFailed) {
		t.Fatalf("wait error = %v", err)
	}
	diagnostic := launcher.Diagnostics()
	if diagnostic.Class != diagnostics.AgentExit || diagnostic.AgentExitCode != 17 {
		t.Fatalf("diagnostic = %#v", diagnostic)
	}
}

func TestAgentStartRetainsFastExitForWaitAndFreeze(t *testing.T) {
	launcher, err := NewAgent(agentTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	launcher.runner = &fakeRunner{responses: []fakeResponse{
		{output: nil},
		{output: mustJSON(t, containerState{Status: "exited", PID: 0, ExitCode: 17})},
	}}
	launcher.prepared = true
	launcher.containerID = "0123456789ab"
	launcher.seedID = "abcdef012345"
	if err := launcher.Start(context.Background()); err != nil || !launcher.started {
		t.Fatalf("start error=%v started=%t", err, launcher.started)
	}
	if diagnostic := launcher.Diagnostics(); diagnostic.Class != diagnostics.AgentExit || diagnostic.AgentExitCode != 17 || diagnostic.Stage != "agent_start" {
		t.Fatalf("diagnostic = %#v", diagnostic)
	}
}

func TestAgentWaitClassifiesTimeout(t *testing.T) {
	launcher, err := NewAgent(agentTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	launcher.runner = &fakeRunner{responses: []fakeResponse{{err: context.DeadlineExceeded}}}
	launcher.started = true
	launcher.containerID = "0123456789ab"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := launcher.Wait(ctx); err == nil {
		t.Fatal("canceled wait unexpectedly succeeded")
	}
	if diagnostic := launcher.Diagnostics(); diagnostic.Class != diagnostics.Timeout || diagnostic.Stage != "agent_wait" {
		t.Fatalf("diagnostic = %#v", diagnostic)
	}
}

func TestAgentDiagnosticsAreBoundedRedactedAndRetained(t *testing.T) {
	config := agentTestConfig(t)
	config.DiagnosticBytes = minDiagnosticBytes
	launcher, err := NewAgent(config)
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{captureOutput: capturedCommandOutput{
		stdout: strings.Repeat("x", minDiagnosticBytes*2),
		stderr: "Bearer abcdefghijklmnopqrstuvwxyz sk-agent-secret-123456789",
	}}
	launcher.runner = runner
	launcher.containerID = "0123456789ab"
	launcher.diagnostic = diagnostics.Record{Class: diagnostics.AgentExit, Stage: "agent_exit", AgentExitCode: 1}
	launcher.captureAgentDiagnostics(context.Background())
	diagnostic := launcher.Diagnostics()
	if !diagnostic.StdoutTruncated || !strings.Contains(diagnostic.Stdout, diagnostics.TruncationMarker) || len(diagnostic.Stdout) > minDiagnosticBytes+len(diagnostics.TruncationMarker) {
		t.Fatalf("stdout cap = %d truncated=%t output=%q", len(diagnostic.Stdout), diagnostic.StdoutTruncated, diagnostic.Stdout)
	}
	if strings.Contains(diagnostic.Stderr, "abcdefghijklmnopqrstuvwxyz") || strings.Contains(diagnostic.Stderr, "agent-secret") {
		t.Fatalf("secret survived agent diagnostics: %q", diagnostic.Stderr)
	}
	if len(runner.captureCalls) != 1 || !containsSequence(runner.captureCalls[0], []string{"logs", "0123456789ab"}) {
		t.Fatalf("capture calls = %v", runner.captureCalls)
	}
}

func agentTestConfig(t *testing.T) AgentConfig {
	t.Helper()
	base := dockerTestConfig(t)
	return AgentConfig{
		AgentImage:     "example.invalid/coding-agent@sha256:" + strings.Repeat("1", 64),
		HelperImage:    base.Image,
		ContainerName:  "mirage-agent-test",
		Workspace:      base.Workspace,
		RealWorkspace:  base.RealWorkspace,
		WorkspaceToken: base.WorkspaceToken,
		Command:        []string{"/usr/local/bin/coding-agent", "exec", "edit README.md"},
	}
}

func secureAgentInspect(t *testing.T, launcher *AgentLauncher) containerInspect {
	t.Helper()
	config := launcher.config
	pids := config.PIDLimit
	var inspected containerInspect
	inspected.Config.User = config.ContainerUser
	inspected.Config.WorkingDir = containerWorkspacePath
	inspected.Config.Image = config.AgentImage
	inspected.Config.Entrypoint = []string{config.Command[0]}
	inspected.Config.Cmd = append([]string(nil), config.Command[1:]...)
	inspected.Config.Healthcheck = &struct {
		Test []string `json:"Test"`
	}{Test: []string{"NONE"}}
	inspected.HostConfig.ReadonlyRootfs = true
	inspected.HostConfig.NetworkMode = "none"
	inspected.HostConfig.IpcMode = "private"
	inspected.HostConfig.CgroupnsMode = "private"
	inspected.HostConfig.CapDrop = []string{"ALL"}
	inspected.HostConfig.SecurityOpt = []string{"no-new-privileges", "seccomp=builtin"}
	inspected.HostConfig.PidsLimit = &pids
	inspected.HostConfig.Memory = config.MemoryBytes
	inspected.HostConfig.MemorySwap = config.MemoryBytes
	inspected.HostConfig.NanoCPUs = config.NanoCPUs
	init := true
	inspected.HostConfig.Init = &init
	inspected.HostConfig.RestartPolicy.Name = "no"
	inspected.HostConfig.LogConfig.Type = "local"
	inspected.HostConfig.LogConfig.Config = map[string]string{
		"max-size": strconv.Itoa(config.DiagnosticBytes),
		"max-file": "1",
		"compress": "false",
	}
	inspected.Mounts = append(inspected.Mounts, struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
		Propagation string `json:"Propagation"`
	}{Type: "volume", Name: launcher.volumeName, Destination: containerWorkspacePath, RW: true})
	return inspected
}

func TestSecureAgentInspectJSONShape(t *testing.T) {
	launcher, err := NewAgent(agentTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(secureAgentInspect(t, launcher)); err != nil {
		t.Fatal(err)
	}
}
