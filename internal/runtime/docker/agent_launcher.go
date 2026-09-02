package docker

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MrGray17/Mirage/internal/runtime/diagnostics"
)

const (
	defaultWorkspaceQuotaBytes = int64(64 << 20)
	minWorkspaceQuotaBytes     = int64(40 << 20)
	maxWorkspaceQuotaBytes     = int64(256 << 20)
	defaultDiagnosticBytes     = 32 << 10
	minDiagnosticBytes         = 4 << 10
	maxDiagnosticBytes         = 256 << 10
	agentBrokerMountPath       = "/run/mirage-broker"
	modelSocketName            = "model.sock"
	seedSleepSeconds           = "2147483647"
)

var (
	ErrAgentFailed = errors.New("coding agent failed")
	ErrQuota       = errors.New("hard workspace quota unavailable")
)

// AgentConfig contains the trusted, immutable inputs for an M4.4 coding-agent
// process. Command is passed to Docker as an argv vector, never through a
// shell. The agent image is part of the trusted deployment configuration, but
// the process executing from it remains hostile.
type AgentConfig struct {
	DockerBinary        string
	AgentImage          string
	HelperImage         string
	ContainerName       string
	Workspace           string
	RealWorkspace       string
	WorkspaceToken      string
	ContainerUser       string
	Command             []string
	WorkspaceQuotaBytes int64
	MemoryBytes         int64
	PIDLimit            int64
	NanoCPUs            int64
	BrokerDirectory     string
	BrokerIdentity      string
	BrokerModel         string
	DiagnosticBytes     int
}

// AgentLauncher runs an arbitrary command from a digest-pinned agent image on
// a hard-capped tmpfs volume. A trusted keeper container holds that volume
// mounted while the hostile process is paused and its frozen final tree is
// copied into the protected host-side disposable directory. Only after the
// copy does Mirage kill and prove the hostile PID namespace stopped.
type AgentLauncher struct {
	mu                   sync.Mutex
	config               AgentConfig
	identity             string
	runner               commandRunner
	delegatedControllers func() ([]string, error)
	hostOS               string
	volumeName           string
	seedName             string
	containerID          string
	seedID               string
	volumeCreated        bool
	volumeCreateTried    bool
	containerCreateTried bool
	seedCreateTried      bool
	prepared             bool
	started              bool
	frozen               bool
	diagnostic           diagnostics.Record
}

func NewAgent(config AgentConfig) (*AgentLauncher, error) {
	normalized, err := normalizeAgentConfig(config)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize agent sandbox identity: %w", ErrInvalidConfig, err)
	}
	digest := sha256.Sum256(encoded)
	nameDigest := sha256.Sum256([]byte(normalized.ContainerName + "\x00" + normalized.WorkspaceToken))
	volumeName := fmt.Sprintf("mirage-m44-%x", nameDigest[:12])
	return &AgentLauncher{
		config:               normalized,
		identity:             fmt.Sprintf("sha256:%x", digest),
		runner:               execCommandRunner{},
		delegatedControllers: hostDelegatedControllers,
		hostOS:               runtime.GOOS,
		volumeName:           volumeName,
		seedName:             normalized.ContainerName + "-seed",
	}, nil
}

func newAgentWithRunner(config AgentConfig, runner commandRunner) (*AgentLauncher, error) {
	launcher, err := NewAgent(config)
	if err != nil {
		return nil, err
	}
	if runner == nil {
		return nil, fmt.Errorf("%w: command runner is required", ErrInvalidConfig)
	}
	launcher.runner = runner
	launcher.delegatedControllers = func() ([]string, error) {
		return []string{"cpu", "memory", "pids"}, nil
	}
	launcher.hostOS = "linux"
	return launcher, nil
}

func (l *AgentLauncher) Identity() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.identity
}

func (l *AgentLauncher) BoundWorkspace() (realWorkspace, disposableWorkspace, token string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.config.RealWorkspace, l.config.Workspace, l.config.WorkspaceToken
}

// Diagnostics returns bounded, redacted agent output retained in trusted
// memory. It is evidence only and has no role in commit authorization.
func (l *AgentLauncher) Diagnostics() diagnostics.Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.diagnostic
}

func (l *AgentLauncher) Prepare(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.prepared || l.containerID != "" || l.seedID != "" || l.volumeCreated {
		return fmt.Errorf("%w: agent launcher is already prepared", ErrInvalidConfig)
	}
	if err := l.verifyDaemon(ctx); err != nil {
		return err
	}
	for _, image := range []string{l.config.AgentImage, l.config.HelperImage} {
		if _, err := l.run(ctx, "image", "inspect", "--format", "{{json .Id}}", image); err != nil {
			return fmt.Errorf("%w: pinned image %q is not available locally: %w", ErrIsolation, image, err)
		}
	}
	for _, name := range []string{l.config.ContainerName, l.seedName} {
		known, err := l.findContainerByName(ctx, name)
		if err != nil {
			return fmt.Errorf("%w: establish container-name availability: %w", ErrIsolation, err)
		}
		if known != "" {
			return fmt.Errorf("%w: container name %q is already in use", ErrIsolation, name)
		}
	}
	knownVolume, err := l.findVolumeByName(ctx)
	if err != nil {
		return fmt.Errorf("%w: establish quota-volume availability: %w", ErrQuota, err)
	}
	if knownVolume != "" {
		return fmt.Errorf("%w: quota volume name is already in use", ErrQuota)
	}

	if err := l.createVolume(ctx); err != nil {
		return errors.Join(err, l.destroyLocked(ctx))
	}
	fail := func(cause error) error {
		return errors.Join(cause, l.destroyLocked(ctx))
	}
	if err := l.createSeed(ctx); err != nil {
		return fail(err)
	}
	if err := l.verifyQuotaCapacity(ctx); err != nil {
		return fail(err)
	}
	if _, err := l.run(ctx, "cp", l.config.Workspace+"/.", l.seedID+":"+containerWorkspacePath); err != nil {
		return fail(fmt.Errorf("seed bounded workspace volume: %w", err))
	}
	if err := l.verifySeedMarker(ctx); err != nil {
		return fail(err)
	}
	if err := l.createAgent(ctx); err != nil {
		return fail(err)
	}
	l.prepared = true
	return nil
}

// verifySeedMarker tolerates only a short Docker exec-readiness race after the
// already-verified keeper reaches RUNNING. Every attempt is the same bounded,
// read-only marker acquisition; a successfully read mismatch fails
// immediately and agent execution is never retried here.
func (l *AgentLauncher) verifySeedMarker(ctx context.Context) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		marker, err := l.run(ctx, "exec", l.seedID, "/bin/sh", "-c", "cat /workspace/"+DisposableMarker)
		if err == nil {
			if string(marker) != l.config.WorkspaceToken {
				return fmt.Errorf("%w: seeded workspace marker mismatch", ErrQuota)
			}
			return nil
		}
		lastErr = err
		if attempt == 2 {
			break
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(fmt.Errorf("%w: seeded workspace marker unavailable", ErrQuota), ctx.Err(), lastErr)
		case <-timer.C:
		}
	}
	return errors.Join(fmt.Errorf("%w: seeded workspace marker unavailable", ErrQuota), lastErr)
}

func (l *AgentLauncher) Start(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.prepared || l.started || l.frozen || l.containerID == "" || l.seedID == "" {
		return fmt.Errorf("%w: agent launcher is not prepared", ErrInvalidConfig)
	}
	if _, err := l.run(ctx, "start", l.containerID); err != nil {
		stopErr := l.stopContainerAndProve(ctx, l.containerID)
		return errors.Join(fmt.Errorf("start coding agent: %w", err), stopErr)
	}
	state, err := l.inspectState(ctx, l.containerID)
	if err != nil {
		stopErr := l.stopContainerAndProve(ctx, l.containerID)
		return errors.Join(fmt.Errorf("inspect started coding agent: %w", err), stopErr)
	}
	if !state.Running && !state.stopped() {
		return fmt.Errorf("%w: coding-agent state is neither running nor stopped", ErrIsolation)
	}
	if state.stopped() && state.ExitCode != 0 {
		l.diagnostic = diagnostics.Record{Class: diagnostics.AgentExit, Stage: "agent_start", AgentExitCode: state.ExitCode, Message: "coding agent exited during startup"}
	}
	l.started = true
	return nil
}

// Wait blocks until the coding-agent PID 1 exits. A context deadline is not a
// stop proof; callers must still invoke Freeze, which pauses or kills every
// remaining process before any reconciliation can occur.
func (l *AgentLauncher) Wait(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.started || l.frozen || l.containerID == "" {
		return fmt.Errorf("%w: agent launcher is not running", ErrInvalidConfig)
	}
	output, err := l.run(ctx, "wait", l.containerID)
	if err != nil {
		if ctx.Err() != nil {
			l.diagnostic = diagnostics.SanitizeRecord(diagnostics.Record{Class: diagnostics.Timeout, Stage: "agent_wait", Message: ctx.Err().Error()}, l.config.DiagnosticBytes)
		} else {
			l.diagnostic = diagnostics.SanitizeRecord(diagnostics.Record{Class: diagnostics.AgentExit, Stage: "agent_wait", Message: err.Error()}, l.config.DiagnosticBytes)
		}
		return fmt.Errorf("wait for coding agent: %w", err)
	}
	exitCode, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil {
		l.diagnostic = diagnostics.Record{Class: diagnostics.AgentExit, Stage: "agent_wait", Message: "Docker returned an invalid agent exit code"}
		return fmt.Errorf("%w: Docker returned an invalid agent exit code", ErrIsolation)
	}
	if exitCode != 0 {
		l.diagnostic = diagnostics.Record{Class: diagnostics.AgentExit, Stage: "agent_exit", AgentExitCode: exitCode, Message: "coding agent exited nonzero"}
		return fmt.Errorf("%w: exit code %d", ErrAgentFailed, exitCode)
	}
	return nil
}

func (l *AgentLauncher) Freeze(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.prepared || !l.started || l.frozen || l.containerID == "" || l.seedID == "" {
		return fmt.Errorf("%w: agent launcher is not running", ErrInvalidConfig)
	}

	state, err := l.inspectState(ctx, l.containerID)
	if err != nil {
		return errors.Join(fmt.Errorf("inspect coding agent before freeze: %w", err), l.emergencyStop(ctx))
	}
	if state.Running {
		if _, err := l.run(ctx, "pause", l.containerID); err != nil {
			return errors.Join(fmt.Errorf("freeze coding-agent cgroup: %w", err), l.emergencyStop(ctx))
		}
		state, err = l.inspectState(ctx, l.containerID)
		if err != nil || !state.Running || !state.Paused || state.Restarting || state.PID <= 0 {
			return errors.Join(fmt.Errorf("%w: Docker did not prove the coding-agent cgroup paused", ErrStopUnproven), err, l.emergencyStop(ctx))
		}
	} else if !state.stopped() {
		return errors.Join(fmt.Errorf("%w: coding-agent stop state is unproven", ErrStopUnproven), l.emergencyStop(ctx))
	}

	exportErr := l.exportFrozenWorkspace(ctx)
	agentStopErr := l.stopContainerAndProve(ctx, l.containerID)
	seedStopErr := l.stopContainerAndProve(ctx, l.seedID)
	l.captureAgentDiagnostics(ctx)
	if exportErr != nil || agentStopErr != nil || seedStopErr != nil {
		return errors.Join(exportErr, agentStopErr, seedStopErr)
	}
	l.started = false
	l.frozen = true
	return nil
}

func (l *AgentLauncher) Destroy(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.destroyLocked(ctx)
}

func (l *AgentLauncher) createVolume(ctx context.Context) error {
	options := fmt.Sprintf("size=%d,mode=0777,nosuid,nodev", l.config.WorkspaceQuotaBytes)
	l.volumeCreateTried = true
	output, err := l.run(ctx,
		"volume", "create",
		"--driver", "local",
		"--opt", "type=tmpfs",
		"--opt", "device=tmpfs",
		"--opt", "o="+options,
		"--label", "dev.mirage.workspace-token-sha256="+hashText(l.config.WorkspaceToken),
		l.volumeName,
	)
	if err != nil {
		return fmt.Errorf("%w: create tmpfs workspace volume: %w", ErrQuota, err)
	}
	l.volumeCreated = true
	if strings.TrimSpace(string(output)) != l.volumeName {
		return fmt.Errorf("%w: Docker returned an unexpected quota-volume identity", ErrQuota)
	}
	inspectOutput, err := l.run(ctx, "volume", "inspect", "--format", "{{json .}}", l.volumeName)
	if err != nil {
		return fmt.Errorf("%w: inspect tmpfs workspace volume: %w", ErrQuota, err)
	}
	var inspected volumeInspect
	if err := json.Unmarshal(inspectOutput, &inspected); err != nil {
		return fmt.Errorf("%w: decode tmpfs workspace volume: %w", ErrQuota, err)
	}
	if inspected.Name != l.volumeName || inspected.Driver != "local" || inspected.Options["type"] != "tmpfs" || inspected.Options["device"] != "tmpfs" || !sameOptionSet(inspected.Options["o"], options) || inspected.Labels["dev.mirage.workspace-token-sha256"] != hashText(l.config.WorkspaceToken) {
		return fmt.Errorf("%w: effective workspace volume options changed", ErrQuota)
	}
	return nil
}

func (l *AgentLauncher) createSeed(ctx context.Context) error {
	l.seedCreateTried = true
	output, err := l.run(ctx, l.seedCreateArguments()...)
	if err != nil {
		l.seedID = l.seedName
		return fmt.Errorf("create trusted quota-volume keeper: %w", err)
	}
	l.seedID = strings.TrimSpace(string(output))
	if !containerIDPattern.MatchString(l.seedID) {
		l.seedID = l.seedName
		return fmt.Errorf("%w: Docker returned an invalid keeper identity", ErrIsolation)
	}
	if err := l.verifySeedContainer(ctx); err != nil {
		return err
	}
	if _, err := l.run(ctx, "start", l.seedID); err != nil {
		return fmt.Errorf("start trusted quota-volume keeper: %w", err)
	}
	state, err := l.inspectState(ctx, l.seedID)
	if err != nil || !state.Running || state.Paused || state.Restarting || state.PID <= 0 {
		return errors.Join(fmt.Errorf("%w: quota-volume keeper did not remain running", ErrIsolation), err)
	}
	return nil
}

func (l *AgentLauncher) verifySeedContainer(ctx context.Context) error {
	output, err := l.run(ctx, "inspect", "--format", "{{json .}}", l.seedID)
	if err != nil {
		return fmt.Errorf("%w: inspect quota-volume keeper: %w", ErrIsolation, err)
	}
	var inspected containerInspect
	if err := json.Unmarshal(output, &inspected); err != nil {
		return fmt.Errorf("%w: decode quota-volume keeper: %w", ErrIsolation, err)
	}
	host := inspected.HostConfig
	if inspected.Config.User != "0:0" || inspected.Config.WorkingDir != containerWorkspacePath || inspected.Config.Image != l.config.HelperImage || len(inspected.Config.Entrypoint) != 1 || inspected.Config.Entrypoint[0] != "/bin/sh" || !equalStrings(inspected.Config.Cmd, []string{"-c", "exec sleep " + seedSleepSeconds}) || inspected.Config.Healthcheck == nil || !equalStrings(inspected.Config.Healthcheck.Test, []string{"NONE"}) {
		return fmt.Errorf("%w: quota-volume keeper image or command changed", ErrIsolation)
	}
	if host.Privileged || !host.ReadonlyRootfs || host.NetworkMode != "none" || !privatePIDMode(host.PidMode) || host.IpcMode != "private" || host.CgroupnsMode != "private" || !containsFold(host.CapDrop, "ALL") || !hasNoNewPrivileges(host.SecurityOpt) || !containsExactFold(host.SecurityOpt, "seccomp=builtin") {
		return fmt.Errorf("%w: quota-volume keeper isolation changed", ErrIsolation)
	}
	if host.PidsLimit == nil || *host.PidsLimit != 8 || host.Memory != 32<<20 || host.MemorySwap != 32<<20 || host.NanoCPUs != 250_000_000 || host.Init == nil || !*host.Init || host.AutoRemove || host.ShmSize != 4<<20 || !safeSizedTmpfs(host.Tmpfs["/tmp"], "size=1048576") || !hasExactNoFileLimit(host.Ulimits, 64) || host.RestartPolicy.Name != "no" || host.LogConfig.Type != "none" || len(host.Devices) != 0 || host.PublishAllPorts || len(host.PortBindings) != 0 {
		return fmt.Errorf("%w: quota-volume keeper resource policy changed", ErrIsolation)
	}
	if len(inspected.Mounts) != 1 {
		return fmt.Errorf("%w: quota-volume keeper mount count changed", ErrIsolation)
	}
	mount := inspected.Mounts[0]
	if mount.Type != "volume" || mount.Name != l.volumeName || !mount.RW || mount.Destination != containerWorkspacePath {
		return fmt.Errorf("%w: quota-volume keeper mount changed", ErrIsolation)
	}
	return nil
}

func (l *AgentLauncher) verifyQuotaCapacity(ctx context.Context) error {
	output, err := l.run(ctx, "exec", l.seedID, "/bin/sh", "-c", "df -Pk /workspace | tail -n 1")
	if err != nil {
		return fmt.Errorf("%w: measure mounted workspace capacity: %w", ErrQuota, err)
	}
	fields := strings.Fields(string(output))
	if len(fields) != 6 || fields[5] != containerWorkspacePath {
		return fmt.Errorf("%w: mounted workspace capacity output is invalid", ErrQuota)
	}
	blocks, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || blocks <= 0 || blocks > maxWorkspaceQuotaBytes/1024 || blocks*1024 != l.config.WorkspaceQuotaBytes {
		return errors.Join(fmt.Errorf("%w: effective mounted capacity differs from the run manifest", ErrQuota), err)
	}
	return nil
}

func (l *AgentLauncher) createAgent(ctx context.Context) error {
	l.containerCreateTried = true
	output, err := l.run(ctx, l.agentCreateArguments()...)
	if err != nil {
		l.containerID = l.config.ContainerName
		return fmt.Errorf("create coding-agent container: %w", err)
	}
	l.containerID = strings.TrimSpace(string(output))
	if !containerIDPattern.MatchString(l.containerID) {
		l.containerID = l.config.ContainerName
		return fmt.Errorf("%w: Docker returned an invalid coding-agent identity", ErrIsolation)
	}
	if err := l.verifyAgentContainer(ctx); err != nil {
		return err
	}
	return nil
}

func (l *AgentLauncher) seedCreateArguments() []string {
	mount := "type=volume,src=" + l.volumeName + ",dst=" + containerWorkspacePath + ",volume-nocopy"
	return []string{
		"create", "--name", l.seedName, "--pull", "never",
		"--user", "0:0", "--workdir", containerWorkspacePath,
		"--read-only", "--network", "none", "--ipc", "private", "--cgroupns", "private",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--security-opt", "seccomp=builtin",
		"--no-healthcheck", "--pids-limit", "8", "--memory", "33554432", "--memory-swap", "33554432",
		"--cpus", "0.250000000", "--ulimit", "nofile=64:64", "--shm-size", "4194304",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=1048576,mode=1777",
		"--restart", "no", "--stop-timeout", "0", "--log-driver", "none", "--init",
		"--mount", mount, "--entrypoint", "/bin/sh", l.config.HelperImage, "-c", "exec sleep " + seedSleepSeconds,
	}
}

func (l *AgentLauncher) agentCreateArguments() []string {
	mount := "type=volume,src=" + l.volumeName + ",dst=" + containerWorkspacePath + ",volume-nocopy"
	args := []string{
		"create", "--name", l.config.ContainerName, "--pull", "never",
		"--user", l.config.ContainerUser, "--workdir", containerWorkspacePath,
		"--read-only", "--network", "none", "--ipc", "private", "--cgroupns", "private",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--security-opt", "seccomp=builtin",
		"--no-healthcheck", "--pids-limit", strconv.FormatInt(l.config.PIDLimit, 10),
		"--memory", strconv.FormatInt(l.config.MemoryBytes, 10), "--memory-swap", strconv.FormatInt(l.config.MemoryBytes, 10),
		"--cpus", formatCPUs(l.config.NanoCPUs), "--ulimit", "nofile=256:256", "--shm-size", "16777216",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777",
		"--restart", "no", "--stop-timeout", "0",
		"--log-driver", "local", "--log-opt", "max-size=" + strconv.Itoa(l.config.DiagnosticBytes), "--log-opt", "max-file=1", "--log-opt", "compress=false",
		"--init",
		"--env", "HOME=/tmp/mirage-home", "--mount", mount,
	}
	if l.config.BrokerDirectory != "" {
		brokerMount := "type=bind,src=" + l.config.BrokerDirectory + ",dst=" + agentBrokerMountPath + ",readonly,bind-propagation=rprivate"
		args = append(args,
			"--env", "MIRAGE_MODEL_SOCKET="+agentBrokerMountPath+"/"+modelSocketName,
			"--env", "MIRAGE_MODEL="+l.config.BrokerModel,
			"--env", "MIRAGE_BROKER_DUMMY=broker-scoped-no-secret",
			"--mount", brokerMount,
		)
	}
	args = append(args, "--entrypoint", l.config.Command[0], l.config.AgentImage)
	args = append(args, l.config.Command[1:]...)
	return args
}

func (l *AgentLauncher) verifyAgentContainer(ctx context.Context) error {
	output, err := l.run(ctx, "inspect", "--format", "{{json .}}", l.containerID)
	if err != nil {
		return fmt.Errorf("%w: inspect coding-agent container: %w", ErrIsolation, err)
	}
	var inspected containerInspect
	if err := json.Unmarshal(output, &inspected); err != nil {
		return fmt.Errorf("%w: decode coding-agent configuration: %w", ErrIsolation, err)
	}
	host := inspected.HostConfig
	if inspected.Config.User != l.config.ContainerUser || inspected.Config.WorkingDir != containerWorkspacePath || inspected.Config.Image != l.config.AgentImage || len(inspected.Config.Entrypoint) != 1 || inspected.Config.Entrypoint[0] != l.config.Command[0] || !equalStrings(inspected.Config.Cmd, l.config.Command[1:]) || inspected.Config.Healthcheck == nil || !equalStrings(inspected.Config.Healthcheck.Test, []string{"NONE"}) {
		return fmt.Errorf("%w: coding-agent image, command, user, or working directory changed", ErrIsolation)
	}
	if hasSensitiveEnvironment(inspected.Config.Env) || environmentValue(inspected.Config.Env, "HOME") != "/tmp/mirage-home" {
		return fmt.Errorf("%w: coding-agent environment contains a credential-bearing or changed value", ErrIsolation)
	}
	if l.config.BrokerDirectory != "" {
		if environmentValue(inspected.Config.Env, "MIRAGE_MODEL_SOCKET") != agentBrokerMountPath+"/"+modelSocketName || environmentValue(inspected.Config.Env, "MIRAGE_MODEL") != l.config.BrokerModel || environmentValue(inspected.Config.Env, "MIRAGE_BROKER_DUMMY") != "broker-scoped-no-secret" {
			return fmt.Errorf("%w: coding-agent broker environment changed", ErrIsolation)
		}
	}
	if host.Privileged || !host.ReadonlyRootfs || host.NetworkMode != "none" || !privatePIDMode(host.PidMode) || host.IpcMode != "private" || host.CgroupnsMode != "private" || !containsFold(host.CapDrop, "ALL") || !hasNoNewPrivileges(host.SecurityOpt) || !containsExactFold(host.SecurityOpt, "seccomp=builtin") {
		return fmt.Errorf("%w: coding-agent isolation changed", ErrIsolation)
	}
	if host.PidsLimit == nil || *host.PidsLimit != l.config.PIDLimit || host.Memory != l.config.MemoryBytes || host.MemorySwap != l.config.MemoryBytes || host.NanoCPUs != l.config.NanoCPUs || host.Init == nil || !*host.Init || host.AutoRemove || host.ShmSize != 16<<20 || !safeSizedTmpfs(host.Tmpfs["/tmp"], "size=16777216") || !hasExactNoFileLimit(host.Ulimits, 256) || host.RestartPolicy.Name != "no" || !safeAgentLogConfig(host.LogConfig.Type, host.LogConfig.Config, l.config.DiagnosticBytes) || len(host.Devices) != 0 || host.PublishAllPorts || len(host.PortBindings) != 0 {
		return fmt.Errorf("%w: coding-agent resource or device policy changed", ErrIsolation)
	}
	expectedMounts := 1
	if l.config.BrokerDirectory != "" {
		expectedMounts++
	}
	if len(inspected.Mounts) != expectedMounts {
		return fmt.Errorf("%w: coding-agent mount count changed", ErrIsolation)
	}
	workspaceOK := false
	brokerOK := l.config.BrokerDirectory == ""
	for _, mount := range inspected.Mounts {
		switch mount.Destination {
		case containerWorkspacePath:
			workspaceOK = mount.Type == "volume" && mount.Name == l.volumeName && mount.RW
		case agentBrokerMountPath:
			brokerOK = mount.Type == "bind" && !mount.RW && mount.Propagation == "rprivate" && samePath(mount.Source, l.config.BrokerDirectory)
		}
	}
	if !workspaceOK || !brokerOK {
		return fmt.Errorf("%w: coding-agent workspace or broker mount changed", ErrIsolation)
	}
	return nil
}

func (l *AgentLauncher) captureAgentDiagnostics(ctx context.Context) {
	capturer, ok := l.runner.(commandCaptureRunner)
	if !ok {
		if l.diagnostic.Message == "" {
			l.diagnostic.Message = "bounded agent output capture unavailable"
		}
		l.diagnostic.Stage = "diagnostic_capture"
		return
	}
	// Docker's local log is itself capped. The extra marker allowance ensures
	// the trusted truncation marker can be retained without enlarging the
	// configured hostile-output budget.
	output, err := capturer.Capture(ctx, l.config.DiagnosticBytes, l.config.DockerBinary, "logs", l.containerID)
	record := l.diagnostic
	record.Stdout = output.stdout
	record.Stderr = output.stderr
	record.StdoutTruncated = output.stdoutTruncated
	record.StderrTruncated = output.stderrTruncated
	if err != nil && record.Message == "" {
		record.Stage = "diagnostic_capture"
		record.Message = "bounded agent output capture failed"
	}
	record = diagnostics.SanitizeRecord(record, l.config.DiagnosticBytes)
	record.StdoutTruncated = record.StdoutTruncated || output.stdoutTruncated
	record.StderrTruncated = record.StderrTruncated || output.stderrTruncated
	if output.stdoutTruncated && !strings.Contains(record.Stdout, diagnostics.TruncationMarker) {
		record.Stdout += diagnostics.TruncationMarker
	}
	if output.stderrTruncated && !strings.Contains(record.Stderr, diagnostics.TruncationMarker) {
		record.Stderr += diagnostics.TruncationMarker
	}
	l.diagnostic = record
}

func safeAgentLogConfig(driver string, config map[string]string, limit int) bool {
	if driver != "local" || len(config) != 3 {
		return false
	}
	return config["max-size"] == strconv.Itoa(limit) && config["max-file"] == "1" && config["compress"] == "false"
}

func (l *AgentLauncher) exportFrozenWorkspace(ctx context.Context) error {
	if err := resetDisposableWorkspace(l.config.Workspace, l.config.WorkspaceToken); err != nil {
		return fmt.Errorf("prepare protected frozen-tree export: %w", err)
	}
	if _, err := l.run(ctx, "cp", l.seedID+":"+containerWorkspacePath+"/.", l.config.Workspace); err != nil {
		return fmt.Errorf("copy frozen quota volume for authoritative scan: %w", err)
	}
	return nil
}

func (l *AgentLauncher) emergencyStop(ctx context.Context) error {
	return errors.Join(l.stopContainerAndProve(ctx, l.containerID), l.stopContainerAndProve(ctx, l.seedID))
}

func (l *AgentLauncher) destroyLocked(ctx context.Context) error {
	if !l.containerCreateTried && !l.seedCreateTried && !l.volumeCreateTried && l.containerID == "" && l.seedID == "" && !l.volumeCreated {
		return nil
	}
	var result error
	for _, item := range []struct {
		name string
		id   *string
	}{
		{name: l.config.ContainerName, id: &l.containerID},
		{name: l.seedName, id: &l.seedID},
	} {
		observed, err := l.findContainerByName(ctx, item.name)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("resolve container %q before cleanup: %w", item.name, err))
			continue
		}
		if observed == "" {
			*item.id = ""
			continue
		}
		*item.id = observed
		if err := l.stopContainerAndProve(ctx, observed); err != nil {
			result = errors.Join(result, err)
			continue
		}
		if _, err := l.run(ctx, "rm", "--force", observed); err != nil {
			result = errors.Join(result, fmt.Errorf("remove container %q: %w", item.name, err))
			continue
		}
		*item.id = ""
	}
	if result == nil && (l.volumeCreated || l.volumeCreateTried) {
		known, err := l.findVolumeByName(ctx)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("resolve quota volume before cleanup: %w", err))
		} else if known != "" {
			if err := l.verifyOwnedVolume(ctx); err != nil {
				result = errors.Join(result, err)
			} else if _, err := l.run(ctx, "volume", "rm", l.volumeName); err != nil {
				result = errors.Join(result, fmt.Errorf("remove quota volume: %w", err))
			} else {
				l.volumeCreated = false
				l.volumeCreateTried = false
			}
		} else {
			l.volumeCreated = false
			l.volumeCreateTried = false
		}
	}
	if result == nil {
		l.prepared = false
		l.started = false
		l.containerCreateTried = false
		l.seedCreateTried = false
	}
	return result
}

func (l *AgentLauncher) verifyOwnedVolume(ctx context.Context) error {
	output, err := l.run(ctx, "volume", "inspect", "--format", "{{json .}}", l.volumeName)
	if err != nil {
		return fmt.Errorf("establish quota-volume ownership before cleanup: %w", err)
	}
	var inspected volumeInspect
	if err := json.Unmarshal(output, &inspected); err != nil {
		return fmt.Errorf("decode quota-volume ownership before cleanup: %w", err)
	}
	if inspected.Name != l.volumeName || inspected.Labels["dev.mirage.workspace-token-sha256"] != hashText(l.config.WorkspaceToken) {
		return errors.New("refuse to remove quota volume without Mirage ownership label")
	}
	return nil
}

func (l *AgentLauncher) stopContainerAndProve(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	if state, err := l.inspectState(ctx, id); err == nil && state.stopped() {
		return nil
	}
	_, killErr := l.run(ctx, "kill", "--signal", "KILL", id)
	_, waitErr := l.run(ctx, "wait", id)
	state, inspectErr := l.inspectState(ctx, id)
	if inspectErr == nil && state.stopped() {
		return nil
	}
	return errors.Join(fmt.Errorf("%w: Docker did not prove container %q stopped", ErrStopUnproven, id), killErr, waitErr, inspectErr)
}

func (l *AgentLauncher) inspectState(ctx context.Context, id string) (containerState, error) {
	output, err := l.run(ctx, "inspect", "--format", "{{json .State}}", id)
	if err != nil {
		return containerState{}, err
	}
	var state containerState
	if err := json.Unmarshal(output, &state); err != nil {
		return containerState{}, err
	}
	return state, nil
}

func (l *AgentLauncher) findContainerByName(ctx context.Context, name string) (string, error) {
	output, err := l.run(ctx, "ps", "--all", "--filter", "name=^/"+name+"$", "--format", "{{.ID}}")
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(output))
	if len(fields) > 1 || (len(fields) == 1 && !containerIDPattern.MatchString(fields[0])) {
		return "", fmt.Errorf("%w: Docker returned an invalid exact-name inventory", ErrIsolation)
	}
	if len(fields) == 1 {
		return fields[0], nil
	}
	return "", nil
}

func (l *AgentLauncher) findVolumeByName(ctx context.Context) (string, error) {
	output, err := l.run(ctx, "volume", "ls", "--filter", "name=^"+l.volumeName+"$", "--format", "{{.Name}}")
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(output))
	if len(fields) > 1 || (len(fields) == 1 && fields[0] != l.volumeName) {
		return "", fmt.Errorf("%w: Docker returned an invalid quota-volume inventory", ErrQuota)
	}
	if len(fields) == 1 {
		return fields[0], nil
	}
	return "", nil
}

func (l *AgentLauncher) verifyDaemon(ctx context.Context) error {
	verifier := &Launcher{
		config:               Config{DockerBinary: l.config.DockerBinary},
		runner:               l.runner,
		delegatedControllers: l.delegatedControllers,
		hostOS:               l.hostOS,
	}
	return verifier.verifyDaemon(ctx)
}

func (l *AgentLauncher) run(ctx context.Context, args ...string) ([]byte, error) {
	return l.runner.Run(ctx, l.config.DockerBinary, args...)
}

func normalizeAgentConfig(config AgentConfig) (AgentConfig, error) {
	config.DockerBinary = strings.TrimSpace(config.DockerBinary)
	if config.DockerBinary == "" {
		config.DockerBinary = "docker"
	}
	config.AgentImage = strings.TrimSpace(config.AgentImage)
	config.HelperImage = strings.TrimSpace(config.HelperImage)
	if !digestImagePattern.MatchString(config.AgentImage) || !digestImagePattern.MatchString(config.HelperImage) {
		return AgentConfig{}, fmt.Errorf("%w: agent and helper images must use exact sha256 digests", ErrInvalidConfig)
	}
	config.ContainerName = strings.TrimSpace(config.ContainerName)
	if !containerNamePattern.MatchString(config.ContainerName) || !containerNamePattern.MatchString(config.ContainerName+"-seed") {
		return AgentConfig{}, fmt.Errorf("%w: invalid coding-agent container name", ErrInvalidConfig)
	}
	config.WorkspaceToken = strings.TrimSpace(config.WorkspaceToken)
	if config.WorkspaceToken == "" || len(config.WorkspaceToken) > 256 {
		return AgentConfig{}, fmt.Errorf("%w: disposable workspace token is invalid", ErrInvalidConfig)
	}
	workspace, err := resolveDirectory(config.Workspace)
	if err != nil {
		return AgentConfig{}, fmt.Errorf("%w: disposable workspace: %w", ErrInvalidConfig, err)
	}
	realWorkspace, err := resolveDirectory(config.RealWorkspace)
	if err != nil {
		return AgentConfig{}, fmt.Errorf("%w: real workspace: %w", ErrInvalidConfig, err)
	}
	if pathsOverlap(workspace, realWorkspace) || strings.Contains(workspace, ",") {
		return AgentConfig{}, fmt.Errorf("%w: real/disposable paths overlap or contain an ambiguous delimiter", ErrInvalidConfig)
	}
	if err := validateMarker(workspace, config.WorkspaceToken); err != nil {
		return AgentConfig{}, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	config.Workspace = workspace
	config.RealWorkspace = realWorkspace
	config.ContainerUser = strings.TrimSpace(config.ContainerUser)
	if config.ContainerUser == "" {
		config.ContainerUser = defaultContainerUser
	}
	if !containerUserPattern.MatchString(config.ContainerUser) {
		return AgentConfig{}, fmt.Errorf("%w: coding agent must use a numeric non-root UID:GID", ErrInvalidConfig)
	}
	if len(config.Command) == 0 || len(config.Command) > 128 {
		return AgentConfig{}, fmt.Errorf("%w: a bounded coding-agent command is required", ErrInvalidConfig)
	}
	totalCommandBytes := 0
	for index, argument := range config.Command {
		if argument == "" || strings.ContainsRune(argument, '\x00') {
			return AgentConfig{}, fmt.Errorf("%w: coding-agent argument %d is invalid", ErrInvalidConfig, index)
		}
		totalCommandBytes += len(argument)
	}
	if !strings.HasPrefix(config.Command[0], "/") || totalCommandBytes > 64<<10 {
		return AgentConfig{}, fmt.Errorf("%w: coding-agent entrypoint must be absolute and argv must be bounded", ErrInvalidConfig)
	}
	config.Command = append([]string(nil), config.Command...)
	if config.WorkspaceQuotaBytes == 0 {
		config.WorkspaceQuotaBytes = defaultWorkspaceQuotaBytes
	}
	if config.WorkspaceQuotaBytes < minWorkspaceQuotaBytes || config.WorkspaceQuotaBytes > maxWorkspaceQuotaBytes || config.WorkspaceQuotaBytes%4096 != 0 {
		return AgentConfig{}, fmt.Errorf("%w: workspace quota is outside M4.4 bounds", ErrInvalidConfig)
	}
	if config.MemoryBytes == 0 {
		config.MemoryBytes = defaultMemoryBytes
	}
	if config.PIDLimit == 0 {
		config.PIDLimit = defaultPIDLimit
	}
	if config.NanoCPUs == 0 {
		config.NanoCPUs = defaultNanoCPUs
	}
	if config.MemoryBytes <= 0 || config.MemoryBytes > 1<<30 || config.PIDLimit <= 0 || config.PIDLimit > 256 || config.NanoCPUs <= 0 || config.NanoCPUs > 2_000_000_000 {
		return AgentConfig{}, fmt.Errorf("%w: sandbox resource limits are outside M4.4 bounds", ErrInvalidConfig)
	}
	if config.DiagnosticBytes == 0 {
		config.DiagnosticBytes = defaultDiagnosticBytes
	}
	if config.DiagnosticBytes < minDiagnosticBytes || config.DiagnosticBytes > maxDiagnosticBytes {
		return AgentConfig{}, fmt.Errorf("%w: diagnostic byte cap is outside M4.4 bounds", ErrInvalidConfig)
	}
	config.BrokerDirectory = strings.TrimSpace(config.BrokerDirectory)
	config.BrokerIdentity = strings.TrimSpace(config.BrokerIdentity)
	config.BrokerModel = strings.TrimSpace(config.BrokerModel)
	brokerFields := 0
	for _, field := range []string{config.BrokerDirectory, config.BrokerIdentity, config.BrokerModel} {
		if field != "" {
			brokerFields++
		}
	}
	if brokerFields != 0 && brokerFields != 3 {
		return AgentConfig{}, fmt.Errorf("%w: broker directory, identity, and model must be supplied together", ErrInvalidConfig)
	}
	if len(config.BrokerModel) > 256 || strings.ContainsAny(config.BrokerModel, "\x00\r\n") {
		return AgentConfig{}, fmt.Errorf("%w: broker model is invalid", ErrInvalidConfig)
	}
	if config.BrokerDirectory != "" {
		broker, err := resolveDirectory(config.BrokerDirectory)
		if err != nil || strings.Contains(broker, ",") || pathsOverlap(broker, workspace) || pathsOverlap(broker, realWorkspace) {
			return AgentConfig{}, fmt.Errorf("%w: broker directory is unsafe", ErrInvalidConfig)
		}
		entries, err := os.ReadDir(broker)
		if err != nil || len(entries) != 1 || entries[0].Name() != modelSocketName {
			return AgentConfig{}, fmt.Errorf("%w: broker directory must contain only %s", ErrInvalidConfig, modelSocketName)
		}
		info, err := os.Lstat(filepath.Join(broker, modelSocketName))
		if err != nil || info.Mode()&os.ModeSocket == 0 {
			return AgentConfig{}, fmt.Errorf("%w: broker endpoint is not a Unix socket", ErrInvalidConfig)
		}
		config.BrokerDirectory = broker
	}
	return config, nil
}

func resetDisposableWorkspace(workspace, token string) error {
	resolved, err := resolveDirectory(workspace)
	if err != nil || !samePath(resolved, workspace) {
		return errors.Join(errors.New("disposable workspace identity changed"), err)
	}
	if err := validateMarker(resolved, token); err != nil {
		return err
	}
	entries, err := os.ReadDir(resolved)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		target := filepath.Join(resolved, entry.Name())
		if err := os.RemoveAll(target); err != nil {
			return err
		}
	}
	return nil
}

type volumeInspect struct {
	Name    string            `json:"Name"`
	Driver  string            `json:"Driver"`
	Options map[string]string `json:"Options"`
	Labels  map[string]string `json:"Labels"`
}

func sameOptionSet(first, second string) bool {
	left := strings.Split(first, ",")
	right := strings.Split(second, ",")
	if len(left) != len(right) {
		return false
	}
	for _, value := range left {
		if !containsFold(right, value) {
			return false
		}
	}
	return true
}

func equalStrings(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func safeSizedTmpfs(options, size string) bool {
	required := []string{"rw", "noexec", "nosuid", "nodev", size, "mode=1777"}
	parts := strings.Split(strings.ToLower(options), ",")
	for _, wanted := range required {
		if !containsFold(parts, wanted) {
			return false
		}
	}
	return true
}

func hasExactNoFileLimit(limits []dockerUlimit, value int64) bool {
	for _, limit := range limits {
		if limit.Name == "nofile" && limit.Soft == value && limit.Hard == value {
			return true
		}
	}
	return false
}

func environmentValue(environment []string, name string) string {
	prefix := name + "="
	for _, value := range environment {
		if strings.HasPrefix(value, prefix) {
			return strings.TrimPrefix(value, prefix)
		}
	}
	return ""
}

func hasSensitiveEnvironment(environment []string) bool {
	for _, value := range environment {
		name, _, _ := strings.Cut(value, "=")
		if strings.EqualFold(name, "DOCKER_HOST") || credentialEnvironmentName(name) {
			return true
		}
	}
	return false
}

func credentialEnvironmentName(name string) bool {
	upper := strings.ToUpper(name)
	return upper == "KUBECONFIG" || upper == "GOOGLE_APPLICATION_CREDENTIALS" || strings.HasPrefix(upper, "AWS_") || strings.HasPrefix(upper, "AZURE_") || strings.HasPrefix(upper, "GITHUB_") || strings.HasPrefix(upper, "SSH_") || strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "SECRET") || strings.Contains(upper, "CREDENTIAL") || strings.HasSuffix(upper, "_TOKEN") || strings.HasSuffix(upper, "_API_KEY")
}

func hashText(value string) string {
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", digest)
}
