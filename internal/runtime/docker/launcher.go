// Package docker implements the M4.1 rootless Docker sandbox backend.
package docker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/MrGray17/Mirage/internal/runtime/hostilefixture"
)

const (
	DisposableMarker       = ".mirage-disposable-workspace"
	defaultContainerUser   = "65532:65532"
	defaultMemoryBytes     = int64(256 << 20)
	defaultPIDLimit        = int64(64)
	defaultNanoCPUs        = int64(1_000_000_000)
	defaultOutputLimit     = 64 << 10
	containerWorkspacePath = "/workspace"
)

var (
	ErrInvalidConfig = errors.New("invalid Docker sandbox config")
	ErrIsolation     = errors.New("Docker isolation requirement not met")
	ErrStopUnproven  = errors.New("sandbox process tree stop is unproven")

	containerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	containerIDPattern   = regexp.MustCompile(`^[0-9a-f]{12,64}$`)
	digestImagePattern   = regexp.MustCompile(`^[^\s@]+@sha256:[0-9a-fA-F]{64}$`)
	containerUserPattern = regexp.MustCompile(`^[1-9][0-9]*:[1-9][0-9]*$`)
)

// Config contains only trusted control-plane inputs. Workspace must be a
// disposable directory, distinct from RealWorkspace, and carry the exact
// marker token supplied here.
type Config struct {
	DockerBinary   string
	Image          string
	ContainerName  string
	Workspace      string
	RealWorkspace  string
	WorkspaceToken string
	ContainerUser  string
	MemoryBytes    int64
	PIDLimit       int64
	NanoCPUs       int64
}

// Launcher owns one container. It is safe for serialized lifecycle calls and
// also guards its own mutable identity against accidental concurrent use.
type Launcher struct {
	mu                   sync.Mutex
	config               Config
	identity             string
	runner               commandRunner
	delegatedControllers func() ([]string, error)
	containerID          string
	prepared             bool
	started              bool
	frozen               bool
	hostOS               string
	createTried          bool
}

type commandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	var stdout, stderr limitedBuffer
	stdout.limit = defaultOutputLimit
	stderr.limit = defaultOutputLimit
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = strings.TrimSpace(stdout.String())
		}
		if message != "" {
			return stdout.Bytes(), fmt.Errorf("%w: %s", err, message)
		}
		return stdout.Bytes(), err
	}
	return stdout.Bytes(), nil
}

type limitedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	originalLength := len(p)
	remaining := b.limit - b.buffer.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
			b.truncated = true
		}
		_, _ = b.buffer.Write(p)
	} else if len(p) != 0 {
		b.truncated = true
	}
	return originalLength, nil
}

func (b *limitedBuffer) Bytes() []byte { return b.buffer.Bytes() }

func (b *limitedBuffer) String() string {
	if b.truncated {
		return b.buffer.String() + " [output truncated]"
	}
	return b.buffer.String()
}

func New(config Config) (*Launcher, error) {
	normalized, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize sandbox identity: %w", ErrInvalidConfig, err)
	}
	digest := sha256.Sum256(encoded)
	return &Launcher{
		config:               normalized,
		identity:             fmt.Sprintf("sha256:%x", digest),
		runner:               execCommandRunner{},
		delegatedControllers: hostDelegatedControllers,
		hostOS:               runtime.GOOS,
	}, nil
}

// Identity binds the complete normalized pre-execution sandbox configuration.
func (l *Launcher) Identity() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.identity
}

// BoundWorkspace exposes trusted constructor inputs for manifest validation.
func (l *Launcher) BoundWorkspace() (realWorkspace, disposableWorkspace, token string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.config.RealWorkspace, l.config.Workspace, l.config.WorkspaceToken
}

func newWithRunner(config Config, runner commandRunner) (*Launcher, error) {
	launcher, err := New(config)
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
	// This constructor is package-private and exists only for deterministic
	// policy tests on non-Linux development hosts.
	launcher.hostOS = "linux"
	return launcher, nil
}

// Prepare verifies the daemon, verifies the preloaded pinned image, creates the
// container, and then inspects the effective configuration before it can run.
func (l *Launcher) Prepare(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.prepared || l.containerID != "" {
		return fmt.Errorf("%w: launcher is already prepared", ErrInvalidConfig)
	}
	if err := l.verifyDaemon(ctx); err != nil {
		return err
	}
	if _, err := l.run(ctx, "image", "inspect", "--format", "{{json .Id}}", l.config.Image); err != nil {
		return fmt.Errorf("%w: pinned sandbox image is not available locally: %w", ErrIsolation, err)
	}
	knownID, err := l.findContainerByName(ctx)
	if err != nil {
		return fmt.Errorf("%w: establish hostile container-name availability: %w", ErrIsolation, err)
	}
	if knownID != "" {
		return fmt.Errorf("%w: hostile container name is already in use", ErrIsolation)
	}

	l.createTried = true
	output, err := l.run(ctx, l.createArguments()...)
	if err != nil {
		// The daemon may have created the container even if the client lost its
		// response. Preserve the random name as a cleanup capability when the
		// follow-up inventory query is itself uncertain.
		l.containerID = l.config.ContainerName
		if observedID, observeErr := l.findContainerByName(ctx); observeErr == nil {
			l.containerID = observedID
		} else {
			err = errors.Join(err, fmt.Errorf("resolve uncertain container creation: %w", observeErr))
		}
		return fmt.Errorf("create hostile container: %w", err)
	}
	l.containerID = strings.TrimSpace(string(output))
	if !containerIDPattern.MatchString(l.containerID) {
		l.containerID = l.config.ContainerName
		cleanupErr := l.removeCreated(ctx)
		return errors.Join(fmt.Errorf("%w: Docker returned an invalid container identity", ErrIsolation), cleanupErr)
	}

	if err := l.verifyContainer(ctx); err != nil {
		cleanupErr := l.removeCreated(ctx)
		return errors.Join(err, cleanupErr)
	}
	l.prepared = true
	return nil
}

// Start launches the fixture and verifies that the container reached RUNNING.
// On uncertainty it attempts to stop and prove the container inactive.
func (l *Launcher) Start(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.prepared || l.started || l.frozen || l.containerID == "" {
		return fmt.Errorf("%w: launcher is not in prepared state", ErrInvalidConfig)
	}
	if _, err := l.run(ctx, "start", l.containerID); err != nil {
		stopErr := l.stopAndProve(ctx)
		return errors.Join(fmt.Errorf("start hostile container: %w", err), stopErr)
	}
	state, err := l.inspectState(ctx)
	if err != nil {
		stopErr := l.stopAndProve(ctx)
		return errors.Join(fmt.Errorf("inspect started hostile container: %w", err), stopErr)
	}
	if !state.Running || state.PID <= 0 || state.Paused || state.Restarting {
		if state.stopped() {
			l.frozen = true
		}
		return fmt.Errorf("%w: hostile container did not remain running", ErrIsolation)
	}
	l.started = true
	return nil
}

// Freeze sends SIGKILL to the container, waits for exit, and accepts success
// only when Docker reports no running, paused, or restarting process and PID 0.
func (l *Launcher) Freeze(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.prepared || !l.started || l.frozen || l.containerID == "" {
		return fmt.Errorf("%w: launcher is not running", ErrInvalidConfig)
	}
	return l.stopAndProve(ctx)
}

// Destroy removes a stopped container. If startup failed ambiguously, Destroy
// first retries stop proof; it never removes the workspace itself.
func (l *Launcher) Destroy(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.createTried && l.containerID == "" {
		return nil
	}
	observedID, observeErr := l.findContainerByName(ctx)
	if observeErr != nil {
		return fmt.Errorf("resolve hostile container before cleanup: %w", observeErr)
	}
	if observedID == "" {
		l.containerID = ""
		l.createTried = false
		return nil
	}
	l.containerID = observedID
	if !l.frozen {
		if err := l.stopAndProve(ctx); err != nil {
			return err
		}
	}
	if _, err := l.run(ctx, "rm", "--force", l.containerID); err != nil {
		return fmt.Errorf("remove hostile container: %w", err)
	}
	l.containerID = ""
	l.prepared = false
	l.started = false
	l.createTried = false
	return nil
}

func (l *Launcher) verifyDaemon(ctx context.Context) error {
	if l.hostOS != "linux" {
		return fmt.Errorf("%w: rootless Docker sandboxing requires a Linux Mirage host", ErrIsolation)
	}
	if endpoint := strings.TrimSpace(os.Getenv("DOCKER_HOST")); endpoint != "" && !strings.HasPrefix(endpoint, "unix:///") {
		return fmt.Errorf("%w: DOCKER_HOST %q is not a local Unix socket", ErrIsolation, endpoint)
	}
	contextOutput, err := l.run(ctx, "context", "show")
	if err != nil {
		return fmt.Errorf("%w: identify Docker context: %w", ErrIsolation, err)
	}
	contextName := strings.TrimSpace(string(contextOutput))
	if contextName == "" || strings.ContainsAny(contextName, "\r\n\t ") {
		return fmt.Errorf("%w: Docker context identity is invalid", ErrIsolation)
	}
	endpointOutput, err := l.run(ctx, "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}", contextName)
	if err != nil {
		return fmt.Errorf("%w: inspect Docker endpoint: %w", ErrIsolation, err)
	}
	var endpoint string
	if err := json.Unmarshal(endpointOutput, &endpoint); err != nil {
		return fmt.Errorf("%w: decode Docker endpoint: %w", ErrIsolation, err)
	}
	if !strings.HasPrefix(endpoint, "unix:///") {
		return fmt.Errorf("%w: Docker endpoint %q is not a local Unix socket", ErrIsolation, endpoint)
	}

	output, err := l.run(ctx, "info", "--format", "{{json .}}")
	if err != nil {
		return fmt.Errorf("%w: Docker daemon is unavailable: %w", ErrIsolation, err)
	}
	var info daemonInfo
	if err := json.Unmarshal(output, &info); err != nil {
		return fmt.Errorf("%w: decode Docker daemon security state: %w", ErrIsolation, err)
	}
	if !strings.EqualFold(info.OSType, "linux") {
		return fmt.Errorf("%w: Docker daemon OS is %q, want linux", ErrIsolation, info.OSType)
	}
	if !containsSecurityOption(info.SecurityOptions, "rootless") {
		return fmt.Errorf("%w: Docker daemon is not rootless", ErrIsolation)
	}
	if !containsSecurityOption(info.SecurityOptions, "seccomp") {
		return fmt.Errorf("%w: Docker daemon does not report seccomp", ErrIsolation)
	}
	if info.CgroupVersion != "2" || !strings.EqualFold(info.CgroupDriver, "systemd") {
		return fmt.Errorf(
			"%w: rootless resource enforcement requires cgroup v2 with the systemd driver",
			ErrIsolation,
		)
	}
	controllers, err := l.delegatedControllers()
	if err != nil {
		return fmt.Errorf("%w: establish rootless cgroup controller delegation: %w", ErrIsolation, err)
	}
	for _, controller := range []string{"cpu", "memory", "pids"} {
		if !containsFold(controllers, controller) {
			return fmt.Errorf(
				"%w: rootless cgroup controller %q is not delegated",
				ErrIsolation,
				controller,
			)
		}
	}
	return nil
}

func (l *Launcher) createArguments() []string {
	mount := "type=bind,src=" + l.config.Workspace + ",dst=" + containerWorkspacePath + ",bind-propagation=rprivate"
	return []string{
		"create",
		"--name", l.config.ContainerName,
		"--pull", "never",
		"--user", l.config.ContainerUser,
		"--workdir", containerWorkspacePath,
		"--read-only",
		"--network", "none",
		"--ipc", "private",
		"--cgroupns", "private",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges=true",
		"--security-opt", "seccomp=builtin",
		"--no-healthcheck",
		"--pids-limit", strconv.FormatInt(l.config.PIDLimit, 10),
		"--memory", strconv.FormatInt(l.config.MemoryBytes, 10),
		"--memory-swap", strconv.FormatInt(l.config.MemoryBytes, 10),
		"--cpus", formatCPUs(l.config.NanoCPUs),
		"--ulimit", "nofile=256:256",
		"--shm-size", "16777216",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777",
		"--restart", "no",
		"--stop-timeout", "0",
		"--log-driver", "none",
		"--init",
		"--env", "HOME=/nonexistent",
		"--mount", mount,
		"--entrypoint", "/bin/sh",
		l.config.Image,
		"-c", hostilefixture.Script,
	}
}

func (l *Launcher) verifyContainer(ctx context.Context) error {
	output, err := l.run(ctx, "inspect", "--format", "{{json .}}", l.containerID)
	if err != nil {
		return fmt.Errorf("%w: inspect hostile container: %w", ErrIsolation, err)
	}
	var inspected containerInspect
	if err := json.Unmarshal(output, &inspected); err != nil {
		return fmt.Errorf("%w: decode hostile container configuration: %w", ErrIsolation, err)
	}

	host := inspected.HostConfig
	if inspected.Config.User != l.config.ContainerUser || inspected.Config.WorkingDir != containerWorkspacePath {
		return fmt.Errorf("%w: hostile container user or working directory changed", ErrIsolation)
	}
	if inspected.Config.Image != l.config.Image ||
		len(inspected.Config.Entrypoint) != 1 || inspected.Config.Entrypoint[0] != "/bin/sh" ||
		len(inspected.Config.Cmd) != 2 || inspected.Config.Cmd[0] != "-c" || inspected.Config.Cmd[1] != hostilefixture.Script ||
		inspected.Config.Healthcheck == nil || len(inspected.Config.Healthcheck.Test) != 1 || inspected.Config.Healthcheck.Test[0] != "NONE" {
		return fmt.Errorf("%w: hostile image or fixture command changed", ErrIsolation)
	}
	if host.Privileged || !host.ReadonlyRootfs || host.NetworkMode != "none" || !privatePIDMode(host.PidMode) || host.IpcMode != "private" || host.CgroupnsMode != "private" {
		return fmt.Errorf("%w: namespace or root-filesystem isolation changed", ErrIsolation)
	}
	if !containsFold(host.CapDrop, "ALL") ||
		!hasNoNewPrivileges(host.SecurityOpt) ||
		!containsExactFold(host.SecurityOpt, "seccomp=builtin") {
		return fmt.Errorf("%w: capability or privilege isolation changed", ErrIsolation)
	}
	if host.PidsLimit == nil || *host.PidsLimit != l.config.PIDLimit || host.Memory != l.config.MemoryBytes || host.MemorySwap != l.config.MemoryBytes || host.NanoCPUs != l.config.NanoCPUs {
		return fmt.Errorf("%w: resource limits changed", ErrIsolation)
	}
	if host.Init == nil || !*host.Init || host.AutoRemove || host.ShmSize != 16<<20 || !safeTmpfs(host.Tmpfs["/tmp"]) || !hasNoFileLimit(host.Ulimits) {
		return fmt.Errorf("%w: init, temporary storage, or descriptor limits changed", ErrIsolation)
	}
	if host.RestartPolicy.Name != "no" || host.LogConfig.Type != "none" || len(host.Devices) != 0 || host.PublishAllPorts || len(host.PortBindings) != 0 {
		return fmt.Errorf("%w: restart, logging, device, or port isolation changed", ErrIsolation)
	}
	if len(inspected.Mounts) != 1 {
		return fmt.Errorf("%w: expected exactly one workspace mount, got %d", ErrIsolation, len(inspected.Mounts))
	}
	mount := inspected.Mounts[0]
	if mount.Type != "bind" || !mount.RW || mount.Destination != containerWorkspacePath || mount.Propagation != "rprivate" || !samePath(mount.Source, l.config.Workspace) {
		return fmt.Errorf("%w: effective workspace mount changed", ErrIsolation)
	}
	return nil
}

func (l *Launcher) stopAndProve(ctx context.Context) error {
	if l.containerID == "" {
		return fmt.Errorf("%w: container identity is unavailable", ErrStopUnproven)
	}
	if state, err := l.inspectState(ctx); err == nil && state.stopped() {
		l.frozen = true
		l.started = false
		return nil
	}
	_, killErr := l.run(ctx, "kill", "--signal", "KILL", l.containerID)
	_, waitErr := l.run(ctx, "wait", l.containerID)
	state, inspectErr := l.inspectState(ctx)
	if inspectErr == nil && state.stopped() {
		l.frozen = true
		l.started = false
		return nil
	}
	return errors.Join(
		fmt.Errorf("%w: Docker did not prove PID namespace shutdown", ErrStopUnproven),
		killErr,
		waitErr,
		inspectErr,
	)
}

func (l *Launcher) findContainerByName(ctx context.Context) (string, error) {
	output, err := l.run(
		ctx,
		"ps", "--all",
		"--filter", "name=^/"+l.config.ContainerName+"$",
		"--format", "{{.ID}}",
	)
	if err != nil {
		return "", err
	}
	lines := strings.Fields(string(output))
	if len(lines) > 1 {
		return "", fmt.Errorf("%w: multiple containers matched the exact hostile name", ErrIsolation)
	}
	if len(lines) == 0 {
		return "", nil
	}
	if !containerIDPattern.MatchString(lines[0]) {
		return "", fmt.Errorf("%w: Docker returned a non-canonical container identity", ErrIsolation)
	}
	return lines[0], nil
}

func (l *Launcher) inspectState(ctx context.Context) (containerState, error) {
	output, err := l.run(ctx, "inspect", "--format", "{{json .State}}", l.containerID)
	if err != nil {
		return containerState{}, err
	}
	var state containerState
	if err := json.Unmarshal(output, &state); err != nil {
		return containerState{}, err
	}
	return state, nil
}

func (l *Launcher) removeCreated(ctx context.Context) error {
	if l.containerID == "" {
		return nil
	}
	_, err := l.run(ctx, "rm", "--force", l.containerID)
	if err != nil {
		return fmt.Errorf("remove rejected hostile container: %w", err)
	}
	l.containerID = ""
	l.createTried = false
	return nil
}

func (l *Launcher) run(ctx context.Context, args ...string) ([]byte, error) {
	return l.runner.Run(ctx, l.config.DockerBinary, args...)
}

type daemonInfo struct {
	OSType          string   `json:"OSType"`
	SecurityOptions []string `json:"SecurityOptions"`
	CgroupDriver    string   `json:"CgroupDriver"`
	CgroupVersion   string   `json:"CgroupVersion"`
}

type containerInspect struct {
	Config struct {
		User        string   `json:"User"`
		WorkingDir  string   `json:"WorkingDir"`
		Image       string   `json:"Image"`
		Entrypoint  []string `json:"Entrypoint"`
		Cmd         []string `json:"Cmd"`
		Healthcheck *struct {
			Test []string `json:"Test"`
		} `json:"Healthcheck"`
	} `json:"Config"`
	HostConfig struct {
		ReadonlyRootfs  bool              `json:"ReadonlyRootfs"`
		Privileged      bool              `json:"Privileged"`
		NetworkMode     string            `json:"NetworkMode"`
		PidMode         string            `json:"PidMode"`
		IpcMode         string            `json:"IpcMode"`
		CgroupnsMode    string            `json:"CgroupnsMode"`
		CapDrop         []string          `json:"CapDrop"`
		SecurityOpt     []string          `json:"SecurityOpt"`
		PidsLimit       *int64            `json:"PidsLimit"`
		Memory          int64             `json:"Memory"`
		MemorySwap      int64             `json:"MemorySwap"`
		NanoCPUs        int64             `json:"NanoCpus"`
		AutoRemove      bool              `json:"AutoRemove"`
		Init            *bool             `json:"Init"`
		ShmSize         int64             `json:"ShmSize"`
		Tmpfs           map[string]string `json:"Tmpfs"`
		Ulimits         []dockerUlimit    `json:"Ulimits"`
		PublishAllPorts bool              `json:"PublishAllPorts"`
		PortBindings    map[string][]any  `json:"PortBindings"`
		Devices         []json.RawMessage `json:"Devices"`
		RestartPolicy   struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
		LogConfig struct {
			Type string `json:"Type"`
		} `json:"LogConfig"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
		Propagation string `json:"Propagation"`
	} `json:"Mounts"`
}

type dockerUlimit struct {
	Name string `json:"Name"`
	Soft int64  `json:"Soft"`
	Hard int64  `json:"Hard"`
}

type containerState struct {
	Status     string `json:"Status"`
	Running    bool   `json:"Running"`
	Paused     bool   `json:"Paused"`
	Restarting bool   `json:"Restarting"`
	Dead       bool   `json:"Dead"`
	PID        int    `json:"Pid"`
}

func (s containerState) stopped() bool {
	return !s.Running && !s.Paused && !s.Restarting && s.PID == 0
}

func normalizeConfig(config Config) (Config, error) {
	config.DockerBinary = strings.TrimSpace(config.DockerBinary)
	if config.DockerBinary == "" {
		config.DockerBinary = "docker"
	}
	config.Image = strings.TrimSpace(config.Image)
	if !digestImagePattern.MatchString(config.Image) {
		return Config{}, fmt.Errorf("%w: image must use an exact sha256 digest", ErrInvalidConfig)
	}
	config.ContainerName = strings.TrimSpace(config.ContainerName)
	if !containerNamePattern.MatchString(config.ContainerName) {
		return Config{}, fmt.Errorf("%w: invalid container name", ErrInvalidConfig)
	}
	config.WorkspaceToken = strings.TrimSpace(config.WorkspaceToken)
	if config.WorkspaceToken == "" || len(config.WorkspaceToken) > 256 {
		return Config{}, fmt.Errorf("%w: disposable workspace token is invalid", ErrInvalidConfig)
	}

	workspace, err := resolveDirectory(config.Workspace)
	if err != nil {
		return Config{}, fmt.Errorf("%w: disposable workspace: %w", ErrInvalidConfig, err)
	}
	realWorkspace, err := resolveDirectory(config.RealWorkspace)
	if err != nil {
		return Config{}, fmt.Errorf("%w: real workspace: %w", ErrInvalidConfig, err)
	}
	if pathsOverlap(workspace, realWorkspace) {
		return Config{}, fmt.Errorf("%w: real and disposable workspaces overlap", ErrInvalidConfig)
	}
	if strings.Contains(workspace, ",") {
		return Config{}, fmt.Errorf("%w: disposable workspace path contains an ambiguous mount delimiter", ErrInvalidConfig)
	}
	if err := validateMarker(workspace, config.WorkspaceToken); err != nil {
		return Config{}, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	config.Workspace = workspace
	config.RealWorkspace = realWorkspace

	config.ContainerUser = strings.TrimSpace(config.ContainerUser)
	if config.ContainerUser == "" {
		config.ContainerUser = defaultContainerUser
	}
	if !containerUserPattern.MatchString(config.ContainerUser) {
		return Config{}, fmt.Errorf("%w: hostile process user must be a numeric non-root UID:GID", ErrInvalidConfig)
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
		return Config{}, fmt.Errorf("%w: sandbox resource limits are outside M4.1 bounds", ErrInvalidConfig)
	}
	return config, nil
}

func resolveDirectory(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("path is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("path is not a non-symlink directory")
	}
	if runtime.GOOS != "linux" {
		return filepath.Clean(absolute), nil
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

func validateMarker(workspace, token string) error {
	marker := filepath.Join(workspace, DisposableMarker)
	info, err := os.Lstat(marker)
	if err != nil {
		return fmt.Errorf("disposable workspace marker: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 256 {
		return errors.New("disposable workspace marker is unsafe")
	}
	contents, err := os.ReadFile(marker)
	if err != nil {
		return fmt.Errorf("read disposable workspace marker: %w", err)
	}
	if string(contents) != token {
		return errors.New("disposable workspace marker does not match trusted token")
	}
	return nil
}

func pathsOverlap(first, second string) bool {
	return pathContains(first, second) || pathContains(second, first)
}

func pathContains(base, target string) bool {
	relative, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func samePath(first, second string) bool {
	first = filepath.Clean(first)
	second = filepath.Clean(second)
	if filepath.Separator == '\\' {
		return strings.EqualFold(first, second)
	}
	return first == second
}

func containsFold(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}

func containsExactFold(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), wanted) {
			return true
		}
	}
	return false
}

func hasNoNewPrivileges(options []string) bool {
	for _, option := range options {
		switch strings.ToLower(strings.TrimSpace(option)) {
		case "no-new-privileges", "no-new-privileges=true", "no-new-privileges:true":
			return true
		}
	}
	return false
}

func privatePIDMode(mode string) bool {
	mode = strings.TrimSpace(mode)
	return mode == "" || strings.EqualFold(mode, "private")
}

func containsSecurityOption(options []string, wanted string) bool {
	wanted = strings.ToLower(wanted)
	for _, option := range options {
		canonical := strings.ToLower(strings.TrimSpace(option))
		if canonical == wanted ||
			strings.HasPrefix(canonical, "name="+wanted) ||
			strings.HasPrefix(canonical, wanted+"=") ||
			strings.HasPrefix(canonical, wanted+":") {
			return true
		}
	}
	return false
}

func safeTmpfs(options string) bool {
	required := []string{"rw", "noexec", "nosuid", "nodev", "size=16777216", "mode=1777"}
	parts := strings.Split(strings.ToLower(options), ",")
	for _, wanted := range required {
		if !containsFold(parts, wanted) {
			return false
		}
	}
	return true
}

func hasNoFileLimit(limits []dockerUlimit) bool {
	for _, limit := range limits {
		if limit.Name == "nofile" && limit.Soft == 256 && limit.Hard == 256 {
			return true
		}
	}
	return false
}

func formatCPUs(nanoCPUs int64) string {
	whole := nanoCPUs / 1_000_000_000
	fraction := nanoCPUs % 1_000_000_000
	if fraction == 0 {
		return strconv.FormatInt(whole, 10)
	}
	return strconv.FormatFloat(float64(nanoCPUs)/1_000_000_000, 'f', 9, 64)
}
