package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
)

// EnvironmentReport is returned only after every runtime prerequisite has
// passed. Launcher.Prepare and mirage doctor call the same checker.
type EnvironmentReport struct {
	HostOS               string   `json:"host_os"`
	DockerContext        string   `json:"docker_context"`
	DockerEndpoint       string   `json:"docker_endpoint"`
	Rootless             bool     `json:"rootless"`
	Seccomp              bool     `json:"seccomp"`
	CgroupVersion        string   `json:"cgroup_version"`
	CgroupDriver         string   `json:"cgroup_driver"`
	DelegatedControllers []string `json:"delegated_controllers"`
}

// CheckEnvironment observes the effective local Docker security environment.
// It performs no mutation.
func CheckEnvironment(ctx context.Context, dockerBinary string) (EnvironmentReport, error) {
	if strings.TrimSpace(dockerBinary) == "" {
		dockerBinary = "docker"
	}
	return checkEnvironment(ctx, runtime.GOOS, dockerBinary, execCommandRunner{}, hostDelegatedControllers)
}

func checkEnvironment(ctx context.Context, hostOS, dockerBinary string, runner commandRunner, delegated func() ([]string, error)) (EnvironmentReport, error) {
	report := EnvironmentReport{HostOS: hostOS}
	if hostOS != "linux" {
		return report, fmt.Errorf("%w: rootless Docker sandboxing requires a Linux Mirage host", ErrIsolation)
	}
	if endpoint := strings.TrimSpace(os.Getenv("DOCKER_HOST")); endpoint != "" && !strings.HasPrefix(endpoint, "unix:///") {
		return report, fmt.Errorf("%w: DOCKER_HOST %q is not a local Unix socket", ErrIsolation, endpoint)
	}
	contextOutput, err := runner.Run(ctx, dockerBinary, "context", "show")
	if err != nil {
		return report, fmt.Errorf("%w: identify Docker context: %w", ErrIsolation, err)
	}
	report.DockerContext = strings.TrimSpace(string(contextOutput))
	if report.DockerContext == "" || strings.ContainsAny(report.DockerContext, "\r\n\t ") {
		return report, fmt.Errorf("%w: Docker context identity is invalid", ErrIsolation)
	}
	endpointOutput, err := runner.Run(ctx, dockerBinary, "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}", report.DockerContext)
	if err != nil {
		return report, fmt.Errorf("%w: inspect Docker endpoint: %w", ErrIsolation, err)
	}
	if err := json.Unmarshal(endpointOutput, &report.DockerEndpoint); err != nil {
		return report, fmt.Errorf("%w: decode Docker endpoint: %w", ErrIsolation, err)
	}
	if !strings.HasPrefix(report.DockerEndpoint, "unix:///") {
		return report, fmt.Errorf("%w: Docker endpoint %q is not a local Unix socket", ErrIsolation, report.DockerEndpoint)
	}
	output, err := runner.Run(ctx, dockerBinary, "info", "--format", "{{json .}}")
	if err != nil {
		return report, fmt.Errorf("%w: Docker daemon is unavailable: %w", ErrIsolation, err)
	}
	var info daemonInfo
	if err := json.Unmarshal(output, &info); err != nil {
		return report, fmt.Errorf("%w: decode Docker daemon security state: %w", ErrIsolation, err)
	}
	if !strings.EqualFold(info.OSType, "linux") {
		return report, fmt.Errorf("%w: Docker daemon OS is %q, want linux", ErrIsolation, info.OSType)
	}
	report.Rootless = containsSecurityOption(info.SecurityOptions, "rootless")
	report.Seccomp = containsSecurityOption(info.SecurityOptions, "seccomp")
	report.CgroupVersion, report.CgroupDriver = info.CgroupVersion, info.CgroupDriver
	if !report.Rootless {
		return report, fmt.Errorf("%w: Docker daemon is not rootless", ErrIsolation)
	}
	if !report.Seccomp {
		return report, fmt.Errorf("%w: Docker daemon does not report seccomp", ErrIsolation)
	}
	if report.CgroupVersion != "2" || !strings.EqualFold(report.CgroupDriver, "systemd") {
		return report, fmt.Errorf("%w: rootless resource enforcement requires cgroup v2 with the systemd driver", ErrIsolation)
	}
	report.DelegatedControllers, err = delegated()
	if err != nil {
		return report, fmt.Errorf("%w: establish rootless cgroup controller delegation: %w", ErrIsolation, err)
	}
	for _, controller := range []string{"cpu", "memory", "pids"} {
		if !containsFold(report.DelegatedControllers, controller) {
			return report, fmt.Errorf("%w: rootless cgroup controller %q is not delegated", ErrIsolation, controller)
		}
	}
	return report, nil
}

// ImageAvailable checks only local image inventory. It never pulls.
func ImageAvailable(ctx context.Context, dockerBinary, image string) error {
	if strings.TrimSpace(dockerBinary) == "" {
		dockerBinary = "docker"
	}
	if !digestImagePattern.MatchString(image) {
		return fmt.Errorf("%w: image must be digest-pinned", ErrInvalidConfig)
	}
	if _, err := (execCommandRunner{}).Run(ctx, dockerBinary, "image", "inspect", "--format", "{{json .Id}}", image); err != nil {
		return fmt.Errorf("%w: pinned sandbox image is not available locally: %w", ErrIsolation, err)
	}
	return nil
}

// EnsureImage is setup's sole acquisition operation. The exact digest must be
// supplied by trusted code, and availability is verified after the pull.
func EnsureImage(ctx context.Context, dockerBinary, image string) (bool, error) {
	if _, err := CheckEnvironment(ctx, dockerBinary); err != nil {
		return false, err
	}
	if err := ImageAvailable(ctx, dockerBinary, image); err == nil {
		return false, nil
	}
	if strings.TrimSpace(dockerBinary) == "" {
		dockerBinary = "docker"
	}
	if _, err := (execCommandRunner{}).Run(ctx, dockerBinary, "pull", image); err != nil {
		return false, fmt.Errorf("pull official pinned demo image: %w", err)
	}
	if err := ImageAvailable(ctx, dockerBinary, image); err != nil {
		return false, fmt.Errorf("verify official pinned demo image after pull: %w", err)
	}
	return true, nil
}
