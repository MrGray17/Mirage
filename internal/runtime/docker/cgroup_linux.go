//go:build linux

package docker

import (
	"fmt"
	"os"
	"strings"
)

// hostDelegatedControllers reads the systemd user-service cgroup used by the
// local rootless daemon. This is trusted host evidence, independent of the
// daemon's requested container HostConfig values.
func hostDelegatedControllers() ([]string, error) {
	uid := os.Getuid()
	path := fmt.Sprintf(
		"/sys/fs/cgroup/user.slice/user-%d.slice/user@%d.service/cgroup.controllers",
		uid,
		uid,
	)
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return strings.Fields(string(contents)), nil
}
