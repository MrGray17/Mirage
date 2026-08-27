//go:build !linux

package docker

import (
	"errors"
	"runtime"
)

func hostDelegatedControllers() ([]string, error) {
	return nil, errors.New("cgroup controller delegation is unavailable on " + runtime.GOOS)
}
