// Package wsl defines the argument-safe Windows-to-WSL bridge protocol.
package wsl

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

var ErrInvalidConfig = errors.New("invalid WSL bridge configuration")

var distributionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type Config struct {
	Distribution string `json:"wsl_distribution"`
	Backend      string `json:"backend"`
}

func (c Config) Validate() error {
	if !distributionPattern.MatchString(c.Distribution) {
		return fmt.Errorf("%w: WSL distribution identity is invalid", ErrInvalidConfig)
	}
	if !strings.HasPrefix(c.Backend, "/") || path.Clean(c.Backend) != c.Backend || strings.ContainsAny(c.Backend, "\x00\r\n") {
		return fmt.Errorf("%w: backend must be an absolute Linux path", ErrInvalidConfig)
	}
	return nil
}

// Invocation returns an argv vector. No element is interpreted by a shell.
func Invocation(config Config, backendArgs []string) ([]string, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	args := []string{"-d", config.Distribution, "--exec", config.Backend}
	return append(args, backendArgs...), nil
}

// ValidateWindowsOutputDirectory rejects relative and non-drive paths before
// asking WSL's own wslpath utility to translate the absolute path.
func ValidateWindowsOutputDirectory(path string) (string, error) {
	clean := filepath.Clean(strings.TrimSpace(path))
	volume := filepath.VolumeName(clean)
	localDrive := len(volume) == 2 && volume[1] == ':' && ((volume[0] >= 'A' && volume[0] <= 'Z') || (volume[0] >= 'a' && volume[0] <= 'z'))
	if clean == "." || !filepath.IsAbs(clean) || !localDrive || strings.ContainsAny(clean, "\x00\r\n") {
		return "", fmt.Errorf("%w: output directory must be an absolute Windows drive path", ErrInvalidConfig)
	}
	return clean, nil
}
