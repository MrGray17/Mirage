// Package buildinfo exposes the small, stable frontend/backend handshake.
package buildinfo

import (
	"regexp"
	"runtime"
)

const BridgeProtocol = 1

// These values may be replaced with -ldflags at release build time.
var (
	Version = "0.1.0-dev"
	Commit  = "unknown"
)

var canonicalCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type Info struct {
	Version        string `json:"version"`
	Commit         string `json:"commit"`
	BridgeProtocol int    `json:"bridge_protocol"`
	Platform       string `json:"platform"`
}

func Current() Info {
	return Info{
		Version:        Version,
		Commit:         Commit,
		BridgeProtocol: BridgeProtocol,
		Platform:       runtime.GOOS,
	}
}

// IsCanonicalCommit reports whether value is the concrete full SHA-1 commit
// identity required by the current source installers and WSL bridge.
func IsCanonicalCommit(value string) bool {
	return canonicalCommitPattern.MatchString(value)
}
