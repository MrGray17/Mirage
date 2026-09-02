// Package buildinfo exposes the small, stable frontend/backend handshake.
package buildinfo

import "runtime"

const BridgeProtocol = 1

// These values may be replaced with -ldflags at release build time.
var (
	Version = "0.1.0-dev"
	Commit  = "unknown"
)

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
