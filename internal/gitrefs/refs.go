// Package gitrefs owns MIRAGE's deterministic, run-scoped Git ref naming.
// Keeping this below contracts and runtime planning prevents two security
// boundaries from silently deriving different publication destinations.
package gitrefs

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const (
	RunBranchPrefix = "refs/heads/mirage/run-"
	runHashLength   = 24
)

// RunTarget returns the M5.1-compatible deterministic branch for runID.
func RunTarget(runID string) string {
	digest := sha256.Sum256([]byte(runID))
	return RunBranchPrefix + hex.EncodeToString(digest[:])[:runHashLength]
}

// IsRunTarget reports whether target is exactly MIRAGE's branch for runID.
func IsRunTarget(runID, target string) bool {
	return strings.TrimSpace(runID) != "" && target == RunTarget(runID)
}
