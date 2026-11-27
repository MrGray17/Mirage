// Package gitrefs owns MIRAGE's deterministic, run-scoped Git ref naming.
// Keeping this below contracts and runtime planning prevents two security
// boundaries from silently deriving different publication destinations.
package gitrefs

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode"
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

// BranchName converts one canonical full heads ref into the branch spelling
// required by GitHub's pull-request API. It deliberately implements the
// security-relevant git-check-ref-format exclusions without invoking ambient
// Git configuration or accepting abbreviated refs.
func BranchName(ref string) (string, bool) {
	const prefix = "refs/heads/"
	if !strings.HasPrefix(ref, prefix) || len(ref) > 1024 || strings.HasSuffix(ref, "/") || strings.HasSuffix(ref, ".") || strings.Contains(ref, "//") || strings.Contains(ref, "..") || strings.Contains(ref, "@{") || strings.Contains(ref, "\\") {
		return "", false
	}
	name := strings.TrimPrefix(ref, prefix)
	if name == "" || name == "@" {
		return "", false
	}
	for _, component := range strings.Split(name, "/") {
		if component == "" || strings.HasPrefix(component, ".") || strings.HasSuffix(component, ".lock") {
			return "", false
		}
	}
	for _, r := range name {
		if r > unicode.MaxASCII || unicode.IsControl(r) || unicode.IsSpace(r) || strings.ContainsRune("~^:?*[", r) {
			return "", false
		}
	}
	return name, true
}
