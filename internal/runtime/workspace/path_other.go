//go:build !linux

package workspace

import "path/filepath"

// M4 hostile execution is Linux-only. Non-Linux builds retain lexical path
// handling so callers can reach the launcher's explicit fail-closed OS check.
func physicalPath(path string) (string, error) {
	return filepath.Clean(path), nil
}
