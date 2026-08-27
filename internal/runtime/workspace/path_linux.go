//go:build linux

package workspace

import "path/filepath"

func physicalPath(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}
