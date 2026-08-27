//go:build !linux

package tree

import "os"

// The hostile runtime is Linux-only. Other platforms retain within-tree alias
// detection through os.SameFile for unit-test and source-preparation support.
func hasMultipleLinks(os.FileInfo) (bool, error) { return false, nil }
