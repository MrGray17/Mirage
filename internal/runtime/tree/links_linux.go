//go:build linux

package tree

import (
	"fmt"
	"os"
	"syscall"
)

func hasMultipleLinks(info os.FileInfo) (bool, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return false, fmt.Errorf("Linux link count is unavailable")
	}
	return stat.Nlink > 1, nil
}
