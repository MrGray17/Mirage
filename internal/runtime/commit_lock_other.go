//go:build !linux

package runtime

import (
	"errors"
	"os"
)

func acquireWorkspaceCommitLock(string) (*os.File, error) {
	return nil, errors.New("workspace commit locking requires the Linux runtime")
}
