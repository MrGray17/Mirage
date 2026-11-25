//go:build linux

package runtime

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// acquireWorkspaceCommitLock locks the opened directory inode. Closing the
// descriptor releases the lock; process termination also releases it. No
// lockfile is introduced into the authoritative workspace snapshot.
func acquireWorkspaceCommitLock(path string) (*os.File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open workspace commit lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.IsDir() {
		_ = file.Close()
		return nil, errors.Join(errors.New("workspace commit lock target is not a directory"), err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrWorkspaceCommitBusy
		}
		return nil, fmt.Errorf("acquire workspace commit lock: %w", err)
	}
	return file, nil
}
