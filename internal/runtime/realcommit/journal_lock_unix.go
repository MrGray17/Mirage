//go:build !windows

package realcommit

import (
	"errors"
	"os"
	"syscall"
)

var errJournalLockBusy = errors.New("journal lock is already held")

func lockJournal(file *os.File) error {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
		return errJournalLockBusy
	}
	return err
}

func unlockJournal(file *os.File) error {
	if file == nil {
		return nil
	}
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
