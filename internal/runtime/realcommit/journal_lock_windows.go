//go:build windows

package realcommit

import (
	"errors"
	"os"
)

// MIRAGE's security backend and its durable transaction journal run inside
// Linux/WSL. The native Windows frontend must route recovery to that backend.
var errJournalLockBusy = errors.New("journal lock is already held")

func lockJournal(file *os.File) error {
	return ErrJournalUnsupportedPlatform
}

func unlockJournal(file *os.File) error {
	return nil
}
