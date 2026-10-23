//go:build windows

package realcommit

import "os"

// MIRAGE's security backend and its durable transaction journal run inside
// Linux/WSL. The native Windows frontend must route recovery to that backend.
var errJournalLockBusy = ErrJournalUnsupportedPlatform

func lockJournal(file *os.File) error {
	return ErrJournalUnsupportedPlatform
}

func unlockJournal(file *os.File) error {
	return nil
}
