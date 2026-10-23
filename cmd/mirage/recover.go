package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/MrGray17/Mirage/internal/runtime/realcommit"
)

// runRecover inspects incomplete local commit journals. It never reapplies a
// planned mutation or repairs the workspace automatically.
func runRecover(args []string, stdout, stderr io.Writer) error {
	if runtime.GOOS == "windows" {
		return errors.New("run 'mirage recover' inside the configured Linux/WSL backend")
	}
	flags := flag.NewFlagSet("recover", flag.ContinueOnError)
	flags.SetOutput(stderr)
	journalDir := flags.String("journal-dir", "", "override the transaction journal directory (primarily for diagnostics)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: mirage recover [--journal-dir DIR]")
	}

	var store *realcommit.JournalStore
	var err error
	if strings.TrimSpace(*journalDir) == "" {
		store, err = realcommit.DefaultJournalStore()
	} else {
		store, err = realcommit.NewJournalStore(*journalDir)
	}
	if err != nil {
		return fmt.Errorf("open transaction journal: %w", err)
	}
	results, err := store.RecoverPending()
	if err != nil {
		return fmt.Errorf("reconcile incomplete local commits: %w", err)
	}
	if len(results) == 0 {
		fmt.Fprintln(stdout, "No incomplete local commit transactions require recovery.")
		return nil
	}

	unresolved := false
	for _, result := range results {
		fmt.Fprintf(stdout,
			"transaction=%s state=%s outcome=%s resource=%q workspace=%q reason=%q\n",
			result.TransactionID, result.State, result.Outcome, result.Resource, result.Workspace, result.Reason,
		)
		if result.State == realcommit.JournalRecoveryRequired || result.State == realcommit.JournalAfterStateObserved {
			unresolved = true
		}
	}
	if unresolved {
		return errors.New("one or more transaction outcomes remain unresolved; MIRAGE did not modify the workspace or replay any commit")
	}
	fmt.Fprintln(stdout, "Recovery complete: incomplete transactions were classified without replaying mutations.")
	return nil
}
