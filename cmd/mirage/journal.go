package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"

	"github.com/MrGray17/Mirage/internal/runtime/realcommit"
)

func runJournal(args []string, stdout, stderr io.Writer) error {
	const usage = "usage: mirage journal list [--json] [--journal-dir DIR] | mirage journal prune --before RFC3339 --confirm [--journal-dir DIR]"
	if runtime.GOOS == "windows" {
		return errors.New("run 'mirage journal' inside the configured Linux/WSL backend")
	}
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, usage)
		return nil
	}
	switch args[0] {
	case "list":
		return runJournalList(args[1:], stdout, stderr)
	case "prune":
		return runJournalPrune(args[1:], stdout, stderr)
	default:
		return errors.New(usage)
	}
}

func runJournalList(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("journal list", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("journal-dir", "", "override the transaction journal directory")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: mirage journal list [--json] [--journal-dir DIR]")
	}
	store, err := openJournalStore(*dir)
	if err != nil {
		return err
	}
	entries, err := store.List()
	if err != nil {
		return fmt.Errorf("list transaction journal: %w", err)
	}
	if *jsonOutput {
		return json.NewEncoder(stdout).Encode(entries)
	}
	if len(entries) == 0 {
		fmt.Fprintln(stdout, "No local commit journal records.")
		return nil
	}
	for _, entry := range entries {
		fmt.Fprintf(stdout, "transaction=%s state=%s outcome=%s updated=%s resource=%q workspace=%q\n",
			entry.TransactionID, entry.State, entry.Outcome, entry.UpdatedAt.Format(time.RFC3339), entry.Resource, entry.Workspace)
	}
	return nil
}

func runJournalPrune(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("journal prune", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("journal-dir", "", "override the transaction journal directory")
	beforeText := flags.String("before", "", "prune terminal records updated before this RFC3339 timestamp")
	confirm := flags.Bool("confirm", false, "confirm deletion of eligible terminal records")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*beforeText) == "" || !*confirm {
		return errors.New("usage: mirage journal prune --before RFC3339 --confirm [--journal-dir DIR]")
	}
	before, err := time.Parse(time.RFC3339, *beforeText)
	if err != nil {
		return fmt.Errorf("parse --before as RFC3339: %w", err)
	}
	store, err := openJournalStore(*dir)
	if err != nil {
		return err
	}
	removed, err := store.PruneTerminal(before)
	if err != nil {
		return fmt.Errorf("prune transaction journal: %w", err)
	}
	fmt.Fprintf(stdout, "Pruned %d terminal journal record(s); unresolved records were retained.\n", len(removed))
	return nil
}

func openJournalStore(dir string) (*realcommit.JournalStore, error) {
	var store *realcommit.JournalStore
	var err error
	if strings.TrimSpace(dir) == "" {
		store, err = realcommit.DefaultJournalStore()
	} else {
		store, err = realcommit.NewJournalStore(dir)
	}
	if err != nil {
		return nil, fmt.Errorf("open transaction journal: %w", err)
	}
	return store, nil
}
