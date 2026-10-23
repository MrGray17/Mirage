//go:build !windows

package realcommit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyWithJournalCommitsOnlyAfterDurableTargetReplacement(t *testing.T) {
	root := t.TempDir()
	journalDir := filepath.Join(t.TempDir(), "transactions")
	target := filepath.Join(root, "README.md")
	before, after := []byte("before"), []byte("authorized after-state")
	if err := os.WriteFile(target, before, 0o640); err != nil {
		t.Fatal(err)
	}
	store, err := NewJournalStore(journalDir)
	if err != nil {
		t.Fatal(err)
	}
	plan := newTestPlan(t, root, before, after, 0o640)
	if err := ApplyWithJournal(plan, allowReplace, store); err != nil {
		t.Fatalf("journaled apply: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != string(after) {
		t.Fatalf("target = %q, error = %v", got, err)
	}
	record, err := store.readRecord(store.recordPath(plan.Hash()))
	if err != nil {
		t.Fatal(err)
	}
	if record.State != JournalCommitted || record.Outcome != "COMMITTED" {
		t.Fatalf("journal state=%s outcome=%s", record.State, record.Outcome)
	}
	recovered, err := store.RecoverPending()
	if err != nil || len(recovered) != 0 {
		t.Fatalf("recovery results=%#v error=%v", recovered, err)
	}
}

func TestApplyWithJournalAbortsBeforeReplacementWhenAuthorityFails(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "README.md")
	before, after := []byte("before"), []byte("authorized after-state")
	if err := os.WriteFile(target, before, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewJournalStore(filepath.Join(t.TempDir(), "transactions"))
	if err != nil {
		t.Fatal(err)
	}
	plan := newTestPlan(t, root, before, after, 0o600)
	authorityErr := errors.New("contract expired")
	err = ApplyWithJournal(plan, func() error { return authorityErr }, store)
	if !errors.Is(err, authorityErr) {
		t.Fatalf("error=%v, want authority error", err)
	}
	got, readErr := os.ReadFile(target)
	if readErr != nil || string(got) != string(before) {
		t.Fatalf("target changed: %q, %v", got, readErr)
	}
	record, readErr := store.readRecord(store.recordPath(plan.Hash()))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if record.State != JournalAborted || record.Outcome != "NOT_COMMITTED" {
		t.Fatalf("journal state=%s outcome=%s", record.State, record.Outcome)
	}
}

func TestRecoverPendingClassifiesAfterStateWithoutClaimingCommitAttribution(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "README.md")
	before, after := []byte("before"), []byte("authorized after-state")
	if err := os.WriteFile(target, before, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewJournalStore(filepath.Join(t.TempDir(), "transactions"))
	if err != nil {
		t.Fatal(err)
	}
	plan := newTestPlan(t, root, before, after, 0o600)
	tx, err := store.Begin(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkApplying(); err != nil {
		_ = tx.Close()
		t.Fatal(err)
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}

	// Model a process crash after the target rename but before COMMITTED was
	// durably recorded. Recovery inspects observed state and never retries.
	if err := os.WriteFile(target, after, 0o600); err != nil {
		t.Fatal(err)
	}
	results, err := store.RecoverPending()
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("recovery results=%#v, want one", results)
	}
	result := results[0]
	if result.State != JournalAfterStateObserved || result.Outcome != "AFTER_STATE_OBSERVED_ATTRIBUTION_UNCERTAIN" {
		t.Fatalf("recovery result=%#v", result)
	}
	if !strings.Contains(result.Reason, "cannot prove which process") {
		t.Fatalf("reason=%q", result.Reason)
	}
	record, err := store.readRecord(store.recordPath(plan.Hash()))
	if err != nil {
		t.Fatal(err)
	}
	if record.State != JournalAfterStateObserved {
		t.Fatalf("persisted state=%s", record.State)
	}
}

func TestRecoverPendingMarksPreparedBeforeStateNotCommitted(t *testing.T) {
	root := t.TempDir()
	before, after := []byte("before"), []byte("authorized after-state")
	if err := os.WriteFile(filepath.Join(root, "README.md"), before, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewJournalStore(filepath.Join(t.TempDir(), "transactions"))
	if err != nil {
		t.Fatal(err)
	}
	plan := newTestPlan(t, root, before, after, 0o600)
	tx, err := store.Begin(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}

	results, err := store.RecoverPending()
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].State != JournalAborted || results[0].Outcome != "NOT_COMMITTED" {
		t.Fatalf("recovery results=%#v", results)
	}
}

func TestRecoverPendingDoesNotClaimApplyingBeforeStateWasNeverCommitted(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "README.md")
	before, after := []byte("before"), []byte("authorized after-state")
	if err := os.WriteFile(target, before, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewJournalStore(filepath.Join(t.TempDir(), "transactions"))
	if err != nil {
		t.Fatal(err)
	}
	plan := newTestPlan(t, root, before, after, 0o600)
	tx, err := store.Begin(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkApplying(); err != nil {
		_ = tx.Close()
		t.Fatal(err)
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}

	results, err := store.RecoverPending()
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].State != JournalBeforeStateObserved ||
		results[0].Outcome != "BEFORE_STATE_OBSERVED_ATTRIBUTION_UNCERTAIN" {
		t.Fatalf("recovery results=%#v", results)
	}
}
func TestRecoveryRejectsWorkspacePathReplacement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "workspace")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	before, after := []byte("before"), []byte("after")
	if err := os.WriteFile(filepath.Join(root, "README.md"), before, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewJournalStore(filepath.Join(t.TempDir(), "transactions"))
	if err != nil {
		t.Fatal(err)
	}
	plan := newTestPlan(t, root, before, after, 0o600)
	tx, err := store.Begin(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkApplying(); err != nil {
		_ = tx.Close()
		t.Fatal(err)
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(parent, "moved")
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "README.md"), before, 0o600); err != nil {
		t.Fatal(err)
	}

	results, err := store.RecoverPending()
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].State != JournalRecoveryRequired || results[0].Reason != "workspace_identity_mismatch" {
		t.Fatalf("recovery results=%#v", results)
	}
}

func TestJournalRejectsConcurrentRecoveryWhileCommitOwnsLock(t *testing.T) {
	root := t.TempDir()
	before, after := []byte("before"), []byte("after")
	if err := os.WriteFile(filepath.Join(root, "README.md"), before, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewJournalStore(filepath.Join(t.TempDir(), "transactions"))
	if err != nil {
		t.Fatal(err)
	}
	plan := newTestPlan(t, root, before, after, 0o600)
	tx, err := store.Begin(plan)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	if _, err := store.RecoverPending(); !errors.Is(err, ErrJournalBusy) {
		t.Fatalf("recovery error=%v, want busy", err)
	}
}

func TestJournalRejectsCorruptedRecordWithoutTouchingWorkspace(t *testing.T) {
	root := t.TempDir()
	before, after := []byte("before"), []byte("after")
	target := filepath.Join(root, "README.md")
	if err := os.WriteFile(target, before, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewJournalStore(filepath.Join(t.TempDir(), "transactions"))
	if err != nil {
		t.Fatal(err)
	}
	plan := newTestPlan(t, root, before, after, 0o600)
	tx, err := store.Begin(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
	path := store.recordPath(plan.Hash())
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	contents = []byte(strings.Replace(string(contents), "PREPARED", "APPLYING", 1))
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecoverPending(); !errors.Is(err, ErrJournalCorrupt) {
		t.Fatalf("recovery error=%v, want corrupt record", err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != string(before) {
		t.Fatalf("workspace changed: %q, %v", got, err)
	}
}
