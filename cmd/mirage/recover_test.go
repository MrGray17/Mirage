package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MrGray17/Mirage/internal/runtime/realcommit"
)

func TestRecoverCommandClassifiesInterruptedPreRenameTransaction(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "README.md")
	before, after := []byte("before"), []byte("after")
	if err := os.WriteFile(target, before, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := realcommit.NewJournalStore(filepath.Join(t.TempDir(), "transactions"))
	if err != nil {
		t.Fatal(err)
	}
	plan := recoveryTestPlan(t, root, before, after)
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

	var stdout, stderr bytes.Buffer
	if err := runRecover([]string{"--journal-dir", store.Directory()}, &stdout, &stderr); err != nil {
		t.Fatalf("recover: %v; stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "outcome=NOT_COMMITTED") {
		t.Fatalf("recovery output=%q", stdout.String())
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != string(before) {
		t.Fatalf("recovery mutated target: %q, %v", got, err)
	}
}

func TestRecoverCommandRetainsUncertainAfterStateFinding(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "README.md")
	before, after := []byte("before"), []byte("after")
	if err := os.WriteFile(target, before, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := realcommit.NewJournalStore(filepath.Join(t.TempDir(), "transactions"))
	if err != nil {
		t.Fatal(err)
	}
	plan := recoveryTestPlan(t, root, before, after)
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
	if err := os.WriteFile(target, after, 0o600); err != nil {
		t.Fatal(err)
	}

	for attempt := 0; attempt < 2; attempt++ {
		var stdout, stderr bytes.Buffer
		err := runRecover([]string{"--journal-dir", store.Directory()}, &stdout, &stderr)
		if err == nil || !strings.Contains(err.Error(), "remain unresolved") {
			t.Fatalf("attempt %d error=%v", attempt, err)
		}
		if !strings.Contains(stdout.String(), "AFTER_STATE_OBSERVED_ATTRIBUTION_UNCERTAIN") {
			t.Fatalf("attempt %d output=%q", attempt, stdout.String())
		}
	}
}

func recoveryTestPlan(t *testing.T, root string, before, after []byte) *realcommit.Plan {
	t.Helper()
	plan, err := realcommit.New(realcommit.Spec{
		ManifestHash:         "sha256:manifest",
		AuthorityHash:        "sha256:authority",
		RealBaselineIdentity: "sha256:baseline",
		RealWorkspace:        root,
		Resource:             "/workspace/README.md",
		BeforeDigest:         recoveryDigest(before),
		AfterDigest:          recoveryDigest(after),
		RealMode:             0o600,
		Contents:             after,
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func recoveryDigest(contents []byte) string {
	sum := sha256.Sum256(contents)
	return fmt.Sprintf("sha256:%x", sum)
}

func TestRecoverCommandRejectsCorruptJournalAndDoesNotReplay(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "README.md")
	before, after := []byte("before"), []byte("after")
	if err := os.WriteFile(target, before, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := realcommit.NewJournalStore(filepath.Join(t.TempDir(), "transactions"))
	if err != nil {
		t.Fatal(err)
	}
	plan := recoveryTestPlan(t, root, before, after)
	tx, err := store.Begin(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
	recordPath := filepath.Join(store.Directory(), strings.TrimPrefix(plan.Hash(), "sha256:")+".json")
	data, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "PREPARED", "APPLYING", 1))
	if err := os.WriteFile(recordPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if err := runRecover([]string{"--journal-dir", store.Directory()}, &stdout, &stderr); !errors.Is(err, realcommit.ErrJournalCorrupt) {
		t.Fatalf("error=%v, want corrupt journal", err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != string(before) {
		t.Fatalf("corrupt journal triggered mutation: %q, %v", got, err)
	}
}
