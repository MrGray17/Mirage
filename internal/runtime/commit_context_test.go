package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCommitContextCancellationPreventsReplacement(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	lifecycle, disposable := verifiedContentLifecycle(t, func() time.Time { return now }, now.Add(time.Hour))
	if _, err := lifecycle.PreCommit(); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(disposable.RealWorkspace(), "README.md")
	before, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := lifecycle.CommitContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("commit error: %v", err)
	}
	after, err := os.ReadFile(target)
	if err != nil || string(after) != string(before) {
		t.Fatalf("canceled commit changed reality: %q, %v", after, err)
	}
}
