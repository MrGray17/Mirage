package tree

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/MrGray17/Mirage/internal/limits"
)

func TestScanIsCanonicalBoundedAndDoesNotExposeMutableContent(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("baseline\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "guide.md"), []byte("guide\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git", "secret"), []byte("not copied"), 0o600); err != nil {
		t.Fatal(err)
	}

	excludeGit := ScanOptions{Exclude: func(resource string, _ Kind) bool {
		return resource == "/workspace/.git"
	}}
	first, err := Scan(root, excludeGit)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	second, err := Scan(root, excludeGit)
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if first.Identity() != second.Identity() {
		t.Fatalf("identities differ: %s != %s", first.Identity(), second.Identity())
	}
	resources := make([]string, 0)
	for _, entry := range first.Entries() {
		resources = append(resources, entry.Resource)
	}
	want := []string{"/workspace/README.md", "/workspace/docs", "/workspace/docs/guide.md"}
	if !reflect.DeepEqual(resources, want) {
		t.Fatalf("resources = %v, want %v", resources, want)
	}

	entries := first.Entries()
	entries[0].content[0] = 'X'
	if got := string(first.Entries()[0].Content()); got != "baseline\n" {
		t.Fatalf("snapshot content mutated through copy: %q", got)
	}
	if err := ValidateBaseline(first); err != nil {
		t.Fatalf("safe baseline rejected: %v", err)
	}
}

func TestScanDescribesSymlinkWithoutFollowingIt(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside-secret")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	snapshot, err := Scan(root, ScanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	entries := snapshot.Entries()
	if len(entries) != 1 || entries[0].Kind != KindSymlink || len(entries[0].Content()) != 0 {
		t.Fatalf("symlink entry = %#v", entries)
	}
	if err := ValidateBaseline(snapshot); !errors.Is(err, ErrUnsafeBaseline) {
		t.Fatalf("baseline validation = %v", err)
	}
}

func TestScanDetectsHardlinkAlias(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "a.txt")
	if err := os.WriteFile(first, []byte("same object"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(first, filepath.Join(root, "b.txt")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	snapshot, err := Scan(root, ScanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	entries := snapshot.Entries()
	hardlinks := 0
	for _, entry := range entries {
		if entry.Kind == KindHardlink {
			hardlinks++
		}
	}
	if len(entries) != 2 || hardlinks == 0 {
		t.Fatalf("hardlink entries = %#v", entries)
	}
	if err := ValidateBaseline(snapshot); !errors.Is(err, ErrUnsafeBaseline) {
		t.Fatalf("baseline validation = %v", err)
	}
}

func TestScanFailsClosedOnOversizedFile(t *testing.T) {
	root := t.TempDir()
	file, err := os.Create(filepath.Join(root, "large.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(limits.MaxTreeFileBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(root, ScanOptions{}); !errors.Is(err, ErrTreeBudget) {
		t.Fatalf("scan error = %v", err)
	}
}

func TestDiffNormalizesRenameAndBindsFinalContents(t *testing.T) {
	baseline, err := newSnapshot([]Entry{{Resource: "/workspace/old.txt", Kind: KindFile, Mode: 0o644, Digest: "sha256:old", content: []byte("old")}})
	if err != nil {
		t.Fatal(err)
	}
	final, err := newSnapshot([]Entry{{Resource: "/workspace/new.txt", Kind: KindFile, Mode: 0o644, Digest: "sha256:new", content: []byte("new")}})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := Diff(baseline, final)
	if err != nil {
		t.Fatal(err)
	}
	changes := plan.Mutations()
	if len(changes) != 2 || changes[0].Operation != OperationCreate || changes[1].Operation != OperationDelete {
		t.Fatalf("changes = %#v", changes)
	}
	changes[0].content[0] = 'X'
	if got := string(plan.Mutations()[0].Content()); got != "new" {
		t.Fatalf("plan content mutated through copy: %q", got)
	}
	if plan.Hash() == "" || plan.BaselineIdentity() != baseline.Identity() || plan.FinalIdentity() != final.Identity() {
		t.Fatalf("invalid plan identity: %#v", plan)
	}
}

func TestDiffClassifiesFinalSpecialObjectsForRejection(t *testing.T) {
	baseline, err := newSnapshot(nil)
	if err != nil {
		t.Fatal(err)
	}
	final, err := newSnapshot([]Entry{
		{Resource: "/workspace/link", Kind: KindSymlink},
		{Resource: "/workspace/socket", Kind: KindUnsupported},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := Diff(baseline, final)
	if err != nil {
		t.Fatal(err)
	}
	changes := plan.Mutations()
	if len(changes) != 2 || changes[0].Operation != OperationSymlink || changes[1].Operation != OperationUnsupported {
		t.Fatalf("changes = %#v", changes)
	}
}

func TestDiffRejectsWorkspaceRootMetadataChange(t *testing.T) {
	baseline, err := newSnapshotWithRoot(nil, 0o777)
	if err != nil {
		t.Fatal(err)
	}
	final, err := newSnapshotWithRoot(nil, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := Diff(baseline, final)
	if err != nil {
		t.Fatal(err)
	}
	changes := plan.Mutations()
	if len(changes) != 1 || changes[0].Operation != OperationUnsupported || changes[0].Resource != "/workspace" {
		t.Fatalf("changes = %#v", changes)
	}
}
