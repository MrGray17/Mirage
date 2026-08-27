package workspace

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	runtimedocker "github.com/MrGray17/Mirage/internal/runtime/docker"
	"github.com/MrGray17/Mirage/internal/runtime/tree"
)

func TestPrepareCopiesBoundedRepositoryTreeAndExcludesSecrets(t *testing.T) {
	real := workspaceTestDir(t)
	if err := os.WriteFile(filepath.Join(real, "README.md"), []byte("real contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(real, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "docs", "guide.md"), []byte("guide"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "docs", ".env.local"), []byte("NESTED_SECRET=value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, ".env"), []byte("SECRET=value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(real, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, ".git", "config"), []byte("credential=secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	disposable, err := Prepare(real)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	t.Cleanup(func() {
		if err := disposable.Cleanup(); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	contents, err := os.ReadFile(filepath.Join(disposable.Path(), "README.md"))
	if err != nil {
		t.Fatalf("read disposable README: %v", err)
	}
	if string(contents) != "real contents" {
		t.Fatalf("contents = %q", contents)
	}
	if _, err := os.Lstat(filepath.Join(disposable.Path(), ".env")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(".env entered disposable workspace: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(disposable.Path(), ".git")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(".git entered disposable workspace: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(disposable.Path(), "docs", ".env.local")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nested .env entered disposable workspace: %v", err)
	}
	guide, err := os.ReadFile(filepath.Join(disposable.Path(), "docs", "guide.md"))
	if err != nil || string(guide) != "guide" {
		t.Fatalf("nested repository file = %q, %v", guide, err)
	}
	marker, err := os.ReadFile(filepath.Join(disposable.Path(), runtimedocker.DisposableMarker))
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if string(marker) != disposable.Token() {
		t.Fatal("trusted disposable marker token mismatch")
	}
	if disposable.RealWorkspace() == disposable.Path() {
		t.Fatal("real workspace reused as disposable workspace")
	}
	if disposable.Baseline() == nil || disposable.Baseline().Identity() == "" {
		t.Fatal("physical disposable baseline was not captured")
	}
	binding, err := disposable.Binding()
	if err != nil {
		t.Fatalf("bind disposable workspace: %v", err)
	}
	if binding.Identity() == "" || binding.RealBaseline() == nil || binding.DisposableBaseline() == nil {
		t.Fatalf("incomplete workspace binding: %#v", binding)
	}
	realREADME, ok := findEntry(binding.RealBaseline(), "/workspace/README.md")
	if !ok {
		t.Fatal("real baseline omitted README")
	}
	disposableREADME, ok := findEntry(binding.DisposableBaseline(), "/workspace/README.md")
	if !ok {
		t.Fatal("disposable baseline omitted README")
	}
	if realREADME.Mode != 0o600 {
		t.Fatalf("real baseline mode = %04o, want 0600", realREADME.Mode)
	}
	if disposableREADME.Mode != 0o666 {
		t.Fatalf("disposable baseline mode = %04o, want normalized 0666", disposableREADME.Mode)
	}
	if binding.RealBaseline().Identity() == binding.DisposableBaseline().Identity() {
		t.Fatal("real and permission-normalized disposable baselines share an identity")
	}
	observedReal, err := binding.ObserveReal()
	if err != nil || observedReal.Identity() != binding.RealBaseline().Identity() {
		t.Fatalf("real baseline freshness = %v, identity %q", err, observedReal.Identity())
	}
	observedDisposable, err := binding.ObserveDisposable()
	if err != nil || observedDisposable.Identity() != binding.DisposableBaseline().Identity() {
		t.Fatalf("disposable baseline freshness = %v, identity %q", err, observedDisposable.Identity())
	}
}

func TestPrepareRejectsSymlinkREADME(t *testing.T) {
	real := workspaceTestDir(t)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(real, "README.md")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := Prepare(real); !errors.Is(err, ErrUnsafeSource) {
		t.Fatalf("prepare error = %v", err)
	}
}

func TestPrepareRejectsHardlinkedSourceObject(t *testing.T) {
	real := workspaceTestDir(t)
	readme := filepath.Join(real, "README.md")
	if err := os.WriteFile(readme, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(readme, filepath.Join(real, "alias.md")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if _, err := Prepare(real); !errors.Is(err, ErrUnsafeSource) {
		t.Fatalf("prepare error = %v", err)
	}
}

func TestCleanupNeverTouchesReality(t *testing.T) {
	real := workspaceTestDir(t)
	realREADME := filepath.Join(real, "README.md")
	if err := os.WriteFile(realREADME, []byte("real"), 0o600); err != nil {
		t.Fatal(err)
	}
	disposable, err := Prepare(real)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	disposablePath := disposable.Path()
	if err := disposable.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(disposablePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("disposable path remains: %v", err)
	}
	contents, err := os.ReadFile(realREADME)
	if err != nil || string(contents) != "real" {
		t.Fatalf("real README changed: %q, %v", contents, err)
	}
}

func TestPrepareRejectsOverlappingPhysicalTempRootBeforeCreation(t *testing.T) {
	real := workspaceTestDir(t)
	if err := os.WriteFile(filepath.Join(real, "README.md"), []byte("real"), 0o600); err != nil {
		t.Fatal(err)
	}
	unsafeTemp := filepath.Join(real, "temp")
	if err := os.Mkdir(unsafeTemp, 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := prepareAtTempRoot(real, unsafeTemp); !errors.Is(err, ErrUnsafeTemp) {
		t.Fatalf("prepare error = %v", err)
	}
	entries, err := os.ReadDir(unsafeTemp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("Prepare created entries under unsafe temp root: %v", entries)
	}
}

func workspaceTestDir(t *testing.T) string {
	t.Helper()
	base, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("resolve native test root: %v", err)
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatalf("create native test root: %v", err)
	}
	directory, err := os.MkdirTemp(base, ".mirage-workspace-test-")
	if err != nil {
		t.Fatalf("create workspace test directory: %v", err)
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		t.Fatalf("resolve workspace test directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(absolute); err != nil {
			t.Errorf("remove workspace test directory: %v", err)
		}
	})
	return absolute
}

func findEntry(snapshot interface{ Entries() []tree.Entry }, resource string) (tree.Entry, bool) {
	for _, entry := range snapshot.Entries() {
		if entry.Resource == resource {
			return entry, true
		}
	}
	return tree.Entry{}, false
}
