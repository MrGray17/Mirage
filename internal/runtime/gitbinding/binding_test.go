package gitbinding

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/runtime/tree"
)

const testManifest = "sha256:manifest-binding-test"

func TestCaptureValidOrdinaryRepositoryWithoutMutation(t *testing.T) {
	repository := newRepository(t)
	gitDir := filepath.Join(repository, ".git")
	before := scanGitDir(t, gitDir)
	statusBefore := testGit(t, repository, "status", "--porcelain=v1", "--untracked-files=all")

	binding, err := Capture(repository, testManifest, testTime())
	if err != nil {
		t.Fatal(err)
	}
	if binding.Identity() == "" || binding.RepositoryIdentity() == "" || binding.ManifestHash() != testManifest || binding.HeadRef() != "refs/heads/main" || !validObjectID(binding.HeadCommit()) || !validObjectID(binding.HeadTree()) {
		t.Fatalf("incomplete binding: %#v", binding)
	}
	if err := binding.Revalidate(testManifest); err != nil {
		t.Fatal(err)
	}
	after := scanGitDir(t, gitDir)
	statusAfter := testGit(t, repository, "status", "--porcelain=v1", "--untracked-files=all")
	if before.Identity() != after.Identity() || statusBefore != statusAfter {
		t.Fatalf("read-only binding mutated Git: before=%s after=%s status=%q/%q", before.Identity(), after.Identity(), statusBefore, statusAfter)
	}
}

func TestBindingIdentityChangesWithHeadEvenWhenTreeDoesNot(t *testing.T) {
	repository := newRepository(t)
	first, err := Capture(repository, testManifest, testTime())
	if err != nil {
		t.Fatal(err)
	}
	testGit(t, repository, "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "--allow-empty", "-m", "second history")
	second, err := Capture(repository, testManifest, testTime())
	if err != nil {
		t.Fatal(err)
	}
	if first.HeadCommit() == second.HeadCommit() || first.HeadTree() != second.HeadTree() || first.Identity() == second.Identity() {
		t.Fatalf("HEAD-only change not bound: first=%s/%s second=%s/%s", first.HeadCommit(), first.HeadTree(), second.HeadCommit(), second.HeadTree())
	}
}

func TestBindingIdentityChangesWithHeadTree(t *testing.T) {
	repository := newRepository(t)
	first, err := Capture(repository, testManifest, testTime())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "README.md"), []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, repository, "add", "--", "README.md")
	testGit(t, repository, "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "-m", "change tree")
	second, err := Capture(repository, testManifest, testTime())
	if err != nil {
		t.Fatal(err)
	}
	if first.HeadTree() == second.HeadTree() || first.Identity() == second.Identity() {
		t.Fatal("tree change did not change repository binding identity")
	}
}

func TestRevalidateFailsClosedWhenHeadOrRefChanges(t *testing.T) {
	t.Run("head", func(t *testing.T) {
		repository := newRepository(t)
		binding, err := Capture(repository, testManifest, testTime())
		if err != nil {
			t.Fatal(err)
		}
		testGit(t, repository, "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "--allow-empty", "-m", "new head")
		if err := binding.Revalidate(testManifest); !errors.Is(err, ErrRepositoryChanged) {
			t.Fatalf("revalidate = %v", err)
		}
	})
	t.Run("ref", func(t *testing.T) {
		repository := newRepository(t)
		binding, err := Capture(repository, testManifest, testTime())
		if err != nil {
			t.Fatal(err)
		}
		testGit(t, repository, "branch", "other")
		if err := os.WriteFile(filepath.Join(repository, ".git", "HEAD"), []byte("ref: refs/heads/other\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := binding.Revalidate(testManifest); !errors.Is(err, ErrRepositoryChanged) {
			t.Fatalf("revalidate = %v", err)
		}
	})
}

func TestCaptureRejectsDirtyAndAmbiguousRepositories(t *testing.T) {
	t.Run("tracked worktree", func(t *testing.T) {
		repository := newRepository(t)
		if err := os.WriteFile(filepath.Join(repository, "README.md"), []byte("dirty\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Capture(repository, testManifest, testTime()); !errors.Is(err, ErrDirtyRepository) {
			t.Fatalf("capture = %v", err)
		}
	})
	t.Run("skip worktree index flag", func(t *testing.T) {
		repository := newRepository(t)
		testGit(t, repository, "update-index", "--skip-worktree", "README.md")
		if _, err := Capture(repository, testManifest, testTime()); !errors.Is(err, ErrUnsupportedLayout) {
			t.Fatalf("capture = %v", err)
		}
	})
	t.Run("gitfile", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: elsewhere\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Capture(root, testManifest, testTime()); !errors.Is(err, ErrUnsupportedLayout) {
			t.Fatalf("capture = %v", err)
		}
	})
	t.Run("config include", func(t *testing.T) {
		repository := newRepository(t)
		config := filepath.Join(repository, ".git", "config")
		file, err := os.OpenFile(config, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.WriteString("\n[include] # legitimate comment\n\tpath = ../outside\n")
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatal(errors.Join(writeErr, closeErr))
		}
		if _, err := Capture(repository, testManifest, testTime()); !errors.Is(err, ErrUnsupportedLayout) {
			t.Fatalf("capture = %v", err)
		}
	})
	t.Run("nested path", func(t *testing.T) {
		repository := newRepository(t)
		nested := filepath.Join(repository, "nested")
		if err := os.Mkdir(nested, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := Capture(nested, testManifest, testTime()); !errors.Is(err, ErrUnsupportedLayout) {
			t.Fatalf("capture = %v", err)
		}
	})
	t.Run("malformed ref", func(t *testing.T) {
		repository := newRepository(t)
		if err := os.WriteFile(filepath.Join(repository, ".git", "HEAD"), []byte("ref: refs/heads/main..evil\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Capture(repository, testManifest, testTime()); err == nil {
			t.Fatal("malformed ref was accepted")
		}
	})
	if runtime.GOOS != "windows" {
		t.Run("git directory symlink", func(t *testing.T) {
			repository := newRepository(t)
			gitDir := filepath.Join(repository, ".git")
			actual := filepath.Join(repository, ".git-actual")
			if err := os.Rename(gitDir, actual); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(actual, gitDir); err != nil {
				t.Fatal(err)
			}
			if _, err := Capture(repository, testManifest, testTime()); !errors.Is(err, ErrUnsupportedLayout) {
				t.Fatalf("capture = %v", err)
			}
		})
	}
}

func TestBindTrackedBlobRejectsUntrackedOrMismatchedM4Base(t *testing.T) {
	repository := newRepository(t)
	binding, err := Capture(repository, testManifest, testTime())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("before\n"))
	expected := "sha256:" + fmt.Sprintf("%x", digest)
	blob, err := binding.BindTrackedBlob(testManifest, "/workspace/README.md", expected, false)
	if err != nil || !validObjectID(blob.ObjectID()) || blob.Digest() != expected || blob.Executable() {
		t.Fatalf("tracked blob = %#v, %v", blob, err)
	}
	if err := os.WriteFile(filepath.Join(repository, "notes.txt"), []byte("untracked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := binding.BindTrackedBlob(testManifest, "/workspace/notes.txt", expected, false); !errors.Is(err, ErrUntrackedResource) {
		t.Fatalf("untracked blob = %v", err)
	}
	if _, err := binding.BindTrackedBlob(testManifest, "/workspace/README.md", "sha256:wrong", false); !errors.Is(err, ErrBlobMismatch) {
		t.Fatalf("mismatched blob = %v", err)
	}
}

func TestTrustedGitEnvironmentScrubsCredentials(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "secret-token")
	t.Setenv("SSH_AUTH_SOCK", "secret-socket")
	t.Setenv("GIT_SSH_COMMAND", "secret-command")
	t.Setenv("DEEPSEEK_API_KEY", "secret-provider")
	joined := strings.Join(scrubbedGitEnvironment(), "\n")
	for _, secret := range []string{"secret-token", "secret-socket", "secret-command", "secret-provider", "GITHUB_TOKEN", "SSH_AUTH_SOCK", "GIT_SSH_COMMAND", "DEEPSEEK_API_KEY"} {
		if strings.Contains(joined, secret) {
			t.Fatalf("credential-bearing environment propagated: %s", secret)
		}
	}
}

func TestAgentShadowGitCannotBecomeTrustedIdentity(t *testing.T) {
	repository := newRepository(t)
	binding, err := Capture(repository, testManifest, testTime())
	if err != nil {
		t.Fatal(err)
	}
	shadow := t.TempDir()
	if err := os.Mkdir(filepath.Join(shadow, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shadow, ".git", "HEAD"), []byte("ref: refs/heads/evil\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if binding.Root() == shadow || strings.Contains(binding.RepositoryIdentity(), shadow) {
		t.Fatal("shadow path entered trusted repository identity")
	}
	if err := binding.Revalidate(testManifest); err != nil {
		t.Fatalf("unrelated hostile shadow changed trusted binding: %v", err)
	}
}

func newRepository(t *testing.T) string {
	t.Helper()
	repository := t.TempDir()
	testGit(t, repository, "init", "-b", "main")
	if err := os.WriteFile(filepath.Join(repository, "README.md"), []byte("before\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, repository, "add", "--", "README.md")
	testGit(t, repository, "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "-m", "initial")
	return repository
}

func testGit(t *testing.T, repository string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", repository}, args...)...)
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v (%s)", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func scanGitDir(t *testing.T, gitDir string) *tree.Snapshot {
	t.Helper()
	snapshot, err := tree.Scan(gitDir, tree.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func testTime() time.Time { return time.Date(2026, 8, 28, 18, 0, 0, 0, time.UTC) }
