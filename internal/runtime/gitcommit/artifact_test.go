package gitcommit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/runtime/gitbinding"
	"github.com/MrGray17/Mirage/internal/runtime/gitplan"
	"github.com/MrGray17/Mirage/internal/runtime/reconcile"
	"github.com/MrGray17/Mirage/internal/runtime/tree"
)

const artifactManifest = "sha256:m52-test-manifest"

func TestConstructIsDeterministicAndLeavesRealGitByteIdentical(t *testing.T) {
	fixture := newArtifactFixture(t, "README.md", []byte("authorized result\n"))
	before := snapshotDirectory(t, fixture.repository.Root())
	t.Setenv("GIT_OBJECT_DIRECTORY", filepath.Join(fixture.repository.GitDir(), "objects"))
	t.Setenv("GIT_INDEX_FILE", filepath.Join(fixture.repository.GitDir(), "index"))
	t.Setenv("GITHUB_TOKEN", "must-not-be-used")
	t.Setenv("SSH_AUTH_SOCK", "must-not-be-used")

	artifact, err := Construct(fixture.spec())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = artifact.Cleanup() })
	if artifact.Version() != Version || artifact.ManifestHash() != artifactManifest || artifact.GitPlanIdentity() != fixture.gitPlan.Identity() || artifact.RepositoryBindingIdentity() != fixture.repository.Identity() || artifact.ReconciliationPlanHash() != fixture.reconciliation.Hash() || artifact.BaseCommit() != fixture.gitPlan.BaseCommit() || artifact.BaseTree() != fixture.gitPlan.BaseTree() || artifact.TargetRef() != fixture.gitPlan.TargetRef() || artifact.Resource() != "/workspace/README.md" || artifact.BaseBlobOID() != fixture.gitPlan.Effects()[0].BaseBlobOID || !validOID(artifact.NewBlobOID()) || !validOID(artifact.NewTreeOID()) || !validOID(artifact.CommitOID()) || artifact.Identity() == "" {
		t.Fatalf("incomplete artifact: %#v", artifact)
	}
	if !artifact.GitTimestamp().Equal(time.Unix(fixture.gitPlan.CreatedAt().Unix(), 0).UTC()) || artifact.GitTimestamp().Nanosecond() != 0 {
		t.Fatalf("Git timestamp = %s", artifact.GitTimestamp())
	}
	blob, err := artifact.transaction.readObject("blob", artifact.NewBlobOID())
	if err != nil || !reflect.DeepEqual(blob, fixture.after) {
		t.Fatalf("blob = %q, %v", blob, err)
	}
	digest := sha256.Sum256(blob)
	if "sha256:"+hex.EncodeToString(digest[:]) != fixture.gitPlan.Effects()[0].AfterDigest {
		t.Fatal("new blob SHA-256 differs from GitEffectPlan")
	}
	commit, err := artifact.transaction.readObject("commit", artifact.CommitOID())
	if err != nil {
		t.Fatal(err)
	}
	expectedCommit := fmt.Sprintf("tree %s\nparent %s\nauthor MIRAGE <mirage@localhost> %d +0000\ncommitter MIRAGE <mirage@localhost> %d +0000\n\n%s\n", artifact.NewTreeOID(), artifact.BaseCommit(), artifact.GitTimestamp().Unix(), artifact.GitTimestamp().Unix(), fixture.gitPlan.Message())
	if string(commit) != expectedCommit || strings.Count(string(commit), "parent ") != 1 {
		t.Fatalf("commit bytes = %q", commit)
	}
	if parsed := runTransactionGit(t, fixture.repository, artifact, "cat-file", "commit", artifact.CommitOID()); !reflect.DeepEqual(parsed, commit) {
		t.Fatalf("Git parsed commit = %q, expected %q", parsed, commit)
	}
	delta := runTransactionGit(t, fixture.repository, artifact, "diff-tree", "--no-commit-id", "--name-status", "-z", artifact.BaseTree(), artifact.NewTreeOID())
	if string(delta) != "M\x00README.md\x00" {
		t.Fatalf("tree delta = %q", delta)
	}
	if err := Revalidate(artifact, fixture.spec()); err != nil {
		t.Fatal(err)
	}
	t.Logf("GitEffectPlan=%s BaseCommit=%s BaseTree=%s BaseBlobOID=%s NewBlobOID=%s NewTreeOID=%s CommitOID=%s CommitArtifact=%s", fixture.gitPlan.Identity(), artifact.BaseCommit(), artifact.BaseTree(), artifact.BaseBlobOID(), artifact.NewBlobOID(), artifact.NewTreeOID(), artifact.CommitOID(), artifact.Identity())

	second, err := Construct(fixture.spec())
	if err != nil {
		t.Fatal(err)
	}
	if second.transaction.root == artifact.transaction.root || second.Identity() != artifact.Identity() || second.NewBlobOID() != artifact.NewBlobOID() || second.NewTreeOID() != artifact.NewTreeOID() || second.CommitOID() != artifact.CommitOID() {
		t.Fatalf("fresh construction differs: first=%s/%s second=%s/%s", artifact.Identity(), artifact.CommitOID(), second.Identity(), second.CommitOID())
	}
	secondRoot := second.transaction.root
	if err := second.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(secondRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("second transaction remains: %v", err)
	}
	after := snapshotDirectory(t, fixture.repository.Root())
	if !reflect.DeepEqual(before, after) {
		t.Fatal("real worktree, HEAD, refs, reflogs, index, config, or object database changed")
	}
	firstRoot := artifact.transaction.root
	if err := artifact.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(firstRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first transaction remains: %v", err)
	}
}

func TestConstructSupportsLiteralHostilePathCharacters(t *testing.T) {
	paths := []string{
		"directory with spaces/-leading [brackets] café.txt",
	}
	if runtime.GOOS != "windows" {
		paths = append(paths, "literal * and ?/colon:name.txt")
	}
	for _, relative := range paths {
		t.Run(relative, func(t *testing.T) {
			fixture := newArtifactFixture(t, relative, []byte("literal path update\n"))
			artifact, err := Construct(fixture.spec())
			if err != nil {
				t.Fatal(err)
			}
			if artifact.Resource() != "/workspace/"+filepath.ToSlash(relative) {
				t.Fatalf("resource = %q", artifact.Resource())
			}
			if err := Revalidate(artifact, fixture.spec()); err != nil {
				t.Fatal(err)
			}
			if err := artifact.Cleanup(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConstructPreservesExecutableGitMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows fixtures do not expose Unix executable mode")
	}
	fixture := newArtifactFixtureWithMode(t, "scripts/run.sh", []byte("#!/bin/sh\necho changed\n"), 0o755)
	artifact, err := Construct(fixture.spec())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := artifact.Cleanup(); err != nil {
			t.Errorf("cleanup executable artifact: %v", err)
		}
	})
	effect := artifact.Effect()
	if effect.BeforeMode&0o111 == 0 || effect.AfterMode != effect.BeforeMode {
		t.Fatalf("effect modes = %04o -> %04o", effect.BeforeMode, effect.AfterMode)
	}
	entry := runTransactionGit(t, fixture.repository, artifact, "ls-tree", "-z", artifact.NewTreeOID(), "--", ":(literal)scripts/run.sh")
	if !strings.HasPrefix(string(entry), "100755 blob "+artifact.NewBlobOID()+"\tscripts/run.sh\x00") {
		t.Fatalf("new executable tree entry = %q", entry)
	}
}

func TestRevalidateRejectsObjectTamperingAndTransactionReplacement(t *testing.T) {
	t.Run("object bytes", func(t *testing.T) {
		fixture := newArtifactFixture(t, "README.md", []byte("authorized result\n"))
		artifact, err := Construct(fixture.spec())
		if err != nil {
			t.Fatal(err)
		}
		objectPath := filepath.Join(artifact.transaction.objects, artifact.NewBlobOID()[:2], artifact.NewBlobOID()[2:])
		if err := os.WriteFile(objectPath, []byte("corrupt"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := Revalidate(artifact, fixture.spec()); !errors.Is(err, ErrObject) {
			t.Fatalf("tampered object = %v", err)
		}
		if err := artifact.Cleanup(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("object trailing bytes", func(t *testing.T) {
		fixture := newArtifactFixture(t, "README.md", []byte("authorized result\n"))
		artifact, err := Construct(fixture.spec())
		if err != nil {
			t.Fatal(err)
		}
		objectPath := filepath.Join(artifact.transaction.objects, artifact.NewBlobOID()[:2], artifact.NewBlobOID()[2:])
		file, err := os.OpenFile(objectPath, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.Write([]byte("trailing"))
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatal(errors.Join(writeErr, closeErr))
		}
		if err := Revalidate(artifact, fixture.spec()); !errors.Is(err, ErrObject) {
			t.Fatalf("trailing object bytes = %v", err)
		}
		if err := artifact.Cleanup(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("physical root", func(t *testing.T) {
		fixture := newArtifactFixture(t, "README.md", []byte("authorized result\n"))
		artifact, err := Construct(fixture.spec())
		if err != nil {
			t.Fatal(err)
		}
		root := artifact.transaction.root
		moved := root + "-owned"
		if err := os.Rename(root, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := artifact.Cleanup(); !errors.Is(err, ErrCleanup) || !errors.Is(err, ErrTransactionChanged) {
			t.Fatalf("replacement cleanup = %v", err)
		}
		if _, err := os.Lstat(root); err != nil {
			t.Fatal("replacement root was removed")
		}
		if err := os.Remove(root); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(moved, root); err != nil {
			t.Fatal(err)
		}
		if err := artifact.Cleanup(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("unbound extra object", func(t *testing.T) {
		fixture := newArtifactFixture(t, "README.md", []byte("authorized result\n"))
		artifact, err := Construct(fixture.spec())
		if err != nil {
			t.Fatal(err)
		}
		oid, _, err := canonicalObject("blob", []byte("unbound"))
		if err != nil {
			t.Fatal(err)
		}
		if err := artifact.transaction.writeObject(objectRecord{kind: "blob", oid: oid, data: []byte("unbound")}); err != nil {
			t.Fatal(err)
		}
		if err := Revalidate(artifact, fixture.spec()); !errors.Is(err, ErrTransactionChanged) {
			t.Fatalf("extra object = %v", err)
		}
		if err := artifact.Cleanup(); err != nil {
			t.Fatal(err)
		}
	})
}

type artifactFixture struct {
	at             time.Time
	contract       *contracts.Contract
	repository     *gitbinding.Binding
	reconciliation *tree.Plan
	decision       reconcile.Decision
	gitPlan        *gitplan.Plan
	after          []byte
}

func (f artifactFixture) spec() Spec {
	return Spec{
		ManifestHash: artifactManifest, Contract: f.contract, Repository: f.repository,
		GitPlan: f.gitPlan, ReconciliationPlan: f.reconciliation, Decision: f.decision,
		ObservedAt: f.at.Add(time.Minute),
	}
}

func newArtifactFixture(t *testing.T, relative string, after []byte) artifactFixture {
	return newArtifactFixtureWithMode(t, relative, after, 0o644)
}

func newArtifactFixtureWithMode(t *testing.T, relative string, after []byte, mode os.FileMode) artifactFixture {
	t.Helper()
	at := time.Date(2026, 8, 29, 1, 2, 3, 987654321, time.UTC)
	repositoryRoot := t.TempDir()
	runArtifactGit(t, repositoryRoot, "init", "-b", "main")
	writeArtifactFileMode(t, repositoryRoot, relative, []byte("before\n"), mode)
	writeArtifactFile(t, repositoryRoot, "unchanged/other.txt", []byte("other\n"))
	runArtifactGit(t, repositoryRoot, "add", "--", ".")
	runArtifactGit(t, repositoryRoot, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "base")
	repository, err := gitbinding.Capture(repositoryRoot, artifactManifest, at.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	baselineRoot := t.TempDir()
	writeArtifactFileMode(t, baselineRoot, relative, []byte("before\n"), mode)
	writeArtifactFile(t, baselineRoot, "unchanged/other.txt", []byte("other\n"))
	baseline, err := tree.Scan(baselineRoot, tree.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	finalRoot := t.TempDir()
	writeArtifactFileMode(t, finalRoot, relative, after, mode)
	writeArtifactFile(t, finalRoot, "unchanged/other.txt", []byte("other\n"))
	resource := "/workspace/" + filepath.ToSlash(relative)
	contract, err := contracts.New(contracts.Spec{
		Version: contracts.VersionV1, RunID: "m52-artifact", ActorID: "test", ExpiresAt: at.Add(time.Hour),
		Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{Allow: []string{resource}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	reconciliation, decision, err := reconcile.Verify(artifactManifest, baseline, finalRoot, contract, at)
	if err != nil || !decision.Allowed {
		t.Fatalf("reconcile = %#v, %v", decision, err)
	}
	gitPlan, err := gitplan.New(gitplan.Spec{
		RunID: contract.RunID(), ManifestHash: artifactManifest, Contract: contract, Repository: repository,
		ReconciliationPlan: reconciliation, Decision: decision, CreatedAt: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	return artifactFixture{at: at, contract: contract, repository: repository, reconciliation: reconciliation, decision: decision, gitPlan: gitPlan, after: append([]byte(nil), after...)}
}

func writeArtifactFile(t *testing.T, root, relative string, contents []byte) {
	writeArtifactFileMode(t, root, relative, contents, 0o644)
}

func writeArtifactFileMode(t *testing.T, root, relative string, contents []byte, mode os.FileMode) {
	t.Helper()
	target := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, contents, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, mode); err != nil {
		t.Fatal(err)
	}
}

func runArtifactGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v (%s)", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func runTransactionGit(t *testing.T, repository *gitbinding.Binding, artifact *Artifact, args ...string) []byte {
	t.Helper()
	command := exec.Command("git", append([]string{"--no-optional-locks", "--git-dir", repository.GitDir()}, args...)...)
	nullDevice := "/dev/null"
	if runtime.GOOS == "windows" {
		nullDevice = "NUL"
	}
	allowed := map[string]bool{"PATH": true, "PATHEXT": true, "SYSTEMROOT": true, "WINDIR": true, "COMSPEC": true}
	environment := make([]string, 0, len(allowed)+8)
	for _, item := range os.Environ() {
		name, _, ok := strings.Cut(item, "=")
		if ok && allowed[strings.ToUpper(name)] {
			environment = append(environment, item)
		}
	}
	command.Env = append(environment,
		"GIT_OBJECT_DIRECTORY="+artifact.transaction.objects,
		"GIT_ALTERNATE_OBJECT_DIRECTORIES="+filepath.Join(repository.GitDir(), "objects"),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+nullDevice,
		"GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1",
	)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("transaction git %v: %v", args, err)
	}
	return output
}

type fileState struct {
	Mode   fs.FileMode
	Digest string
}

func snapshotDirectory(t *testing.T, root string) map[string]fileState {
	t.Helper()
	states := make(map[string]fileState)
	err := filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		state := fileState{Mode: info.Mode()}
		if info.Mode().IsRegular() {
			contents, err := os.ReadFile(current)
			if err != nil {
				return err
			}
			digest := sha256.Sum256(contents)
			state.Digest = hex.EncodeToString(digest[:])
		}
		states[filepath.ToSlash(relative)] = state
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return states
}
