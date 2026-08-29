package gitpublication

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	workspacePrefix   = ".mirage-m53-"
	maxWorkspaceBytes = 96 << 20
	maxGitEntries     = 100000
)

var (
	ErrWorkspace        = errors.New("Git publication workspace failed")
	ErrWorkspaceChanged = errors.New("Git publication workspace identity changed")
	ErrCleanup          = errors.New("Git publication workspace cleanup failed")
	ErrLocalGitChanged  = errors.New("real local Git state changed")
)

type workspace struct {
	root        string
	gitDir      string
	objects     string
	home        string
	hooks       string
	askpass     string
	tempRoot    string
	realRoot    string
	realGitDir  string
	rootInfo    os.FileInfo
	gitInfo     os.FileInfo
	objectsInfo os.FileInfo
	cleaned     bool
}

func newWorkspace(realRoot, realGitDir string) (*workspace, error) {
	tempRoot, err := filepath.Abs(os.TempDir())
	if err != nil {
		return nil, fmt.Errorf("%w: resolve temp root", ErrWorkspace)
	}
	tempRoot, err = filepath.EvalSymlinks(filepath.Clean(tempRoot))
	if err != nil {
		return nil, fmt.Errorf("%w: resolve physical temp root", ErrWorkspace)
	}
	realRoot, err = filepath.Abs(realRoot)
	if err != nil {
		return nil, ErrWorkspace
	}
	realGitDir, err = filepath.Abs(realGitDir)
	if err != nil {
		return nil, ErrWorkspace
	}
	root, err := os.MkdirTemp(tempRoot, workspacePrefix)
	if err != nil {
		return nil, fmt.Errorf("%w: create root", ErrWorkspace)
	}
	fail := func(cause error) (*workspace, error) {
		if cleanupErr := os.RemoveAll(root); cleanupErr != nil {
			return nil, errors.Join(cause, fmt.Errorf("%w: %v", ErrCleanup, cleanupErr))
		}
		return nil, cause
	}
	if pathsOverlap(root, realRoot) || pathsOverlap(root, realGitDir) {
		return fail(fmt.Errorf("%w: publication and real roots overlap", ErrWorkspace))
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return fail(fmt.Errorf("%w: protect root", ErrWorkspace))
	}
	gitDir := filepath.Join(root, "repository.git")
	objects := filepath.Join(gitDir, "objects")
	home := filepath.Join(root, "home")
	hooks := filepath.Join(root, "hooks-disabled")
	for _, directory := range []string{gitDir, objects, filepath.Join(gitDir, "refs"), home, hooks} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			return fail(fmt.Errorf("%w: create bounded layout", ErrWorkspace))
		}
	}
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/mirage-unborn\n"), 0o600); err != nil {
		return fail(ErrWorkspace)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte("[core]\n\trepositoryformatversion = 0\n\tbare = true\n"), 0o600); err != nil {
		return fail(ErrWorkspace)
	}
	askpass := filepath.Join(root, "askpass.sh")
	helper := "#!/bin/sh\ncase \"$1\" in\n  *Username*github.com*) printf '%s\\n' 'x-access-token' ;;\n  *Password*github.com*) printf '%s\\n' \"$MIRAGE_M53_ASKPASS_TOKEN\" ;;\n  *) exit 1 ;;\nesac\n"
	if err := os.WriteFile(askpass, []byte(helper), 0o700); err != nil {
		return fail(fmt.Errorf("%w: create secret-free askpass helper", ErrWorkspace))
	}
	rootInfo, rootErr := os.Lstat(root)
	gitInfo, gitErr := os.Lstat(gitDir)
	objectsInfo, objectsErr := os.Lstat(objects)
	if rootErr != nil || gitErr != nil || objectsErr != nil || !safeDirectory(rootInfo) || !safeDirectory(gitInfo) || !safeDirectory(objectsInfo) {
		return fail(fmt.Errorf("%w: acquire physical layout", ErrWorkspace))
	}
	return &workspace{root: filepath.Clean(root), gitDir: filepath.Clean(gitDir), objects: filepath.Clean(objects), home: home, hooks: hooks, askpass: askpass, tempRoot: tempRoot, realRoot: filepath.Clean(realRoot), realGitDir: filepath.Clean(realGitDir), rootInfo: rootInfo, gitInfo: gitInfo, objectsInfo: objectsInfo}, nil
}

func (w *workspace) revalidate() error {
	if w == nil || w.cleaned {
		return ErrWorkspaceChanged
	}
	root, rootErr := os.Lstat(w.root)
	gitDir, gitErr := os.Lstat(w.gitDir)
	objects, objectsErr := os.Lstat(w.objects)
	if rootErr != nil || gitErr != nil || objectsErr != nil || !safeDirectory(root) || !safeDirectory(gitDir) || !safeDirectory(objects) || !os.SameFile(w.rootInfo, root) || !os.SameFile(w.gitInfo, gitDir) || !os.SameFile(w.objectsInfo, objects) {
		return fmt.Errorf("%w: protected directory identity differs", ErrWorkspaceChanged)
	}
	return nil
}

func (w *workspace) cleanup() error {
	if w == nil || w.cleaned {
		return nil
	}
	if filepath.Base(w.root) == w.root || !strings.HasPrefix(filepath.Base(w.root), workspacePrefix) || !pathContains(w.tempRoot, w.root) || pathsOverlap(w.root, w.realRoot) || pathsOverlap(w.root, w.realGitDir) {
		return fmt.Errorf("%w: unsafe cleanup target", ErrCleanup)
	}
	if err := w.revalidate(); err != nil {
		return errors.Join(ErrCleanup, err)
	}
	if err := os.RemoveAll(w.root); err != nil {
		return fmt.Errorf("%w: %v", ErrCleanup, err)
	}
	w.cleaned = true
	return nil
}

func (w *workspace) verifyBounded() error {
	if err := w.revalidate(); err != nil {
		return err
	}
	entries := 0
	var bytes int64
	err := filepath.WalkDir(w.root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > maxGitEntries {
			return errors.New("publication entry bound exceeded")
		}
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return errors.New("unsupported publication object")
		}
		if info.Mode().IsRegular() {
			if info.Size() < 0 || bytes > maxWorkspaceBytes-info.Size() {
				return errors.New("publication byte bound exceeded")
			}
			bytes += info.Size()
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWorkspace, err)
	}
	return nil
}

func safeDirectory(info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}
func pathsOverlap(left, right string) bool {
	return pathContains(left, right) || pathContains(right, left)
}
func pathContains(base, target string) bool {
	relative, err := filepath.Rel(filepath.Clean(base), filepath.Clean(target))
	return err == nil && (relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))))
}

// snapshotGit hashes path, type, permission mode, size, and regular-file bytes
// for the entire real administrative directory. Reads are bounded and reject
// links/special objects, so publication can prove it caused no local Git write.
func snapshotGit(gitDir string) (string, error) {
	root, err := filepath.Abs(gitDir)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(root)
	if err != nil || !safeDirectory(info) {
		return "", fmt.Errorf("%w: unsafe .git root", ErrLocalGitChanged)
	}
	type entry struct {
		Path   string `json:"path"`
		Mode   uint32 `json:"mode"`
		Size   int64  `json:"size"`
		Digest string `json:"digest"`
	}
	entries := make([]entry, 0)
	var total int64
	err = filepath.WalkDir(root, func(current string, dirEntry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		if len(entries) >= maxGitEntries {
			return errors.New("Git entry bound exceeded")
		}
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return errors.New("unsupported object in real .git")
		}
		item := entry{Path: filepath.ToSlash(relative), Mode: uint32(info.Mode().Perm()), Size: info.Size()}
		if info.Mode().IsRegular() {
			if info.Size() < 0 || total > maxWorkspaceBytes-info.Size() {
				return errors.New("Git snapshot byte bound exceeded")
			}
			file, err := os.Open(current)
			if err != nil {
				return err
			}
			opened, err := file.Stat()
			if err != nil || !os.SameFile(info, opened) {
				_ = file.Close()
				return errors.New("Git file changed during acquisition")
			}
			hash := sha256.New()
			written, copyErr := io.Copy(hash, io.LimitReader(file, info.Size()+1))
			closeErr := file.Close()
			final, finalErr := os.Lstat(current)
			if copyErr != nil || closeErr != nil || finalErr != nil || written != info.Size() || !os.SameFile(opened, final) {
				return errors.New("Git file changed during snapshot")
			}
			item.Digest = "sha256:" + hex.EncodeToString(hash.Sum(nil))
			total += info.Size()
		}
		entries = append(entries, item)
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrLocalGitChanged, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return hashCanonical(entries)
}
