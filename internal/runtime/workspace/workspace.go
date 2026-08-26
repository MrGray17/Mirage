// Package workspace prepares the deliberately narrow disposable workspace used
// by M4.1. It snapshots only README.md; bounded tree snapshots belong to M4.2.
package workspace

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/MrGray17/Mirage/internal/limits"
	runtimedocker "github.com/MrGray17/Mirage/internal/runtime/docker"
)

const managedFile = "README.md"

var (
	ErrInvalidSource = errors.New("invalid M4.1 source workspace")
	ErrUnsafeSource  = errors.New("unsafe M4.1 source resource")
	ErrCleanup       = errors.New("M4.1 disposable workspace cleanup failed")
)

// Disposable owns a protected outer directory and a container-writable inner
// workspace. The outer 0700 directory prevents unrelated host users from
// traversing the world-writable bind source required by a numeric non-root UID
// in a rootless container.
type Disposable struct {
	mu            sync.Mutex
	realWorkspace string
	outer         string
	workspace     string
	token         string
	cleaned       bool
}

func Prepare(realWorkspace string) (*Disposable, error) {
	real, err := resolveSource(realWorkspace)
	if err != nil {
		return nil, err
	}
	contents, err := readBoundedRegularFile(real)
	if err != nil {
		return nil, fmt.Errorf("%w: snapshot %s: %w", ErrInvalidSource, managedFile, err)
	}
	token, err := randomToken()
	if err != nil {
		return nil, fmt.Errorf("create disposable workspace token: %w", err)
	}

	outer, err := os.MkdirTemp("", "mirage-m41-")
	if err != nil {
		return nil, fmt.Errorf("create protected disposable root: %w", err)
	}
	fail := func(cause error) (*Disposable, error) {
		return nil, errors.Join(cause, removeOwnedDirectory(outer, real))
	}
	if err := os.Chmod(outer, 0o700); err != nil {
		return fail(fmt.Errorf("protect disposable root: %w", err))
	}

	inner := filepath.Join(outer, "workspace")
	if err := os.Mkdir(inner, 0o777); err != nil {
		return fail(fmt.Errorf("create disposable workspace: %w", err))
	}
	if err := os.Chmod(inner, 0o777); err != nil {
		return fail(fmt.Errorf("make disposable workspace container-writable: %w", err))
	}
	if err := writeExclusive(filepath.Join(inner, managedFile), contents, 0o666); err != nil {
		return fail(fmt.Errorf("populate disposable %s: %w", managedFile, err))
	}
	if err := writeExclusive(filepath.Join(inner, runtimedocker.DisposableMarker), []byte(token), 0o444); err != nil {
		return fail(fmt.Errorf("mark disposable workspace: %w", err))
	}

	return &Disposable{
		realWorkspace: real,
		outer:         filepath.Clean(outer),
		workspace:     filepath.Clean(inner),
		token:         token,
	}, nil
}

func (d *Disposable) Path() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.workspace
}

func (d *Disposable) RealWorkspace() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.realWorkspace
}

func (d *Disposable) Token() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.token
}

// Cleanup must be called only after the sandbox backend has proved its process
// tree stopped and removed the container. It never touches the real workspace.
func (d *Disposable) Cleanup() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cleaned {
		return nil
	}
	if err := removeOwnedDirectory(d.outer, d.realWorkspace); err != nil {
		return err
	}
	d.cleaned = true
	return nil
}

func resolveSource(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("%w: path is empty", ErrInvalidSource)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("%w: resolve path: %w", ErrInvalidSource, err)
	}
	absolute = filepath.Clean(absolute)
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", fmt.Errorf("%w: inspect path: %w", ErrInvalidSource, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("%w: path is not a non-symlink directory", ErrInvalidSource)
	}
	return absolute, nil
}

func readBoundedRegularFile(workspace string) (contents []byte, returnErr error) {
	root, err := os.OpenRoot(workspace)
	if err != nil {
		return nil, fmt.Errorf("open source root: %w", err)
	}
	var file *os.File
	defer func() {
		if file != nil {
			returnErr = errors.Join(returnErr, file.Close())
		}
		returnErr = errors.Join(returnErr, root.Close())
	}()

	initial, err := root.Lstat(managedFile)
	if err != nil {
		return nil, fmt.Errorf("inspect rooted %s: %w", managedFile, err)
	}
	if !initial.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not regular", ErrUnsafeSource, managedFile)
	}
	if initial.Size() > limits.MaxManagedFileBytes {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrUnsafeSource, managedFile, limits.MaxManagedFileBytes)
	}
	file, err = root.Open(managedFile)
	if err != nil {
		return nil, fmt.Errorf("open rooted %s: %w", managedFile, err)
	}
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened %s: %w", managedFile, err)
	}
	current, err := root.Lstat(managedFile)
	if err != nil || !opened.Mode().IsRegular() || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return nil, fmt.Errorf("%w: %s changed during acquisition", ErrUnsafeSource, managedFile)
	}

	contents, err = io.ReadAll(io.LimitReader(file, limits.MaxManagedFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read rooted %s: %w", managedFile, err)
	}
	if int64(len(contents)) > limits.MaxManagedFileBytes {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrUnsafeSource, managedFile, limits.MaxManagedFileBytes)
	}
	after, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("reinspect opened %s: %w", managedFile, err)
	}
	current, err = root.Lstat(managedFile)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(opened, current) || opened.Size() != after.Size() || opened.Mode() != after.Mode() || !opened.ModTime().Equal(after.ModTime()) {
		return nil, fmt.Errorf("%w: %s changed during snapshot", ErrUnsafeSource, managedFile)
	}
	return contents, nil
}

func writeExclusive(path string, contents []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func randomToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func removeOwnedDirectory(outer, real string) error {
	outer = filepath.Clean(outer)
	real = filepath.Clean(real)
	if outer == "" || outer == "." || pathsOverlap(outer, real) {
		return fmt.Errorf("%w: refusing unsafe cleanup target %q", ErrCleanup, outer)
	}
	if err := os.RemoveAll(outer); err != nil {
		return fmt.Errorf("%w: %w", ErrCleanup, err)
	}
	return nil
}

func pathsOverlap(first, second string) bool {
	return pathContains(first, second) || pathContains(second, first)
}

func pathContains(base, target string) bool {
	relative, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}
