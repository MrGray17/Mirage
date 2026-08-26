// Package shadowfs implements Mirage's directory-backed shadow filesystem
// transaction for Milestone 1.
package shadowfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const managedFile = "README.md"

var (
	// ErrInvalidWorkspace means the real workspace cannot safely be used as the
	// source of a shadow transaction.
	ErrInvalidWorkspace = errors.New("invalid real workspace")
	// ErrUnsafeFile means a managed file is not a regular file. Symlinks are
	// deliberately rejected because following them could cross the workspace
	// boundary.
	ErrUnsafeFile = errors.New("unsafe managed file")
	// ErrInvalidTransition means an operation is not valid in the transaction's
	// current state.
	ErrInvalidTransition = errors.New("invalid shadow transaction transition")
	// ErrCleanup means the transaction reached its intended terminal state, but
	// Mirage could not remove the transaction-owned shadow directory.
	ErrCleanup = errors.New("shadow cleanup failed")
)

// State is the authoritative lifecycle state of an M1 shadow transaction.
type State uint8

const (
	StateActive State = iota + 1
	StateCommitted
	StateRejected
)

func (s State) String() string {
	switch s {
	case StateActive:
		return "ACTIVE"
	case StateCommitted:
		return "COMMITTED"
	case StateRejected:
		return "REJECTED"
	default:
		return "UNKNOWN"
	}
}

// Transaction owns one disposable shadow workspace derived from a real
// workspace. The real workspace can be changed only by ApplyCommit.
type Transaction struct {
	mu              sync.Mutex
	realWorkspace   string
	shadowWorkspace string
	state           State
}

// Begin creates a private shadow workspace containing a copy of README.md.
// The real workspace is a trusted control-plane input in M1 and the managed
// file must be a regular file, never a symlink.
func Begin(realWorkspace string) (*Transaction, error) {
	resolvedReal, err := resolveRealWorkspace(realWorkspace)
	if err != nil {
		return nil, err
	}

	contents, mode, err := readManagedFile(resolvedReal)
	if err != nil {
		return nil, fmt.Errorf("%w: prepare %s: %w", ErrInvalidWorkspace, managedFile, err)
	}

	shadow, err := os.MkdirTemp("", "mirage-shadow-")
	if err != nil {
		return nil, fmt.Errorf("create shadow workspace: %w", err)
	}

	cleanupOnFailure := func(cause error) (*Transaction, error) {
		if cleanupErr := os.RemoveAll(shadow); cleanupErr != nil {
			return nil, errors.Join(cause, fmt.Errorf("%w: remove incomplete shadow workspace: %w", ErrCleanup, cleanupErr))
		}
		return nil, cause
	}

	resolvedShadow, err := filepath.Abs(shadow)
	if err != nil {
		return cleanupOnFailure(fmt.Errorf("make shadow workspace absolute: %w", err))
	}
	resolvedShadow = filepath.Clean(resolvedShadow)
	if pathsOverlap(resolvedReal, resolvedShadow) {
		return cleanupOnFailure(fmt.Errorf("%w: real and shadow workspaces overlap", ErrInvalidWorkspace))
	}

	shadowFile := filepath.Join(resolvedShadow, managedFile)
	if err := writeNewFile(shadowFile, contents, mode.Perm()); err != nil {
		return cleanupOnFailure(fmt.Errorf("populate shadow %s: %w", managedFile, err))
	}

	return &Transaction{
		realWorkspace:   resolvedReal,
		shadowWorkspace: resolvedShadow,
		state:           StateActive,
	}, nil
}

// ShadowWorkspace returns the absolute path owned by this transaction. Agent
// code may mutate this directory; it must never receive the real workspace as
// its writable working directory.
func (t *Transaction) ShadowWorkspace() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.shadowWorkspace
}

// State returns the transaction's current authoritative lifecycle state.
func (t *Transaction) State() State {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}

// ApplyCommit is the only operation in this package that changes the real
// workspace. It validates both managed files, prepares replacement bytes in
// the real directory, and then renames the prepared file into place.
func (t *Transaction) ApplyCommit() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.state != StateActive {
		return fmt.Errorf("%w: cannot commit transaction in state %s", ErrInvalidTransition, t.state)
	}

	contents, _, err := readManagedFile(t.shadowWorkspace)
	if err != nil {
		return fmt.Errorf("validate shadow %s before commit: %w", managedFile, err)
	}
	_, realMode, err := readManagedFile(t.realWorkspace)
	if err != nil {
		return fmt.Errorf("validate real %s before commit: %w", managedFile, err)
	}

	if err := replaceManagedFile(t.realWorkspace, contents, realMode.Perm()); err != nil {
		return fmt.Errorf("apply committed %s: %w", managedFile, err)
	}

	// Reality has changed at this point. Record that fact before attempting
	// cleanup so a cleanup failure cannot make the transaction appear uncommitted.
	t.state = StateCommitted
	if err := os.RemoveAll(t.shadowWorkspace); err != nil {
		return fmt.Errorf("%w: transaction committed but shadow remains: %w", ErrCleanup, err)
	}
	return nil
}

// Reject destroys only this transaction's shadow workspace. It never writes
// to the real workspace.
func (t *Transaction) Reject() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.state != StateActive {
		return fmt.Errorf("%w: cannot reject transaction in state %s", ErrInvalidTransition, t.state)
	}
	if pathsOverlap(t.realWorkspace, t.shadowWorkspace) {
		return fmt.Errorf("%w: refusing to clean overlapping shadow workspace", ErrCleanup)
	}
	if err := os.RemoveAll(t.shadowWorkspace); err != nil {
		return fmt.Errorf("%w: remove rejected shadow workspace: %w", ErrCleanup, err)
	}
	t.state = StateRejected
	return nil
}

func resolveRealWorkspace(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("%w: path is empty", ErrInvalidWorkspace)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("%w: make path absolute: %w", ErrInvalidWorkspace, err)
	}
	cleaned := filepath.Clean(absolute)
	info, err := os.Stat(cleaned)
	if err != nil {
		return "", fmt.Errorf("%w: inspect path: %w", ErrInvalidWorkspace, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%w: path is not a directory", ErrInvalidWorkspace)
	}
	return cleaned, nil
}

func readManagedFile(workspace string) ([]byte, os.FileMode, error) {
	path := filepath.Join(workspace, managedFile)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, 0, fmt.Errorf("inspect %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("%w: %s has type %s", ErrUnsafeFile, path, info.Mode().Type())
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("read %s: %w", path, err)
	}
	return contents, info.Mode(), nil
}

func writeNewFile(path string, contents []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func replaceManagedFile(workspace string, contents []byte, mode os.FileMode) (returnErr error) {
	prepared, err := os.CreateTemp(workspace, ".mirage-readme-")
	if err != nil {
		return err
	}
	preparedPath := prepared.Name()
	defer func() {
		if err := os.Remove(preparedPath); err != nil && !errors.Is(err, os.ErrNotExist) && returnErr == nil {
			returnErr = fmt.Errorf("remove prepared commit file: %w", err)
		}
	}()

	if err := prepared.Chmod(mode); err != nil {
		_ = prepared.Close()
		return err
	}
	if _, err := prepared.Write(contents); err != nil {
		_ = prepared.Close()
		return err
	}
	if err := prepared.Sync(); err != nil {
		_ = prepared.Close()
		return err
	}
	if err := prepared.Close(); err != nil {
		return err
	}
	return os.Rename(preparedPath, filepath.Join(workspace, managedFile))
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
