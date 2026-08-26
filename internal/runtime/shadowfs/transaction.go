// Package shadowfs implements Mirage's directory-backed shadow filesystem
// transaction and content-baseline conflict detection.
package shadowfs

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
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
	// ErrStateConflict means the real resource no longer has the content identity
	// from which the shadow transaction was derived.
	ErrStateConflict = errors.New("real resource state conflict")
	// ErrRevalidation means Mirage could not establish the real resource's
	// current state and therefore refused to commit.
	ErrRevalidation = errors.New("real resource revalidation failed")
	// ErrCleanup means Mirage could not remove transaction-owned filesystem state.
	ErrCleanup = errors.New("shadow cleanup failed")
)

// StateConflict reports a content-identity mismatch without exposing either
// version's contents.
type StateConflict struct {
	Resource         string
	ExpectedBaseline string
	ObservedCurrent  string
}

func (e *StateConflict) Error() string {
	return fmt.Sprintf("%s: %s expected %s, observed %s", ErrStateConflict, e.Resource, e.ExpectedBaseline, e.ObservedCurrent)
}

// Unwrap lets callers distinguish conflicts with errors.Is while retaining
// structured evidence through errors.As.
func (e *StateConflict) Unwrap() error {
	return ErrStateConflict
}

// RevalidationError reports uncertainty while establishing current real state.
// It is not a conflict because Mirage did not successfully observe a different
// resource identity.
type RevalidationError struct {
	Resource string
	Cause    error
}

func (e *RevalidationError) Error() string {
	return fmt.Sprintf("%s: %s: %v", ErrRevalidation, e.Resource, e.Cause)
}

// Unwrap preserves both the error category and the underlying filesystem cause.
func (e *RevalidationError) Unwrap() []error {
	return []error{ErrRevalidation, e.Cause}
}

// State is the authoritative lifecycle state of a shadow transaction.
type State uint8

const (
	StateActive State = iota + 1
	StateCommitted
	StateRejected
	StateConflicted
)

func (s State) String() string {
	switch s {
	case StateActive:
		return "ACTIVE"
	case StateCommitted:
		return "COMMITTED"
	case StateRejected:
		return "REJECTED"
	case StateConflicted:
		return "CONFLICTED"
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
	baseline        contentIdentity
	baselineMode    os.FileMode
	observeReal     func(string) (resourceObservation, error)
	state           State
}

type contentIdentity [sha256.Size]byte

type resourceObservation struct {
	identity string
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
		baseline:        identifyContent(contents),
		baselineMode:    mode,
		observeReal:     observeManagedResource,
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
// workspace. It prepares replacement bytes, revalidates the real content
// identity immediately before replacement, and then renames the prepared file
// into place. The hash check and rename are not an atomic compare-and-swap; see
// ARCHITECTURE.md for the residual external-writer race.
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

	preparedPath, err := prepareManagedFile(t.realWorkspace, contents, t.baselineMode.Perm())
	if err != nil {
		return fmt.Errorf("prepare committed %s: %w", managedFile, err)
	}

	if t.observeReal == nil {
		return errors.Join(
			&RevalidationError{Resource: managedFile, Cause: errors.New("real resource observer is unavailable")},
			removePreparedFile(preparedPath),
		)
	}
	current, err := t.observeReal(t.realWorkspace)
	if err != nil {
		return errors.Join(
			&RevalidationError{Resource: managedFile, Cause: err},
			removePreparedFile(preparedPath),
		)
	}
	if current.identity != t.baseline.String() {
		conflict := &StateConflict{
			Resource:         managedFile,
			ExpectedBaseline: t.baseline.String(),
			ObservedCurrent:  current.identity,
		}
		t.state = StateConflicted
		return errors.Join(
			conflict,
			removePreparedFile(preparedPath),
			t.removeShadowWorkspace(),
		)
	}

	if err := replaceRealManagedFile(preparedPath, t.realWorkspace); err != nil {
		return errors.Join(
			fmt.Errorf("apply committed %s: %w", managedFile, err),
			removePreparedFile(preparedPath),
		)
	}

	// Reality has changed at this point. Record that fact before attempting
	// cleanup so a cleanup failure cannot make the transaction appear uncommitted.
	t.state = StateCommitted
	if err := t.removeShadowWorkspace(); err != nil {
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
	if err := t.removeShadowWorkspace(); err != nil {
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
	return readManagedFileWithHook(workspace, nil)
}

func readManagedFileWithHook(workspace string, afterInitialInspection func()) (contents []byte, mode os.FileMode, returnErr error) {
	root, file, openedInfo, err := acquireManagedRegularFile(workspace, os.O_RDONLY, afterInitialInspection)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		returnErr = errors.Join(returnErr, closeManagedAcquisition(root, file))
	}()

	contents, err = io.ReadAll(file)
	if err != nil {
		return nil, 0, fmt.Errorf("read rooted %s: %w", managedFile, err)
	}
	afterReadInfo, err := file.Stat()
	if err != nil {
		return nil, 0, fmt.Errorf("reinspect opened %s: %w", managedFile, err)
	}
	if err := validateManagedCurrentEntry(root, openedInfo); err != nil {
		return nil, 0, err
	}
	if managedFileChangedDuringRead(openedInfo, afterReadInfo) {
		return nil, 0, fmt.Errorf("%w: %s changed during read", ErrUnsafeFile, managedFile)
	}
	return contents, openedInfo.Mode(), nil
}

func observeManagedResource(workspace string) (resourceObservation, error) {
	return observeManagedResourceWithHook(workspace, nil)
}

func observeManagedResourceWithHook(workspace string, afterInitialInspection func()) (observation resourceObservation, returnErr error) {
	root, err := os.OpenRoot(workspace)
	if err != nil {
		return resourceObservation{}, fmt.Errorf("open real workspace root: %w", err)
	}
	var file *os.File
	defer func() {
		returnErr = errors.Join(returnErr, closeManagedAcquisition(root, file))
	}()

	info, err := root.Lstat(managedFile)
	if errors.Is(err, os.ErrNotExist) {
		return resourceObservation{identity: "missing"}, nil
	}
	if err != nil {
		return resourceObservation{}, fmt.Errorf("inspect rooted %s: %w", managedFile, err)
	}
	if !info.Mode().IsRegular() {
		return resourceObservation{identity: "type:" + resourceType(info.Mode())}, nil
	}
	if afterInitialInspection != nil {
		afterInitialInspection()
	}

	file, err = root.Open(managedFile)
	if err != nil {
		current, currentErr := observeCurrentEntry(root)
		if currentErr == nil && current.identity != "regular" {
			return current, nil
		}
		return resourceObservation{}, errors.Join(fmt.Errorf("open rooted %s: %w", managedFile, err), currentErr)
	}
	openedInfo, err := file.Stat()
	if err != nil {
		return resourceObservation{}, fmt.Errorf("inspect opened %s: %w", managedFile, err)
	}
	current, err := observeCurrentEntry(root)
	if err != nil {
		return resourceObservation{}, err
	}
	if current.identity != "regular" {
		return current, nil
	}
	currentInfo, err := root.Lstat(managedFile)
	if err != nil {
		return resourceObservation{}, fmt.Errorf("reinspect rooted %s: %w", managedFile, err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(openedInfo, currentInfo) {
		return resourceObservation{}, fmt.Errorf("%s changed during object acquisition", managedFile)
	}
	contents, err := io.ReadAll(file)
	if err != nil {
		return resourceObservation{}, fmt.Errorf("read rooted %s: %w", managedFile, err)
	}
	afterReadInfo, err := file.Stat()
	if err != nil {
		return resourceObservation{}, fmt.Errorf("reinspect opened %s: %w", managedFile, err)
	}
	if managedFileChangedDuringRead(openedInfo, afterReadInfo) {
		return resourceObservation{}, fmt.Errorf("%s changed while Mirage was reading its current contents", managedFile)
	}

	current, err = observeCurrentEntry(root)
	if err != nil {
		return resourceObservation{}, err
	}
	if current.identity != "regular" {
		return current, nil
	}
	currentInfo, err = root.Lstat(managedFile)
	if err != nil {
		return resourceObservation{}, fmt.Errorf("reinspect rooted %s: %w", managedFile, err)
	}
	if !os.SameFile(openedInfo, currentInfo) {
		return resourceObservation{}, fmt.Errorf("%s changed while Mirage was establishing its current identity", managedFile)
	}
	return resourceObservation{identity: identifyContent(contents).String()}, nil
}

func acquireManagedRegularFile(workspace string, flag int, afterInitialInspection func()) (*os.Root, *os.File, os.FileInfo, error) {
	root, err := os.OpenRoot(workspace)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open workspace root: %w", err)
	}
	fail := func(cause error, file *os.File) (*os.Root, *os.File, os.FileInfo, error) {
		return nil, nil, nil, errors.Join(cause, closeManagedAcquisition(root, file))
	}

	initialInfo, err := root.Lstat(managedFile)
	if err != nil {
		return fail(fmt.Errorf("inspect rooted %s: %w", managedFile, err), nil)
	}
	if !initialInfo.Mode().IsRegular() {
		return fail(fmt.Errorf("%w: %s has type %s", ErrUnsafeFile, managedFile, initialInfo.Mode().Type()), nil)
	}
	if afterInitialInspection != nil {
		afterInitialInspection()
	}

	file, err := root.OpenFile(managedFile, flag, 0)
	if err != nil {
		if currentInfo, currentErr := root.Lstat(managedFile); currentErr == nil && !currentInfo.Mode().IsRegular() {
			return fail(fmt.Errorf("%w: %s has type %s", ErrUnsafeFile, managedFile, currentInfo.Mode().Type()), nil)
		}
		return fail(fmt.Errorf("open rooted %s: %w", managedFile, err), nil)
	}
	openedInfo, err := file.Stat()
	if err != nil {
		return fail(fmt.Errorf("inspect opened %s: %w", managedFile, err), file)
	}
	if !openedInfo.Mode().IsRegular() {
		return fail(fmt.Errorf("%w: opened %s has type %s", ErrUnsafeFile, managedFile, openedInfo.Mode().Type()), file)
	}
	if err := validateManagedCurrentEntry(root, openedInfo); err != nil {
		return fail(err, file)
	}
	return root, file, openedInfo, nil
}

func validateManagedCurrentEntry(root *os.Root, openedInfo os.FileInfo) error {
	currentInfo, err := root.Lstat(managedFile)
	if err != nil {
		return fmt.Errorf("reinspect rooted %s: %w", managedFile, err)
	}
	if !currentInfo.Mode().IsRegular() {
		return fmt.Errorf("%w: %s has type %s", ErrUnsafeFile, managedFile, currentInfo.Mode().Type())
	}
	if !os.SameFile(openedInfo, currentInfo) {
		return fmt.Errorf("%w: %s changed during object acquisition", ErrUnsafeFile, managedFile)
	}
	return nil
}

func observeCurrentEntry(root *os.Root) (resourceObservation, error) {
	info, err := root.Lstat(managedFile)
	if errors.Is(err, os.ErrNotExist) {
		return resourceObservation{identity: "missing"}, nil
	}
	if err != nil {
		return resourceObservation{}, fmt.Errorf("inspect rooted %s: %w", managedFile, err)
	}
	if !info.Mode().IsRegular() {
		return resourceObservation{identity: "type:" + resourceType(info.Mode())}, nil
	}
	return resourceObservation{identity: "regular"}, nil
}

func managedFileChangedDuringRead(before, after os.FileInfo) bool {
	return before.Size() != after.Size() ||
		before.Mode() != after.Mode() ||
		!before.ModTime().Equal(after.ModTime())
}

func closeManagedAcquisition(root *os.Root, file *os.File) error {
	var closeErr error
	if file != nil {
		closeErr = errors.Join(closeErr, file.Close())
	}
	if root != nil {
		closeErr = errors.Join(closeErr, root.Close())
	}
	return closeErr
}

func resourceType(mode os.FileMode) string {
	switch {
	case mode.IsDir():
		return "directory"
	case mode&os.ModeSymlink != 0:
		return "symlink"
	case mode&os.ModeNamedPipe != 0:
		return "named-pipe"
	case mode&os.ModeSocket != 0:
		return "socket"
	case mode&os.ModeDevice != 0:
		return "device"
	default:
		return "unsupported"
	}
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

func prepareManagedFile(workspace string, contents []byte, mode os.FileMode) (string, error) {
	prepared, err := os.CreateTemp(workspace, ".mirage-readme-")
	if err != nil {
		return "", err
	}
	preparedPath := prepared.Name()
	fail := func(cause error) (string, error) {
		_ = prepared.Close()
		return "", errors.Join(cause, removePreparedFile(preparedPath))
	}

	if err := prepared.Chmod(mode); err != nil {
		return fail(err)
	}
	if _, err := prepared.Write(contents); err != nil {
		return fail(err)
	}
	if err := prepared.Sync(); err != nil {
		return fail(err)
	}
	if err := prepared.Close(); err != nil {
		return "", errors.Join(err, removePreparedFile(preparedPath))
	}
	return preparedPath, nil
}

func replaceRealManagedFile(preparedPath, workspace string) error {
	return os.Rename(preparedPath, filepath.Join(workspace, managedFile))
}

func removePreparedFile(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: remove prepared commit file: %w", ErrCleanup, err)
	}
	return nil
}

func (t *Transaction) removeShadowWorkspace() error {
	if pathsOverlap(t.realWorkspace, t.shadowWorkspace) {
		return fmt.Errorf("%w: refusing to clean overlapping shadow workspace", ErrCleanup)
	}
	if err := os.RemoveAll(t.shadowWorkspace); err != nil {
		return fmt.Errorf("%w: remove shadow workspace: %w", ErrCleanup, err)
	}
	return nil
}

func identifyContent(contents []byte) contentIdentity {
	return sha256.Sum256(contents)
}

func (i contentIdentity) String() string {
	return fmt.Sprintf("sha256:%x", i[:])
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
