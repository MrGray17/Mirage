// Package workspace prepares a bounded disposable repository snapshot for the
// hostile runtime. The real repository is never mounted into the sandbox.
package workspace

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	runtimedocker "github.com/MrGray17/Mirage/internal/runtime/docker"
	"github.com/MrGray17/Mirage/internal/runtime/tree"
)

var (
	ErrInvalidSource = errors.New("invalid M4 source workspace")
	ErrUnsafeSource  = errors.New("unsafe M4 source resource")
	ErrUnsafeTemp    = errors.New("unsafe M4 temporary root")
	ErrCleanup       = errors.New("M4 disposable workspace cleanup failed")
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
	realBaseline  *tree.Snapshot
	baseline      *tree.Snapshot
	cleaned       bool
}

func Prepare(realWorkspace string) (*Disposable, error) {
	return prepareAtTempRoot(realWorkspace, os.TempDir())
}

func prepareAtTempRoot(realWorkspace, tempRoot string) (*Disposable, error) {
	real, err := resolveSource(realWorkspace)
	if err != nil {
		return nil, err
	}
	temporary, err := resolveTempRoot(tempRoot)
	if err != nil {
		return nil, err
	}
	if pathsOverlap(real, temporary) {
		return nil, fmt.Errorf(
			"%w: real workspace %q and temporary root %q overlap",
			ErrUnsafeTemp,
			real,
			temporary,
		)
	}
	source, err := tree.Scan(real, tree.ScanOptions{Exclude: excludedSourceResource})
	if err != nil {
		return nil, fmt.Errorf("%w: bounded source snapshot: %w", ErrInvalidSource, err)
	}
	if err := tree.ValidateBaseline(source); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsafeSource, err)
	}
	token, err := randomToken()
	if err != nil {
		return nil, fmt.Errorf("create disposable workspace token: %w", err)
	}

	outer, err := os.MkdirTemp(temporary, "mirage-m42-")
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
	if err := materializeSnapshot(inner, source); err != nil {
		return fail(fmt.Errorf("populate disposable workspace: %w", err))
	}
	if err := writeExclusive(filepath.Join(inner, runtimedocker.DisposableMarker), []byte(token), 0o444); err != nil {
		return fail(fmt.Errorf("mark disposable workspace: %w", err))
	}
	baseline, err := tree.Scan(inner, tree.ScanOptions{})
	if err != nil {
		return fail(fmt.Errorf("capture disposable baseline: %w", err))
	}
	if err := tree.ValidateBaseline(baseline); err != nil {
		return fail(fmt.Errorf("validate disposable baseline: %w", err))
	}

	return &Disposable{
		realWorkspace: real,
		outer:         filepath.Clean(outer),
		workspace:     filepath.Clean(inner),
		token:         token,
		realBaseline:  source,
		baseline:      baseline,
	}, nil
}

// Binding is immutable workspace authority created before hostile execution.
// It retains real and disposable baselines as distinct security objects.
type Binding struct {
	realWorkspace       string
	disposableWorkspace string
	token               string
	realBaseline        *tree.Snapshot
	disposableBaseline  *tree.Snapshot
	identity            string
}

// Binding returns one immutable subject for later manifest construction.
func (d *Disposable) Binding() (Binding, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cleaned || d.realBaseline == nil || d.baseline == nil {
		return Binding{}, fmt.Errorf("%w: disposable workspace is unavailable", ErrInvalidSource)
	}
	canonical := struct {
		RealWorkspace       string `json:"real_workspace"`
		RealBaseline        string `json:"real_baseline"`
		DisposableWorkspace string `json:"disposable_workspace"`
		DisposableBaseline  string `json:"disposable_baseline"`
		TokenHash           string `json:"token_hash"`
	}{
		RealWorkspace:       d.realWorkspace,
		RealBaseline:        d.realBaseline.Identity(),
		DisposableWorkspace: d.workspace,
		DisposableBaseline:  d.baseline.Identity(),
		TokenHash:           hashString(d.token),
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return Binding{}, fmt.Errorf("canonicalize workspace binding: %w", err)
	}
	return Binding{
		realWorkspace:       d.realWorkspace,
		disposableWorkspace: d.workspace,
		token:               d.token,
		realBaseline:        d.realBaseline,
		disposableBaseline:  d.baseline,
		identity:            hashBytes(encoded),
	}, nil
}

func (b Binding) Identity() string                   { return b.identity }
func (b Binding) RealWorkspace() string              { return b.realWorkspace }
func (b Binding) DisposableWorkspace() string        { return b.disposableWorkspace }
func (b Binding) Token() string                      { return b.token }
func (b Binding) RealBaseline() *tree.Snapshot       { return b.realBaseline }
func (b Binding) DisposableBaseline() *tree.Snapshot { return b.disposableBaseline }

// ObserveReal applies the exact source inclusion rules used to capture the
// real baseline. Excluded host metadata never becomes part of commit freshness.
func (b Binding) ObserveReal() (*tree.Snapshot, error) {
	if b.identity == "" || b.realWorkspace == "" {
		return nil, fmt.Errorf("%w: workspace binding is invalid", ErrInvalidSource)
	}
	return tree.Scan(b.realWorkspace, tree.ScanOptions{Exclude: excludedSourceResource})
}

func (b Binding) ObserveDisposable() (*tree.Snapshot, error) {
	if b.identity == "" || b.disposableWorkspace == "" {
		return nil, fmt.Errorf("%w: workspace binding is invalid", ErrInvalidSource)
	}
	return tree.Scan(b.disposableWorkspace, tree.ScanOptions{})
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

// Baseline returns the immutable identity and contents of the exact physical
// tree presented to the sandbox, including Mirage's tamper-evident marker.
func (d *Disposable) Baseline() *tree.Snapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.baseline
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
	resolved, err := physicalPath(absolute)
	if err != nil {
		return "", fmt.Errorf("%w: resolve physical path: %w", ErrInvalidSource, err)
	}
	resolved = filepath.Clean(resolved)
	info, err = os.Lstat(resolved)
	if err != nil {
		return "", fmt.Errorf("%w: inspect physical path: %w", ErrInvalidSource, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("%w: physical path is not a directory", ErrInvalidSource)
	}
	return resolved, nil
}

func resolveTempRoot(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("%w: path is empty", ErrUnsafeTemp)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("%w: resolve path: %w", ErrUnsafeTemp, err)
	}
	resolved, err := physicalPath(filepath.Clean(absolute))
	if err != nil {
		return "", fmt.Errorf("%w: resolve physical path: %w", ErrUnsafeTemp, err)
	}
	resolved = filepath.Clean(resolved)
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", fmt.Errorf("%w: inspect physical path: %w", ErrUnsafeTemp, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("%w: physical path is not a directory", ErrUnsafeTemp)
	}
	return resolved, nil
}

func materializeSnapshot(workspace string, snapshot *tree.Snapshot) error {
	for _, entry := range snapshot.Entries() {
		relative := strings.TrimPrefix(entry.Resource, "/workspace/")
		if relative == entry.Resource || relative == "" {
			return fmt.Errorf("%w: non-workspace resource %q", ErrUnsafeSource, entry.Resource)
		}
		target := filepath.Join(workspace, filepath.FromSlash(relative))
		switch entry.Kind {
		case tree.KindDirectory:
			if err := os.Mkdir(target, 0o777); err != nil {
				return fmt.Errorf("create directory %s: %w", entry.Resource, err)
			}
			if err := os.Chmod(target, 0o777); err != nil {
				return fmt.Errorf("make directory writable %s: %w", entry.Resource, err)
			}
		case tree.KindFile:
			mode := os.FileMode(0o666)
			if entry.Mode&0o111 != 0 {
				mode = 0o777
			}
			if err := writeExclusive(target, entry.Content(), mode); err != nil {
				return fmt.Errorf("create file %s: %w", entry.Resource, err)
			}
		default:
			return fmt.Errorf("%w: cannot materialize %s object %s", ErrUnsafeSource, entry.Kind, entry.Resource)
		}
	}
	return nil
}

func excludedSourceResource(resource string, _ tree.Kind) bool {
	relative := strings.TrimPrefix(resource, "/workspace/")
	parts := strings.Split(relative, "/")
	if len(parts) == 0 {
		return false
	}
	top := parts[0]
	if top == ".git" || top == ".ssh" || top == ".aws" || top == ".azure" || top == ".git-credentials" || top == ".npmrc" || top == ".pypirc" || top == runtimedocker.DisposableMarker {
		return true
	}
	if len(parts) >= 2 && top == ".config" && parts[1] == "gcloud" {
		return true
	}
	base := path.Base(relative)
	return base == ".env" || strings.HasPrefix(base, ".env.")
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

func hashString(value string) string { return hashBytes([]byte(value)) }

func hashBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return fmt.Sprintf("sha256:%x", digest)
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
