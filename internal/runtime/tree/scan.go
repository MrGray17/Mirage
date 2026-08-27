package tree

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/MrGray17/Mirage/internal/limits"
)

const workspaceResourcePrefix = "/workspace/"

// ScanOptions permits a trusted caller to exclude a complete source subtree.
// Exclusion is intended for snapshot preparation, not final reconciliation.
type ScanOptions struct {
	Exclude func(resource string, kind Kind) bool
}

type fileIdentity struct {
	resource string
	info     os.FileInfo
}

type scanner struct {
	root           *os.Root
	options        ScanOptions
	entries        []Entry
	totalBytes     int64
	enumerated     int
	caseResources  map[string]string
	regularObjects []fileIdentity
}

// Scan creates a deterministic, bounded snapshot of rootPath. Regular files
// are acquired through an os.Root-bound handle and checked again after the
// read. Symlinks and unsupported objects are described but never opened as
// content, allowing the trusted reconciler to reject them deterministically.
func Scan(rootPath string, options ScanOptions) (_ *Snapshot, returnErr error) {
	absolute, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, fmt.Errorf("%w: absolute path: %v", ErrInvalidRoot, err)
	}
	rootInfo, err := os.Lstat(absolute)
	if err != nil {
		return nil, fmt.Errorf("%w: lstat: %v", ErrInvalidRoot, err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: root must be a directory", ErrInvalidRoot)
	}

	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, fmt.Errorf("%w: open root: %v", ErrInvalidRoot, err)
	}
	defer func() {
		if closeErr := root.Close(); returnErr == nil && closeErr != nil {
			returnErr = fmt.Errorf("%w: close root: %v", ErrInvalidRoot, closeErr)
		}
	}()
	boundRootInfo, err := root.Lstat(".")
	if err != nil || !boundRootInfo.IsDir() || !os.SameFile(rootInfo, boundRootInfo) {
		return nil, fmt.Errorf("%w: root changed during acquisition", ErrTreeChanged)
	}

	s := &scanner{
		root:          root,
		options:       options,
		caseResources: make(map[string]string),
	}
	if err := s.scanDirectory(".", 0); err != nil {
		return nil, err
	}
	afterBound, boundErr := root.Lstat(".")
	afterHost, hostErr := os.Lstat(absolute)
	if boundErr != nil || hostErr != nil || !stableObject(boundRootInfo, afterBound) || !os.SameFile(boundRootInfo, afterHost) || !afterHost.IsDir() {
		return nil, fmt.Errorf("%w: root changed during scan", ErrTreeChanged)
	}
	return newSnapshotWithRoot(s.entries, uint32(boundRootInfo.Mode().Perm()))
}

func (s *scanner) scanDirectory(relative string, depth int) error {
	if depth > limits.MaxTreeDepth {
		return fmt.Errorf("%w: depth exceeds %d", ErrTreeBudget, limits.MaxTreeDepth)
	}

	initial, err := s.root.Lstat(relative)
	if err != nil {
		return fmt.Errorf("%w: lstat directory %q: %v", ErrTreeChanged, relative, err)
	}
	if !initial.IsDir() || initial.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: directory %q changed type", ErrTreeChanged, relative)
	}
	directory, err := s.root.Open(relative)
	if err != nil {
		return fmt.Errorf("%w: open directory %q: %v", ErrTreeChanged, relative, err)
	}
	opened, err := directory.Stat()
	if err != nil || !opened.IsDir() || !os.SameFile(initial, opened) {
		_ = directory.Close()
		return fmt.Errorf("%w: directory %q acquisition changed", ErrTreeChanged, relative)
	}

	var names []string
	for {
		batch, readErr := directory.ReadDir(128)
		for _, candidate := range batch {
			s.enumerated++
			if s.enumerated > limits.MaxTreeEntries {
				_ = directory.Close()
				return fmt.Errorf("%w: entries exceed %d", ErrTreeBudget, limits.MaxTreeEntries)
			}
			names = append(names, candidate.Name())
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = directory.Close()
			return fmt.Errorf("%w: read directory %q: %v", ErrTreeChanged, relative, readErr)
		}
	}
	after, statErr := directory.Stat()
	current, lstatErr := s.root.Lstat(relative)
	closeErr := directory.Close()
	if statErr != nil || lstatErr != nil || closeErr != nil || !stableObject(opened, after) || !os.SameFile(opened, current) || !current.IsDir() {
		return fmt.Errorf("%w: directory %q changed during enumeration", ErrTreeChanged, relative)
	}

	sort.Strings(names)
	for _, name := range names {
		child, resource, err := canonicalChild(relative, name)
		if err != nil {
			return err
		}
		info, err := s.root.Lstat(child)
		if err != nil {
			return fmt.Errorf("%w: lstat %q: %v", ErrTreeChanged, resource, err)
		}
		kind := classify(info.Mode())
		if s.options.Exclude != nil && s.options.Exclude(resource, kind) {
			continue
		}
		if err := s.claimResource(resource); err != nil {
			return err
		}

		switch kind {
		case KindDirectory:
			s.entries = append(s.entries, Entry{Resource: resource, Kind: kind, Mode: uint32(info.Mode().Perm())})
			if err := s.scanDirectory(child, depth+1); err != nil {
				return err
			}
		case KindFile:
			entry, err := s.readRegular(child, resource, info)
			if err != nil {
				return err
			}
			s.entries = append(s.entries, entry)
		case KindSymlink:
			s.entries = append(s.entries, Entry{Resource: resource, Kind: kind, Mode: uint32(info.Mode().Perm())})
		default:
			s.entries = append(s.entries, Entry{Resource: resource, Kind: KindUnsupported, Mode: uint32(info.Mode())})
		}
	}
	return nil
}

func (s *scanner) claimResource(resource string) error {
	if len(s.entries) >= limits.MaxTreeEntries {
		return fmt.Errorf("%w: entries exceed %d", ErrTreeBudget, limits.MaxTreeEntries)
	}
	folded := strings.ToLower(resource)
	if previous, exists := s.caseResources[folded]; exists && previous != resource {
		return fmt.Errorf("%w: case-fold collision between %q and %q", ErrUnsafePath, previous, resource)
	}
	s.caseResources[folded] = resource
	return nil
}

func (s *scanner) readRegular(relative, resource string, initial os.FileInfo) (Entry, error) {
	if initial.Size() < 0 || initial.Size() > limits.MaxTreeFileBytes {
		return Entry{}, fmt.Errorf("%w: %q exceeds per-file limit", ErrTreeBudget, resource)
	}
	file, err := s.root.Open(relative)
	if err != nil {
		return Entry{}, fmt.Errorf("%w: open %q: %v", ErrTreeChanged, resource, err)
	}
	fail := func(cause error) (Entry, error) {
		_ = file.Close()
		return Entry{}, cause
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(initial, opened) {
		return fail(fmt.Errorf("%w: file %q acquisition changed", ErrTreeChanged, resource))
	}
	current, err := s.root.Lstat(relative)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return fail(fmt.Errorf("%w: file %q path changed", ErrTreeChanged, resource))
	}
	multipleLinks, err := hasMultipleLinks(opened)
	if err != nil {
		return fail(fmt.Errorf("%w: inspect hard links for %q: %v", ErrTreeChanged, resource, err))
	}
	if multipleLinks {
		if err := file.Close(); err != nil {
			return Entry{}, fmt.Errorf("%w: close hard-linked file %q: %v", ErrTreeChanged, resource, err)
		}
		current, err := s.root.Lstat(relative)
		if err != nil || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
			return Entry{}, fmt.Errorf("%w: hard-linked file %q changed during acquisition", ErrTreeChanged, resource)
		}
		return Entry{Resource: resource, Kind: KindHardlink, Mode: uint32(opened.Mode().Perm()), Size: opened.Size()}, nil
	}
	for _, seen := range s.regularObjects {
		if os.SameFile(opened, seen.info) {
			if err := file.Close(); err != nil {
				return Entry{}, fmt.Errorf("%w: close hard link %q: %v", ErrTreeChanged, resource, err)
			}
			current, err := s.root.Lstat(relative)
			if err != nil || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
				return Entry{}, fmt.Errorf("%w: hard link %q changed during acquisition", ErrTreeChanged, resource)
			}
			return Entry{Resource: resource, Kind: KindHardlink, Mode: uint32(opened.Mode().Perm()), Size: opened.Size(), LinkTarget: seen.resource}, nil
		}
	}

	contents, err := io.ReadAll(io.LimitReader(file, limits.MaxTreeFileBytes+1))
	if err != nil {
		return fail(fmt.Errorf("%w: read %q: %v", ErrTreeChanged, resource, err))
	}
	if int64(len(contents)) > limits.MaxTreeFileBytes {
		return fail(fmt.Errorf("%w: %q exceeds per-file limit", ErrTreeBudget, resource))
	}
	after, statErr := file.Stat()
	current, lstatErr := s.root.Lstat(relative)
	closeErr := file.Close()
	if statErr != nil || lstatErr != nil || closeErr != nil || !stableObject(opened, after) || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return Entry{}, fmt.Errorf("%w: file %q changed during read", ErrTreeChanged, resource)
	}
	if after.Size() != int64(len(contents)) {
		return Entry{}, fmt.Errorf("%w: file %q size changed during read", ErrTreeChanged, resource)
	}
	if s.totalBytes > limits.MaxTreeTotalBytes-int64(len(contents)) {
		return Entry{}, fmt.Errorf("%w: total bytes exceed %d", ErrTreeBudget, limits.MaxTreeTotalBytes)
	}
	s.totalBytes += int64(len(contents))
	digest := sha256.Sum256(contents)
	s.regularObjects = append(s.regularObjects, fileIdentity{resource: resource, info: opened})
	return Entry{
		Resource: resource,
		Kind:     KindFile,
		Mode:     uint32(opened.Mode().Perm()),
		Size:     int64(len(contents)),
		Digest:   fmt.Sprintf("sha256:%x", digest),
		content:  contents,
	}, nil
}

func canonicalChild(parent, name string) (string, string, error) {
	if name == "" || name == "." || name == ".." || !utf8.ValidString(name) || strings.ContainsAny(name, "\\/") {
		return "", "", fmt.Errorf("%w: invalid name %q", ErrUnsafePath, name)
	}
	relative := name
	if parent != "." {
		relative = path.Join(filepath.ToSlash(parent), name)
	}
	resource := workspaceResourcePrefix + relative
	if len(resource) > limits.MaxResourceIdentifierBytes {
		return "", "", fmt.Errorf("%w: resource exceeds %d bytes", ErrUnsafePath, limits.MaxResourceIdentifierBytes)
	}
	return filepath.FromSlash(relative), resource, nil
}

func classify(mode os.FileMode) Kind {
	switch {
	case mode.IsRegular():
		return KindFile
	case mode.IsDir():
		return KindDirectory
	case mode&os.ModeSymlink != 0:
		return KindSymlink
	default:
		return KindUnsupported
	}
}

func stableObject(before, after os.FileInfo) bool {
	return before != nil && after != nil && os.SameFile(before, after) && before.Size() == after.Size() && before.Mode() == after.Mode() && before.ModTime().Equal(after.ModTime())
}

// ValidateBaseline requires a materializable snapshot: only independent
// regular files and directories are accepted.
func ValidateBaseline(snapshot *Snapshot) error {
	if snapshot == nil || snapshot.identity == "" {
		return ErrInvalidSnapshot
	}
	for _, entry := range snapshot.entries {
		if entry.Kind != KindFile && entry.Kind != KindDirectory {
			return fmt.Errorf("%w: %s is %s", ErrUnsafeBaseline, entry.Resource, entry.Kind)
		}
	}
	return nil
}
