package gitcommit

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1" // Git SHA-1 object format is explicitly bound by M5.1.
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const (
	maxObjectPayloadBytes = 64 << 20
	maxTransactionBytes   = 80 << 20
	transactionPrefix     = ".mirage-m52-"
)

type objectRecord struct {
	kind string
	oid  string
	data []byte
}

type transaction struct {
	mu          sync.Mutex
	root        string
	objects     string
	tempRoot    string
	realRoot    string
	rootInfo    os.FileInfo
	objectsInfo os.FileInfo
	written     int64
	cleaned     bool
}

func newTransaction(realRoot string) (*transaction, error) {
	tempRoot, err := filepath.Abs(os.TempDir())
	if err != nil {
		return nil, fmt.Errorf("%w: resolve temporary root: %v", ErrTransaction, err)
	}
	tempRoot, err = filepath.EvalSymlinks(filepath.Clean(tempRoot))
	if err != nil {
		return nil, fmt.Errorf("%w: resolve physical temporary root: %v", ErrTransaction, err)
	}
	realRoot, err = filepath.Abs(realRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve real repository: %v", ErrTransaction, err)
	}
	realRoot = filepath.Clean(realRoot)
	root, err := os.MkdirTemp(tempRoot, transactionPrefix)
	if err != nil {
		return nil, fmt.Errorf("%w: create protected transaction root: %v", ErrTransaction, err)
	}
	fail := func(cause error) (*transaction, error) {
		cleanupErr := os.RemoveAll(root)
		if cleanupErr != nil {
			return nil, errors.Join(cause, fmt.Errorf("%w: remove incomplete transaction: %v", ErrCleanup, cleanupErr))
		}
		return nil, cause
	}
	if pathsOverlap(root, realRoot) {
		return fail(fmt.Errorf("%w: transaction and real repository roots overlap", ErrTransaction))
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return fail(fmt.Errorf("%w: protect transaction root: %v", ErrTransaction, err))
	}
	objects := filepath.Join(root, "objects")
	if err := os.Mkdir(objects, 0o700); err != nil {
		return fail(fmt.Errorf("%w: create transaction object store: %v", ErrTransaction, err))
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return fail(fmt.Errorf("%w: transaction root acquisition failed", ErrTransaction))
	}
	objectsInfo, err := os.Lstat(objects)
	if err != nil || !objectsInfo.IsDir() || objectsInfo.Mode()&os.ModeSymlink != 0 {
		return fail(fmt.Errorf("%w: object store acquisition failed", ErrTransaction))
	}
	return &transaction{
		root: filepath.Clean(root), objects: filepath.Clean(objects), tempRoot: filepath.Clean(tempRoot),
		realRoot: realRoot, rootInfo: rootInfo, objectsInfo: objectsInfo,
	}, nil
}

func canonicalObject(kind string, data []byte) (string, []byte, error) {
	if kind != "blob" && kind != "tree" && kind != "commit" {
		return "", nil, fmt.Errorf("%w: unsupported object type %q", ErrObject, kind)
	}
	if len(data) > maxObjectPayloadBytes {
		return "", nil, fmt.Errorf("%w: %s object exceeds bounded payload", ErrObject, kind)
	}
	header := []byte(kind + " " + strconv.Itoa(len(data)) + "\x00")
	canonical := make([]byte, 0, len(header)+len(data))
	canonical = append(canonical, header...)
	canonical = append(canonical, data...)
	digest := sha1.Sum(canonical)
	return hex.EncodeToString(digest[:]), canonical, nil
}

func (t *transaction) writeObject(record objectRecord) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.revalidateLocked(); err != nil {
		return err
	}
	oid, canonical, err := canonicalObject(record.kind, record.data)
	if err != nil {
		return err
	}
	if oid != record.oid {
		return fmt.Errorf("%w: expected %s object %s, derived %s", ErrObject, record.kind, record.oid, oid)
	}
	var compressed bytes.Buffer
	writer := zlib.NewWriter(&compressed)
	if _, err := writer.Write(canonical); err != nil {
		_ = writer.Close()
		return fmt.Errorf("%w: compress %s object: %v", ErrObject, record.kind, err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("%w: finish %s object compression: %v", ErrObject, record.kind, err)
	}
	if t.written > maxTransactionBytes-int64(compressed.Len()) {
		return fmt.Errorf("%w: transaction object budget exceeded", ErrTransaction)
	}
	fanout := filepath.Join(t.objects, oid[:2])
	if err := os.Mkdir(fanout, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%w: create object fanout: %v", ErrTransaction, err)
	}
	fanoutInfo, err := os.Lstat(fanout)
	if err != nil || !fanoutInfo.IsDir() || fanoutInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: unsafe object fanout", ErrTransaction)
	}
	target := filepath.Join(fanout, oid[2:])
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("%w: create loose object: %v", ErrTransaction, err)
	}
	writeErr := error(nil)
	if _, err := file.Write(compressed.Bytes()); err != nil {
		writeErr = fmt.Errorf("write loose object: %w", err)
	}
	if err := file.Close(); err != nil {
		writeErr = errors.Join(writeErr, fmt.Errorf("close loose object: %w", err))
	}
	if writeErr != nil {
		removeErr := os.Remove(target)
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return errors.Join(fmt.Errorf("%w: %v", ErrTransaction, writeErr), fmt.Errorf("%w: remove incomplete object: %v", ErrCleanup, removeErr))
		}
		return fmt.Errorf("%w: %v", ErrTransaction, writeErr)
	}
	t.written += int64(compressed.Len())
	return nil
}

func (t *transaction) readObject(kind, oid string) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.revalidateLocked(); err != nil {
		return nil, err
	}
	if !validOID(oid) {
		return nil, fmt.Errorf("%w: invalid object ID", ErrObject)
	}
	target := filepath.Join(t.objects, oid[:2], oid[2:])
	initial, err := os.Lstat(target)
	if err != nil || !initial.Mode().IsRegular() || initial.Mode()&os.ModeSymlink != 0 || initial.Size() < 0 || initial.Size() > maxTransactionBytes {
		return nil, fmt.Errorf("%w: transaction object is unavailable or unsafe", ErrObject)
	}
	file, err := os.Open(target)
	if err != nil {
		return nil, fmt.Errorf("%w: open transaction object: %v", ErrObject, err)
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(initial, opened) {
		_ = file.Close()
		return nil, fmt.Errorf("%w: transaction object changed during acquisition", ErrObject)
	}
	compressed, readErr := io.ReadAll(io.LimitReader(file, maxTransactionBytes+1))
	fileErr := file.Close()
	final, statErr := os.Lstat(target)
	if readErr != nil || fileErr != nil || statErr != nil || !os.SameFile(opened, final) || initial.Size() != int64(len(compressed)) || final.Size() != initial.Size() || len(compressed) > maxTransactionBytes {
		return nil, fmt.Errorf("%w: bounded transaction object read failed", ErrObject)
	}
	compressedReader := bytes.NewReader(compressed)
	reader, err := zlib.NewReader(compressedReader)
	if err != nil {
		return nil, fmt.Errorf("%w: decompress transaction object: %v", ErrObject, err)
	}
	canonical, readErr := io.ReadAll(io.LimitReader(reader, maxObjectPayloadBytes+129))
	readerErr := reader.Close()
	if readErr != nil || readerErr != nil || compressedReader.Len() != 0 || len(canonical) > maxObjectPayloadBytes+128 {
		return nil, fmt.Errorf("%w: non-canonical or over-budget compressed object", ErrObject)
	}
	nul := bytes.IndexByte(canonical, 0)
	if nul <= 0 {
		return nil, fmt.Errorf("%w: malformed loose object header", ErrObject)
	}
	header := string(canonical[:nul])
	observedKind, sizeText, ok := strings.Cut(header, " ")
	size, sizeErr := strconv.Atoi(sizeText)
	data := canonical[nul+1:]
	if !ok || sizeErr != nil || observedKind != kind || size != len(data) || len(data) > maxObjectPayloadBytes {
		return nil, fmt.Errorf("%w: loose object type or size differs", ErrObject)
	}
	digest := sha1.Sum(canonical)
	if hex.EncodeToString(digest[:]) != oid {
		return nil, fmt.Errorf("%w: loose object identity differs", ErrObject)
	}
	return append([]byte(nil), data...), nil
}

func (t *transaction) revalidateLocked() error {
	if t == nil || t.cleaned || t.rootInfo == nil || t.objectsInfo == nil {
		return fmt.Errorf("%w: transaction is unavailable", ErrTransactionChanged)
	}
	rootInfo, rootErr := os.Lstat(t.root)
	objectsInfo, objectsErr := os.Lstat(t.objects)
	if rootErr != nil || objectsErr != nil || !rootInfo.IsDir() || !objectsInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || objectsInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(t.rootInfo, rootInfo) || !os.SameFile(t.objectsInfo, objectsInfo) {
		return fmt.Errorf("%w: transaction root or object store identity differs", ErrTransactionChanged)
	}
	return nil
}

func (t *transaction) verifyObjectSet(expected map[string]struct{}) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.revalidateLocked(); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(expected))
	err := filepath.WalkDir(t.root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(t.root, current)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in transaction object store")
		}
		parts := strings.Split(filepath.ToSlash(relative), "/")
		if entry.IsDir() {
			if len(parts) == 1 && parts[0] == "objects" {
				return nil
			}
			if len(parts) != 2 || parts[0] != "objects" || len(parts[1]) != 2 {
				return fmt.Errorf("unexpected transaction object directory")
			}
			return nil
		}
		if len(parts) != 3 || parts[0] != "objects" || len(parts[1]) != 2 || len(parts[2]) != 38 {
			return fmt.Errorf("unexpected transaction object file")
		}
		oid := parts[1] + parts[2]
		if !validOID(oid) {
			return fmt.Errorf("invalid transaction object path")
		}
		if _, ok := expected[oid]; !ok {
			return fmt.Errorf("unbound transaction object %s", oid)
		}
		seen[oid] = struct{}{}
		return nil
	})
	if err != nil {
		return fmt.Errorf("%w: verify exact object set: %v", ErrTransactionChanged, err)
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("%w: transaction object set is incomplete", ErrTransactionChanged)
	}
	return nil
}

func (t *transaction) cleanup() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t == nil || t.cleaned {
		return nil
	}
	if filepath.Base(t.root) == t.root || !strings.HasPrefix(filepath.Base(t.root), transactionPrefix) || pathsOverlap(t.root, t.realRoot) || !pathContains(t.tempRoot, t.root) {
		return fmt.Errorf("%w: refusing unsafe transaction cleanup target", ErrCleanup)
	}
	if err := t.revalidateLocked(); err != nil {
		return errors.Join(fmt.Errorf("%w: transaction identity uncertain", ErrCleanup), err)
	}
	if err := os.RemoveAll(t.root); err != nil {
		return fmt.Errorf("%w: remove transaction state: %v", ErrCleanup, err)
	}
	t.cleaned = true
	return nil
}

func validOID(value string) bool {
	if len(value) != 40 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func pathsOverlap(first, second string) bool {
	return pathContains(first, second) || pathContains(second, first)
}

func pathContains(base, target string) bool {
	relative, err := filepath.Rel(filepath.Clean(base), filepath.Clean(target))
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}
