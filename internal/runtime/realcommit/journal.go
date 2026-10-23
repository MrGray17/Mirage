package realcommit

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	journalVersion  = "mirage.commit-journal/v1"
	maxJournalBytes = 1 << 20
	maxJournalFiles = 4096
)

type JournalState string

const (
	JournalPrepared           JournalState = "PREPARED"
	JournalApplying           JournalState = "APPLYING"
	JournalCommitted          JournalState = "COMMITTED"
	JournalAborted             JournalState = "ABORTED"
	JournalAfterStateObserved JournalState = "AFTER_STATE_OBSERVED"
	JournalRecoveryRequired   JournalState = "RECOVERY_REQUIRED"
)

var (
	ErrJournalInvalid             = errors.New("invalid commit journal")
	ErrJournalBusy                = errors.New("commit journal is busy")
	ErrJournalDuplicate           = errors.New("commit transaction already has a journal record")
	ErrJournalCorrupt             = errors.New("commit journal record is corrupt")
	ErrJournalUnsupportedPlatform = errors.New("durable commit journal locking is unsupported on this platform")
	ErrJournalFull                = errors.New("commit journal record limit reached")
	ErrOutcomeUncertain           = errors.New("real commit outcome requires recovery")
)

type journalRecord struct {
	Version              string       `json:"version"`
	TransactionID        string       `json:"transaction_id"`
	PlanHash             string       `json:"plan_hash"`
	ManifestHash         string       `json:"manifest_hash"`
	AuthorityHash        string       `json:"authority_hash"`
	RealBaselineIdentity string       `json:"real_baseline_identity"`
	Workspace            string       `json:"workspace"`
	WorkspaceIdentity    string       `json:"workspace_identity"`
	Resource             string       `json:"resource"`
	BeforeDigest         string       `json:"before_digest"`
	AfterDigest          string       `json:"after_digest"`
	RealMode             uint32       `json:"real_mode"`
	State                JournalState `json:"state"`
	Outcome              string       `json:"outcome,omitempty"`
	Reason               string       `json:"reason,omitempty"`
	CreatedAt            string       `json:"created_at"`
	UpdatedAt            string       `json:"updated_at"`
	Checksum             string       `json:"checksum"`
}

type journalPayload struct {
	Version              string       `json:"version"`
	TransactionID        string       `json:"transaction_id"`
	PlanHash             string       `json:"plan_hash"`
	ManifestHash         string       `json:"manifest_hash"`
	AuthorityHash        string       `json:"authority_hash"`
	RealBaselineIdentity string       `json:"real_baseline_identity"`
	Workspace            string       `json:"workspace"`
	WorkspaceIdentity    string       `json:"workspace_identity"`
	Resource             string       `json:"resource"`
	BeforeDigest         string       `json:"before_digest"`
	AfterDigest          string       `json:"after_digest"`
	RealMode             uint32       `json:"real_mode"`
	State                JournalState `json:"state"`
	Outcome              string       `json:"outcome,omitempty"`
	Reason               string       `json:"reason,omitempty"`
	CreatedAt            string       `json:"created_at"`
	UpdatedAt            string       `json:"updated_at"`
}

type JournalStore struct {
	dir string
	now func() time.Time
	mu  sync.Mutex
}

type JournalTransaction struct {
	store    *JournalStore
	lockFile *os.File
	record   journalRecord
	closed   bool
}

type RecoveryResult struct {
	TransactionID string       `json:"transaction_id"`
	PlanHash      string       `json:"plan_hash"`
	Workspace     string       `json:"workspace"`
	Resource      string       `json:"resource"`
	PreviousState JournalState `json:"previous_state"`
	State         JournalState `json:"state"`
	Outcome       string       `json:"outcome"`
	Reason        string       `json:"reason,omitempty"`
}

func NewJournalStore(dir string) (*JournalStore, error) {
	if runtime.GOOS == "windows" {
		return nil, ErrJournalUnsupportedPlatform
	}
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("%w: journal directory is empty", ErrJournalInvalid)
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve journal directory: %v", ErrJournalInvalid, err)
	}
	if err := ensurePrivateDirectory(absolute); err != nil {
		return nil, fmt.Errorf("%w: prepare journal directory: %v", ErrJournalInvalid, err)
	}
	return &JournalStore{dir: filepath.Clean(absolute), now: time.Now}, nil
}

func DefaultJournalStore() (*JournalStore, error) {
	if runtime.GOOS == "windows" {
		return nil, ErrJournalUnsupportedPlatform
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("locate MIRAGE transaction state: %w", err)
	}
	appDir := filepath.Join(configDir, "mirage")
	if err := ensurePrivateDirectory(appDir); err != nil {
		return nil, fmt.Errorf("prepare MIRAGE transaction state: %w", err)
	}
	return NewJournalStore(filepath.Join(appDir, "transactions"))
}

func (s *JournalStore) Directory() string {
	if s == nil {
		return ""
	}
	return s.dir
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path is not a real directory")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	info, err = os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("directory permissions could not be restricted")
	}
	// Persist both the directory metadata and its name in the parent directory.
	// A journal must not claim durability while its containing directory entry
	// itself is still only in cache.
	if err := syncDirectory(path); err != nil {
		return fmt.Errorf("sync private directory: %w", err)
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("sync parent directory: %w", err)
	}
	return nil
}

func (s *JournalStore) Begin(plan *Plan) (*JournalTransaction, error) {
	if s == nil || plan == nil || plan.hash == "" {
		return nil, ErrInvalidPlan
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	lockFile, err := s.acquire()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		_ = unlockJournal(lockFile)
		_ = lockFile.Close()
		return nil, fmt.Errorf("%w: inspect journal capacity: %v", ErrJournalInvalid, err)
	}
	journalRecords := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			journalRecords++
		}
	}
	if journalRecords >= maxJournalFiles {
		_ = unlockJournal(lockFile)
		_ = lockFile.Close()
		return nil, fmt.Errorf("%w: found %d records; inspect and archive records before starting more journaled commits", ErrJournalFull, journalRecords)
	}

	recordPath := s.recordPath(plan.hash)
	if _, err := os.Lstat(recordPath); err == nil {
		_ = unlockJournal(lockFile)
		_ = lockFile.Close()
		return nil, ErrJournalDuplicate
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = unlockJournal(lockFile)
		_ = lockFile.Close()
		return nil, fmt.Errorf("%w: inspect existing record: %v", ErrJournalInvalid, err)
	}

	root, err := os.OpenRoot(plan.realWorkspace)
	if err != nil {
		_ = unlockJournal(lockFile)
		_ = lockFile.Close()
		return nil, fmt.Errorf("%w: open bound workspace: %v", ErrJournalInvalid, err)
	}
	if err := requireNamedWorkspace(root, plan.realWorkspace); err != nil {
		_ = root.Close()
		_ = unlockJournal(lockFile)
		_ = lockFile.Close()
		return nil, err
	}
	identity, identityErr := workspaceIdentity(root)
	closeErr := root.Close()
	if identityErr != nil || closeErr != nil {
		_ = unlockJournal(lockFile)
		_ = lockFile.Close()
		return nil, fmt.Errorf("%w: establish workspace identity: %v", ErrJournalInvalid, errors.Join(identityErr, closeErr))
	}

	now := s.now().UTC().Format(time.RFC3339Nano)
	record := journalRecord{
		Version: journalVersion, TransactionID: transactionID(plan.hash),
		PlanHash: plan.hash, ManifestHash: plan.manifestHash,
		AuthorityHash: plan.authorityHash, RealBaselineIdentity: plan.realBaselineIdentity,
		Workspace: plan.realWorkspace, WorkspaceIdentity: identity,
		Resource: plan.resource, BeforeDigest: plan.beforeDigest, AfterDigest: plan.afterDigest,
		RealMode: plan.realMode, State: JournalPrepared, Outcome: "PENDING",
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.writeRecord(record); err != nil {
		_ = unlockJournal(lockFile)
		_ = lockFile.Close()
		return nil, fmt.Errorf("%w: persist prepared record: %v", ErrJournalInvalid, err)
	}
	return &JournalTransaction{store: s, lockFile: lockFile, record: record}, nil
}

func (tx *JournalTransaction) State() JournalState {
	if tx == nil {
		return ""
	}
	return tx.record.State
}

func (tx *JournalTransaction) MarkApplying() error {
	return tx.transition(JournalApplying, "PENDING", "")
}

func (tx *JournalTransaction) MarkCommitted() error {
	return tx.transition(JournalCommitted, "COMMITTED", "")
}

func (tx *JournalTransaction) MarkAborted(reason string) error {
	if reason == "" {
		reason = "commit_not_applied"
	}
	return tx.transition(JournalAborted, "NOT_COMMITTED", reason)
}

func (tx *JournalTransaction) transition(state JournalState, outcome, reason string) error {
	if tx == nil || tx.closed || tx.store == nil {
		return ErrJournalInvalid
	}
	valid := false
	switch tx.record.State {
	case JournalPrepared:
		valid = state == JournalApplying || state == JournalAborted || state == JournalRecoveryRequired
	case JournalApplying:
		valid = state == JournalCommitted || state == JournalAborted || state == JournalAfterStateObserved || state == JournalRecoveryRequired
	case JournalRecoveryRequired:
		valid = state == JournalAborted || state == JournalAfterStateObserved || state == JournalRecoveryRequired
	}
	if !valid {
		return fmt.Errorf("%w: illegal state transition %s -> %s", ErrJournalInvalid, tx.record.State, state)
	}
	tx.record.State = state
	tx.record.Outcome = outcome
	tx.record.Reason = reason
	tx.record.UpdatedAt = tx.store.now().UTC().Format(time.RFC3339Nano)
	if err := tx.store.writeRecord(tx.record); err != nil {
		// The on-disk state may be either version after a failed directory sync.
		// Callers must not proceed when a journal transition is not durable.
		return fmt.Errorf("%w: persist state %s: %v", ErrJournalInvalid, state, err)
	}
	return nil
}

func (tx *JournalTransaction) Close() error {
	if tx == nil || tx.closed {
		return nil
	}
	tx.closed = true
	var result error
	if err := unlockJournal(tx.lockFile); err != nil {
		result = errors.Join(result, err)
	}
	if err := tx.lockFile.Close(); err != nil {
		result = errors.Join(result, err)
	}
	return result
}

func (s *JournalStore) RecoverPending() ([]RecoveryResult, error) {
	if s == nil {
		return nil, ErrJournalInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	lockFile, err := s.acquire()
	if err != nil {
		return nil, err
	}
	defer unlockAndClose(lockFile)

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("%w: list transaction records: %v", ErrJournalInvalid, err)
	}
	var names []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	if len(names) > maxJournalFiles {
		return nil, fmt.Errorf("%w: found %d journal records, limit is %d", ErrJournalInvalid, len(names), maxJournalFiles)
	}

	var results []RecoveryResult
	for _, name := range names {
		record, err := s.readRecord(filepath.Join(s.dir, name))
		if err != nil {
			return results, err
		}
		if record.State == JournalAfterStateObserved {
			results = append(results, RecoveryResult{
				TransactionID: record.TransactionID, PlanHash: record.PlanHash,
				Workspace: record.Workspace, Resource: record.Resource,
				PreviousState: record.State, State: record.State, Outcome: record.Outcome, Reason: record.Reason,
			})
			continue
		}
		if record.State != JournalPrepared && record.State != JournalApplying && record.State != JournalRecoveryRequired {
			continue
		}
		result := s.reconcileRecord(record)
		next := record
		next.State = result.State
		next.Outcome = result.Outcome
		next.Reason = result.Reason
		next.UpdatedAt = s.now().UTC().Format(time.RFC3339Nano)
		if err := s.writeRecord(next); err != nil {
			return results, fmt.Errorf("%w: persist recovery outcome for %s: %v", ErrJournalInvalid, record.TransactionID, err)
		}
		results = append(results, result)
	}
	return results, nil
}

func (s *JournalStore) reconcileRecord(record journalRecord) RecoveryResult {
	result := RecoveryResult{
		TransactionID: record.TransactionID, PlanHash: record.PlanHash,
		Workspace: record.Workspace, Resource: record.Resource,
		PreviousState: record.State, State: JournalRecoveryRequired,
		Outcome: "RECOVERY_REQUIRED", Reason: "current target could not be safely matched to the recorded transaction",
	}
	root, err := os.OpenRoot(record.Workspace)
	if err != nil {
		result.Reason = "workspace_unavailable"
		return result
	}
	defer root.Close()
	if err := requireNamedWorkspace(root, record.Workspace); err != nil {
		result.Reason = "workspace_identity_mismatch"
		return result
	}
	identity, err := workspaceIdentity(root)
	if err != nil || identity != record.WorkspaceIdentity {
		result.Reason = "workspace_identity_mismatch"
		return result
	}
	relative, err := canonicalRelative(record.Resource)
	if err != nil {
		result.Reason = "recorded_resource_is_invalid"
		return result
	}
	digest, mode, err := observeRegular(root, relative)
	if err != nil {
		result.Reason = "target_unavailable_or_unsupported"
		return result
	}
	if mode != record.RealMode {
		result.Reason = "target_mode_differs_from_recorded_mode"
		return result
	}
	if digest == record.BeforeDigest {
		result.State = JournalAborted
		result.Outcome = "NOT_COMMITTED"
		result.Reason = "the bound workspace target still matches the pre-commit digest"
		return result
	}
	if digest == record.AfterDigest && record.State == JournalApplying {
		result.State = JournalAfterStateObserved
		result.Outcome = "AFTER_STATE_OBSERVED_ATTRIBUTION_UNCERTAIN"
		result.Reason = "the planned after-state is present, but the journal cannot prove which process produced it"
		return result
	}
	result.Reason = "target_digest_does_not_match_a_recoverable_state"
	return result
}

func (s *JournalStore) acquire() (*os.File, error) {
	path := filepath.Join(s.dir, ".lock")
	info, statErr := os.Lstat(path)
	if statErr == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return nil, fmt.Errorf("%w: journal lock is not a regular file", ErrJournalInvalid)
	}
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: inspect journal lock: %v", ErrJournalInvalid, statErr)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: open journal lock: %v", ErrJournalInvalid, err)
	}
	opened, err := file.Stat()
	named, namedErr := os.Lstat(path)
	if err != nil || namedErr != nil || !opened.Mode().IsRegular() || !named.Mode().IsRegular() || named.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, named) {
		_ = file.Close()
		return nil, fmt.Errorf("%w: journal lock changed while opening", ErrJournalInvalid)
	}
	if err := lockJournal(file); err != nil {
		_ = file.Close()
		if errors.Is(err, errJournalLockBusy) {
			return nil, ErrJournalBusy
		}
		return nil, fmt.Errorf("%w: acquire journal lock: %v", ErrJournalInvalid, err)
	}
	return file, nil
}

func (s *JournalStore) recordPath(planHash string) string {
	return filepath.Join(s.dir, transactionID(planHash)+".json")
}

func transactionID(planHash string) string {
	return strings.TrimPrefix(planHash, "sha256:")
}

func (s *JournalStore) writeRecord(record journalRecord) error {
	record.Checksum = checksumRecord(record)
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(encoded) > maxJournalBytes {
		return fmt.Errorf("journal record exceeds %d bytes", maxJournalBytes)
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	finalPath := filepath.Join(s.dir, record.TransactionID+".json")
	tempPath := filepath.Join(s.dir, "."+record.TransactionID+"."+hex.EncodeToString(random)+".tmp")
	file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()
	written, writeErr := file.Write(encoded)
	if writeErr == nil && written != len(encoded) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	if err := os.Rename(tempPath, finalPath); err != nil {
		return err
	}
	cleanup = false
	return syncDirectory(s.dir)
}

func (s *JournalStore) readRecord(path string) (journalRecord, error) {
	var record journalRecord
	info, err := os.Lstat(path)
	if err != nil {
		return record, fmt.Errorf("%w: inspect record: %v", ErrJournalCorrupt, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > maxJournalBytes {
		return record, fmt.Errorf("%w: record is not a bounded regular file", ErrJournalCorrupt)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return record, fmt.Errorf("%w: read record: %v", ErrJournalCorrupt, err)
	}
	if int64(len(contents)) > maxJournalBytes {
		return record, fmt.Errorf("%w: record exceeds size limit", ErrJournalCorrupt)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, fmt.Errorf("%w: decode record: %v", ErrJournalCorrupt, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return record, fmt.Errorf("%w: trailing record data: %v", ErrJournalCorrupt, err)
	}
	if err := validateJournalRecord(record); err != nil {
		return record, err
	}
	if filepath.Base(path) != record.TransactionID+".json" {
		return record, fmt.Errorf("%w: record filename does not match transaction identity", ErrJournalCorrupt)
	}
	return record, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func validateJournalRecord(record journalRecord) error {
	if record.Version != journalVersion || !validSHA256(record.PlanHash) ||
		record.TransactionID != transactionID(record.PlanHash) || len(record.TransactionID) != 64 ||
		record.ManifestHash == "" || record.AuthorityHash == "" || record.RealBaselineIdentity == "" ||
		!filepath.IsAbs(record.Workspace) || filepath.Clean(record.Workspace) != record.Workspace || record.WorkspaceIdentity == "" ||
		!validSHA256(record.BeforeDigest) || !validSHA256(record.AfterDigest) || record.RealMode > 0o777 ||
		record.CreatedAt == "" || record.UpdatedAt == "" {
		return fmt.Errorf("%w: required field or identity is invalid", ErrJournalCorrupt)
	}
	createdAt, createdErr := time.Parse(time.RFC3339Nano, record.CreatedAt)
	updatedAt, updatedErr := time.Parse(time.RFC3339Nano, record.UpdatedAt)
	if createdErr != nil || updatedErr != nil || updatedAt.Before(createdAt) {
		return fmt.Errorf("%w: transaction timestamps are invalid", ErrJournalCorrupt)
	}
	switch record.State {
	case JournalPrepared, JournalApplying:
		if record.Outcome != "PENDING" {
			return fmt.Errorf("%w: non-terminal state has outcome %q", ErrJournalCorrupt, record.Outcome)
		}
	case JournalCommitted:
		if record.Outcome != "COMMITTED" {
			return fmt.Errorf("%w: committed state has invalid outcome", ErrJournalCorrupt)
		}
	case JournalAborted:
		if record.Outcome != "NOT_COMMITTED" {
			return fmt.Errorf("%w: aborted state has invalid outcome", ErrJournalCorrupt)
		}
	case JournalAfterStateObserved:
		if record.Outcome != "AFTER_STATE_OBSERVED_ATTRIBUTION_UNCERTAIN" {
			return fmt.Errorf("%w: observed-after state has invalid outcome", ErrJournalCorrupt)
		}
	case JournalRecoveryRequired:
		if record.Outcome != "RECOVERY_REQUIRED" {
			return fmt.Errorf("%w: recovery-required state has invalid outcome", ErrJournalCorrupt)
		}
	default:
		return fmt.Errorf("%w: unknown journal state %q", ErrJournalCorrupt, record.State)
	}
	if _, err := canonicalRelative(record.Resource); err != nil {
		return fmt.Errorf("%w: invalid resource binding", ErrJournalCorrupt)
	}
	switch record.State {
	case JournalPrepared, JournalApplying, JournalCommitted, JournalAborted, JournalAfterStateObserved, JournalRecoveryRequired:
	default:
		return fmt.Errorf("%w: unknown journal state %q", ErrJournalCorrupt, record.State)
	}
	if record.Checksum == "" || record.Checksum != checksumRecord(record) {
		return fmt.Errorf("%w: checksum mismatch", ErrJournalCorrupt)
	}
	return nil
}

func checksumRecord(record journalRecord) string {
	payload := journalPayload{
		Version: record.Version, TransactionID: record.TransactionID, PlanHash: record.PlanHash,
		ManifestHash: record.ManifestHash, AuthorityHash: record.AuthorityHash,
		RealBaselineIdentity: record.RealBaselineIdentity, Workspace: record.Workspace,
		WorkspaceIdentity: record.WorkspaceIdentity, Resource: record.Resource,
		BeforeDigest: record.BeforeDigest, AfterDigest: record.AfterDigest, RealMode: record.RealMode,
		State: record.State, Outcome: record.Outcome, Reason: record.Reason,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func workspaceIdentity(root *os.Root) (string, error) {
	info, err := root.Stat(".")
	if err != nil {
		return "", err
	}
	system := reflect.ValueOf(info.Sys())
	if system.Kind() == reflect.Pointer {
		system = system.Elem()
	}
	if !system.IsValid() || system.Kind() != reflect.Struct {
		return "", errors.New("workspace filesystem identity is unavailable")
	}
	device := system.FieldByName("Dev")
	inode := system.FieldByName("Ino")
	if !device.IsValid() || !inode.IsValid() {
		return "", errors.New("workspace device/inode identity is unavailable")
	}
	return fmt.Sprintf("%v:%v", device.Interface(), inode.Interface()), nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	return errors.Join(syncErr, closeErr)
}

func unlockAndClose(file *os.File) {
	if file == nil {
		return
	}
	_ = unlockJournal(file)
	_ = file.Close()
}


func validSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	digest := strings.TrimPrefix(value, "sha256:")
	if strings.ToLower(digest) != digest {
		return false
	}
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == sha256.Size
}
