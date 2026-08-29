// Package gitcommit deterministically constructs and revalidates candidate Git
// commit objects in MIRAGE-owned disposable storage. It never updates a real
// repository object database, index, ref, worktree, or remote.
package gitcommit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/runtime/gitbinding"
	"github.com/MrGray17/Mirage/internal/runtime/gitplan"
	"github.com/MrGray17/Mirage/internal/runtime/reconcile"
	"github.com/MrGray17/Mirage/internal/runtime/tree"
)

const (
	Version            = "mirage.git-commit-artifact/v1"
	fixedAuthorName    = "MIRAGE"
	fixedAuthorEmail   = "mirage@localhost"
	canonicalTimezone  = "+0000"
	maxTreeTraversal   = 64 << 20
	maxBaseCommitBytes = 1 << 20
	maxCommitDataBytes = 4096
)

var (
	ErrInvalidArtifact    = errors.New("invalid deterministic Git commit artifact")
	ErrAuthorityChanged   = errors.New("Git commit construction authority changed")
	ErrRepositoryChanged  = errors.New("Git repository changed during commit construction")
	ErrContentMismatch    = errors.New("verified Git output content differs")
	ErrObject             = errors.New("invalid transaction-owned Git object")
	ErrTransaction        = errors.New("Git commit transaction failed")
	ErrTransactionChanged = errors.New("Git commit transaction identity changed")
	ErrCleanup            = errors.New("Git commit transaction cleanup failed")
)

// Spec contains only already-trusted authority. The output bytes are derived
// from ReconciliationPlan and are never accepted as a caller-provided value.
type Spec struct {
	ManifestHash       string
	Contract           *contracts.Contract
	Repository         *gitbinding.Binding
	GitPlan            *gitplan.Plan
	ReconciliationPlan *tree.Plan
	Decision           reconcile.Decision
	ObservedAt         time.Time
}

// Artifact is immutable authority plus a private capability to its disposable
// object store. Cleanup state is synchronized and is not part of its identity.
type Artifact struct {
	mu                        sync.Mutex
	version                   string
	identity                  string
	manifestHash              string
	gitPlanIdentity           string
	repositoryBindingIdentity string
	reconciliationPlanHash    string
	baseCommit                string
	baseTree                  string
	targetRef                 string
	resource                  string
	baseBlob                  string
	newBlob                   string
	newTree                   string
	commit                    string
	gitTimestamp              time.Time
	effect                    gitplan.Effect
	authorizedBytes           []byte
	transaction               *transaction
}

type canonicalArtifact struct {
	Version                   string `json:"version"`
	ManifestHash              string `json:"manifest_hash"`
	GitPlanIdentity           string `json:"git_plan_identity"`
	RepositoryBindingIdentity string `json:"repository_binding_identity"`
	ReconciliationPlanHash    string `json:"reconciliation_plan_hash"`
	BaseCommit                string `json:"base_commit"`
	BaseTree                  string `json:"base_tree"`
	TargetRef                 string `json:"target_ref"`
	Resource                  string `json:"resource"`
	BaseBlob                  string `json:"base_blob"`
	NewBlob                   string `json:"new_blob"`
	NewTree                   string `json:"new_tree"`
	Commit                    string `json:"commit"`
	GitTimestamp              int64  `json:"git_timestamp"`
}

func Construct(spec Spec) (*Artifact, error) {
	effect, contents, err := validateAuthority(spec)
	if err != nil {
		return nil, err
	}
	txn, err := newTransaction(spec.Repository.Root())
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*Artifact, error) {
		if cleanupErr := txn.cleanup(); cleanupErr != nil {
			return nil, errors.Join(cause, cleanupErr)
		}
		return nil, cause
	}

	newBlob, _, err := canonicalObject("blob", contents)
	if err != nil {
		return fail(err)
	}
	if err := txn.writeObject(objectRecord{kind: "blob", oid: newBlob, data: contents}); err != nil {
		return fail(err)
	}
	newTree, treeRecords, err := deriveTree(spec.Repository, spec.ManifestHash, spec.GitPlan.BaseTree(), effect, newBlob)
	if err != nil {
		return fail(err)
	}
	for _, record := range treeRecords {
		if err := txn.writeObject(record); err != nil {
			return fail(err)
		}
	}
	gitTime := time.Unix(spec.GitPlan.CreatedAt().Unix(), 0).UTC()
	commitData, err := canonicalCommit(spec.GitPlan, newTree, gitTime)
	if err != nil {
		return fail(err)
	}
	commitOID, _, err := canonicalObject("commit", commitData)
	if err != nil {
		return fail(err)
	}
	if err := txn.writeObject(objectRecord{kind: "commit", oid: commitOID, data: commitData}); err != nil {
		return fail(err)
	}
	canonical := canonicalArtifact{
		Version: Version, ManifestHash: spec.ManifestHash, GitPlanIdentity: spec.GitPlan.Identity(),
		RepositoryBindingIdentity: spec.Repository.Identity(), ReconciliationPlanHash: spec.ReconciliationPlan.Hash(),
		BaseCommit: spec.GitPlan.BaseCommit(), BaseTree: spec.GitPlan.BaseTree(), TargetRef: spec.GitPlan.TargetRef(),
		Resource: effect.Resource, BaseBlob: effect.BaseBlobOID, NewBlob: newBlob, NewTree: newTree,
		Commit: commitOID, GitTimestamp: gitTime.Unix(),
	}
	identity, err := artifactIdentity(canonical)
	if err != nil {
		return fail(err)
	}
	artifact := &Artifact{
		version: Version, identity: identity, manifestHash: spec.ManifestHash,
		gitPlanIdentity: spec.GitPlan.Identity(), repositoryBindingIdentity: spec.Repository.Identity(),
		reconciliationPlanHash: spec.ReconciliationPlan.Hash(), baseCommit: spec.GitPlan.BaseCommit(),
		baseTree: spec.GitPlan.BaseTree(), targetRef: spec.GitPlan.TargetRef(), resource: effect.Resource,
		baseBlob: effect.BaseBlobOID, newBlob: newBlob, newTree: newTree, commit: commitOID,
		gitTimestamp: gitTime, effect: effect, authorizedBytes: append([]byte(nil), contents...), transaction: txn,
	}
	if err := Revalidate(artifact, spec); err != nil {
		return fail(err)
	}
	return artifact, nil
}

func Revalidate(artifact *Artifact, spec Spec) error {
	if artifact == nil || artifact.transaction == nil || artifact.identity == "" {
		return fmt.Errorf("%w: artifact is unavailable", ErrInvalidArtifact)
	}
	effect, contents, err := validateAuthority(spec)
	if err != nil {
		return err
	}
	if artifact.version != Version || artifact.manifestHash != spec.ManifestHash || artifact.gitPlanIdentity != spec.GitPlan.Identity() || artifact.repositoryBindingIdentity != spec.Repository.Identity() || artifact.reconciliationPlanHash != spec.ReconciliationPlan.Hash() || artifact.baseCommit != spec.GitPlan.BaseCommit() || artifact.baseTree != spec.GitPlan.BaseTree() || artifact.targetRef != spec.GitPlan.TargetRef() || artifact.effect != effect || artifact.resource != effect.Resource || artifact.baseBlob != effect.BaseBlobOID || !bytes.Equal(artifact.authorizedBytes, contents) {
		return fmt.Errorf("%w: immutable artifact authority differs", ErrAuthorityChanged)
	}
	newBlob, _, err := canonicalObject("blob", contents)
	if err != nil || newBlob != artifact.newBlob {
		return fmt.Errorf("%w: new blob identity differs", ErrObject)
	}
	observedBlob, err := artifact.transaction.readObject("blob", artifact.newBlob)
	if err != nil || !bytes.Equal(observedBlob, contents) {
		return errors.Join(fmt.Errorf("%w: new blob bytes differ", ErrObject), err)
	}
	newTree, treeRecords, err := deriveTree(spec.Repository, spec.ManifestHash, spec.GitPlan.BaseTree(), effect, artifact.newBlob)
	if err != nil || newTree != artifact.newTree {
		return errors.Join(fmt.Errorf("%w: derived tree identity differs", ErrObject), err)
	}
	for _, record := range treeRecords {
		observed, readErr := artifact.transaction.readObject("tree", record.oid)
		if readErr != nil || !bytes.Equal(observed, record.data) {
			return errors.Join(fmt.Errorf("%w: tree object %s differs", ErrObject, record.oid), readErr)
		}
	}
	gitTime := time.Unix(spec.GitPlan.CreatedAt().Unix(), 0).UTC()
	if !gitTime.Equal(artifact.gitTimestamp) {
		return fmt.Errorf("%w: deterministic Git timestamp differs", ErrAuthorityChanged)
	}
	commitData, err := canonicalCommit(spec.GitPlan, artifact.newTree, gitTime)
	if err != nil {
		return err
	}
	commitOID, _, err := canonicalObject("commit", commitData)
	if err != nil || commitOID != artifact.commit {
		return fmt.Errorf("%w: commit identity differs", ErrObject)
	}
	observedCommit, err := artifact.transaction.readObject("commit", artifact.commit)
	if err != nil || !bytes.Equal(observedCommit, commitData) {
		return errors.Join(fmt.Errorf("%w: commit bytes differ", ErrObject), err)
	}
	expectedObjects := map[string]struct{}{artifact.newBlob: {}, artifact.commit: {}}
	for _, record := range treeRecords {
		expectedObjects[record.oid] = struct{}{}
	}
	if err := artifact.transaction.verifyObjectSet(expectedObjects); err != nil {
		return err
	}
	canonical := canonicalArtifact{
		Version: artifact.version, ManifestHash: artifact.manifestHash, GitPlanIdentity: artifact.gitPlanIdentity,
		RepositoryBindingIdentity: artifact.repositoryBindingIdentity, ReconciliationPlanHash: artifact.reconciliationPlanHash,
		BaseCommit: artifact.baseCommit, BaseTree: artifact.baseTree, TargetRef: artifact.targetRef,
		Resource: artifact.resource, BaseBlob: artifact.baseBlob, NewBlob: artifact.newBlob,
		NewTree: artifact.newTree, Commit: artifact.commit, GitTimestamp: artifact.gitTimestamp.Unix(),
	}
	identity, err := artifactIdentity(canonical)
	if err != nil || identity != artifact.identity {
		return fmt.Errorf("%w: canonical artifact identity differs", ErrInvalidArtifact)
	}
	return nil
}

func validateAuthority(spec Spec) (gitplan.Effect, []byte, error) {
	if spec.ManifestHash == "" || spec.Contract == nil || spec.Repository == nil || spec.GitPlan == nil || spec.ReconciliationPlan == nil || spec.ObservedAt.IsZero() {
		return gitplan.Effect{}, nil, fmt.Errorf("%w: complete trusted authority is required", ErrInvalidArtifact)
	}
	if err := gitplan.Revalidate(spec.GitPlan, spec.ManifestHash, spec.Contract, spec.Repository, spec.ReconciliationPlan, spec.Decision, spec.ObservedAt); err != nil {
		if errors.Is(err, gitplan.ErrRepositoryChanged) {
			return gitplan.Effect{}, nil, fmt.Errorf("%w: %v", ErrRepositoryChanged, err)
		}
		return gitplan.Effect{}, nil, fmt.Errorf("%w: %v", ErrAuthorityChanged, err)
	}
	baseCommit, err := spec.Repository.ReadObject(spec.ManifestHash, "commit", spec.GitPlan.BaseCommit(), maxBaseCommitBytes)
	if err != nil {
		return gitplan.Effect{}, nil, fmt.Errorf("%w: acquire bound base commit: %v", ErrRepositoryChanged, err)
	}
	firstLine, _, found := bytes.Cut(baseCommit, []byte{'\n'})
	if !found || string(firstLine) != "tree "+spec.GitPlan.BaseTree() {
		return gitplan.Effect{}, nil, fmt.Errorf("%w: base commit does not bind the planned base tree", ErrRepositoryChanged)
	}
	effects := spec.GitPlan.Effects()
	mutations := spec.ReconciliationPlan.Mutations()
	if len(effects) != 1 || len(mutations) != 1 {
		return gitplan.Effect{}, nil, fmt.Errorf("%w: exactly one effect is required", ErrContentMismatch)
	}
	effect := effects[0]
	mutation := mutations[0]
	if effect.Operation != mutation.Operation || effect.Resource != mutation.Resource || effect.BeforeKind != mutation.BeforeKind || effect.AfterKind != mutation.AfterKind || effect.BeforeMode != mutation.BeforeMode || effect.AfterMode != mutation.AfterMode || effect.BeforeDigest != mutation.BeforeDigest || effect.AfterDigest != mutation.AfterDigest || effect.BaseBlobOID == "" {
		return gitplan.Effect{}, nil, fmt.Errorf("%w: reconciliation mutation and Git effect differ", ErrContentMismatch)
	}
	contents := mutation.Content()
	digest := sha256.Sum256(contents)
	if "sha256:"+hex.EncodeToString(digest[:]) != effect.AfterDigest {
		return gitplan.Effect{}, nil, fmt.Errorf("%w: after bytes do not match planned digest", ErrContentMismatch)
	}
	return effect, contents, nil
}

type treeEntry struct {
	mode []byte
	name []byte
	oid  string
}

func deriveTree(repository *gitbinding.Binding, manifestHash, baseTree string, effect gitplan.Effect, newBlob string) (string, []objectRecord, error) {
	relative := strings.TrimPrefix(effect.Resource, "/workspace/")
	if relative == effect.Resource || relative == "" || path.Clean(effect.Resource) != effect.Resource || strings.Contains(relative, "\\") {
		return "", nil, fmt.Errorf("%w: invalid canonical resource", ErrContentMismatch)
	}
	parts := strings.Split(relative, "/")
	budget := int64(0)
	return rewriteTree(repository, manifestHash, baseTree, parts, effect, newBlob, &budget)
}

func rewriteTree(repository *gitbinding.Binding, manifestHash, treeOID string, parts []string, effect gitplan.Effect, newBlob string, budget *int64) (string, []objectRecord, error) {
	if len(parts) == 0 || !validOID(treeOID) || !validOID(newBlob) {
		return "", nil, fmt.Errorf("%w: invalid tree rewrite request", ErrObject)
	}
	raw, err := repository.ReadObject(manifestHash, "tree", treeOID, maxTreeTraversal)
	if err != nil {
		return "", nil, fmt.Errorf("%w: read bound base tree: %v", ErrRepositoryChanged, err)
	}
	if *budget > maxTreeTraversal-int64(len(raw)) {
		return "", nil, fmt.Errorf("%w: base tree traversal budget exceeded", ErrObject)
	}
	*budget += int64(len(raw))
	entries, err := parseTree(raw)
	if err != nil {
		return "", nil, err
	}
	component := []byte(parts[0])
	match := -1
	for index := range entries {
		if bytes.Equal(entries[index].name, component) {
			if match >= 0 {
				return "", nil, fmt.Errorf("%w: duplicate target tree entry", ErrObject)
			}
			match = index
		}
	}
	if match < 0 {
		return "", nil, fmt.Errorf("%w: authorized path is absent from base tree", ErrContentMismatch)
	}
	records := []objectRecord(nil)
	entry := &entries[match]
	if len(parts) == 1 {
		expectedMode := "100644"
		if effect.BeforeMode&0o111 != 0 {
			expectedMode = "100755"
		}
		if string(entry.mode) != expectedMode || entry.oid != effect.BaseBlobOID {
			return "", nil, fmt.Errorf("%w: base tree leaf differs from Git effect", ErrContentMismatch)
		}
		entry.oid = newBlob
	} else {
		if string(entry.mode) != "40000" {
			return "", nil, fmt.Errorf("%w: path component is not a tree", ErrContentMismatch)
		}
		childOID, childRecords, err := rewriteTree(repository, manifestHash, entry.oid, parts[1:], effect, newBlob, budget)
		if err != nil {
			return "", nil, err
		}
		entry.oid = childOID
		records = append(records, childRecords...)
	}
	updated, err := encodeTree(entries)
	if err != nil {
		return "", nil, err
	}
	newTree, _, err := canonicalObject("tree", updated)
	if err != nil {
		return "", nil, err
	}
	records = append(records, objectRecord{kind: "tree", oid: newTree, data: updated})
	return newTree, records, nil
}

func parseTree(raw []byte) ([]treeEntry, error) {
	entries := make([]treeEntry, 0)
	for offset := 0; offset < len(raw); {
		space := bytes.IndexByte(raw[offset:], ' ')
		if space <= 0 {
			return nil, fmt.Errorf("%w: malformed tree mode", ErrObject)
		}
		space += offset
		nul := bytes.IndexByte(raw[space+1:], 0)
		if nul <= 0 {
			return nil, fmt.Errorf("%w: malformed tree name", ErrObject)
		}
		nul += space + 1
		if len(raw)-nul-1 < 20 {
			return nil, fmt.Errorf("%w: truncated tree object ID", ErrObject)
		}
		mode := append([]byte(nil), raw[offset:space]...)
		if string(mode) != "100644" && string(mode) != "100755" && string(mode) != "40000" {
			return nil, fmt.Errorf("%w: unsupported base tree mode %q", ErrObject, mode)
		}
		name := append([]byte(nil), raw[space+1:nul]...)
		if len(name) == 0 || bytes.ContainsAny(name, "/") {
			return nil, fmt.Errorf("%w: unsafe tree entry name", ErrObject)
		}
		oid := hex.EncodeToString(raw[nul+1 : nul+21])
		entries = append(entries, treeEntry{mode: mode, name: name, oid: oid})
		offset = nul + 21
	}
	return entries, nil
}

func encodeTree(entries []treeEntry) ([]byte, error) {
	var encoded bytes.Buffer
	for _, entry := range entries {
		if !validOID(entry.oid) || len(entry.name) == 0 || bytes.ContainsAny(entry.name, "/\x00") {
			return nil, fmt.Errorf("%w: unsafe tree entry", ErrObject)
		}
		oid, err := hex.DecodeString(entry.oid)
		if err != nil || len(oid) != 20 {
			return nil, fmt.Errorf("%w: invalid tree entry object ID", ErrObject)
		}
		encoded.Write(entry.mode)
		encoded.WriteByte(' ')
		encoded.Write(entry.name)
		encoded.WriteByte(0)
		encoded.Write(oid)
	}
	return encoded.Bytes(), nil
}

func canonicalCommit(plan *gitplan.Plan, newTree string, gitTime time.Time) ([]byte, error) {
	if plan == nil || !validOID(newTree) || !validOID(plan.BaseCommit()) || plan.AuthorName() != fixedAuthorName || plan.AuthorEmail() != fixedAuthorEmail || strings.TrimSpace(plan.Message()) == "" || strings.ContainsAny(plan.Message(), "\r\n\x00") || gitTime.Unix() < 0 || gitTime.Nanosecond() != 0 || gitTime.Location() != time.UTC {
		return nil, fmt.Errorf("%w: deterministic commit metadata is invalid", ErrInvalidArtifact)
	}
	data := fmt.Sprintf("tree %s\nparent %s\nauthor %s <%s> %d %s\ncommitter %s <%s> %d %s\n\n%s\n",
		newTree, plan.BaseCommit(), plan.AuthorName(), plan.AuthorEmail(), gitTime.Unix(), canonicalTimezone,
		plan.AuthorName(), plan.AuthorEmail(), gitTime.Unix(), canonicalTimezone, plan.Message())
	if len(data) > maxCommitDataBytes {
		return nil, fmt.Errorf("%w: deterministic commit exceeds bounded size", ErrInvalidArtifact)
	}
	return []byte(data), nil
}

func artifactIdentity(canonical canonicalArtifact) (string, error) {
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("%w: canonicalize artifact: %v", ErrInvalidArtifact, err)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func (a *Artifact) Version() string      { return value(a, func() string { return a.version }) }
func (a *Artifact) Identity() string     { return value(a, func() string { return a.identity }) }
func (a *Artifact) ManifestHash() string { return value(a, func() string { return a.manifestHash }) }
func (a *Artifact) GitPlanIdentity() string {
	return value(a, func() string { return a.gitPlanIdentity })
}
func (a *Artifact) RepositoryBindingIdentity() string {
	return value(a, func() string { return a.repositoryBindingIdentity })
}
func (a *Artifact) ReconciliationPlanHash() string {
	return value(a, func() string { return a.reconciliationPlanHash })
}
func (a *Artifact) BaseCommit() string  { return value(a, func() string { return a.baseCommit }) }
func (a *Artifact) BaseTree() string    { return value(a, func() string { return a.baseTree }) }
func (a *Artifact) TargetRef() string   { return value(a, func() string { return a.targetRef }) }
func (a *Artifact) Resource() string    { return value(a, func() string { return a.resource }) }
func (a *Artifact) BaseBlobOID() string { return value(a, func() string { return a.baseBlob }) }
func (a *Artifact) NewBlobOID() string  { return value(a, func() string { return a.newBlob }) }
func (a *Artifact) NewTreeOID() string  { return value(a, func() string { return a.newTree }) }
func (a *Artifact) CommitOID() string   { return value(a, func() string { return a.commit }) }
func (a *Artifact) Effect() gitplan.Effect {
	if a == nil {
		return gitplan.Effect{}
	}
	return a.effect
}
func (a *Artifact) GitTimestamp() time.Time {
	if a == nil {
		return time.Time{}
	}
	return a.gitTimestamp
}

// ExportObjects copies the already-constructed loose object set into an empty,
// caller-owned directory. This is a local data operation only; it grants no
// ref, repository, credential, or publication authority.
func (a *Artifact) ExportObjects(destination string) error {
	if a == nil || a.transaction == nil {
		return fmt.Errorf("%w: artifact transaction is unavailable", ErrInvalidArtifact)
	}
	return a.transaction.exportObjects(destination)
}

func value(a *Artifact, getter func() string) string {
	if a == nil {
		return ""
	}
	return getter()
}

// Cleanup destroys only the transaction-owned object store. Physical identity
// uncertainty fails closed and leaves evidence for explicit recovery.
func (a *Artifact) Cleanup() error {
	if a == nil || a.transaction == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.transaction.cleanup()
}
