// Package gitplan derives immutable, data-only Git effect plans from MIRAGE's
// verified frozen-tree evidence. M5.1 contains no Git mutation executor.
package gitplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/gitrefs"
	"github.com/MrGray17/Mirage/internal/runtime/gitbinding"
	"github.com/MrGray17/Mirage/internal/runtime/reconcile"
	"github.com/MrGray17/Mirage/internal/runtime/tree"
)

const (
	Version        = "mirage.git-effect-plan/v1"
	authorName     = "MIRAGE"
	authorEmail    = "mirage@localhost"
	branchPrefix   = gitrefs.RunBranchPrefix // compatibility alias; derivation lives in gitrefs.
	maxMessageSize = 256
	maxRunIDSize   = 256
)

var (
	ErrInvalidPlan       = errors.New("invalid deferred Git effect plan")
	ErrUnverified        = errors.New("Git effect plan requires verified reconciliation")
	ErrAuthorityChanged  = errors.New("deferred Git plan authority changed")
	ErrRepositoryChanged = errors.New("deferred Git repository state changed")
	ErrContractExpired   = errors.New("deferred Git plan contract expired")
	ErrUnsupportedEffect = errors.New("unsupported deferred Git file effect")
)

// Effect is an immutable projection of one MIRAGE-observed filesystem
// mutation. It never contains agent prose, an agent patch, or agent Git state.
type Effect struct {
	Operation    tree.Operation `json:"operation"`
	Resource     string         `json:"resource"`
	BeforeKind   tree.Kind      `json:"before_kind"`
	AfterKind    tree.Kind      `json:"after_kind"`
	BeforeMode   uint32         `json:"before_mode"`
	AfterMode    uint32         `json:"after_mode"`
	BeforeDigest string         `json:"before_digest"`
	AfterDigest  string         `json:"after_digest"`
	BaseBlobOID  string         `json:"base_blob_oid"`
}

// Spec contains trusted construction inputs. New validates the complete
// authority chain and copies every resulting value into a private Plan.
type Spec struct {
	RunID              string
	ManifestHash       string
	Contract           *contracts.Contract
	Repository         *gitbinding.Binding
	ReconciliationPlan *tree.Plan
	Decision           reconcile.Decision
	CreatedAt          time.Time
}

type Plan struct {
	version                 string
	identity                string
	runID                   string
	manifestHash            string
	contractHash            string
	contractExpiry          time.Time
	repositoryBindingHash   string
	repositoryIdentity      string
	baseCommit              string
	baseTree                string
	baseRef                 string
	reconciliationPlanHash  string
	reconciliationAuthority string
	targetRef               string
	authorName              string
	authorEmail             string
	message                 string
	createdAt               time.Time
	effects                 []Effect
}

func New(spec Spec) (*Plan, error) {
	if strings.TrimSpace(spec.RunID) == "" || len(spec.RunID) > maxRunIDSize || !utf8.ValidString(spec.RunID) || strings.TrimSpace(spec.ManifestHash) == "" || spec.Contract == nil || spec.Repository == nil || spec.ReconciliationPlan == nil || spec.CreatedAt.IsZero() {
		return nil, fmt.Errorf("%w: complete trusted inputs are required", ErrInvalidPlan)
	}
	if spec.RunID != spec.Contract.RunID() {
		return nil, fmt.Errorf("%w: run and contract identities differ", ErrAuthorityChanged)
	}
	if spec.CreatedAt.UTC().Before(spec.Repository.CapturedAt()) {
		return nil, fmt.Errorf("%w: plan time predates repository binding", ErrAuthorityChanged)
	}
	if spec.Repository.ManifestHash() != spec.ManifestHash {
		return nil, fmt.Errorf("%w: repository and manifest differ", ErrAuthorityChanged)
	}
	if spec.Contract.ExpiredAt(spec.CreatedAt) {
		return nil, fmt.Errorf("%w: %s", ErrContractExpired, spec.Contract.ExpiresAt().Format(time.RFC3339Nano))
	}
	if !spec.Decision.Allowed || !spec.Decision.BoundTo(spec.ManifestHash, spec.Contract.Hash(), spec.ReconciliationPlan.Hash()) {
		return nil, fmt.Errorf("%w: decision is absent, denied, or not bound to the supplied plan", ErrUnverified)
	}
	if err := spec.Repository.Revalidate(spec.ManifestHash); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRepositoryChanged, err)
	}
	effects, err := deriveEffects(spec.ReconciliationPlan)
	if err != nil {
		return nil, err
	}
	baseBlob, err := spec.Repository.BindTrackedBlob(spec.ManifestHash, effects[0].Resource, effects[0].BeforeDigest, effects[0].BeforeMode&0o111 != 0)
	if err != nil {
		if errors.Is(err, gitbinding.ErrUntrackedResource) || errors.Is(err, gitbinding.ErrBlobMismatch) {
			return nil, fmt.Errorf("%w: %v", ErrUnsupportedEffect, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrRepositoryChanged, err)
	}
	effects[0].BaseBlobOID = baseBlob.ObjectID()
	targetRef := gitrefs.RunTarget(spec.RunID)
	manifestDigest := sha256.Sum256([]byte(spec.ManifestHash))
	message := "MIRAGE verified change " + hex.EncodeToString(manifestDigest[:])[:12]
	if !utf8.ValidString(message) || len(message) > maxMessageSize {
		return nil, fmt.Errorf("%w: deterministic commit message is invalid", ErrInvalidPlan)
	}
	canonical := canonicalPlan{
		Version: Version, RunID: spec.RunID, ManifestHash: spec.ManifestHash,
		ContractHash: spec.Contract.Hash(), ContractExpiry: spec.Contract.ExpiresAt().UTC().Format(time.RFC3339Nano),
		RepositoryBindingHash: spec.Repository.Identity(), RepositoryIdentity: spec.Repository.RepositoryIdentity(),
		BaseCommit: spec.Repository.HeadCommit(), BaseTree: spec.Repository.HeadTree(), BaseRef: spec.Repository.HeadRef(),
		ReconciliationPlanHash: spec.ReconciliationPlan.Hash(), ReconciliationAuthority: spec.Decision.AuthorityHash,
		TargetRef: targetRef, AuthorName: authorName, AuthorEmail: authorEmail, Message: message,
		CreatedAt: spec.CreatedAt.UTC().Format(time.RFC3339Nano), Effects: effects,
	}
	identity, err := canonicalIdentity(canonical)
	if err != nil {
		return nil, err
	}
	return &Plan{
		version: Version, identity: identity, runID: spec.RunID, manifestHash: spec.ManifestHash,
		contractHash: spec.Contract.Hash(), contractExpiry: spec.Contract.ExpiresAt().UTC(),
		repositoryBindingHash: spec.Repository.Identity(), repositoryIdentity: spec.Repository.RepositoryIdentity(),
		baseCommit: spec.Repository.HeadCommit(), baseTree: spec.Repository.HeadTree(), baseRef: spec.Repository.HeadRef(),
		reconciliationPlanHash: spec.ReconciliationPlan.Hash(), reconciliationAuthority: spec.Decision.AuthorityHash,
		targetRef: targetRef, authorName: authorName, authorEmail: authorEmail, message: message,
		createdAt: spec.CreatedAt.UTC(), effects: append([]Effect(nil), effects...),
	}, nil
}

func (p *Plan) Version() string {
	if p == nil {
		return ""
	}
	return p.version
}
func (p *Plan) Identity() string {
	if p == nil {
		return ""
	}
	return p.identity
}
func (p *Plan) RunID() string {
	if p == nil {
		return ""
	}
	return p.runID
}
func (p *Plan) ManifestHash() string {
	if p == nil {
		return ""
	}
	return p.manifestHash
}
func (p *Plan) ContractHash() string {
	if p == nil {
		return ""
	}
	return p.contractHash
}
func (p *Plan) RepositoryBindingHash() string {
	if p == nil {
		return ""
	}
	return p.repositoryBindingHash
}
func (p *Plan) RepositoryIdentity() string {
	if p == nil {
		return ""
	}
	return p.repositoryIdentity
}
func (p *Plan) BaseCommit() string {
	if p == nil {
		return ""
	}
	return p.baseCommit
}
func (p *Plan) BaseTree() string {
	if p == nil {
		return ""
	}
	return p.baseTree
}
func (p *Plan) BaseRef() string {
	if p == nil {
		return ""
	}
	return p.baseRef
}
func (p *Plan) ReconciliationPlanHash() string {
	if p == nil {
		return ""
	}
	return p.reconciliationPlanHash
}
func (p *Plan) ReconciliationAuthority() string {
	if p == nil {
		return ""
	}
	return p.reconciliationAuthority
}
func (p *Plan) TargetRef() string {
	if p == nil {
		return ""
	}
	return p.targetRef
}
func (p *Plan) AuthorName() string {
	if p == nil {
		return ""
	}
	return p.authorName
}
func (p *Plan) AuthorEmail() string {
	if p == nil {
		return ""
	}
	return p.authorEmail
}
func (p *Plan) Message() string {
	if p == nil {
		return ""
	}
	return p.message
}
func (p *Plan) CreatedAt() time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.createdAt
}
func (p *Plan) Effects() []Effect {
	if p == nil {
		return nil
	}
	return append([]Effect(nil), p.effects...)
}

// Revalidate repeats every non-mutating authority and repository freshness
// check required before a future M5.2 engine may consume the plan. It never
// replaces stale authority with newly observed state.
func Revalidate(plan *Plan, manifestHash string, contract *contracts.Contract, repository *gitbinding.Binding, reconciliationPlan *tree.Plan, decision reconcile.Decision, at time.Time) error {
	if plan == nil || plan.identity == "" || contract == nil || repository == nil || reconciliationPlan == nil || at.IsZero() {
		return fmt.Errorf("%w: complete revalidation inputs are required", ErrInvalidPlan)
	}
	if contract.ExpiredAt(at) {
		return fmt.Errorf("%w: %s", ErrContractExpired, contract.ExpiresAt().Format(time.RFC3339Nano))
	}
	if at.UTC().Before(plan.createdAt) {
		return fmt.Errorf("%w: trusted time predates plan creation", ErrAuthorityChanged)
	}
	if manifestHash != plan.manifestHash || contract.Hash() != plan.contractHash || !contract.ExpiresAt().UTC().Equal(plan.contractExpiry) || repository.Identity() != plan.repositoryBindingHash || repository.RepositoryIdentity() != plan.repositoryIdentity {
		return fmt.Errorf("%w: manifest, contract, or repository binding differs", ErrAuthorityChanged)
	}
	if reconciliationPlan.Hash() != plan.reconciliationPlanHash || !decision.Allowed || decision.AuthorityHash != plan.reconciliationAuthority || !decision.BoundTo(manifestHash, contract.Hash(), reconciliationPlan.Hash()) {
		return fmt.Errorf("%w: verified reconciliation evidence differs", ErrAuthorityChanged)
	}
	if len(plan.effects) != 1 {
		return fmt.Errorf("%w: planned effect shape changed", ErrAuthorityChanged)
	}
	baseBlob, err := repository.BindTrackedBlob(manifestHash, plan.effects[0].Resource, plan.effects[0].BeforeDigest, plan.effects[0].BeforeMode&0o111 != 0)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRepositoryChanged, err)
	}
	if baseBlob.ObjectID() != plan.effects[0].BaseBlobOID {
		return fmt.Errorf("%w: base blob identity differs", ErrAuthorityChanged)
	}
	canonical := canonicalPlan{
		Version: plan.version, RunID: plan.runID, ManifestHash: plan.manifestHash,
		ContractHash: plan.contractHash, ContractExpiry: plan.contractExpiry.Format(time.RFC3339Nano),
		RepositoryBindingHash: plan.repositoryBindingHash, RepositoryIdentity: plan.repositoryIdentity,
		BaseCommit: plan.baseCommit, BaseTree: plan.baseTree, BaseRef: plan.baseRef,
		ReconciliationPlanHash: plan.reconciliationPlanHash, ReconciliationAuthority: plan.reconciliationAuthority,
		TargetRef: plan.targetRef, AuthorName: plan.authorName, AuthorEmail: plan.authorEmail,
		Message: plan.message, CreatedAt: plan.createdAt.Format(time.RFC3339Nano), Effects: plan.effects,
	}
	identity, err := canonicalIdentity(canonical)
	if err != nil || identity != plan.identity {
		return fmt.Errorf("%w: plan identity is not canonical", ErrAuthorityChanged)
	}
	return nil
}

type canonicalPlan struct {
	Version                 string   `json:"version"`
	RunID                   string   `json:"run_id"`
	ManifestHash            string   `json:"manifest_hash"`
	ContractHash            string   `json:"contract_hash"`
	ContractExpiry          string   `json:"contract_expiry"`
	RepositoryBindingHash   string   `json:"repository_binding_hash"`
	RepositoryIdentity      string   `json:"repository_identity"`
	BaseCommit              string   `json:"base_commit"`
	BaseTree                string   `json:"base_tree"`
	BaseRef                 string   `json:"base_ref"`
	ReconciliationPlanHash  string   `json:"reconciliation_plan_hash"`
	ReconciliationAuthority string   `json:"reconciliation_authority"`
	TargetRef               string   `json:"target_ref"`
	AuthorName              string   `json:"author_name"`
	AuthorEmail             string   `json:"author_email"`
	Message                 string   `json:"message"`
	CreatedAt               string   `json:"created_at"`
	Effects                 []Effect `json:"effects"`
}

func deriveEffects(plan *tree.Plan) ([]Effect, error) {
	mutations := plan.Mutations()
	if len(mutations) != 1 {
		return nil, fmt.Errorf("%w: M5.1 retains the one-file M4.3 boundary", ErrUnsupportedEffect)
	}
	mutation := mutations[0]
	if mutation.Operation != tree.OperationModify || mutation.BeforeKind != tree.KindFile || mutation.AfterKind != tree.KindFile || mutation.BeforeMode != mutation.AfterMode || mutation.BeforeDigest == "" || mutation.AfterDigest == "" {
		return nil, fmt.Errorf("%w: only one existing regular-file content MODIFY is supported", ErrUnsupportedEffect)
	}
	return []Effect{{
		Operation: mutation.Operation, Resource: mutation.Resource,
		BeforeKind: mutation.BeforeKind, AfterKind: mutation.AfterKind,
		BeforeMode: mutation.BeforeMode, AfterMode: mutation.AfterMode,
		BeforeDigest: mutation.BeforeDigest, AfterDigest: mutation.AfterDigest,
	}}, nil
}

func canonicalIdentity(plan canonicalPlan) (string, error) {
	encoded, err := json.Marshal(plan)
	if err != nil {
		return "", fmt.Errorf("%w: canonicalize plan: %v", ErrInvalidPlan, err)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
