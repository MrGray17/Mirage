// Package gitpublication defines immutable M5.3 publication plans, records,
// and the narrow create-only Git transport engine.
package gitpublication

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/runtime/gitbinding"
	"github.com/MrGray17/Mirage/internal/runtime/gitcommit"
	"github.com/MrGray17/Mirage/internal/runtime/githubbinding"
	"github.com/MrGray17/Mirage/internal/runtime/gitplan"
)

const PlanVersion = "mirage.git-publication-plan/v1"

var (
	ErrInvalidPlan      = errors.New("invalid Git publication plan")
	ErrAuthorityChanged = errors.New("Git publication authority changed")
	ErrExpired          = errors.New("Git publication contract expired")
)

type PlanSpec struct {
	ManifestHash string
	Contract     *contracts.Contract
	Repository   *gitbinding.Binding
	GitPlan      *gitplan.Plan
	Artifact     *gitcommit.Artifact
	GitHub       *githubbinding.Binding
	CreatedAt    time.Time
}

type Plan struct {
	version                   string
	identity                  string
	manifestHash              string
	contractHash              string
	repositoryBindingIdentity string
	gitPlanIdentity           string
	artifactIdentity          string
	commitOID                 string
	baseCommit                string
	githubBindingIdentity     string
	githubRepositoryID        int64
	repositoryFullName        string
	targetRef                 string
	operation                 contracts.GitHubPublicationOperation
	createdAt                 time.Time
}

func NewPlan(spec PlanSpec) (*Plan, error) {
	canonical, err := validatePlanAuthority(spec)
	if err != nil {
		return nil, err
	}
	identity, err := hashCanonical(canonical)
	if err != nil {
		return nil, err
	}
	return &Plan{
		version: PlanVersion, identity: identity, manifestHash: spec.ManifestHash,
		contractHash: spec.Contract.Hash(), repositoryBindingIdentity: spec.Repository.Identity(),
		gitPlanIdentity: spec.GitPlan.Identity(), artifactIdentity: spec.Artifact.Identity(),
		commitOID: spec.Artifact.CommitOID(), baseCommit: spec.Artifact.BaseCommit(),
		githubBindingIdentity: spec.GitHub.Identity(), githubRepositoryID: spec.GitHub.RepositoryID(),
		repositoryFullName: spec.GitHub.FullName(), targetRef: spec.GitPlan.TargetRef(),
		operation: contracts.GitHubCreateBranch, createdAt: spec.CreatedAt.UTC(),
	}, nil
}

func RevalidatePlan(plan *Plan, spec PlanSpec) error {
	if plan == nil || plan.identity == "" {
		return fmt.Errorf("%w: plan is unavailable", ErrInvalidPlan)
	}
	canonical, err := validatePlanAuthority(spec)
	if err != nil {
		return err
	}
	identity, err := hashCanonical(canonical)
	if err != nil || identity != plan.identity || plan.version != PlanVersion || plan.manifestHash != spec.ManifestHash || plan.contractHash != spec.Contract.Hash() || plan.repositoryBindingIdentity != spec.Repository.Identity() || plan.gitPlanIdentity != spec.GitPlan.Identity() || plan.artifactIdentity != spec.Artifact.Identity() || plan.commitOID != spec.Artifact.CommitOID() || plan.baseCommit != spec.Artifact.BaseCommit() || plan.githubBindingIdentity != spec.GitHub.Identity() || plan.githubRepositoryID != spec.GitHub.RepositoryID() || plan.repositoryFullName != spec.GitHub.FullName() || plan.targetRef != spec.GitPlan.TargetRef() || plan.operation != contracts.GitHubCreateBranch || !plan.createdAt.Equal(spec.CreatedAt.UTC()) {
		return fmt.Errorf("%w: immutable plan identity differs", ErrAuthorityChanged)
	}
	return nil
}

func validatePlanAuthority(spec PlanSpec) (canonicalPlan, error) {
	if spec.ManifestHash == "" || spec.Contract == nil || spec.Repository == nil || spec.GitPlan == nil || spec.Artifact == nil || spec.GitHub == nil || spec.CreatedAt.IsZero() {
		return canonicalPlan{}, fmt.Errorf("%w: complete trusted inputs are required", ErrInvalidPlan)
	}
	if spec.Contract.ExpiredAt(spec.CreatedAt) {
		return canonicalPlan{}, fmt.Errorf("%w: %s", ErrExpired, spec.Contract.ExpiresAt().Format(time.RFC3339Nano))
	}
	if spec.CreatedAt.UTC().Before(spec.GitHub.CapturedAt()) || spec.CreatedAt.UTC().Before(spec.GitPlan.CreatedAt()) {
		return canonicalPlan{}, fmt.Errorf("%w: publication plan predates upstream authority", ErrAuthorityChanged)
	}
	if spec.Contract.Version() != contracts.VersionV2 || spec.ManifestHash != spec.Artifact.ManifestHash() || spec.ManifestHash != spec.GitPlan.ManifestHash() || spec.ManifestHash != spec.GitHub.ManifestHash() || spec.Contract.Hash() != spec.GitPlan.ContractHash() || spec.Contract.Hash() != spec.GitHub.ContractHash() || spec.Repository.Identity() != spec.GitPlan.RepositoryBindingHash() || spec.Repository.Identity() != spec.Artifact.RepositoryBindingIdentity() || spec.GitPlan.Identity() != spec.Artifact.GitPlanIdentity() || spec.GitPlan.BaseCommit() != spec.Artifact.BaseCommit() || spec.GitPlan.TargetRef() != spec.Artifact.TargetRef() || spec.GitPlan.TargetRef() == "" || !validOID(spec.Artifact.CommitOID()) || !validOID(spec.Artifact.BaseCommit()) {
		return canonicalPlan{}, fmt.Errorf("%w: upstream identities differ", ErrAuthorityChanged)
	}
	decision := spec.Contract.EvaluateGitHubPublication(contracts.GitHubCreateBranch, spec.GitHub.FullName(), spec.GitPlan.TargetRef(), spec.CreatedAt)
	if !decision.Allowed {
		return canonicalPlan{}, fmt.Errorf("%w: %s", ErrAuthorityChanged, decision.RuleID)
	}
	return canonicalPlan{
		Version: PlanVersion, ManifestHash: spec.ManifestHash, ContractHash: spec.Contract.Hash(),
		RepositoryBindingIdentity: spec.Repository.Identity(), GitPlanIdentity: spec.GitPlan.Identity(),
		ArtifactIdentity: spec.Artifact.Identity(), CommitOID: spec.Artifact.CommitOID(), BaseCommit: spec.Artifact.BaseCommit(),
		GitHubBindingIdentity: spec.GitHub.Identity(), GitHubRepositoryID: spec.GitHub.RepositoryID(),
		RepositoryFullName: spec.GitHub.FullName(), TargetRef: spec.GitPlan.TargetRef(),
		Operation: contracts.GitHubCreateBranch, CreatedAt: spec.CreatedAt.UTC().Format(time.RFC3339Nano),
	}, nil
}

type canonicalPlan struct {
	Version                   string                               `json:"version"`
	ManifestHash              string                               `json:"manifest_hash"`
	ContractHash              string                               `json:"contract_hash"`
	RepositoryBindingIdentity string                               `json:"repository_binding_identity"`
	GitPlanIdentity           string                               `json:"git_plan_identity"`
	ArtifactIdentity          string                               `json:"artifact_identity"`
	CommitOID                 string                               `json:"commit_oid"`
	BaseCommit                string                               `json:"base_commit"`
	GitHubBindingIdentity     string                               `json:"github_binding_identity"`
	GitHubRepositoryID        int64                                `json:"github_repository_id"`
	RepositoryFullName        string                               `json:"repository_full_name"`
	TargetRef                 string                               `json:"target_ref"`
	Operation                 contracts.GitHubPublicationOperation `json:"operation"`
	CreatedAt                 string                               `json:"created_at"`
}

func (p *Plan) Version() string      { return planString(p, func() string { return p.version }) }
func (p *Plan) Identity() string     { return planString(p, func() string { return p.identity }) }
func (p *Plan) ManifestHash() string { return planString(p, func() string { return p.manifestHash }) }
func (p *Plan) ContractHash() string { return planString(p, func() string { return p.contractHash }) }
func (p *Plan) RepositoryBindingIdentity() string {
	return planString(p, func() string { return p.repositoryBindingIdentity })
}
func (p *Plan) GitPlanIdentity() string {
	return planString(p, func() string { return p.gitPlanIdentity })
}
func (p *Plan) ArtifactIdentity() string {
	return planString(p, func() string { return p.artifactIdentity })
}
func (p *Plan) CommitOID() string  { return planString(p, func() string { return p.commitOID }) }
func (p *Plan) BaseCommit() string { return planString(p, func() string { return p.baseCommit }) }
func (p *Plan) GitHubBindingIdentity() string {
	return planString(p, func() string { return p.githubBindingIdentity })
}
func (p *Plan) RepositoryFullName() string {
	return planString(p, func() string { return p.repositoryFullName })
}
func (p *Plan) TargetRef() string { return planString(p, func() string { return p.targetRef }) }
func (p *Plan) GitHubRepositoryID() int64 {
	if p == nil {
		return 0
	}
	return p.githubRepositoryID
}
func (p *Plan) Operation() contracts.GitHubPublicationOperation {
	if p == nil {
		return ""
	}
	return p.operation
}
func (p *Plan) CreatedAt() time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.createdAt
}
func planString(p *Plan, getter func() string) string {
	if p == nil {
		return ""
	}
	return getter()
}

func hashCanonical(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("canonicalize publication data: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validOID(value string) bool {
	if len(value) != 40 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
