package githubpullrequest

import (
	"errors"
	"fmt"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/runtime/gitbinding"
	"github.com/MrGray17/Mirage/internal/runtime/gitcommit"
	"github.com/MrGray17/Mirage/internal/runtime/githubbinding"
	"github.com/MrGray17/Mirage/internal/runtime/gitplan"
	"github.com/MrGray17/Mirage/internal/runtime/gitpublication"
)

const PlanVersion = "mirage.github-pull-request-plan/v1"

var (
	ErrInvalidPlan      = errors.New("invalid GitHub pull-request plan")
	ErrAuthorityChanged = errors.New("GitHub pull-request authority changed")
)

type PlanSpec struct {
	ManifestHash      string
	Contract          *contracts.Contract
	Repository        *gitbinding.Binding
	GitPlan           *gitplan.Plan
	Artifact          *gitcommit.Artifact
	GitHub            *githubbinding.Binding
	PublicationPlan   *gitpublication.Plan
	PublicationRecord *gitpublication.Record
	CreatedAt         time.Time
}

type Plan struct {
	version                    string
	identity                   string
	manifestHash               string
	contractHash               string
	repositoryBindingIdentity  string
	gitPlanIdentity            string
	artifactIdentity           string
	gitPublicationPlanIdentity string
	publicationRecordIdentity  string
	githubBindingIdentity      string
	repositoryID               int64
	repositoryFullName         string
	baseRef                    string
	baseCommit                 string
	targetRef                  string
	commitOID                  string
	operation                  contracts.GitHubPublicationOperation
	metadata                   *Metadata
	createdAt                  time.Time
}

type planAuthority struct {
	ManifestHash               string
	ContractHash               string
	RepositoryBindingIdentity  string
	GitPlanIdentity            string
	ArtifactIdentity           string
	GitPublicationPlanIdentity string
	PublicationRecordIdentity  string
	GitHubBindingIdentity      string
	RepositoryID               int64
	RepositoryFullName         string
	BaseRef                    string
	BaseCommit                 string
	TargetRef                  string
	CommitOID                  string
	Metadata                   *Metadata
	CreatedAt                  time.Time
}

type canonicalPlan struct {
	Version                    string                               `json:"version"`
	ManifestHash               string                               `json:"manifest_hash"`
	ContractHash               string                               `json:"contract_hash"`
	RepositoryBindingIdentity  string                               `json:"repository_binding_identity"`
	GitPlanIdentity            string                               `json:"git_plan_identity"`
	ArtifactIdentity           string                               `json:"artifact_identity"`
	GitPublicationPlanIdentity string                               `json:"git_publication_plan_identity"`
	PublicationRecordIdentity  string                               `json:"publication_record_identity"`
	GitHubBindingIdentity      string                               `json:"github_binding_identity"`
	RepositoryID               int64                                `json:"repository_id"`
	RepositoryFullName         string                               `json:"repository_full_name"`
	BaseRef                    string                               `json:"base_ref"`
	BaseCommit                 string                               `json:"base_commit"`
	TargetRef                  string                               `json:"target_ref"`
	CommitOID                  string                               `json:"commit_oid"`
	Operation                  contracts.GitHubPublicationOperation `json:"operation"`
	MetadataPolicy             string                               `json:"metadata_policy"`
	MetadataIdentity           string                               `json:"metadata_identity"`
	Title                      string                               `json:"title"`
	Body                       string                               `json:"body"`
	TitleDigest                string                               `json:"title_digest"`
	BodyDigest                 string                               `json:"body_digest"`
	CreatedAt                  string                               `json:"created_at"`
}

func NewPlan(spec PlanSpec) (*Plan, error) {
	if spec.ManifestHash == "" || spec.Contract == nil || spec.Repository == nil || spec.GitPlan == nil || spec.Artifact == nil || spec.GitHub == nil || spec.PublicationPlan == nil || spec.PublicationRecord == nil || spec.CreatedAt.IsZero() {
		return nil, fmt.Errorf("%w: complete trusted inputs are required", ErrInvalidPlan)
	}
	createdAt := spec.CreatedAt.UTC()
	if spec.Contract.Version() != contracts.VersionV3 || spec.Contract.ExpiredAt(createdAt) || createdAt.Before(spec.PublicationRecord.DispatchTime()) {
		return nil, fmt.Errorf("%w: contract version, time, or publication ordering is invalid", ErrAuthorityChanged)
	}
	if spec.ManifestHash != spec.ContractHashInputs() {
		return nil, fmt.Errorf("%w: upstream manifest identities differ", ErrAuthorityChanged)
	}
	if spec.Contract.Hash() != spec.GitPlan.ContractHash() || spec.Contract.Hash() != spec.GitHub.ContractHash() || spec.Contract.Hash() != spec.PublicationPlan.ContractHash() || spec.Contract.Hash() != spec.PublicationRecord.ContractHash() {
		return nil, fmt.Errorf("%w: upstream contract identities differ", ErrAuthorityChanged)
	}
	if spec.Repository.Identity() != spec.GitPlan.RepositoryBindingHash() || spec.Repository.Identity() != spec.Artifact.RepositoryBindingIdentity() || spec.Repository.Identity() != spec.PublicationPlan.RepositoryBindingIdentity() {
		return nil, fmt.Errorf("%w: repository binding identities differ", ErrAuthorityChanged)
	}
	if spec.GitPlan.Identity() != spec.Artifact.GitPlanIdentity() || spec.GitPlan.Identity() != spec.PublicationPlan.GitPlanIdentity() || spec.Artifact.Identity() != spec.PublicationPlan.ArtifactIdentity() || spec.Artifact.Identity() != spec.PublicationRecord.ArtifactIdentity() {
		return nil, fmt.Errorf("%w: Git plan or artifact identities differ", ErrAuthorityChanged)
	}
	if spec.PublicationPlan.Identity() != spec.PublicationRecord.PublicationPlanIdentity() || spec.GitHub.Identity() != spec.PublicationPlan.GitHubBindingIdentity() || spec.GitHub.Identity() != spec.PublicationRecord.GitHubBindingIdentity() {
		return nil, fmt.Errorf("%w: publication or GitHub binding identities differ", ErrAuthorityChanged)
	}
	if spec.PublicationRecord.Outcome() != gitpublication.OutcomePublished || spec.PublicationRecord.ObservedStatus() != githubbinding.RefPresentExact || spec.PublicationRecord.ObservedOID() != spec.Artifact.CommitOID() || !spec.PublicationRecord.ResolvedByReconciliation() {
		return nil, fmt.Errorf("%w: M5.3 publication is not authoritatively proven", ErrAuthorityChanged)
	}
	if spec.GitPlan.BaseRef() != spec.GitHub.BaseRef() || spec.GitPlan.BaseRef() != spec.PublicationPlan.BaseRef() || spec.GitPlan.BaseCommit() != spec.GitHub.BaseCommit() || spec.GitPlan.BaseCommit() != spec.PublicationPlan.BaseCommit() || spec.GitPlan.BaseCommit() != spec.Artifact.BaseCommit() {
		return nil, fmt.Errorf("%w: base authority differs", ErrAuthorityChanged)
	}
	if spec.GitPlan.TargetRef() != spec.Artifact.TargetRef() || spec.GitPlan.TargetRef() != spec.PublicationPlan.TargetRef() || spec.GitPlan.TargetRef() != spec.PublicationRecord.TargetRef() || spec.Artifact.CommitOID() != spec.PublicationPlan.CommitOID() || spec.Artifact.CommitOID() != spec.PublicationRecord.CommitOID() {
		return nil, fmt.Errorf("%w: published head authority differs", ErrAuthorityChanged)
	}
	if spec.GitHub.RepositoryID() != spec.PublicationPlan.GitHubRepositoryID() || spec.GitHub.RepositoryID() != spec.PublicationRecord.RepositoryID() || spec.GitHub.FullName() != spec.PublicationPlan.RepositoryFullName() || spec.GitHub.FullName() != spec.PublicationRecord.RepositoryFullName() {
		return nil, fmt.Errorf("%w: GitHub repository identity differs", ErrAuthorityChanged)
	}
	policy := spec.Contract.GitHubPullRequest()
	decision := spec.Contract.EvaluateGitHubPullRequest(contracts.GitHubCreatePullRequest, spec.GitHub.FullName(), spec.GitPlan.BaseRef(), spec.GitPlan.TargetRef(), contracts.PullRequestMetadataV1, createdAt)
	if !decision.Allowed || policy.Operation != contracts.GitHubCreatePullRequest || policy.BaseRef != spec.GitPlan.BaseRef() || policy.TargetRef != spec.GitPlan.TargetRef() || policy.MetadataPolicy != contracts.PullRequestMetadataV1 {
		return nil, fmt.Errorf("%w: exact PR policy denied: %s", ErrAuthorityChanged, decision.RuleID)
	}
	metadata, err := NewMetadata(MetadataSpec{RunID: spec.GitPlan.RunID(), ContractHash: spec.Contract.Hash(), Operation: string(spec.Artifact.Effect().Operation), Resource: spec.Artifact.Resource(), CommitOID: spec.Artifact.CommitOID(), PublicationRecordIdentity: spec.PublicationRecord.Identity()})
	if err != nil {
		return nil, err
	}
	return newPlan(planAuthority{
		ManifestHash: spec.ManifestHash, ContractHash: spec.Contract.Hash(), RepositoryBindingIdentity: spec.Repository.Identity(),
		GitPlanIdentity: spec.GitPlan.Identity(), ArtifactIdentity: spec.Artifact.Identity(), GitPublicationPlanIdentity: spec.PublicationPlan.Identity(), PublicationRecordIdentity: spec.PublicationRecord.Identity(),
		GitHubBindingIdentity: spec.GitHub.Identity(), RepositoryID: spec.GitHub.RepositoryID(), RepositoryFullName: spec.GitHub.FullName(), BaseRef: spec.GitPlan.BaseRef(), BaseCommit: spec.GitPlan.BaseCommit(),
		TargetRef: spec.GitPlan.TargetRef(), CommitOID: spec.Artifact.CommitOID(), Metadata: metadata, CreatedAt: createdAt,
	})
}

func (spec PlanSpec) ContractHashInputs() string {
	if spec.GitPlan == nil || spec.Artifact == nil || spec.GitHub == nil || spec.PublicationPlan == nil || spec.PublicationRecord == nil {
		return ""
	}
	if spec.ManifestHash != spec.GitPlan.ManifestHash() || spec.ManifestHash != spec.Artifact.ManifestHash() || spec.ManifestHash != spec.GitHub.ManifestHash() || spec.ManifestHash != spec.PublicationPlan.ManifestHash() || spec.ManifestHash != spec.PublicationRecord.ManifestHash() {
		return ""
	}
	return spec.ManifestHash
}

func newPlan(authority planAuthority) (*Plan, error) {
	if authority.ManifestHash == "" || !validDigest(authority.ContractHash) || authority.RepositoryBindingIdentity == "" || authority.GitPlanIdentity == "" || authority.ArtifactIdentity == "" || authority.GitPublicationPlanIdentity == "" || authority.PublicationRecordIdentity == "" || authority.GitHubBindingIdentity == "" || authority.RepositoryID <= 0 || authority.RepositoryFullName == "" || authority.BaseRef == "" || !validOID(authority.BaseCommit) || authority.TargetRef == "" || !validOID(authority.CommitOID) || authority.Metadata == nil || authority.Metadata.Version() != contracts.PullRequestMetadataV1 || authority.CreatedAt.IsZero() {
		return nil, fmt.Errorf("%w: canonical authority is incomplete", ErrInvalidPlan)
	}
	canonical := canonicalPlan{
		Version: PlanVersion, ManifestHash: authority.ManifestHash, ContractHash: authority.ContractHash, RepositoryBindingIdentity: authority.RepositoryBindingIdentity,
		GitPlanIdentity: authority.GitPlanIdentity, ArtifactIdentity: authority.ArtifactIdentity, GitPublicationPlanIdentity: authority.GitPublicationPlanIdentity, PublicationRecordIdentity: authority.PublicationRecordIdentity,
		GitHubBindingIdentity: authority.GitHubBindingIdentity, RepositoryID: authority.RepositoryID, RepositoryFullName: authority.RepositoryFullName, BaseRef: authority.BaseRef, BaseCommit: authority.BaseCommit,
		TargetRef: authority.TargetRef, CommitOID: authority.CommitOID, Operation: contracts.GitHubCreatePullRequest, MetadataPolicy: authority.Metadata.Version(), MetadataIdentity: authority.Metadata.Identity(),
		Title: authority.Metadata.Title(), Body: authority.Metadata.Body(), TitleDigest: authority.Metadata.TitleDigest(), BodyDigest: authority.Metadata.BodyDigest(), CreatedAt: authority.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	identity, err := canonicalHash(canonical)
	if err != nil {
		return nil, err
	}
	return &Plan{
		version: PlanVersion, identity: identity, manifestHash: authority.ManifestHash, contractHash: authority.ContractHash, repositoryBindingIdentity: authority.RepositoryBindingIdentity,
		gitPlanIdentity: authority.GitPlanIdentity, artifactIdentity: authority.ArtifactIdentity, gitPublicationPlanIdentity: authority.GitPublicationPlanIdentity, publicationRecordIdentity: authority.PublicationRecordIdentity,
		githubBindingIdentity: authority.GitHubBindingIdentity, repositoryID: authority.RepositoryID, repositoryFullName: authority.RepositoryFullName, baseRef: authority.BaseRef, baseCommit: authority.BaseCommit,
		targetRef: authority.TargetRef, commitOID: authority.CommitOID, operation: contracts.GitHubCreatePullRequest, metadata: authority.Metadata, createdAt: authority.CreatedAt.UTC(),
	}, nil
}

func RevalidatePlan(plan *Plan, spec PlanSpec) error {
	if plan == nil {
		return ErrInvalidPlan
	}
	fresh, err := NewPlan(spec)
	if err != nil {
		return err
	}
	if fresh.identity != plan.identity || fresh.createdAt != plan.createdAt {
		return fmt.Errorf("%w: canonical plan identity differs", ErrAuthorityChanged)
	}
	return nil
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
func (p *Plan) GitPublicationPlanIdentity() string {
	return planString(p, func() string { return p.gitPublicationPlanIdentity })
}
func (p *Plan) PublicationRecordIdentity() string {
	return planString(p, func() string { return p.publicationRecordIdentity })
}
func (p *Plan) GitHubBindingIdentity() string {
	return planString(p, func() string { return p.githubBindingIdentity })
}
func (p *Plan) RepositoryFullName() string {
	return planString(p, func() string { return p.repositoryFullName })
}
func (p *Plan) BaseRef() string    { return planString(p, func() string { return p.baseRef }) }
func (p *Plan) BaseCommit() string { return planString(p, func() string { return p.baseCommit }) }
func (p *Plan) TargetRef() string  { return planString(p, func() string { return p.targetRef }) }
func (p *Plan) CommitOID() string  { return planString(p, func() string { return p.commitOID }) }
func (p *Plan) RepositoryID() int64 {
	if p == nil {
		return 0
	}
	return p.repositoryID
}
func (p *Plan) Operation() contracts.GitHubPublicationOperation {
	if p == nil {
		return ""
	}
	return p.operation
}
func (p *Plan) Metadata() *Metadata {
	if p == nil {
		return nil
	}
	return p.metadata
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
