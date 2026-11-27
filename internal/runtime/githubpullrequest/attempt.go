package githubpullrequest

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/MrGray17/Mirage/internal/gitrefs"
)

const AttemptVersion = "mirage.github-pull-request-attempt/v1"

var ErrInvalidAttempt = errors.New("invalid GitHub pull-request attempt")

type requestRepresentation struct {
	Title string `json:"title"`
	Body  string `json:"body"`
	Base  string `json:"base"`
	Head  string `json:"head"`
	Draft bool   `json:"draft"`
}

type PullRequestAttempt struct {
	version       string
	identity      string
	planIdentity  string
	repositoryID  int64
	baseRef       string
	targetRef     string
	commitOID     string
	requestDigest string
	titleDigest   string
	bodyDigest    string
	authorityTime time.Time
}

type canonicalAttempt struct {
	Version       string `json:"version"`
	PlanIdentity  string `json:"plan_identity"`
	RepositoryID  int64  `json:"repository_id"`
	BaseRef       string `json:"base_ref"`
	TargetRef     string `json:"target_ref"`
	CommitOID     string `json:"commit_oid"`
	RequestDigest string `json:"request_digest"`
	TitleDigest   string `json:"title_digest"`
	BodyDigest    string `json:"body_digest"`
	AuthorityTime string `json:"authority_time"`
}

func NewPullRequestAttempt(plan *Plan, authorityTime time.Time) (*PullRequestAttempt, error) {
	if plan == nil || plan.Identity() == "" || plan.Metadata() == nil || authorityTime.IsZero() || authorityTime.UTC().Before(plan.CreatedAt()) {
		return nil, fmt.Errorf("%w: plan or trusted authority time is invalid", ErrInvalidAttempt)
	}
	requestBytes, err := canonicalRequestBytes(plan)
	if err != nil {
		return nil, err
	}
	canonical := canonicalAttempt{
		Version: AttemptVersion, PlanIdentity: plan.Identity(), RepositoryID: plan.RepositoryID(), BaseRef: plan.BaseRef(), TargetRef: plan.TargetRef(), CommitOID: plan.CommitOID(),
		RequestDigest: bytesDigest(requestBytes), TitleDigest: plan.Metadata().TitleDigest(), BodyDigest: plan.Metadata().BodyDigest(), AuthorityTime: authorityTime.UTC().Format(time.RFC3339Nano),
	}
	identity, err := canonicalHash(canonical)
	if err != nil {
		return nil, err
	}
	return &PullRequestAttempt{version: AttemptVersion, identity: identity, planIdentity: plan.Identity(), repositoryID: plan.RepositoryID(), baseRef: plan.BaseRef(), targetRef: plan.TargetRef(), commitOID: plan.CommitOID(), requestDigest: canonical.RequestDigest, titleDigest: canonical.TitleDigest, bodyDigest: canonical.BodyDigest, authorityTime: authorityTime.UTC()}, nil
}

func canonicalRequestBytes(plan *Plan) ([]byte, error) {
	if plan == nil || plan.Metadata() == nil {
		return nil, ErrInvalidAttempt
	}
	base, baseOK := gitrefs.BranchName(plan.BaseRef())
	head, headOK := gitrefs.BranchName(plan.TargetRef())
	if !baseOK || !headOK || base == head {
		return nil, fmt.Errorf("%w: canonical API branch conversion failed", ErrInvalidAttempt)
	}
	encoded, err := json.Marshal(requestRepresentation{Title: plan.Metadata().Title(), Body: plan.Metadata().Body(), Base: base, Head: head, Draft: false})
	if err != nil {
		return nil, fmt.Errorf("%w: canonical request: %v", ErrInvalidAttempt, err)
	}
	return encoded, nil
}

func (a *PullRequestAttempt) Version() string {
	return attemptString(a, func() string { return a.version })
}
func (a *PullRequestAttempt) Identity() string {
	return attemptString(a, func() string { return a.identity })
}
func (a *PullRequestAttempt) PlanIdentity() string {
	return attemptString(a, func() string { return a.planIdentity })
}
func (a *PullRequestAttempt) BaseRef() string {
	return attemptString(a, func() string { return a.baseRef })
}
func (a *PullRequestAttempt) TargetRef() string {
	return attemptString(a, func() string { return a.targetRef })
}
func (a *PullRequestAttempt) CommitOID() string {
	return attemptString(a, func() string { return a.commitOID })
}
func (a *PullRequestAttempt) RequestDigest() string {
	return attemptString(a, func() string { return a.requestDigest })
}
func (a *PullRequestAttempt) TitleDigest() string {
	return attemptString(a, func() string { return a.titleDigest })
}
func (a *PullRequestAttempt) BodyDigest() string {
	return attemptString(a, func() string { return a.bodyDigest })
}
func (a *PullRequestAttempt) RepositoryID() int64 {
	if a == nil {
		return 0
	}
	return a.repositoryID
}
func (a *PullRequestAttempt) AuthorityTime() time.Time {
	if a == nil {
		return time.Time{}
	}
	return a.authorityTime
}

func attemptString(a *PullRequestAttempt, getter func() string) string {
	if a == nil {
		return ""
	}
	return getter()
}
