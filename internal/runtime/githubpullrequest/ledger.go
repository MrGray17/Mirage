package githubpullrequest

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/MrGray17/Mirage/internal/contracts"
)

const (
	LedgerVersion        = "mirage.external-effect-ledger/v1"
	PullRequestIDVersion = "mirage.github-pull-request-identity/v1"
)

var (
	ErrInvalidPullRequestIdentity = errors.New("invalid exact GitHub pull-request identity")
	ErrInvalidLedger              = errors.New("invalid external-effect ledger")
)

type ObservationStatus string

const (
	ObservationAbsent      ObservationStatus = "ABSENT"
	ObservationExact       ObservationStatus = "PRESENT_EXACT"
	ObservationConflicting ObservationStatus = "PRESENT_CONFLICTING"
	ObservationUnavailable ObservationStatus = "UNAVAILABLE"
)

type PullRequestOutcome string

const (
	OutcomeNotAttempted   PullRequestOutcome = "NOT_ATTEMPTED"
	OutcomeNotCreated     PullRequestOutcome = "NOT_CREATED"
	OutcomeAlreadyPresent PullRequestOutcome = "ALREADY_PRESENT"
	OutcomeCreated        PullRequestOutcome = "CREATED"
	OutcomeConflict       PullRequestOutcome = "CONFLICTED"
	OutcomeUncertain      PullRequestOutcome = "UNCERTAIN"
)

type Causality string

const (
	CausalityNone               Causality = "NONE"
	CausalityPreexisting        Causality = "PREEXISTING"
	CausalityMirageAcknowledged Causality = "MIRAGE_ACKNOWLEDGED"
	CausalityUnknown            Causality = "UNKNOWN"
)

type PullRequestIdentitySpec struct {
	Plan               *Plan
	Number             int64
	StableID           int64
	URL                string
	RepositoryID       int64
	RepositoryFullName string
	BaseRef            string
	TargetRef          string
	HeadOID            string
	MetadataPolicy     string
	Title              string
	Body               string
	Draft              bool
	Open               bool
}

type PullRequestIdentity struct {
	identity           string
	number             int64
	stableID           int64
	url                string
	repositoryID       int64
	repositoryFullName string
	baseRef            string
	targetRef          string
	headOID            string
	metadataPolicy     string
	titleDigest        string
	bodyDigest         string
}

type canonicalPullRequestIdentity struct {
	Version            string `json:"version"`
	Number             int64  `json:"number"`
	StableID           int64  `json:"stable_id"`
	URL                string `json:"url"`
	RepositoryID       int64  `json:"repository_id"`
	RepositoryFullName string `json:"repository_full_name"`
	BaseRef            string `json:"base_ref"`
	TargetRef          string `json:"target_ref"`
	HeadOID            string `json:"head_oid"`
	MetadataPolicy     string `json:"metadata_policy"`
	TitleDigest        string `json:"title_digest"`
	BodyDigest         string `json:"body_digest"`
}

func NewPullRequestIdentity(spec PullRequestIdentitySpec) (*PullRequestIdentity, error) {
	if spec.Plan == nil || spec.Plan.Metadata() == nil || spec.Number <= 0 || spec.StableID <= 0 || spec.Draft || !spec.Open || spec.RepositoryID != spec.Plan.RepositoryID() || spec.RepositoryFullName != spec.Plan.RepositoryFullName() || spec.BaseRef != spec.Plan.BaseRef() || spec.TargetRef != spec.Plan.TargetRef() || spec.HeadOID != spec.Plan.CommitOID() || spec.MetadataPolicy != spec.Plan.Metadata().Version() || spec.Title != spec.Plan.Metadata().Title() || spec.Body != spec.Plan.Metadata().Body() {
		return nil, fmt.Errorf("%w: observed PR does not equal the authorized plan", ErrInvalidPullRequestIdentity)
	}
	expectedURL := "https://github.com/" + spec.RepositoryFullName + "/pull/" + strconv.FormatInt(spec.Number, 10)
	parsed, err := url.Parse(spec.URL)
	if err != nil || spec.URL != expectedURL || parsed.Scheme != "https" || parsed.Host != "github.com" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%w: PR URL is not the exact canonical github.com URL", ErrInvalidPullRequestIdentity)
	}
	canonical := canonicalPullRequestIdentity{Version: PullRequestIDVersion, Number: spec.Number, StableID: spec.StableID, URL: spec.URL, RepositoryID: spec.RepositoryID, RepositoryFullName: spec.RepositoryFullName, BaseRef: spec.BaseRef, TargetRef: spec.TargetRef, HeadOID: spec.HeadOID, MetadataPolicy: spec.MetadataPolicy, TitleDigest: bytesDigest([]byte(spec.Title)), BodyDigest: bytesDigest([]byte(spec.Body))}
	identity, err := canonicalHash(canonical)
	if err != nil {
		return nil, err
	}
	return &PullRequestIdentity{identity: identity, number: spec.Number, stableID: spec.StableID, url: spec.URL, repositoryID: spec.RepositoryID, repositoryFullName: spec.RepositoryFullName, baseRef: spec.BaseRef, targetRef: spec.TargetRef, headOID: spec.HeadOID, metadataPolicy: spec.MetadataPolicy, titleDigest: canonical.TitleDigest, bodyDigest: canonical.BodyDigest}, nil
}

func (p *PullRequestIdentity) Identity() string {
	return prString(p, func() string { return p.identity })
}
func (p *PullRequestIdentity) URL() string { return prString(p, func() string { return p.url }) }
func (p *PullRequestIdentity) RepositoryFullName() string {
	return prString(p, func() string { return p.repositoryFullName })
}
func (p *PullRequestIdentity) BaseRef() string {
	return prString(p, func() string { return p.baseRef })
}
func (p *PullRequestIdentity) TargetRef() string {
	return prString(p, func() string { return p.targetRef })
}
func (p *PullRequestIdentity) HeadOID() string {
	return prString(p, func() string { return p.headOID })
}
func (p *PullRequestIdentity) MetadataPolicy() string {
	return prString(p, func() string { return p.metadataPolicy })
}
func (p *PullRequestIdentity) TitleDigest() string {
	return prString(p, func() string { return p.titleDigest })
}
func (p *PullRequestIdentity) BodyDigest() string {
	return prString(p, func() string { return p.bodyDigest })
}
func (p *PullRequestIdentity) Number() int64 {
	if p == nil {
		return 0
	}
	return p.number
}
func (p *PullRequestIdentity) StableID() int64 {
	if p == nil {
		return 0
	}
	return p.stableID
}
func (p *PullRequestIdentity) RepositoryID() int64 {
	if p == nil {
		return 0
	}
	return p.repositoryID
}

func prString(p *PullRequestIdentity, getter func() string) string {
	if p == nil {
		return ""
	}
	return getter()
}

type Observation struct {
	Status   ObservationStatus
	Exact    *PullRequestIdentity
	Evidence string
}

type LedgerSpec struct {
	Previous                  *ExternalEffectLedger
	Plan                      *Plan
	Attempt                   *PullRequestAttempt
	Outcome                   PullRequestOutcome
	Observation               Observation
	Postflight                bool
	CompatibleAcknowledgement bool
	Reconciled                bool
	Causality                 Causality
}

type ExternalEffectLedger struct {
	identity         string
	previousIdentity string
	planIdentity     string
	branch           canonicalBranchEffect
	pullRequest      canonicalPullRequestEffect
}

type canonicalBranchEffect struct {
	Operation                 contracts.GitHubPublicationOperation `json:"operation"`
	Outcome                   string                               `json:"outcome"`
	Ref                       string                               `json:"ref"`
	OID                       string                               `json:"oid"`
	PublicationRecordIdentity string                               `json:"publication_record_identity"`
}

type canonicalPullRequestEffect struct {
	Operation             contracts.GitHubPublicationOperation `json:"operation"`
	Outcome               PullRequestOutcome                   `json:"outcome"`
	Attempted             bool                                 `json:"attempted"`
	RepositoryID          int64                                `json:"repository_id"`
	RepositoryFullName    string                               `json:"repository_full_name"`
	BaseRef               string                               `json:"base_ref"`
	TargetRef             string                               `json:"target_ref"`
	HeadOID               string                               `json:"head_oid"`
	MetadataPolicy        string                               `json:"metadata_policy"`
	TitleDigest           string                               `json:"title_digest"`
	BodyDigest            string                               `json:"body_digest"`
	Number                int64                                `json:"number"`
	StableID              int64                                `json:"stable_id"`
	URL                   string                               `json:"url"`
	PullRequestIdentity   string                               `json:"pull_request_identity"`
	PlanIdentity          string                               `json:"plan_identity"`
	AttemptIdentity       string                               `json:"attempt_identity"`
	Observation           ObservationStatus                    `json:"observation"`
	ConflictEvidence      string                               `json:"conflict_evidence"`
	TransportAcknowledged bool                                 `json:"transport_acknowledged"`
	ExactPostflight       bool                                 `json:"exact_postflight"`
	Reconciled            bool                                 `json:"reconciled"`
	Causality             Causality                            `json:"causality"`
}

type canonicalLedger struct {
	Version          string                     `json:"version"`
	PreviousIdentity string                     `json:"previous_identity"`
	ManifestHash     string                     `json:"manifest_hash"`
	ContractHash     string                     `json:"contract_hash"`
	PlanIdentity     string                     `json:"plan_identity"`
	Branch           canonicalBranchEffect      `json:"branch_effect"`
	PullRequest      canonicalPullRequestEffect `json:"pull_request_effect"`
}

func NewExternalEffectLedger(spec LedgerSpec) (*ExternalEffectLedger, error) {
	if spec.Plan == nil || spec.Plan.Identity() == "" {
		return nil, fmt.Errorf("%w: PR plan is unavailable", ErrInvalidLedger)
	}
	attempted := spec.Attempt != nil
	if attempted && (spec.Attempt.PlanIdentity() != spec.Plan.Identity() || spec.Attempt.RepositoryID() != spec.Plan.RepositoryID() || spec.Attempt.BaseRef() != spec.Plan.BaseRef() || spec.Attempt.TargetRef() != spec.Plan.TargetRef() || spec.Attempt.CommitOID() != spec.Plan.CommitOID()) {
		return nil, fmt.Errorf("%w: attempt does not bind the plan", ErrInvalidLedger)
	}
	if spec.CompatibleAcknowledgement && !attempted {
		return nil, fmt.Errorf("%w: acknowledgement without an attempt", ErrInvalidLedger)
	}
	if len(spec.Observation.Evidence) > 128 || strings.ContainsAny(spec.Observation.Evidence, "\r\n\x00") {
		return nil, fmt.Errorf("%w: conflict evidence is unbounded", ErrInvalidLedger)
	}
	if err := validateOutcome(spec, attempted); err != nil {
		return nil, err
	}
	if err := validateLedgerTransition(spec); err != nil {
		return nil, err
	}
	branch := canonicalBranchEffect{Operation: contracts.GitHubCreateBranch, Outcome: "PUBLISHED", Ref: spec.Plan.TargetRef(), OID: spec.Plan.CommitOID(), PublicationRecordIdentity: spec.Plan.PublicationRecordIdentity()}
	pr := canonicalPullRequestEffect{
		Operation: contracts.GitHubCreatePullRequest, Outcome: spec.Outcome, Attempted: attempted, RepositoryID: spec.Plan.RepositoryID(), RepositoryFullName: spec.Plan.RepositoryFullName(), BaseRef: spec.Plan.BaseRef(), TargetRef: spec.Plan.TargetRef(), HeadOID: spec.Plan.CommitOID(),
		MetadataPolicy: spec.Plan.Metadata().Version(), TitleDigest: spec.Plan.Metadata().TitleDigest(), BodyDigest: spec.Plan.Metadata().BodyDigest(), PlanIdentity: spec.Plan.Identity(), Observation: spec.Observation.Status, ConflictEvidence: spec.Observation.Evidence,
		TransportAcknowledged: spec.CompatibleAcknowledgement, ExactPostflight: spec.Postflight && spec.Observation.Status == ObservationExact, Reconciled: spec.Reconciled, Causality: spec.Causality,
	}
	if attempted {
		pr.AttemptIdentity = spec.Attempt.Identity()
	}
	if spec.Observation.Exact != nil {
		exact := spec.Observation.Exact
		pr.Number, pr.StableID, pr.URL, pr.PullRequestIdentity = exact.Number(), exact.StableID(), exact.URL(), exact.Identity()
	}
	previousIdentity := ""
	if spec.Previous != nil {
		if spec.Previous.planIdentity != spec.Plan.Identity() || spec.Previous.branch != branch {
			return nil, fmt.Errorf("%w: prior ledger belongs to different authority", ErrInvalidLedger)
		}
		previousIdentity = spec.Previous.identity
	}
	canonical := canonicalLedger{Version: LedgerVersion, PreviousIdentity: previousIdentity, ManifestHash: spec.Plan.ManifestHash(), ContractHash: spec.Plan.ContractHash(), PlanIdentity: spec.Plan.Identity(), Branch: branch, PullRequest: pr}
	identity, err := canonicalHash(canonical)
	if err != nil {
		return nil, err
	}
	return &ExternalEffectLedger{identity: identity, previousIdentity: previousIdentity, planIdentity: spec.Plan.Identity(), branch: branch, pullRequest: pr}, nil
}

func validateLedgerTransition(spec LedgerSpec) error {
	if spec.Previous == nil {
		if spec.Outcome != OutcomeNotAttempted {
			return fmt.Errorf("%w: the initial snapshot must be NOT_ATTEMPTED", ErrInvalidLedger)
		}
		return nil
	}

	previous := spec.Previous.pullRequest
	switch previous.Outcome {
	case OutcomeNotAttempted:
		if spec.Outcome == OutcomeNotAttempted {
			return fmt.Errorf("%w: a ledger update must add new external-effect evidence", ErrInvalidLedger)
		}
	case OutcomeUncertain:
		if spec.Attempt == nil || spec.Attempt.Identity() != previous.AttemptIdentity || spec.CompatibleAcknowledgement != previous.TransportAcknowledged || spec.Outcome == OutcomeNotAttempted {
			return fmt.Errorf("%w: uncertain reconciliation must retain the exact attempt and acknowledgement evidence", ErrInvalidLedger)
		}
	default:
		return fmt.Errorf("%w: terminal PR evidence cannot be rewritten or downgraded", ErrInvalidLedger)
	}
	return nil
}

func validateOutcome(spec LedgerSpec, attempted bool) error {
	exact := spec.Observation.Status == ObservationExact && spec.Observation.Exact != nil
	switch spec.Outcome {
	case OutcomeNotAttempted:
		if attempted || spec.CompatibleAcknowledgement || spec.Postflight || exact || spec.Causality != CausalityNone {
			return fmt.Errorf("%w: NOT_ATTEMPTED contains mutation or established evidence", ErrInvalidLedger)
		}
	case OutcomeNotCreated:
		if !attempted || !spec.Postflight || spec.Observation.Status != ObservationAbsent || spec.Observation.Exact != nil || spec.CompatibleAcknowledgement || spec.Causality != CausalityNone {
			return fmt.Errorf("%w: NOT_CREATED requires attempted POST and authoritative absence", ErrInvalidLedger)
		}
	case OutcomeCreated:
		if !attempted || !spec.Postflight || !exact || !spec.CompatibleAcknowledgement || spec.Causality != CausalityMirageAcknowledged {
			return fmt.Errorf("%w: CREATED requires acknowledged compatible creation and exact postflight", ErrInvalidLedger)
		}
	case OutcomeAlreadyPresent:
		if !exact || spec.CompatibleAcknowledgement {
			return fmt.Errorf("%w: ALREADY_PRESENT requires exact state without compatible acknowledgement", ErrInvalidLedger)
		}
		if attempted {
			if !spec.Postflight || spec.Causality != CausalityUnknown {
				return fmt.Errorf("%w: post-attempt ALREADY_PRESENT requires unknown causality", ErrInvalidLedger)
			}
		} else if spec.Postflight || spec.Causality != CausalityPreexisting {
			return fmt.Errorf("%w: preexisting exact PR must remain non-attempted", ErrInvalidLedger)
		}
	case OutcomeConflict:
		if spec.Observation.Status != ObservationConflicting || spec.Observation.Exact != nil || spec.Causality != CausalityNone || spec.Postflight != attempted {
			return fmt.Errorf("%w: CONFLICTED requires matching preflight/attempt evidence", ErrInvalidLedger)
		}
	case OutcomeUncertain:
		if !attempted || !spec.Postflight || spec.Observation.Status != ObservationUnavailable || spec.Observation.Exact != nil || spec.Causality != CausalityUnknown {
			return fmt.Errorf("%w: UNCERTAIN requires attempted POST and unavailable postflight", ErrInvalidLedger)
		}
	default:
		return fmt.Errorf("%w: unknown PR outcome %q", ErrInvalidLedger, spec.Outcome)
	}
	if exact {
		pr := spec.Observation.Exact
		if pr.RepositoryID() != spec.Plan.RepositoryID() || pr.RepositoryFullName() != spec.Plan.RepositoryFullName() || pr.BaseRef() != spec.Plan.BaseRef() || pr.TargetRef() != spec.Plan.TargetRef() || pr.HeadOID() != spec.Plan.CommitOID() || pr.MetadataPolicy() != spec.Plan.Metadata().Version() || pr.TitleDigest() != spec.Plan.Metadata().TitleDigest() || pr.BodyDigest() != spec.Plan.Metadata().BodyDigest() || pr.Number() <= 0 || pr.StableID() <= 0 || pr.URL() == "" {
			return fmt.Errorf("%w: established PR identity differs from the plan", ErrInvalidLedger)
		}
	} else if spec.Observation.Exact != nil {
		return fmt.Errorf("%w: non-exact observation contains exact identity", ErrInvalidLedger)
	}
	return nil
}

func (l *ExternalEffectLedger) Identity() string {
	if l == nil {
		return ""
	}
	return l.identity
}
func (l *ExternalEffectLedger) PreviousIdentity() string {
	if l == nil {
		return ""
	}
	return l.previousIdentity
}
func (l *ExternalEffectLedger) PullRequestOutcome() PullRequestOutcome {
	if l == nil {
		return ""
	}
	return l.pullRequest.Outcome
}
func (l *ExternalEffectLedger) Attempted() bool { return l != nil && l.pullRequest.Attempted }
func (l *ExternalEffectLedger) AttemptIdentity() string {
	if l == nil {
		return ""
	}
	return l.pullRequest.AttemptIdentity
}
func (l *ExternalEffectLedger) ObservationStatus() ObservationStatus {
	if l == nil {
		return ""
	}
	return l.pullRequest.Observation
}
func (l *ExternalEffectLedger) TransportAcknowledged() bool {
	return l != nil && l.pullRequest.TransportAcknowledged
}
func (l *ExternalEffectLedger) Causality() Causality {
	if l == nil {
		return ""
	}
	return l.pullRequest.Causality
}
func (l *ExternalEffectLedger) PullRequestNumber() int64 {
	if l == nil {
		return 0
	}
	return l.pullRequest.Number
}
func (l *ExternalEffectLedger) PullRequestStableID() int64 {
	if l == nil {
		return 0
	}
	return l.pullRequest.StableID
}
func (l *ExternalEffectLedger) PullRequestURL() string {
	if l == nil {
		return ""
	}
	return l.pullRequest.URL
}
