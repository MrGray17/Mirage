package gitpublication

import (
	"fmt"
	"time"

	"github.com/MrGray17/Mirage/internal/runtime/githubbinding"
)

const RecordVersion = "mirage.git-publication-record/v1"

type Outcome string

const (
	OutcomePublished            Outcome = "PUBLISHED"
	OutcomeNotPublished         Outcome = "NOT_PUBLISHED"
	OutcomeConflicted           Outcome = "CONFLICTED"
	OutcomePublicationUncertain Outcome = "PUBLICATION_UNCERTAIN"
)

type TransportOutcome string

const (
	TransportAcknowledged TransportOutcome = "ACKNOWLEDGED"
	TransportFailed       TransportOutcome = "FAILED_OR_UNACKNOWLEDGED"
)

type Record struct {
	version                  string
	identity                 string
	manifestHash             string
	contractHash             string
	publicationPlanIdentity  string
	artifactIdentity         string
	commitOID                string
	githubBindingIdentity    string
	repositoryID             int64
	repositoryFullName       string
	targetRef                string
	attemptIdentity          string
	dispatchTime             time.Time
	transport                TransportOutcome
	observedStatus           githubbinding.RefStatus
	observedOID              string
	transportAcknowledged    bool
	resolvedByReconciliation bool
	outcome                  Outcome
}

type canonicalRecord struct {
	Version                  string                  `json:"version"`
	ManifestHash             string                  `json:"manifest_hash"`
	ContractHash             string                  `json:"contract_hash"`
	PublicationPlanIdentity  string                  `json:"publication_plan_identity"`
	ArtifactIdentity         string                  `json:"artifact_identity"`
	CommitOID                string                  `json:"commit_oid"`
	GitHubBindingIdentity    string                  `json:"github_binding_identity"`
	RepositoryID             int64                   `json:"repository_id"`
	RepositoryFullName       string                  `json:"repository_full_name"`
	TargetRef                string                  `json:"target_ref"`
	AttemptIdentity          string                  `json:"attempt_identity"`
	DispatchTime             string                  `json:"dispatch_time"`
	Transport                TransportOutcome        `json:"transport"`
	ObservedStatus           githubbinding.RefStatus `json:"observed_status"`
	ObservedOID              string                  `json:"observed_oid,omitempty"`
	TransportAcknowledged    bool                    `json:"transport_acknowledged"`
	ResolvedByReconciliation bool                    `json:"resolved_by_reconciliation"`
	Outcome                  Outcome                 `json:"outcome"`
}

func newRecord(plan *Plan, dispatch time.Time, acknowledged bool, observation githubbinding.RefObservation, outcome Outcome) (*Record, error) {
	if plan == nil || dispatch.IsZero() || dispatch.UTC().Before(plan.CreatedAt()) || !validRecordObservation(plan.CommitOID(), observation) {
		return nil, fmt.Errorf("invalid publication record evidence")
	}
	expectedOutcome, err := reconcileOutcome(observation, acknowledged)
	if err != nil || expectedOutcome != outcome {
		return nil, fmt.Errorf("publication outcome differs from observed ref")
	}
	transport := TransportFailed
	if acknowledged {
		transport = TransportAcknowledged
	}
	attempt, err := hashCanonical(struct {
		Plan     string `json:"plan"`
		Dispatch string `json:"dispatch"`
	}{plan.Identity(), dispatch.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return nil, err
	}
	canonical := canonicalRecord{Version: RecordVersion, ManifestHash: plan.ManifestHash(), ContractHash: plan.ContractHash(), PublicationPlanIdentity: plan.Identity(), ArtifactIdentity: plan.ArtifactIdentity(), CommitOID: plan.CommitOID(), GitHubBindingIdentity: plan.GitHubBindingIdentity(), RepositoryID: plan.GitHubRepositoryID(), RepositoryFullName: plan.RepositoryFullName(), TargetRef: plan.TargetRef(), AttemptIdentity: attempt, DispatchTime: dispatch.UTC().Format(time.RFC3339Nano), Transport: transport, ObservedStatus: observation.Status, ObservedOID: observation.OID, TransportAcknowledged: acknowledged, ResolvedByReconciliation: observation.Status != githubbinding.RefUnavailable, Outcome: outcome}
	identity, err := hashCanonical(canonical)
	if err != nil {
		return nil, err
	}
	return &Record{version: RecordVersion, identity: identity, manifestHash: canonical.ManifestHash, contractHash: canonical.ContractHash, publicationPlanIdentity: canonical.PublicationPlanIdentity, artifactIdentity: canonical.ArtifactIdentity, commitOID: canonical.CommitOID, githubBindingIdentity: canonical.GitHubBindingIdentity, repositoryID: canonical.RepositoryID, repositoryFullName: canonical.RepositoryFullName, targetRef: canonical.TargetRef, attemptIdentity: attempt, dispatchTime: dispatch.UTC(), transport: transport, observedStatus: observation.Status, observedOID: observation.OID, transportAcknowledged: acknowledged, resolvedByReconciliation: canonical.ResolvedByReconciliation, outcome: outcome}, nil
}

// NewRecordForObservation derives immutable evidence from one attempted plan
// and the authoritative post-attempt observation. Records are data only and do
// not grant publication authority.
func NewRecordForObservation(plan *Plan, dispatch time.Time, acknowledged bool, observation githubbinding.RefObservation) (*Record, error) {
	outcome, err := reconcileOutcome(observation, acknowledged)
	if err != nil {
		return nil, err
	}
	return newRecord(plan, dispatch, acknowledged, observation, outcome)
}

// ReconciledRecord creates new immutable evidence for a later read-only
// observation while preserving the original attempt and transport facts.
func ReconciledRecord(previous *Record, observation githubbinding.RefObservation, outcome Outcome) (*Record, error) {
	if previous == nil || previous.identity == "" {
		return nil, fmt.Errorf("publication record is unavailable")
	}
	expectedOutcome, outcomeErr := reconcileOutcome(observation, false)
	if outcomeErr != nil || expectedOutcome != outcome || !validRecordObservation(previous.commitOID, observation) {
		return nil, fmt.Errorf("invalid reconciled publication evidence")
	}
	canonical := canonicalRecord{Version: RecordVersion, ManifestHash: previous.manifestHash, ContractHash: previous.contractHash, PublicationPlanIdentity: previous.publicationPlanIdentity, ArtifactIdentity: previous.artifactIdentity, CommitOID: previous.commitOID, GitHubBindingIdentity: previous.githubBindingIdentity, RepositoryID: previous.repositoryID, RepositoryFullName: previous.repositoryFullName, TargetRef: previous.targetRef, AttemptIdentity: previous.attemptIdentity, DispatchTime: previous.dispatchTime.Format(time.RFC3339Nano), Transport: previous.transport, ObservedStatus: observation.Status, ObservedOID: observation.OID, TransportAcknowledged: previous.transportAcknowledged, ResolvedByReconciliation: true, Outcome: outcome}
	identity, err := hashCanonical(canonical)
	if err != nil {
		return nil, err
	}
	return &Record{version: RecordVersion, identity: identity, manifestHash: previous.manifestHash, contractHash: previous.contractHash, publicationPlanIdentity: previous.publicationPlanIdentity, artifactIdentity: previous.artifactIdentity, commitOID: previous.commitOID, githubBindingIdentity: previous.githubBindingIdentity, repositoryID: previous.repositoryID, repositoryFullName: previous.repositoryFullName, targetRef: previous.targetRef, attemptIdentity: previous.attemptIdentity, dispatchTime: previous.dispatchTime, transport: previous.transport, observedStatus: observation.Status, observedOID: observation.OID, transportAcknowledged: previous.transportAcknowledged, resolvedByReconciliation: true, outcome: outcome}, nil
}

func validRecordObservation(commitOID string, observation githubbinding.RefObservation) bool {
	switch observation.Status {
	case githubbinding.RefPresentExact:
		return observation.OID == commitOID && validOID(observation.OID)
	case githubbinding.RefPresentOther:
		return observation.OID != commitOID && validOID(observation.OID)
	case githubbinding.RefAbsent, githubbinding.RefUnavailable:
		return observation.OID == ""
	default:
		return false
	}
}

func (r *Record) Version() string  { return recordString(r, func() string { return r.version }) }
func (r *Record) Identity() string { return recordString(r, func() string { return r.identity }) }
func (r *Record) ManifestHash() string {
	return recordString(r, func() string { return r.manifestHash })
}
func (r *Record) ContractHash() string {
	return recordString(r, func() string { return r.contractHash })
}
func (r *Record) PublicationPlanIdentity() string {
	return recordString(r, func() string { return r.publicationPlanIdentity })
}
func (r *Record) ArtifactIdentity() string {
	return recordString(r, func() string { return r.artifactIdentity })
}
func (r *Record) CommitOID() string { return recordString(r, func() string { return r.commitOID }) }
func (r *Record) GitHubBindingIdentity() string {
	return recordString(r, func() string { return r.githubBindingIdentity })
}
func (r *Record) RepositoryFullName() string {
	return recordString(r, func() string { return r.repositoryFullName })
}
func (r *Record) TargetRef() string { return recordString(r, func() string { return r.targetRef }) }
func (r *Record) AttemptIdentity() string {
	return recordString(r, func() string { return r.attemptIdentity })
}
func (r *Record) ObservedOID() string { return recordString(r, func() string { return r.observedOID }) }
func (r *Record) RepositoryID() int64 {
	if r == nil {
		return 0
	}
	return r.repositoryID
}
func (r *Record) DispatchTime() time.Time {
	if r == nil {
		return time.Time{}
	}
	return r.dispatchTime
}
func (r *Record) Transport() TransportOutcome {
	if r == nil {
		return ""
	}
	return r.transport
}
func (r *Record) ObservedStatus() githubbinding.RefStatus {
	if r == nil {
		return ""
	}
	return r.observedStatus
}
func (r *Record) TransportAcknowledged() bool    { return r != nil && r.transportAcknowledged }
func (r *Record) ResolvedByReconciliation() bool { return r != nil && r.resolvedByReconciliation }
func (r *Record) Outcome() Outcome {
	if r == nil {
		return ""
	}
	return r.outcome
}
func recordString(r *Record, getter func() string) string {
	if r == nil {
		return ""
	}
	return getter()
}

func reconcileOutcome(observation githubbinding.RefObservation, acknowledged bool) (Outcome, error) {
	switch observation.Status {
	case githubbinding.RefPresentExact:
		return OutcomePublished, nil
	case githubbinding.RefPresentOther:
		return OutcomeConflicted, nil
	case githubbinding.RefAbsent:
		return OutcomeNotPublished, nil
	case githubbinding.RefUnavailable:
		return OutcomePublicationUncertain, nil
	default:
		return OutcomePublicationUncertain, fmt.Errorf("unknown authoritative remote observation")
	}
}
