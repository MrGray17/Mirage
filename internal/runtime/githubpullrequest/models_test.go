package githubpullrequest

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	testContractHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testRecordHash   = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testCommitOID    = "cccccccccccccccccccccccccccccccccccccccc"
	testBaseOID      = "dddddddddddddddddddddddddddddddddddddddd"
)

func TestMetadataIsDeterministicBoundedAndMarkdownSafe(t *testing.T) {
	spec := MetadataSpec{RunID: "run-1", ContractHash: testContractHash, Operation: "MODIFY", Resource: "/workspace/docs/a`@[*].md", CommitOID: testCommitOID, PublicationRecordIdentity: testRecordHash}
	first, err := NewMetadata(spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewMetadata(spec)
	if err != nil || first.Identity() != second.Identity() || first.Title() != second.Title() || first.Body() != second.Body() {
		t.Fatalf("metadata is not deterministic: second=%#v err=%v", second, err)
	}
	if len(first.Title()) > maxTitleBytes || len(first.Body()) > maxBodyBytes || strings.Contains(first.Body(), spec.Resource) || strings.Contains(first.Body(), "@[") || !strings.Contains(first.Body(), "resource_b64url") || !validDigest(first.ResourceDigest()) {
		t.Fatalf("unsafe generated metadata: title=%q body=%q", first.Title(), first.Body())
	}
	for name, mutate := range map[string]func(*MetadataSpec){
		"raw operation": func(spec *MetadataSpec) { spec.Operation = "CREATE" },
		"bad contract":  func(spec *MetadataSpec) { spec.ContractHash = "bad" },
		"bad OID":       func(spec *MetadataSpec) { spec.CommitOID = "bad" },
		"bad record":    func(spec *MetadataSpec) { spec.PublicationRecordIdentity = "bad" },
		"bad resource":  func(spec *MetadataSpec) { spec.Resource = "README.md" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := spec
			mutate(&candidate)
			if _, err := NewMetadata(candidate); !errors.Is(err, ErrInvalidMetadata) {
				t.Fatalf("error=%v, want ErrInvalidMetadata", err)
			}
		})
	}
}

func TestPlanAndAttemptCanonicalIdentity(t *testing.T) {
	plan := testPlan(t)
	second := testPlan(t)
	if plan.Identity() != second.Identity() || plan.Metadata().Identity() != second.Metadata().Identity() {
		t.Fatal("identical authority produced different plan")
	}
	at := plan.CreatedAt().Add(time.Second)
	attempt, err := NewPullRequestAttempt(plan, at)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewPullRequestAttempt(plan, at)
	if err != nil || other.Identity() != attempt.Identity() || !validDigest(attempt.RequestDigest()) {
		t.Fatalf("attempt not deterministic: %#v %v", other, err)
	}
	request, err := canonicalRequestBytes(plan)
	if err != nil || bytesDigest(request) != attempt.RequestDigest() || strings.Contains(string(request), "github.com") || strings.Contains(string(request), "token") {
		t.Fatalf("request binding=%q err=%v", request, err)
	}
	if _, err := NewPullRequestAttempt(plan, plan.CreatedAt().Add(-time.Nanosecond)); !errors.Is(err, ErrInvalidAttempt) {
		t.Fatalf("rollback attempt error=%v", err)
	}
}

func TestLedgerAcceptsOnlyTruthfulOutcomeShapes(t *testing.T) {
	plan := testPlan(t)
	attempt, err := NewPullRequestAttempt(plan, plan.CreatedAt().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	exact := testPullRequestIdentity(t, plan)

	initial := mustLedger(t, LedgerSpec{Plan: plan, Outcome: OutcomeNotAttempted, Causality: CausalityNone})
	if initial.Attempted() || initial.PullRequestOutcome() != OutcomeNotAttempted {
		t.Fatalf("initial ledger=%#v", initial)
	}
	preexisting := mustLedger(t, LedgerSpec{Previous: initial, Plan: plan, Outcome: OutcomeAlreadyPresent, Observation: Observation{Status: ObservationExact, Exact: exact}, Causality: CausalityPreexisting})
	if preexisting.Attempted() || preexisting.PullRequestNumber() != 17 || preexisting.PreviousIdentity() != initial.Identity() {
		t.Fatalf("preexisting ledger=%#v", preexisting)
	}
	created := mustLedger(t, LedgerSpec{Previous: initial, Plan: plan, Attempt: attempt, Outcome: OutcomeCreated, Observation: Observation{Status: ObservationExact, Exact: exact}, Postflight: true, CompatibleAcknowledgement: true, Reconciled: true, Causality: CausalityMirageAcknowledged})
	if !created.Attempted() || !created.TransportAcknowledged() || created.Causality() != CausalityMirageAcknowledged || created.PullRequestURL() == "" || created.PullRequestBaseCommit() != plan.BaseCommit() {
		t.Fatalf("created ledger=%#v", created)
	}
	mustLedger(t, LedgerSpec{Previous: initial, Plan: plan, Attempt: attempt, Outcome: OutcomeAlreadyPresent, Observation: Observation{Status: ObservationExact, Exact: exact}, Postflight: true, Reconciled: true, Causality: CausalityUnknown})
	mustLedger(t, LedgerSpec{Previous: initial, Plan: plan, Attempt: attempt, Outcome: OutcomeNotCreated, Observation: Observation{Status: ObservationAbsent}, Postflight: true, Reconciled: true, Causality: CausalityNone})
	mustLedger(t, LedgerSpec{Previous: initial, Plan: plan, Attempt: attempt, Outcome: OutcomeUncertain, Observation: Observation{Status: ObservationUnavailable}, Postflight: true, Causality: CausalityUnknown})
	mustLedger(t, LedgerSpec{Previous: initial, Plan: plan, Outcome: OutcomeConflict, Observation: Observation{Status: ObservationConflicting, Evidence: "closed"}, Causality: CausalityNone})
	mustLedger(t, LedgerSpec{Previous: initial, Plan: plan, Attempt: attempt, Outcome: OutcomeConflict, Observation: Observation{Status: ObservationConflicting, Evidence: "race"}, Postflight: true, Causality: CausalityNone})
}

func TestLedgerRejectsImpossibleSnapshots(t *testing.T) {
	plan := testPlan(t)
	attempt, err := NewPullRequestAttempt(plan, plan.CreatedAt().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	exact := testPullRequestIdentity(t, plan)
	wrong := *exact
	wrong.repositoryID++
	wrongBase := *exact
	wrongBase.baseCommit = plan.CommitOID()

	tests := map[string]LedgerSpec{
		"created without identity":        {Plan: plan, Attempt: attempt, Outcome: OutcomeCreated, Observation: Observation{Status: ObservationExact}, Postflight: true, CompatibleAcknowledgement: true, Causality: CausalityMirageAcknowledged},
		"created without postflight":      {Plan: plan, Attempt: attempt, Outcome: OutcomeCreated, Observation: Observation{Status: ObservationExact, Exact: exact}, CompatibleAcknowledgement: true, Causality: CausalityMirageAcknowledged},
		"created without acknowledgement": {Plan: plan, Attempt: attempt, Outcome: OutcomeCreated, Observation: Observation{Status: ObservationExact, Exact: exact}, Postflight: true, Causality: CausalityMirageAcknowledged},
		"not created without attempt":     {Plan: plan, Outcome: OutcomeNotCreated, Observation: Observation{Status: ObservationAbsent}, Postflight: true, Causality: CausalityNone},
		"not attempted with identity":     {Plan: plan, Attempt: attempt, Outcome: OutcomeNotAttempted, Causality: CausalityNone},
		"not attempted acknowledged":      {Plan: plan, Outcome: OutcomeNotAttempted, CompatibleAcknowledgement: true, Causality: CausalityNone},
		"uncertain without attempt":       {Plan: plan, Outcome: OutcomeUncertain, Observation: Observation{Status: ObservationUnavailable}, Postflight: true, Causality: CausalityUnknown},
		"acknowledged wrong causality":    {Plan: plan, Attempt: attempt, Outcome: OutcomeCreated, Observation: Observation{Status: ObservationExact, Exact: exact}, Postflight: true, CompatibleAcknowledgement: true, Causality: CausalityUnknown},
		"established wrong repository":    {Plan: plan, Attempt: attempt, Outcome: OutcomeCreated, Observation: Observation{Status: ObservationExact, Exact: &wrong}, Postflight: true, CompatibleAcknowledgement: true, Causality: CausalityMirageAcknowledged},
		"established wrong base commit":   {Plan: plan, Attempt: attempt, Outcome: OutcomeCreated, Observation: Observation{Status: ObservationExact, Exact: &wrongBase}, Postflight: true, CompatibleAcknowledgement: true, Causality: CausalityMirageAcknowledged},
	}
	for name, spec := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewExternalEffectLedger(spec); !errors.Is(err, ErrInvalidLedger) {
				t.Fatalf("error=%v, want ErrInvalidLedger", err)
			}
		})
	}
}

func TestLedgerRejectsRewrittenOrDowngradedHistory(t *testing.T) {
	plan := testPlan(t)
	attempt, err := NewPullRequestAttempt(plan, plan.CreatedAt().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	otherAttempt, err := NewPullRequestAttempt(plan, plan.CreatedAt().Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	exact := testPullRequestIdentity(t, plan)
	initial := mustLedger(t, LedgerSpec{Plan: plan, Outcome: OutcomeNotAttempted, Causality: CausalityNone})
	created := mustLedger(t, LedgerSpec{Previous: initial, Plan: plan, Attempt: attempt, Outcome: OutcomeCreated, Observation: Observation{Status: ObservationExact, Exact: exact}, Postflight: true, CompatibleAcknowledgement: true, Reconciled: true, Causality: CausalityMirageAcknowledged})
	uncertain := mustLedger(t, LedgerSpec{Previous: initial, Plan: plan, Attempt: attempt, Outcome: OutcomeUncertain, Observation: Observation{Status: ObservationUnavailable}, Postflight: true, Causality: CausalityUnknown})

	tests := map[string]LedgerSpec{
		"noninitial first snapshot":         {Plan: plan, Attempt: attempt, Outcome: OutcomeNotCreated, Observation: Observation{Status: ObservationAbsent}, Postflight: true, Reconciled: true, Causality: CausalityNone},
		"duplicate initial snapshot":        {Previous: initial, Plan: plan, Outcome: OutcomeNotAttempted, Causality: CausalityNone},
		"terminal result downgraded":        {Previous: created, Plan: plan, Attempt: attempt, Outcome: OutcomeNotCreated, Observation: Observation{Status: ObservationAbsent}, Postflight: true, Reconciled: true, Causality: CausalityNone},
		"uncertain loses attempt":           {Previous: uncertain, Plan: plan, Outcome: OutcomeConflict, Observation: Observation{Status: ObservationConflicting, Evidence: "changed"}, Causality: CausalityNone},
		"uncertain changes attempt":         {Previous: uncertain, Plan: plan, Attempt: otherAttempt, Outcome: OutcomeNotCreated, Observation: Observation{Status: ObservationAbsent}, Postflight: true, Reconciled: true, Causality: CausalityNone},
		"uncertain changes acknowledgement": {Previous: uncertain, Plan: plan, Attempt: attempt, Outcome: OutcomeCreated, Observation: Observation{Status: ObservationExact, Exact: exact}, Postflight: true, CompatibleAcknowledgement: true, Reconciled: true, Causality: CausalityMirageAcknowledged},
	}
	for name, spec := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewExternalEffectLedger(spec); !errors.Is(err, ErrInvalidLedger) {
				t.Fatalf("error=%v, want ErrInvalidLedger", err)
			}
		})
	}
}

func TestPullRequestIdentityRequiresExactExternalIdentity(t *testing.T) {
	plan := testPlan(t)
	valid := PullRequestIdentitySpec{Plan: plan, Number: 17, StableID: 1700, URL: "https://github.com/owner/repo/pull/17", RepositoryID: plan.RepositoryID(), RepositoryFullName: plan.RepositoryFullName(), BaseRef: plan.BaseRef(), BaseCommit: plan.BaseCommit(), TargetRef: plan.TargetRef(), HeadOID: plan.CommitOID(), MetadataPolicy: plan.Metadata().Version(), Title: plan.Metadata().Title(), Body: plan.Metadata().Body(), Open: true}
	casePreserving := valid
	casePreserving.URL = "https://github.com/Owner/Repo/pull/17"
	identity, err := NewPullRequestIdentity(casePreserving)
	if err != nil || identity.URL() != valid.URL {
		t.Fatalf("case-preserving provider URL identity=%#v error=%v", identity, err)
	}
	canonicalIdentity, err := NewPullRequestIdentity(valid)
	if err != nil || canonicalIdentity.Identity() != identity.Identity() {
		t.Fatalf("provider display casing changed canonical identity: canonical=%#v display=%#v error=%v", canonicalIdentity, identity, err)
	}
	for name, mutate := range map[string]func(*PullRequestIdentitySpec){
		"missing ID":     func(spec *PullRequestIdentitySpec) { spec.StableID = 0 },
		"wrong URL":      func(spec *PullRequestIdentitySpec) { spec.URL = "https://evil.invalid/pull/17" },
		"wrong repo":     func(spec *PullRequestIdentitySpec) { spec.RepositoryID++ },
		"wrong base":     func(spec *PullRequestIdentitySpec) { spec.BaseRef = "refs/heads/other" },
		"wrong base OID": func(spec *PullRequestIdentitySpec) { spec.BaseCommit = plan.CommitOID() },
		"wrong head":     func(spec *PullRequestIdentitySpec) { spec.TargetRef += "x" },
		"wrong OID":      func(spec *PullRequestIdentitySpec) { spec.HeadOID = testBaseOID },
		"wrong metadata": func(spec *PullRequestIdentitySpec) { spec.Title += "agent" },
		"draft":          func(spec *PullRequestIdentitySpec) { spec.Draft = true },
		"closed":         func(spec *PullRequestIdentitySpec) { spec.Open = false },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := NewPullRequestIdentity(candidate); !errors.Is(err, ErrInvalidPullRequestIdentity) {
				t.Fatalf("error=%v, want ErrInvalidPullRequestIdentity", err)
			}
		})
	}
}

func TestPullRequestIdentityRejectsAmbiguousProviderURLs(t *testing.T) {
	plan := testPlan(t)
	valid := PullRequestIdentitySpec{Plan: plan, Number: 17, StableID: 1700, URL: "https://github.com/owner/repo/pull/17", RepositoryID: plan.RepositoryID(), RepositoryFullName: plan.RepositoryFullName(), BaseRef: plan.BaseRef(), BaseCommit: plan.BaseCommit(), TargetRef: plan.TargetRef(), HeadOID: plan.CommitOID(), MetadataPolicy: plan.Metadata().Version(), Title: plan.Metadata().Title(), Body: plan.Metadata().Body(), Open: true}
	tests := map[string]string{
		"wrong repository":  "https://github.com/owner/other/pull/17",
		"wrong PR number":   "https://github.com/owner/repo/pull/18",
		"evil host":         "https://evil.invalid/owner/repo/pull/17",
		"userinfo":          "https://user@github.com/owner/repo/pull/17",
		"explicit port":     "https://github.com:443/owner/repo/pull/17",
		"query":             "https://github.com/owner/repo/pull/17?view=1",
		"empty query":       "https://github.com/owner/repo/pull/17?",
		"fragment":          "https://github.com/owner/repo/pull/17#issue",
		"extra component":   "https://github.com/owner/repo/pull/17/files",
		"missing component": "https://github.com/owner/pull/17",
		"non-decimal":       "https://github.com/owner/repo/pull/seventeen",
		"leading zero":      "https://github.com/owner/repo/pull/017",
		"percent encoded":   "https://github.com/own%65r/repo/pull/17",
	}
	for name, providerURL := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.URL = providerURL
			if _, err := NewPullRequestIdentity(candidate); !errors.Is(err, ErrInvalidPullRequestIdentity) {
				t.Fatalf("URL=%q error=%v, want ErrInvalidPullRequestIdentity", providerURL, err)
			}
		})
	}
}

func testPlan(t *testing.T) *Plan {
	return testPlanForRepository(t, "owner/repo")
}

func testPlanForRepository(t *testing.T, repository string) *Plan {
	t.Helper()
	metadata, err := NewMetadata(MetadataSpec{RunID: "run-1", ContractHash: testContractHash, Operation: "MODIFY", Resource: "/workspace/README.md", CommitOID: testCommitOID, PublicationRecordIdentity: testRecordHash})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := newPlan(planAuthority{ManifestHash: "sha256:manifest", ContractHash: testContractHash, RepositoryBindingIdentity: "sha256:repository", GitPlanIdentity: "sha256:git-plan", ArtifactIdentity: "sha256:artifact", GitPublicationPlanIdentity: "sha256:publication-plan", PublicationRecordIdentity: testRecordHash, GitHubBindingIdentity: "sha256:github-binding", RepositoryID: 42, RepositoryFullName: repository, BaseRef: "refs/heads/main", BaseCommit: testBaseOID, TargetRef: "refs/heads/mirage/run-123456789012345678901234", CommitOID: testCommitOID, Metadata: metadata, CreatedAt: time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func testPullRequestIdentity(t *testing.T, plan *Plan) *PullRequestIdentity {
	t.Helper()
	identity, err := NewPullRequestIdentity(PullRequestIdentitySpec{Plan: plan, Number: 17, StableID: 1700, URL: "https://github.com/owner/repo/pull/17", RepositoryID: plan.RepositoryID(), RepositoryFullName: plan.RepositoryFullName(), BaseRef: plan.BaseRef(), BaseCommit: plan.BaseCommit(), TargetRef: plan.TargetRef(), HeadOID: plan.CommitOID(), MetadataPolicy: plan.Metadata().Version(), Title: plan.Metadata().Title(), Body: plan.Metadata().Body(), Open: true})
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func mustLedger(t *testing.T, spec LedgerSpec) *ExternalEffectLedger {
	t.Helper()
	ledger, err := NewExternalEffectLedger(spec)
	if err != nil {
		t.Fatal(err)
	}
	return ledger
}
