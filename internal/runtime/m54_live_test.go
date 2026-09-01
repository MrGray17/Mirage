package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/gitrefs"
	"github.com/MrGray17/Mirage/internal/runtime/gitbinding"
	"github.com/MrGray17/Mirage/internal/runtime/gitcommit"
	"github.com/MrGray17/Mirage/internal/runtime/githubbinding"
	"github.com/MrGray17/Mirage/internal/runtime/githubpullrequest"
	"github.com/MrGray17/Mirage/internal/runtime/gitpublication"
	"github.com/MrGray17/Mirage/internal/runtime/workspace"
)

const (
	m54LiveRepositoryInput  = "MrGray17/test"
	m54LiveRepository       = "mrgray17/test"
	m54LiveRepositoryID     = int64(1351679704)
	m54ReviewedHead         = "17483b55a2395181ae2ea62aef6a099e61240acc"
	m54LiveRunID            = "m54-live-proof-2-2c1ebcd6d1351551e1d3da1d011573f4434f4172"
	m54LiveHarnessPath      = "internal/runtime/m54_live_test.go"
	m54LiveResponseLimit    = int64(2 << 20)
	m54LiveInventoryPages   = 5
	m54DiagnosticValueLimit = 512
	m54RetryAfterMaxSeconds = 24 * 60 * 60

	m54LiveBaseRef           = "refs/heads/main"
	m54LiveBaseOID           = "3f7b3d9d0ba3185008572756a9193e77808247b3"
	m53LiveEvidenceRef       = "refs/heads/mirage/run-86dc0b907b8b25114873736a"
	m53LiveEvidenceOID       = "0d62e0eafd7f0b8ffbd8da488ea3bfdc28579a3a"
	m54FailedLiveEvidenceRef = "refs/heads/mirage/run-725991efe593ed4120479276"
	m54FailedLiveEvidenceOID = "fac9b2cabb096dfd03ace6f25e28470b9780a7ed"
	m54FreshLiveTargetRef    = "refs/heads/mirage/run-3cd302b9301ff95e1e83b54b"
)

// TestM54LiveGitHubPullRequestProof is intentionally skipped unless every
// explicit gate is present. It is a single-use proof: its fixed RunID produces
// one fixed target ref, and any prior branch publication makes a later run fail
// before either external mutation path is entered.
func TestM54LiveGitHubPullRequestProof(t *testing.T) {
	if os.Getenv("MIRAGE_M54_LIVE") != "1" {
		t.Skip("set every MIRAGE_M54 live-proof gate for the one-branch/one-PR GitHub proof")
	}
	if os.Getenv("MIRAGE_M54_TEST_REPO") != m54LiveRepositoryInput {
		t.Fatalf("MIRAGE_M54_TEST_REPO must be exactly %q", m54LiveRepositoryInput)
	}
	expectedHead := os.Getenv("MIRAGE_M54_EXPECTED_HEAD")
	if !validM54OID(expectedHead) {
		t.Fatal("MIRAGE_M54_EXPECTED_HEAD must be the exact reviewed live-harness commit OID")
	}
	repositoryRoot := strings.TrimSpace(os.Getenv("MIRAGE_M54_TEST_REPO_ROOT"))
	token := os.Getenv("MIRAGE_GITHUB_TOKEN")
	if repositoryRoot == "" || token == "" || token != strings.TrimSpace(token) {
		t.Fatal("a clean dedicated repository root and one explicit host-only GitHub credential are required")
	}

	// Remove the credential from this process environment as soon as the trusted
	// host clients have captured it. The caller must also remove/revoke its
	// temporary user-scoped credential after the separately authorized run.
	t.Cleanup(func() { _ = os.Unsetenv("MIRAGE_GITHUB_TOKEN") })

	sourceRoot, sourceHead := requireM54ReviewedSource(t, expectedHead)
	real := requireM54CleanRepository(t, repositoryRoot)
	if pathsOverlapForM54(sourceRoot, real) {
		t.Fatal("the MIRAGE source checkout and disposable live-proof repository must be distinct")
	}
	localBefore := captureM54LocalState(t, real)
	readmeBefore, err := os.ReadFile(filepath.Join(real, "README.md"))
	if err != nil {
		t.Fatalf("read trusted README baseline: %v", err)
	}
	if bytes.Contains(readmeBefore, []byte("MIRAGE M5.4 live pull-request proof.")) {
		t.Fatal("fixed M5.4 proof mutation is already present")
	}

	readClient, err := githubbinding.NewHTTPClient(token)
	if err != nil {
		t.Fatal(err)
	}
	prTransport := &m54CountingDoer{client: newM54LiveHTTPClient()}
	prClient, err := githubpullrequest.NewHTTPClientForDoer(token, prTransport)
	if err != nil {
		t.Fatal(err)
	}
	audit := &m54LiveAuditClient{token: token, client: newM54LiveHTTPClient()}
	if err := os.Unsetenv("MIRAGE_GITHUB_TOKEN"); err != nil {
		t.Fatalf("remove credential from process environment: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	repository, err := readClient.Repository(ctx, m54LiveRepository)
	if err != nil || repository.ID != m54LiveRepositoryID {
		t.Fatalf("hard-bound repository identity unavailable: id=%d err=%v", repository.ID, err)
	}
	canonicalName, err := contracts.CanonicalGitHubRepository(repository.FullName)
	if err != nil || canonicalName != m54LiveRepository {
		t.Fatalf("provider returned a different repository identity: %v", err)
	}

	disposable, err := workspace.Prepare(real)
	if err != nil {
		t.Fatal(err)
	}
	disposablePath := disposable.Path()
	cleanedDisposable := false
	t.Cleanup(func() {
		if !cleanedDisposable {
			if cleanupErr := disposable.Cleanup(); cleanupErr != nil {
				t.Errorf("cleanup disposable live workspace: %v", cleanupErr)
			}
		}
	})
	binding, err := disposable.Binding()
	if err != nil {
		t.Fatal(err)
	}
	sandbox := &sandboxStub{real: binding.RealWorkspace(), disposable: binding.DisposableWorkspace(), token: binding.Token()}
	targetRef := gitrefs.RunTarget(m54LiveRunID)
	if targetRef != m54FreshLiveTargetRef || targetRef == m54FailedLiveEvidenceRef {
		t.Fatalf("fresh fixed RunID derived unexpected target ref %q", targetRef)
	}
	now := time.Now().UTC()
	contract, err := contracts.New(contracts.Spec{
		Version:   contracts.VersionV3,
		RunID:     m54LiveRunID,
		ActorID:   "m54-live-proof",
		ExpiresAt: now.Add(20 * time.Minute),
		Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{Allow: []string{
			"/workspace/README.md",
		}}},
		GitHubV3: contracts.GitHubEffectsPolicy{
			RepositoryFullName: m54LiveRepository,
			Branch: contracts.GitHubBranchPolicy{
				TargetRef: targetRef,
				Operation: contracts.GitHubCreateBranch,
			},
			PullRequest: contracts.GitHubPullRequestPolicy{
				BaseRef:        "refs/heads/main",
				TargetRef:      targetRef,
				Operation:      contracts.GitHubCreatePullRequest,
				MetadataPolicy: contracts.PullRequestMetadataV1,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := NewRunManifest(contract, binding, sandbox, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := NewBoundLifecycle(manifest)
	if err != nil {
		t.Fatal(err)
	}
	destroyed := false
	t.Cleanup(func() {
		if !destroyed {
			if destroyErr := lifecycle.Destroy(context.Background()); destroyErr != nil {
				t.Errorf("destroy live lifecycle: %v", destroyErr)
			}
		}
	})
	gitBinding, err := lifecycle.BindGitRepository()
	if err != nil {
		t.Fatal(err)
	}
	if gitBinding.HeadRef() != "refs/heads/main" {
		t.Fatalf("dedicated checkout must be on refs/heads/main, got %q", gitBinding.HeadRef())
	}
	remoteBinding, err := lifecycle.BindGitHubRepository(ctx, m54LiveRepository, readClient)
	if err != nil {
		t.Fatal(err)
	}
	if remoteBinding.RepositoryID() != m54LiveRepositoryID || remoteBinding.BaseRef() != gitBinding.HeadRef() || remoteBinding.BaseCommit() != gitBinding.HeadCommit() {
		t.Fatal("local and provider base authority are not exactly bound")
	}

	runToStarted(t, lifecycle)
	authorized := append(append([]byte(nil), readmeBefore...), []byte("\nMIRAGE M5.4 live pull-request proof.\n")...)
	if err := os.WriteFile(filepath.Join(disposablePath, "README.md"), authorized, 0o600); err != nil {
		t.Fatal(err)
	}
	freezeAndVerify(t, lifecycle)
	if _, err := lifecycle.DeriveGitEffectPlan(); err != nil {
		t.Fatal(err)
	}
	artifact, err := lifecycle.ConstructGitCommitArtifact()
	if err != nil {
		t.Fatal(err)
	}
	publicationPlan, err := lifecycle.DeriveGitPublicationPlan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if publicationPlan.TargetRef() != targetRef || publicationPlan.BaseCommit() != gitBinding.HeadCommit() || publicationPlan.CommitOID() != artifact.CommitOID() {
		t.Fatal("deterministic branch plan differs from the verified artifact")
	}

	remoteBefore := audit.capture(t, ctx)
	if remoteBefore.repositoryID != m54LiveRepositoryID {
		t.Fatal("read-only inventory did not prove the hard-bound repository ID")
	}
	requireM54EvidenceBranches(t, remoteBefore)
	if len(remoteBefore.pullRequests) != 0 {
		t.Fatalf("single-use proof requires an empty PR inventory, got %d", len(remoteBefore.pullRequests))
	}
	if _, exists := remoteBefore.branches[targetRef]; exists {
		t.Fatalf("single-use target ref already exists: %s", targetRef)
	}
	if remoteBefore.hasPullRequestTuple("refs/heads/main", targetRef) {
		t.Fatal("single-use pull-request tuple already exists")
	}
	baseBefore, err := readClient.ExactRef(ctx, m54LiveRepository, m54LiveRepositoryID, m54LiveBaseRef, gitBinding.HeadCommit())
	if err != nil || baseBefore.Status != githubbinding.RefPresentExact || baseBefore.OID != gitBinding.HeadCommit() {
		t.Fatalf("base preflight is not exact: observation=%#v err=%v", baseBefore, err)
	}
	targetBefore, err := readClient.ExactRef(ctx, m54LiveRepository, m54LiveRepositoryID, targetRef, artifact.CommitOID())
	if err != nil || targetBefore.Status != githubbinding.RefAbsent {
		t.Fatalf("target preflight is not absent: observation=%#v err=%v", targetBefore, err)
	}

	publicationEngineInner, err := gitpublication.NewEngine(readClient, func() (string, error) { return token, nil })
	if err != nil {
		t.Fatal(err)
	}
	publicationEngine := &m54CountingPublicationEngine{inner: publicationEngineInner}
	record, publishErr := lifecycle.PublishGitHub(ctx, publicationEngine)
	if publishErr != nil || record == nil {
		if lifecycle.State() == StatePublicationUncertain {
			t.Fatalf("branch publication is uncertain; STOP without PR activity: %v", publishErr)
		}
		t.Fatalf("branch publication failed closed: %v", publishErr)
	}
	if publicationEngine.publishes.Load() != 1 || publicationEngine.reconciles.Load() != 0 || record.Outcome() != gitpublication.OutcomePublished || !record.TransportAcknowledged() || !record.ResolvedByReconciliation() || lifecycle.State() != StatePublished {
		t.Fatalf("branch evidence is incomplete: state=%s outcome=%s publishes=%d reads=%d", lifecycle.State(), record.Outcome(), publicationEngine.publishes.Load(), publicationEngine.reconciles.Load())
	}

	prPlan, err := lifecycle.DeriveGitHubPullRequestPlan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if prPlan.PublicationRecordIdentity() != record.Identity() || prPlan.RepositoryID() != m54LiveRepositoryID || prPlan.BaseCommit() != gitBinding.HeadCommit() || prPlan.TargetRef() != targetRef || prPlan.CommitOID() != artifact.CommitOID() {
		t.Fatal("PR plan is not exactly bound to M5.3 publication truth")
	}
	initialLedger := lifecycle.ExternalEffectLedger()
	if initialLedger == nil || initialLedger.PullRequestOutcome() != githubpullrequest.OutcomeNotAttempted || initialLedger.Attempted() {
		t.Fatalf("initial external-effect ledger is not immutable NOT_ATTEMPTED evidence: %#v", initialLedger)
	}
	prEngineInner, err := githubpullrequest.NewEngine(prClient)
	if err != nil {
		t.Fatal(err)
	}
	prEngine := &m54CountingPullRequestEngine{inner: prEngineInner}
	ledger, establishErr := lifecycle.EstablishGitHubPullRequest(ctx, prEngine)
	if lifecycle.State() == StatePRCreationUncertain {
		// Once attempted, the only permitted recovery is this read-only path.
		ledger, establishErr = lifecycle.ReconcileGitHubPullRequest(prEngine)
	}
	if ledger == nil {
		t.Fatalf("PR effect returned no immutable external-effect ledger: state=%s err=%v", lifecycle.State(), establishErr)
	}
	if prEngine.establishes.Load() != 1 || prTransport.posts.Load() != 1 || prEngine.reconciles.Load() > 1 {
		t.Fatalf("mutation budget violated: establish=%d POST=%d reconcile=%d", prEngine.establishes.Load(), prTransport.posts.Load(), prEngine.reconciles.Load())
	}
	attempt := lifecycle.PullRequestAttempt()
	if attempt == nil || attempt.Identity() != ledger.AttemptIdentity() || attempt.PlanIdentity() != prPlan.Identity() {
		t.Fatal("PR attempt latch is absent or differs from the immutable plan/ledger")
	}
	diagnostic, diagnosticAvailable := prTransport.postDiagnostic()
	if !diagnosticAvailable {
		diagnostic = normalizeM54PostDiagnostic(nil)
	}
	diagnosticEvidence := diagnostic.evidence(t)
	if strings.Contains(diagnosticEvidence, token) {
		t.Fatal("credential entered normalized POST diagnostics")
	}

	if establishErr != nil {
		failureClass := classifyM54CreationFailure(establishErr)
		if lifecycle.State() != StateFailed || ledger.PullRequestOutcome() != githubpullrequest.OutcomeNotCreated || !ledger.Attempted() || ledger.TransportAcknowledged() || ledger.ObservationStatus() != githubpullrequest.ObservationAbsent || ledger.Causality() != githubpullrequest.CausalityNone {
			t.Fatalf("PR creation failure did not preserve exact partial-effect truth: state=%s outcome=%s observation=%s err=%v", lifecycle.State(), ledger.PullRequestOutcome(), ledger.ObservationStatus(), establishErr)
		}
		expectedLedger, expectedLedgerErr := githubpullrequest.NewExternalEffectLedger(githubpullrequest.LedgerSpec{
			Previous:                  initialLedger,
			Plan:                      prPlan,
			Attempt:                   attempt,
			Outcome:                   githubpullrequest.OutcomeNotCreated,
			Observation:               githubpullrequest.Observation{Status: githubpullrequest.ObservationAbsent},
			Postflight:                true,
			CompatibleAcknowledgement: false,
			Reconciled:                true,
			Causality:                 githubpullrequest.CausalityNone,
		})
		ledgerIdentityVerified := expectedLedgerErr == nil && expectedLedger != nil && expectedLedger.Identity() == ledger.Identity()

		// This fresh read is independent of the engine's mandatory postflight.
		providerObservation, observeErr := prClient.ObserveExactPullRequest(ctx, prPlan)
		if observeErr != nil || providerObservation.Status != githubpullrequest.ObservationAbsent || providerObservation.Exact != nil {
			t.Fatalf("independent failed-creation postflight is not authoritative absence: status=%s err=%v", providerObservation.Status, observeErr)
		}
		baseAfter, baseErr := readClient.ExactRef(ctx, m54LiveRepository, m54LiveRepositoryID, prPlan.BaseRef(), prPlan.BaseCommit())
		if baseErr != nil || baseAfter.Status != githubbinding.RefPresentExact || baseAfter.OID != prPlan.BaseCommit() {
			t.Fatalf("provider base moved during failed proof: observation=%#v err=%v", baseAfter, baseErr)
		}
		targetAfter, targetErr := readClient.ExactRef(ctx, m54LiveRepository, m54LiveRepositoryID, prPlan.TargetRef(), prPlan.CommitOID())
		if targetErr != nil || targetAfter.Status != githubbinding.RefPresentExact || targetAfter.OID != prPlan.CommitOID() {
			t.Fatalf("provider target differs after failed proof: observation=%#v err=%v", targetAfter, targetErr)
		}
		remoteAfter := audit.capture(t, ctx)
		assertM54FailedRemoteDelta(t, remoteBefore, remoteAfter, prPlan)
		requireM54EvidenceBranches(t, remoteAfter)
		requireM54LiveLocalTruth(t, sourceRoot, real, disposablePath, readmeBefore, token)
		finishM54LiveLocalProof(t, lifecycle, disposable, disposablePath, real, localBefore, &destroyed, &cleanedDisposable)
		if !ledgerIdentityVerified {
			t.Fatalf("terminal NOT_CREATED ledger failed canonical identity reconstruction: construction_error=%t", expectedLedgerErr != nil)
		}
		if failureClass == m54FailureProviderRejected && (!diagnosticAvailable || diagnostic.HTTPStatus < 100 || diagnostic.HTTPStatus > 599 || diagnostic.HTTPStatus == http.StatusCreated) {
			t.Fatalf("PROVIDER_REJECTED lacks one normalized non-201 provider response: available=%t status=%d", diagnosticAvailable, diagnostic.HTTPStatus)
		}
		evidence := fmt.Sprintf("run=%s repository=%s repository_id=%d base_ref=%s base_commit=%s target_ref=%s commit_oid=%s publication_record=%s branch_outcome=PUBLISHED branch_transport_acknowledged=%t branch_reconciled=%t pr_plan=%s initial_ledger=%s metadata_policy=%s title_digest=%s body_digest=%s attempt=%s outcome=%s attempted=%t transport_acknowledged=%t observation=%s exact_postflight=false reconciled=true causality=%s ledger=%s ledger_identity_verified=true ledger_base_commit=%s lifecycle=%s source_head=%s branch_inventory_before=%s pr_inventory_before=%s branch_inventory_after=%s pr_inventory_after=%s failure_class=%s diagnostic_available=%t diagnostic=%s",
			m54LiveRunID, m54LiveRepository, m54LiveRepositoryID, prPlan.BaseRef(), prPlan.BaseCommit(), prPlan.TargetRef(), prPlan.CommitOID(), record.Identity(), record.TransportAcknowledged(), record.ResolvedByReconciliation(), prPlan.Identity(), initialLedger.Identity(), prPlan.Metadata().Version(), prPlan.Metadata().TitleDigest(), prPlan.Metadata().BodyDigest(), attempt.Identity(), ledger.PullRequestOutcome(), ledger.Attempted(), ledger.TransportAcknowledged(), ledger.ObservationStatus(), ledger.Causality(), ledger.Identity(), ledger.PullRequestBaseCommit(), lifecycle.State(), sourceHead, remoteBefore.branchDigest, remoteBefore.pullRequestDigest, remoteAfter.branchDigest, remoteAfter.pullRequestDigest, failureClass, diagnosticAvailable, diagnosticEvidence)
		if strings.Contains(evidence, token) {
			t.Fatal("credential entered sanitized failure evidence")
		}
		t.Log(evidence)
		t.Fatalf("PR establishment failed after complete partial-effect evidence: class=%s status=%d", failureClass, diagnostic.HTTPStatus)
	}
	if !diagnosticAvailable {
		t.Fatal("acknowledged PR creation returned no normalized POST diagnostics")
	}
	if lifecycle.State() != StatePREstablished || ledger.PullRequestOutcome() != githubpullrequest.OutcomeCreated || !ledger.Attempted() || !ledger.TransportAcknowledged() || ledger.ObservationStatus() != githubpullrequest.ObservationExact || ledger.Causality() != githubpullrequest.CausalityMirageAcknowledged {
		t.Fatalf("final PR ledger is not acknowledged exact creation: state=%s outcome=%s observation=%s", lifecycle.State(), ledger.PullRequestOutcome(), ledger.ObservationStatus())
	}

	// This fresh provider read is independent of the engine's postflight and is
	// the live proof that GitHub still reports the exact bound base and head.
	providerObservation, err := prClient.ObserveExactPullRequest(ctx, prPlan)
	if err != nil || providerObservation.Status != githubpullrequest.ObservationExact || providerObservation.Exact == nil {
		t.Fatalf("independent PR postflight is not exact: status=%s err=%v", providerObservation.Status, err)
	}
	pullRequest := providerObservation.Exact
	if pullRequest.RepositoryID() != m54LiveRepositoryID || pullRequest.RepositoryFullName() != m54LiveRepository || pullRequest.BaseRef() != prPlan.BaseRef() || pullRequest.BaseCommit() != prPlan.BaseCommit() || pullRequest.TargetRef() != prPlan.TargetRef() || pullRequest.HeadOID() != prPlan.CommitOID() || pullRequest.MetadataPolicy() != contracts.PullRequestMetadataV1 || pullRequest.TitleDigest() != prPlan.Metadata().TitleDigest() || pullRequest.BodyDigest() != prPlan.Metadata().BodyDigest() || pullRequest.Number() != ledger.PullRequestNumber() || pullRequest.StableID() != ledger.PullRequestStableID() || pullRequest.URL() != ledger.PullRequestURL() || ledger.PullRequestBaseCommit() != prPlan.BaseCommit() {
		t.Fatal("independent provider identity differs from the plan or external-effect ledger")
	}
	expectedLedger, err := githubpullrequest.NewExternalEffectLedger(githubpullrequest.LedgerSpec{
		Previous:                  initialLedger,
		Plan:                      prPlan,
		Attempt:                   attempt,
		Outcome:                   githubpullrequest.OutcomeCreated,
		Observation:               githubpullrequest.Observation{Status: githubpullrequest.ObservationExact, Exact: pullRequest},
		Postflight:                true,
		CompatibleAcknowledgement: true,
		Reconciled:                true,
		Causality:                 githubpullrequest.CausalityMirageAcknowledged,
	})
	if err != nil || expectedLedger == nil || expectedLedger.Identity() != ledger.Identity() {
		t.Fatalf("terminal CREATED ledger failed canonical identity reconstruction: construction_error=%t", err != nil)
	}
	baseAfter, err := readClient.ExactRef(ctx, m54LiveRepository, m54LiveRepositoryID, prPlan.BaseRef(), prPlan.BaseCommit())
	if err != nil || baseAfter.Status != githubbinding.RefPresentExact || baseAfter.OID != prPlan.BaseCommit() {
		t.Fatalf("provider base moved during proof: observation=%#v err=%v", baseAfter, err)
	}
	targetAfter, err := readClient.ExactRef(ctx, m54LiveRepository, m54LiveRepositoryID, prPlan.TargetRef(), prPlan.CommitOID())
	if err != nil || targetAfter.Status != githubbinding.RefPresentExact || targetAfter.OID != prPlan.CommitOID() {
		t.Fatalf("provider target differs: observation=%#v err=%v", targetAfter, err)
	}
	remoteAfter := audit.capture(t, ctx)
	assertM54RemoteDelta(t, remoteBefore, remoteAfter, prPlan, pullRequest)
	requireM54EvidenceBranches(t, remoteAfter)

	requireM54LiveLocalTruth(t, sourceRoot, real, disposablePath, readmeBefore, token)
	evidence := fmt.Sprintf("run=%s repository=%s repository_id=%d base_ref=%s base_commit=%s target_ref=%s commit_oid=%s publication_record=%s branch_outcome=PUBLISHED branch_transport_acknowledged=%t branch_reconciled=%t pr_plan=%s initial_ledger=%s metadata_policy=%s title_digest=%s body_digest=%s attempt=%s outcome=%s pr_number=%d pr_stable_id=%d pr_url=%s pr_identity=%s transport_acknowledged=%t exact_postflight=true reconciled=true causality=%s ledger=%s ledger_identity_verified=true ledger_base_commit=%s lifecycle=%s source_head=%s branch_inventory_before=%s pr_inventory_before=%s branch_inventory_after=%s pr_inventory_after=%s diagnostic=%s",
		m54LiveRunID, m54LiveRepository, m54LiveRepositoryID, prPlan.BaseRef(), prPlan.BaseCommit(), prPlan.TargetRef(), prPlan.CommitOID(), record.Identity(), record.TransportAcknowledged(), record.ResolvedByReconciliation(), prPlan.Identity(), initialLedger.Identity(), prPlan.Metadata().Version(), prPlan.Metadata().TitleDigest(), prPlan.Metadata().BodyDigest(), attempt.Identity(), ledger.PullRequestOutcome(), pullRequest.Number(), pullRequest.StableID(), pullRequest.URL(), pullRequest.Identity(), ledger.TransportAcknowledged(), ledger.Causality(), ledger.Identity(), ledger.PullRequestBaseCommit(), lifecycle.State(), sourceHead, remoteBefore.branchDigest, remoteBefore.pullRequestDigest, remoteAfter.branchDigest, remoteAfter.pullRequestDigest, diagnosticEvidence)
	if strings.Contains(evidence, token) {
		t.Fatal("credential entered sanitized live evidence")
	}
	finishM54LiveLocalProof(t, lifecycle, disposable, disposablePath, real, localBefore, &destroyed, &cleanedDisposable)
	t.Log(evidence)
}

type m54CountingPublicationEngine struct {
	inner      GitPublicationEngine
	publishes  atomic.Int64
	reconciles atomic.Int64
}

func (e *m54CountingPublicationEngine) Publish(ctx context.Context, binding *githubbinding.Binding, plan *gitpublication.Plan, artifact *gitcommit.Artifact, repository *gitbinding.Binding, final gitpublication.FinalAuthority) (gitpublication.Result, error) {
	e.publishes.Add(1)
	return e.inner.Publish(ctx, binding, plan, artifact, repository, final)
}

func (e *m54CountingPublicationEngine) Reconcile(ctx context.Context, binding *githubbinding.Binding, plan *gitpublication.Plan) (githubbinding.RefObservation, gitpublication.Outcome, error) {
	e.reconciles.Add(1)
	return e.inner.Reconcile(ctx, binding, plan)
}

type m54CountingPullRequestEngine struct {
	inner       GitHubPullRequestEngine
	establishes atomic.Int64
	reconciles  atomic.Int64
}

func (e *m54CountingPullRequestEngine) Establish(ctx context.Context, plan *githubpullrequest.Plan, final githubpullrequest.FinalAuthority) (githubpullrequest.EstablishResult, error) {
	e.establishes.Add(1)
	return e.inner.Establish(ctx, plan, final)
}

func (e *m54CountingPullRequestEngine) Reconcile(ctx context.Context, plan *githubpullrequest.Plan) (githubpullrequest.Observation, error) {
	e.reconciles.Add(1)
	return e.inner.Reconcile(ctx, plan)
}

type m54CountingDoer struct {
	client interface {
		Do(*http.Request) (*http.Response, error)
	}
	posts      atomic.Int64
	diagnostic sync.Mutex
	postResult *m54PostDiagnostic
}

func (d *m54CountingDoer) Do(request *http.Request) (*http.Response, error) {
	if d == nil || d.client == nil || request == nil || request.URL == nil || request.URL.Scheme != "https" || request.URL.Host != "api.github.com" || request.URL.User != nil || request.URL.Opaque != "" || request.URL.RawPath != "" || request.URL.Fragment != "" || request.URL.RawFragment != "" {
		return nil, errors.New("live proof transport rejected non-bound GitHub request")
	}
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/repos/"+m54LiveRepository:
		if request.URL.RawQuery != "" || request.URL.ForceQuery {
			return nil, errors.New("live proof transport rejected repository query")
		}
	case request.Method == http.MethodGet && request.URL.Path == "/repos/"+m54LiveRepository+"/pulls":
		if !validM54PullRequestQuery(request.URL) {
			return nil, errors.New("live proof transport rejected pull-request query")
		}
	case request.Method == http.MethodPost && request.URL.Path == "/repos/"+m54LiveRepository+"/pulls":
		if request.URL.RawQuery != "" || request.URL.ForceQuery {
			return nil, errors.New("live proof transport rejected pull-request POST query")
		}
		if d.posts.Add(1) != 1 {
			return nil, errors.New("second live pull-request POST is permanently forbidden")
		}
	default:
		return nil, errors.New("live proof transport rejected unsupported method")
	}
	response, err := d.client.Do(request)
	if request.Method == http.MethodPost && response != nil {
		diagnostic := normalizeM54PostDiagnostic(response)
		d.diagnostic.Lock()
		if d.postResult == nil {
			d.postResult = &diagnostic
		}
		d.diagnostic.Unlock()
	}
	return response, err
}

type m54DiagnosticState string

type m54CreationFailureClass string

const (
	m54DiagnosticMissing   m54DiagnosticState = "MISSING"
	m54DiagnosticValid     m54DiagnosticState = "VALID"
	m54DiagnosticMalformed m54DiagnosticState = "MALFORMED"
	m54RetryAfterNone      m54DiagnosticState = "NONE"
	m54RetryAfterSeconds   m54DiagnosticState = "SECONDS"
	m54RetryAfterHTTPDate  m54DiagnosticState = "HTTP_DATE"

	m54FailureProviderRejected  m54CreationFailureClass = "PROVIDER_REJECTED"
	m54FailureCreateUnavailable m54CreationFailureClass = "CREATE_UNAVAILABLE"
	m54FailureUnexpected        m54CreationFailureClass = "UNEXPECTED_ERROR"
)

type m54NormalizedPermission struct {
	Name  string `json:"name"`
	Level string `json:"level"`
}

type m54NormalizedPermissionSet []m54NormalizedPermission

type m54PostDiagnostic struct {
	HTTPStatus               int                          `json:"http_status"`
	AcceptedPermissionsState m54DiagnosticState           `json:"accepted_permissions_state"`
	AcceptedPermissionSets   []m54NormalizedPermissionSet `json:"accepted_permission_sets,omitempty"`
	RateLimitRemainingState  m54DiagnosticState           `json:"rate_limit_remaining_state"`
	RateLimitRemaining       uint64                       `json:"rate_limit_remaining,omitempty"`
	RateLimitResourceState   m54DiagnosticState           `json:"rate_limit_resource_state"`
	RateLimitResource        string                       `json:"rate_limit_resource,omitempty"`
	RetryAfterState          m54DiagnosticState           `json:"retry_after_state"`
	RetryAfterSeconds        uint64                       `json:"retry_after_seconds,omitempty"`
	RequestIDState           m54DiagnosticState           `json:"request_id_state"`
	RequestIDDigest          string                       `json:"request_id_digest,omitempty"`
}

func (d *m54CountingDoer) postDiagnostic() (m54PostDiagnostic, bool) {
	if d == nil {
		return m54PostDiagnostic{}, false
	}
	d.diagnostic.Lock()
	defer d.diagnostic.Unlock()
	if d.postResult == nil {
		return m54PostDiagnostic{}, false
	}
	result := *d.postResult
	result.AcceptedPermissionSets = make([]m54NormalizedPermissionSet, len(d.postResult.AcceptedPermissionSets))
	for index := range d.postResult.AcceptedPermissionSets {
		result.AcceptedPermissionSets[index] = append(m54NormalizedPermissionSet(nil), d.postResult.AcceptedPermissionSets[index]...)
	}
	return result, true
}

func (d m54PostDiagnostic) evidence(t *testing.T) string {
	t.Helper()
	encoded, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("encode trusted POST diagnostics: %v", err)
	}
	return string(encoded)
}

func classifyM54CreationFailure(err error) m54CreationFailureClass {
	switch {
	case errors.Is(err, githubpullrequest.ErrCreateRejected):
		return m54FailureProviderRejected
	case errors.Is(err, githubpullrequest.ErrCreateUnavailable):
		return m54FailureCreateUnavailable
	default:
		return m54FailureUnexpected
	}
}

func normalizeM54PostDiagnostic(response *http.Response) m54PostDiagnostic {
	result := m54PostDiagnostic{
		AcceptedPermissionsState: m54DiagnosticMissing,
		RateLimitRemainingState:  m54DiagnosticMissing,
		RateLimitResourceState:   m54DiagnosticMissing,
		RetryAfterState:          m54RetryAfterNone,
		RequestIDState:           m54DiagnosticMissing,
	}
	if response == nil {
		return result
	}
	result.HTTPStatus = response.StatusCode
	result.AcceptedPermissionSets, result.AcceptedPermissionsState = normalizeM54AcceptedPermissions(response.Header)
	result.RateLimitRemaining, result.RateLimitRemainingState = normalizeM54RateLimitRemaining(response.Header)
	result.RateLimitResource, result.RateLimitResourceState = normalizeM54RateLimitResource(response.Header)
	result.RetryAfterState, result.RetryAfterSeconds = normalizeM54RetryAfter(response.Header)
	result.RequestIDDigest, result.RequestIDState = normalizeM54RequestID(response.Header)
	return result
}

func normalizeM54AcceptedPermissions(header http.Header) ([]m54NormalizedPermissionSet, m54DiagnosticState) {
	value, state := m54SingleDiagnosticHeader(header, "X-Accepted-GitHub-Permissions")
	if state != m54DiagnosticValid {
		return nil, state
	}
	knownNames := map[string]bool{"contents": true, "issues": true, "metadata": true, "pull_requests": true}
	seenSets := make(map[string]bool)
	sets := make([]m54NormalizedPermissionSet, 0, 2)
	for _, alternative := range strings.Split(value, ";") {
		alternative = strings.Trim(alternative, " ")
		if alternative == "" {
			return nil, m54DiagnosticMalformed
		}
		seenNames := make(map[string]bool)
		permissions := make(m54NormalizedPermissionSet, 0, 3)
		for _, entry := range strings.Split(alternative, ",") {
			entry = strings.Trim(entry, " ")
			if entry == "" || strings.Count(entry, "=") != 1 {
				return nil, m54DiagnosticMalformed
			}
			parts := strings.SplitN(entry, "=", 2)
			name, level := parts[0], parts[1]
			if !knownNames[name] || (level != "read" && level != "write") || seenNames[name] {
				return nil, m54DiagnosticMalformed
			}
			seenNames[name] = true
			permissions = append(permissions, m54NormalizedPermission{Name: name, Level: level})
		}
		sort.Slice(permissions, func(i, j int) bool { return permissions[i].Name < permissions[j].Name })
		key := m54PermissionSetKey(permissions)
		if seenSets[key] {
			return nil, m54DiagnosticMalformed
		}
		seenSets[key] = true
		sets = append(sets, permissions)
	}
	sort.Slice(sets, func(i, j int) bool { return m54PermissionSetKey(sets[i]) < m54PermissionSetKey(sets[j]) })
	return sets, m54DiagnosticValid
}

func m54PermissionSetKey(set m54NormalizedPermissionSet) string {
	var key strings.Builder
	for _, permission := range set {
		key.WriteString(permission.Name)
		key.WriteByte('=')
		key.WriteString(permission.Level)
		key.WriteByte(',')
	}
	return key.String()
}

func normalizeM54RateLimitRemaining(header http.Header) (uint64, m54DiagnosticState) {
	value, state := m54SingleDiagnosticHeader(header, "X-RateLimit-Remaining")
	if state != m54DiagnosticValid {
		return 0, state
	}
	if value == "" || strings.Trim(value, "0123456789") != "" {
		return 0, m54DiagnosticMalformed
	}
	remaining, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, m54DiagnosticMalformed
	}
	return remaining, m54DiagnosticValid
}

func normalizeM54RateLimitResource(header http.Header) (string, m54DiagnosticState) {
	value, state := m54SingleDiagnosticHeader(header, "X-RateLimit-Resource")
	if state != m54DiagnosticValid {
		return "", state
	}
	known := map[string]bool{
		"actions_runner_registration": true,
		"audit_log":                   true,
		"code_scanning_upload":        true,
		"core":                        true,
		"dependency_snapshots":        true,
		"graphql":                     true,
		"integration_manifest":        true,
		"scim":                        true,
		"search":                      true,
		"source_import":               true,
	}
	if !known[value] {
		return "", m54DiagnosticMalformed
	}
	return value, m54DiagnosticValid
}

func normalizeM54RetryAfter(header http.Header) (m54DiagnosticState, uint64) {
	value, state := m54SingleDiagnosticHeader(header, "Retry-After")
	if state == m54DiagnosticMissing {
		return m54RetryAfterNone, 0
	}
	if state != m54DiagnosticValid {
		return m54DiagnosticMalformed, 0
	}
	if value != "" && strings.Trim(value, "0123456789") == "" {
		seconds, err := strconv.ParseUint(value, 10, 32)
		if err == nil && seconds <= m54RetryAfterMaxSeconds {
			return m54RetryAfterSeconds, seconds
		}
		return m54DiagnosticMalformed, 0
	}
	if _, err := http.ParseTime(value); err == nil {
		return m54RetryAfterHTTPDate, 0
	}
	return m54DiagnosticMalformed, 0
}

func normalizeM54RequestID(header http.Header) (string, m54DiagnosticState) {
	value, state := m54SingleDiagnosticHeader(header, "X-GitHub-Request-Id")
	if state != m54DiagnosticValid {
		return "", state
	}
	if value == "" || len(value) > 128 {
		return "", m54DiagnosticMalformed
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == ':' || character == '-') {
			return "", m54DiagnosticMalformed
		}
	}
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:]), m54DiagnosticValid
}

func m54SingleDiagnosticHeader(header http.Header, name string) (string, m54DiagnosticState) {
	values := header.Values(name)
	if len(values) == 0 {
		return "", m54DiagnosticMissing
	}
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > m54DiagnosticValueLimit {
		return "", m54DiagnosticMalformed
	}
	for _, character := range values[0] {
		if character < 0x20 || character > 0x7e {
			return "", m54DiagnosticMalformed
		}
	}
	return values[0], m54DiagnosticValid
}

func TestM54FreshLiveRunTargetIsSingleUse(t *testing.T) {
	if target := gitrefs.RunTarget(m54LiveRunID); target != m54FreshLiveTargetRef || target == m54FailedLiveEvidenceRef {
		t.Fatalf("fresh fixed RunID target = %q", target)
	}
	for _, oid := range []string{m54LiveBaseOID, m53LiveEvidenceOID, m54FailedLiveEvidenceOID} {
		if !validM54OID(oid) {
			t.Fatalf("pinned live evidence OID is malformed: %q", oid)
		}
	}
}

func TestM54CreationFailureClassification(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want m54CreationFailureClass
	}{
		{name: "provider rejected", err: fmt.Errorf("wrapped: %w", githubpullrequest.ErrCreateRejected), want: m54FailureProviderRejected},
		{name: "provider rejection precedence", err: errors.Join(githubpullrequest.ErrCreateUnavailable, githubpullrequest.ErrCreateRejected), want: m54FailureProviderRejected},
		{name: "create unavailable", err: fmt.Errorf("wrapped: %w", githubpullrequest.ErrCreateUnavailable), want: m54FailureCreateUnavailable},
		{name: "unexpected", err: errors.New("different failure"), want: m54FailureUnexpected},
		{name: "nil", err: nil, want: m54FailureUnexpected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyM54CreationFailure(test.err); got != test.want {
				t.Fatalf("failure class = %s, want %s", got, test.want)
			}
		})
	}
}

func TestM54HarnessReconstructsCanonicalTerminalLedgers(t *testing.T) {
	tests := []struct {
		name         string
		outcome      githubpullrequest.PullRequestOutcome
		postflight   githubpullrequest.ObservationStatus
		acknowledged bool
		establishErr error
		causality    githubpullrequest.Causality
	}{
		{name: "not created", outcome: githubpullrequest.OutcomeNotCreated, postflight: githubpullrequest.ObservationAbsent, establishErr: githubpullrequest.ErrCreateRejected, causality: githubpullrequest.CausalityNone},
		{name: "created", outcome: githubpullrequest.OutcomeCreated, postflight: githubpullrequest.ObservationExact, acknowledged: true, causality: githubpullrequest.CausalityMirageAcknowledged},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
			lifecycle, _, _ := preparedPullRequestLifecycle(t, func() time.Time { return current }, current.Add(time.Hour))
			plan := lifecycle.GitHubPullRequestPlan()
			initial := lifecycle.ExternalEffectLedger()
			observation := lifecyclePRObservation(t, plan, test.postflight)
			engine := &m54LifecycleEngine{lifecycle: lifecycle, preflight: githubpullrequest.Observation{Status: githubpullrequest.ObservationAbsent}, postflight: observation, acknowledged: test.acknowledged, establishErr: test.establishErr}
			actual, establishErr := lifecycle.EstablishGitHubPullRequest(context.Background(), engine)
			if test.establishErr == nil && establishErr != nil {
				t.Fatal(establishErr)
			}
			if test.establishErr != nil && !errors.Is(establishErr, test.establishErr) {
				t.Fatalf("establish error = %v, want %v", establishErr, test.establishErr)
			}
			attempt := lifecycle.PullRequestAttempt()
			expected, expectedErr := githubpullrequest.NewExternalEffectLedger(githubpullrequest.LedgerSpec{
				Previous:                  initial,
				Plan:                      plan,
				Attempt:                   attempt,
				Outcome:                   test.outcome,
				Observation:               observation,
				Postflight:                true,
				CompatibleAcknowledgement: test.acknowledged,
				Reconciled:                true,
				Causality:                 test.causality,
			})
			if expectedErr != nil || expected == nil || actual == nil || expected.Identity() != actual.Identity() {
				t.Fatalf("terminal ledger identity differs: expected=%#v actual=%#v error=%v", expected, actual, expectedErr)
			}
		})
	}
}

func TestM54PostDiagnosticNormalization(t *testing.T) {
	t.Run("valid allowlisted values", func(t *testing.T) {
		header := make(http.Header)
		header.Set("X-Accepted-GitHub-Permissions", "pull_requests=write,contents=read")
		header.Set("X-RateLimit-Remaining", "4999")
		header.Set("X-RateLimit-Resource", "core")
		header.Set("Retry-After", "120")
		header.Set("X-GitHub-Request-Id", "ABCD:1234:EFGH:5678")
		diagnostic := normalizeM54PostDiagnostic(&http.Response{StatusCode: http.StatusForbidden, Header: header})
		if diagnostic.HTTPStatus != http.StatusForbidden || diagnostic.AcceptedPermissionsState != m54DiagnosticValid || len(diagnostic.AcceptedPermissionSets) != 1 || len(diagnostic.AcceptedPermissionSets[0]) != 2 || diagnostic.AcceptedPermissionSets[0][0] != (m54NormalizedPermission{Name: "contents", Level: "read"}) || diagnostic.AcceptedPermissionSets[0][1] != (m54NormalizedPermission{Name: "pull_requests", Level: "write"}) {
			t.Fatalf("accepted permission normalization differs: %#v", diagnostic)
		}
		if diagnostic.RateLimitRemainingState != m54DiagnosticValid || diagnostic.RateLimitRemaining != 4999 || diagnostic.RateLimitResourceState != m54DiagnosticValid || diagnostic.RateLimitResource != "core" || diagnostic.RetryAfterState != m54RetryAfterSeconds || diagnostic.RetryAfterSeconds != 120 || diagnostic.RequestIDState != m54DiagnosticValid || !strings.HasPrefix(diagnostic.RequestIDDigest, "sha256:") || strings.Contains(diagnostic.RequestIDDigest, "ABCD") {
			t.Fatalf("bounded diagnostic normalization differs: %#v", diagnostic)
		}
	})

	t.Run("one permission and alternative sets stay canonical", func(t *testing.T) {
		one := make(http.Header)
		one.Set("X-Accepted-GitHub-Permissions", "pull_requests=write")
		oneDiagnostic := normalizeM54PostDiagnostic(&http.Response{Header: one})
		if oneDiagnostic.AcceptedPermissionsState != m54DiagnosticValid || len(oneDiagnostic.AcceptedPermissionSets) != 1 || len(oneDiagnostic.AcceptedPermissionSets[0]) != 1 || oneDiagnostic.AcceptedPermissionSets[0][0] != (m54NormalizedPermission{Name: "pull_requests", Level: "write"}) {
			t.Fatalf("single permission normalization differs: %#v", oneDiagnostic)
		}

		alternatives := make(http.Header)
		alternatives.Set("X-Accepted-GitHub-Permissions", "pull_requests=read,contents=read;issues=read,contents=read")
		alternativeDiagnostic := normalizeM54PostDiagnostic(&http.Response{Header: alternatives})
		if alternativeDiagnostic.AcceptedPermissionsState != m54DiagnosticValid || len(alternativeDiagnostic.AcceptedPermissionSets) != 2 || m54PermissionSetKey(alternativeDiagnostic.AcceptedPermissionSets[0]) != "contents=read,issues=read," || m54PermissionSetKey(alternativeDiagnostic.AcceptedPermissionSets[1]) != "contents=read,pull_requests=read," {
			t.Fatalf("alternative permission-set normalization differs: %#v", alternativeDiagnostic)
		}
	})

	t.Run("missing values remain explicit", func(t *testing.T) {
		diagnostic := normalizeM54PostDiagnostic(&http.Response{StatusCode: http.StatusCreated, Header: make(http.Header)})
		if diagnostic.AcceptedPermissionsState != m54DiagnosticMissing || diagnostic.RateLimitRemainingState != m54DiagnosticMissing || diagnostic.RateLimitResourceState != m54DiagnosticMissing || diagnostic.RetryAfterState != m54RetryAfterNone || diagnostic.RequestIDState != m54DiagnosticMissing {
			t.Fatalf("missing diagnostic values were not explicit: %#v", diagnostic)
		}
	})

	t.Run("valid HTTP date is classified without retention", func(t *testing.T) {
		header := make(http.Header)
		header.Set("Retry-After", "Wed, 21 Oct 2015 07:28:00 GMT")
		diagnostic := normalizeM54PostDiagnostic(&http.Response{Header: header})
		if diagnostic.RetryAfterState != m54RetryAfterHTTPDate || diagnostic.RetryAfterSeconds != 0 {
			t.Fatalf("HTTP-date Retry-After differs: %#v", diagnostic)
		}
		if strings.Contains(diagnostic.evidence(t), "2015") {
			t.Fatal("raw Retry-After HTTP date entered evidence")
		}
	})

	t.Run("malformed provider values collapse to enums", func(t *testing.T) {
		tests := []struct {
			name   string
			header http.Header
			check  func(m54PostDiagnostic) bool
		}{
			{name: "oversized permission input", header: http.Header{"X-Accepted-Github-Permissions": []string{strings.Repeat("x", m54DiagnosticValueLimit+1)}}, check: func(value m54PostDiagnostic) bool { return value.AcceptedPermissionsState == m54DiagnosticMalformed }},
			{name: "permission grammar", header: http.Header{"X-Accepted-Github-Permissions": []string{"pull_requests:write"}}, check: func(value m54PostDiagnostic) bool { return value.AcceptedPermissionsState == m54DiagnosticMalformed }},
			{name: "permission duplicate in set", header: http.Header{"X-Accepted-Github-Permissions": []string{"pull_requests=write,pull_requests=read"}}, check: func(value m54PostDiagnostic) bool { return value.AcceptedPermissionsState == m54DiagnosticMalformed }},
			{name: "duplicate equivalent alternatives", header: http.Header{"X-Accepted-Github-Permissions": []string{"contents=read,pull_requests=write;pull_requests=write,contents=read"}}, check: func(value m54PostDiagnostic) bool { return value.AcceptedPermissionsState == m54DiagnosticMalformed }},
			{name: "empty alternative", header: http.Header{"X-Accepted-Github-Permissions": []string{"contents=read;;pull_requests=write"}}, check: func(value m54PostDiagnostic) bool { return value.AcceptedPermissionsState == m54DiagnosticMalformed }},
			{name: "malformed separator", header: http.Header{"X-Accepted-Github-Permissions": []string{"contents=read,,pull_requests=write"}}, check: func(value m54PostDiagnostic) bool { return value.AcceptedPermissionsState == m54DiagnosticMalformed }},
			{name: "unknown permission", header: http.Header{"X-Accepted-Github-Permissions": []string{"members=read"}}, check: func(value m54PostDiagnostic) bool { return value.AcceptedPermissionsState == m54DiagnosticMalformed }},
			{name: "duplicate header", header: http.Header{"X-Accepted-Github-Permissions": []string{"pull_requests=write", "contents=read"}}, check: func(value m54PostDiagnostic) bool { return value.AcceptedPermissionsState == m54DiagnosticMalformed }},
			{name: "integer", header: http.Header{"X-Ratelimit-Remaining": []string{"-1"}}, check: func(value m54PostDiagnostic) bool { return value.RateLimitRemainingState == m54DiagnosticMalformed }},
			{name: "permission control", header: http.Header{"X-Accepted-Github-Permissions": []string{"pull_requests=write\r\nmalicious"}}, check: func(value m54PostDiagnostic) bool { return value.AcceptedPermissionsState == m54DiagnosticMalformed }},
			{name: "retry bound", header: http.Header{"Retry-After": []string{strconv.FormatUint(m54RetryAfterMaxSeconds+1, 10)}}, check: func(value m54PostDiagnostic) bool { return value.RetryAfterState == m54DiagnosticMalformed }},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				diagnostic := normalizeM54PostDiagnostic(&http.Response{Header: test.header})
				if !test.check(diagnostic) {
					t.Fatalf("provider value was not rejected: %#v", diagnostic)
				}
			})
		}
	})

	t.Run("secret-shaped provider data never reaches evidence", func(t *testing.T) {
		const secret = "SECRETVALUE123"
		header := make(http.Header)
		header.Set("X-Accepted-GitHub-Permissions", "pull_requests=write; "+secret+"=read")
		header.Set("X-RateLimit-Resource", secret)
		header.Set("Retry-After", secret)
		header.Set("X-GitHub-Request-Id", secret)
		evidence := normalizeM54PostDiagnostic(&http.Response{StatusCode: http.StatusForbidden, Header: header}).evidence(t)
		if strings.Contains(evidence, secret) {
			t.Fatal("provider-controlled secret-shaped value entered normalized evidence")
		}
	})
}

func validM54PullRequestQuery(requestURL *url.URL) bool {
	if requestURL == nil || requestURL.ForceQuery {
		return false
	}
	values, err := url.ParseQuery(requestURL.RawQuery)
	if err != nil || requestURL.RawQuery != values.Encode() || len(values) != 5 {
		return false
	}
	target, ok := gitrefs.BranchName(gitrefs.RunTarget(m54LiveRunID))
	if !ok {
		return false
	}
	expected := map[string]string{
		"base":     "main",
		"head":     "mrgray17:" + target,
		"page":     values.Get("page"),
		"per_page": "50",
		"state":    "all",
	}
	if expected["page"] != "1" && expected["page"] != "2" {
		return false
	}
	for key, value := range expected {
		observed, exists := values[key]
		if !exists || len(observed) != 1 || observed[0] != value {
			return false
		}
	}
	return true
}

func TestM54LiveTransportExactAllowlistAndOneWayPostFuse(t *testing.T) {
	target, ok := gitrefs.BranchName(gitrefs.RunTarget(m54LiveRunID))
	if !ok {
		t.Fatal("fixed live target is invalid")
	}
	query := url.Values{
		"base":     []string{"main"},
		"head":     []string{"mrgray17:" + target},
		"page":     []string{"1"},
		"per_page": []string{"50"},
		"state":    []string{"all"},
	}.Encode()
	recorder := &m54RecordingDoer{}
	fuse := &m54CountingDoer{client: recorder}

	for _, rawURL := range []string{
		"https://api.github.com/repos/" + m54LiveRepository,
		"https://api.github.com/repos/" + m54LiveRepository + "/pulls?" + query,
	} {
		request, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := fuse.Do(request)
		if err != nil {
			t.Fatalf("allowed GET rejected: %v", err)
		}
		_ = response.Body.Close()
	}
	if recorder.calls.Load() != 2 || fuse.posts.Load() != 0 {
		t.Fatalf("allowed GET accounting differs: calls=%d posts=%d", recorder.calls.Load(), fuse.posts.Load())
	}

	for _, test := range []struct {
		method string
		url    string
	}{
		{method: http.MethodGet, url: "https://api.github.com/repos/" + m54LiveRepository + "/"},
		{method: http.MethodGet, url: "https://api.github.com/repos/" + m54LiveRepository + "?extra=1"},
		{method: http.MethodGet, url: "https://api.github.com/repos/" + m54LiveRepository + "/pulls"},
		{method: http.MethodGet, url: "https://api.github.com/repos/" + m54LiveRepository + "/pulls?" + query + "&extra=1"},
		{method: http.MethodGet, url: "https://api.github.com/repos/" + m54LiveRepository + "/pulls?" + strings.Replace(query, "page=1", "page=3", 1)},
		{method: http.MethodPost, url: "https://api.github.com/repos/" + m54LiveRepository + "/pulls?extra=1"},
		{method: http.MethodPatch, url: "https://api.github.com/repos/" + m54LiveRepository + "/pulls"},
		{method: http.MethodGet, url: "https://example.invalid/repos/" + m54LiveRepository},
	} {
		request, err := http.NewRequest(test.method, test.url, nil)
		if err != nil {
			t.Fatal(err)
		}
		if response, err := fuse.Do(request); err == nil || response != nil {
			t.Fatalf("transport accepted forbidden request %s %s", test.method, test.url)
		}
	}
	if recorder.calls.Load() != 2 || fuse.posts.Load() != 0 {
		t.Fatalf("forbidden requests reached transport: calls=%d posts=%d", recorder.calls.Load(), fuse.posts.Load())
	}

	post, err := http.NewRequest(http.MethodPost, "https://api.github.com/repos/"+m54LiveRepository+"/pulls", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := fuse.Do(post)
	if err != nil {
		t.Fatalf("first POST rejected: %v", err)
	}
	_ = response.Body.Close()
	second, err := http.NewRequest(http.MethodPost, post.URL.String(), strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if response, err := fuse.Do(second); err == nil || response != nil {
		t.Fatal("second POST passed the one-way transport fuse")
	}
	if recorder.calls.Load() != 3 || fuse.posts.Load() != 2 {
		t.Fatalf("second POST was not blocked before transport: calls=%d posts=%d", recorder.calls.Load(), fuse.posts.Load())
	}
	if diagnostic, ok := fuse.postDiagnostic(); !ok || diagnostic.HTTPStatus != http.StatusOK {
		t.Fatalf("first POST diagnostic was not retained across blocked second dispatch: ok=%t diagnostic=%#v", ok, diagnostic)
	}

	t.Run("failed first dispatch permanently consumes fuse", func(t *testing.T) {
		failure := &m54RecordingDoer{err: errors.New("simulated connection reset")}
		failedFuse := &m54CountingDoer{client: failure}
		first, _ := http.NewRequest(http.MethodPost, post.URL.String(), strings.NewReader("{}"))
		if response, err := failedFuse.Do(first); err == nil || response != nil {
			t.Fatal("simulated first transport failure was not observed")
		}
		second, _ := http.NewRequest(http.MethodPost, post.URL.String(), strings.NewReader("{}"))
		if response, err := failedFuse.Do(second); err == nil || response != nil {
			t.Fatal("POST fuse reset after transport failure")
		}
		if failure.calls.Load() != 1 || failedFuse.posts.Load() != 2 {
			t.Fatalf("failed dispatch fuse accounting differs: calls=%d posts=%d", failure.calls.Load(), failedFuse.posts.Load())
		}
		if _, ok := failedFuse.postDiagnostic(); ok {
			t.Fatal("transport failure fabricated a provider response diagnostic")
		}
	})
}

type m54RecordingDoer struct {
	calls atomic.Int64
	err   error
}

func (d *m54RecordingDoer) Do(*http.Request) (*http.Response, error) {
	d.calls.Add(1)
	if d.err != nil {
		return nil, d.err
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header)}, nil
}

func newM54LiveHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ResponseHeaderTimeout = 10 * time.Second
	transport.ExpectContinueTimeout = time.Second
	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("GitHub redirects are forbidden")
		},
	}
}

type m54LiveAuditClient struct {
	token  string
	client *http.Client
}

type m54RemoteInventory struct {
	repositoryID      int64
	branches          map[string]string
	pullRequests      map[int64]m54PullRequestInventory
	branchDigest      string
	pullRequestDigest string
}

type m54PullRequestInventory struct {
	Number           int64  `json:"number"`
	StableID         int64  `json:"stable_id"`
	State            string `json:"state"`
	Draft            bool   `json:"draft"`
	URL              string `json:"url"`
	TitleDigest      string `json:"title_digest"`
	BodyDigest       string `json:"body_digest"`
	BaseRef          string `json:"base_ref"`
	BaseSHA          string `json:"base_sha"`
	BaseRepositoryID int64  `json:"base_repository_id"`
	BaseRepository   string `json:"base_repository"`
	HeadRef          string `json:"head_ref"`
	HeadSHA          string `json:"head_sha"`
	HeadRepositoryID int64  `json:"head_repository_id"`
	HeadRepository   string `json:"head_repository"`
}

func (a *m54LiveAuditClient) capture(t *testing.T, ctx context.Context) m54RemoteInventory {
	t.Helper()
	var repository struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
	}
	a.getJSON(t, ctx, "/repos/"+m54LiveRepository, &repository)
	canonical, err := contracts.CanonicalGitHubRepository(repository.FullName)
	if err != nil || canonical != m54LiveRepository || repository.ID != m54LiveRepositoryID {
		t.Fatalf("audit repository identity differs: id=%d err=%v", repository.ID, err)
	}

	branches := make(map[string]string)
	for page := 1; page <= m54LiveInventoryPages; page++ {
		var response []struct {
			Name   string `json:"name"`
			Commit struct {
				SHA string `json:"sha"`
			} `json:"commit"`
		}
		path := fmt.Sprintf("/repos/%s/branches?per_page=100&page=%d", m54LiveRepository, page)
		a.getJSON(t, ctx, path, &response)
		if len(response) > 100 {
			t.Fatal("GitHub branch inventory exceeded page bound")
		}
		for _, branch := range response {
			ref := "refs/heads/" + branch.Name
			if _, ok := gitrefs.BranchName(ref); !ok || !validM54OID(branch.Commit.SHA) {
				t.Fatal("GitHub branch inventory contained malformed authority")
			}
			if _, duplicate := branches[ref]; duplicate {
				t.Fatalf("GitHub branch inventory duplicated %s", ref)
			}
			branches[ref] = branch.Commit.SHA
		}
		if len(response) < 100 {
			break
		}
		if page == m54LiveInventoryPages {
			t.Fatal("GitHub branch inventory exceeded total page bound")
		}
	}

	pullRequests := make(map[int64]m54PullRequestInventory)
	for page := 1; page <= m54LiveInventoryPages; page++ {
		var response []struct {
			Number  int64  `json:"number"`
			ID      int64  `json:"id"`
			HTMLURL string `json:"html_url"`
			State   string `json:"state"`
			Draft   bool   `json:"draft"`
			Title   string `json:"title"`
			Body    string `json:"body"`
			Base    struct {
				Ref  string `json:"ref"`
				SHA  string `json:"sha"`
				Repo struct {
					ID       int64  `json:"id"`
					FullName string `json:"full_name"`
				} `json:"repo"`
			} `json:"base"`
			Head struct {
				Ref  string `json:"ref"`
				SHA  string `json:"sha"`
				Repo struct {
					ID       int64  `json:"id"`
					FullName string `json:"full_name"`
				} `json:"repo"`
			} `json:"head"`
		}
		path := fmt.Sprintf("/repos/%s/pulls?state=all&per_page=100&page=%d", m54LiveRepository, page)
		a.getJSON(t, ctx, path, &response)
		if len(response) > 100 {
			t.Fatal("GitHub pull-request inventory exceeded page bound")
		}
		for _, pullRequest := range response {
			baseRepository, baseErr := contracts.CanonicalGitHubRepository(pullRequest.Base.Repo.FullName)
			headRepository, headErr := contracts.CanonicalGitHubRepository(pullRequest.Head.Repo.FullName)
			if pullRequest.Number <= 0 || pullRequest.ID <= 0 || baseErr != nil || headErr != nil || !validM54OID(pullRequest.Base.SHA) || !validM54OID(pullRequest.Head.SHA) {
				t.Fatal("GitHub pull-request inventory contained malformed identity")
			}
			canonicalURL, urlErr := canonicalM54PullRequestURL(pullRequest.HTMLURL, pullRequest.Number)
			if urlErr != nil {
				t.Fatal("GitHub pull-request inventory contained a non-canonical provider URL")
			}
			entry := m54PullRequestInventory{
				Number: pullRequest.Number, StableID: pullRequest.ID, State: pullRequest.State, Draft: pullRequest.Draft, URL: canonicalURL,
				TitleDigest: digestM54Bytes([]byte(pullRequest.Title)), BodyDigest: digestM54Bytes([]byte(pullRequest.Body)),
				BaseRef: "refs/heads/" + pullRequest.Base.Ref, BaseSHA: pullRequest.Base.SHA, BaseRepositoryID: pullRequest.Base.Repo.ID, BaseRepository: baseRepository,
				HeadRef: "refs/heads/" + pullRequest.Head.Ref, HeadSHA: pullRequest.Head.SHA, HeadRepositoryID: pullRequest.Head.Repo.ID, HeadRepository: headRepository,
			}
			if _, duplicate := pullRequests[entry.Number]; duplicate {
				t.Fatalf("GitHub pull-request inventory duplicated #%d", entry.Number)
			}
			pullRequests[entry.Number] = entry
		}
		if len(response) < 100 {
			break
		}
		if page == m54LiveInventoryPages {
			t.Fatal("GitHub pull-request inventory exceeded total page bound")
		}
	}
	return m54RemoteInventory{
		repositoryID:      repository.ID,
		branches:          branches,
		pullRequests:      pullRequests,
		branchDigest:      digestM54Canonical(t, branches),
		pullRequestDigest: digestM54Canonical(t, pullRequests),
	}
}

func (a *m54LiveAuditClient) getJSON(t *testing.T, ctx context.Context, path string, destination any) {
	t.Helper()
	if a == nil || a.client == nil || a.token == "" || !strings.HasPrefix(path, "/repos/"+m54LiveRepository) {
		t.Fatal("invalid hard-bound live audit request")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com"+path, nil)
	if err != nil {
		t.Fatal("construct bounded GitHub audit request")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+a.token)
	request.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	response, err := a.client.Do(request)
	if err != nil {
		t.Fatal("bounded GitHub audit request unavailable")
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, m54LiveResponseLimit+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) > int(m54LiveResponseLimit) || response.StatusCode != http.StatusOK {
		t.Fatalf("bounded GitHub audit response unavailable: status=%d", response.StatusCode)
	}
	if err := json.Unmarshal(body, destination); err != nil {
		t.Fatal("malformed GitHub audit response")
	}
}

func (inventory m54RemoteInventory) hasPullRequestTuple(baseRef, targetRef string) bool {
	for _, pullRequest := range inventory.pullRequests {
		if pullRequest.BaseRef == baseRef && pullRequest.HeadRef == targetRef && pullRequest.BaseRepositoryID == m54LiveRepositoryID && pullRequest.HeadRepositoryID == m54LiveRepositoryID && pullRequest.BaseRepository == m54LiveRepository && pullRequest.HeadRepository == m54LiveRepository {
			return true
		}
	}
	return false
}

func requireM54EvidenceBranches(t *testing.T, inventory m54RemoteInventory) {
	t.Helper()
	expected := map[string]string{
		m54LiveBaseRef:           m54LiveBaseOID,
		m53LiveEvidenceRef:       m53LiveEvidenceOID,
		m54FailedLiveEvidenceRef: m54FailedLiveEvidenceOID,
	}
	for ref, oid := range expected {
		if inventory.branches[ref] != oid {
			t.Fatalf("required immutable evidence branch differs: ref=%s want=%s got=%s", ref, oid, inventory.branches[ref])
		}
	}
}

func assertM54RemoteDelta(t *testing.T, before, after m54RemoteInventory, plan *githubpullrequest.Plan, identity *githubpullrequest.PullRequestIdentity) {
	t.Helper()
	if before.repositoryID != m54LiveRepositoryID || after.repositoryID != m54LiveRepositoryID {
		t.Fatal("repository stable identity changed")
	}
	if len(after.branches) != len(before.branches)+1 || after.branches[plan.TargetRef()] != plan.CommitOID() {
		t.Fatalf("remote branch delta is not exactly one bound create: before=%d after=%d", len(before.branches), len(after.branches))
	}
	for ref, oid := range before.branches {
		if after.branches[ref] != oid {
			t.Fatalf("preexisting remote branch changed: %s", ref)
		}
	}
	if len(after.pullRequests) != len(before.pullRequests)+1 {
		t.Fatalf("remote PR delta is not exactly one create: before=%d after=%d", len(before.pullRequests), len(after.pullRequests))
	}
	for number, pullRequest := range before.pullRequests {
		if after.pullRequests[number] != pullRequest {
			t.Fatalf("preexisting remote PR changed: #%d", number)
		}
	}
	created, ok := after.pullRequests[identity.Number()]
	if !ok || created.StableID != identity.StableID() || created.State != "open" || created.Draft || created.URL != identity.URL() || created.BaseRef != plan.BaseRef() || created.BaseSHA != plan.BaseCommit() || created.BaseRepositoryID != m54LiveRepositoryID || created.BaseRepository != m54LiveRepository || created.HeadRef != plan.TargetRef() || created.HeadSHA != plan.CommitOID() || created.HeadRepositoryID != m54LiveRepositoryID || created.HeadRepository != m54LiveRepository || created.TitleDigest != plan.Metadata().TitleDigest() || created.BodyDigest != plan.Metadata().BodyDigest() {
		t.Fatal("created remote PR inventory entry differs from exact MIRAGE authority")
	}
}

func assertM54FailedRemoteDelta(t *testing.T, before, after m54RemoteInventory, plan *githubpullrequest.Plan) {
	t.Helper()
	if before.repositoryID != m54LiveRepositoryID || after.repositoryID != m54LiveRepositoryID {
		t.Fatal("repository stable identity changed")
	}
	if len(after.branches) != len(before.branches)+1 || after.branches[plan.TargetRef()] != plan.CommitOID() {
		t.Fatalf("failed proof branch delta is not exactly one bound create: before=%d after=%d", len(before.branches), len(after.branches))
	}
	for ref, oid := range before.branches {
		if after.branches[ref] != oid {
			t.Fatalf("preexisting remote branch changed during failed proof: %s", ref)
		}
	}
	if len(after.pullRequests) != len(before.pullRequests) {
		t.Fatalf("failed proof changed PR inventory: before=%d after=%d", len(before.pullRequests), len(after.pullRequests))
	}
	for number, pullRequest := range before.pullRequests {
		if after.pullRequests[number] != pullRequest {
			t.Fatalf("preexisting remote PR changed during failed proof: #%d", number)
		}
	}
}

func requireM54LiveLocalTruth(t *testing.T, sourceRoot, real, disposablePath string, readmeBefore []byte, token string) {
	t.Helper()
	if !bytes.Equal(mustReadM54(t, filepath.Join(real, "README.md")), readmeBefore) {
		t.Fatal("trusted worktree README changed during publication proof")
	}
	if containsM54Secret(t, sourceRoot, token) || containsM54Secret(t, real, token) || containsM54Secret(t, disposablePath, token) {
		t.Fatal("host credential entered a repository or disposable workspace")
	}
}

func finishM54LiveLocalProof(t *testing.T, lifecycle *Lifecycle, disposable *workspace.Disposable, disposablePath, real string, localBefore m54LocalState, destroyed, cleanedDisposable *bool) {
	t.Helper()
	if err := lifecycle.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	*destroyed = true
	if err := disposable.Cleanup(); err != nil {
		t.Fatal(err)
	}
	*cleanedDisposable = true
	if _, err := os.Lstat(disposablePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("disposable workspace leaked: %v", err)
	}
	localAfter := captureM54LocalState(t, real)
	if localAfter != localBefore {
		t.Fatalf("trusted checkout Git state changed:\nbefore=%+v\nafter=%+v", localBefore, localAfter)
	}
	requireM54CleanRepository(t, real)
}

type m54LocalState struct {
	Worktree   string
	Index      string
	HEAD       string
	Refs       string
	PackedRefs string
	Reflogs    string
	Config     string
	Objects    string
}

func requireM54ReviewedSource(t *testing.T, expectedHead string) (string, string) {
	t.Helper()
	if !validM54OID(expectedHead) {
		t.Fatal("reviewed live-harness head is malformed")
	}
	root := strings.TrimSpace(runM54Git(t, "", "rev-parse", "--show-toplevel"))
	root = requireM54PhysicalDirectory(t, root)
	head := strings.TrimSpace(runM54Git(t, root, "rev-parse", "HEAD"))
	if !validM54OID(head) || head != expectedHead {
		t.Fatalf("MIRAGE source HEAD %s does not equal reviewed live-harness head %s", head, expectedHead)
	}
	if status := runM54Git(t, root, "status", "--porcelain=v2", "--untracked-files=all"); status != "" {
		t.Fatal("MIRAGE source checkout must be clean for the live proof")
	}
	command := exec.Command(m54GitExecutable(), "-C", root, "merge-base", "--is-ancestor", m54ReviewedHead, head)
	command.Env = m54GitEnvironment()
	if err := command.Run(); err != nil {
		t.Fatalf("reviewed production head %s is not an ancestor of source HEAD %s", m54ReviewedHead, head)
	}
	changed := strings.Fields(runM54Git(t, root, "diff", "--name-only", m54ReviewedHead+".."+head))
	if len(changed) != 1 || filepath.ToSlash(changed[0]) != m54LiveHarnessPath {
		t.Fatalf("source after reviewed production head contains non-harness changes: %v", changed)
	}
	return root, head
}

func requireM54CleanRepository(t *testing.T, root string) string {
	t.Helper()
	real := requireM54PhysicalDirectory(t, root)
	if status := runM54Git(t, real, "status", "--porcelain=v2", "--untracked-files=all"); status != "" {
		t.Fatal("dedicated live-proof checkout must be clean")
	}
	if got := strings.TrimSpace(runM54Git(t, real, "rev-parse", "--is-inside-work-tree")); got != "true" {
		t.Fatal("dedicated live-proof root is not a Git worktree")
	}
	return real
}

func requireM54PhysicalDirectory(t *testing.T, path string) string {
	t.Helper()
	absolute, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		t.Fatalf("resolve directory: %v", err)
	}
	physical, err := filepath.EvalSymlinks(filepath.Clean(absolute))
	if err != nil {
		t.Fatalf("resolve physical directory: %v", err)
	}
	info, err := os.Lstat(physical)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("live-proof path is not a physical directory: %v", err)
	}
	return filepath.Clean(physical)
}

func captureM54LocalState(t *testing.T, root string) m54LocalState {
	t.Helper()
	gitDir := strings.TrimSpace(runM54Git(t, root, "rev-parse", "--absolute-git-dir"))
	gitDir = requireM54PhysicalDirectory(t, gitDir)
	resolvedHEAD := strings.TrimSpace(runM54Git(t, root, "rev-parse", "HEAD"))
	if !validM54OID(resolvedHEAD) {
		t.Fatal("trusted checkout HEAD is malformed")
	}
	return m54LocalState{
		Worktree:   digestM54Tree(t, root, true),
		Index:      digestM54Path(t, filepath.Join(gitDir, "index")),
		HEAD:       digestM54Bytes(append(mustReadM54(t, filepath.Join(gitDir, "HEAD")), []byte("\x00"+resolvedHEAD)...)),
		Refs:       digestM54Path(t, filepath.Join(gitDir, "refs")),
		PackedRefs: digestM54Path(t, filepath.Join(gitDir, "packed-refs")),
		Reflogs:    digestM54Path(t, filepath.Join(gitDir, "logs")),
		Config:     digestM54Path(t, filepath.Join(gitDir, "config")),
		Objects:    digestM54Path(t, filepath.Join(gitDir, "objects")),
	}
}

func runM54Git(t *testing.T, root string, arguments ...string) string {
	t.Helper()
	args := append([]string(nil), arguments...)
	if root != "" {
		args = append([]string{"-C", root}, args...)
	}
	command := exec.Command(m54GitExecutable(), args...)
	command.Env = m54GitEnvironment()
	var output m54BoundedBuffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		t.Fatalf("trusted read-only Git command failed: %v", err)
	}
	return string(output.Bytes())
}

func m54GitExecutable() string {
	if executable, err := exec.LookPath("git"); err == nil {
		return executable
	}
	return "git"
}

func m54GitEnvironment() []string {
	environment := []string{
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_NO_LAZY_FETCH=1",
		"GIT_NO_REPLACE_OBJECTS=1",
		"GIT_PROTOCOL_FROM_USER=0",
		"GIT_TERMINAL_PROMPT=0",
	}
	for _, key := range []string{"SystemRoot", "WINDIR", "ComSpec", "PATHEXT", "PATH", "LANG", "LC_ALL"} {
		if value := os.Getenv(key); value != "" {
			environment = append(environment, key+"="+value)
		}
	}
	return environment
}

type m54BoundedBuffer struct{ bytes.Buffer }

func (b *m54BoundedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	if b.Len()+len(value) > 1<<20 {
		return original, errors.New("trusted Git output exceeded bound")
	}
	_, err := b.Buffer.Write(value)
	return original, err
}

func digestM54Tree(t *testing.T, root string, skipTopLevelGit bool) string {
	t.Helper()
	hash := sha256.New()
	files := 0
	var total int64
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		if skipTopLevelGit && (relative == ".git" || strings.HasPrefix(relative, ".git"+string(filepath.Separator))) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		files++
		if files > 100000 {
			return errors.New("local-state file-count bound exceeded")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!entry.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("unsupported local-state object %s", filepath.ToSlash(relative))
		}
		fmt.Fprintf(hash, "%s\x00%o\x00%d\x00", filepath.ToSlash(relative), info.Mode()&os.ModeType|info.Mode().Perm(), info.Size())
		if entry.IsDir() {
			return nil
		}
		total += info.Size()
		if total > 1<<30 {
			return errors.New("local-state byte bound exceeded")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return errors.Join(copyErr, closeErr)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("capture local-state tree %s: %v", root, err)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func digestM54Path(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return digestM54Bytes([]byte("ABSENT"))
	}
	if err != nil {
		t.Fatalf("inspect local-state path: %v", err)
	}
	if info.IsDir() {
		return digestM54Tree(t, path, false)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("unsupported local-state path object: %s", path)
	}
	return digestM54Bytes(mustReadM54(t, path))
}

func mustReadM54(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return contents
}

func digestM54Bytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func digestM54Canonical(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("canonicalize live inventory: %v", err)
	}
	return digestM54Bytes(encoded)
}

func validM54OID(value string) bool {
	if len(value) != 40 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func containsM54Secret(t *testing.T, root, secret string) bool {
	t.Helper()
	if secret == "" {
		t.Fatal("refusing empty credential leak scan")
	}
	needle := []byte(secret)
	found := false
	files := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		files++
		if files > 100000 || info.Size() > 64<<20 {
			return errors.New("credential leak scan bound exceeded")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		buffer := make([]byte, 64<<10)
		overlap := make([]byte, 0, len(needle)-1)
		for {
			count, readErr := file.Read(buffer)
			if count > 0 {
				chunk := append(append([]byte(nil), overlap...), buffer[:count]...)
				if bytes.Contains(chunk, needle) {
					_ = file.Close()
					found = true
					return io.EOF
				}
				keep := len(needle) - 1
				if keep > len(chunk) {
					keep = len(chunk)
				}
				overlap = append(overlap[:0], chunk[len(chunk)-keep:]...)
			}
			if errors.Is(readErr, io.EOF) {
				return file.Close()
			}
			if readErr != nil {
				return errors.Join(readErr, file.Close())
			}
		}
	})
	if found && errors.Is(err, io.EOF) {
		return true
	}
	if err != nil {
		t.Fatalf("credential leak scan failed: %v", err)
	}
	return found
}

func pathsOverlapForM54(first, second string) bool {
	for _, pair := range [][2]string{{first, second}, {second, first}} {
		relative, err := filepath.Rel(pair[0], pair[1])
		if err == nil && (relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))) {
			return true
		}
	}
	return false
}

func canonicalM54PullRequestURL(value string, number int64) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "github.com" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("invalid provider PR URL")
	}
	parts := strings.Split(parsed.Path, "/")
	if len(parts) != 5 || parts[0] != "" || parts[3] != "pull" || parts[4] != fmt.Sprint(number) {
		return "", errors.New("invalid provider PR URL path")
	}
	repository, err := contracts.CanonicalGitHubRepository(parts[1] + "/" + parts[2])
	if err != nil || repository != m54LiveRepository {
		return "", errors.New("provider PR URL repository differs")
	}
	return fmt.Sprintf("https://github.com/%s/pull/%d", m54LiveRepository, number), nil
}
