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
	"strings"
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
	m54LiveRepositoryInput = "MrGray17/test"
	m54LiveRepository      = "mrgray17/test"
	m54LiveRepositoryID    = int64(1351679704)
	m54ReviewedHead        = "17483b55a2395181ae2ea62aef6a099e61240acc"
	m54LiveRunID           = "m54-live-17483b55a2395181ae2ea62aef6a099e61240acc"
	m54LiveHarnessPath     = "internal/runtime/m54_live_test.go"
	m54LiveResponseLimit   = int64(2 << 20)
	m54LiveInventoryPages  = 5
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
	if os.Getenv("MIRAGE_M54_EXPECTED_HEAD") != m54ReviewedHead {
		t.Fatalf("MIRAGE_M54_EXPECTED_HEAD must bind reviewed production head %s", m54ReviewedHead)
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

	sourceRoot, sourceHead := requireM54ReviewedSource(t)
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
	if _, exists := remoteBefore.branches[targetRef]; exists {
		t.Fatalf("single-use target ref already exists: %s", targetRef)
	}
	if remoteBefore.hasPullRequestTuple("refs/heads/main", targetRef) {
		t.Fatal("single-use pull-request tuple already exists")
	}
	baseBefore, err := readClient.ExactRef(ctx, m54LiveRepository, m54LiveRepositoryID, "refs/heads/main", gitBinding.HeadCommit())
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
	if establishErr != nil || ledger == nil {
		t.Fatalf("PR effect did not establish exact truth: state=%s err=%v", lifecycle.State(), establishErr)
	}
	if prEngine.establishes.Load() != 1 || prTransport.posts.Load() != 1 || prEngine.reconciles.Load() > 1 {
		t.Fatalf("mutation budget violated: establish=%d POST=%d reconcile=%d", prEngine.establishes.Load(), prTransport.posts.Load(), prEngine.reconciles.Load())
	}
	if lifecycle.State() != StatePREstablished || ledger.PullRequestOutcome() != githubpullrequest.OutcomeCreated || !ledger.Attempted() || !ledger.TransportAcknowledged() || ledger.ObservationStatus() != githubpullrequest.ObservationExact || ledger.Causality() != githubpullrequest.CausalityMirageAcknowledged {
		t.Fatalf("final PR ledger is not acknowledged exact creation: state=%s outcome=%s observation=%s", lifecycle.State(), ledger.PullRequestOutcome(), ledger.ObservationStatus())
	}
	attempt := lifecycle.PullRequestAttempt()
	if attempt == nil || attempt.Identity() != ledger.AttemptIdentity() || attempt.PlanIdentity() != prPlan.Identity() {
		t.Fatal("PR attempt latch is absent or differs from the immutable plan/ledger")
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

	if !bytes.Equal(mustReadM54(t, filepath.Join(real, "README.md")), readmeBefore) {
		t.Fatal("trusted worktree README changed during publication proof")
	}
	if containsM54Secret(t, sourceRoot, token) || containsM54Secret(t, real, token) || containsM54Secret(t, disposablePath, token) {
		t.Fatal("host credential entered a repository or disposable workspace")
	}
	evidence := fmt.Sprintf("run=%s repository=%s repository_id=%d base_ref=%s base_commit=%s target_ref=%s commit_oid=%s publication_record=%s branch_transport_acknowledged=%t branch_reconciled=%t pr_plan=%s metadata_policy=%s title_digest=%s body_digest=%s attempt=%s outcome=%s pr_number=%d pr_stable_id=%d pr_url=%s pr_identity=%s transport_acknowledged=%t exact_postflight=%t reconciled=%t causality=%s ledger=%s ledger_base_commit=%s lifecycle=%s source_head=%s branch_inventory_before=%s pr_inventory_before=%s branch_inventory_after=%s pr_inventory_after=%s",
		m54LiveRunID, m54LiveRepository, m54LiveRepositoryID, prPlan.BaseRef(), prPlan.BaseCommit(), prPlan.TargetRef(), prPlan.CommitOID(), record.Identity(), record.TransportAcknowledged(), record.ResolvedByReconciliation(), prPlan.Identity(), prPlan.Metadata().Version(), prPlan.Metadata().TitleDigest(), prPlan.Metadata().BodyDigest(), attempt.Identity(), ledger.PullRequestOutcome(), pullRequest.Number(), pullRequest.StableID(), pullRequest.URL(), pullRequest.Identity(), ledger.TransportAcknowledged(), ledger.ObservationStatus() == githubpullrequest.ObservationExact, ledger.ObservationStatus() != githubpullrequest.ObservationUnavailable, ledger.Causality(), ledger.Identity(), ledger.PullRequestBaseCommit(), lifecycle.State(), sourceHead, remoteBefore.branchDigest, remoteBefore.pullRequestDigest, remoteAfter.branchDigest, remoteAfter.pullRequestDigest)
	if strings.Contains(evidence, token) {
		t.Fatal("credential entered sanitized live evidence")
	}
	t.Log(evidence)

	if err := lifecycle.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	destroyed = true
	if err := disposable.Cleanup(); err != nil {
		t.Fatal(err)
	}
	cleanedDisposable = true
	if _, err := os.Lstat(disposablePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("disposable workspace leaked: %v", err)
	}
	localAfter := captureM54LocalState(t, real)
	if localAfter != localBefore {
		t.Fatalf("trusted checkout Git state changed:\nbefore=%+v\nafter=%+v", localBefore, localAfter)
	}
	requireM54CleanRepository(t, real)
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
	client *http.Client
	posts  atomic.Int64
}

func (d *m54CountingDoer) Do(request *http.Request) (*http.Response, error) {
	if d == nil || d.client == nil || request == nil || request.URL.Scheme != "https" || request.URL.Host != "api.github.com" || !strings.HasPrefix(request.URL.Path, "/repos/"+m54LiveRepository+"/") {
		return nil, errors.New("live proof transport rejected non-bound GitHub request")
	}
	if request.Method == http.MethodPost {
		d.posts.Add(1)
	} else if request.Method != http.MethodGet {
		return nil, errors.New("live proof transport rejected unsupported method")
	}
	return d.client.Do(request)
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

func requireM54ReviewedSource(t *testing.T) (string, string) {
	t.Helper()
	root := strings.TrimSpace(runM54Git(t, "", "rev-parse", "--show-toplevel"))
	root = requireM54PhysicalDirectory(t, root)
	head := strings.TrimSpace(runM54Git(t, root, "rev-parse", "HEAD"))
	if !validM54OID(head) {
		t.Fatal("MIRAGE source HEAD is malformed")
	}
	if status := runM54Git(t, root, "status", "--porcelain=v2", "--untracked-files=all"); status != "" {
		t.Fatal("MIRAGE source checkout must be clean for the live proof")
	}
	if head != m54ReviewedHead {
		command := exec.Command(m54GitExecutable(), "-C", root, "merge-base", "--is-ancestor", m54ReviewedHead, head)
		command.Env = m54GitEnvironment()
		if err := command.Run(); err != nil {
			t.Fatalf("reviewed production head %s is not an ancestor of source HEAD %s", m54ReviewedHead, head)
		}
		changed := strings.Fields(runM54Git(t, root, "diff", "--name-only", m54ReviewedHead+".."+head))
		if len(changed) != 1 || filepath.ToSlash(changed[0]) != m54LiveHarnessPath {
			t.Fatalf("source after reviewed production head contains non-harness changes: %v", changed)
		}
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
