package gitpublication

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/runtime/gitbinding"
	"github.com/MrGray17/Mirage/internal/runtime/gitcommit"
	"github.com/MrGray17/Mirage/internal/runtime/githubbinding"
	"github.com/MrGray17/Mirage/internal/runtime/gitplan"
	"github.com/MrGray17/Mirage/internal/runtime/reconcile"
	"github.com/MrGray17/Mirage/internal/runtime/tree"
)

const (
	publicationManifest = "sha256:m53-publication-manifest"
	publicationRepo     = "mrgray17/mirage-test"
	fakeSecret          = "m53-distinctive-secret-never-persist"
)

type publicationFixture struct {
	at             time.Time
	repositoryRoot string
	repository     *gitbinding.Binding
	contract       *contracts.Contract
	reconciliation *tree.Plan
	decision       reconcile.Decision
	gitPlan        *gitplan.Plan
	artifact       *gitcommit.Artifact
	remote         string
	observer       *bareObserver
	github         *githubbinding.Binding
	plan           *Plan
}

func newPublicationFixture(t *testing.T) publicationFixture {
	return newPublicationFixtureVersion(t, contracts.VersionV2)
}

func newPublicationFixtureVersion(t *testing.T, contractVersion string) publicationFixture {
	t.Helper()
	at := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	runFixtureGit(t, root, "init", "-b", "main")
	writeFixtureFile(t, root, "unchanged.txt", []byte("unchanged\n"))
	runFixtureGit(t, root, "add", "--", ".")
	runFixtureGit(t, root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "seed")
	writeFixtureFile(t, root, "README.md", []byte("before\n"))
	runFixtureGit(t, root, "add", "--", "README.md")
	runFixtureGit(t, root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "base")
	repository, err := gitbinding.Capture(root, publicationManifest, at.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	baselineRoot := t.TempDir()
	writeFixtureFile(t, baselineRoot, "README.md", []byte("before\n"))
	writeFixtureFile(t, baselineRoot, "unchanged.txt", []byte("unchanged\n"))
	baseline, err := tree.Scan(baselineRoot, tree.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	finalRoot := t.TempDir()
	writeFixtureFile(t, finalRoot, "README.md", []byte("authorized\n"))
	writeFixtureFile(t, finalRoot, "unchanged.txt", []byte("unchanged\n"))
	runID := "m53-publication"
	targetRef := "refs/heads/mirage/run-" + sha256Prefix(runID)
	contractSpec := contracts.Spec{Version: contractVersion, RunID: runID, ActorID: "agent", ExpiresAt: at.Add(time.Hour), Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{Allow: []string{"/workspace/README.md"}}}}
	if contractVersion == contracts.VersionV2 {
		contractSpec.GitHub = contracts.GitHubPublicationPolicy{RepositoryFullName: publicationRepo, TargetRef: targetRef, Operation: contracts.GitHubCreateBranch}
	} else {
		contractSpec.GitHubV3 = contracts.GitHubEffectsPolicy{
			RepositoryFullName: publicationRepo,
			Branch:             contracts.GitHubBranchPolicy{TargetRef: targetRef, Operation: contracts.GitHubCreateBranch},
			PullRequest:        contracts.GitHubPullRequestPolicy{BaseRef: repository.HeadRef(), TargetRef: targetRef, Operation: contracts.GitHubCreatePullRequest, MetadataPolicy: contracts.PullRequestMetadataV1},
		}
	}
	contract, err := contracts.New(contractSpec)
	if err != nil {
		t.Fatal(err)
	}
	reconciliation, decision, err := reconcile.Verify(publicationManifest, baseline, finalRoot, contract, at)
	if err != nil || !decision.Allowed {
		t.Fatalf("reconcile = %#v, %v", decision, err)
	}
	gitPlan, err := gitplan.New(gitplan.Spec{RunID: runID, ManifestHash: publicationManifest, Contract: contract, Repository: repository, ReconciliationPlan: reconciliation, Decision: decision, CreatedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := gitcommit.Construct(gitcommit.Spec{ManifestHash: publicationManifest, Contract: contract, Repository: repository, GitPlan: gitPlan, ReconciliationPlan: reconciliation, Decision: decision, ObservedAt: at.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = artifact.Cleanup() })
	remote := filepath.Join(t.TempDir(), "remote.git")
	runFixtureGit(t, filepath.Dir(remote), "init", "--bare", remote)
	runFixtureGit(t, root, "push", remote, repository.HeadCommit()+":"+repository.HeadRef())
	observer := &bareObserver{remote: remote, repository: githubbinding.Repository{ID: 1729, FullName: publicationRepo}}
	github, err := githubbinding.Capture(context.Background(), observer, publicationRepo, contract.Hash(), publicationManifest, gitPlan.BaseRef(), gitPlan.BaseCommit(), at.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewPlan(PlanSpec{ManifestHash: publicationManifest, Contract: contract, Repository: repository, GitPlan: gitPlan, Artifact: artifact, GitHub: github, CreatedAt: at.Add(2 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	return publicationFixture{at: at, repositoryRoot: root, repository: repository, contract: contract, reconciliation: reconciliation, decision: decision, gitPlan: gitPlan, artifact: artifact, remote: remote, observer: observer, github: github, plan: plan}
}

func TestPublicationPlanAcceptsV3OnlyThroughExactBranchEvaluation(t *testing.T) {
	fixture := newPublicationFixtureVersion(t, contracts.VersionV3)
	if fixture.plan == nil || fixture.plan.ContractHash() != fixture.contract.Hash() {
		t.Fatal("v3 publication plan did not bind the exact contract")
	}
	decision := fixture.contract.EvaluateGitHubPublication(contracts.GitHubCreateBranch, publicationRepo, fixture.plan.TargetRef(), fixture.plan.CreatedAt())
	if !decision.Allowed {
		t.Fatalf("v3 exact branch authority denied: %#v", decision)
	}
	wrong := fixture.contract.EvaluateGitHubPublication(contracts.GitHubCreateBranch, publicationRepo, fixture.plan.TargetRef()+"x", fixture.plan.CreatedAt())
	if wrong.Allowed {
		t.Fatalf("v3 mismatched branch unexpectedly allowed: %#v", wrong)
	}
}

func TestPublicationPlanBindsExactArtifactDestinationAndIsIdempotent(t *testing.T) {
	fixture := newPublicationFixture(t)
	if fixture.plan.CommitOID() != fixture.artifact.CommitOID() || fixture.plan.ArtifactIdentity() != fixture.artifact.Identity() || fixture.plan.BaseRef() != fixture.gitPlan.BaseRef() || fixture.plan.BaseCommit() != fixture.gitPlan.BaseCommit() || fixture.plan.TargetRef() != fixture.gitPlan.TargetRef() || fixture.plan.RepositoryFullName() != publicationRepo || fixture.plan.GitHubRepositoryID() != 1729 || fixture.plan.Operation() != contracts.GitHubCreateBranch || fixture.plan.Identity() == "" {
		t.Fatalf("plan = %#v", fixture.plan)
	}
	spec := PlanSpec{ManifestHash: publicationManifest, Contract: fixture.contract, Repository: fixture.repository, GitPlan: fixture.gitPlan, Artifact: fixture.artifact, GitHub: fixture.github, CreatedAt: fixture.plan.CreatedAt()}
	if err := RevalidatePlan(fixture.plan, spec); err != nil {
		t.Fatal(err)
	}
	second, err := NewPlan(spec)
	if err != nil || second.Identity() != fixture.plan.Identity() {
		t.Fatalf("second = %#v, %v", second, err)
	}
	tampered := *fixture.plan
	tampered.baseRef = "refs/heads/other"
	if err := RevalidatePlan(&tampered, spec); !errors.Is(err, ErrAuthorityChanged) {
		t.Fatalf("base ref was not identity-bound: %v", err)
	}
	tampered = *fixture.plan
	tampered.baseCommit = strings.Repeat("f", 40)
	if err := RevalidatePlan(&tampered, spec); !errors.Is(err, ErrAuthorityChanged) {
		t.Fatalf("base commit was not identity-bound: %v", err)
	}
	if strings.Contains(fmt.Sprintf("%#v %#v", fixture.plan, fixture.artifact), fakeSecret) {
		t.Fatal("secret entered immutable authority")
	}
}

func TestRemoteBaseMustAlreadyContainTrustedHistoryBeforeAuthorityExists(t *testing.T) {
	fixture := newPublicationFixture(t)
	for _, test := range []struct {
		name string
		oid  string
	}{
		{name: "empty"},
		{name: "behind", oid: runFixtureGit(t, fixture.repositoryRoot, "rev-parse", "HEAD^")},
	} {
		t.Run(test.name, func(t *testing.T) {
			remote := filepath.Join(t.TempDir(), "remote.git")
			runFixtureGit(t, filepath.Dir(remote), "init", "--bare", remote)
			if test.oid != "" {
				runFixtureGit(t, fixture.repositoryRoot, "push", remote, test.oid+":"+fixture.gitPlan.BaseRef())
			}
			observer := &bareObserver{remote: remote, repository: githubbinding.Repository{ID: 1729, FullName: publicationRepo}}
			if _, err := githubbinding.Capture(context.Background(), observer, publicationRepo, fixture.contract.Hash(), publicationManifest, fixture.gitPlan.BaseRef(), fixture.gitPlan.BaseCommit(), fixture.at); !errors.Is(err, githubbinding.ErrRepositoryChanged) {
				t.Fatalf("capture = %v", err)
			}
			if observed := observer.observe(fixture.gitPlan.TargetRef(), fixture.artifact.CommitOID()); observed.Status != githubbinding.RefAbsent {
				t.Fatalf("target changed without authority: %#v", observed)
			}
			if gitObjectExists(remote, fixture.gitPlan.BaseCommit()) || gitObjectExists(remote, fixture.artifact.CommitOID()) {
				t.Fatal("M5.3 exported local-only base or candidate history before authority existed")
			}
		})
	}
}

func TestRemoteBaseDisappearingBeforePublicationPerformsNoPush(t *testing.T) {
	fixture := newPublicationFixture(t)
	runFixtureGit(t, fixture.remote, "update-ref", "-d", fixture.plan.BaseRef())
	runner := &countRunner{}
	engine, _ := NewEngine(fixture.observer, func() (string, error) { return fakeSecret, nil })
	engine.runner = runner
	result, err := engine.Publish(context.Background(), fixture.github, fixture.plan, fixture.artifact, fixture.repository, trustedDispatch(fixture.at))
	if !errors.Is(err, githubbinding.ErrRepositoryChanged) || result.Attempted || result.Record != nil || runner.calls != 0 {
		t.Fatalf("result=%#v err=%v calls=%d", result, err, runner.calls)
	}
	if observed := fixture.observer.observe(fixture.plan.TargetRef(), fixture.plan.CommitOID()); observed.Status != githubbinding.RefAbsent {
		t.Fatalf("target changed: %#v", observed)
	}
}

func TestRemoteBaseMovingBeforeFinalAuthorityPerformsNoPush(t *testing.T) {
	fixture := newPublicationFixture(t)
	runner := &countRunner{}
	engine, _ := NewEngine(fixture.observer, func() (string, error) { return fakeSecret, nil })
	engine.runner = runner
	parent := runFixtureGit(t, fixture.repositoryRoot, "rev-parse", "HEAD^")
	final := func(ctx context.Context) (time.Time, error) {
		runFixtureGit(t, fixture.remote, "update-ref", fixture.plan.BaseRef(), parent)
		if err := fixture.github.Revalidate(ctx, fixture.observer, fixture.plan.ContractHash(), fixture.plan.ManifestHash()); err != nil {
			return time.Time{}, err
		}
		return fixture.at.Add(3 * time.Minute), nil
	}
	result, err := engine.Publish(context.Background(), fixture.github, fixture.plan, fixture.artifact, fixture.repository, final)
	if !errors.Is(err, githubbinding.ErrRepositoryChanged) || result.Attempted || result.Record != nil || runner.calls != 0 {
		t.Fatalf("result=%#v err=%v calls=%d", result, err, runner.calls)
	}
	if observed := fixture.observer.observe(fixture.plan.TargetRef(), fixture.plan.CommitOID()); observed.Status != githubbinding.RefAbsent {
		t.Fatalf("target changed: %#v", observed)
	}
}

func TestLocalBarePublicationCreatesExactlyOneNewRefAndLeavesLocalGitIdentical(t *testing.T) {
	fixture := newPublicationFixture(t)
	before, err := snapshotGit(fixture.repository.GitDir())
	if err != nil {
		t.Fatal(err)
	}
	engine := newLocalEngine(t, fixture)
	cleanedRoot := trackCleanup(engine)
	callbackCalls := 0
	result, err := engine.Publish(context.Background(), fixture.github, fixture.plan, fixture.artifact, fixture.repository, func(context.Context) (time.Time, error) { callbackCalls++; return fixture.at.Add(3 * time.Minute), nil })
	if err != nil {
		t.Fatal(err)
	}
	if callbackCalls != 1 || result.Record == nil || result.Record.Outcome() != OutcomePublished || !result.Record.TransportAcknowledged() || !result.Record.ResolvedByReconciliation() {
		t.Fatalf("result = %#v calls=%d", result, callbackCalls)
	}
	if observed := fixture.observer.observe(fixture.gitPlan.TargetRef(), fixture.artifact.CommitOID()); observed.Status != githubbinding.RefPresentExact {
		t.Fatalf("remote = %#v", observed)
	}
	refs := runFixtureGit(t, fixture.remote, "for-each-ref", "--format=%(refname) %(objectname)")
	wantRefs := fixture.plan.BaseRef() + " " + fixture.plan.BaseCommit() + "\n" + fixture.gitPlan.TargetRef() + " " + fixture.artifact.CommitOID()
	if refs != wantRefs || strings.Contains(refs, "refs/tags/") {
		t.Fatalf("unexpected refs: %q", refs)
	}
	after, err := snapshotGit(fixture.repository.GitDir())
	if err != nil || after != before {
		t.Fatalf("real .git changed: %s != %s (%v)", before, after, err)
	}
	assertRemoved(t, *cleanedRoot)
}

func TestCreateOnlyLeaseRejectsPreflightRaceWithoutOverwrite(t *testing.T) {
	fixture := newPublicationFixture(t)
	other := fixture.repository.HeadCommit()
	runner := &hookRunner{delegate: gitPushRunner{remoteURL: fixture.remote}, hook: func() {
		runFixtureGit(t, fixture.repositoryRoot, "push", fixture.remote, "HEAD:"+fixture.plan.TargetRef())
	}}
	engine, _ := NewEngine(fixture.observer, func() (string, error) { return fakeSecret, nil })
	engine.runner = runner
	result, err := engine.Publish(context.Background(), fixture.github, fixture.plan, fixture.artifact, fixture.repository, trustedDispatch(fixture.at))
	if !errors.Is(err, ErrPreexistingRef) || runner.calls != 1 || result.Record == nil || result.Record.Outcome() != OutcomeConflicted || result.Record.ObservedOID() != other {
		t.Fatalf("race result=%#v err=%v calls=%d", result, err, runner.calls)
	}
	if got := fixture.observer.observe(fixture.plan.TargetRef(), fixture.artifact.CommitOID()); got.Status != githubbinding.RefPresentOther || got.OID != other {
		t.Fatalf("lease overwrote pre-existing ref: %#v", got)
	}
}

func TestPreexistingExactRefIsNotAttributedAndPerformsNoPush(t *testing.T) {
	fixture := newPublicationFixture(t)
	publishObjectToRemote(t, fixture)
	runner := &countRunner{}
	engine, _ := NewEngine(fixture.observer, func() (string, error) { return fakeSecret, nil })
	engine.runner = runner
	result, err := engine.Publish(context.Background(), fixture.github, fixture.plan, fixture.artifact, fixture.repository, trustedDispatch(fixture.at))
	if !errors.Is(err, ErrPreexistingRef) || runner.calls != 0 || result.Record != nil || result.Attempted {
		t.Fatalf("preexisting result=%#v err=%v calls=%d", result, err, runner.calls)
	}
}

func TestPostAttemptReconciliationClassifiesEveryRemoteTruthWithoutRetry(t *testing.T) {
	t.Run("lost acknowledgement exact", func(t *testing.T) {
		fixture := newPublicationFixture(t)
		engine := newLocalEngine(t, fixture)
		engine.runner = unacknowledgedRunner{delegate: gitPushRunner{remoteURL: fixture.remote}}
		result, err := engine.Publish(context.Background(), fixture.github, fixture.plan, fixture.artifact, fixture.repository, trustedDispatch(fixture.at))
		if err != nil || result.Record.Outcome() != OutcomePublished || result.Record.TransportAcknowledged() || !result.Record.ResolvedByReconciliation() {
			t.Fatalf("result=%#v err=%v", result, err)
		}
	})
	t.Run("failure absent", func(t *testing.T) {
		fixture := newPublicationFixture(t)
		runner := &countRunner{}
		engine, _ := NewEngine(fixture.observer, func() (string, error) { return fakeSecret, nil })
		engine.runner = runner
		result, err := engine.Publish(context.Background(), fixture.github, fixture.plan, fixture.artifact, fixture.repository, trustedDispatch(fixture.at))
		if !errors.Is(err, ErrPublication) || runner.calls != 1 || result.Record.Outcome() != OutcomeNotPublished {
			t.Fatalf("result=%#v err=%v", result, err)
		}
	})
	t.Run("query unavailable", func(t *testing.T) {
		fixture := newPublicationFixture(t)
		fixture.observer.unavailableAfter = fixture.observer.calls + 2
		runner := &countRunner{}
		engine, _ := NewEngine(fixture.observer, func() (string, error) { return fakeSecret, nil })
		engine.runner = runner
		result, err := engine.Publish(context.Background(), fixture.github, fixture.plan, fixture.artifact, fixture.repository, trustedDispatch(fixture.at))
		if !errors.Is(err, ErrPublicationUncertain) || runner.calls != 1 || result.Record.Outcome() != OutcomePublicationUncertain {
			t.Fatalf("result=%#v err=%v", result, err)
		}
		fixture.observer.unavailableAfter = 0
		observation, outcome, err := engine.Reconcile(context.Background(), fixture.github, fixture.plan)
		if err != nil || outcome != OutcomeNotPublished || observation.Status != githubbinding.RefAbsent {
			t.Fatalf("reconcile=%#v/%s/%v", observation, outcome, err)
		}
	})
}

func TestCredentialAndFinalAuthorityFailBeforeMutation(t *testing.T) {
	fixture := newPublicationFixture(t)
	runner := &countRunner{}
	missing, _ := NewEngine(fixture.observer, func() (string, error) { return "", nil })
	missing.runner = runner
	if _, err := missing.Publish(context.Background(), fixture.github, fixture.plan, fixture.artifact, fixture.repository, trustedDispatch(fixture.at)); !errors.Is(err, ErrCredential) || runner.calls != 0 {
		t.Fatalf("missing credential = %v calls=%d", err, runner.calls)
	}
	engine, _ := NewEngine(fixture.observer, func() (string, error) { return fakeSecret, nil })
	engine.runner = runner
	if _, err := engine.Publish(context.Background(), fixture.github, fixture.plan, fixture.artifact, fixture.repository, func(context.Context) (time.Time, error) { return time.Time{}, ErrAuthorityChanged }); !errors.Is(err, ErrAuthorityChanged) || runner.calls != 0 {
		t.Fatalf("authority failure = %v calls=%d", err, runner.calls)
	}
	if strings.Contains(fmt.Sprintf("%v", ErrCredential), fakeSecret) {
		t.Fatal("credential leaked through error")
	}
}

func TestPushCapabilityContainsExactRefspecAndSecretOnlyInTrustedEnvironment(t *testing.T) {
	real := t.TempDir()
	publication, err := newWorkspace(real, filepath.Join(real, ".git"))
	if err != nil {
		t.Fatal(err)
	}
	args := pushArguments(publication, "https://github.com/mrgray17/mirage-test.git", "refs/heads/mirage/run-aaaaaaaaaaaaaaaaaaaaaaaa", "1111111111111111111111111111111111111111")
	joinedArgs := strings.Join(args, "\x00")
	for _, required := range []string{"--force-with-lease=refs/heads/mirage/run-aaaaaaaaaaaaaaaaaaaaaaaa:", "https://github.com/mrgray17/mirage-test.git", "1111111111111111111111111111111111111111:refs/heads/mirage/run-aaaaaaaaaaaaaaaaaaaaaaaa", "--no-verify", "--no-follow-tags", "--recurse-submodules=no"} {
		if !strings.Contains(joinedArgs, required) {
			t.Fatalf("missing exact push argument %q: %v", required, args)
		}
	}
	if strings.Contains(joinedArgs, fakeSecret) || strings.Contains(joinedArgs, "--force\x00") || strings.Contains(joinedArgs, "refs/tags/") || strings.Contains(joinedArgs, "*:") {
		t.Fatalf("unsafe push argv: %v", args)
	}
	environment := publicationEnvironment(publication, nil, fakeSecret)
	secretCount := 0
	for _, item := range environment {
		if strings.Contains(item, fakeSecret) {
			secretCount++
			if !strings.HasPrefix(item, "MIRAGE_M53_ASKPASS_TOKEN=") {
				t.Fatalf("secret escaped credential channel: %q", item)
			}
		}
	}
	if secretCount != 1 {
		t.Fatalf("secret environment count=%d", secretCount)
	}
	err = filepath.WalkDir(publication.root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink")
		}
		if !entry.IsDir() {
			contents, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(contents), fakeSecret) {
				return errors.New("secret on disk")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	root := publication.root
	if err := publication.cleanup(); err != nil {
		t.Fatal(err)
	}
	assertRemoved(t, root)
}

func TestKnownPublishedTruthSurvivesLocalCleanupFailure(t *testing.T) {
	fixture := newPublicationFixture(t)
	engine := newLocalEngine(t, fixture)
	cleanedRoot := ""
	engine.cleanup = func(publication *workspace) error {
		cleanedRoot = publication.root
		return errors.Join(publication.cleanup(), ErrCleanup)
	}
	result, err := engine.Publish(context.Background(), fixture.github, fixture.plan, fixture.artifact, fixture.repository, trustedDispatch(fixture.at))
	if !errors.Is(err, ErrCleanup) || result.Record == nil || result.Record.Outcome() != OutcomePublished || !result.Record.TransportAcknowledged() {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if observed := fixture.observer.observe(fixture.plan.TargetRef(), fixture.plan.CommitOID()); observed.Status != githubbinding.RefPresentExact {
		t.Fatalf("known remote truth hidden: %#v", observed)
	}
	assertRemoved(t, cleanedRoot)
}

func TestPreexistingOtherRefCannotBeUpdated(t *testing.T) {
	fixture := newPublicationFixture(t)
	runFixtureGit(t, fixture.repositoryRoot, "push", fixture.remote, "HEAD:"+fixture.plan.TargetRef())
	runner := &countRunner{}
	engine, _ := NewEngine(fixture.observer, func() (string, error) { return fakeSecret, nil })
	engine.runner = runner
	result, err := engine.Publish(context.Background(), fixture.github, fixture.plan, fixture.artifact, fixture.repository, trustedDispatch(fixture.at))
	if !errors.Is(err, ErrPreexistingRef) || result.Attempted || result.Record != nil || runner.calls != 0 {
		t.Fatalf("result=%#v err=%v calls=%d", result, err, runner.calls)
	}
	if observed := fixture.observer.observe(fixture.plan.TargetRef(), fixture.plan.CommitOID()); observed.Status != githubbinding.RefPresentOther {
		t.Fatalf("existing ref changed: %#v", observed)
	}
}

type bareObserver struct {
	remote           string
	repository       githubbinding.Repository
	calls            int
	unavailableAfter int
}

func (b *bareObserver) Repository(context.Context, string) (githubbinding.Repository, error) {
	return b.repository, nil
}
func (b *bareObserver) ExactRef(_ context.Context, _ string, repositoryID int64, targetRef, expected string) (githubbinding.RefObservation, error) {
	b.calls++
	if repositoryID != b.repository.ID {
		return githubbinding.RefObservation{Status: githubbinding.RefUnavailable}, errors.New("repository identity differs")
	}
	if b.unavailableAfter > 0 && b.calls > b.unavailableAfter {
		return githubbinding.RefObservation{Status: githubbinding.RefUnavailable}, errors.New("unavailable")
	}
	return b.observe(targetRef, expected), nil
}
func (b *bareObserver) observe(targetRef, expected string) githubbinding.RefObservation {
	command := exec.Command("git", "--git-dir="+b.remote, "rev-parse", "--verify", targetRef+"^{commit}")
	output, err := command.Output()
	if err != nil {
		return githubbinding.RefObservation{Status: githubbinding.RefAbsent}
	}
	oid := strings.TrimSpace(string(output))
	if oid == expected {
		return githubbinding.RefObservation{Status: githubbinding.RefPresentExact, OID: oid}
	}
	return githubbinding.RefObservation{Status: githubbinding.RefPresentOther, OID: oid}
}

type countRunner struct{ calls int }

func (r *countRunner) prepare(*workspace, *gitbinding.Binding, string, string, string, string) (func(context.Context) pushResult, error) {
	return func(context.Context) pushResult { r.calls++; return pushResult{} }, nil
}

type hookRunner struct {
	delegate pushRunner
	hook     func()
	calls    int
}

func (r *hookRunner) prepare(w *workspace, binding *gitbinding.Binding, token, repo, ref, oid string) (func(context.Context) pushResult, error) {
	delegate, err := r.delegate.prepare(w, binding, token, repo, ref, oid)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) pushResult { r.calls++; r.hook(); return delegate(ctx) }, nil
}

type unacknowledgedRunner struct{ delegate pushRunner }

func (r unacknowledgedRunner) prepare(w *workspace, binding *gitbinding.Binding, token, repo, ref, oid string) (func(context.Context) pushResult, error) {
	delegate, err := r.delegate.prepare(w, binding, token, repo, ref, oid)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) pushResult { _ = delegate(ctx); return pushResult{} }, nil
}

func newLocalEngine(t *testing.T, fixture publicationFixture) *Engine {
	t.Helper()
	engine, err := NewEngine(fixture.observer, func() (string, error) { return fakeSecret, nil })
	if err != nil {
		t.Fatal(err)
	}
	engine.runner = gitPushRunner{remoteURL: fixture.remote}
	return engine
}
func trustedDispatch(at time.Time) FinalAuthority {
	return func(context.Context) (time.Time, error) { return at.Add(3 * time.Minute), nil }
}
func publishObjectToRemote(t *testing.T, fixture publicationFixture) {
	t.Helper()
	engine := newLocalEngine(t, fixture)
	if _, err := engine.Publish(context.Background(), fixture.github, fixture.plan, fixture.artifact, fixture.repository, trustedDispatch(fixture.at)); err != nil {
		t.Fatal(err)
	}
}

func writeFixtureFile(t *testing.T, root, relative string, value []byte) {
	t.Helper()
	target := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, value, 0o644); err != nil {
		t.Fatal(err)
	}
}
func runFixtureGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v (%s)", args, err, output)
	}
	return strings.TrimSpace(string(output))
}
func gitObjectExists(gitDir, oid string) bool {
	command := exec.Command("git", "--git-dir="+gitDir, "cat-file", "-e", oid+"^{object}")
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	return command.Run() == nil
}
func sha256Prefix(value string) string {
	digest := fmt.Sprintf("%x", sha256Bytes([]byte(value)))
	return digest[:24]
}
func sha256Bytes(value []byte) [32]byte { return sha256.Sum256(value) }
func trackCleanup(engine *Engine) *string {
	root := ""
	engine.cleanup = func(publication *workspace) error { root = publication.root; return publication.cleanup() }
	return &root
}

func assertRemoved(t *testing.T, root string) {
	t.Helper()
	if root == "" {
		t.Fatal("publication cleanup target was not captured")
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("publication workspace remains: %s (%v)", root, err)
	}
}
