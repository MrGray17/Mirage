package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/gitrefs"
	"github.com/MrGray17/Mirage/internal/runtime/gitbinding"
	"github.com/MrGray17/Mirage/internal/runtime/gitcommit"
	"github.com/MrGray17/Mirage/internal/runtime/githubbinding"
	"github.com/MrGray17/Mirage/internal/runtime/githubpullrequest"
	"github.com/MrGray17/Mirage/internal/runtime/gitplan"
	"github.com/MrGray17/Mirage/internal/runtime/gitpublication"
	"github.com/MrGray17/Mirage/internal/runtime/realcommit"
	"github.com/MrGray17/Mirage/internal/runtime/tree"
	"github.com/MrGray17/Mirage/internal/runtime/workspace"
)

type sandboxStub struct {
	prepareErr error
	startErr   error
	freezeErr  error
	destroyErr error
	calls      []string
	identity   string
	real       string
	disposable string
	token      string
}

func TestM53LifecycleMintsOnePlanAndRejectsStaleAuthorityBeforeDispatch(t *testing.T) {
	t.Run("idempotent plan", func(t *testing.T) {
		current := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
		lifecycle, _, client := preparedPublicationLifecycle(t, func() time.Time { return current }, current.Add(time.Hour))
		first := lifecycle.GitPublicationPlan()
		second, err := lifecycle.DeriveGitPublicationPlan(context.Background())
		if err != nil || first == nil || second != first || first.Identity() == "" {
			t.Fatalf("plans = %p/%p, %v", first, second, err)
		}
		if lifecycle.GitCommitArtifact() == nil {
			t.Fatal("verified lifecycle lost artifact")
		}
		if client.refCalls != 1 {
			t.Fatalf("plan derivation did not revalidate the bound remote base: calls=%d", client.refCalls)
		}
	})

	t.Run("missing token", func(t *testing.T) {
		current := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
		lifecycle, _, client := preparedPublicationLifecycle(t, func() time.Time { return current }, current.Add(time.Hour))
		engine, _ := gitpublication.NewEngine(client, func() (string, error) { return "", nil })
		if record, err := lifecycle.PublishGitHub(context.Background(), engine); !errors.Is(err, gitpublication.ErrCredential) || record != nil || client.refCalls != 0 || lifecycle.State() != StateFailed {
			t.Fatalf("record=%#v err=%v refs=%d state=%s", record, err, client.refCalls, lifecycle.State())
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *Lifecycle, *workspace.Disposable, *m53LifecycleClient, *time.Time)
		want   error
		state  State
	}{
		{name: "expired", mutate: func(_ *testing.T, _ *Lifecycle, _ *workspace.Disposable, _ *m53LifecycleClient, current *time.Time) {
			*current = current.Add(2 * time.Hour)
		}, want: ErrContractExpired, state: StateRejected},
		{name: "clock rollback", mutate: func(_ *testing.T, _ *Lifecycle, _ *workspace.Disposable, _ *m53LifecycleClient, current *time.Time) {
			*current = current.Add(-time.Second)
		}, want: ErrClockRollback, state: StateFailed},
		{name: "GitHub identity changed", mutate: func(_ *testing.T, _ *Lifecycle, _ *workspace.Disposable, client *m53LifecycleClient, _ *time.Time) {
			client.repository.ID++
		}, want: githubbinding.ErrRepositoryChanged, state: StateConflicted},
		{name: "stale commit artifact", mutate: func(t *testing.T, lifecycle *Lifecycle, _ *workspace.Disposable, _ *m53LifecycleClient, _ *time.Time) {
			if err := lifecycle.gitArtifact.Cleanup(); err != nil {
				t.Fatal(err)
			}
		}, want: gitcommit.ErrTransactionChanged, state: StateFailed},
		{name: "frozen shadow changed", mutate: func(t *testing.T, _ *Lifecycle, disposable *workspace.Disposable, client *m53LifecycleClient, _ *time.Time) {
			client.beforeRef = func() {
				if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("late mutation\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}, want: ErrShadowChanged, state: StateRejected},
		{name: "real Git changed", mutate: func(t *testing.T, _ *Lifecycle, disposable *workspace.Disposable, client *m53LifecycleClient, _ *time.Time) {
			client.beforeRef = func() {
				writeLifecycleFile(t, disposable.RealWorkspace(), "other.txt", "other\n", 0o600)
				runLifecycleGit(t, disposable.RealWorkspace(), "add", "other.txt")
				runLifecycleGit(t, disposable.RealWorkspace(), "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "-m", "concurrent")
			}
		}, want: gitplan.ErrRepositoryChanged, state: StateConflicted},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
			lifecycle, disposable, client := preparedPublicationLifecycle(t, func() time.Time { return current }, current.Add(time.Hour))
			test.mutate(t, lifecycle, disposable, client, &current)
			engine, _ := gitpublication.NewEngine(client, func() (string, error) { return "fake-host-token", nil })
			record, err := lifecycle.PublishGitHub(context.Background(), engine)
			if !errors.Is(err, test.want) || record != nil || lifecycle.State() != test.state {
				t.Fatalf("record=%#v err=%v state=%s want %v/%s", record, err, lifecycle.State(), test.want, test.state)
			}
		})
	}
}

func TestM53LifecycleOwnsPublicationIdempotencyAndUncertainReconciliation(t *testing.T) {
	t.Run("published idempotency and drift", func(t *testing.T) {
		current := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
		lifecycle, _, _ := preparedPublicationLifecycle(t, func() time.Time { return current }, current.Add(time.Hour))
		plan := lifecycle.GitPublicationPlan()
		engine := &m53LifecycleEngine{publishObservation: githubbinding.RefObservation{Status: githubbinding.RefPresentExact, OID: plan.CommitOID()}, acknowledged: true, reconcileObservation: githubbinding.RefObservation{Status: githubbinding.RefPresentExact, OID: plan.CommitOID()}}
		first, err := lifecycle.PublishGitHub(context.Background(), engine)
		if err != nil || first == nil || first.Outcome() != gitpublication.OutcomePublished || lifecycle.State() != StatePublished || engine.pushes != 1 {
			t.Fatalf("first=%#v err=%v state=%s pushes=%d", first, err, lifecycle.State(), engine.pushes)
		}
		second, err := lifecycle.PublishGitHub(context.Background(), engine)
		if err != nil || second != first || engine.pushes != 1 || engine.reads != 1 {
			t.Fatalf("second=%#v err=%v pushes=%d reads=%d", second, err, engine.pushes, engine.reads)
		}
		engine.reconcileObservation = githubbinding.RefObservation{Status: githubbinding.RefPresentOther, OID: lifecycle.GitRepositoryBinding().HeadCommit()}
		if record, err := lifecycle.PublishGitHub(context.Background(), engine); !errors.Is(err, gitpublication.ErrPreexistingRef) || record != nil || lifecycle.State() != StateConflicted || engine.pushes != 1 {
			t.Fatalf("drift=%#v err=%v state=%s pushes=%d", record, err, lifecycle.State(), engine.pushes)
		}
	})

	t.Run("uncertain permits reads only", func(t *testing.T) {
		current := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
		lifecycle, _, _ := preparedPublicationLifecycle(t, func() time.Time { return current }, current.Add(time.Hour))
		plan := lifecycle.GitPublicationPlan()
		engine := &m53LifecycleEngine{publishObservation: githubbinding.RefObservation{Status: githubbinding.RefUnavailable}, publishErr: gitpublication.ErrPublicationUncertain, reconcileObservation: githubbinding.RefObservation{Status: githubbinding.RefPresentExact, OID: plan.CommitOID()}}
		uncertain, err := lifecycle.PublishGitHub(context.Background(), engine)
		if !errors.Is(err, gitpublication.ErrPublicationUncertain) || uncertain == nil || lifecycle.State() != StatePublicationUncertain || engine.pushes != 1 {
			t.Fatalf("uncertain=%#v err=%v state=%s pushes=%d", uncertain, err, lifecycle.State(), engine.pushes)
		}
		if _, err := lifecycle.PublishGitHub(context.Background(), engine); !errors.Is(err, ErrInvalidTransition) || engine.pushes != 1 {
			t.Fatalf("second push err=%v pushes=%d", err, engine.pushes)
		}
		resolved, err := lifecycle.ReconcileGitPublication(context.Background(), engine)
		if err != nil || resolved == nil || resolved.Outcome() != gitpublication.OutcomePublished || !resolved.ResolvedByReconciliation() || lifecycle.State() != StatePublished || engine.pushes != 1 || engine.reads != 1 {
			t.Fatalf("resolved=%#v err=%v state=%s pushes=%d reads=%d", resolved, err, lifecycle.State(), engine.pushes, engine.reads)
		}
	})

	t.Run("published then unavailable then absent is drift", func(t *testing.T) {
		current := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
		lifecycle, _, _ := preparedPublicationLifecycle(t, func() time.Time { return current }, current.Add(time.Hour))
		plan := lifecycle.GitPublicationPlan()
		engine := &m53LifecycleEngine{publishObservation: githubbinding.RefObservation{Status: githubbinding.RefPresentExact, OID: plan.CommitOID()}, acknowledged: true, reconcileObservation: githubbinding.RefObservation{Status: githubbinding.RefUnavailable}, reconcileOutcome: gitpublication.OutcomePublicationUncertain}
		if _, err := lifecycle.PublishGitHub(context.Background(), engine); err != nil {
			t.Fatal(err)
		}
		if _, err := lifecycle.PublishGitHub(context.Background(), engine); !errors.Is(err, gitpublication.ErrPublicationUncertain) || lifecycle.State() != StatePublicationUncertain {
			t.Fatalf("unavailable err=%v state=%s", err, lifecycle.State())
		}
		engine.reconcileObservation = githubbinding.RefObservation{Status: githubbinding.RefAbsent}
		engine.reconcileOutcome = gitpublication.OutcomeNotPublished
		record, err := lifecycle.ReconcileGitPublication(context.Background(), engine)
		if err != nil || record.Outcome() != gitpublication.OutcomeNotPublished || lifecycle.State() != StateConflicted || engine.pushes != 1 {
			t.Fatalf("drift record=%#v err=%v state=%s pushes=%d", record, err, lifecycle.State(), engine.pushes)
		}
	})

	for _, test := range []struct {
		name        string
		observation githubbinding.RefObservation
		outcome     gitpublication.Outcome
		state       State
	}{
		{name: "absent terminal", observation: githubbinding.RefObservation{Status: githubbinding.RefAbsent}, outcome: gitpublication.OutcomeNotPublished, state: StateFailed},
		{name: "other conflict", observation: githubbinding.RefObservation{Status: githubbinding.RefPresentOther, OID: "1111111111111111111111111111111111111111"}, outcome: gitpublication.OutcomeConflicted, state: StateConflicted},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
			lifecycle, _, _ := preparedPublicationLifecycle(t, func() time.Time { return current }, current.Add(time.Hour))
			engine := &m53LifecycleEngine{publishObservation: githubbinding.RefObservation{Status: githubbinding.RefUnavailable}, publishErr: gitpublication.ErrPublicationUncertain, reconcileObservation: test.observation, reconcileOutcome: test.outcome}
			if _, err := lifecycle.PublishGitHub(context.Background(), engine); !errors.Is(err, gitpublication.ErrPublicationUncertain) {
				t.Fatal(err)
			}
			record, err := lifecycle.ReconcileGitPublication(context.Background(), engine)
			if err != nil || record.Outcome() != test.outcome || lifecycle.State() != test.state || engine.pushes != 1 {
				t.Fatalf("record=%#v err=%v state=%s pushes=%d", record, err, lifecycle.State(), engine.pushes)
			}
		})
	}
}

type m53LifecycleEngine struct {
	publishObservation   githubbinding.RefObservation
	reconcileObservation githubbinding.RefObservation
	reconcileOutcome     gitpublication.Outcome
	acknowledged         bool
	publishErr           error
	pushes               int
	reads                int
}

func (e *m53LifecycleEngine) Publish(ctx context.Context, _ *githubbinding.Binding, plan *gitpublication.Plan, _ *gitcommit.Artifact, _ *gitbinding.Binding, final gitpublication.FinalAuthority) (gitpublication.Result, error) {
	dispatch, err := final(ctx)
	if err != nil {
		return gitpublication.Result{}, err
	}
	e.pushes++
	record, err := gitpublication.NewRecordForObservation(plan, dispatch, e.acknowledged, e.publishObservation)
	if err != nil {
		return gitpublication.Result{Attempted: true}, err
	}
	return gitpublication.Result{Record: record, Attempted: true}, e.publishErr
}
func (e *m53LifecycleEngine) Reconcile(context.Context, *githubbinding.Binding, *gitpublication.Plan) (githubbinding.RefObservation, gitpublication.Outcome, error) {
	e.reads++
	outcome := e.reconcileOutcome
	if outcome == "" {
		if e.reconcileObservation.Status == githubbinding.RefPresentExact {
			outcome = gitpublication.OutcomePublished
		} else if e.reconcileObservation.Status == githubbinding.RefPresentOther {
			outcome = gitpublication.OutcomeConflicted
		} else if e.reconcileObservation.Status == githubbinding.RefAbsent {
			outcome = gitpublication.OutcomeNotPublished
		} else {
			outcome = gitpublication.OutcomePublicationUncertain
		}
	}
	if outcome == gitpublication.OutcomePublicationUncertain {
		return e.reconcileObservation, outcome, gitpublication.ErrPublicationUncertain
	}
	return e.reconcileObservation, outcome, nil
}

func TestM54LifecyclePlansOnlyFromPublishedV3Authority(t *testing.T) {
	current := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	lifecycle, _, _ := preparedPullRequestLifecycle(t, func() time.Time { return current }, current.Add(time.Hour))
	first := lifecycle.GitHubPullRequestPlan()
	second, err := lifecycle.DeriveGitHubPullRequestPlan(context.Background())
	if err != nil || first == nil || second != first || first.Identity() == "" || lifecycle.ExternalEffectLedger().PullRequestOutcome() != githubpullrequest.OutcomeNotAttempted {
		t.Fatalf("plans=%p/%p ledger=%#v err=%v", first, second, lifecycle.ExternalEffectLedger(), err)
	}
}

func TestM54LifecycleClassifiesExactPartialEffectsWithoutRetry(t *testing.T) {
	tests := map[string]struct {
		preflight    githubpullrequest.ObservationStatus
		postflight   githubpullrequest.ObservationStatus
		acknowledged bool
		establishErr error
		wantState    State
		wantOutcome  githubpullrequest.PullRequestOutcome
		wantPosts    int
	}{
		"preexisting exact":          {preflight: githubpullrequest.ObservationExact, wantState: StatePREstablished, wantOutcome: githubpullrequest.OutcomeAlreadyPresent},
		"acknowledged exact":         {preflight: githubpullrequest.ObservationAbsent, postflight: githubpullrequest.ObservationExact, acknowledged: true, wantState: StatePREstablished, wantOutcome: githubpullrequest.OutcomeCreated, wantPosts: 1},
		"lost acknowledgement exact": {preflight: githubpullrequest.ObservationAbsent, postflight: githubpullrequest.ObservationExact, establishErr: githubpullrequest.ErrCreateUnavailable, wantState: StatePREstablished, wantOutcome: githubpullrequest.OutcomeAlreadyPresent, wantPosts: 1},
		"attempted absent":           {preflight: githubpullrequest.ObservationAbsent, postflight: githubpullrequest.ObservationAbsent, establishErr: githubpullrequest.ErrCreateRejected, wantState: StateFailed, wantOutcome: githubpullrequest.OutcomeNotCreated, wantPosts: 1},
		"preflight conflict":         {preflight: githubpullrequest.ObservationConflicting, wantState: StateConflicted, wantOutcome: githubpullrequest.OutcomeConflict},
		"postflight unavailable":     {preflight: githubpullrequest.ObservationAbsent, postflight: githubpullrequest.ObservationUnavailable, establishErr: githubpullrequest.ErrObservationUnavailable, wantState: StatePRCreationUncertain, wantOutcome: githubpullrequest.OutcomeUncertain, wantPosts: 1},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			current := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
			lifecycle, _, _ := preparedPullRequestLifecycle(t, func() time.Time { return current }, current.Add(time.Hour))
			plan := lifecycle.GitHubPullRequestPlan()
			preflight := lifecyclePRObservation(t, plan, test.preflight)
			postflight := lifecyclePRObservation(t, plan, test.postflight)
			engine := &m54LifecycleEngine{lifecycle: lifecycle, preflight: preflight, postflight: postflight, acknowledged: test.acknowledged, establishErr: test.establishErr}
			ledger, err := lifecycle.EstablishGitHubPullRequest(context.Background(), engine)
			if test.establishErr == nil && test.preflight != githubpullrequest.ObservationConflicting && err != nil {
				t.Fatal(err)
			}
			if ledger == nil || ledger.PullRequestOutcome() != test.wantOutcome || lifecycle.State() != test.wantState || engine.postCount() != test.wantPosts {
				t.Fatalf("ledger=%#v err=%v state=%s posts=%d", ledger, err, lifecycle.State(), engine.postCount())
			}
			if test.wantPosts == 0 && (ledger.Attempted() || lifecycle.PullRequestAttempt() != nil) {
				t.Fatal("zero-POST outcome installed an attempt")
			}
			if test.wantPosts == 1 && test.wantState != StatePRCreationUncertain {
				repeated, repeatedErr := lifecycle.EstablishGitHubPullRequest(context.Background(), engine)
				if test.wantState == StatePREstablished {
					if repeatedErr != nil || repeated != ledger {
						t.Fatalf("established repeat ledger=%#v err=%v", repeated, repeatedErr)
					}
				} else if !errors.Is(repeatedErr, ErrInvalidTransition) {
					t.Fatalf("terminal repeat err=%v", repeatedErr)
				}
				if engine.postCount() != 1 {
					t.Fatalf("later call dispatched another POST: %d", engine.postCount())
				}
			}
			if test.wantState == StatePRCreationUncertain {
				if _, err := lifecycle.EstablishGitHubPullRequest(context.Background(), engine); !errors.Is(err, ErrInvalidTransition) || engine.postCount() != 1 {
					t.Fatalf("uncertain retry err=%v posts=%d", err, engine.postCount())
				}
				engine.reconcileObservation = lifecyclePRObservation(t, plan, githubpullrequest.ObservationExact)
				resolved, err := lifecycle.ReconcileGitHubPullRequest(engine)
				if err != nil || resolved.PullRequestOutcome() != githubpullrequest.OutcomeAlreadyPresent || lifecycle.State() != StatePREstablished || engine.postCount() != 1 || engine.readCount() != 1 {
					t.Fatalf("resolved=%#v err=%v state=%s posts=%d reads=%d", resolved, err, lifecycle.State(), engine.postCount(), engine.readCount())
				}
			}
		})
	}
}

func TestM54LifecycleAttemptLatchSerializesConcurrentCallers(t *testing.T) {
	current := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	lifecycle, _, _ := preparedPullRequestLifecycle(t, func() time.Time { return current }, current.Add(time.Hour))
	plan := lifecycle.GitHubPullRequestPlan()
	entered := make(chan struct{})
	release := make(chan struct{})
	engine := &m54LifecycleEngine{lifecycle: lifecycle, preflight: githubpullrequest.Observation{Status: githubpullrequest.ObservationAbsent}, postflight: lifecyclePRObservation(t, plan, githubpullrequest.ObservationExact), acknowledged: true, entered: entered, release: release}
	type result struct {
		ledger *githubpullrequest.ExternalEffectLedger
		err    error
	}
	results := make(chan result, 2)
	go func() {
		ledger, err := lifecycle.EstablishGitHubPullRequest(context.Background(), engine)
		results <- result{ledger, err}
	}()
	<-entered
	go func() {
		ledger, err := lifecycle.EstablishGitHubPullRequest(context.Background(), engine)
		results <- result{ledger, err}
	}()
	close(release)
	for range 2 {
		result := <-results
		if result.err != nil || result.ledger == nil || result.ledger.PullRequestOutcome() != githubpullrequest.OutcomeCreated {
			t.Fatalf("concurrent result=%#v err=%v", result.ledger, result.err)
		}
	}
	if engine.postCount() != 1 || lifecycle.PullRequestAttempt() == nil || lifecycle.State() != StatePREstablished {
		t.Fatalf("posts=%d attempt=%#v state=%s", engine.postCount(), lifecycle.PullRequestAttempt(), lifecycle.State())
	}
}

func TestM54LifecycleAuthorityChangesBeforeLatchPerformZeroPOSTs(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Lifecycle, *m53LifecycleClient, *time.Time)
		want   error
	}{
		{name: "expiry", mutate: func(_ *Lifecycle, _ *m53LifecycleClient, current *time.Time) { *current = current.Add(2 * time.Hour) }, want: ErrContractExpired},
		{name: "clock rollback", mutate: func(_ *Lifecycle, _ *m53LifecycleClient, current *time.Time) { *current = current.Add(-time.Second) }, want: ErrClockRollback},
		{name: "published head changed", mutate: func(lifecycle *Lifecycle, client *m53LifecycleClient, _ *time.Time) {
			client.targetOID = lifecycle.GitRepositoryBinding().HeadCommit()
			client.targetState = githubbinding.RefPresentOther
		}, want: githubbinding.ErrRepositoryChanged},
		{name: "published head missing", mutate: func(_ *Lifecycle, client *m53LifecycleClient, _ *time.Time) {
			client.targetState = githubbinding.RefAbsent
		}, want: githubbinding.ErrRepositoryChanged},
		{name: "base moved", mutate: func(_ *Lifecycle, client *m53LifecycleClient, _ *time.Time) {
			client.baseCommit = strings.Repeat("f", 40)
		}, want: githubbinding.ErrRepositoryChanged},
		{name: "repository identity changed", mutate: func(_ *Lifecycle, client *m53LifecycleClient, _ *time.Time) {
			client.repository.ID++
		}, want: githubbinding.ErrRepositoryChanged},
		{name: "publication record missing", mutate: func(lifecycle *Lifecycle, _ *m53LifecycleClient, _ *time.Time) {
			lifecycle.publicationRecord = nil
		}, want: ErrCommitAuthority},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
			lifecycle, _, client := preparedPullRequestLifecycle(t, func() time.Time { return current }, current.Add(time.Hour))
			test.mutate(lifecycle, client, &current)
			engine := &m54LifecycleEngine{lifecycle: lifecycle, preflight: githubpullrequest.Observation{Status: githubpullrequest.ObservationAbsent}}
			ledger, err := lifecycle.EstablishGitHubPullRequest(context.Background(), engine)
			if !errors.Is(err, test.want) || engine.postCount() != 0 || lifecycle.PullRequestAttempt() != nil || ledger.PullRequestOutcome() != githubpullrequest.OutcomeNotAttempted {
				t.Fatalf("ledger=%#v err=%v posts=%d attempt=%#v", ledger, err, engine.postCount(), lifecycle.PullRequestAttempt())
			}
		})
	}
}

type m54LifecycleEngine struct {
	lifecycle            *Lifecycle
	preflight            githubpullrequest.Observation
	postflight           githubpullrequest.Observation
	reconcileObservation githubpullrequest.Observation
	acknowledged         bool
	establishErr         error
	reconcileErr         error
	entered              chan struct{}
	release              chan struct{}
	mu                   sync.Mutex
	posts                int
	reads                int
	enterOnce            sync.Once
}

func (e *m54LifecycleEngine) Establish(ctx context.Context, _ *githubpullrequest.Plan, final githubpullrequest.FinalAuthority) (githubpullrequest.EstablishResult, error) {
	result := githubpullrequest.EstablishResult{Preflight: e.preflight}
	if e.preflight.Status != githubpullrequest.ObservationAbsent {
		return result, e.establishErr
	}
	attempt, err := final(ctx)
	if err != nil {
		return result, err
	}
	if e.lifecycle.pullRequestAttempt == nil || e.lifecycle.pullRequestAttempt.Identity() != attempt.Identity() || e.lifecycle.state != StatePRCreating {
		return result, errors.New("POST became reachable before lifecycle attempt latch")
	}
	e.mu.Lock()
	e.posts++
	e.mu.Unlock()
	result.Attempted = true
	result.Attempt = attempt
	result.Postflight = e.postflight
	result.CompatibleAcknowledgement = e.acknowledged
	if e.entered != nil {
		e.enterOnce.Do(func() { close(e.entered) })
	}
	if e.release != nil {
		<-e.release
	}
	return result, e.establishErr
}

func (e *m54LifecycleEngine) Reconcile(context.Context, *githubpullrequest.Plan) (githubpullrequest.Observation, error) {
	e.mu.Lock()
	e.reads++
	e.mu.Unlock()
	return e.reconcileObservation, e.reconcileErr
}

func (e *m54LifecycleEngine) postCount() int { e.mu.Lock(); defer e.mu.Unlock(); return e.posts }
func (e *m54LifecycleEngine) readCount() int { e.mu.Lock(); defer e.mu.Unlock(); return e.reads }

func preparedPullRequestLifecycle(t *testing.T, now func() time.Time, expires time.Time) (*Lifecycle, *workspace.Disposable, *m53LifecycleClient) {
	t.Helper()
	lifecycle, disposable, client := preparedPublicationLifecycleVersion(t, now, expires, contracts.VersionV3)
	publicationPlan := lifecycle.GitPublicationPlan()
	publicationEngine := &m53LifecycleEngine{publishObservation: githubbinding.RefObservation{Status: githubbinding.RefPresentExact, OID: publicationPlan.CommitOID()}, acknowledged: true}
	if _, err := lifecycle.PublishGitHub(context.Background(), publicationEngine); err != nil {
		t.Fatal(err)
	}
	client.targetRef = publicationPlan.TargetRef()
	client.targetOID = publicationPlan.CommitOID()
	client.targetState = githubbinding.RefPresentExact
	if _, err := lifecycle.DeriveGitHubPullRequestPlan(context.Background()); err != nil {
		t.Fatal(err)
	}
	return lifecycle, disposable, client
}

func lifecyclePRObservation(t *testing.T, plan *githubpullrequest.Plan, status githubpullrequest.ObservationStatus) githubpullrequest.Observation {
	t.Helper()
	switch status {
	case githubpullrequest.ObservationExact:
		identity, err := githubpullrequest.NewPullRequestIdentity(githubpullrequest.PullRequestIdentitySpec{Plan: plan, Number: 17, StableID: 1700, URL: "https://github.com/" + plan.RepositoryFullName() + "/pull/17", RepositoryID: plan.RepositoryID(), RepositoryFullName: plan.RepositoryFullName(), BaseRef: plan.BaseRef(), TargetRef: plan.TargetRef(), HeadOID: plan.CommitOID(), MetadataPolicy: plan.Metadata().Version(), Title: plan.Metadata().Title(), Body: plan.Metadata().Body(), Open: true})
		if err != nil {
			t.Fatal(err)
		}
		return githubpullrequest.Observation{Status: status, Exact: identity}
	case githubpullrequest.ObservationConflicting:
		return githubpullrequest.Observation{Status: status, Evidence: "hostile_test_conflict"}
	default:
		return githubpullrequest.Observation{Status: status}
	}
}

type m53LifecycleClient struct {
	repository  githubbinding.Repository
	beforeRef   func()
	refCalls    int
	baseRef     string
	baseCommit  string
	targetRef   string
	targetOID   string
	targetState githubbinding.RefStatus
}

func (c *m53LifecycleClient) Repository(context.Context, string) (githubbinding.Repository, error) {
	return c.repository, nil
}
func (c *m53LifecycleClient) ExactRef(_ context.Context, _ string, _ int64, ref, expected string) (githubbinding.RefObservation, error) {
	c.refCalls++
	if c.beforeRef != nil {
		hook := c.beforeRef
		c.beforeRef = nil
		hook()
	}
	if ref == c.baseRef {
		if c.baseCommit == expected {
			return githubbinding.RefObservation{Status: githubbinding.RefPresentExact, OID: c.baseCommit}, nil
		}
		return githubbinding.RefObservation{Status: githubbinding.RefPresentOther, OID: c.baseCommit}, nil
	}
	if ref == c.targetRef {
		status := c.targetState
		if status == "" {
			status = githubbinding.RefPresentExact
		}
		switch status {
		case githubbinding.RefPresentExact, githubbinding.RefPresentOther:
			return githubbinding.RefObservation{Status: status, OID: c.targetOID}, nil
		default:
			return githubbinding.RefObservation{Status: status}, nil
		}
	}
	return githubbinding.RefObservation{Status: githubbinding.RefAbsent}, nil
}

func preparedPublicationLifecycle(t *testing.T, now func() time.Time, expires time.Time) (*Lifecycle, *workspace.Disposable, *m53LifecycleClient) {
	return preparedPublicationLifecycleVersion(t, now, expires, contracts.VersionV2)
}

func preparedPublicationLifecycleVersion(t *testing.T, now func() time.Time, expires time.Time, contractVersion string) (*Lifecycle, *workspace.Disposable, *m53LifecycleClient) {
	t.Helper()
	real := lifecycleRealWorkspace(t)
	runLifecycleGit(t, real, "init", "-b", "main")
	writeLifecycleFile(t, real, "README.md", "before\n", 0o600)
	runLifecycleGit(t, real, "add", "README.md")
	runLifecycleGit(t, real, "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "-m", "initial")
	disposable, err := workspace.Prepare(real)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := disposable.Cleanup(); err != nil {
			t.Errorf("cleanup disposable: %v", err)
		}
	})
	binding, err := disposable.Binding()
	if err != nil {
		t.Fatal(err)
	}
	stub := &sandboxStub{real: binding.RealWorkspace(), disposable: binding.DisposableWorkspace(), token: binding.Token()}
	runID := "lifecycle-m53"
	targetRef := gitrefs.RunTarget(runID)
	contractSpec := contracts.Spec{Version: contractVersion, RunID: runID, ActorID: "hostile-fixture", ExpiresAt: expires, Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{Allow: []string{"/workspace/README.md"}}}}
	if contractVersion == contracts.VersionV2 {
		contractSpec.GitHub = contracts.GitHubPublicationPolicy{RepositoryFullName: publicationLifecycleRepo, TargetRef: targetRef, Operation: contracts.GitHubCreateBranch}
	} else {
		contractSpec.GitHubV3 = contracts.GitHubEffectsPolicy{RepositoryFullName: publicationLifecycleRepo, Branch: contracts.GitHubBranchPolicy{TargetRef: targetRef, Operation: contracts.GitHubCreateBranch}, PullRequest: contracts.GitHubPullRequestPolicy{BaseRef: "refs/heads/main", TargetRef: targetRef, Operation: contracts.GitHubCreatePullRequest, MetadataPolicy: contracts.PullRequestMetadataV1}}
	}
	contract, err := contracts.New(contractSpec)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := NewRunManifest(contract, binding, stub, now)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := NewBoundLifecycle(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.BindGitRepository(); err != nil {
		t.Fatal(err)
	}
	localGit := lifecycle.GitRepositoryBinding()
	client := &m53LifecycleClient{repository: githubbinding.Repository{ID: 1729, FullName: publicationLifecycleRepo}, baseRef: localGit.HeadRef(), baseCommit: localGit.HeadCommit()}
	if _, err := lifecycle.BindGitHubRepository(context.Background(), publicationLifecycleRepo, client); err != nil {
		t.Fatal(err)
	}
	runToStarted(t, lifecycle)
	if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("verified Git publication\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	freezeAndVerify(t, lifecycle)
	if _, err := lifecycle.DeriveGitEffectPlan(); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.ConstructGitCommitArtifact(); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.DeriveGitPublicationPlan(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lifecycle.CleanupGitCommitArtifact() })
	client.refCalls = 0
	return lifecycle, disposable, client
}

const publicationLifecycleRepo = "mrgray17/mirage-test"

func (s *sandboxStub) Identity() string {
	if s.identity == "" {
		return "sandbox:test"
	}
	return s.identity
}

func (s *sandboxStub) BoundWorkspace() (string, string, string) {
	return s.real, s.disposable, s.token
}

func (s *sandboxStub) Prepare(context.Context) error {
	s.calls = append(s.calls, "prepare")
	return s.prepareErr
}

func (s *sandboxStub) Start(context.Context) error {
	s.calls = append(s.calls, "start")
	return s.startErr
}

func (s *sandboxStub) Freeze(context.Context) error {
	s.calls = append(s.calls, "freeze")
	return s.freezeErr
}

func (s *sandboxStub) Destroy(context.Context) error {
	s.calls = append(s.calls, "destroy")
	return s.destroyErr
}

func TestLifecycleRequiresStopProofBeforeFrozen(t *testing.T) {
	stub := &sandboxStub{}
	lifecycle, err := NewLifecycle(stub)
	if err != nil {
		t.Fatalf("new lifecycle: %v", err)
	}
	if lifecycle.State() != StateCreated {
		t.Fatalf("initial state = %s", lifecycle.State())
	}
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if lifecycle.State() != StatePreparing {
		t.Fatalf("prepared state = %s", lifecycle.State())
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if lifecycle.State() != StateRunning {
		t.Fatalf("running state = %s", lifecycle.State())
	}
	if err := lifecycle.Freeze(context.Background()); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if lifecycle.State() != StateFrozen {
		t.Fatalf("frozen state = %s", lifecycle.State())
	}
	if got := len(stub.calls); got != 3 {
		t.Fatalf("calls = %v", stub.calls)
	}
}

func TestLifecycleFreezeFailureIsNeverFrozen(t *testing.T) {
	stopErr := errors.New("stop proof unavailable")
	stub := &sandboxStub{freezeErr: stopErr}
	lifecycle, err := NewLifecycle(stub)
	if err != nil {
		t.Fatalf("new lifecycle: %v", err)
	}
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := lifecycle.Freeze(context.Background()); !errors.Is(err, stopErr) {
		t.Fatalf("freeze error = %v", err)
	}
	if lifecycle.State() != StateFailed {
		t.Fatalf("state = %s, want FAILED", lifecycle.State())
	}
	if _, err := lifecycle.Reconcile(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("reconcile error = %v", err)
	}
}

func TestLifecycleStartFailureCannotBeReconciled(t *testing.T) {
	startErr := errors.New("uncertain start")
	stub := &sandboxStub{startErr: startErr}
	lifecycle, err := NewLifecycle(stub)
	if err != nil {
		t.Fatalf("new lifecycle: %v", err)
	}
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := lifecycle.Start(context.Background()); !errors.Is(err, startErr) {
		t.Fatalf("start error = %v", err)
	}
	if lifecycle.State() != StateFailed {
		t.Fatalf("state = %s, want FAILED", lifecycle.State())
	}
	if _, err := lifecycle.Reconcile(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("reconcile error = %v", err)
	}
}

func TestLifecycleVerificationRequiresFrozenExactReconciliation(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	lifecycle, disposable := boundLifecycle(t, func() time.Time { return now }, now.Add(time.Hour), "/workspace/README.md")
	if _, err := lifecycle.Reconcile(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("early verify error = %v", err)
	}
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("after"), 0o666); err != nil {
		t.Fatal(err)
	}
	decision, err := lifecycle.Reconcile()
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("decision = %#v, violations = %#v", decision, decision.Violations())
	}
	if lifecycle.State() != StateVerified {
		t.Fatalf("state = %s, want VERIFIED", lifecycle.State())
	}
	plan, stored := lifecycle.Reconciliation()
	if plan == nil || len(plan.Mutations()) != 1 || stored.AuthorityHash != decision.AuthorityHash {
		t.Fatalf("stored reconciliation = %#v, %#v", plan, stored)
	}
}

func TestLifecyclePolicyDenialIsRejectedNotFailed(t *testing.T) {
	lifecycle, disposable := frozenLifecycle(t)
	if err := os.WriteFile(filepath.Join(disposable.Path(), "forbidden.txt"), []byte("hostile"), 0o644); err != nil {
		t.Fatal(err)
	}
	decision, err := lifecycle.Reconcile()
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed || lifecycle.State() != StateRejected {
		t.Fatalf("decision = %#v, state = %s", decision, lifecycle.State())
	}
}

func TestLifecycleScanUncertaintyFailsClosed(t *testing.T) {
	lifecycle, disposable := frozenLifecycle(t)
	if err := os.RemoveAll(disposable.Path()); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.Reconcile(); err == nil {
		t.Fatal("missing frozen workspace was reconciled")
	}
	if lifecycle.State() != StateFailed {
		t.Fatalf("state = %s, want FAILED", lifecycle.State())
	}
}

func TestLifecycleBindsGitBeforeHostileExecutionAndPlansOnlyAfterVerification(t *testing.T) {
	lifecycle, disposable, gitDir := boundGitLifecycle(t)
	before, err := tree.Scan(gitDir, tree.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := lifecycle.BindGitRepository()
	if err != nil {
		t.Fatal(err)
	}
	if binding.Root() != disposable.RealWorkspace() || binding.ManifestHash() == "" {
		t.Fatalf("binding = %#v", binding)
	}
	if _, err := os.Lstat(filepath.Join(disposable.Path(), ".git")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("real .git entered disposable workspace: %v", err)
	}
	if _, err := lifecycle.DeriveGitEffectPlan(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("unverified derivation = %v", err)
	}
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.BindGitRepository(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("late binding = %v", err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("verified Git proposal\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	freezeAndVerify(t, lifecycle)
	plan, err := lifecycle.DeriveGitEffectPlan()
	if err != nil {
		t.Fatal(err)
	}
	if plan == nil || plan.RepositoryBindingHash() != binding.Identity() || plan.TargetRef() == "refs/heads/main" || len(plan.Effects()) != 1 {
		t.Fatalf("Git plan = %#v", plan)
	}
	again, err := lifecycle.DeriveGitEffectPlan()
	if err != nil || again != plan || again.Identity() != plan.Identity() || again.CreatedAt() != plan.CreatedAt() {
		t.Fatalf("repeated derivation minted new authority: first=%p second=%p error=%v", plan, again, err)
	}
	if err := lifecycle.RevalidateGitEffectPlan(); err != nil {
		t.Fatal(err)
	}
	after, err := tree.Scan(gitDir, tree.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if before.Identity() != after.Identity() {
		t.Fatalf("M5.1 mutated real Git metadata: before=%s after=%s", before.Identity(), after.Identity())
	}
}

func TestLifecycleGitBindingRejectsM4BaselineGitBaseMismatch(t *testing.T) {
	lifecycle, disposable, _ := boundGitLifecycle(t)
	if err := os.WriteFile(filepath.Join(disposable.RealWorkspace(), "README.md"), []byte("outside commit after M4 baseline\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runLifecycleGit(t, disposable.RealWorkspace(), "add", "--", "README.md")
	runLifecycleGit(t, disposable.RealWorkspace(), "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "-m", "outside change")
	if _, err := lifecycle.BindGitRepository(); !errors.Is(err, ErrRealStateConflict) {
		t.Fatalf("binding mismatch = %v", err)
	}
	if lifecycle.State() != StateConflicted || lifecycle.GitRepositoryBinding() != nil {
		t.Fatalf("state=%s binding=%#v", lifecycle.State(), lifecycle.GitRepositoryBinding())
	}
}

func TestLifecycleGitPlanRejectsUntrackedM4Modify(t *testing.T) {
	now := time.Date(2026, 8, 28, 18, 0, 0, 0, time.UTC)
	real := lifecycleRealWorkspace(t)
	runLifecycleGit(t, real, "init", "-b", "main")
	writeLifecycleFile(t, real, "README.md", "tracked\n", 0o600)
	runLifecycleGit(t, real, "add", "--", "README.md")
	runLifecycleGit(t, real, "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "-m", "initial")
	writeLifecycleFile(t, real, "notes.txt", "untracked before\n", 0o600)
	disposable, err := workspace.Prepare(real)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := disposable.Cleanup(); err != nil {
			t.Errorf("cleanup disposable: %v", err)
		}
	})
	workspaceBinding, err := disposable.Binding()
	if err != nil {
		t.Fatal(err)
	}
	stub := &sandboxStub{real: workspaceBinding.RealWorkspace(), disposable: workspaceBinding.DisposableWorkspace(), token: workspaceBinding.Token()}
	manifest, err := NewRunManifest(lifecycleContract(t, now.Add(time.Hour), "/workspace/notes.txt"), workspaceBinding, stub, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := NewBoundLifecycle(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.BindGitRepository(); err != nil {
		t.Fatal(err)
	}
	runToStarted(t, lifecycle)
	if err := os.WriteFile(filepath.Join(disposable.Path(), "notes.txt"), []byte("agent update\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	freezeAndVerify(t, lifecycle)
	if _, err := lifecycle.DeriveGitEffectPlan(); !errors.Is(err, gitplan.ErrUnsupportedEffect) {
		t.Fatalf("untracked Git effect = %v", err)
	}
	if lifecycle.State() != StateRejected || lifecycle.GitEffectPlan() != nil {
		t.Fatalf("state=%s plan=%#v", lifecycle.State(), lifecycle.GitEffectPlan())
	}
}

func TestLifecycleRejectsAgentCreatedShadowGitAsFilesystemMutation(t *testing.T) {
	lifecycle, disposable, _ := boundGitLifecycle(t)
	binding, err := lifecycle.BindGitRepository()
	if err != nil {
		t.Fatal(err)
	}
	runToStarted(t, lifecycle)
	if err := os.Mkdir(filepath.Join(disposable.Path(), ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(disposable.Path(), ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	decision, err := lifecycle.Reconcile()
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed || lifecycle.State() != StateRejected {
		t.Fatalf("shadow .git decision=%#v state=%s", decision, lifecycle.State())
	}
	if lifecycle.GitRepositoryBinding().Identity() != binding.Identity() || lifecycle.GitEffectPlan() != nil {
		t.Fatal("hostile shadow .git influenced trusted Git authority")
	}
	if _, err := lifecycle.DeriveGitEffectPlan(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("rejected state derived plan: %v", err)
	}
}

func TestLifecycleGitPlanRevalidationFailsOnConcurrentHeadChange(t *testing.T) {
	lifecycle, disposable, _ := boundGitLifecycle(t)
	if _, err := lifecycle.BindGitRepository(); err != nil {
		t.Fatal(err)
	}
	runToStarted(t, lifecycle)
	if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("verified Git proposal\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	freezeAndVerify(t, lifecycle)
	if _, err := lifecycle.DeriveGitEffectPlan(); err != nil {
		t.Fatal(err)
	}
	runLifecycleGit(t, disposable.RealWorkspace(), "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "--allow-empty", "-m", "concurrent head")
	if err := lifecycle.RevalidateGitEffectPlan(); !errors.Is(err, gitplan.ErrRepositoryChanged) {
		t.Fatalf("revalidation = %v", err)
	}
	if lifecycle.State() != StateConflicted {
		t.Fatalf("state = %s, want CONFLICTED", lifecycle.State())
	}
	if err := lifecycle.RevalidateGitEffectPlan(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("conflicted plan was retryable: %v", err)
	}
}

func TestLifecycleConstructsOneDeterministicGitArtifactWithoutTouchingReality(t *testing.T) {
	lifecycle, disposable, gitDir := preparedGitArtifactLifecycle(t, func() time.Time {
		return time.Date(2026, 8, 29, 2, 0, 0, 987654321, time.UTC)
	}, time.Date(2026, 8, 29, 3, 0, 0, 0, time.UTC))
	beforeGit, err := tree.Scan(gitDir, tree.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	beforeReal, err := lifecycle.manifest.workspace.ObserveReal()
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := lifecycle.ConstructGitCommitArtifact()
	if err != nil {
		t.Fatal(err)
	}
	if artifact == nil || lifecycle.State() != StateVerified || artifact.GitPlanIdentity() != lifecycle.GitEffectPlan().Identity() || artifact.BaseBlobOID() != lifecycle.GitEffectPlan().Effects()[0].BaseBlobOID || artifact.Resource() != "/workspace/README.md" {
		t.Fatalf("artifact=%#v state=%s", artifact, lifecycle.State())
	}
	again, err := lifecycle.ConstructGitCommitArtifact()
	if err != nil || again != artifact || again.Identity() != artifact.Identity() || again.CommitOID() != artifact.CommitOID() {
		t.Fatalf("repeated artifact = %p/%s, %v", again, again.Identity(), err)
	}
	if err := lifecycle.RevalidateGitCommitArtifact(); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.PreCommit(); !errors.Is(err, ErrInvalidTransition) || lifecycle.State() != StateVerified {
		t.Fatalf("direct commit path after Git artifact = %v, state=%s", err, lifecycle.State())
	}
	afterGit, err := tree.Scan(gitDir, tree.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	afterReal, err := lifecycle.manifest.workspace.ObserveReal()
	if err != nil {
		t.Fatal(err)
	}
	if beforeGit.Identity() != afterGit.Identity() || beforeReal.Identity() != afterReal.Identity() {
		t.Fatal("M5.2 changed real Git metadata or worktree state")
	}
	assertRealREADME(t, disposable, "before\n", 0o600)
	if err := lifecycle.CleanupGitCommitArtifact(); err != nil {
		t.Fatal(err)
	}
	if lifecycle.GitCommitArtifact() != nil {
		t.Fatal("cleaned artifact remains installed")
	}
	if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("cleaned lifecycle minted another artifact: %v", err)
	}
}

func TestLifecycleGitArtifactRejectsStaleRealityAndFrozenShadow(t *testing.T) {
	base := time.Date(2026, 8, 29, 2, 0, 0, 0, time.UTC)
	t.Run("HEAD before construction", func(t *testing.T) {
		lifecycle, disposable, _ := preparedGitArtifactLifecycle(t, func() time.Time { return base }, base.Add(time.Hour))
		runLifecycleGit(t, disposable.RealWorkspace(), "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "--allow-empty", "-m", "concurrent head")
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, gitplan.ErrRepositoryChanged) || lifecycle.State() != StateConflicted || lifecycle.GitCommitArtifact() != nil {
			t.Fatalf("stale HEAD = %v, state=%s artifact=%#v", err, lifecycle.State(), lifecycle.GitCommitArtifact())
		}
	})
	t.Run("HEAD during construction", func(t *testing.T) {
		lifecycle, disposable, _ := preparedGitArtifactLifecycle(t, func() time.Time { return base }, base.Add(time.Hour))
		lifecycle.afterGitConstruction = func() {
			runLifecycleGit(t, disposable.RealWorkspace(), "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "--allow-empty", "-m", "concurrent head")
		}
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, gitplan.ErrRepositoryChanged) || lifecycle.State() != StateConflicted || lifecycle.GitCommitArtifact() != nil {
			t.Fatalf("concurrent HEAD = %v, state=%s artifact=%#v", err, lifecycle.State(), lifecycle.GitCommitArtifact())
		}
	})
	t.Run("shadow before construction", func(t *testing.T) {
		lifecycle, disposable, _ := preparedGitArtifactLifecycle(t, func() time.Time { return base }, base.Add(time.Hour))
		if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("late shadow bytes\n"), 0o666); err != nil {
			t.Fatal(err)
		}
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, ErrShadowChanged) || lifecycle.State() != StateRejected || lifecycle.GitCommitArtifact() != nil {
			t.Fatalf("stale shadow = %v, state=%s artifact=%#v", err, lifecycle.State(), lifecycle.GitCommitArtifact())
		}
	})
	t.Run("shadow during construction", func(t *testing.T) {
		lifecycle, disposable, _ := preparedGitArtifactLifecycle(t, func() time.Time { return base }, base.Add(time.Hour))
		lifecycle.afterGitConstruction = func() {
			if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("late shadow bytes\n"), 0o666); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, ErrShadowChanged) || lifecycle.State() != StateRejected || lifecycle.GitCommitArtifact() != nil {
			t.Fatalf("concurrent shadow = %v, state=%s artifact=%#v", err, lifecycle.State(), lifecycle.GitCommitArtifact())
		}
	})
}

func TestLifecycleGitArtifactExpiryRollbackAndCleanupUncertaintyFailClosed(t *testing.T) {
	base := time.Date(2026, 8, 29, 2, 0, 0, 0, time.UTC)
	t.Run("expiry", func(t *testing.T) {
		current := base
		lifecycle, _, _ := preparedGitArtifactLifecycle(t, func() time.Time { return current }, base.Add(time.Minute))
		current = base.Add(time.Minute)
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, ErrContractExpired) || lifecycle.State() != StateRejected {
			t.Fatalf("expiry = %v, state=%s", err, lifecycle.State())
		}
	})
	t.Run("rollback", func(t *testing.T) {
		current := base
		lifecycle, _, _ := preparedGitArtifactLifecycle(t, func() time.Time { return current }, base.Add(time.Hour))
		current = base.Add(-time.Second)
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, ErrClockRollback) || lifecycle.State() != StateFailed {
			t.Fatalf("rollback = %v, state=%s", err, lifecycle.State())
		}
	})
	t.Run("cleanup dominates conflict", func(t *testing.T) {
		lifecycle, disposable, _ := preparedGitArtifactLifecycle(t, func() time.Time { return base }, base.Add(time.Hour))
		lifecycle.afterGitConstruction = func() {
			runLifecycleGit(t, disposable.RealWorkspace(), "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "--allow-empty", "-m", "concurrent head")
		}
		lifecycle.cleanupGitArtifact = func(artifact *gitcommit.Artifact) error {
			return errors.Join(artifact.Cleanup(), fmt.Errorf("%w: injected cleanup uncertainty", gitcommit.ErrCleanup))
		}
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, gitplan.ErrRepositoryChanged) || !errors.Is(err, gitcommit.ErrCleanup) || lifecycle.State() != StateFailed {
			t.Fatalf("cleanup conflict = %v, state=%s", err, lifecycle.State())
		}
		if lifecycle.GitCommitArtifact() != nil || lifecycle.gitCleanupArtifact == nil {
			t.Fatal("failed cleanup exposed authority or lost cleanup ownership")
		}
		lifecycle.cleanupGitArtifact = nil
		if err := lifecycle.CleanupGitCommitArtifact(); err != nil || lifecycle.gitCleanupArtifact != nil {
			t.Fatalf("cleanup retry = %v, retained=%#v", err, lifecycle.gitCleanupArtifact)
		}
	})
	t.Run("explicit cleanup uncertainty revokes artifact", func(t *testing.T) {
		lifecycle, _, _ := preparedGitArtifactLifecycle(t, func() time.Time { return base }, base.Add(time.Hour))
		if _, err := lifecycle.ConstructGitCommitArtifact(); err != nil {
			t.Fatal(err)
		}
		lifecycle.cleanupGitArtifact = func(artifact *gitcommit.Artifact) error {
			return errors.Join(artifact.Cleanup(), fmt.Errorf("%w: injected cleanup uncertainty", gitcommit.ErrCleanup))
		}
		if err := lifecycle.CleanupGitCommitArtifact(); !errors.Is(err, gitcommit.ErrCleanup) || lifecycle.State() != StateFailed || lifecycle.GitCommitArtifact() != nil || lifecycle.gitCleanupArtifact == nil {
			t.Fatalf("uncertain explicit cleanup = %v, state=%s valid=%#v recovery=%#v", err, lifecycle.State(), lifecycle.GitCommitArtifact(), lifecycle.gitCleanupArtifact)
		}
		lifecycle.cleanupGitArtifact = nil
		if err := lifecycle.CleanupGitCommitArtifact(); err != nil || lifecycle.gitCleanupArtifact != nil {
			t.Fatalf("explicit cleanup retry = %v, retained=%#v", err, lifecycle.gitCleanupArtifact)
		}
	})
}

func TestLifecycleRevokesInstalledGitArtifactOnLaterAuthorityFailure(t *testing.T) {
	base := time.Date(2026, 8, 29, 3, 0, 0, 0, time.UTC)
	t.Run("HEAD then repeat construction", func(t *testing.T) {
		lifecycle, disposable, _ := preparedGitArtifactLifecycle(t, func() time.Time { return base }, base.Add(time.Hour))
		if _, err := lifecycle.ConstructGitCommitArtifact(); err != nil {
			t.Fatal(err)
		}
		cleanupCalled := false
		lifecycle.cleanupGitArtifact = func(artifact *gitcommit.Artifact) error {
			cleanupCalled = true
			return artifact.Cleanup()
		}
		runLifecycleGit(t, disposable.RealWorkspace(), "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "--allow-empty", "-m", "later head")
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, gitplan.ErrRepositoryChanged) || lifecycle.State() != StateConflicted || lifecycle.GitCommitArtifact() != nil || lifecycle.gitArtifact != nil || lifecycle.gitCleanupArtifact != nil || !cleanupCalled {
			t.Fatalf("later HEAD = %v, state=%s valid=%#v installed=%#v recovery=%#v cleanup=%t", err, lifecycle.State(), lifecycle.GitCommitArtifact(), lifecycle.gitArtifact, lifecycle.gitCleanupArtifact, cleanupCalled)
		}
	})

	t.Run("shadow then repeat construction", func(t *testing.T) {
		lifecycle, disposable, _ := preparedGitArtifactLifecycle(t, func() time.Time { return base }, base.Add(time.Hour))
		if _, err := lifecycle.ConstructGitCommitArtifact(); err != nil {
			t.Fatal(err)
		}
		cleanupCalled := false
		lifecycle.cleanupGitArtifact = func(artifact *gitcommit.Artifact) error {
			cleanupCalled = true
			return artifact.Cleanup()
		}
		if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("later shadow\n"), 0o666); err != nil {
			t.Fatal(err)
		}
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, ErrShadowChanged) || lifecycle.State() != StateRejected || lifecycle.GitCommitArtifact() != nil || lifecycle.gitArtifact != nil || lifecycle.gitCleanupArtifact != nil || !cleanupCalled {
			t.Fatalf("later shadow = %v, state=%s valid=%#v installed=%#v recovery=%#v cleanup=%t", err, lifecycle.State(), lifecycle.GitCommitArtifact(), lifecycle.gitArtifact, lifecycle.gitCleanupArtifact, cleanupCalled)
		}
	})

	t.Run("contract expiry then repeat construction", func(t *testing.T) {
		current := base
		lifecycle, _, _ := preparedGitArtifactLifecycle(t, func() time.Time { return current }, base.Add(time.Minute))
		if _, err := lifecycle.ConstructGitCommitArtifact(); err != nil {
			t.Fatal(err)
		}
		cleanupCalled := false
		lifecycle.cleanupGitArtifact = func(artifact *gitcommit.Artifact) error {
			cleanupCalled = true
			return artifact.Cleanup()
		}
		current = base.Add(time.Minute)
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, ErrContractExpired) || lifecycle.State() != StateRejected || lifecycle.GitCommitArtifact() != nil || lifecycle.gitArtifact != nil || !cleanupCalled {
			t.Fatalf("later expiry = %v, state=%s valid=%#v installed=%#v cleanup=%t", err, lifecycle.State(), lifecycle.GitCommitArtifact(), lifecycle.gitArtifact, cleanupCalled)
		}
	})

	t.Run("clock rollback then artifact revalidation", func(t *testing.T) {
		current := base
		lifecycle, _, _ := preparedGitArtifactLifecycle(t, func() time.Time { return current }, base.Add(time.Hour))
		if _, err := lifecycle.ConstructGitCommitArtifact(); err != nil {
			t.Fatal(err)
		}
		cleanupCalled := false
		lifecycle.cleanupGitArtifact = func(artifact *gitcommit.Artifact) error {
			cleanupCalled = true
			return artifact.Cleanup()
		}
		current = base.Add(-time.Second)
		if err := lifecycle.RevalidateGitCommitArtifact(); !errors.Is(err, ErrClockRollback) || lifecycle.State() != StateFailed || lifecycle.GitCommitArtifact() != nil || lifecycle.gitArtifact != nil || !cleanupCalled {
			t.Fatalf("later rollback = %v, state=%s valid=%#v installed=%#v cleanup=%t", err, lifecycle.State(), lifecycle.GitCommitArtifact(), lifecycle.gitArtifact, cleanupCalled)
		}
	})

	t.Run("cleanup uncertainty dominates later conflict", func(t *testing.T) {
		lifecycle, disposable, _ := preparedGitArtifactLifecycle(t, func() time.Time { return base }, base.Add(time.Hour))
		if _, err := lifecycle.ConstructGitCommitArtifact(); err != nil {
			t.Fatal(err)
		}
		lifecycle.cleanupGitArtifact = func(artifact *gitcommit.Artifact) error {
			return errors.Join(artifact.Cleanup(), fmt.Errorf("%w: injected later cleanup uncertainty", gitcommit.ErrCleanup))
		}
		runLifecycleGit(t, disposable.RealWorkspace(), "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "--allow-empty", "-m", "later head")
		if _, err := lifecycle.ConstructGitCommitArtifact(); !errors.Is(err, gitplan.ErrRepositoryChanged) || !errors.Is(err, gitcommit.ErrCleanup) || lifecycle.State() != StateFailed || lifecycle.GitCommitArtifact() != nil || lifecycle.gitArtifact != nil || lifecycle.gitCleanupArtifact == nil {
			t.Fatalf("later cleanup uncertainty = %v, state=%s valid=%#v installed=%#v recovery=%#v", err, lifecycle.State(), lifecycle.GitCommitArtifact(), lifecycle.gitArtifact, lifecycle.gitCleanupArtifact)
		}
		lifecycle.cleanupGitArtifact = nil
		if err := lifecycle.CleanupGitCommitArtifact(); err != nil || lifecycle.gitCleanupArtifact != nil {
			t.Fatalf("later cleanup retry = %v, retained=%#v", err, lifecycle.gitCleanupArtifact)
		}
	})
}

func TestLifecycleClockRollbackBeforePrepareFailsClosed(t *testing.T) {
	base := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	stub := &sandboxStub{}
	lifecycle, err := NewLifecycleWithClock(stub, sequenceClock(t, base, base.Add(-time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Prepare(context.Background()); !errors.Is(err, ErrClockRollback) {
		t.Fatalf("prepare error = %v", err)
	}
	if lifecycle.State() != StateFailed || len(stub.calls) != 0 {
		t.Fatalf("state = %s, calls = %v", lifecycle.State(), stub.calls)
	}
}

func TestLifecycleClockRollbackBeforeStartFailsClosed(t *testing.T) {
	base := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	stub := &sandboxStub{}
	lifecycle, err := NewLifecycleWithClock(stub, sequenceClock(t, base, base.Add(time.Minute), base))
	if err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Start(context.Background()); !errors.Is(err, ErrClockRollback) {
		t.Fatalf("start error = %v", err)
	}
	if lifecycle.State() != StateFailed || len(stub.calls) != 1 || stub.calls[0] != "prepare" {
		t.Fatalf("state = %s, calls = %v", lifecycle.State(), stub.calls)
	}
}

func TestLifecycleClockRollbackBeforeFreezeStillStopsProcessTree(t *testing.T) {
	base := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	stub := &sandboxStub{}
	lifecycle, err := NewLifecycleWithClock(stub, sequenceClock(t,
		base,
		base.Add(time.Minute),
		base.Add(2*time.Minute),
		base.Add(time.Minute),
	))
	if err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Freeze(context.Background()); !errors.Is(err, ErrClockRollback) {
		t.Fatalf("freeze error = %v", err)
	}
	if lifecycle.State() != StateFailed {
		t.Fatalf("state = %s", lifecycle.State())
	}
	if len(stub.calls) != 3 || stub.calls[2] != "freeze" {
		t.Fatalf("rollback bypassed process-tree stop: %v", stub.calls)
	}
}

func TestLifecycleClockRollbackBeforeReconciliationCannotRevalidateExpiredContract(t *testing.T) {
	base := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	lifecycle, disposable := boundLifecycle(t, sequenceClock(t,
		base,
		base.Add(time.Minute),
		base.Add(2*time.Minute),
		base.Add(10*time.Minute),
		base.Add(3*time.Minute),
	), base.Add(5*time.Minute))
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = disposable
	if _, err := lifecycle.Reconcile(); !errors.Is(err, ErrClockRollback) {
		t.Fatalf("reconcile error = %v", err)
	}
	if lifecycle.State() != StateFailed {
		t.Fatalf("state = %s, want FAILED", lifecycle.State())
	}
	if plan, decision := lifecycle.Reconciliation(); plan != nil || decision.Allowed {
		t.Fatalf("rollback created reconciliation authority: plan=%#v decision=%#v", plan, decision)
	}
}

func TestLifecycleRejectsUnavailableClockAtCreation(t *testing.T) {
	if _, err := NewLifecycleWithClock(&sandboxStub{}, nil); !errors.Is(err, ErrTrustedTime) {
		t.Fatalf("nil clock error = %v", err)
	}
	if _, err := NewLifecycleWithClock(&sandboxStub{}, func() time.Time { return time.Time{} }); !errors.Is(err, ErrTrustedTime) {
		t.Fatalf("zero clock error = %v", err)
	}
}

func TestLifecycleRejectCannotHideRunningProcess(t *testing.T) {
	stub := &sandboxStub{}
	lifecycle, err := NewLifecycle(stub)
	if err != nil {
		t.Fatalf("new lifecycle: %v", err)
	}
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Reject(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("reject error = %v", err)
	}
	if lifecycle.State() != StateRunning {
		t.Fatalf("state = %s, want RUNNING", lifecycle.State())
	}
}

func TestLifecycleCommitsOneVerifiedContentChangeAndPreservesRealMode(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	lifecycle, disposable := boundLifecycle(t, func() time.Time { return now }, now.Add(time.Hour), "/workspace/README.md")
	runToStarted(t, lifecycle)
	if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("authorized update\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	freezeAndVerify(t, lifecycle)
	commitPlan, err := lifecycle.PreCommit()
	if err != nil {
		t.Fatalf("precommit: %v", err)
	}
	if commitPlan.ManifestHash() == "" || commitPlan.AuthorityHash() == "" || commitPlan.RealBaselineIdentity() == "" || commitPlan.RealMode() != 0o600 {
		t.Fatalf("incomplete real commit authority: %#v", commitPlan)
	}
	if err := lifecycle.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if lifecycle.State() != StateCommitted {
		t.Fatalf("state = %s, want COMMITTED", lifecycle.State())
	}
	realREADME := filepath.Join(disposable.RealWorkspace(), "README.md")
	contents, err := os.ReadFile(realREADME)
	if err != nil || string(contents) != "authorized update\n" {
		t.Fatalf("real contents = %q, %v", contents, err)
	}
	info, err := os.Lstat(realREADME)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("real mode = %v, %v", info, err)
	}
	entries, err := os.ReadDir(disposable.RealWorkspace())
	if err != nil || len(entries) != 1 || entries[0].Name() != "README.md" {
		t.Fatalf("real workspace entries = %v, %v", entries, err)
	}
}

func TestLifecycleRejectsRealChangeImmediatelyBeforeCommit(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	lifecycle, disposable := verifiedContentLifecycle(t, func() time.Time { return now }, now.Add(time.Hour))
	if _, err := lifecycle.PreCommit(); err != nil {
		t.Fatal(err)
	}
	realREADME := filepath.Join(disposable.RealWorkspace(), "README.md")
	if err := os.WriteFile(realREADME, []byte("external winner"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Commit(); !errors.Is(err, ErrRealStateConflict) {
		t.Fatalf("commit error = %v, want real-state conflict", err)
	}
	if lifecycle.State() != StateConflicted {
		t.Fatalf("state = %s, want CONFLICTED", lifecycle.State())
	}
	contents, err := os.ReadFile(realREADME)
	if err != nil || string(contents) != "external winner" {
		t.Fatalf("conflict overwrote reality: %q, %v", contents, err)
	}
}

func TestLifecycleRejectsShadowChangeAfterVerification(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	for _, afterPrecommit := range []bool{false, true} {
		name := "before precommit"
		if afterPrecommit {
			name = "immediately before commit"
		}
		t.Run(name, func(t *testing.T) {
			lifecycle, disposable := verifiedContentLifecycle(t, func() time.Time { return now }, now.Add(time.Hour))
			if afterPrecommit {
				if _, err := lifecycle.PreCommit(); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("shadow tamper"), 0o666); err != nil {
				t.Fatal(err)
			}
			var err error
			if afterPrecommit {
				err = lifecycle.Commit()
			} else {
				_, err = lifecycle.PreCommit()
			}
			if !errors.Is(err, ErrShadowChanged) {
				t.Fatalf("shadow tamper error = %v", err)
			}
			if lifecycle.State() != StateRejected {
				t.Fatalf("state = %s, want REJECTED", lifecycle.State())
			}
			assertRealREADME(t, disposable, "before", 0o600)
		})
	}
}

func TestLifecycleRejectsExpiredOrRolledBackClockBeforeCommit(t *testing.T) {
	base := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	t.Run("expired", func(t *testing.T) {
		current := base
		lifecycle, disposable := verifiedContentLifecycle(t, func() time.Time { return current }, base.Add(time.Minute))
		current = base.Add(2 * time.Minute)
		if _, err := lifecycle.PreCommit(); !errors.Is(err, ErrContractExpired) {
			t.Fatalf("precommit error = %v", err)
		}
		if lifecycle.State() != StateRejected {
			t.Fatalf("state = %s, want REJECTED", lifecycle.State())
		}
		assertRealREADME(t, disposable, "before", 0o600)
	})
	t.Run("rollback immediately before commit", func(t *testing.T) {
		current := base
		lifecycle, disposable := verifiedContentLifecycle(t, func() time.Time { return current }, base.Add(time.Hour))
		if _, err := lifecycle.PreCommit(); err != nil {
			t.Fatal(err)
		}
		current = base.Add(-time.Second)
		if err := lifecycle.Commit(); !errors.Is(err, ErrClockRollback) {
			t.Fatalf("commit error = %v", err)
		}
		if lifecycle.State() != StateFailed {
			t.Fatalf("state = %s, want FAILED", lifecycle.State())
		}
		assertRealREADME(t, disposable, "before", 0o600)
	})
}

func TestLifecycleRechecksTrustedTimeImmediatelyBeforeReplacement(t *testing.T) {
	base := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	t.Run("expires during apply", func(t *testing.T) {
		clock := sequenceClock(t,
			base,                    // manifest
			base,                    // prepare
			base,                    // start
			base,                    // freeze
			base,                    // reconcile
			base,                    // precommit
			base,                    // commit derivation
			base.Add(2*time.Minute), // immediately before rename
		)
		lifecycle, disposable := verifiedContentLifecycle(t, clock, base.Add(time.Minute))
		if _, err := lifecycle.PreCommit(); err != nil {
			t.Fatal(err)
		}
		if err := lifecycle.Commit(); !errors.Is(err, ErrContractExpired) {
			t.Fatalf("commit error = %v, want replacement-time expiry", err)
		}
		if lifecycle.State() != StateRejected {
			t.Fatalf("state = %s, want REJECTED", lifecycle.State())
		}
		assertRealREADME(t, disposable, "before", 0o600)
		assertNoLifecycleStaging(t, disposable.RealWorkspace())
	})
	t.Run("rolls back during apply", func(t *testing.T) {
		clock := sequenceClock(t,
			base,                   // manifest
			base,                   // prepare
			base,                   // start
			base,                   // freeze
			base,                   // reconcile
			base,                   // precommit
			base,                   // commit derivation
			base.Add(-time.Second), // immediately before rename
		)
		lifecycle, disposable := verifiedContentLifecycle(t, clock, base.Add(time.Hour))
		if _, err := lifecycle.PreCommit(); err != nil {
			t.Fatal(err)
		}
		if err := lifecycle.Commit(); !errors.Is(err, ErrClockRollback) {
			t.Fatalf("commit error = %v, want replacement-time rollback", err)
		}
		if lifecycle.State() != StateFailed {
			t.Fatalf("state = %s, want FAILED", lifecycle.State())
		}
		assertRealREADME(t, disposable, "before", 0o600)
		assertNoLifecycleStaging(t, disposable.RealWorkspace())
	})
}

func TestCommitFailureStateCleanupAndUncertaintyDominateSemanticOutcome(t *testing.T) {
	cleanup := fmt.Errorf("%w: remove staging", realcommit.ErrCleanup)
	for _, test := range []struct {
		name string
		err  error
	}{
		{
			name: "expired plus cleanup failure",
			err:  errors.Join(ErrContractExpired, cleanup),
		},
		{
			name: "conflict plus cleanup failure",
			err:  errors.Join(ErrRealStateConflict, cleanup),
		},
		{
			name: "conflict plus revalidation uncertainty",
			err:  errors.Join(realcommit.ErrConflict, realcommit.ErrRevalidation),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if state := commitFailureState(test.err); state != StateFailed {
				t.Fatalf("state = %s, want FAILED for %v", state, test.err)
			}
		})
	}
	if state := commitFailureState(ErrContractExpired); state != StateRejected {
		t.Fatalf("clean expiry state = %s, want REJECTED", state)
	}
	if state := commitFailureState(realcommit.ErrConflict); state != StateConflicted {
		t.Fatalf("clean conflict state = %s, want CONFLICTED", state)
	}
}

func TestLifecycleRejectsTwoFileCommitPlanWithoutTouchingReality(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	lifecycle, disposable := boundLifecycleWithSetup(t, func() time.Time { return now }, now.Add(time.Hour), func(t *testing.T, real string) {
		writeLifecycleFile(t, real, "README.md", "before", 0o600)
		writeLifecycleFile(t, real, "notes.txt", "notes before", 0o640)
	}, "/workspace/README.md", "/workspace/notes.txt")
	runToStarted(t, lifecycle)
	writeLifecycleFile(t, disposable.Path(), "README.md", "after", 0o666)
	writeLifecycleFile(t, disposable.Path(), "notes.txt", "notes after", 0o666)
	if err := lifecycle.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	decision, err := lifecycle.Reconcile()
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed || lifecycle.State() != StateRejected {
		t.Fatalf("decision = %#v, state = %s", decision, lifecycle.State())
	}
	assertRealREADME(t, disposable, "before", 0o600)
	contents, err := os.ReadFile(filepath.Join(disposable.RealWorkspace(), "notes.txt"))
	if err != nil || string(contents) != "notes before" {
		t.Fatalf("real notes = %q, %v", contents, err)
	}
}

func verifiedContentLifecycle(t *testing.T, now func() time.Time, expires time.Time) (*Lifecycle, *workspace.Disposable) {
	t.Helper()
	lifecycle, disposable := boundLifecycle(t, now, expires, "/workspace/README.md")
	runToStarted(t, lifecycle)
	if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("authorized update"), 0o666); err != nil {
		t.Fatal(err)
	}
	freezeAndVerify(t, lifecycle)
	return lifecycle, disposable
}

func runToStarted(t *testing.T, lifecycle *Lifecycle) {
	t.Helper()
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func freezeAndVerify(t *testing.T, lifecycle *Lifecycle) {
	t.Helper()
	if err := lifecycle.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	decision, err := lifecycle.Reconcile()
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed || lifecycle.State() != StateVerified {
		t.Fatalf("decision = %#v, state = %s", decision, lifecycle.State())
	}
}

func assertRealREADME(t *testing.T, disposable *workspace.Disposable, contents string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(disposable.RealWorkspace(), "README.md")
	observed, err := os.ReadFile(path)
	if err != nil || string(observed) != contents {
		t.Fatalf("real README = %q, %v", observed, err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != mode {
		t.Fatalf("real README mode = %v, %v", info, err)
	}
}

func assertNoLifecycleStaging(t *testing.T, root string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(root, workspace.CommitStagingPrefix+"*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("commit staging remains after denied replacement: %v", matches)
	}
}

func frozenLifecycle(t *testing.T) (*Lifecycle, *workspace.Disposable) {
	t.Helper()
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	lifecycle, disposable := boundLifecycle(t, func() time.Time { return now }, now.Add(time.Hour))
	if err := lifecycle.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	return lifecycle, disposable
}

func boundLifecycle(t *testing.T, now func() time.Time, expires time.Time, allow ...string) (*Lifecycle, *workspace.Disposable) {
	t.Helper()
	return boundLifecycleWithSetup(t, now, expires, func(t *testing.T, real string) {
		writeLifecycleFile(t, real, "README.md", "before", 0o600)
	}, allow...)
}

func boundLifecycleWithSetup(t *testing.T, now func() time.Time, expires time.Time, setup func(*testing.T, string), allow ...string) (*Lifecycle, *workspace.Disposable) {
	t.Helper()
	real := lifecycleRealWorkspace(t)
	setup(t, real)
	disposable, err := workspace.Prepare(real)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := disposable.Cleanup(); err != nil {
			t.Errorf("cleanup disposable: %v", err)
		}
	})
	binding, err := disposable.Binding()
	if err != nil {
		t.Fatal(err)
	}
	stub := &sandboxStub{
		real:       binding.RealWorkspace(),
		disposable: binding.DisposableWorkspace(),
		token:      binding.Token(),
	}
	manifest, err := NewRunManifest(lifecycleContract(t, expires, allow...), binding, stub, now)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := NewBoundLifecycle(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return lifecycle, disposable
}

func writeLifecycleFile(t *testing.T, root, relative, contents string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(root, relative)
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func lifecycleRealWorkspace(t *testing.T) string {
	t.Helper()
	base, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(base, ".mirage-lifecycle-real-")
	if err != nil {
		t.Fatal(err)
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(absolute); err != nil {
			t.Errorf("cleanup real fixture: %v", err)
		}
	})
	return absolute
}

func sequenceClock(t *testing.T, readings ...time.Time) func() time.Time {
	t.Helper()
	index := 0
	return func() time.Time {
		if index >= len(readings) {
			t.Fatalf("trusted clock read %d exceeds %d deterministic readings", index+1, len(readings))
		}
		reading := readings[index]
		index++
		return reading
	}
}

func lifecycleContract(t *testing.T, expires time.Time, allow ...string) *contracts.Contract {
	t.Helper()
	contract, err := contracts.New(contracts.Spec{
		Version:   contracts.VersionV1,
		RunID:     "lifecycle-test",
		ActorID:   "hostile-fixture",
		ExpiresAt: expires,
		Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{
			Allow: allow,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return contract
}

func boundGitLifecycle(t *testing.T) (*Lifecycle, *workspace.Disposable, string) {
	t.Helper()
	now := time.Date(2026, 8, 28, 18, 0, 0, 0, time.UTC)
	real := lifecycleRealWorkspace(t)
	runLifecycleGit(t, real, "init", "-b", "main")
	writeLifecycleFile(t, real, "README.md", "before\n", 0o600)
	runLifecycleGit(t, real, "add", "--", "README.md")
	runLifecycleGit(t, real, "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "-m", "initial")
	disposable, err := workspace.Prepare(real)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := disposable.Cleanup(); err != nil {
			t.Errorf("cleanup disposable: %v", err)
		}
	})
	binding, err := disposable.Binding()
	if err != nil {
		t.Fatal(err)
	}
	stub := &sandboxStub{real: binding.RealWorkspace(), disposable: binding.DisposableWorkspace(), token: binding.Token()}
	manifest, err := NewRunManifest(lifecycleContract(t, now.Add(time.Hour), "/workspace/README.md"), binding, stub, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := NewBoundLifecycle(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return lifecycle, disposable, filepath.Join(real, ".git")
}

func preparedGitArtifactLifecycle(t *testing.T, now func() time.Time, expires time.Time) (*Lifecycle, *workspace.Disposable, string) {
	t.Helper()
	real := lifecycleRealWorkspace(t)
	runLifecycleGit(t, real, "init", "-b", "main")
	writeLifecycleFile(t, real, "README.md", "before\n", 0o600)
	runLifecycleGit(t, real, "add", "--", "README.md")
	runLifecycleGit(t, real, "-c", "user.name=MIRAGE Test", "-c", "user.email=mirage@example.invalid", "commit", "-m", "initial")
	disposable, err := workspace.Prepare(real)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := disposable.Cleanup(); err != nil {
			t.Errorf("cleanup disposable: %v", err)
		}
	})
	binding, err := disposable.Binding()
	if err != nil {
		t.Fatal(err)
	}
	stub := &sandboxStub{real: binding.RealWorkspace(), disposable: binding.DisposableWorkspace(), token: binding.Token()}
	manifest, err := NewRunManifest(lifecycleContract(t, expires, "/workspace/README.md"), binding, stub, now)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := NewBoundLifecycle(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.BindGitRepository(); err != nil {
		t.Fatal(err)
	}
	runToStarted(t, lifecycle)
	if err := os.WriteFile(filepath.Join(disposable.Path(), "README.md"), []byte("verified Git artifact\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	freezeAndVerify(t, lifecycle)
	if _, err := lifecycle.DeriveGitEffectPlan(); err != nil {
		t.Fatal(err)
	}
	return lifecycle, disposable, filepath.Join(real, ".git")
}

func runLifecycleGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v (%s)", args, err, output)
	}
	return strings.TrimSpace(string(output))
}
