package githubpullrequest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type scriptedPRDoer struct {
	t                  *testing.T
	mu                 sync.Mutex
	plan               *Plan
	pullResponses      [][]apiPullRequest
	postStatus         int
	postBody           string
	postErr            error
	cancelOnPost       context.CancelFunc
	postCount          int
	pullCount          int
	latchVisibleOnPost func() bool
}

func (d *scriptedPRDoer) Do(request *http.Request) (*http.Response, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if request.URL.Path == "/repos/owner/repo" && request.Method == http.MethodGet {
		return response(http.StatusOK, `{"id":42,"full_name":"owner/repo"}`), nil
	}
	if request.URL.Path == "/repos/owner/repo/pulls" && request.Method == http.MethodGet {
		if d.pullCount >= len(d.pullResponses) {
			d.t.Fatal("unexpected extra PR observation")
		}
		value := d.pullResponses[d.pullCount]
		d.pullCount++
		return jsonResponse(d.t, value), nil
	}
	if request.URL.Path == "/repos/owner/repo/pulls" && request.Method == http.MethodPost {
		d.postCount++
		if d.latchVisibleOnPost != nil && !d.latchVisibleOnPost() {
			d.t.Fatal("POST observed before one-way attempt latch")
		}
		expected, err := canonicalRequestBytes(d.plan)
		if err != nil {
			d.t.Fatal(err)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil || string(body) != string(expected) {
			d.t.Fatalf("POST body=%q err=%v want=%q", body, err, expected)
		}
		if d.cancelOnPost != nil {
			d.cancelOnPost()
		}
		if d.postErr != nil {
			return nil, d.postErr
		}
		return response(d.postStatus, d.postBody), nil
	}
	d.t.Fatalf("unexpected request %s %s", request.Method, request.URL)
	return nil, errors.New("unexpected request")
}

func (d *scriptedPRDoer) counts() (posts, pulls int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.postCount, d.pullCount
}

func TestEngineInstallsAttemptBeforeOneExactPOSTAndUsesAuthoritativePostflight(t *testing.T) {
	plan := testPlan(t)
	exact := exactAPIPullRequest(plan)
	exactBody := string(mustJSON(t, exact))
	tests := map[string]struct {
		postStatus int
		postBody   string
		postErr    error
		postflight []apiPullRequest
		wantAck    bool
		wantStatus ObservationStatus
	}{
		"acknowledged exact":              {postStatus: http.StatusCreated, postBody: exactBody, postflight: []apiPullRequest{exact}, wantAck: true, wantStatus: ObservationExact},
		"lost acknowledgement exact":      {postErr: errors.New("connection reset secret"), postflight: []apiPullRequest{exact}, wantStatus: ObservationExact},
		"rejected absent":                 {postStatus: http.StatusUnprocessableEntity, postBody: `{}`, wantStatus: ObservationAbsent},
		"malformed acknowledgement exact": {postStatus: http.StatusCreated, postBody: `{`, postflight: []apiPullRequest{exact}, wantStatus: ObservationExact},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			latched := false
			doer := &scriptedPRDoer{t: t, plan: plan, pullResponses: [][]apiPullRequest{nil, test.postflight}, postStatus: test.postStatus, postBody: test.postBody, postErr: test.postErr, latchVisibleOnPost: func() bool { return latched }}
			client, err := NewHTTPClientForDoer("host-secret", doer)
			if err != nil {
				t.Fatal(err)
			}
			engine, err := NewEngine(client)
			if err != nil {
				t.Fatal(err)
			}
			result, _ := engine.Establish(context.Background(), plan, func(context.Context) (*PullRequestAttempt, error) {
				attempt, attemptErr := NewPullRequestAttempt(plan, plan.CreatedAt().Add(time.Second))
				latched = attemptErr == nil
				return attempt, attemptErr
			})
			posts, pulls := doer.counts()
			if posts != 1 || pulls != 2 || !result.Attempted || result.Attempt == nil || result.CompatibleAcknowledgement != test.wantAck || result.Postflight.Status != test.wantStatus {
				t.Fatalf("result=%#v posts=%d pulls=%d", result, posts, pulls)
			}
		})
	}
}

func TestEnginePostflightSurvivesCallerCancellation(t *testing.T) {
	plan := testPlan(t)
	callerCtx, cancel := context.WithCancel(context.Background())
	doer := &scriptedPRDoer{t: t, plan: plan, pullResponses: [][]apiPullRequest{nil, nil}, postErr: context.Canceled, cancelOnPost: cancel}
	client, _ := NewHTTPClientForDoer("host-secret", doer)
	engine, _ := NewEngine(client)
	result, err := engine.Establish(callerCtx, plan, func(context.Context) (*PullRequestAttempt, error) {
		return NewPullRequestAttempt(plan, plan.CreatedAt().Add(time.Second))
	})
	posts, pulls := doer.counts()
	if posts != 1 || pulls != 2 || result.Postflight.Status != ObservationAbsent || !errors.Is(err, ErrCreateUnavailable) || callerCtx.Err() == nil {
		t.Fatalf("result=%#v err=%v posts=%d pulls=%d", result, err, posts, pulls)
	}
}

func TestEnginePreflightAndFinalAuthorityFailuresPerformNoPOST(t *testing.T) {
	plan := testPlan(t)
	exact := exactAPIPullRequest(plan)
	for name, preflight := range map[string][]apiPullRequest{
		"already exact": {exact},
		"conflicting":   {mutateCandidate(exact, func(pr *apiPullRequest) { pr.Draft = true })},
	} {
		t.Run(name, func(t *testing.T) {
			doer := &scriptedPRDoer{t: t, plan: plan, pullResponses: [][]apiPullRequest{preflight}}
			client, _ := NewHTTPClientForDoer("host-secret", doer)
			engine, _ := NewEngine(client)
			callbackCalls := 0
			result, err := engine.Establish(context.Background(), plan, func(context.Context) (*PullRequestAttempt, error) {
				callbackCalls++
				return NewPullRequestAttempt(plan, plan.CreatedAt().Add(time.Second))
			})
			posts, _ := doer.counts()
			if err != nil || posts != 0 || callbackCalls != 0 || result.Attempted {
				t.Fatalf("result=%#v err=%v posts=%d callbacks=%d", result, err, posts, callbackCalls)
			}
		})
	}

	doer := &scriptedPRDoer{t: t, plan: plan, pullResponses: [][]apiPullRequest{nil}}
	client, _ := NewHTTPClientForDoer("host-secret", doer)
	engine, _ := NewEngine(client)
	result, err := engine.Establish(context.Background(), plan, func(context.Context) (*PullRequestAttempt, error) {
		return nil, errors.New("final authority denied")
	})
	posts, pulls := doer.counts()
	if err == nil || posts != 0 || pulls != 1 || result.Attempted {
		t.Fatalf("final authority result=%#v err=%v posts=%d pulls=%d", result, err, posts, pulls)
	}
}

func TestEngineErrorsNeverContainCredential(t *testing.T) {
	const secret = "m54-distinctive-host-secret"
	plan := testPlan(t)
	doer := &scriptedPRDoer{t: t, plan: plan, pullResponses: [][]apiPullRequest{nil, nil}, postErr: errors.New("provider leaked " + secret)}
	client, _ := NewHTTPClientForDoer(secret, doer)
	engine, _ := NewEngine(client)
	_, err := engine.Establish(context.Background(), plan, func(context.Context) (*PullRequestAttempt, error) {
		return NewPullRequestAttempt(plan, plan.CreatedAt().Add(time.Second))
	})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsanitized error=%v", err)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
