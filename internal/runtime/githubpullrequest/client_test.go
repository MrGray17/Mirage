package githubpullrequest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(request *http.Request) (*http.Response, error) { return f(request) }

func TestObserveExactPullRequestUsesFixedBoundAuthority(t *testing.T) {
	const secret = "m54-observer-secret-never-log"
	plan := testPlan(t)
	candidate := exactAPIPullRequest(plan)
	client, err := NewHTTPClientForDoer(secret, doerFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Scheme != "https" || request.URL.Host != "api.github.com" {
			t.Fatalf("unsafe request %s %s", request.Method, request.URL)
		}
		if request.Header.Get("Authorization") != "Bearer "+secret || request.Header.Get("X-GitHub-Api-Version") != apiVersion {
			t.Fatal("dedicated credential or API version missing")
		}
		if request.URL.Path == "/repos/owner/repo" {
			return response(http.StatusOK, `{"id":42,"full_name":"Owner/Repo"}`), nil
		}
		if request.URL.Path != "/repos/owner/repo/pulls" || request.URL.Query().Get("state") != "all" || request.URL.Query().Get("head") != "owner:mirage/run-123456789012345678901234" || request.URL.Query().Get("base") != "main" || request.URL.Query().Get("page") != "1" {
			t.Fatalf("untrusted query authority: %s", request.URL)
		}
		return jsonResponse(t, []apiPullRequest{candidate}), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := client.ObserveExactPullRequest(context.Background(), plan)
	if err != nil || observation.Status != ObservationExact || observation.Exact == nil || observation.Exact.Number() != 17 || observation.Exact.StableID() != 1700 {
		t.Fatalf("observation=%#v err=%v", observation, err)
	}
}

func TestObserveExactPullRequestCanonicalizesProviderDisplayCasing(t *testing.T) {
	plan := testPlanForRepository(t, "mrgray17/mirage")
	candidate := exactAPIPullRequest(plan)
	candidate.HTMLURL = "https://github.com/MrGray17/Mirage/pull/17"
	candidate.Head.Repo.FullName = "MrGray17/Mirage"
	candidate.Base.Repo.FullName = "MrGray17/Mirage"
	client, err := NewHTTPClientForDoer("secret", doerFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/repos/mrgray17/mirage":
			return response(http.StatusOK, `{"id":42,"full_name":"MrGray17/Mirage"}`), nil
		case "/repos/mrgray17/mirage/pulls":
			return jsonResponse(t, []apiPullRequest{candidate}), nil
		default:
			t.Fatalf("unexpected request path %q", request.URL.Path)
			return nil, errors.New("unexpected request")
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := client.ObserveExactPullRequest(context.Background(), plan)
	if err != nil || observation.Status != ObservationExact || observation.Exact == nil || observation.Exact.URL() != "https://github.com/mrgray17/mirage/pull/17" {
		t.Fatalf("observation=%#v error=%v", observation, err)
	}
}

func TestObserveExactPullRequestClassifiesAbsentAndHostileCandidates(t *testing.T) {
	plan := testPlan(t)
	exact := exactAPIPullRequest(plan)
	tests := map[string]struct {
		candidates []apiPullRequest
		want       ObservationStatus
		evidence   string
	}{
		"absent":      {want: ObservationAbsent},
		"duplicate":   {candidates: []apiPullRequest{exact, exact}, want: ObservationConflicting, evidence: "duplicate_candidates"},
		"closed":      {candidates: []apiPullRequest{mutateCandidate(exact, func(pr *apiPullRequest) { pr.State = "closed" })}, want: ObservationConflicting, evidence: "closed_or_draft"},
		"draft":       {candidates: []apiPullRequest{mutateCandidate(exact, func(pr *apiPullRequest) { pr.Draft = true })}, want: ObservationConflicting, evidence: "closed_or_draft"},
		"fork":        {candidates: []apiPullRequest{mutateCandidate(exact, func(pr *apiPullRequest) { pr.Head.Repo.ID = 99; pr.Head.Repo.FullName = "fork/repo" })}, want: ObservationConflicting, evidence: "fork_or_repository_mismatch"},
		"wrong base":  {candidates: []apiPullRequest{mutateCandidate(exact, func(pr *apiPullRequest) { pr.Base.Ref = "release" })}, want: ObservationConflicting, evidence: "ref_or_oid_mismatch"},
		"wrong head":  {candidates: []apiPullRequest{mutateCandidate(exact, func(pr *apiPullRequest) { pr.Head.Ref = "other" })}, want: ObservationConflicting, evidence: "ref_or_oid_mismatch"},
		"wrong OID":   {candidates: []apiPullRequest{mutateCandidate(exact, func(pr *apiPullRequest) { pr.Head.SHA = testBaseOID })}, want: ObservationConflicting, evidence: "ref_or_oid_mismatch"},
		"wrong title": {candidates: []apiPullRequest{mutateCandidate(exact, func(pr *apiPullRequest) { pr.Title += " agent" })}, want: ObservationConflicting, evidence: "metadata_mismatch"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := observerWithCandidates(t, plan, test.candidates)
			observation, err := client.ObserveExactPullRequest(context.Background(), plan)
			if err != nil || observation.Status != test.want || observation.Evidence != test.evidence {
				t.Fatalf("observation=%#v err=%v, want %s/%s", observation, err, test.want, test.evidence)
			}
		})
	}
}

func TestObserveExactPullRequestFailsUnavailableOnIncompleteOrMalformedState(t *testing.T) {
	plan := testPlan(t)
	exact := exactAPIPullRequest(plan)
	fullPage := make([]apiPullRequest, pullRequestsPerPage)
	for index := range fullPage {
		fullPage[index] = exact
		fullPage[index].Number = int64(index + 1)
		fullPage[index].ID = int64(index + 100)
		fullPage[index].HTMLURL = "https://github.com/owner/repo/pull/" + strconv.Itoa(index+1)
	}
	pageCalls := 0
	client, err := NewHTTPClientForDoer("secret", doerFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/repos/owner/repo" {
			return response(http.StatusOK, `{"id":42,"full_name":"owner/repo"}`), nil
		}
		pageCalls++
		return jsonResponse(t, fullPage), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := client.ObserveExactPullRequest(context.Background(), plan)
	if !errors.Is(err, ErrObservationUnavailable) || observation.Status != ObservationUnavailable || pageCalls != maxPullRequestPages {
		t.Fatalf("truncated pagination observation=%#v err=%v pages=%d", observation, err, pageCalls)
	}

	for name, body := range map[string]string{
		"malformed JSON": `{`,
		"oversized":      `"` + strings.Repeat("x", maxResponseBytes+1) + `"`,
	} {
		t.Run(name, func(t *testing.T) {
			malformed, _ := NewHTTPClientForDoer("secret", doerFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Path == "/repos/owner/repo" {
					return response(http.StatusOK, `{"id":42,"full_name":"owner/repo"}`), nil
				}
				return response(http.StatusOK, body), nil
			}))
			observation, err := malformed.ObserveExactPullRequest(context.Background(), plan)
			if !errors.Is(err, ErrObservationUnavailable) || observation.Status != ObservationUnavailable {
				t.Fatalf("observation=%#v err=%v", observation, err)
			}
		})
	}
}

func TestObserverSanitizesCredentialAndNeverTreatsRepositoryFailureAsAbsent(t *testing.T) {
	const secret = "m54-secret-do-not-leak"
	plan := testPlan(t)
	client, err := NewHTTPClientForDoer(secret, doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport exposed " + secret)
	}))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := client.ObserveExactPullRequest(context.Background(), plan)
	if !errors.Is(err, ErrObservationUnavailable) || observation.Status != ObservationUnavailable || strings.Contains(err.Error(), secret) {
		t.Fatalf("observation=%#v unsanitized error=%v", observation, err)
	}

	missing, _ := NewHTTPClientForDoer(secret, doerFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusNotFound, `{}`), nil
	}))
	observation, err = missing.ObserveExactPullRequest(context.Background(), plan)
	if !errors.Is(err, ErrObservationUnavailable) || observation.Status != ObservationUnavailable {
		t.Fatalf("invisible repository misclassified: %#v %v", observation, err)
	}
}

func observerWithCandidates(t *testing.T, plan *Plan, candidates []apiPullRequest) *HTTPClient {
	t.Helper()
	client, err := NewHTTPClientForDoer("secret", doerFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/repos/owner/repo" {
			return response(http.StatusOK, `{"id":42,"full_name":"owner/repo"}`), nil
		}
		return jsonResponse(t, candidates), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func exactAPIPullRequest(plan *Plan) apiPullRequest {
	var candidate apiPullRequest
	candidate.Number = 17
	candidate.ID = 1700
	candidate.HTMLURL = "https://github.com/owner/repo/pull/17"
	candidate.State = "open"
	candidate.Title = plan.Metadata().Title()
	candidate.Body = plan.Metadata().Body()
	candidate.Head.Ref = "mirage/run-123456789012345678901234"
	candidate.Head.SHA = plan.CommitOID()
	candidate.Head.Repo = apiRepository{ID: plan.RepositoryID(), FullName: plan.RepositoryFullName()}
	candidate.Base.Ref = "main"
	candidate.Base.Repo = apiRepository{ID: plan.RepositoryID(), FullName: plan.RepositoryFullName()}
	return candidate
}

func mutateCandidate(candidate apiPullRequest, mutate func(*apiPullRequest)) apiPullRequest {
	mutate(&candidate)
	return candidate
}

func jsonResponse(t *testing.T, value any) *http.Response {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return response(http.StatusOK, string(encoded))
}

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}
