package githubpullrequest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/gitrefs"
)

const (
	apiOrigin           = "https://api.github.com"
	apiVersion          = "2026-03-10"
	maxResponseBytes    = 1 << 20
	pullRequestsPerPage = 50
	maxPullRequestPages = 2
)

var ErrObservationUnavailable = errors.New("GitHub pull-request observation unavailable")

type Observer interface {
	ObserveExactPullRequest(context.Context, *Plan) (Observation, error)
}

type HTTPClient struct {
	token string
	doer  interface {
		Do(*http.Request) (*http.Response, error)
	}
}

func NewHTTPClient(token string) (*HTTPClient, error) {
	if strings.TrimSpace(token) == "" || token != strings.TrimSpace(token) {
		return nil, fmt.Errorf("%w: dedicated host credential is unavailable", ErrObservationUnavailable)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ResponseHeaderTimeout = 10 * time.Second
	transport.ExpectContinueTimeout = time.Second
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("GitHub redirects are forbidden") }}
	return &HTTPClient{token: token, doer: client}, nil
}

// NewHTTPClientForDoer preserves the fixed origin and semantic validation while
// allowing deterministic tests to replace network transport.
func NewHTTPClientForDoer(token string, doer interface {
	Do(*http.Request) (*http.Response, error)
}) (*HTTPClient, error) {
	if strings.TrimSpace(token) == "" || token != strings.TrimSpace(token) || doer == nil {
		return nil, fmt.Errorf("%w: credential and transport are required", ErrObservationUnavailable)
	}
	return &HTTPClient{token: token, doer: doer}, nil
}

type apiRepository struct {
	ID       int64  `json:"id"`
	FullName string `json:"full_name"`
}

type apiPullRequest struct {
	Number  int64  `json:"number"`
	ID      int64  `json:"id"`
	HTMLURL string `json:"html_url"`
	State   string `json:"state"`
	Draft   bool   `json:"draft"`
	Title   string `json:"title"`
	Body    string `json:"body"`
	Head    struct {
		Ref  string        `json:"ref"`
		SHA  string        `json:"sha"`
		Repo apiRepository `json:"repo"`
	} `json:"head"`
	Base struct {
		Ref  string        `json:"ref"`
		Repo apiRepository `json:"repo"`
	} `json:"base"`
}

func (c *HTTPClient) ObserveExactPullRequest(ctx context.Context, plan *Plan) (Observation, error) {
	if c == nil || c.doer == nil || c.token == "" || plan == nil || plan.Metadata() == nil {
		return Observation{Status: ObservationUnavailable}, ErrObservationUnavailable
	}
	canonicalRepository, err := contracts.CanonicalGitHubRepository(plan.RepositoryFullName())
	if err != nil || canonicalRepository != plan.RepositoryFullName() || plan.RepositoryID() <= 0 {
		return Observation{Status: ObservationUnavailable}, fmt.Errorf("%w: invalid repository authority", ErrObservationUnavailable)
	}
	baseBranch, baseOK := gitrefs.BranchName(plan.BaseRef())
	headBranch, headOK := gitrefs.BranchName(plan.TargetRef())
	owner, _, ownerOK := strings.Cut(canonicalRepository, "/")
	if !baseOK || !headOK || !ownerOK || baseBranch == headBranch || !validOID(plan.CommitOID()) {
		return Observation{Status: ObservationUnavailable}, fmt.Errorf("%w: invalid ref authority", ErrObservationUnavailable)
	}
	repository, err := c.observeRepository(ctx, canonicalRepository)
	observedName, nameErr := contracts.CanonicalGitHubRepository(repository.FullName)
	if err != nil || nameErr != nil || observedName != canonicalRepository || repository.ID != plan.RepositoryID() {
		return Observation{Status: ObservationUnavailable}, fmt.Errorf("%w: repository identity could not be proven", ErrObservationUnavailable)
	}

	var candidates []apiPullRequest
	for page := 1; page <= maxPullRequestPages; page++ {
		query := url.Values{}
		query.Set("state", "all")
		query.Set("head", owner+":"+headBranch)
		query.Set("base", baseBranch)
		query.Set("per_page", strconv.Itoa(pullRequestsPerPage))
		query.Set("page", strconv.Itoa(page))
		body, status, header, requestErr := c.get(ctx, "/repos/"+canonicalRepository+"/pulls?"+query.Encode())
		if requestErr != nil || status != http.StatusOK {
			return Observation{Status: ObservationUnavailable}, fmt.Errorf("%w: pull-request query failed", ErrObservationUnavailable)
		}
		var pageCandidates []apiPullRequest
		if err := json.Unmarshal(body, &pageCandidates); err != nil || len(pageCandidates) > pullRequestsPerPage {
			return Observation{Status: ObservationUnavailable}, fmt.Errorf("%w: malformed pull-request response", ErrObservationUnavailable)
		}
		candidates = append(candidates, pageCandidates...)
		hasNext := len(pageCandidates) == pullRequestsPerPage || strings.Contains(header.Get("Link"), `rel="next"`)
		if !hasNext {
			return classifyPullRequests(plan, baseBranch, headBranch, candidates)
		}
		if page == maxPullRequestPages {
			return Observation{Status: ObservationUnavailable}, fmt.Errorf("%w: bounded pagination incomplete", ErrObservationUnavailable)
		}
	}
	return Observation{Status: ObservationUnavailable}, ErrObservationUnavailable
}

func classifyPullRequests(plan *Plan, baseBranch, headBranch string, candidates []apiPullRequest) (Observation, error) {
	if len(candidates) == 0 {
		return Observation{Status: ObservationAbsent}, nil
	}
	if len(candidates) != 1 {
		return Observation{Status: ObservationConflicting, Evidence: "duplicate_candidates"}, nil
	}
	candidate := candidates[0]
	if candidate.Number <= 0 || candidate.ID <= 0 || candidate.HTMLURL == "" || candidate.Head.Repo.ID <= 0 || candidate.Base.Repo.ID <= 0 || candidate.Head.Repo.FullName == "" || candidate.Base.Repo.FullName == "" || !validOID(candidate.Head.SHA) {
		return Observation{Status: ObservationUnavailable}, fmt.Errorf("%w: incomplete pull-request identity", ErrObservationUnavailable)
	}
	headName, headNameErr := contracts.CanonicalGitHubRepository(candidate.Head.Repo.FullName)
	baseName, baseNameErr := contracts.CanonicalGitHubRepository(candidate.Base.Repo.FullName)
	if headNameErr != nil || baseNameErr != nil {
		return Observation{Status: ObservationUnavailable}, fmt.Errorf("%w: malformed PR repository identity", ErrObservationUnavailable)
	}
	if candidate.Head.Repo.ID != plan.RepositoryID() || candidate.Base.Repo.ID != plan.RepositoryID() || headName != plan.RepositoryFullName() || baseName != plan.RepositoryFullName() {
		return Observation{Status: ObservationConflicting, Evidence: "fork_or_repository_mismatch"}, nil
	}
	if candidate.Head.Ref != headBranch || candidate.Base.Ref != baseBranch || candidate.Head.SHA != plan.CommitOID() {
		return Observation{Status: ObservationConflicting, Evidence: "ref_or_oid_mismatch"}, nil
	}
	if candidate.State != "open" || candidate.Draft {
		return Observation{Status: ObservationConflicting, Evidence: "closed_or_draft"}, nil
	}
	if candidate.Title != plan.Metadata().Title() || candidate.Body != plan.Metadata().Body() {
		return Observation{Status: ObservationConflicting, Evidence: "metadata_mismatch"}, nil
	}
	identity, err := NewPullRequestIdentity(PullRequestIdentitySpec{Plan: plan, Number: candidate.Number, StableID: candidate.ID, URL: candidate.HTMLURL, RepositoryID: candidate.Base.Repo.ID, RepositoryFullName: baseName, BaseRef: plan.BaseRef(), TargetRef: plan.TargetRef(), HeadOID: candidate.Head.SHA, MetadataPolicy: plan.Metadata().Version(), Title: candidate.Title, Body: candidate.Body, Draft: candidate.Draft, Open: candidate.State == "open"})
	if err != nil {
		return Observation{Status: ObservationUnavailable}, fmt.Errorf("%w: invalid exact PR identity", ErrObservationUnavailable)
	}
	return Observation{Status: ObservationExact, Exact: identity}, nil
}

func (c *HTTPClient) observeRepository(ctx context.Context, fullName string) (apiRepository, error) {
	body, status, _, err := c.get(ctx, "/repos/"+fullName)
	if err != nil || status != http.StatusOK {
		return apiRepository{}, ErrObservationUnavailable
	}
	var repository apiRepository
	if err := json.Unmarshal(body, &repository); err != nil || repository.ID <= 0 || repository.FullName == "" {
		return apiRepository{}, ErrObservationUnavailable
	}
	return repository, nil
}

func (c *HTTPClient) get(ctx context.Context, path string) ([]byte, int, http.Header, error) {
	if c == nil || c.doer == nil || c.token == "" || !strings.HasPrefix(path, "/repos/") {
		return nil, 0, nil, ErrObservationUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, apiOrigin+path, nil)
	if err != nil {
		return nil, 0, nil, ErrObservationUnavailable
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("X-GitHub-Api-Version", apiVersion)
	response, err := c.doer.Do(request)
	if err != nil {
		return nil, 0, nil, ErrObservationUnavailable
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) > maxResponseBytes {
		return nil, response.StatusCode, nil, ErrObservationUnavailable
	}
	return body, response.StatusCode, response.Header.Clone(), nil
}
