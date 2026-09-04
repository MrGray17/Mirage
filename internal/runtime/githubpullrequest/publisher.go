package githubpullrequest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/MrGray17/Mirage/internal/gitrefs"
)

const reconciliationTimeout = 15 * time.Second

var (
	ErrCreateUnavailable = errors.New("GitHub pull-request creation unavailable")
	ErrCreateRejected    = errors.New("GitHub pull-request creation rejected")
)

type FinalAuthority func(context.Context) (*PullRequestAttempt, error)

type EstablishResult struct {
	Preflight                 Observation
	Attempt                   *PullRequestAttempt
	Postflight                Observation
	CompatibleAcknowledgement bool
	Attempted                 bool
}

type Engine struct {
	client *HTTPClient
}

func NewEngine(client *HTTPClient) (*Engine, error) {
	if client == nil || client.doer == nil || client.token == "" {
		return nil, ErrCreateUnavailable
	}
	return &Engine{client: client}, nil
}

// Establish performs one preflight and, only when absent, invokes the
// lifecycle's final-authority callback before entering the unexported POST
// transport exactly once. It always performs synchronous bounded postflight
// after an attempt, even when the caller context was canceled by the POST.
func (e *Engine) Establish(ctx context.Context, plan *Plan, finalAuthority FinalAuthority) (EstablishResult, error) {
	if e == nil || e.client == nil || plan == nil || finalAuthority == nil {
		return EstablishResult{}, ErrCreateUnavailable
	}
	preflight, err := e.client.ObserveExactPullRequest(ctx, plan)
	result := EstablishResult{Preflight: preflight}
	if err != nil {
		return result, err
	}
	switch preflight.Status {
	case ObservationExact, ObservationConflicting:
		return result, nil
	case ObservationAbsent:
		// Continue to exact request preparation and final authority.
	default:
		return result, ErrObservationUnavailable
	}
	requestBytes, err := canonicalRequestBytes(plan)
	if err != nil {
		return result, err
	}
	attempt, err := finalAuthority(ctx)
	if err != nil {
		return result, err
	}
	if err := validateAttemptForDispatch(plan, attempt, requestBytes); err != nil {
		return result, err
	}
	result.Attempt = attempt
	result.Attempted = true
	acknowledged, createErr := e.client.createExactPullRequest(ctx, plan, attempt, requestBytes)
	result.CompatibleAcknowledgement = acknowledged

	// This fresh context is not derived from the caller. Establish remains
	// synchronous under lifecycle ownership; no detached goroutine can outlive
	// the transition lock or publish state after teardown.
	reconcileCtx, cancel := context.WithTimeout(context.Background(), reconciliationTimeout)
	postflight, observeErr := e.client.ObserveExactPullRequest(reconcileCtx, plan)
	cancel()
	result.Postflight = postflight
	return result, errors.Join(createErr, observeErr)
}

// Reconcile is read-only. Callers in the lifecycle use it only after the
// attempt latch exists or to revalidate an established exact PR.
func (e *Engine) Reconcile(ctx context.Context, plan *Plan) (Observation, error) {
	if e == nil || e.client == nil {
		return Observation{Status: ObservationUnavailable}, ErrObservationUnavailable
	}
	return e.client.ObserveExactPullRequest(ctx, plan)
}

func validateAttemptForDispatch(plan *Plan, attempt *PullRequestAttempt, requestBytes []byte) error {
	if plan == nil || attempt == nil || attempt.PlanIdentity() != plan.Identity() || attempt.RepositoryID() != plan.RepositoryID() || attempt.BaseRef() != plan.BaseRef() || attempt.TargetRef() != plan.TargetRef() || attempt.CommitOID() != plan.CommitOID() || attempt.RequestDigest() != bytesDigest(requestBytes) || attempt.TitleDigest() != plan.Metadata().TitleDigest() || attempt.BodyDigest() != plan.Metadata().BodyDigest() || attempt.AuthorityTime().Before(plan.CreatedAt()) {
		return fmt.Errorf("%w: attempt does not authorize the exact request", ErrInvalidAttempt)
	}
	return nil
}

// createExactPullRequest is deliberately unexported. Possession of a plan or
// attempt cannot call the mutation from outside this callback-gated engine.
func (c *HTTPClient) createExactPullRequest(ctx context.Context, plan *Plan, attempt *PullRequestAttempt, requestBytes []byte) (bool, error) {
	if err := validateAttemptForDispatch(plan, attempt, requestBytes); c == nil || c.doer == nil || c.token == "" || err != nil {
		return false, ErrCreateUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, apiOrigin+"/repos/"+plan.RepositoryFullName()+"/pulls", bytes.NewReader(requestBytes))
	if err != nil {
		return false, ErrCreateUnavailable
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("X-GitHub-Api-Version", apiVersion)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.doer.Do(request)
	if err != nil {
		return false, ErrCreateUnavailable
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) > maxResponseBytes {
		return false, ErrCreateUnavailable
	}
	if response.StatusCode != http.StatusCreated {
		return false, fmt.Errorf("%w: provider status %d", ErrCreateRejected, response.StatusCode)
	}
	var candidate apiPullRequest
	if err := json.Unmarshal(body, &candidate); err != nil {
		return false, ErrCreateUnavailable
	}
	base, baseOK := gitrefs.BranchName(plan.BaseRef())
	head, headOK := gitrefs.BranchName(plan.TargetRef())
	if !baseOK || !headOK {
		return false, ErrCreateUnavailable
	}
	observation, classifyErr := classifyPullRequests(plan, base, head, []apiPullRequest{candidate})
	if classifyErr != nil || observation.Status != ObservationExact || observation.Exact == nil {
		return false, ErrCreateUnavailable
	}
	return true, nil
}
