// Package githubbinding captures and revalidates the exact github.com
// repository identity authorized for one MIRAGE lifecycle. It performs only
// bounded read-only observation; it cannot mutate GitHub.
package githubbinding

import (
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
	"strings"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
)

const (
	Version          = "mirage.github-repository-binding/v1"
	Provider         = "github.com"
	apiOrigin        = "https://api.github.com"
	apiVersion       = "2026-03-10"
	maxResponseBytes = 1 << 20
	maxRepositoryID  = int64(^uint64(0) >> 1)
	maxReferenceSize = 1024
)

var (
	ErrInvalidBinding    = errors.New("invalid GitHub repository binding")
	ErrRepositoryChanged = errors.New("GitHub repository identity changed")
	ErrUnavailable       = errors.New("GitHub repository state unavailable")
)

type Repository struct {
	ID       int64
	FullName string
}

type RefStatus string

const (
	RefAbsent       RefStatus = "ABSENT"
	RefPresentExact RefStatus = "PRESENT_EXACT"
	RefPresentOther RefStatus = "PRESENT_OTHER"
	RefUnavailable  RefStatus = "UNAVAILABLE"
)

type RefObservation struct {
	Status RefStatus
	OID    string
}

// Client is intentionally narrow and read-only.
type Client interface {
	Repository(context.Context, string) (Repository, error)
	ExactRef(context.Context, string, int64, string, string) (RefObservation, error)
}

type Binding struct {
	version      string
	identity     string
	provider     string
	fullName     string
	repositoryID int64
	contractHash string
	manifestHash string
	baseRef      string
	baseCommit   string
	capturedAt   time.Time
}

func Capture(ctx context.Context, client Client, fullName, contractHash, manifestHash, baseRef, baseCommit string, at time.Time) (*Binding, error) {
	canonical, err := contracts.CanonicalGitHubRepository(fullName)
	if err != nil || client == nil || contractHash == "" || manifestHash == "" || !validBranchRef(baseRef) || !validOID(baseCommit) || at.IsZero() {
		return nil, errors.Join(ErrInvalidBinding, err)
	}
	repository, err := client.Repository(ctx, canonical)
	if err != nil {
		return nil, fmt.Errorf("%w: repository observation failed", ErrUnavailable)
	}
	observedName, err := contracts.CanonicalGitHubRepository(repository.FullName)
	if err != nil || observedName != canonical || repository.ID <= 0 || repository.ID > maxRepositoryID {
		return nil, fmt.Errorf("%w: GitHub returned a different repository identity", ErrRepositoryChanged)
	}
	if err := requireExactBase(ctx, client, canonical, repository.ID, baseRef, baseCommit); err != nil {
		return nil, err
	}
	canonicalBinding := canonicalBinding{Version: Version, Provider: Provider, FullName: canonical, RepositoryID: repository.ID, ContractHash: contractHash, ManifestHash: manifestHash, BaseRef: baseRef, BaseCommit: baseCommit, CapturedAt: at.UTC().Format(time.RFC3339Nano)}
	identity, err := hashCanonical(canonicalBinding)
	if err != nil {
		return nil, err
	}
	return &Binding{version: Version, identity: identity, provider: Provider, fullName: canonical, repositoryID: repository.ID, contractHash: contractHash, manifestHash: manifestHash, baseRef: baseRef, baseCommit: baseCommit, capturedAt: at.UTC()}, nil
}

func (b *Binding) Revalidate(ctx context.Context, client Client, contractHash, manifestHash string) error {
	if b == nil || client == nil || b.identity == "" || contractHash != b.contractHash || manifestHash != b.manifestHash {
		return fmt.Errorf("%w: binding authority differs", ErrInvalidBinding)
	}
	repository, err := client.Repository(ctx, b.fullName)
	if err != nil {
		return fmt.Errorf("%w: repository observation failed", ErrUnavailable)
	}
	name, nameErr := contracts.CanonicalGitHubRepository(repository.FullName)
	if nameErr != nil || name != b.fullName || repository.ID != b.repositoryID {
		return fmt.Errorf("%w: expected %s/%d", ErrRepositoryChanged, b.fullName, b.repositoryID)
	}
	if err := requireExactBase(ctx, client, b.fullName, b.repositoryID, b.baseRef, b.baseCommit); err != nil {
		return err
	}
	identity, err := hashCanonical(canonicalBinding{Version: b.version, Provider: b.provider, FullName: b.fullName, RepositoryID: b.repositoryID, ContractHash: b.contractHash, ManifestHash: b.manifestHash, BaseRef: b.baseRef, BaseCommit: b.baseCommit, CapturedAt: b.capturedAt.Format(time.RFC3339Nano)})
	if err != nil || identity != b.identity {
		return fmt.Errorf("%w: canonical binding identity differs", ErrInvalidBinding)
	}
	return nil
}

func (b *Binding) Identity() string { return bindingValue(b, func() string { return b.identity }) }
func (b *Binding) Provider() string { return bindingValue(b, func() string { return b.provider }) }
func (b *Binding) FullName() string { return bindingValue(b, func() string { return b.fullName }) }
func (b *Binding) ContractHash() string {
	return bindingValue(b, func() string { return b.contractHash })
}
func (b *Binding) ManifestHash() string {
	return bindingValue(b, func() string { return b.manifestHash })
}
func (b *Binding) BaseRef() string { return bindingValue(b, func() string { return b.baseRef }) }
func (b *Binding) BaseCommit() string {
	return bindingValue(b, func() string { return b.baseCommit })
}
func (b *Binding) RepositoryID() int64 {
	if b == nil {
		return 0
	}
	return b.repositoryID
}
func (b *Binding) CapturedAt() time.Time {
	if b == nil {
		return time.Time{}
	}
	return b.capturedAt
}

func bindingValue(b *Binding, getter func() string) string {
	if b == nil {
		return ""
	}
	return getter()
}

type canonicalBinding struct {
	Version      string `json:"version"`
	Provider     string `json:"provider"`
	FullName     string `json:"repository_full_name"`
	RepositoryID int64  `json:"repository_id"`
	ContractHash string `json:"contract_hash"`
	ManifestHash string `json:"manifest_hash"`
	BaseRef      string `json:"base_ref"`
	BaseCommit   string `json:"base_commit"`
	CapturedAt   string `json:"captured_at"`
}

func requireExactBase(ctx context.Context, client Client, fullName string, repositoryID int64, baseRef, baseCommit string) error {
	observation, err := client.ExactRef(ctx, fullName, repositoryID, baseRef, baseCommit)
	if err != nil || observation.Status == RefUnavailable {
		return fmt.Errorf("%w: remote base observation failed", ErrUnavailable)
	}
	if observation.Status != RefPresentExact || observation.OID != baseCommit {
		return fmt.Errorf("%w: remote base %s does not equal bound commit", ErrRepositoryChanged, observation.Status)
	}
	return nil
}

func hashCanonical(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("%w: canonicalize: %v", ErrInvalidBinding, err)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// HTTPClient is fixed to api.github.com, refuses redirects, bounds every
// response, and exposes no generic request method.
type HTTPClient struct {
	token string
	doer  interface {
		Do(*http.Request) (*http.Response, error)
	}
}

func NewHTTPClient(token string) (*HTTPClient, error) {
	if strings.TrimSpace(token) == "" || token != strings.TrimSpace(token) {
		return nil, fmt.Errorf("%w: dedicated host credential is unavailable", ErrUnavailable)
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

// NewHTTPClientForDoer is test infrastructure: requests still target the fixed
// GitHub origin, while a deterministic doer supplies responses without network.
func NewHTTPClientForDoer(token string, doer interface {
	Do(*http.Request) (*http.Response, error)
}) (*HTTPClient, error) {
	if strings.TrimSpace(token) == "" || doer == nil {
		return nil, fmt.Errorf("%w: credential and transport are required", ErrUnavailable)
	}
	return &HTTPClient{token: token, doer: doer}, nil
}

func (c *HTTPClient) Repository(ctx context.Context, fullName string) (Repository, error) {
	canonical, err := contracts.CanonicalGitHubRepository(fullName)
	if err != nil {
		return Repository{}, err
	}
	body, status, err := c.get(ctx, "/repos/"+canonical)
	if err != nil {
		return Repository{}, err
	}
	if status != http.StatusOK {
		return Repository{}, fmt.Errorf("unexpected GitHub repository status %d", status)
	}
	var response struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
	}
	if err := json.Unmarshal(body, &response); err != nil || response.FullName == "" || response.ID <= 0 {
		return Repository{}, errors.New("malformed GitHub repository response")
	}
	return Repository{ID: response.ID, FullName: response.FullName}, nil
}

func (c *HTTPClient) ExactRef(ctx context.Context, fullName string, repositoryID int64, targetRef, expectedOID string) (RefObservation, error) {
	canonical, err := contracts.CanonicalGitHubRepository(fullName)
	if err != nil || repositoryID <= 0 || !strings.HasPrefix(targetRef, "refs/") || !validOID(expectedOID) {
		return RefObservation{}, errors.New("invalid exact-ref query")
	}
	repository, err := c.Repository(ctx, canonical)
	observedName, nameErr := contracts.CanonicalGitHubRepository(repository.FullName)
	if err != nil || nameErr != nil || observedName != canonical || repository.ID != repositoryID {
		return RefObservation{Status: RefUnavailable}, errors.New("GitHub repository binding unavailable")
	}
	refSuffix := strings.TrimPrefix(targetRef, "refs/")
	parts := strings.Split(refSuffix, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	body, status, err := c.get(ctx, "/repos/"+canonical+"/git/ref/"+strings.Join(parts, "/"))
	if err != nil {
		return RefObservation{Status: RefUnavailable}, err
	}
	if status == http.StatusNotFound {
		return RefObservation{Status: RefAbsent}, nil
	}
	if status != http.StatusOK {
		return RefObservation{Status: RefUnavailable}, fmt.Errorf("unexpected GitHub ref status %d", status)
	}
	var response struct {
		Ref    string `json:"ref"`
		Object struct {
			Type string `json:"type"`
			SHA  string `json:"sha"`
		} `json:"object"`
	}
	if err := json.Unmarshal(body, &response); err != nil || response.Ref != targetRef || response.Object.Type != "commit" || !validOID(response.Object.SHA) {
		return RefObservation{Status: RefUnavailable}, errors.New("malformed GitHub ref response")
	}
	if response.Object.SHA == expectedOID {
		return RefObservation{Status: RefPresentExact, OID: response.Object.SHA}, nil
	}
	return RefObservation{Status: RefPresentOther, OID: response.Object.SHA}, nil
}

func (c *HTTPClient) get(ctx context.Context, path string) ([]byte, int, error) {
	if c == nil || c.doer == nil || c.token == "" || !strings.HasPrefix(path, "/repos/") {
		return nil, 0, errors.New("GitHub client unavailable")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, apiOrigin+path, nil)
	if err != nil {
		return nil, 0, errors.New("construct GitHub request")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("X-GitHub-Api-Version", apiVersion)
	response, err := c.doer.Do(request)
	if err != nil {
		return nil, 0, errors.New("GitHub request unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	closeErr := response.Body.Close()
	if err != nil {
		return nil, response.StatusCode, errors.New("read GitHub response")
	}
	if closeErr != nil {
		return nil, response.StatusCode, errors.New("close GitHub response")
	}
	if len(body) > maxResponseBytes {
		return nil, response.StatusCode, errors.New("GitHub response exceeds bound")
	}
	return body, response.StatusCode, nil
}

func validOID(value string) bool {
	if len(value) != 40 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validBranchRef(ref string) bool {
	if len(ref) <= len("refs/heads/") || len(ref) > maxReferenceSize || !strings.HasPrefix(ref, "refs/heads/") {
		return false
	}
	name := strings.TrimPrefix(ref, "refs/heads/")
	if strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") || strings.Contains(name, "@{") || strings.Contains(name, "//") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	for _, r := range name {
		if r <= 0x20 || r == 0x7f || strings.ContainsRune("~^:?*[\\", r) {
			return false
		}
	}
	return true
}
