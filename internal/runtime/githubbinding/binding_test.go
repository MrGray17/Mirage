package githubbinding

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type fakeClient struct {
	repository    Repository
	repositoryErr error
	observation   RefObservation
	refErr        error
}

func (f *fakeClient) Repository(context.Context, string) (Repository, error) {
	return f.repository, f.repositoryErr
}
func (f *fakeClient) ExactRef(context.Context, string, int64, string, string) (RefObservation, error) {
	return f.observation, f.refErr
}

func TestBindingCapturesStableRepositoryIdentityAndRevalidates(t *testing.T) {
	at := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	baseRef := "refs/heads/main"
	baseCommit := "1111111111111111111111111111111111111111"
	client := &fakeClient{repository: Repository{ID: 1729, FullName: "MrGray17/Mirage-Test"}, observation: RefObservation{Status: RefPresentExact, OID: baseCommit}}
	binding, err := Capture(context.Background(), client, "mrgray17/mirage-test", "contract", "manifest", baseRef, baseCommit, at)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Provider() != Provider || binding.FullName() != "mrgray17/mirage-test" || binding.RepositoryID() != 1729 || binding.Identity() == "" || binding.ContractHash() != "contract" || binding.ManifestHash() != "manifest" || binding.BaseRef() != baseRef || binding.BaseCommit() != baseCommit {
		t.Fatalf("binding = %#v", binding)
	}
	if err := binding.Revalidate(context.Background(), client, "contract", "manifest"); err != nil {
		t.Fatal(err)
	}
	client.repository.ID++
	if err := binding.Revalidate(context.Background(), client, "contract", "manifest"); !errors.Is(err, ErrRepositoryChanged) {
		t.Fatalf("identity drift = %v", err)
	}
}

func TestBindingRequiresExactRemoteBase(t *testing.T) {
	at := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	baseRef := "refs/heads/main"
	baseCommit := "1111111111111111111111111111111111111111"
	for _, test := range []struct {
		name        string
		observation RefObservation
		refErr      error
		want        error
	}{
		{name: "absent", observation: RefObservation{Status: RefAbsent}, want: ErrRepositoryChanged},
		{name: "other", observation: RefObservation{Status: RefPresentOther, OID: "2222222222222222222222222222222222222222"}, want: ErrRepositoryChanged},
		{name: "unavailable", observation: RefObservation{Status: RefUnavailable}, refErr: errors.New("unavailable"), want: ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeClient{repository: Repository{ID: 1729, FullName: "owner/repo"}, observation: test.observation, refErr: test.refErr}
			if _, err := Capture(context.Background(), client, "owner/repo", "contract", "manifest", baseRef, baseCommit, at); !errors.Is(err, test.want) {
				t.Fatalf("capture = %v, want %v", err, test.want)
			}
		})
	}
}

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(request *http.Request) (*http.Response, error) { return f(request) }

func TestHTTPClientUsesFixedOriginAndClassifiesExactRefs(t *testing.T) {
	const secret = "m53-distinctive-secret"
	refResponses := []struct {
		status int
		body   string
	}{
		{404, `{}`},
		{200, `{"ref":"refs/heads/mirage/run-aaaaaaaaaaaaaaaaaaaaaaaa","object":{"type":"commit","sha":"1111111111111111111111111111111111111111"}}`},
		{200, `{"ref":"refs/heads/mirage/run-aaaaaaaaaaaaaaaaaaaaaaaa","object":{"type":"commit","sha":"2222222222222222222222222222222222222222"}}`},
	}
	refIndex := 0
	client, err := NewHTTPClientForDoer(secret, doerFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Scheme != "https" || request.URL.Host != "api.github.com" || request.Method != http.MethodGet {
			t.Fatalf("unsafe request %s %s", request.Method, request.URL)
		}
		if request.Header.Get("Authorization") != "Bearer "+secret {
			t.Fatal("dedicated credential missing")
		}
		if request.Header.Get("X-GitHub-Api-Version") != apiVersion {
			t.Fatal("GitHub API version binding missing")
		}
		response := struct {
			status int
			body   string
		}{200, `{"id":1729,"full_name":"MrGray17/Mirage-Test"}`}
		if strings.Contains(request.URL.Path, "/git/ref/") {
			response = refResponses[refIndex]
			refIndex++
		}
		return &http.Response{StatusCode: response.status, Body: io.NopCloser(strings.NewReader(response.body)), Header: make(http.Header)}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	repository, err := client.Repository(context.Background(), "mrgray17/mirage-test")
	if err != nil || repository.ID != 1729 {
		t.Fatalf("repository = %#v, %v", repository, err)
	}
	target := "refs/heads/mirage/run-aaaaaaaaaaaaaaaaaaaaaaaa"
	expected := "1111111111111111111111111111111111111111"
	statuses := []RefStatus{RefAbsent, RefPresentExact, RefPresentOther}
	for _, status := range statuses {
		observation, err := client.ExactRef(context.Background(), "mrgray17/mirage-test", 1729, target, expected)
		if err != nil || observation.Status != status {
			t.Fatalf("observation = %#v, %v, want %s", observation, err, status)
		}
	}
}

func TestExactRefDoesNotMisclassifyInvisibleRepositoryAsAbsent(t *testing.T) {
	client, err := NewHTTPClientForDoer("host-secret", doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := client.ExactRef(context.Background(), "owner/repo", 1729, "refs/heads/mirage/run-aaaaaaaaaaaaaaaaaaaaaaaa", "1111111111111111111111111111111111111111")
	if err == nil || observation.Status != RefUnavailable {
		t.Fatalf("invisible repository = %#v, %v", observation, err)
	}
}

func TestHTTPClientSanitizesFailuresAndRejectsMalformedRef(t *testing.T) {
	const secret = "m53-secret-must-never-leak"
	client, err := NewHTTPClientForDoer(secret, doerFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("transport " + secret) }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Repository(context.Background(), "owner/repo"); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsanitized error = %v", err)
	}
	malformed, _ := NewHTTPClientForDoer(secret, doerFunc(func(request *http.Request) (*http.Response, error) {
		body := `{"id":1729,"full_name":"owner/repo"}`
		if strings.Contains(request.URL.Path, "/git/ref/") {
			body = `{"ref":"wrong","object":{"type":"tag","sha":"bad"}}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	}))
	observation, err := malformed.ExactRef(context.Background(), "owner/repo", 1729, "refs/heads/mirage/run-aaaaaaaaaaaaaaaaaaaaaaaa", "1111111111111111111111111111111111111111")
	if err == nil || observation.Status != RefUnavailable || strings.Contains(err.Error(), secret) {
		t.Fatalf("malformed = %#v, %v", observation, err)
	}
}
