package modelbroker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/runtime/diagnostics"
)

func TestBrokerKeepsProviderCredentialOutsideIdentityAndSocket(t *testing.T) {
	first, err := NewOpenAI(Config{APIKey: "first-secret", Model: "gpt-test", RunID: "run-1"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewOpenAI(Config{APIKey: "second-secret", Model: "gpt-test", RunID: "run-1"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Identity() != second.Identity() {
		t.Fatal("credential material affected the public broker policy identity")
	}
}

func TestDeepSeekRequiresExactApprovedModel(t *testing.T) {
	for _, model := range []string{"", "deepseek-v4-pro", "gpt-5.3-codex", " deepseek-v4-flash-extra "} {
		if _, err := NewDeepSeek(Config{APIKey: "secret", Model: model, RunID: "run-1"}); err == nil || !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("model %q error = %v", model, err)
		}
	}
	if _, err := NewDeepSeek(Config{APIKey: "secret", Model: DeepSeekV4Flash, RunID: "run-1"}); err != nil {
		t.Fatalf("approved model: %v", err)
	}
}

func TestProviderAffectsBrokerPolicyIdentity(t *testing.T) {
	config := Config{APIKey: "secret", Model: DeepSeekV4Flash, RunID: "run-1"}
	openAI, err := newResponses(config, "openai-responses", nil, openAIResponsesURL)
	if err != nil {
		t.Fatal(err)
	}
	deepSeek, err := NewDeepSeek(config)
	if err != nil {
		t.Fatal(err)
	}
	if openAI.Identity() == deepSeek.Identity() {
		t.Fatal("provider did not affect the manifest-bound broker identity")
	}
}

func TestBrokerForwardsOnlyBoundedAuthorizedResponsesRequests(t *testing.T) {
	var upstreamCalls int
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upstreamCalls++
		if got := request.Header.Get("Authorization"); got != "Bearer host-only-secret" {
			t.Errorf("authorization = %q", got)
		}
		if got := request.Header.Get("X-Client-Request-Id"); got != "run-7" {
			t.Errorf("run binding = %q", got)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}
		if strings.Contains(string(body), "host-only-secret") {
			t.Error("provider secret appeared in sandbox request body")
		}
		var bounded struct {
			MaxOutputTokens int `json:"max_output_tokens"`
		}
		if err := json.Unmarshal(body, &bounded); err != nil || bounded.MaxOutputTokens != defaultMaxOutputTokens {
			t.Errorf("trusted output-token cap = %d, %v", bounded.MaxOutputTokens, err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"id":"response-1"}`))
	}))
	defer upstream.Close()
	client := upstream.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	broker, err := newResponses(Config{
		APIKey:      "host-only-secret",
		Model:       "gpt-test",
		RunID:       "run-7",
		TempRoot:    shortTempRoot(t),
		MaxRequests: 1,
	}, "test-responses", client, upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Start(); err != nil {
		t.Fatal(err)
	}
	directory := broker.Directory()
	info, err := os.Lstat(filepath.Join(directory, SocketName))
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("broker socket = %v, %v", info, err)
	}
	sandboxClient := unixHTTPClient(filepath.Join(directory, SocketName))
	response, err := sandboxClient.Post("http://mirage/v1/responses", "application/json", strings.NewReader(`{"model":"gpt-test","input":"edit README"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != `{"id":"response-1"}` {
		t.Fatalf("response = %d %q", response.StatusCode, body)
	}
	response, err = sandboxClient.Post("http://mirage/v1/responses", "application/json", strings.NewReader(`{"model":"gpt-test"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests || upstreamCalls != 1 {
		t.Fatalf("limit response = %d, upstream calls = %d", response.StatusCode, upstreamCalls)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := broker.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		t.Fatalf("broker directory survived cleanup: %v", err)
	}
}

func TestBrokerRejectsPathAndModelWithoutUpstreamCall(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamCalls++ }))
	defer upstream.Close()
	client := upstream.Client()
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // test server only
	broker, err := newResponses(Config{APIKey: "secret", Model: "allowed", RunID: "run", TempRoot: shortTempRoot(t)}, "test-responses", client, upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = broker.Close(context.Background()) }()
	sandboxClient := unixHTTPClient(filepath.Join(broker.Directory(), SocketName))
	for _, request := range []struct {
		path string
		body any
		want int
	}{
		{path: "/v1/models", body: map[string]string{"model": "allowed"}, want: http.StatusNotFound},
		{path: "/v1/responses", body: map[string]string{"model": "denied"}, want: http.StatusForbidden},
	} {
		encoded, _ := json.Marshal(request.body)
		response, err := sandboxClient.Post("http://mirage"+request.path, "application/json", strings.NewReader(string(encoded)))
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != request.want {
			t.Fatalf("%s status = %d, want %d", request.path, response.StatusCode, request.want)
		}
	}
	if upstreamCalls != 0 {
		t.Fatalf("denied requests reached upstream %d times", upstreamCalls)
	}
}

func TestBrokerClassifiesProviderHTTPWithoutForwardingBody(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(status)
				_, _ = writer.Write([]byte(`{"error":"sk-provider-body-secret-123456789"}`))
			}))
			defer upstream.Close()
			broker := testBroker(t, upstream.Client(), upstream.URL)
			response := postBroker(t, broker, `{"model":"allowed"}`)
			body, _ := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if response.StatusCode != status || strings.Contains(string(body), "provider-body-secret") {
				t.Fatalf("response = %d %q", response.StatusCode, body)
			}
			snapshot := broker.Diagnostics()
			if snapshot.Failure.Class != diagnostics.ProviderHTTP || snapshot.Failure.Stage != "provider_status" || snapshot.Failure.ProviderStatus != status {
				t.Fatalf("diagnostic = %#v", snapshot)
			}
		})
	}
}

func TestBrokerClassifiesMalformedAndAcceptsValidResponsesPayloads(t *testing.T) {
	for _, test := range []struct {
		name        string
		contentType string
		body        string
		wantStatus  int
		wantClass   diagnostics.Class
		wantSuccess int
	}{
		{name: "malformed JSON", contentType: "application/json", body: `{"id":`, wantStatus: http.StatusBadGateway, wantClass: diagnostics.ProviderSchema},
		{name: "valid response", contentType: "application/json", body: `{"id":"response-1","object":"response","status":"completed","output":[]}`, wantStatus: http.StatusOK, wantSuccess: 1},
		{name: "valid response stream", contentType: "text/event-stream", body: "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"response-1\"}}\n\ndata: [DONE]\n", wantStatus: http.StatusOK, wantSuccess: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", test.contentType)
				_, _ = writer.Write([]byte(test.body))
			}))
			defer upstream.Close()
			broker := testBroker(t, upstream.Client(), upstream.URL)
			response := postBroker(t, broker, `{"model":"allowed"}`)
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != test.wantStatus {
				t.Fatalf("status = %d", response.StatusCode)
			}
			snapshot := broker.Diagnostics()
			if snapshot.Failure.Class != test.wantClass || snapshot.SuccessfulResponses != test.wantSuccess {
				t.Fatalf("diagnostic = %#v", snapshot)
			}
		})
	}
}

func TestBrokerConnectDiagnosticRedactsSecrets(t *testing.T) {
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connect failed with sk-transport-secret-123456789 and host-only-secret")
	})}
	broker := testBroker(t, client, "https://provider.invalid/responses")
	response := postBroker(t, broker, `{"model":"allowed"}`)
	_ = response.Body.Close()
	snapshot := broker.Diagnostics()
	if snapshot.Failure.Class != diagnostics.BrokerConnect || strings.Contains(snapshot.Failure.Message, "transport-secret") || strings.Contains(snapshot.Failure.Message, "host-only-secret") {
		t.Fatalf("diagnostic = %#v", snapshot)
	}
}

func testBroker(t *testing.T, client *http.Client, upstream string) *Broker {
	t.Helper()
	broker, err := newResponses(Config{APIKey: "host-only-secret", Model: "allowed", RunID: "run", TempRoot: shortTempRoot(t)}, "test-responses", client, upstream)
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close(context.Background()) })
	return broker
}

func postBroker(t *testing.T, broker *Broker, body string) *http.Response {
	t.Helper()
	response, err := unixHTTPClient(filepath.Join(broker.Directory(), SocketName)).Post("http://mirage/v1/responses", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return response
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func unixHTTPClient(socket string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}
}

func shortTempRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "mirage-broker-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove broker test root: %v", err)
		}
	})
	return directory
}
