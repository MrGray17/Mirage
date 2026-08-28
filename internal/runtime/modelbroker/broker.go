// Package modelbroker exposes one bounded model API capability to a hostile
// coding-agent sandbox without placing provider credentials or general network
// access inside that sandbox.
package modelbroker

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/MrGray17/Mirage/internal/runtime/diagnostics"
)

const (
	SocketName               = "model.sock"
	DeepSeekV4Flash          = "deepseek-v4-flash"
	openAIResponsesURL       = "https://api.openai.com/v1/responses"
	deepSeekResponsesURL     = "https://api.deepseek.com/responses"
	defaultMaxRequests       = 64
	defaultMaxConcurrent     = 4
	defaultMaxRequestBytes   = int64(4 << 20)
	defaultMaxResponseBytes  = int64(16 << 20)
	defaultMaxOutputTokens   = 32768
	defaultUpstreamTimeout   = 5 * time.Minute
	defaultReadHeaderTimeout = 5 * time.Second
)

var (
	ErrInvalidConfig = errors.New("invalid model broker config")
	ErrLimit         = errors.New("model broker limit exceeded")
	ErrCleanup       = errors.New("model broker cleanup failed")
)

// Config is trusted control-plane policy. APIKey is intentionally excluded
// from Identity and is never written to the broker directory or sandbox.
type Config struct {
	APIKey           string
	Model            string
	RunID            string
	TempRoot         string
	MaxRequests      int
	MaxConcurrent    int
	MaxRequestBytes  int64
	MaxResponseBytes int64
	MaxOutputTokens  int
}

type Broker struct {
	mu                   sync.Mutex
	config               Config
	identity             string
	directory            string
	listener             net.Listener
	server               *http.Server
	client               *http.Client
	upstream             *url.URL
	requests             int
	inFlight             int
	diagnostic           diagnostics.Record
	successfulResponses  int
	preflightConnections int
	started              bool
	closed               bool
}

type DiagnosticSnapshot struct {
	Failure              diagnostics.Record
	Requests             int
	SuccessfulResponses  int
	PreflightConnections int
}

func NewOpenAI(config Config) (*Broker, error) {
	return newResponses(config, "openai-responses", nil, openAIResponsesURL)
}

// NewDeepSeek creates the one M4.4 provider accepted for the live coding-agent
// proof. It fails closed rather than allowing a silent model substitution.
func NewDeepSeek(config Config) (*Broker, error) {
	if strings.TrimSpace(config.Model) != DeepSeekV4Flash {
		return nil, fmt.Errorf("%w: DeepSeek model must be exactly %s", ErrInvalidConfig, DeepSeekV4Flash)
	}
	return newResponses(config, "deepseek-responses", nil, deepSeekResponsesURL)
}

func newResponses(config Config, provider string, client *http.Client, upstream string) (*Broker, error) {
	config.APIKey = strings.TrimSpace(config.APIKey)
	config.Model = strings.TrimSpace(config.Model)
	config.RunID = strings.TrimSpace(config.RunID)
	provider = strings.TrimSpace(provider)
	if config.APIKey == "" || config.Model == "" || config.RunID == "" || provider == "" || len(config.Model) > 256 || len(config.RunID) > 256 || len(provider) > 256 {
		return nil, fmt.Errorf("%w: provider, API key, model, and run ID are required", ErrInvalidConfig)
	}
	if strings.ContainsAny(provider+config.Model+config.RunID, "\x00\r\n") {
		return nil, fmt.Errorf("%w: provider, model, or run ID contains control characters", ErrInvalidConfig)
	}
	if config.MaxRequests == 0 {
		config.MaxRequests = defaultMaxRequests
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = defaultMaxConcurrent
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = defaultMaxRequestBytes
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultMaxResponseBytes
	}
	if config.MaxOutputTokens == 0 {
		config.MaxOutputTokens = defaultMaxOutputTokens
	}
	if config.MaxRequests < 1 || config.MaxRequests > 256 || config.MaxConcurrent < 1 || config.MaxConcurrent > 8 || config.MaxRequestBytes < 1 || config.MaxRequestBytes > 16<<20 || config.MaxResponseBytes < 1 || config.MaxResponseBytes > 64<<20 || config.MaxOutputTokens < 1 || config.MaxOutputTokens > 131072 {
		return nil, fmt.Errorf("%w: broker limits are outside M4.4 bounds", ErrInvalidConfig)
	}
	if config.TempRoot == "" {
		config.TempRoot = os.TempDir()
	}
	tempRoot, err := filepath.Abs(config.TempRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve temporary root: %w", ErrInvalidConfig, err)
	}
	info, err := os.Lstat(tempRoot)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.Join(fmt.Errorf("%w: temporary root is unsafe", ErrInvalidConfig), err)
	}
	config.TempRoot = filepath.Clean(tempRoot)
	upstreamURL, err := url.Parse(upstream)
	if err != nil || upstreamURL.Scheme != "https" || upstreamURL.Host == "" || upstreamURL.User != nil || upstreamURL.RawQuery != "" || upstreamURL.Fragment != "" {
		return nil, fmt.Errorf("%w: upstream URL is unsafe", ErrInvalidConfig)
	}
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		client = &http.Client{
			Transport: transport,
			Timeout:   defaultUpstreamTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("model broker refuses upstream redirects")
			},
		}
	}
	canonical := struct {
		Version          string `json:"version"`
		Provider         string `json:"provider"`
		Endpoint         string `json:"endpoint"`
		Model            string `json:"model"`
		RunID            string `json:"run_id"`
		MaxRequests      int    `json:"max_requests"`
		MaxConcurrent    int    `json:"max_concurrent"`
		MaxRequestBytes  int64  `json:"max_request_bytes"`
		MaxResponseBytes int64  `json:"max_response_bytes"`
		MaxOutputTokens  int    `json:"max_output_tokens"`
	}{
		Version:          "mirage.model-broker/v1",
		Provider:         provider,
		Endpoint:         upstreamURL.String(),
		Model:            config.Model,
		RunID:            config.RunID,
		MaxRequests:      config.MaxRequests,
		MaxConcurrent:    config.MaxConcurrent,
		MaxRequestBytes:  config.MaxRequestBytes,
		MaxResponseBytes: config.MaxResponseBytes,
		MaxOutputTokens:  config.MaxOutputTokens,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize policy: %w", ErrInvalidConfig, err)
	}
	digest := sha256.Sum256(encoded)
	return &Broker{
		config:   config,
		identity: fmt.Sprintf("sha256:%x", digest),
		client:   client,
		upstream: upstreamURL,
	}, nil
}

func (b *Broker) Identity() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.identity
}

func (b *Broker) Directory() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.directory
}

func (b *Broker) Diagnostics() DiagnosticSnapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	return DiagnosticSnapshot{
		Failure:              b.diagnostic,
		Requests:             b.requests,
		SuccessfulResponses:  b.successfulResponses,
		PreflightConnections: b.preflightConnections,
	}
}

func (b *Broker) Start() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.started || b.closed || b.listener != nil || b.directory != "" {
		return fmt.Errorf("%w: broker has already been used", ErrInvalidConfig)
	}
	directory, err := os.MkdirTemp(b.config.TempRoot, "mirage-m44-broker-")
	if err != nil {
		return fmt.Errorf("create protected broker directory: %w", err)
	}
	fail := func(cause error) error {
		return errors.Join(cause, removeDirectory(directory))
	}
	// The trusted host owner retains rwx. The remapped non-root sandbox gets
	// execute-only traversal to the known socket path: no listing or writes.
	if err := os.Chmod(directory, 0o711); err != nil {
		return fail(fmt.Errorf("protect broker directory: %w", err))
	}
	socket := filepath.Join(directory, SocketName)
	// Linux sockaddr_un.sun_path is 108 bytes including its terminator. Check
	// before Listen so an unsuitable temporary root fails with a structured
	// configuration error rather than a platform-dependent bind failure.
	if len(socket) >= 108 {
		return fail(fmt.Errorf("%w: broker socket path is too long", ErrInvalidConfig))
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return fail(fmt.Errorf("listen on model broker socket: %w", err))
	}
	if err := os.Chmod(socket, 0o666); err != nil {
		_ = listener.Close()
		return fail(fmt.Errorf("make broker socket reachable by remapped sandbox user: %w", err))
	}
	b.directory = directory
	b.listener = listener
	b.server = &http.Server{
		Handler:           http.HandlerFunc(b.handle),
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		MaxHeaderBytes:    16 << 10,
	}
	b.started = true
	server := b.server
	go func() {
		_ = server.Serve(listener)
	}()
	return nil
}

func (b *Broker) Close(ctx context.Context) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	server := b.server
	listener := b.listener
	directory := b.directory
	b.mu.Unlock()

	var result error
	if server != nil {
		if err := server.Shutdown(ctx); err != nil {
			result = errors.Join(result, fmt.Errorf("%w: stop HTTP server: %v", ErrCleanup, err))
		}
	} else if listener != nil {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, fmt.Errorf("%w: close listener: %v", ErrCleanup, err))
		}
	}
	if directory != "" {
		if err := removeDirectory(directory); err != nil {
			result = errors.Join(result, fmt.Errorf("%w: %v", ErrCleanup, err))
		}
	}
	if result == nil {
		b.mu.Lock()
		b.listener = nil
		b.server = nil
		b.directory = ""
		b.mu.Unlock()
	}
	return result
}

func (b *Broker) handle(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet && request.URL.Path == "/_mirage/broker-preflight" && request.URL.RawQuery == "" {
		b.mu.Lock()
		b.preflightConnections++
		b.mu.Unlock()
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if request.Method != http.MethodPost || request.URL.Path != "/v1/responses" || request.URL.RawQuery != "" {
		http.Error(writer, "model broker endpoint denied", http.StatusNotFound)
		return
	}
	if !strings.HasPrefix(strings.ToLower(request.Header.Get("Content-Type")), "application/json") {
		http.Error(writer, "application/json required", http.StatusUnsupportedMediaType)
		return
	}
	b.mu.Lock()
	if b.requests >= b.config.MaxRequests || b.inFlight >= b.config.MaxConcurrent {
		b.mu.Unlock()
		http.Error(writer, ErrLimit.Error(), http.StatusTooManyRequests)
		return
	}
	b.requests++
	b.inFlight++
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		b.inFlight--
		b.mu.Unlock()
	}()

	body, err := io.ReadAll(io.LimitReader(request.Body, b.config.MaxRequestBytes+1))
	if err != nil || int64(len(body)) > b.config.MaxRequestBytes {
		http.Error(writer, ErrLimit.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		http.Error(writer, "model broker policy mismatch", http.StatusForbidden)
		return
	}
	var requestedModel string
	if err := json.Unmarshal(envelope["model"], &requestedModel); err != nil || requestedModel != b.config.Model {
		http.Error(writer, "model broker policy mismatch", http.StatusForbidden)
		return
	}
	var requestedOutputTokens int
	if raw, ok := envelope["max_output_tokens"]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &requestedOutputTokens); err != nil || requestedOutputTokens < 1 {
			http.Error(writer, "model broker output budget is invalid", http.StatusForbidden)
			return
		}
	}
	if requestedOutputTokens == 0 || requestedOutputTokens > b.config.MaxOutputTokens {
		envelope["max_output_tokens"] = json.RawMessage(fmt.Sprintf("%d", b.config.MaxOutputTokens))
	}
	boundedBody, err := json.Marshal(envelope)
	if err != nil {
		http.Error(writer, "model broker request failed", http.StatusBadGateway)
		return
	}
	upstreamRequest, err := http.NewRequestWithContext(request.Context(), http.MethodPost, b.upstream.String(), strings.NewReader(string(boundedBody)))
	if err != nil {
		http.Error(writer, "model broker request failed", http.StatusBadGateway)
		return
	}
	upstreamRequest.Header.Set("Authorization", "Bearer "+b.config.APIKey)
	upstreamRequest.Header.Set("Content-Type", "application/json")
	upstreamRequest.Header.Set("Accept", request.Header.Get("Accept"))
	upstreamRequest.Header.Set("X-Client-Request-Id", b.config.RunID)
	response, err := b.client.Do(upstreamRequest)
	if err != nil {
		b.recordFailure(diagnostics.Record{Class: diagnostics.BrokerConnect, Stage: "provider_connect", Message: err.Error()})
		http.Error(writer, "model broker upstream unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, b.config.MaxResponseBytes+1))
	if err != nil {
		b.recordFailure(diagnostics.Record{Class: diagnostics.BrokerConnect, Stage: "provider_read", ProviderStatus: response.StatusCode, Message: err.Error()})
		http.Error(writer, "model broker upstream unavailable", http.StatusBadGateway)
		return
	}
	if int64(len(responseBody)) > b.config.MaxResponseBytes {
		b.recordFailure(diagnostics.Record{Class: diagnostics.ProviderSchema, Stage: "provider_response_limit", ProviderStatus: response.StatusCode, Message: "provider response exceeded the trusted byte cap"})
		http.Error(writer, "provider response failed trusted validation", http.StatusBadGateway)
		return
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		b.recordFailure(diagnostics.Record{Class: diagnostics.ProviderHTTP, Stage: "provider_status", ProviderStatus: response.StatusCode, Message: http.StatusText(response.StatusCode)})
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(response.StatusCode)
		_, _ = writer.Write([]byte(`{"error":{"message":"provider request failed","type":"provider_http"}}`))
		return
	}
	contentType := response.Header.Get("Content-Type")
	if !validResponsesPayload(contentType, responseBody) {
		b.recordFailure(diagnostics.Record{Class: diagnostics.ProviderSchema, Stage: "provider_schema", ProviderStatus: response.StatusCode, Message: "provider returned a malformed Responses payload"})
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusBadGateway)
		_, _ = writer.Write([]byte(`{"error":{"message":"provider response failed trusted validation","type":"provider_schema"}}`))
		return
	}
	b.recordSuccess()
	if contentType != "" {
		writer.Header().Set("Content-Type", contentType)
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(response.StatusCode)
	_, _ = writer.Write(responseBody)
}

func (b *Broker) recordFailure(record diagnostics.Record) {
	record = diagnostics.SanitizeRecord(record, 4<<10, b.config.APIKey)
	b.mu.Lock()
	b.diagnostic = record
	b.mu.Unlock()
}

func (b *Broker) recordSuccess() {
	b.mu.Lock()
	b.successfulResponses++
	b.mu.Unlock()
}

func validResponsesPayload(contentType string, body []byte) bool {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return false
	}
	if strings.Contains(strings.ToLower(contentType), "text/event-stream") || strings.HasPrefix(trimmed, "data:") || strings.HasPrefix(trimmed, "event:") {
		validEvents := 0
		for _, line := range strings.Split(trimmed, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if payload == "[DONE]" {
				continue
			}
			if !json.Valid([]byte(payload)) {
				return false
			}
			validEvents++
		}
		return validEvents > 0
	}
	var envelope map[string]json.RawMessage
	return json.Unmarshal(body, &envelope) == nil && envelope != nil
}

func removeDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !strings.HasPrefix(filepath.Base(directory), "mirage-m44-broker-") {
		return errors.New("refuse unsafe broker cleanup target")
	}
	return os.RemoveAll(directory)
}
