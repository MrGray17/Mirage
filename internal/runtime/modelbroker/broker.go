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
	RequestProfileCodex = "codex-responses-v1"
	RequestProfileQwen  = "qwen-structured-v1"

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
	RequestProfile   string
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
	config.RequestProfile = RequestProfileCodex
	return newResponses(config, "openai-responses", nil, openAIResponsesURL)
}

// NewDeepSeek creates the one M4.4 provider accepted for the live coding-agent
// proof. It fails closed rather than allowing a silent model substitution.
func NewDeepSeek(config Config) (*Broker, error) {
	if strings.TrimSpace(config.Model) != DeepSeekV4Flash {
		return nil, fmt.Errorf("%w: DeepSeek model must be exactly %s", ErrInvalidConfig, DeepSeekV4Flash)
	}
	config.RequestProfile = RequestProfileCodex
	return newResponses(config, "deepseek-responses", nil, deepSeekResponsesURL)
}

func newResponses(config Config, provider string, client *http.Client, upstream string) (*Broker, error) {
	config.APIKey = strings.TrimSpace(config.APIKey)
	config.Model = strings.TrimSpace(config.Model)
	config.RunID = strings.TrimSpace(config.RunID)
	provider = strings.TrimSpace(provider)
	if config.RequestProfile == "" {
		config.RequestProfile = RequestProfileCodex
	}
	if config.RequestProfile != RequestProfileCodex && config.RequestProfile != RequestProfileQwen {
		return nil, fmt.Errorf("%w: unsupported request profile", ErrInvalidConfig)
	}
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
		RequestProfile   string `json:"request_profile"`
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
		RequestProfile:   config.RequestProfile,
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
	boundedBody, err := sanitizeRequest(body, b.config.Model, b.config.MaxOutputTokens, b.config.RequestProfile, b.config.RunID)
	if err != nil {
		http.Error(writer, "model broker policy mismatch", http.StatusForbidden)
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

// sanitizeRequest applies a profile-bound allowlist to the untrusted request.
// Codex's pinned Responses client is supported, but only client-executed
// function/custom tools are forwarded. Provider-hosted tools and unknown fields
// fail closed. The Qwen profile intentionally remains non-streaming and narrow.
func sanitizeRequest(body []byte, model string, maxOutputTokens int, profile, runID string) ([]byte, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil || envelope == nil {
		return nil, errors.New("request must be one JSON object")
	}
	allowed := map[string]struct{}{
		"model": {}, "input": {}, "instructions": {}, "max_output_tokens": {}, "temperature": {}, "text": {},
	}
	switch profile {
	case RequestProfileQwen:
		allowed["stream"] = struct{}{}
	case RequestProfileCodex:
		for _, field := range []string{
			"tools", "tool_choice", "parallel_tool_calls", "reasoning", "store", "stream",
			"stream_options", "include", "service_tier", "prompt_cache_key", "client_metadata",
		} {
			allowed[field] = struct{}{}
		}
	default:
		return nil, errors.New("unknown request profile")
	}
	for field := range envelope {
		if _, ok := allowed[field]; !ok {
			return nil, fmt.Errorf("unsupported model request field %q", field)
		}
	}

	var requestedModel string
	if err := json.Unmarshal(envelope["model"], &requestedModel); err != nil || requestedModel != model {
		return nil, errors.New("model does not match trusted policy")
	}
	inputRaw, ok := envelope["input"]
	if !ok || string(inputRaw) == "null" || strings.TrimSpace(string(inputRaw)) == "" {
		return nil, errors.New("input is required")
	}
	if profile == RequestProfileQwen {
		var input string
		if err := json.Unmarshal(inputRaw, &input); err != nil || strings.TrimSpace(input) == "" {
			return nil, errors.New("Qwen input must be a non-empty string")
		}
	} else {
		var input string
		if err := json.Unmarshal(inputRaw, &input); err == nil {
			if strings.TrimSpace(input) == "" {
				return nil, errors.New("input string is empty")
			}
		} else {
			var items []json.RawMessage
			if err := json.Unmarshal(inputRaw, &items); err != nil || items == nil || len(items) == 0 || len(items) > 4096 {
				return nil, errors.New("Codex input must be a non-empty string or bounded item array")
			}
			for _, item := range items {
				var object map[string]json.RawMessage
				if err := json.Unmarshal(item, &object); err != nil || object == nil {
					return nil, errors.New("Codex input items must be JSON objects")
				}
			}
		}
	}

	if raw, ok := envelope["instructions"]; ok {
		var instructions string
		if string(raw) == "null" || json.Unmarshal(raw, &instructions) != nil ||
			(profile == RequestProfileQwen && strings.TrimSpace(instructions) == "") {
			return nil, errors.New("instructions has an invalid type or value")
		}
	} else if profile == RequestProfileQwen {
		return nil, errors.New("Qwen instructions are required")
	}

	requestedOutputTokens := 0
	if raw, ok := envelope["max_output_tokens"]; ok {
		if string(raw) == "null" || json.Unmarshal(raw, &requestedOutputTokens) != nil || requestedOutputTokens < 1 {
			return nil, errors.New("output-token budget is invalid")
		}
	}
	if requestedOutputTokens == 0 || requestedOutputTokens > maxOutputTokens {
		envelope["max_output_tokens"] = json.RawMessage(fmt.Sprintf("%d", maxOutputTokens))
	}
	if raw, ok := envelope["temperature"]; ok {
		var temperature float64
		if string(raw) == "null" || json.Unmarshal(raw, &temperature) != nil || temperature != 0 {
			return nil, errors.New("temperature must be the trusted value zero")
		}
	}
	envelope["temperature"] = json.RawMessage("0")

	if raw, ok := envelope["text"]; ok && string(raw) != "null" {
		if err := validateTextConfig(raw); err != nil {
			return nil, err
		}
	} else if profile == RequestProfileQwen {
		return nil, errors.New("Qwen structured output format is required")
	} else {
		delete(envelope, "text")
	}

	if profile == RequestProfileQwen {
		if raw, ok := envelope["stream"]; ok {
			var stream bool
			if string(raw) == "null" || json.Unmarshal(raw, &stream) != nil || stream {
				return nil, errors.New("Qwen streaming is not authorized")
			}
		}
		envelope["stream"] = json.RawMessage("false")
		return json.Marshal(envelope)
	}

	if raw, ok := envelope["tools"]; ok && string(raw) != "null" {
		if err := validateCodexTools(raw); err != nil {
			return nil, err
		}
	} else {
		delete(envelope, "tools")
	}
	if raw, ok := envelope["tool_choice"]; ok {
		var choice string
		if json.Unmarshal(raw, &choice) != nil || choice != "auto" {
			return nil, errors.New("only automatic client-side tool selection is authorized")
		}
	} else {
		envelope["tool_choice"] = json.RawMessage("\"auto\"")
	}
	if raw, ok := envelope["parallel_tool_calls"]; ok {
		var parallel bool
		if string(raw) == "null" || json.Unmarshal(raw, &parallel) != nil {
			return nil, errors.New("parallel_tool_calls must be boolean")
		}
	}
	if raw, ok := envelope["reasoning"]; ok && string(raw) != "null" {
		if err := validateCodexReasoning(raw); err != nil {
			return nil, err
		}
	} else {
		delete(envelope, "reasoning")
	}
	if raw, ok := envelope["store"]; ok {
		var store bool
		if string(raw) == "null" || json.Unmarshal(raw, &store) != nil || store {
			return nil, errors.New("provider-side response storage is not authorized")
		}
	}
	envelope["store"] = json.RawMessage("false")
	if raw, ok := envelope["stream"]; ok {
		var stream bool
		if string(raw) == "null" || json.Unmarshal(raw, &stream) != nil || !stream {
			return nil, errors.New("Codex streaming must remain enabled")
		}
	}
	envelope["stream"] = json.RawMessage("true")
	if raw, ok := envelope["stream_options"]; ok && string(raw) != "null" {
		if err := validateCodexStreamOptions(raw); err != nil {
			return nil, err
		}
	} else {
		delete(envelope, "stream_options")
	}
	if raw, ok := envelope["include"]; ok && string(raw) != "null" {
		var includes []string
		if json.Unmarshal(raw, &includes) != nil || len(includes) > 8 {
			return nil, errors.New("include must be a bounded string array")
		}
		for _, item := range includes {
			if item != "reasoning.encrypted_content" {
				return nil, fmt.Errorf("unsupported response include %q", item)
			}
		}
	} else {
		delete(envelope, "include")
	}
	if raw, ok := envelope["service_tier"]; ok && string(raw) != "null" {
		var tier string
		if json.Unmarshal(raw, &tier) != nil || (tier != "auto" && tier != "default") {
			return nil, errors.New("service_tier is outside the trusted budget policy")
		}
	} else {
		delete(envelope, "service_tier")
	}
	if raw, ok := envelope["prompt_cache_key"]; ok && string(raw) != "null" {
		var key string
		if json.Unmarshal(raw, &key) != nil || strings.TrimSpace(key) == "" {
			return nil, errors.New("prompt_cache_key must be a non-empty string")
		}
		sum := sha256.Sum256([]byte(runID))
		envelope["prompt_cache_key"] = mustJSON(fmt.Sprintf("mirage-%x", sum[:24]))
	} else {
		delete(envelope, "prompt_cache_key")
	}
	if raw, ok := envelope["client_metadata"]; ok && string(raw) != "null" {
		var metadata map[string]string
		if json.Unmarshal(raw, &metadata) != nil || metadata == nil || len(metadata) > 32 {
			return nil, errors.New("client_metadata must be a bounded string map")
		}
		for key, value := range metadata {
			if strings.TrimSpace(key) == "" || len(key) > 128 || len(value) > 512 || strings.ContainsAny(key+value, "\x00\r\n") {
				return nil, errors.New("client_metadata field is invalid")
			}
		}
	} else {
		delete(envelope, "client_metadata")
	}
	return json.Marshal(envelope)
}

func validateCodexTools(raw json.RawMessage) error {
	var tools []json.RawMessage
	if json.Unmarshal(raw, &tools) != nil || tools == nil || len(tools) > 128 {
		return errors.New("Codex tools must be a bounded array")
	}
	names := make(map[string]struct{}, len(tools))
	for _, rawTool := range tools {
		var tool map[string]json.RawMessage
		if json.Unmarshal(rawTool, &tool) != nil || tool == nil {
			return errors.New("Codex tool must be an object")
		}
		var kind, name string
		if json.Unmarshal(tool["type"], &kind) != nil || json.Unmarshal(tool["name"], &name) != nil || strings.TrimSpace(name) == "" || len(name) > 128 {
			return errors.New("Codex tool type or name is invalid")
		}
		allowed := map[string]struct{}{"type": {}, "name": {}, "description": {}, "defer_loading": {}}
		switch kind {
		case "function":
			allowed["parameters"] = struct{}{}
			allowed["strict"] = struct{}{}
		case "custom":
			allowed["format"] = struct{}{}
		default:
			return fmt.Errorf("provider-hosted or unknown tool type %q is not authorized", kind)
		}
		for key := range tool {
			if _, ok := allowed[key]; !ok {
				return fmt.Errorf("unsupported %s tool field %q", kind, key)
			}
		}
		if rawDescription, exists := tool["description"]; exists {
			var description string
			if json.Unmarshal(rawDescription, &description) != nil || len(description) > 16<<10 {
				return errors.New("tool description is invalid or too long")
			}
		}
		if rawDefer, exists := tool["defer_loading"]; exists {
			var deferLoading bool
			if json.Unmarshal(rawDefer, &deferLoading) != nil {
				return errors.New("defer_loading must be boolean")
			}
		}
		if kind == "function" {
			if parameters, exists := tool["parameters"]; exists {
				var schema map[string]json.RawMessage
				if json.Unmarshal(parameters, &schema) != nil || schema == nil {
					return errors.New("function parameters must be a JSON schema object")
				}
			}
			if strictRaw, exists := tool["strict"]; exists {
				var strict bool
				if json.Unmarshal(strictRaw, &strict) != nil {
					return errors.New("function strict option must be boolean")
				}
			}
		} else if format, exists := tool["format"]; exists {
			var textFormat map[string]json.RawMessage
			if json.Unmarshal(format, &textFormat) != nil || textFormat == nil {
				return errors.New("custom tool format must be an object")
			}
			for key := range textFormat {
				if key != "type" && key != "syntax" && key != "definition" {
					return fmt.Errorf("unsupported custom tool format field %q", key)
				}
			}
		}
		if _, duplicate := names[name]; duplicate {
			return fmt.Errorf("duplicate Codex tool name %q", name)
		}
		names[name] = struct{}{}
	}
	return nil
}

func validateCodexReasoning(raw json.RawMessage) error {
	var reasoning map[string]json.RawMessage
	if json.Unmarshal(raw, &reasoning) != nil || reasoning == nil {
		return errors.New("reasoning must be an object")
	}
	for key, rawValue := range reasoning {
		var value string
		if json.Unmarshal(rawValue, &value) != nil {
			return fmt.Errorf("reasoning field %q must be a string", key)
		}
		switch key {
		case "effort":
			if value != "minimal" && value != "low" && value != "medium" && value != "high" && value != "xhigh" && value != "max" {
				return errors.New("reasoning effort is outside the supported range")
			}
		case "summary":
			if value != "auto" && value != "concise" && value != "detailed" {
				return errors.New("reasoning summary is not supported")
			}
		case "context":
			if value != "all_turns" && value != "current_turn" {
				return errors.New("reasoning context is not supported")
			}
		default:
			return fmt.Errorf("unsupported reasoning field %q", key)
		}
	}
	return nil
}

func validateCodexStreamOptions(raw json.RawMessage) error {
	var options map[string]json.RawMessage
	if json.Unmarshal(raw, &options) != nil || options == nil {
		return errors.New("stream_options must be an object")
	}
	for key, rawValue := range options {
		switch key {
		case "reasoning_summary_delivery":
			var value string
			if json.Unmarshal(rawValue, &value) != nil || value != "sequential_cutoff" {
				return errors.New("unsupported reasoning summary delivery mode")
			}
		case "include_obfuscation":
			var value bool
			if json.Unmarshal(rawValue, &value) != nil {
				return errors.New("include_obfuscation must be boolean")
			}
		default:
			return fmt.Errorf("unsupported stream option %q", key)
		}
	}
	return nil
}

func validateTextConfig(raw json.RawMessage) error {
	var textConfig map[string]json.RawMessage
	if string(raw) == "null" || json.Unmarshal(raw, &textConfig) != nil || textConfig == nil {
		return errors.New("text format must be an object")
	}
	for key, value := range textConfig {
		switch key {
		case "verbosity":
			var verbosity string
			if json.Unmarshal(value, &verbosity) != nil || (verbosity != "low" && verbosity != "medium" && verbosity != "high") {
				return errors.New("text verbosity is invalid")
			}
		case "format":
			var format map[string]json.RawMessage
			if json.Unmarshal(value, &format) != nil || format == nil {
				return errors.New("text format descriptor must be an object")
			}
			for field := range format {
				if field != "type" && field != "name" && field != "schema" && field != "strict" && field != "description" {
					return fmt.Errorf("unsupported text format field %q", field)
				}
			}
			if schema, exists := format["schema"]; exists {
				var object map[string]json.RawMessage
				if json.Unmarshal(schema, &object) != nil || object == nil {
					return errors.New("text schema must be a JSON object")
				}
			}
		default:
			return fmt.Errorf("unsupported text configuration field %q", key)
		}
	}
	return nil
}

func mustJSON(value any) json.RawMessage {
	encoded, _ := json.Marshal(value)
	return encoded
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
