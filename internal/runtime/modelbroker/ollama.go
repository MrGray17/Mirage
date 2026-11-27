package modelbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	Qwen25Coder15B  = "qwen2.5-coder:1.5b"
	ollamaLoopback  = "http://127.0.0.1:11434/v1/responses"
	ollamaPolicyURL = "https://ollama.local.invalid/v1/responses"
)

// NewOllama creates the single local-model broker accepted by the Qwen agent
// proof. The endpoint and model are fixed; the sandbox cannot select either.
func NewOllama(config Config) (*Broker, error) {
	config.RequestProfile = RequestProfileQwen
	if strings.TrimSpace(config.Model) != Qwen25Coder15B {
		return nil, fmt.Errorf("%w: Ollama model must be exactly %s", ErrInvalidConfig, Qwen25Coder15B)
	}
	config.APIKey = "ollama-local-no-secret"
	client := &http.Client{
		Transport: ollamaTransport{},
		Timeout:   defaultUpstreamTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("local Ollama broker refuses redirects")
		},
	}
	return newResponses(config, "ollama-local-responses", client, ollamaPolicyURL)
}

type ollamaTransport struct{}

func (ollamaTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodPost || request.URL.String() != ollamaPolicyURL {
		return nil, errors.New("local Ollama transport denied request")
	}
	if isWSLInteropAvailable() {
		return roundTripWindowsOllama(request)
	}
	forward := request.Clone(request.Context())
	forward.URL.Scheme = "http"
	forward.URL.Host = "127.0.0.1:11434"
	forward.Host = "127.0.0.1:11434"
	forward.Header.Del("Authorization")
	forward.Header.Del("X-Client-Request-Id")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return transport.RoundTrip(forward)
}

func isWSLInteropAvailable() bool {
	if os.Getenv("WSL_INTEROP") == "" {
		return false
	}
	for _, name := range []string{"/init", "/mnt/c/Windows/System32/curl.exe"} {
		info, err := os.Stat(name)
		if err != nil || info.IsDir() {
			return false
		}
	}
	return true
}

func roundTripWindowsOllama(request *http.Request) (*http.Response, error) {
	const marker = "\nMIRAGE_OLLAMA_STATUS:"
	command := exec.CommandContext(request.Context(), "/init", "/mnt/c/Windows/System32/curl.exe",
		"--disable", "--silent", "--show-error", "--max-time", strconv.Itoa(int(defaultUpstreamTimeout/time.Second)),
		"--noproxy", "*", "--proxy", "", "--request", "POST",
		"--header", "Content-Type: application/json", "--header", "Accept: application/json",
		"--data-binary", "@-", "--write-out", marker+"%{http_code}", ollamaLoopback,
	)
	command.Stdin = request.Body
	command.Env = []string{
		"LANG=C",
		"SystemRoot=C:\\Windows",
		"WSLENV=",
		"WSL_INTEROP=" + os.Getenv("WSL_INTEROP"),
	}
	var output boundedOllamaBuffer
	output.limit = int(defaultMaxResponseBytes) + 128
	var stderr boundedOllamaBuffer
	stderr.limit = 4 << 10
	command.Stdout = &output
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("fixed Windows Ollama request failed: %w", err)
	}
	if output.overflow {
		return nil, errors.New("fixed Windows Ollama response exceeded transport cap")
	}
	encoded := output.Bytes()
	index := bytes.LastIndex(encoded, []byte(marker))
	if index < 0 {
		return nil, errors.New("fixed Windows Ollama response lacked status marker")
	}
	status, err := strconv.Atoi(strings.TrimSpace(string(encoded[index+len(marker):])))
	if err != nil || status < 100 || status > 599 {
		return nil, errors.New("fixed Windows Ollama response had invalid status")
	}
	body := append([]byte(nil), encoded[:index]...)
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    request,
	}, nil
}

type boundedOllamaBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (buffer *boundedOllamaBuffer) Bytes() []byte { return buffer.buffer.Bytes() }

func (buffer *boundedOllamaBuffer) String() string { return buffer.buffer.String() }

func (buffer *boundedOllamaBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining <= 0 {
		buffer.overflow = true
		return original, nil
	}
	if len(value) > remaining {
		value = value[:remaining]
		buffer.overflow = true
	}
	_, _ = buffer.buffer.Write(value)
	return original, nil
}

// CheckOllamaModel performs a bounded, read-only probe of the same local Ollama
// installation used by the runtime. It never pulls a model or generates tokens.
func CheckOllamaModel(ctx context.Context) error {
	const endpoint = "http://127.0.0.1:11434/api/tags"
	const limit = 1 << 20
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var body []byte
	if isWSLInteropAvailable() {
		command := exec.CommandContext(ctx, "/init", "/mnt/c/Windows/System32/curl.exe",
			"--disable", "--silent", "--show-error", "--fail", "--max-time", "5",
			"--noproxy", "*", "--proxy", "", endpoint)
		command.Env = []string{"LANG=C", "SystemRoot=C:\\Windows", "WSLENV=", "WSL_INTEROP=" + os.Getenv("WSL_INTEROP")}
		output := &boundedOllamaBuffer{limit: limit}
		command.Stdout = output
		command.Stderr = io.Discard
		if err := command.Run(); err != nil || output.overflow {
			return errors.New("local Windows Ollama model inventory unavailable")
		}
		body = output.Bytes()
	} else {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("local Ollama probe refuses redirects")
		}}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err != nil {
			return errors.New("local Ollama model inventory unavailable")
		}
		defer response.Body.Close()
		body, err = io.ReadAll(io.LimitReader(response.Body, limit+1))
		if err != nil || len(body) > limit || response.StatusCode != http.StatusOK {
			return errors.New("local Ollama model inventory unavailable")
		}
	}
	return requireOllamaModel(body)
}

func requireOllamaModel(body []byte) error {
	var inventory struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &inventory); err != nil {
		return errors.New("local Ollama model inventory is invalid")
	}
	for _, model := range inventory.Models {
		if model.Name == Qwen25Coder15B {
			return nil
		}
	}
	return fmt.Errorf("required Ollama model %s is not installed", Qwen25Coder15B)
}
