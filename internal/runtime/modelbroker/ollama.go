package modelbroker

import (
	"bytes"
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
		"--silent", "--show-error", "--max-time", strconv.Itoa(int(defaultUpstreamTimeout/time.Second)),
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
	bytes.Buffer
	limit    int
	overflow bool
}

func (buffer *boundedOllamaBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := buffer.limit - buffer.Len()
	if remaining <= 0 {
		buffer.overflow = true
		return original, nil
	}
	if len(value) > remaining {
		value = value[:remaining]
		buffer.overflow = true
	}
	_, _ = buffer.Buffer.Write(value)
	return original, nil
}
