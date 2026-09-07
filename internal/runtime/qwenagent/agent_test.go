package qwenagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestStrictActionProtocol(t *testing.T) {
	t.Parallel()
	valid := []string{
		`{"tool":"list_files","arguments":{}}`,
		`{"tool":"read_file","arguments":{"path":"README.md"}}`,
		`{"tool":"patch_file","arguments":{"path":"README.md","append":"changed"}}`,
		`{"tool":"finish","arguments":{}}`,
	}
	for _, encoded := range valid {
		if _, err := parseAction([]byte(encoded)); err != nil {
			t.Errorf("valid action %s: %v", encoded, err)
		}
	}
	invalid := []string{
		`plain prose`,
		"```json\n{\"tool\":\"finish\",\"arguments\":{}}\n```",
		`[{"tool":"finish","arguments":{}}]`,
		`{"tool":"finish","arguments":{}} {"tool":"finish","arguments":{}}`,
		`{"tool":"finish","arguments":{},"extra":true}`,
		`{"tool":"finish"}`,
		``,
	}
	for _, encoded := range invalid {
		if _, err := parseAction([]byte(encoded)); !errors.Is(err, ErrProtocol) {
			t.Errorf("invalid action %q returned %v", encoded, err)
		}
	}
	if _, err := parseAction([]byte(strings.Repeat("x", maxModelResponse+1))); !errors.Is(err, ErrProtocol) {
		t.Fatalf("oversized action returned %v", err)
	}
}

func TestSequenceRequiresRootedInspectThenSinglePatchThenFinish(t *testing.T) {
	t.Parallel()
	state := sequenceState{readContent: make(map[string]string)}
	read, _ := parseAction([]byte(`{"tool":"read_file","arguments":{"path":"README.md"}}`))
	if err := state.validate(read); !errors.Is(err, ErrProtocol) {
		t.Fatalf("read before list returned %v", err)
	}
	list, _ := parseAction([]byte(`{"tool":"list_files","arguments":{}}`))
	if err := state.validate(list); err != nil {
		t.Fatal(err)
	}
	state.observe(list, `[]`)
	if err := state.validate(read); err != nil {
		t.Fatal(err)
	}
	state.observe(read, `"original"`)
	wrong, _ := parseAction([]byte(`{"tool":"patch_file","arguments":{"path":"other.txt","append":"x"}}`))
	if err := state.validate(wrong); !errors.Is(err, ErrProtocol) {
		t.Fatalf("patch without same-path read returned %v", err)
	}
	patch, _ := parseAction([]byte(`{"tool":"patch_file","arguments":{"path":"README.md","append":"x"}}`))
	if err := state.validate(patch); err != nil {
		t.Fatal(err)
	}
	state.observe(patch, `"appended"`)
	if err := state.validate(patch); !errors.Is(err, ErrProtocol) {
		t.Fatalf("second patch returned %v", err)
	}
	finish, _ := parseAction([]byte(`{"tool":"finish","arguments":{}}`))
	if err := state.validate(finish); err != nil {
		t.Fatal(err)
	}
}

func TestExecuteRejectsHostilePathsAndUnsupportedTools(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), []byte("before"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	config := defaults(Config{})
	tests := []struct {
		name   string
		action string
		want   error
	}{
		{"traversal", `{"tool":"read_file","arguments":{"path":"../secret"}}`, ErrPolicy},
		{"absolute", `{"tool":"read_file","arguments":{"path":"/etc/passwd"}}`, ErrPolicy},
		{"env", `{"tool":"read_file","arguments":{"path":".env"}}`, ErrPolicy},
		{"git", `{"tool":"patch_file","arguments":{"path":".git/config","append":"x"}}`, ErrPolicy},
		{"nested-env", `{"tool":"read_file","arguments":{"path":"docs/.env.local"}}`, ErrPolicy},
		{"nested-git", `{"tool":"read_file","arguments":{"path":"vendor/repo/.git/config"}}`, ErrPolicy},
		{"nested-credential-directory", `{"tool":"read_file","arguments":{"path":"vendor/.ssh/id_ed25519"}}`, ErrPolicy},
		{"alternate-separator", `{"tool":"read_file","arguments":{"path":"docs\\secret"}}`, ErrPolicy},
		{"empty-path", `{"tool":"read_file","arguments":{"path":""}}`, ErrPolicy},
		{"control", "{\"tool\":\"read_file\",\"arguments\":{\"path\":\"bad\\u0001name\"}}", ErrPolicy},
		{"shell", `{"tool":"shell","arguments":{"command":"id"}}`, ErrProtocol},
		{"network", `{"tool":"http","arguments":{"url":"https://example.com"}}`, ErrProtocol},
		{"git-tool", `{"tool":"git","arguments":{"args":["status"]}}`, ErrProtocol},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selected, err := parseAction([]byte(test.action))
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = execute(root, selected, config)
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestRootedFileOperationsAndLimits(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), []byte("before"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(workspace, "escape")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("Windows symlink privilege unavailable: %v", err)
		}
		t.Fatal(err)
	}
	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := readFile(root, "escape", 1024); err == nil {
		t.Fatal("symlink escape read succeeded")
	}
	if err := writeFile(root, "escape", []byte("changed")); err == nil {
		t.Fatal("symlink escape write succeeded")
	}
	outsideBytes, _ := os.ReadFile(outside)
	if string(outsideBytes) != "secret" {
		t.Fatal("outside file changed")
	}
	if _, err := readFile(root, "README.md", 2); !errors.Is(err, ErrLimit) {
		t.Fatalf("oversized read returned %v", err)
	}
	selected, _ := parseAction([]byte(`{"tool":"patch_file","arguments":{"path":"README.md","append":"changed"}}`))
	if _, _, err := execute(root, selected, Config{MaxWriteBytes: 2}); !errors.Is(err, ErrLimit) {
		t.Fatalf("oversized write returned %v", err)
	}
	if err := writeFile(root, "README.md", []byte("changed")); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(filepath.Join(workspace, "README.md"))
	if string(content) != "changed" {
		t.Fatalf("README = %q", content)
	}
}

func TestRootedFileOperationsRejectDirectorySymlinkEscape(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(workspace, "escape-dir")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("Windows symlink privilege unavailable: %v", err)
		}
		t.Fatal(err)
	}
	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := readFile(root, "escape-dir/secret.txt", 1024); err == nil {
		t.Fatal("directory symlink escape read succeeded")
	}
	if err := writeFile(root, "escape-dir/secret.txt", []byte("changed")); err == nil {
		t.Fatal("directory symlink escape write succeeded")
	}
	content, err := os.ReadFile(secret)
	if err != nil || string(content) != "secret" {
		t.Fatalf("outside content=%q error=%v", content, err)
	}
}

func TestRunExecutesStructuredModelLoop(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), []byte("before\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	responses := []string{
		`{"tool":"list_files","arguments":{}}`,
		`{"tool":"read_file","arguments":{"path":"README.md"}}`,
		`{"tool":"patch_file","arguments":{"path":"README.md","append":"verified by Qwen\n"}}`,
		`{"tool":"finish","arguments":{}}`,
	}
	socket, closeServer := responseServer(t, responses)
	defer closeServer()
	var output strings.Builder
	err := Run(context.Background(), Config{Workspace: workspace, BrokerSocket: socket, Model: "qwen2.5-coder:1.5b", Task: "edit README", Output: &output})
	if err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(filepath.Join(workspace, "README.md"))
	if string(content) != "before\nverified by Qwen\n" || !strings.Contains(output.String(), "tool=patch_file") {
		t.Fatalf("content=%q output=%q", content, output.String())
	}
}

func TestRunFailsClosedOnProtocolAndStepLimit(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		responses []string
		maxSteps  int
		want      error
	}{
		{"prose", []string{"I will edit it"}, 1, ErrProtocol},
		{"malformed", []string{`{"tool":`}, 1, ErrProtocol},
		{"unknown", []string{`{"tool":"exec","arguments":{}}`}, 1, ErrProtocol},
		{"refuses-finish", []string{`{"tool":"list_files","arguments":{}}`, `{"tool":"read_file","arguments":{"path":"README.md"}}`, `{"tool":"patch_file","arguments":{"path":"README.md","append":" changed"}}`}, 3, ErrLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			workspace := t.TempDir()
			if test.name == "refuses-finish" {
				if err := os.WriteFile(filepath.Join(workspace, "README.md"), []byte("content"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			socket, closeServer := responseServer(t, test.responses)
			defer closeServer()
			err := Run(context.Background(), Config{Workspace: workspace, BrokerSocket: socket, Model: "qwen2.5-coder:1.5b", Task: "task", MaxSteps: test.maxSteps})
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func responseServer(t *testing.T, actions []string) (string, func()) {
	t.Helper()
	directory, err := os.MkdirTemp("", "qwen-agent-")
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(directory, "model.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		_ = os.RemoveAll(directory)
		t.Fatal(err)
	}
	var mu sync.Mutex
	index := 0
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if index >= len(actions) {
			http.Error(writer, "no response", http.StatusTooManyRequests)
			return
		}
		payload := map[string]any{
			"output": []any{
				map[string]any{
					"type": "message",
					"content": []any{
						map[string]any{"type": "output_text", "text": actions[index]},
					},
				},
			},
		}
		index++
		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(payload); err != nil {
			t.Errorf("encode response: %v", err)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	return socket, func() {
		_ = server.Close()
		_ = listener.Close()
		_ = os.RemoveAll(directory)
	}
}

func TestListFilesRejectsSymlinkAndCapsEntries(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	if err := os.Symlink("target", filepath.Join(workspace, "link")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("Windows symlink privilege unavailable: %v", err)
		}
		t.Fatal(err)
	}
	root, _ := os.OpenRoot(workspace)
	defer root.Close()
	if _, err := listFiles(root); !errors.Is(err, ErrPolicy) {
		t.Fatalf("symlink list returned %v", err)
	}
	workspace = t.TempDir()
	for index := 0; index <= maxListedFiles; index++ {
		if err := os.WriteFile(filepath.Join(workspace, fmt.Sprintf("f-%03d", index)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, _ = os.OpenRoot(workspace)
	defer root.Close()
	if _, err := listFiles(root); !errors.Is(err, ErrLimit) {
		t.Fatalf("file cap returned %v", err)
	}
}

func TestListFilesHidesNestedProtectedMetadata(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	for _, name := range []string{"vendor/repo/.git", "docs/.ssh", "nested"} {
		if err := os.MkdirAll(filepath.Join(workspace, filepath.FromSlash(name)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range map[string]string{
		"vendor/repo/.git/config": "credential material",
		"docs/.ssh/id_ed25519":    "private key",
		"nested/.env.local":       "secret",
		"README.md":               "visible",
	} {
		if err := os.WriteFile(filepath.Join(workspace, filepath.FromSlash(name)), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	files, err := listFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0] != "README.md" {
		t.Fatalf("listed protected metadata: %#v", files)
	}
}
