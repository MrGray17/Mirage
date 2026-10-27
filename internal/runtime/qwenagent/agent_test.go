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
		`{"tool":"patch_file","arguments":{"path":"README.md","mode":"append","append":"changed","search":null,"replace":null,"edits":null}}`,
		`{"tool":"patch_file","arguments":{"path":"README.md","mode":"replace","append":null,"search":"before","replace":"after","edits":null}}`,
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
	wrong, _ := parseAction([]byte(`{"tool":"patch_file","arguments":{"path":"other.txt","mode":"append","append":"x","search":null,"replace":null,"edits":null}}`))
	if err := state.validate(wrong); !errors.Is(err, ErrProtocol) {
		t.Fatalf("patch without same-path read returned %v", err)
	}
	patch, _ := parseAction([]byte(`{"tool":"patch_file","arguments":{"path":"README.md","mode":"append","append":"x","search":null,"replace":null,"edits":null}}`))
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
		{"git", `{"tool":"patch_file","arguments":{"path":".git/config","mode":"append","append":"x","search":null,"replace":null,"edits":null}}`, ErrPolicy},
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
	selected, _ := parseAction([]byte(`{"tool":"patch_file","arguments":{"path":"README.md","mode":"append","append":"changed","search":null,"replace":null,"edits":null}}`))
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

func TestActionFormatDeclaresBoundedEditBatch(t *testing.T) {
	t.Parallel()
	formatted := actionFormat(sequenceState{readContent: map[string]string{"README.md": "before"}}).(map[string]any)
	format := formatted["format"].(map[string]any)
	schema := format["schema"].(map[string]any)
	variants := schema["oneOf"].([]any)
	if len(variants) != 1 {
		t.Fatalf("patch action schema has %d variants, want one explicit-mode schema", len(variants))
	}
	arguments := variants[0].(map[string]any)["properties"].(map[string]any)["arguments"].(map[string]any)
	properties := arguments["properties"].(map[string]any)
	mode := properties["mode"].(map[string]any)
	allowed, ok := mode["enum"].([]string)
	if !ok || strings.Join(allowed, ",") != "append,replace,batch" {
		t.Fatalf("mode enum = %#v, want append,replace,batch", mode["enum"])
	}
	edits := properties["edits"].(map[string]any)
	if edits["maxItems"] != maxFileEdits {
		t.Fatalf("edits maxItems = %v, want %d", edits["maxItems"], maxFileEdits)
	}
	if _, ok := edits["items"].(map[string]any); !ok {
		t.Fatal("edits schema is missing item shape")
	}
	required, ok := arguments["required"].([]string)
	if !ok {
		t.Fatalf("required schema has unexpected type %T", arguments["required"])
	}
	for _, field := range []string{"path", "mode", "append", "search", "replace", "edits"} {
		found := false
		for _, candidate := range required {
			if candidate == field {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s must be required in strict schema", field)
		}
	}
}

func TestQwenBatchEditsApplyAsSinglePreparedUpdate(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	file := filepath.Join(workspace, "config.txt")
	before := "version = 1\nname = old\n"
	if err := os.WriteFile(file, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	selected, err := parseAction([]byte(`{"tool":"patch_file","arguments":{"path":"config.txt","mode":"batch","append":null,"search":null,"replace":null,"edits":[{"search":"version = 1","replace":"version = 2"},{"search":"name = old","replace":"name = new"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := execute(root, selected, defaults(Config{})); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != "version = 2\nname = new\n" {
		t.Fatalf("content = %q", after)
	}
}

func TestQwenBatchEditFailureDoesNotWritePartialResult(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	file := filepath.Join(workspace, "config.txt")
	before := "alpha beta"
	if err := os.WriteFile(file, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	selected, err := parseAction([]byte(`{"tool":"patch_file","arguments":{"path":"config.txt","mode":"batch","append":null,"search":null,"replace":null,"edits":[{"search":"alpha","replace":"gamma"},{"search":"missing","replace":"delta"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := execute(root, selected, defaults(Config{})); !errors.Is(err, ErrProtocol) {
		t.Fatalf("execute error = %v, want ErrProtocol", err)
	}
	after, err := os.ReadFile(file)
	if err != nil || string(after) != before {
		t.Fatalf("failed batch changed file: content=%q error=%v", after, err)
	}
}

func TestQwenBatchEditWriteLimitDoesNotWritePartialResult(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	file := filepath.Join(workspace, "config.txt")
	before := "a b"
	if err := os.WriteFile(file, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	selected, err := parseAction([]byte(`{"tool":"patch_file","arguments":{"path":"config.txt","mode":"batch","append":null,"search":null,"replace":null,"edits":[{"search":"a","replace":"aa"},{"search":"b","replace":"bb"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := execute(root, selected, Config{MaxReadBytes: 1024, MaxWriteBytes: 4}); !errors.Is(err, ErrLimit) {
		t.Fatalf("execute error = %v, want ErrLimit", err)
	}
	after, err := os.ReadFile(file)
	if err != nil || string(after) != before {
		t.Fatalf("write-limited batch changed file: content=%q error=%v", after, err)
	}
}

func TestQwenBatchEditRejectsNetNoOpWithoutWriting(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	file := filepath.Join(workspace, "config.txt")
	before := "alpha beta"
	if err := os.WriteFile(file, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	selected, err := parseAction([]byte(`{"tool":"patch_file","arguments":{"path":"config.txt","mode":"batch","append":null,"search":null,"replace":null,"edits":[{"search":"alpha","replace":"gamma"},{"search":"gamma","replace":"alpha"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := execute(root, selected, defaults(Config{})); !errors.Is(err, ErrProtocol) {
		t.Fatalf("execute error = %v, want ErrProtocol", err)
	}
	after, err := os.ReadFile(file)
	if err != nil || string(after) != before {
		t.Fatalf("net-no-op batch changed file: content=%q error=%v", after, err)
	}
}

func TestQwenPatchShapeRejectsConflictingModes(t *testing.T) {
	t.Parallel()
	appendText := "tail"
	searchText := "before"
	replaceText := "after"
	validEdits := []textEdit{{Search: "before", Replace: "after"}}
	emptyEdits := []textEdit{}
	tests := []struct {
		name      string
		arguments patchArguments
		want      error
	}{
		{name: "missing-mode", arguments: patchArguments{}, want: ErrProtocol},
		{name: "append-and-replace", arguments: patchArguments{Mode: "append", Append: &appendText, Search: &searchText, Replace: &replaceText}, want: ErrProtocol},
		{name: "append-and-batch", arguments: patchArguments{Mode: "append", Append: &appendText, Edits: &validEdits}, want: ErrProtocol},
		{name: "replace-and-batch", arguments: patchArguments{Mode: "replace", Search: &searchText, Replace: &replaceText, Edits: &validEdits}, want: ErrProtocol},
		{name: "incomplete-replacement", arguments: patchArguments{Mode: "replace", Search: &searchText}, want: ErrProtocol},
		{name: "empty-batch", arguments: patchArguments{Mode: "batch", Edits: &emptyEdits}, want: ErrLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := validatePatchShape(test.arguments); !errors.Is(err, test.want) {
				t.Fatalf("validatePatchShape error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestQwenBatchEditRejectsAmbiguousLaterMatchWithoutWriting(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	file := filepath.Join(workspace, "config.txt")
	before := "alpha beta beta"
	if err := os.WriteFile(file, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	selected, err := parseAction([]byte(`{"tool":"patch_file","arguments":{"path":"config.txt","mode":"batch","append":null,"search":null,"replace":null,"edits":[{"search":"alpha","replace":"gamma"},{"search":"beta","replace":"delta"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := execute(root, selected, defaults(Config{})); !errors.Is(err, ErrProtocol) {
		t.Fatalf("execute error = %v, want ErrProtocol", err)
	}
	after, err := os.ReadFile(file)
	if err != nil || string(after) != before {
		t.Fatalf("ambiguous batch changed file: content=%q error=%v", after, err)
	}
}

func TestQwenBatchEditRejectsTooManyOperations(t *testing.T) {
	t.Parallel()
	edits := make([]textEdit, maxFileEdits+1)
	for i := range edits {
		edits[i] = textEdit{Search: "x", Replace: "y"}
	}
	arguments := patchArguments{Mode: "batch", Edits: &edits}
	if err := validatePatchShape(arguments); !errors.Is(err, ErrLimit) {
		t.Fatalf("shape error = %v, want ErrLimit", err)
	}
}

func TestQwenPatchFileRequiresOneExactMatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		before      string
		search      string
		replacement string
	}{
		{name: "missing", before: "alpha beta", search: "missing", replacement: "gamma"},
		{name: "duplicate", before: "alpha alpha", search: "alpha", replacement: "gamma"},
		{name: "overlapping", before: "aaa", search: "aa", replacement: "b"},
		{name: "empty-search", before: "alpha", search: "", replacement: "beta"},
		{name: "no-op", before: "alpha", search: "alpha", replacement: "alpha"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workspace := t.TempDir()
			file := filepath.Join(workspace, "README.md")
			if err := os.WriteFile(file, []byte(test.before), 0o600); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(workspace)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			encoded := fmt.Sprintf(
				`{"tool":"patch_file","arguments":{"path":"README.md","mode":"replace","append":null,"search":%q,"replace":%q,"edits":null}}`,
				test.search, test.replacement,
			)
			selected, err := parseAction([]byte(encoded))
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = execute(root, selected, defaults(Config{}))
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("execute error = %v, want ErrProtocol", err)
			}
			after, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != test.before {
				t.Fatalf("failed patch changed file: got %q want %q", after, test.before)
			}
		})
	}
}

func TestQwenPatchFileReplacementRejectsNonUTF8(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	file := filepath.Join(workspace, "README.md")
	before := []byte{0xff, 'a'}
	if err := os.WriteFile(file, before, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	selected, err := parseAction([]byte(`{"tool":"patch_file","arguments":{"path":"README.md","mode":"replace","append":null,"search":"a","replace":"b","edits":null}}`))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = execute(root, selected, defaults(Config{}))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("execute error = %v, want ErrPolicy", err)
	}
	after, err := os.ReadFile(file)
	if err != nil || string(after) != string(before) {
		t.Fatalf("failed patch changed non-UTF-8 file: bytes=%v error=%v", after, err)
	}
}

func TestQwenPatchFileReplacementRespectsWriteLimit(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	file := filepath.Join(workspace, "README.md")
	if err := os.WriteFile(file, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	selected, err := parseAction([]byte(`{"tool":"patch_file","arguments":{"path":"README.md","mode":"replace","append":null,"search":"one","replace":"a much longer replacement","edits":null}}`))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = execute(root, selected, Config{MaxReadBytes: 1024, MaxWriteBytes: 4})
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("execute error = %v, want ErrLimit", err)
	}
	content, err := os.ReadFile(file)
	if err != nil || string(content) != "one" {
		t.Fatalf("content = %q, error = %v", content, err)
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
		`{"tool":"patch_file","arguments":{"path":"README.md","mode":"replace","append":null,"search":"before\n","replace":"before\nverified by Qwen\n","edits":null}}`,
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
		// Invalid model actions are rejected, then the bounded loop exhausts its
		// one-step budget. The lower-level parser tests still assert ErrProtocol.
		{"prose", []string{"I will edit it"}, 1, ErrLimit},
		{"malformed", []string{`{"tool":`}, 1, ErrLimit},
		{"unknown", []string{`{"tool":"exec","arguments":{}}`}, 1, ErrLimit},
		{"refuses-finish", []string{`{"tool":"list_files","arguments":{}}`, `{"tool":"read_file","arguments":{"path":"README.md"}}`, `{"tool":"patch_file","arguments":{"path":"README.md","mode":"append","append":" changed","search":null,"replace":null,"edits":null}}`}, 3, ErrLimit},
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

func TestRunRetriesRejectedPatchWithoutExecutingIt(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	file := filepath.Join(workspace, "README.md")
	before := "Project: MIRAGE-QWEN-SMOKE\nStatus: draft\nOwner: local-agent\n"
	if err := os.WriteFile(file, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	responses := []string{
		"{\"tool\":\"list_files\",\"arguments\":{}}",
		"{\"tool\":\"read_file\",\"arguments\":{\"path\":\"README.md\"}}",
		"{\"tool\":\"patch_file\",\"arguments\":{\"path\":\"README.md\",\"mode\":\"batch\",\"append\":null,\"search\":null,\"replace\":null,\"edits\":null}}",
		"{\"tool\":\"patch_file\",\"arguments\":{\"path\":\"README.md\",\"mode\":\"batch\",\"append\":null,\"search\":null,\"replace\":null,\"edits\":[{\"search\":\"Status: draft\",\"replace\":\"Status: verified\"},{\"search\":\"Owner: local-agent\",\"replace\":\"Owner: qwen-agent\"}]}}",
		"{\"tool\":\"finish\",\"arguments\":{}}",
	}
	socket, closeServer := responseServer(t, responses)
	defer closeServer()
	var output strings.Builder
	err := Run(context.Background(), Config{
		Workspace: workspace, BrokerSocket: socket, Model: "qwen2.5-coder:1.5b",
		Task: "replace status and owner in README", Output: &output,
	})
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	want := "Project: MIRAGE-QWEN-SMOKE\nStatus: verified\nOwner: qwen-agent\n"
	if string(content) != want {
		t.Fatalf("content = %q, want %q", content, want)
	}
	if !strings.Contains(output.String(), "step=4 tool=patch_file") {
		t.Fatalf("corrected patch action wasn't logged at the fourth model step: %q", output.String())
	}
	if strings.Contains(output.String(), "step=3 tool=patch_file") {
		t.Fatalf("rejected patch was logged as an executed action: %q", output.String())
	}
}


func TestRunStopsAfterThreeIdenticalRejectedActions(t *testing.T) {
	workspace := t.TempDir()
	file := filepath.Join(workspace, "README.md")
	before := "Status: draft\n"
	if err := os.WriteFile(file, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := `{"tool":"patch_file","arguments":{"path":"README.md","mode":"batch","append":null,"search":null,"replace":null,"edits":null}}`
	responses := []string{
		`{"tool":"list_files","arguments":{}}`,
		`{"tool":"read_file","arguments":{"path":"README.md"}}`,
		bad, bad, bad,
	}
	socket, closeServer := responseServer(t, responses)
	defer closeServer()
	err := Run(context.Background(), Config{
		Workspace: workspace, BrokerSocket: socket, Model: "qwen2.5-coder:1.5b",
		Task: "edit README", MaxSteps: 10,
	})
	if !errors.Is(err, ErrProtocol) || !strings.Contains(err.Error(), "repeated the same rejected action 3 times") {
		t.Fatalf("Run error = %v, want early repeated-action protocol error", err)
	}
	after, readErr := os.ReadFile(file)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != before {
		t.Fatalf("rejected actions changed file: got %q want %q", after, before)
	}
}
