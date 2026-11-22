package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/MrGray17/Mirage/internal/cliapi"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPStdioProcessHandshake(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=^TestMCPStdioHelper$")
	command.Env = append(os.Environ(), "MIRAGE_MCP_TEST_HELPER=1")
	client := mcp.NewClient(&mcp.Implementation{Name: "mirage-stdio-test", Version: "1"}, nil)
	session, err := client.Connect(context.Background(), &mcp.CommandTransport{Command: command}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Tools) != 3 || result.Tools[0].Name != "mirage_doctor" || result.Tools[1].Name != "mirage_edit_file" || result.Tools[2].Name != "mirage_verify_receipt" {
		t.Fatalf("stdio tools = %#v", result.Tools)
	}
}

func TestMCPStdioHelper(t *testing.T) {
	if os.Getenv("MIRAGE_MCP_TEST_HELPER") != "1" {
		return
	}
	if err := runMCP(nil, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestHarnessIntegrationManifestsAreValidAndLaunchMirageMCP(t *testing.T) {
	root := filepath.Join("..", "..", "integrations")
	jsonFiles := []string{
		"claude-code.mcp.json",
		"opencode.jsonc",
		filepath.Join("agent-plugin", "plugin.json"),
		filepath.Join("agent-plugin", "mcp.json"),
		filepath.Join("claude-plugin", ".claude-plugin", "plugin.json"),
		filepath.Join("claude-plugin", ".mcp.json"),
	}
	for _, relative := range jsonFiles {
		encoded, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatalf("read %s: %v", relative, err)
		}
		var manifest any
		if err := json.Unmarshal(encoded, &manifest); err != nil {
			t.Fatalf("decode %s: %v", relative, err)
		}
	}
	for _, relative := range []string{
		"claude-code.mcp.json",
		filepath.Join("agent-plugin", "mcp.json"),
		filepath.Join("claude-plugin", ".mcp.json"),
	} {
		encoded, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(encoded, []byte(`"command": "mirage"`)) || !bytes.Contains(encoded, []byte(`"args": ["mcp"]`)) {
			t.Fatalf("%s does not launch 'mirage mcp'", relative)
		}
	}
	codex, err := os.ReadFile(filepath.Join(root, "codex.config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(codex, []byte(`command = "mirage"`)) || !bytes.Contains(codex, []byte(`args = ["mcp"]`)) {
		t.Fatal("Codex configuration does not launch 'mirage mcp'")
	}
}

func TestMCPClientDiscoversNarrowAnnotatedTools(t *testing.T) {
	session := connectMCPTestClient(t, newMirageMCPServer(func([]string, io.Writer, io.Writer) error {
		return errors.New("runner should not be called while listing tools")
	}))
	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	wantNames := []string{"mirage_doctor", "mirage_edit_file", "mirage_verify_receipt"}
	gotNames := make([]string, 0, len(result.Tools))
	for _, tool := range result.Tools {
		gotNames = append(gotNames, tool.Name)
		if tool.Annotations == nil || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
			t.Fatalf("tool %q is missing its closed-world annotation: %#v", tool.Name, tool.Annotations)
		}
		switch tool.Name {
		case "mirage_edit_file":
			if tool.Annotations.ReadOnlyHint || tool.Annotations.DestructiveHint == nil || !*tool.Annotations.DestructiveHint {
				t.Fatalf("edit annotations do not describe a write: %#v", tool.Annotations)
			}
		default:
			if !tool.Annotations.ReadOnlyHint {
				t.Fatalf("read-only tool %q is not marked read-only", tool.Name)
			}
		}
	}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("tools = %#v, want %#v", gotNames, wantNames)
	}
}

func TestMCPEditCallsMachineInterfaceAndReturnsValidatedEvidence(t *testing.T) {
	workspace := t.TempDir()
	outputDir := filepath.Join(t.TempDir(), "evidence")
	receiptPath := filepath.Join(outputDir, "receipt.json")
	observatoryPath := filepath.Join(outputDir, "receipt.observatory.html")
	summary := validMCPAgentSummary(workspace, receiptPath, observatoryPath)
	var called bool
	runner := func(args []string, stdout, stderr io.Writer) error {
		called = true
		want := []string{
			"edit", "--yes", "--format", "json",
			"--workspace", workspace,
			"--output-dir", outputDir,
			"README.md", "Improve the introduction",
		}
		if !reflect.DeepEqual(args, want) {
			t.Fatalf("MCP edit args = %#v, want %#v", args, want)
		}
		return json.NewEncoder(stdout).Encode(summary)
	}
	session := connectMCPTestClient(t, newMirageMCPServer(runner))
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "mirage_edit_file",
		Arguments: map[string]any{
			"file": "README.md", "task": "Improve the introduction", "workspace": workspace,
			"output_dir": outputDir, "approved": true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError || !called {
		t.Fatalf("edit result error=%t called=%t content=%#v", result.IsError, called, result.Content)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cliapi.ParseAgentRunSummary(encoded)
	if err != nil {
		t.Fatalf("structured result is not a valid agent summary: %v\n%s", err, encoded)
	}
	if !reflect.DeepEqual(got, summary) {
		t.Fatalf("summary = %#v, want %#v", got, summary)
	}
}

func TestMCPEditRequiresExplicitApprovalBeforeRunner(t *testing.T) {
	called := false
	session := connectMCPTestClient(t, newMirageMCPServer(func([]string, io.Writer, io.Writer) error {
		called = true
		return nil
	}))
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "mirage_edit_file",
		Arguments: map[string]any{"file": "README.md", "task": "Change it", "approved": false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError || called || !strings.Contains(mcpText(t, result), "edit not authorized") {
		t.Fatalf("unauthorized edit result error=%t called=%t content=%q", result.IsError, called, mcpText(t, result))
	}
}

func TestMCPDoctorAndReceiptVerificationUseExistingCLIContracts(t *testing.T) {
	report := doctorReport{Ready: true, EditReady: true, ImageAvailable: true, QwenImageAvailable: true, HelperImageAvailable: true}
	var mu sync.Mutex
	var calls [][]string
	runner := func(args []string, stdout, stderr io.Writer) error {
		mu.Lock()
		calls = append(calls, append([]string(nil), args...))
		mu.Unlock()
		switch args[0] {
		case "doctor":
			return json.NewEncoder(stdout).Encode(report)
		case "verify":
			_, err := io.WriteString(stdout, "VALID receipt=sha256:"+strings.Repeat("a", 64)+" run=test graph=sha256:"+strings.Repeat("b", 64)+" committed=1\n")
			return err
		default:
			return errors.New("unexpected command")
		}
	}
	session := connectMCPTestClient(t, newMirageMCPServer(runner))
	doctor, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "mirage_doctor", Arguments: map[string]any{}})
	if err != nil || doctor.IsError {
		t.Fatalf("doctor error=%v result=%#v", err, doctor)
	}
	verify, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "mirage_verify_receipt", Arguments: map[string]any{"receipt": "/tmp/receipt.json"}})
	if err != nil || verify.IsError || !strings.Contains(mcpText(t, verify), `"valid":true`) {
		t.Fatalf("verify error=%v result=%#v text=%q", err, verify, mcpText(t, verify))
	}
	mu.Lock()
	defer mu.Unlock()
	wantCalls := [][]string{{"doctor", "--json"}, {"verify", "/tmp/receipt.json"}}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
}

func TestMCPRejectsInvalidBackendJSONAndBoundsOutput(t *testing.T) {
	for name, runner := range map[string]mcpCommandRunner{
		"unknown JSON field": func(_ []string, stdout, _ io.Writer) error {
			_, _ = io.WriteString(stdout, `{"ready":true,"unknown":true}`)
			return nil
		},
		"oversized output": func(_ []string, stdout, _ io.Writer) error {
			_, _ = io.WriteString(stdout, strings.Repeat("x", mcpCommandOutputLimit+1))
			return nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			session := connectMCPTestClient(t, newMirageMCPServer(runner))
			result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "mirage_doctor", Arguments: map[string]any{}})
			if err != nil {
				t.Fatal(err)
			}
			if !result.IsError {
				t.Fatalf("invalid backend output was accepted: %#v", result)
			}
		})
	}
}

func connectMCPTestClient(t *testing.T, server *mcp.Server) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "mirage-test", Version: "1"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		_ = serverSession.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = clientSession.Close()
		_ = serverSession.Close()
	})
	return clientSession
}

func validMCPAgentSummary(workspace, receiptPath, observatoryPath string) cliapi.AgentRunSummary {
	return cliapi.AgentRunSummary{
		Schema: cliapi.AgentRunSchemaV2, RunID: "coding-agent-test", Agent: "structured-qwen-agent",
		Outcome: "COMMITTED", Attempted: 1, Authorized: 1, Denied: 0, Observed: 1, Committed: 1,
		Verification: "PASSED", ReceiptValid: true,
		GraphHash: "sha256:" + strings.Repeat("a", 64), ReceiptHash: "sha256:" + strings.Repeat("b", 64),
		ReceiptPath: receiptPath, ObservatoryPath: observatoryPath, WorkspacePath: workspace, CleanupComplete: true,
	}
}

func mcpText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if len(result.Content) == 0 {
		return ""
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("first MCP content is %T, want text", result.Content[0])
	}
	return text.Text
}
