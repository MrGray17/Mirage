package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/MrGray17/Mirage/internal/runtime/diagnostics"
	"github.com/MrGray17/Mirage/internal/runtime/modelbroker"
)

func TestRunRequiresExplicitHostileFixtureCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(nil, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunRequiresPinnedImageInput(t *testing.T) {
	t.Setenv("MIRAGE_HOSTILE_IMAGE", "")
	var stdout, stderr bytes.Buffer
	if err := run([]string{"run", "hostile-fixture"}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "--image") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunAgentRequiresNarrowInputsBeforeWorkspaceCreation(t *testing.T) {
	t.Setenv("MIRAGE_AGENT_IMAGE", "")
	t.Setenv("MIRAGE_HELPER_IMAGE", "")
	var stdout, stderr bytes.Buffer
	if err := run([]string{"run", "agent"}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "--image") {
		t.Fatalf("missing images error = %v", err)
	}

	image := "example.invalid/image@sha256:" + strings.Repeat("0", 64)
	if err := run([]string{"run", "agent", "--image", image, "--helper-image", image}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "--allow") {
		t.Fatalf("missing authority error = %v", err)
	}
	if err := run([]string{"run", "agent", "--image", image, "--helper-image", image, "--allow", "/workspace/README.md"}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "command") {
		t.Fatalf("missing command error = %v", err)
	}
	if err := run([]string{"run", "agent", "--image", image, "--helper-image", image, "--allow", "/workspace/README.md", "--model", "gpt-test", "--", "/agent"}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "model broker") {
		t.Fatalf("unbrokered model error = %v", err)
	}
	if err := run([]string{"run", "agent", "--image", image, "--helper-image", image, "--allow", "/workspace/README.md", "--model-broker", "deepseek", "--model", "deepseek-v4-pro", "--", "/agent"}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "exactly "+modelbroker.DeepSeekV4Flash) {
		t.Fatalf("DeepSeek fallback error = %v", err)
	}
}

func TestValidProviderResponseRejectedByAgentClassifiesProtocol(t *testing.T) {
	agent := diagnostics.Record{
		Class:         diagnostics.AgentExit,
		Stage:         "agent_exit",
		AgentExitCode: 1,
		Stderr:        "unsupported response event",
	}
	got := resolveAgentDiagnostic(agent, modelbroker.DiagnosticSnapshot{SuccessfulResponses: 1})
	if got.Class != diagnostics.AgentProtocol || got.Stage != "agent_protocol" || got.Stderr != agent.Stderr {
		t.Fatalf("diagnostic = %#v", got)
	}
}

func TestBrokerFailureClassificationPrecedesGenericAgentExit(t *testing.T) {
	agent := diagnostics.Record{Class: diagnostics.AgentExit, AgentExitCode: 1, Stderr: "agent stopped"}
	broker := modelbroker.DiagnosticSnapshot{Failure: diagnostics.Record{Class: diagnostics.ProviderHTTP, Stage: "provider_status", ProviderStatus: 429}}
	got := resolveAgentDiagnostic(agent, broker)
	if got.Class != diagnostics.ProviderHTTP || got.ProviderStatus != 429 || got.Stderr != agent.Stderr {
		t.Fatalf("diagnostic = %#v", got)
	}
}

func TestBrokerPreflightExitClassifiesConnectBeforeAgentLaunch(t *testing.T) {
	agent := diagnostics.Record{Class: diagnostics.AgentExit, AgentExitCode: brokerPreflightExit, Stderr: "MIRAGE_DIAGNOSTIC_CLASS=BROKER_CONNECT"}
	got := resolveAgentDiagnostic(agent, modelbroker.DiagnosticSnapshot{})
	if got.Class != diagnostics.BrokerConnect || got.Stage != "sandbox_broker_preflight" {
		t.Fatalf("diagnostic = %#v", got)
	}

	connected := resolveAgentDiagnostic(agent, modelbroker.DiagnosticSnapshot{PreflightConnections: 1})
	if connected.Class == diagnostics.BrokerConnect {
		t.Fatalf("successful preflight misclassified: %#v", connected)
	}
}

func TestRunRejectsUnsafeDurationBeforeWorkspaceCreation(t *testing.T) {
	t.Setenv("MIRAGE_HOSTILE_IMAGE", "example.invalid/image@sha256:"+strings.Repeat("0", 64))
	var stdout, stderr bytes.Buffer
	if err := run([]string{"run", "hostile-fixture", "--duration", "0s"}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "--duration") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunFailsClosedAndCleansWorkspaceOnNonLinuxHost(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("non-Linux fail-closed behavior")
	}
	real := mainTestWorkspace(t)
	if err := os.WriteFile(filepath.Join(real, "README.md"), []byte("real\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := m42TemporaryDirectories(t)
	image := "example.invalid/image@sha256:" + strings.Repeat("0", 64)
	var stdout, stderr bytes.Buffer
	err := run([]string{"run", "hostile-fixture", "--workspace", real, "--image", image, "--duration", "1s"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "requires a Linux Mirage host") {
		t.Fatalf("error = %v", err)
	}
	after := m42TemporaryDirectories(t)
	for path := range after {
		if _, existed := before[path]; !existed {
			t.Errorf("failed launch leaked disposable workspace %s", path)
		}
	}
}

func mainTestWorkspace(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp(".", ".mirage-main-test-")
	if err != nil {
		t.Fatalf("create main test workspace: %v", err)
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		t.Fatalf("resolve main test workspace: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(absolute); err != nil {
			t.Errorf("remove main test workspace: %v", err)
		}
	})
	return absolute
}

func m42TemporaryDirectories(t *testing.T) map[string]struct{} {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(os.TempDir(), "mirage-m42-*"))
	if err != nil {
		t.Fatalf("list M4.1 temporary directories: %v", err)
	}
	result := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		result[match] = struct{}{}
	}
	return result
}
