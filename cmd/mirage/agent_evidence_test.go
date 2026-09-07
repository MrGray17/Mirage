package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/MrGray17/Mirage/internal/cliapi"
)

func TestQwenEvidencePreflightRejectsCreateOnlyCollision(t *testing.T) {
	root := t.TempDir()
	spec := qwenProductSpec{RunID: "coding-agent-test", OutputDir: root}
	if err := preflightQwenEvidence(spec); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(root, spec.RunID, "receipt.json")
	if err := os.MkdirAll(filepath.Dir(receiptPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receiptPath, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := preflightQwenEvidence(spec); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("collision error=%v", err)
	}
}

func TestQwenEvidencePreflightRejectsOutputsInsideReality(t *testing.T) {
	real := t.TempDir()
	for _, spec := range []qwenProductSpec{
		{RunID: "coding-agent-test", RealWorkspace: real, OutputDir: filepath.Join(real, "evidence")},
		{RunID: "coding-agent-test", RealWorkspace: real, EvidenceOut: filepath.Join(real, "receipt.json")},
		{RunID: "coding-agent-test", RealWorkspace: real, EvidenceOut: filepath.Join(t.TempDir(), "receipt.json"), ObservatoryOut: filepath.Join(real, "observatory.html")},
	} {
		if err := preflightQwenEvidence(spec); err == nil || !strings.Contains(err.Error(), "outside the trusted real workspace") {
			t.Fatalf("inside-real evidence output error=%v", err)
		}
	}
}

func TestQwenEvidencePreflightRejectsSymlinkAliasIntoReality(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ordinary Windows users cannot reliably create directory symlinks")
	}
	real := t.TempDir()
	aliasRoot := t.TempDir()
	alias := filepath.Join(aliasRoot, "real-alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	spec := qwenProductSpec{RunID: "coding-agent-test", RealWorkspace: real, OutputDir: filepath.Join(alias, "evidence")}
	if err := preflightQwenEvidence(spec); err == nil || !strings.Contains(err.Error(), "outside the trusted real workspace") {
		t.Fatalf("symlink-aliased evidence output error=%v", err)
	}
}

func TestQwenJSONSummaryIsOneStructuredValue(t *testing.T) {
	summary := cliapi.AgentRunSummary{
		Schema: cliapi.AgentRunSchemaV2, RunID: "coding-agent-0123456789abcdef", Agent: "structured-qwen-agent", Outcome: "REJECTED",
		Attempted: 1, Denied: 1, Observed: 1, Verification: "REJECTED", ReceiptValid: true,
		GraphHash: "sha256:" + strings.Repeat("a", 64), ReceiptHash: "sha256:" + strings.Repeat("b", 64),
		ReceiptPath: "/receipt.json", ObservatoryPath: "/observatory.html", WorkspacePath: "/workspace", CleanupComplete: true,
	}
	var output bytes.Buffer
	if err := emitQwenSummary(&output, summary, "json"); err != nil {
		t.Fatal(err)
	}
	var decoded cliapi.AgentRunSummary
	decoder := json.NewDecoder(&output)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil || decoded != summary {
		t.Fatalf("decoded=%#v error=%v output=%q", decoded, err, output.String())
	}
}
