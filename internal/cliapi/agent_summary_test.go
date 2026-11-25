package cliapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAgentRunSummaryAcceptsCommittedAndRejectedEvidence(t *testing.T) {
	base := AgentRunSummary{
		Schema: AgentRunSchemaV2, RunID: "coding-agent-0123456789abcdef", Agent: "structured-qwen-agent",
		Attempted: 1, ReceiptValid: true, GraphHash: "sha256:" + strings.Repeat("a", 64), ReceiptHash: "sha256:" + strings.Repeat("b", 64),
		ReceiptPath: "/receipt.json", ObservatoryPath: "/observatory.html", WorkspacePath: "/workspace", CleanupComplete: true,
	}
	committed := base
	committed.Outcome, committed.Verification, committed.Authorized, committed.Observed, committed.Committed = "COMMITTED", "PASSED", 1, 1, 1
	if err := committed.Validate(); err != nil {
		t.Fatal(err)
	}
	rejected := base
	rejected.Outcome, rejected.Verification, rejected.Denied, rejected.Observed = "REJECTED", "REJECTED", 1, 1
	if err := rejected.Validate(); err != nil {
		t.Fatal(err)
	}
	rejected.Observed = 2
	if err := rejected.Validate(); err != nil {
		t.Fatalf("multi-mutation rejection: %v", err)
	}
	rejected.Committed = 1
	if err := rejected.Validate(); err == nil {
		t.Fatal("rejected summary claimed a commit")
	}
}

func TestParseAgentRunSummaryIsStrict(t *testing.T) {
	summary := AgentRunSummary{
		Schema: AgentRunSchemaV2, RunID: "coding-agent-test", Agent: "structured-qwen-agent",
		Outcome: "COMMITTED", Attempted: 1, Authorized: 1, Observed: 1, Committed: 1,
		Verification: "PASSED", ReceiptValid: true,
		GraphHash: "sha256:" + strings.Repeat("a", 64), ReceiptHash: "sha256:" + strings.Repeat("b", 64),
		ReceiptPath: "/tmp/receipt.json", ObservatoryPath: "/tmp/receipt.html", WorkspacePath: "/tmp/project", CleanupComplete: true,
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseAgentRunSummary(encoded)
	if err != nil || got != summary {
		t.Fatalf("parsed summary = %#v, error = %v", got, err)
	}
	for _, invalid := range [][]byte{
		append(append([]byte(nil), encoded...), []byte(" {}")...),
		[]byte(`{"schema":"mirage.agent-run/v2","unknown":true}`),
	} {
		if _, err := ParseAgentRunSummary(invalid); err == nil {
			t.Fatalf("invalid summary accepted: %s", invalid)
		}
	}
}
