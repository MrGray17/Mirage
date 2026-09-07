package cliapi

import (
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
	rejected.Committed = 1
	if err := rejected.Validate(); err == nil {
		t.Fatal("rejected summary claimed a commit")
	}
}
