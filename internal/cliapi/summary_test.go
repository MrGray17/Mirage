package cliapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func validRunSummary() RunSummary {
	return RunSummary{
		Schema: RunSchemaV1, RunID: "competition-malicious-0123456789abcdef", Scenario: "malicious",
		Attempted: 4, Authorized: 1, Denied: 3, Committed: 1, Verification: "PASSED",
		ReceiptValid: true, GraphHash: "sha256:" + strings.Repeat("a", 64),
		ReceiptHash: "sha256:" + strings.Repeat("b", 64), ReceiptPath: "/tmp/receipt.json",
		ObservatoryPath: "/tmp/observatory.html", WorkspacePath: "/tmp/workspace", CleanupComplete: true,
	}
}

func TestParseRunSummaryAcceptsExactSuccessfulShape(t *testing.T) {
	malicious := validRunSummary()
	benign := validRunSummary()
	benign.Scenario, benign.Attempted, benign.Denied = "benign", 1, 0
	for _, summary := range []RunSummary{malicious, benign} {
		encoded, err := json.Marshal(summary)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseRunSummary(encoded); err != nil {
			t.Fatalf("valid summary rejected: %v", err)
		}
	}
}

func TestParseRunSummaryRejectsMalformedUnknownAndTrailingJSON(t *testing.T) {
	valid, err := json.Marshal(validRunSummary())
	if err != nil {
		t.Fatal(err)
	}
	unknown := append([]byte(nil), valid[:len(valid)-1]...)
	unknown = append(unknown, []byte(`,"unexpected":true}`)...)
	for _, encoded := range [][]byte{
		[]byte(`{"schema":`),
		unknown,
		append(append([]byte(nil), valid...), []byte(` {}`)...),
	} {
		if _, err := ParseRunSummary(encoded); err == nil {
			t.Fatalf("invalid summary accepted: %s", encoded)
		}
	}
}

func TestParseRunSummaryRejectsMissingOrFalseSecurityEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RunSummary)
	}{
		{"missing run identity", func(s *RunSummary) { s.RunID = "" }},
		{"bad accounting", func(s *RunSummary) { s.Denied = 2 }},
		{"failed verification", func(s *RunSummary) { s.Verification = "FAILED" }},
		{"invalid receipt", func(s *RunSummary) { s.ReceiptValid = false }},
		{"incomplete cleanup", func(s *RunSummary) { s.CleanupComplete = false }},
		{"invalid graph hash", func(s *RunSummary) { s.GraphHash = "sha256:no" }},
		{"relative evidence path", func(s *RunSummary) { s.ReceiptPath = "receipt.json" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			summary := validRunSummary()
			test.mutate(&summary)
			encoded, err := json.Marshal(summary)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseRunSummary(encoded); err == nil {
				t.Fatal("invalid summary accepted")
			}
		})
	}
}
