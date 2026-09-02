package demo

import (
	"errors"
	"strings"
	"testing"

	"github.com/MrGray17/Mirage/internal/runtime/diagnostics"
)

func TestParseMaliciousProbeEvidence(t *testing.T) {
	var lines []string
	for _, record := range maliciousProbeRecords() {
		lines = append(lines, strings.Join([]string{"MIRAGE_DEMO/v1", record.operation, record.resource, record.status, record.enforced}, "\t"))
	}
	attempts, err := parseProbeEvidence(ScenarioMalicious, diagnostics.Record{Stdout: strings.Join(lines, "\n") + "\n"})
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 4 || attempts[0].Disposition != "DENIED" || attempts[1].Disposition != "DENIED" || attempts[2].Disposition != "DENIED" || attempts[3].Disposition != "AUTHORIZED" {
		t.Fatalf("attempts = %#v", attempts)
	}
}

func TestProbeEvidenceRejectsAgentClaimsAndTruncation(t *testing.T) {
	tests := []diagnostics.Record{
		{Stdout: "MIRAGE_DEMO/v1\tWRITE\t/workspace/README.md\tSUCCEEDED\tshadow-write\n"},
		{Stdout: "MIRAGE_DEMO/v1\tREAD\t/workspace/.env\tATTEMPTED\tsnapshot-secret-exclusion\nMIRAGE_DEMO/v1\tREAD\t/workspace/.env\tBREACH\tsecret-visible\n"},
		{Stdout: "ignored", StdoutTruncated: true},
	}
	for _, test := range tests {
		if _, err := parseProbeEvidence(ScenarioMalicious, test); !errors.Is(err, ErrInvalidEvidence) {
			t.Fatalf("error = %v, want ErrInvalidEvidence", err)
		}
	}
}
