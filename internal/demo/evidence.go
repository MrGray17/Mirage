package demo

import (
	"fmt"
	"strings"

	"github.com/MrGray17/Mirage/internal/runtime/diagnostics"
)

const probePrefix = "MIRAGE_DEMO/v1\t"

type probeRecord struct {
	operation string
	resource  string
	status    string
	enforced  string
}

func parseProbeEvidence(scenario string, diagnostic diagnostics.Record) ([]Attempt, error) {
	if diagnostic.StdoutTruncated || diagnostic.StderrTruncated {
		return nil, fmt.Errorf("%w: probe output was truncated", ErrInvalidEvidence)
	}
	var records []probeRecord
	for _, line := range strings.Split(strings.TrimSpace(diagnostic.Stdout), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if !strings.HasPrefix(line, probePrefix) {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 5 || parts[0] != "MIRAGE_DEMO/v1" {
			return nil, fmt.Errorf("%w: malformed probe record", ErrInvalidEvidence)
		}
		records = append(records, probeRecord{parts[1], parts[2], parts[3], parts[4]})
	}

	expected := maliciousProbeRecords()
	if scenario == ScenarioBenign {
		expected = benignProbeRecords()
	}
	if len(records) != len(expected) {
		return nil, fmt.Errorf("%w: got %d probe records, want %d", ErrInvalidEvidence, len(records), len(expected))
	}
	for index := range expected {
		if records[index] != expected[index] {
			return nil, fmt.Errorf("%w: probe record %d differs from the bound scenario", ErrInvalidEvidence, index+1)
		}
	}

	attempts := make([]Attempt, 0, len(expected)/2)
	for index := 0; index < len(records); index += 2 {
		started, completed := records[index], records[index+1]
		if started.status != "ATTEMPTED" || started.operation != completed.operation || started.resource != completed.resource || started.enforced != completed.enforced {
			return nil, fmt.Errorf("%w: incomplete probe pair", ErrInvalidEvidence)
		}
		disposition := completed.status
		if completed.resource == "/workspace/README.md" && completed.status == "SUCCEEDED" {
			disposition = "AUTHORIZED"
		}
		attempts = append(attempts, Attempt{
			Operation:   completed.operation,
			Resource:    completed.resource,
			Disposition: disposition,
			EnforcedBy:  completed.enforced,
		})
	}
	return attempts, nil
}

func maliciousProbeRecords() []probeRecord {
	return []probeRecord{
		{"READ", "/workspace/.env", "ATTEMPTED", "snapshot-secret-exclusion"},
		{"READ", "/workspace/.env", "DENIED", "snapshot-secret-exclusion"},
		{"POST", "http://198.51.100.1/", "ATTEMPTED", "sandbox-network-none"},
		{"POST", "http://198.51.100.1/", "DENIED", "sandbox-network-none"},
		{"WRITE", "/etc/mirage-protected", "ATTEMPTED", "read-only-root"},
		{"WRITE", "/etc/mirage-protected", "DENIED", "read-only-root"},
		{"WRITE", "/workspace/README.md", "ATTEMPTED", "effect-contract"},
		{"WRITE", "/workspace/README.md", "SUCCEEDED", "effect-contract"},
	}
}

func benignProbeRecords() []probeRecord {
	return []probeRecord{
		{"WRITE", "/workspace/README.md", "ATTEMPTED", "effect-contract"},
		{"WRITE", "/workspace/README.md", "SUCCEEDED", "effect-contract"},
	}
}
