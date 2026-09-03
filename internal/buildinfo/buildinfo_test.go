package buildinfo

import (
	"strings"
	"testing"
)

func TestCanonicalCommitIdentity(t *testing.T) {
	const valid = "0123456789abcdef0123456789abcdef01234567"
	if !IsCanonicalCommit(valid) {
		t.Fatalf("canonical commit rejected: %q", valid)
	}
	for _, invalid := range []string{
		"",
		"unknown",
		"UNKNOWN",
		"abc123",
		strings.Repeat("g", 40),
		strings.ToUpper(valid),
		valid[:39],
		valid + "8",
	} {
		if IsCanonicalCommit(invalid) {
			t.Errorf("invalid commit identity accepted: %q", invalid)
		}
	}
}
