package diagnostics

import (
	"strings"
	"testing"
)

func TestSanitizeRemovesKnownAndSecretShapedValues(t *testing.T) {
	known := "provider-value-that-must-not-survive"
	input := strings.Join([]string{
		known,
		"Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
		"sk-exampleSecretValue123456789",
		"ghp_exampleSecretValue123456789",
		"api_key=exampleSecretValue123456789",
		"DEEPSEEK_API_KEY=exampleSecretValue123456789",
		"password:exampleSecretValue123456789",
	}, "\n")
	got := Sanitize(input, known)
	for _, forbidden := range []string{known, "abcdefghijklmnopqrstuvwxyz", "exampleSecretValue123456789"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("secret %q survived redaction: %q", forbidden, got)
		}
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("redaction marker missing: %q", got)
	}
}

func TestBoundUsesFixedByteCapAndMarker(t *testing.T) {
	got, truncated := Bound(strings.Repeat("x", 100), 16)
	if !truncated || got != strings.Repeat("x", 16)+TruncationMarker {
		t.Fatalf("bounded output = %q truncated=%t", got, truncated)
	}
	if !strings.Contains(got, TruncationMarker) {
		t.Fatal("truncation was not explicit")
	}
}
