// Package diagnostics defines bounded, redacted M4.4 failure evidence. It is
// observability only: diagnostic records never grant commit authority.
package diagnostics

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

type Class string

const (
	BrokerConnect  Class = "BROKER_CONNECT"
	ProviderHTTP   Class = "PROVIDER_HTTP"
	ProviderSchema Class = "PROVIDER_SCHEMA"
	AgentProtocol  Class = "AGENT_PROTOCOL"
	AgentExit      Class = "AGENT_EXIT"
	Timeout        Class = "TIMEOUT"

	TruncationMarker = "\n[diagnostic output truncated]"
)

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bBearer[ \t]+[A-Za-z0-9._~+/=-]{8,}`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{8,}\b`),
	regexp.MustCompile(`\b(?:ghp|github_pat)_[A-Za-z0-9_]{8,}\b`),
	regexp.MustCompile(`(?i)\b[A-Za-z0-9_]*(?:api[_-]?key|password|secret|token)[ \t]*[=:][ \t]*["']?[^\s"']{4,}`),
}

// Record is safe to retain after freeze. Stdout, Stderr, and Message must be
// populated only through NewRecord or SanitizeRecord.
type Record struct {
	Class           Class
	Stage           string
	ProviderStatus  int
	AgentExitCode   int
	Message         string
	Stdout          string
	Stderr          string
	StdoutTruncated bool
	StderrTruncated bool
}

func Sanitize(value string, knownSecrets ...string) string {
	value = strings.ToValidUTF8(value, "�")
	for _, secret := range knownSecrets {
		if secret = strings.TrimSpace(secret); secret != "" {
			value = strings.ReplaceAll(value, secret, "[REDACTED]")
		}
	}
	for _, pattern := range secretPatterns {
		value = pattern.ReplaceAllStringFunc(value, func(match string) string {
			if index := strings.IndexAny(match, "=:"); index >= 0 {
				return match[:index+1] + "[REDACTED]"
			}
			if strings.HasPrefix(strings.ToLower(match), "bearer") {
				return "Bearer [REDACTED]"
			}
			return "[REDACTED]"
		})
	}
	return value
}

// Bound applies a byte cap after redaction and never returns invalid UTF-8.
func Bound(value string, limit int) (string, bool) {
	if limit < 1 {
		return "", value != ""
	}
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= limit {
		return value, false
	}
	cut := limit
	for cut > 0 && !utf8.ValidString(value[:cut]) {
		cut--
	}
	return value[:cut] + TruncationMarker, true
}

func SanitizeRecord(record Record, limit int, knownSecrets ...string) Record {
	record.Stage, _ = Bound(Sanitize(record.Stage, knownSecrets...), limit)
	record.Message, _ = Bound(Sanitize(record.Message, knownSecrets...), limit)
	stdout := Sanitize(record.Stdout, knownSecrets...)
	stderr := Sanitize(record.Stderr, knownSecrets...)
	record.Stdout, record.StdoutTruncated = Bound(stdout, limit)
	record.Stderr, record.StderrTruncated = Bound(stderr, limit)
	return record
}
