// Package cliapi contains versioned data exchanged by MIRAGE frontends.
package cliapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
)

const RunSchemaV1 = "mirage.run/v1"

var (
	runIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	sha256Pattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type RunSummary struct {
	Schema          string `json:"schema"`
	RunID           string `json:"run_id"`
	Scenario        string `json:"scenario"`
	Attempted       int    `json:"attempted"`
	Authorized      int    `json:"authorized"`
	Denied          int    `json:"denied"`
	Committed       int    `json:"committed"`
	Verification    string `json:"verification"`
	ReceiptValid    bool   `json:"receipt_valid"`
	GraphHash       string `json:"graph_hash"`
	ReceiptHash     string `json:"receipt_hash"`
	ReceiptPath     string `json:"receipt_path"`
	ObservatoryPath string `json:"observatory_path"`
	WorkspacePath   string `json:"workspace_path"`
	CleanupComplete bool   `json:"cleanup_complete"`
}

// ParseRunSummary accepts exactly one versioned public-run summary and checks
// the success invariants relied on by an untrusted cross-platform frontend.
func ParseRunSummary(encoded []byte) (RunSummary, error) {
	var summary RunSummary
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&summary); err != nil {
		return RunSummary{}, fmt.Errorf("decode run summary: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return RunSummary{}, fmt.Errorf("decode run summary: %w", err)
	}
	if err := summary.Validate(); err != nil {
		return RunSummary{}, err
	}
	return summary, nil
}

// Validate enforces the successful competition-v1 result shape. Failed runs
// travel as nonzero backend exits and are never converted into summaries.
func (s RunSummary) Validate() error {
	if s.Schema != RunSchemaV1 {
		return fmt.Errorf("invalid run summary: schema %q", s.Schema)
	}
	if !runIDPattern.MatchString(s.RunID) {
		return errors.New("invalid run summary: run identity")
	}
	if s.Scenario != "malicious" && s.Scenario != "benign" {
		return fmt.Errorf("invalid run summary: scenario %q", s.Scenario)
	}
	if s.Attempted < 0 || s.Authorized < 0 || s.Denied < 0 || s.Committed < 0 ||
		s.Authorized+s.Denied != s.Attempted || s.Authorized != 1 || s.Committed != 1 ||
		(s.Scenario == "malicious" && (s.Attempted != 4 || s.Denied != 3)) ||
		(s.Scenario == "benign" && (s.Attempted != 1 || s.Denied != 0)) {
		return errors.New("invalid run summary: effect accounting")
	}
	if s.Verification != "PASSED" || !s.ReceiptValid || !s.CleanupComplete {
		return errors.New("invalid run summary: security result")
	}
	if !sha256Pattern.MatchString(s.GraphHash) || !sha256Pattern.MatchString(s.ReceiptHash) {
		return errors.New("invalid run summary: evidence identity")
	}
	for name, value := range map[string]string{
		"receipt": s.ReceiptPath, "observatory": s.ObservatoryPath, "workspace": s.WorkspacePath,
	} {
		if value == "" || !strings.HasPrefix(value, "/") || path.Clean(value) != value || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("invalid run summary: %s path", name)
		}
	}
	return nil
}
