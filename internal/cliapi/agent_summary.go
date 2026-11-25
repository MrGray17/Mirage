package cliapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/MrGray17/Mirage/internal/limits"
)

const AgentRunSchemaV2 = "mirage.agent-run/v2"

type AgentRunSummary struct {
	Schema          string `json:"schema"`
	RunID           string `json:"run_id"`
	Agent           string `json:"agent"`
	Outcome         string `json:"outcome"`
	Attempted       int    `json:"attempted"`
	Authorized      int    `json:"authorized"`
	Denied          int    `json:"denied"`
	Observed        int    `json:"observed"`
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

// ParseAgentRunSummary accepts exactly one versioned agent-run summary and
// validates the evidence invariants before a frontend or integration trusts it.
func ParseAgentRunSummary(encoded []byte) (AgentRunSummary, error) {
	var summary AgentRunSummary
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&summary); err != nil {
		return AgentRunSummary{}, fmt.Errorf("decode agent run summary: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return AgentRunSummary{}, fmt.Errorf("decode agent run summary: %w", err)
	}
	if err := summary.Validate(); err != nil {
		return AgentRunSummary{}, err
	}
	return summary, nil
}

func (s AgentRunSummary) Validate() error {
	if s.Schema != AgentRunSchemaV2 || !runIDPattern.MatchString(s.RunID) || s.Agent != "structured-qwen-agent" {
		return errors.New("invalid agent run summary: identity")
	}
	if s.Attempted != 1 || s.Authorized+s.Denied != s.Attempted || s.Observed < 0 || s.Observed > limits.MaxTreeMutations || !s.ReceiptValid || !s.CleanupComplete {
		return errors.New("invalid agent run summary: evidence accounting")
	}
	switch s.Outcome {
	case "COMMITTED":
		if s.Verification != "PASSED" || s.Authorized != 1 || s.Denied != 0 || s.Observed != 1 || s.Committed != 1 {
			return errors.New("invalid agent run summary: committed outcome")
		}
	case "REJECTED":
		if s.Verification != "REJECTED" || s.Authorized != 0 || s.Denied != 1 || s.Committed != 0 {
			return errors.New("invalid agent run summary: rejected outcome")
		}
	default:
		return fmt.Errorf("invalid agent run summary: outcome %q", s.Outcome)
	}
	if !sha256Pattern.MatchString(s.GraphHash) || !sha256Pattern.MatchString(s.ReceiptHash) {
		return errors.New("invalid agent run summary: evidence identity")
	}
	for name, value := range map[string]string{"receipt": s.ReceiptPath, "observatory": s.ObservatoryPath, "workspace": s.WorkspacePath} {
		if value == "" || (!strings.HasPrefix(value, "/") && !windowsAbsolutePath(value)) || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("invalid agent run summary: %s path", name)
		}
	}
	return nil
}

func windowsAbsolutePath(value string) bool {
	return len(value) >= 3 && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) && value[1] == ':' && (value[2] == '\\' || value[2] == '/')
}
