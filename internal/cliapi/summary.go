// Package cliapi contains versioned data exchanged by MIRAGE frontends.
package cliapi

const RunSchemaV1 = "mirage.run/v1"

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
