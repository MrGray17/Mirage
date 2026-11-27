package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MrGray17/Mirage/internal/cliapi"
	"github.com/MrGray17/Mirage/internal/demo"
)

func TestExportLabDashboardPreview(t *testing.T) {
	dir := os.Getenv("MIRAGE_DASHBOARD_PREVIEW_DIR")
	if dir == "" {
		t.Skip("set MIRAGE_DASHBOARD_PREVIEW_DIR to export a synthetic test report")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	report := labReport{
		Schema: "mirage.attack-lab/v1", Platform: "synthetic preview (not live execution)", Image: demo.OfficialImage,
		Planned: 3, Passed: 2, Trials: []labTrial{
			{Scenario: "benign", DurationMS: 1200, Summary: cliapi.RunSummary{Committed: 1}, ReportLink: "committed.html"},
			{Scenario: "malicious", DurationMS: 1800, Summary: cliapi.RunSummary{Denied: 3, Committed: 1}, ReportLink: "committed.html"},
			{Scenario: "malicious", DurationMS: 2100, Failure: "Synthetic failure: outcome unavailable"},
		},
	}
	var output strings.Builder
	if err := labTemplate.Execute(&output, report); err != nil {
		t.Fatal(err)
	}
	html := strings.Replace(output.String(), "Measured outcomes from real isolated workloads. No simulated metrics.", "Synthetic design preview — not measured execution results.", 1)
	if err := os.WriteFile(filepath.Join(dir, "lab.html"), []byte(html), 0o600); err != nil {
		t.Fatal(err)
	}
}
