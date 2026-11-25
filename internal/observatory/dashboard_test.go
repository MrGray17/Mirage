package observatory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDashboardPresentationRetainsOutcomeAndOfflineDesign(t *testing.T) {
	for _, outcome := range []string{"committed", "rejected"} {
		t.Run(outcome, func(t *testing.T) {
			evidence := testEvidence(t, "Update README.md", "/workspace/README.md", true)
			if outcome == "rejected" {
				evidence = rejectedAgentEvidence(t)
			}
			page, err := Render(evidence)
			if err != nil {
				t.Fatal(err)
			}
			html := string(page)
			for _, marker := range []string{
				`data-outcome="` + outcome + `"`,
				"Attempted effects", "Blocked effects", "Committed mutations",
				"Evidence inspector", "prefers-color-scheme: dark",
				"prefers-reduced-motion: reduce", "Receipt integrity is not a digital signature",
			} {
				if !strings.Contains(html, marker) {
					t.Errorf("missing %q", marker)
				}
			}
			for _, marker := range []string{"__MIRAGE_DESIGN_CSS__", "<link rel=\"stylesheet\"", "@import", "fonts.googleapis.com"} {
				if strings.Contains(html, marker) {
					t.Errorf("unexpected external dependency or unresolved marker %q", marker)
				}
			}
		})
	}
}

// TestExportDashboardPreviews is opt-in. The exported reports are rendered
// from synthetic test receipts, never represented as measured live runs.
func TestExportDashboardPreviews(t *testing.T) {
	dir := os.Getenv("MIRAGE_DASHBOARD_PREVIEW_DIR")
	if dir == "" {
		t.Skip("set MIRAGE_DASHBOARD_PREVIEW_DIR to export synthetic test reports")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"committed", "rejected"} {
		evidence := testEvidence(t, "Update README.md — synthetic preview", "/workspace/README.md", true)
		if name == "rejected" {
			evidence = rejectedAgentEvidence(t)
		}
		page, err := Render(evidence)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".html"), page, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
