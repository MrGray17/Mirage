package observatory

import (
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
