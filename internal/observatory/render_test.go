package observatory

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/effectgraph"
	"github.com/MrGray17/Mirage/internal/receipt"
)

func TestRenderVerifiedReceiptAsSingleCausalCanvas(t *testing.T) {
	evidence := testEvidence(t, "Update README.md", "deterministic-malicious-fixture", "/workspace/README.md", true)
	page, err := Render(evidence)
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(page)
	for _, required := range []string{
		"MIRAGE", "transactional security runtime", "Speculative / untrusted", "Untrusted agent",
		"READ", "/workspace/.env", "POST", "http://198.51.100.1/", "/etc/mirage-protected",
		"DENIED", "AUTHORIZED", "Observed mutation", "MODIFY /workspace/README.md", "Verified",
		"Trust boundary", "Trusted reality", "Trusted commit", "Reality",
		"<b>4</b>attempted", "<b>3</b>denied", "<b>1</b>authorized", "<b>1</b>committed",
		"CommittedEffects &sube; AuthorizedEffects", "PASSED",
		evidence.SHA256, evidence.EffectGraphHash, evidence.ContractHash, evidence.CommitPlan,
	} {
		if !strings.Contains(rendered, required) {
			t.Errorf("rendered page missing %q", required)
		}
	}
	if strings.Contains(rendered, "grid-template-columns:minmax(250px") || strings.Contains(rendered, "Execution timeline") || strings.Contains(rendered, "Run summary") {
		t.Fatal("legacy three-column dashboard chrome remains")
	}
}

func TestRenderRejectsInvalidReceipt(t *testing.T) {
	evidence := testEvidence(t, "Update README.md", "fixture", "/workspace/README.md", false)
	evidence.SHA256 = "sha256:forged"
	if _, err := Render(evidence); !errors.Is(err, receipt.ErrInvalidReceipt) {
		t.Fatalf("error=%v, want ErrInvalidReceipt", err)
	}
}

func TestRenderEscapesHostileEvidenceAndHasNoExecutableContent(t *testing.T) {
	task := `</div><style>body{display:none}</style><script>alert(1)</script>`
	resource := `/workspace/README.md"><img src="https://evil.example/x" onerror="alert(1)">`
	evidence := testEvidence(t, task, `fixture"><iframe src="https://evil.example">`, resource, false)
	page, err := Render(evidence)
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(page)
	for _, forbidden := range []string{"<script", "<iframe", "<img", "</style><style>body{display:none}"} {
		if strings.Contains(strings.ToLower(rendered), forbidden) {
			t.Fatalf("hostile evidence became active markup: %q", forbidden)
		}
	}
	for _, escaped := range []string{"&lt;script&gt;", "&lt;img", "&lt;iframe"} {
		if !strings.Contains(rendered, escaped) {
			t.Errorf("rendered page missing escaped value %q", escaped)
		}
	}
	if regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']https?://`).MatchString(rendered) {
		t.Fatal("rendered page contains an external resource reference")
	}
}

func TestRenderUsesStrictSelfContainedPolicy(t *testing.T) {
	evidence := testEvidence(t, "Update README.md", "fixture", "/workspace/README.md", false)
	page, err := Render(evidence)
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(page)
	wantCSP := `default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'`
	if !strings.Contains(rendered, wantCSP) {
		t.Fatalf("strict CSP missing: %s", wantCSP)
	}
	if regexp.MustCompile(`(?i)<script(?:\s|>)`).MatchString(rendered) {
		t.Fatal("Observatory contains a script tag")
	}
	if regexp.MustCompile(`(?i)<(?:link|iframe|object|embed)(?:\s|>)`).MatchString(rendered) {
		t.Fatal("Observatory contains an external-capable element")
	}
}

func TestRenderSummaryCountsAreReceiptDerived(t *testing.T) {
	for _, test := range []struct {
		name      string
		malicious bool
		want      []string
	}{
		{"malicious", true, []string{"<b>4</b>attempted", "<b>3</b>denied", "<b>1</b>authorized", "<b>1</b>committed"}},
		{"benign", false, []string{"<b>1</b>attempted", "<b>0</b>denied", "<b>1</b>authorized", "<b>1</b>committed"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			evidence := testEvidence(t, "Update README.md", "fixture", "/workspace/README.md", test.malicious)
			page, err := Render(evidence)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range test.want {
				if !strings.Contains(string(page), want) {
					t.Errorf("rendered page missing receipt-derived count %q", want)
				}
			}
		})
	}
}

func testEvidence(t *testing.T, task, agent, resource string, malicious bool) *receipt.Receipt {
	t.Helper()
	authorized := receipt.Effect{Operation: "WRITE", Resource: resource, EnforcedBy: "effect-contract"}
	attempted := []receipt.Effect{authorized}
	graphEffects := []effectgraph.Effect{{Operation: authorized.Operation, Resource: authorized.Resource, Disposition: "AUTHORIZED", EnforcedBy: authorized.EnforcedBy}}
	var denied []receipt.Effect
	if malicious {
		denied = []receipt.Effect{
			{Operation: "READ", Resource: "/workspace/.env", EnforcedBy: "snapshot-secret-exclusion"},
			{Operation: "POST", Resource: "http://198.51.100.1/", EnforcedBy: "sandbox-network-none"},
			{Operation: "WRITE", Resource: "/etc/mirage-protected", EnforcedBy: "read-only-root"},
		}
		attempted = append(append([]receipt.Effect(nil), denied...), authorized)
		graphEffects = nil
		for _, effect := range attempted {
			disposition := "DENIED"
			if effect == authorized {
				disposition = "AUTHORIZED"
			}
			graphEffects = append(graphEffects, effectgraph.Effect{
				Operation: effect.Operation, Resource: effect.Resource, Disposition: disposition, EnforcedBy: effect.EnforcedBy,
			})
		}
	}
	mutation := receipt.Mutation{Operation: "MODIFY", Resource: resource, BeforeDigest: "sha256:before", AfterDigest: "sha256:after"}
	graph, err := effectgraph.New(effectgraph.Spec{
		RunID: "competition-malicious-1234567890abcdef", Task: task, Agent: agent,
		Effects: graphEffects, Mutations: []effectgraph.Mutation{{Operation: mutation.Operation, Resource: mutation.Resource, AfterDigest: mutation.AfterDigest}},
		Verification: "PASSED", VerificationPlan: "sha256:verification-plan", Committed: true,
		CommitPlan: "sha256:commit-plan", CommittedResource: resource,
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	evidence, err := receipt.New(receipt.Spec{
		RunID: graph.RunID, ContractHash: "sha256:contract", StartedAt: start, CompletedAt: start.Add(time.Second),
		AttemptedEffects: attempted, AuthorizedEffects: []receipt.Effect{authorized}, DeniedEffects: denied,
		ObservedMutations: []receipt.Mutation{mutation}, Verification: "PASSED", VerificationPlan: "sha256:verification-plan",
		CommittedMutations: []receipt.Mutation{mutation}, CommitPlan: "sha256:commit-plan", Graph: graph,
	})
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}
