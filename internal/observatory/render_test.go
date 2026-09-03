package observatory

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/effectgraph"
	"github.com/MrGray17/Mirage/internal/receipt"
)

var (
	testBeforeDigest = "sha256:66595402" + strings.Repeat("a", 48) + "99368a02"
	testAfterDigest  = "sha256:20922841" + strings.Repeat("b", 48) + "f4acf630"
)

func TestRenderVerifiedMaliciousExecutionInspector(t *testing.T) {
	evidence := testEvidence(t, "Update README.md with a short verified MIRAGE demo message.", "/workspace/README.md", true)
	page, err := Render(evidence)
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(page)
	for _, required := range []string{
		"MIRAGE", "Observatory", "Update README.md with a short verified MIRAGE demo message.",
		`<strong>4</strong> effects`, `<strong class="blocked">3</strong> blocked`, `<strong class="committed">1</strong> committed`,
		"READ", "/workspace/.env", "POST", "http://198.51.100.1/", "/etc/mirage-protected",
		"Execution history", "Effect 03", "WRITE", "/workspace/README.md", "AUTHORIZED", "Observed", "MODIFY", "PASSED", "COMMITTED",
		"Trust boundary", "Reality", "README.md", shortDigest(testBeforeDigest), shortDigest(testAfterDigest),
		"CommittedEffects &sube; AuthorizedEffects", `Receipt <strong>VALID</strong>`, "Cryptographic proof",
		"Integrity", "Run", "Plans", `via <code>snapshot-secret-exclusion</code>`,
		evidence.SHA256, evidence.EffectGraphHash, evidence.ContractHash, evidence.VerificationPlan, evidence.CommitPlan,
		testBeforeDigest, testAfterDigest,
		evidence.StartedAt, evidence.CompletedAt, "1s",
	} {
		if !strings.Contains(rendered, required) {
			t.Errorf("rendered page missing %q", required)
		}
	}
	if got := strings.Count(rendered, `class="effect-row blocked"`); got != 3 {
		t.Errorf("blocked rows=%d, want 3", got)
	}
	if got := strings.Count(rendered, `class="effect-row selected"`); got != 1 {
		t.Errorf("selected authorized rows=%d, want 1", got)
	}
	if got := strings.Count(rendered, `<div class="history-stage`); got != 4 {
		t.Errorf("history continuation stages=%d, want 4", got)
	}
	for _, digest := range []string{testBeforeDigest, testAfterDigest} {
		if got := strings.Count(rendered, digest); got != 1 {
			t.Errorf("full digest appears %d times, want proof-only occurrence", got)
		}
	}
	for _, removed := range []string{"Receipt order", "Enforced by", "<details open", "causal-arrow", `class="trust-boundary"`} {
		if strings.Contains(rendered, removed) {
			t.Errorf("rendered page retained unwanted UI text/state %q", removed)
		}
	}
}

func TestRenderRejectsInvalidReceipt(t *testing.T) {
	evidence := testEvidence(t, "Update README.md", "/workspace/README.md", false)
	evidence.SHA256 = "sha256:forged"
	if _, err := Render(evidence); !errors.Is(err, receipt.ErrInvalidReceipt) {
		t.Fatalf("error=%v, want ErrInvalidReceipt", err)
	}
}

func TestRenderVerifiedBenignReceipt(t *testing.T) {
	evidence := testEvidence(t, "Update README.md", "/workspace/README.md", false)
	page, err := Render(evidence)
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(page)
	for _, required := range []string{
		`<strong>1</strong> effects`, `<strong class="blocked">0</strong> blocked`, `<strong class="committed">1</strong> committed`,
		"Effect 01", "WRITE", "/workspace/README.md", "COMMITTED", "Receipt <strong>VALID</strong>",
	} {
		if !strings.Contains(rendered, required) {
			t.Errorf("rendered page missing %q", required)
		}
	}
	if strings.Contains(rendered, `class="effect-row blocked"`) {
		t.Fatal("benign receipt rendered a blocked effect")
	}
}

func TestRenderPreservesAttemptedEffectOrder(t *testing.T) {
	evidence := testEvidence(t, "Update README.md", "/workspace/README.md", true)
	page, err := Render(evidence)
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(page)
	resources := []string{
		"/workspace/.env",
		"http://198.51.100.1/",
		"/workspace/README.md",
		"/etc/mirage-protected",
	}
	previous := -1
	for _, resource := range resources {
		position := strings.Index(rendered, resource)
		if position < 0 || position <= previous {
			t.Fatalf("resource %q rendered out of receipt order", resource)
		}
		previous = position
	}
}

func TestCommittedEffectUsesCompetitionV1WriteToModifyMatch(t *testing.T) {
	read := receipt.Effect{Operation: "READ", Resource: "/workspace/README.md", EnforcedBy: "read-contract"}
	write := receipt.Effect{Operation: "WRITE", Resource: "/workspace/README.md", EnforcedBy: "write-contract"}
	mutation := receipt.Mutation{Operation: "MODIFY", Resource: write.Resource, BeforeDigest: testBeforeDigest, AfterDigest: testAfterDigest}
	evidence := newEvidence(t, "Inspect then update README.md", []receipt.Effect{read, write}, []receipt.Effect{read, write}, nil, mutation)

	view, err := buildPageData(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if view.Effects[0].State != "AUTHORIZED" || view.Effects[0].IsCommitted {
		t.Fatalf("READ row=%+v, want authorized but not committed", view.Effects[0])
	}
	if view.Effects[1].State != "AUTHORIZED" || view.Effects[1].StateClass != "selected" || !view.Effects[1].IsCommitted || view.Inspector.Index != 2 {
		t.Fatalf("WRITE row=%+v inspector=%+v, want second effect selected for committed path", view.Effects[1], view.Inspector)
	}
}

func TestRenderEscapesHostileEvidence(t *testing.T) {
	task := `"><script>alert(1)</script><style>body{display:none}</style>`
	resource := `/workspace/README.md"><img src=x onerror=alert(1)>`
	authority := `contract"><iframe src=https://evil.example>`
	write := receipt.Effect{Operation: "WRITE", Resource: resource, EnforcedBy: authority}
	mutation := receipt.Mutation{Operation: "MODIFY", Resource: resource, BeforeDigest: testBeforeDigest, AfterDigest: testAfterDigest}
	evidence := newEvidence(t, task, []receipt.Effect{write}, []receipt.Effect{write}, nil, mutation)
	page, err := Render(evidence)
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(page)
	for _, forbidden := range []string{"<script", "<iframe", "<img", "</style><style>"} {
		if strings.Contains(strings.ToLower(rendered), forbidden) {
			t.Fatalf("hostile evidence became active markup: %q", forbidden)
		}
	}
	for _, escaped := range []string{"&lt;script&gt;", "&lt;img", "&lt;iframe"} {
		if !strings.Contains(rendered, escaped) {
			t.Errorf("rendered page missing escaped value %q", escaped)
		}
	}
}

func TestTemplateIsSelfContainedAndStrict(t *testing.T) {
	wantCSP := `default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'`
	if !strings.Contains(pageTemplate, wantCSP) {
		t.Fatalf("strict CSP missing: %s", wantCSP)
	}
	for _, pattern := range []string{
		`(?i)<script(?:\s|>)`,
		`(?i)<(?:link|iframe|object|embed)(?:\s|>)`,
		`(?i)(?:src|href)\s*=\s*["'](?:https?:)?//`,
		`(?i)@import\s|url\s*\(`,
	} {
		if regexp.MustCompile(pattern).MatchString(pageTemplate) {
			t.Fatalf("template contains prohibited external/executable content matching %q", pattern)
		}
	}
}

func TestRenderIsDeterministicAndRetainsFullEvidence(t *testing.T) {
	resource := "/workspace/" + strings.Repeat("nested-directory/", 20) + "README.md"
	evidence := testEvidence(t, "Update one deeply nested README", resource, false)
	first, err := Render(evidence)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Render(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("same verified receipt produced different HTML bytes")
	}
	for _, full := range []string{resource, evidence.SHA256, evidence.EffectGraphHash, evidence.ContractHash, evidence.RunID} {
		if !bytes.Contains(first, []byte(full)) {
			t.Errorf("full evidence value was omitted: %q", full)
		}
	}
}

func testEvidence(t *testing.T, task, resource string, malicious bool) *receipt.Receipt {
	t.Helper()
	write := receipt.Effect{Operation: "WRITE", Resource: resource, EnforcedBy: "effect-contract"}
	attempted := []receipt.Effect{write}
	var denied []receipt.Effect
	if malicious {
		read := receipt.Effect{Operation: "READ", Resource: "/workspace/.env", EnforcedBy: "snapshot-secret-exclusion"}
		post := receipt.Effect{Operation: "POST", Resource: "http://198.51.100.1/", EnforcedBy: "sandbox-network-none"}
		protected := receipt.Effect{Operation: "WRITE", Resource: "/etc/mirage-protected", EnforcedBy: "read-only-root"}
		attempted = []receipt.Effect{read, post, write, protected}
		denied = []receipt.Effect{read, post, protected}
	}
	mutation := receipt.Mutation{Operation: "MODIFY", Resource: resource, BeforeDigest: testBeforeDigest, AfterDigest: testAfterDigest}
	return newEvidence(t, task, attempted, []receipt.Effect{write}, denied, mutation)
}

func newEvidence(t *testing.T, task string, attempted, authorized, denied []receipt.Effect, mutation receipt.Mutation) *receipt.Receipt {
	t.Helper()
	graphEffects := make([]effectgraph.Effect, 0, len(attempted))
	for _, effect := range attempted {
		disposition := "DENIED"
		if containsEffect(authorized, effect) {
			disposition = "AUTHORIZED"
		}
		graphEffects = append(graphEffects, effectgraph.Effect{
			Operation: effect.Operation, Resource: effect.Resource, Disposition: disposition, EnforcedBy: effect.EnforcedBy,
		})
	}
	graph, err := effectgraph.New(effectgraph.Spec{
		RunID: "competition-malicious-1234567890abcdef", Task: task, Agent: "deterministic-fixture",
		Effects: graphEffects, Mutations: []effectgraph.Mutation{{Operation: mutation.Operation, Resource: mutation.Resource, AfterDigest: mutation.AfterDigest}},
		Verification: "PASSED", VerificationPlan: "sha256:verification-plan", Committed: true,
		CommitPlan: "sha256:commit-plan", CommittedResource: mutation.Resource,
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	evidence, err := receipt.New(receipt.Spec{
		RunID: graph.RunID, ContractHash: "sha256:contract", StartedAt: start, CompletedAt: start.Add(time.Second),
		AttemptedEffects: attempted, AuthorizedEffects: authorized, DeniedEffects: denied,
		ObservedMutations: []receipt.Mutation{mutation}, Verification: "PASSED", VerificationPlan: "sha256:verification-plan",
		CommittedMutations: []receipt.Mutation{mutation}, CommitOID: "0123456789abcdef0123456789abcdef01234567",
		CommitPlan: "sha256:commit-plan", Graph: graph,
	})
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}
