package observatory

import (
	"strings"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/effectgraph"
	"github.com/MrGray17/Mirage/internal/receipt"
)

func TestRenderVerifiedReceiptWithoutExecutableContent(t *testing.T) {
	graph, err := effectgraph.New(effectgraph.Spec{
		RunID: "run-1", Task: "<script>alert(1)</script>", Agent: "fixture", Verification: "PASSED", VerificationPlan: "sha256:plan", Committed: true, CommitPlan: "sha256:commit", CommittedResource: "/workspace/README.md",
		Effects:   []effectgraph.Effect{{Operation: "WRITE", Resource: "/workspace/README.md", Disposition: "AUTHORIZED", EnforcedBy: "contract"}},
		Mutations: []effectgraph.Mutation{{Operation: "MODIFY", Resource: "/workspace/README.md", AfterDigest: "sha256:after"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	effect := receipt.Effect{Operation: "WRITE", Resource: "/workspace/README.md", EnforcedBy: "contract"}
	mutation := receipt.Mutation{Operation: "MODIFY", Resource: "/workspace/README.md", BeforeDigest: "before", AfterDigest: "sha256:after"}
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	evidence, err := receipt.New(receipt.Spec{
		RunID: "run-1", ContractHash: "sha256:contract", StartedAt: now, CompletedAt: now,
		AttemptedEffects: []receipt.Effect{effect}, AuthorizedEffects: []receipt.Effect{effect}, ObservedMutations: []receipt.Mutation{mutation}, Verification: "PASSED", VerificationPlan: "sha256:plan", CommittedMutations: []receipt.Mutation{mutation}, CommitPlan: "sha256:commit", Graph: graph,
	})
	if err != nil {
		t.Fatal(err)
	}
	page, err := Render(evidence)
	if err != nil {
		t.Fatal(err)
	}
	text := string(page)
	for _, required := range []string{"MIRAGE OBSERVATORY", "Content-Security-Policy", "ATTEMPTED", "AUTHORIZED", "COMMITTED", evidence.SHA256} {
		if !strings.Contains(text, required) {
			t.Errorf("rendered page missing %q", required)
		}
	}
	if strings.Contains(text, "<script>alert(1)</script>") {
		t.Fatal("receipt content was rendered as executable HTML")
	}
}
