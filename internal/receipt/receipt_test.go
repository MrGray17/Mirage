package receipt

import (
	"errors"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/effectgraph"
)

func TestReceiptRoundTripAndTamperDetection(t *testing.T) {
	graph, err := effectgraph.New(effectgraph.Spec{
		RunID: "run-1", Task: "task", Agent: "fixture", Verification: "PASSED", VerificationPlan: "sha256:plan", Committed: true, CommitPlan: "sha256:commit", CommittedResource: "/workspace/README.md",
		Effects:   []effectgraph.Effect{{Operation: "WRITE", Resource: "/workspace/README.md", Disposition: "AUTHORIZED", EnforcedBy: "contract"}},
		Mutations: []effectgraph.Mutation{{Operation: "MODIFY", Resource: "/workspace/README.md", AfterDigest: "sha256:after"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	effect := Effect{Operation: "WRITE", Resource: "/workspace/README.md", EnforcedBy: "contract"}
	mutation := Mutation{Operation: "MODIFY", Resource: "/workspace/README.md", BeforeDigest: "sha256:before", AfterDigest: "sha256:after"}
	start := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	receipt, err := New(Spec{
		RunID: "run-1", ContractHash: "sha256:contract", StartedAt: start, CompletedAt: start.Add(time.Second),
		AttemptedEffects: []Effect{effect}, AuthorizedEffects: []Effect{effect}, ObservedMutations: []Mutation{mutation}, Verification: "PASSED", VerificationPlan: "sha256:plan", CommittedMutations: []Mutation{mutation}, CommitPlan: "sha256:commit", Graph: graph,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseAndVerify(encoded)
	if err != nil || parsed.SHA256 != receipt.SHA256 {
		t.Fatalf("parsed=%#v error=%v", parsed, err)
	}
	receipt.Verification = "FORGED"
	if err := Verify(receipt); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("error=%v, want ErrInvalidReceipt", err)
	}
}

func TestReceiptRejectsCommittedUnauthorizedMutation(t *testing.T) {
	graph, err := effectgraph.New(effectgraph.Spec{
		RunID: "run-1", Task: "task", Agent: "fixture", Verification: "PASSED", VerificationPlan: "sha256:plan",
		Effects: []effectgraph.Effect{{Operation: "READ", Resource: "/workspace/.env", Disposition: "DENIED", EnforcedBy: "isolation"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	denied := Effect{Operation: "READ", Resource: "/workspace/.env", EnforcedBy: "isolation"}
	mutation := Mutation{Operation: "MODIFY", Resource: "/workspace/README.md", BeforeDigest: "a", AfterDigest: "b"}
	_, err = New(Spec{
		RunID: "run-1", ContractHash: "sha256:contract", StartedAt: start, CompletedAt: start,
		AttemptedEffects: []Effect{denied}, DeniedEffects: []Effect{denied}, ObservedMutations: []Mutation{mutation}, Verification: "PASSED", VerificationPlan: "sha256:plan", CommittedMutations: []Mutation{mutation}, CommitPlan: "sha256:commit", Graph: graph,
	})
	if !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("error=%v, want ErrInvalidReceipt", err)
	}
}
