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
	if receipt.SHA256 != "sha256:b3774b01aa91fade08992c3d626a229ec34aa195e2dfcb086d49a4d73c8b8aaa" {
		t.Fatalf("competition v1 canonical hash changed: %s", receipt.SHA256)
	}
	encoded, err := Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseAndVerify(encoded)
	if err != nil || parsed.SHA256 != receipt.SHA256 {
		t.Fatalf("parsed=%#v error=%v", parsed, err)
	}
	if _, err := ParseAndVerify(append(append([]byte(nil), encoded...), []byte(`{}`)...)); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("trailing receipt value error=%v", err)
	}
	unknown := append(append([]byte(nil), encoded[:len(encoded)-2]...), []byte(",\n  \"unknown_field\": true\n}\n")...)
	if _, err := ParseAndVerify(unknown); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("unknown receipt field error=%v", err)
	}
	receipt.Verification = "FORGED"
	if err := Verify(receipt); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("error=%v, want ErrInvalidReceipt", err)
	}
}

func TestAgentV2ReceiptRejectsCommitAndObservationTampering(t *testing.T) {
	graph, err := effectgraph.New(effectgraph.Spec{
		RunID: "agent-1", Task: "edit README", Agent: "structured-qwen-agent", Verification: "PASSED", VerificationPlan: "sha256:plan", Committed: true, CommitPlan: "sha256:commit", CommittedResource: "/workspace/README.md",
		Effects:   []effectgraph.Effect{{Operation: "WRITE", Resource: "/workspace/README.md", Disposition: "AUTHORIZED", EnforcedBy: "effect-contract"}},
		Mutations: []effectgraph.Mutation{{Operation: "MODIFY", Resource: "/workspace/README.md", AfterDigest: "sha256:after"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	effect := Effect{Operation: "WRITE", Resource: "/workspace/README.md", EnforcedBy: "effect-contract"}
	mutation := Mutation{Operation: "MODIFY", Resource: "/workspace/README.md", BeforeDigest: "sha256:before", AfterDigest: "sha256:after"}
	start := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	evidence, err := New(Spec{
		Version: VersionV2, RunID: "agent-1", ContractHash: "sha256:contract", StartedAt: start, CompletedAt: start.Add(time.Second),
		AttemptedEffects: []Effect{effect}, AuthorizedEffects: []Effect{effect}, ObservedMutations: []Mutation{mutation}, Verification: "PASSED", VerificationPlan: "sha256:plan", CommittedMutations: []Mutation{mutation}, CommitPlan: "sha256:commit", Graph: graph,
		Outcome: OutcomeCommitted, AgentImage: "agent@sha256:exact", SandboxIdentity: "sha256:sandbox", AgentActions: testAgentActions(),
		ProcessTreeStopped: true, CleanupComplete: true, Reality: "COMMITTED_RESOURCE_VERIFIED",
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence.CommittedMutations[0].AfterDigest = "sha256:forged"
	if err := Verify(evidence); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("tampered commit error=%v", err)
	}
}

func TestAgentV2ReceiptRejectsNonCanonicalActionResource(t *testing.T) {
	resource := "/workspace/../outside"
	graph, err := effectgraph.New(effectgraph.Spec{
		RunID: "agent-1", Task: "edit", Agent: "structured-qwen-agent", Verification: "PASSED", VerificationPlan: "sha256:plan", Committed: true, CommitPlan: "sha256:commit", CommittedResource: resource,
		Effects:   []effectgraph.Effect{{Operation: "WRITE", Resource: resource, Disposition: "AUTHORIZED", EnforcedBy: "effect-contract"}},
		Mutations: []effectgraph.Mutation{{Operation: "MODIFY", Resource: resource, AfterDigest: "sha256:after"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	effect := Effect{Operation: "WRITE", Resource: resource, EnforcedBy: "effect-contract"}
	mutation := Mutation{Operation: "MODIFY", Resource: resource, BeforeDigest: "sha256:before", AfterDigest: "sha256:after"}
	actions := testAgentActions()
	actions[1].Resource, actions[2].Resource = resource, resource
	start := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	_, err = New(Spec{
		Version: VersionV2, RunID: "agent-1", ContractHash: "sha256:contract", StartedAt: start, CompletedAt: start.Add(time.Second),
		AttemptedEffects: []Effect{effect}, AuthorizedEffects: []Effect{effect}, ObservedMutations: []Mutation{mutation}, Verification: "PASSED", VerificationPlan: "sha256:plan", CommittedMutations: []Mutation{mutation}, CommitPlan: "sha256:commit", Graph: graph,
		Outcome: OutcomeCommitted, AgentImage: "agent@sha256:exact", SandboxIdentity: "sha256:sandbox", AgentActions: actions,
		ProcessTreeStopped: true, CleanupComplete: true, Reality: "COMMITTED_RESOURCE_VERIFIED",
	})
	if !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("non-canonical action resource error=%v", err)
	}
}

func TestAgentV2RejectedReceiptBindsRejectionToObservedMutation(t *testing.T) {
	const attemptedResource = "/workspace/README.md"
	const observedResource = "/workspace/other.txt"
	graph, err := effectgraph.New(effectgraph.Spec{
		RunID: "agent-1", Task: "edit", Agent: "structured-qwen-agent", Verification: "REJECTED", VerificationPlan: "sha256:plan",
		Effects:   []effectgraph.Effect{{Operation: "WRITE", Resource: attemptedResource, Disposition: "DENIED", EnforcedBy: "trusted-reconciliation"}},
		Mutations: []effectgraph.Mutation{{Operation: "MODIFY", Resource: observedResource, AfterDigest: "sha256:after"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	effect := Effect{Operation: "WRITE", Resource: attemptedResource, EnforcedBy: "trusted-reconciliation"}
	mutation := Mutation{Operation: "MODIFY", Resource: observedResource, BeforeDigest: "sha256:before", AfterDigest: "sha256:after"}
	start := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	_, err = New(Spec{
		Version: VersionV2, RunID: "agent-1", ContractHash: "sha256:contract", StartedAt: start, CompletedAt: start.Add(time.Second),
		AttemptedEffects: []Effect{effect}, DeniedEffects: []Effect{effect}, ObservedMutations: []Mutation{mutation}, Verification: "REJECTED", VerificationPlan: "sha256:plan", Graph: graph,
		Outcome: OutcomeRejected, AgentImage: "agent@sha256:exact", SandboxIdentity: "sha256:sandbox", AgentActions: testAgentActions(),
		Rejections:         []Rejection{{Operation: "MODIFY", Resource: attemptedResource, Rule: "filesystem.default_deny", Reason: "denied"}},
		ProcessTreeStopped: true, CleanupComplete: true, Reality: "M4_VISIBLE_BASELINE_UNCHANGED",
	})
	if !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("mismatched rejection error=%v", err)
	}
}

func testAgentActions() []AgentAction {
	return []AgentAction{
		{Sequence: 1, Tool: "list_files", Resource: "/workspace"},
		{Sequence: 2, Tool: "read_file", Resource: "/workspace/README.md"},
		{Sequence: 3, Tool: "patch_file", Resource: "/workspace/README.md"},
		{Sequence: 4, Tool: "finish"},
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

func TestReceiptRequiresCompetitionV1WriteAuthorityForCommittedModify(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		resource  string
		wantError bool
	}{
		{"write same resource", "WRITE", "/workspace/README.md", false},
		{"read same resource", "READ", "/workspace/README.md", true},
		{"post same resource", "POST", "/workspace/README.md", true},
		{"write other resource", "WRITE", "/workspace/other.txt", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			graph, err := effectgraph.New(effectgraph.Spec{
				RunID: "run-1", Task: "task", Agent: "fixture", Verification: "PASSED", VerificationPlan: "sha256:plan", Committed: true, CommitPlan: "sha256:commit", CommittedResource: "/workspace/README.md",
				Effects:   []effectgraph.Effect{{Operation: test.operation, Resource: test.resource, Disposition: "AUTHORIZED", EnforcedBy: "contract"}},
				Mutations: []effectgraph.Mutation{{Operation: "MODIFY", Resource: "/workspace/README.md", AfterDigest: "sha256:after"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			effect := Effect{Operation: test.operation, Resource: test.resource, EnforcedBy: "contract"}
			mutation := Mutation{Operation: "MODIFY", Resource: "/workspace/README.md", BeforeDigest: "sha256:before", AfterDigest: "sha256:after"}
			start := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
			_, err = New(Spec{
				RunID: "run-1", ContractHash: "sha256:contract", StartedAt: start, CompletedAt: start.Add(time.Second),
				AttemptedEffects: []Effect{effect}, AuthorizedEffects: []Effect{effect}, ObservedMutations: []Mutation{mutation}, Verification: "PASSED", VerificationPlan: "sha256:plan", CommittedMutations: []Mutation{mutation}, CommitPlan: "sha256:commit", Graph: graph,
			})
			if test.wantError && !errors.Is(err, ErrInvalidReceipt) {
				t.Fatalf("error=%v, want ErrInvalidReceipt", err)
			}
			if !test.wantError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
