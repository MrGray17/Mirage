package effectgraph

import (
	"errors"
	"testing"
)

func TestGraphIsDeterministicAndVerifiable(t *testing.T) {
	spec := Spec{
		RunID: "run-1", Task: "Update README", Agent: "fixture", Verification: "PASSED", VerificationPlan: "sha256:verification", Committed: true, CommitPlan: "sha256:commit", CommittedResource: "/workspace/README.md",
		Effects: []Effect{
			{Operation: "READ", Resource: "/workspace/.env", Disposition: "DENIED", EnforcedBy: "snapshot-secret-exclusion"},
			{Operation: "WRITE", Resource: "/workspace/README.md", Disposition: "AUTHORIZED", EnforcedBy: "effect-contract"},
		},
		Mutations: []Mutation{{Operation: "MODIFY", Resource: "/workspace/README.md", AfterDigest: "sha256:after"}},
	}
	first, err := New(spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(spec)
	if err != nil {
		t.Fatal(err)
	}
	if first.Hash != second.Hash || first.Nodes[0].ID != second.Nodes[0].ID {
		t.Fatal("same evidence produced different graph identity")
	}
	if err := Verify(first); err != nil {
		t.Fatal(err)
	}
	if len(first.Nodes) != 10 || len(first.Edges) != 9 {
		t.Fatalf("nodes=%d edges=%d", len(first.Nodes), len(first.Edges))
	}
}

func TestGraphVerificationRejectsTampering(t *testing.T) {
	graph, err := New(Spec{
		RunID: "run-1", Task: "task", Agent: "fixture", Verification: "PASSED", VerificationPlan: "sha256:plan",
		Effects: []Effect{{Operation: "READ", Resource: "/workspace/.env", Disposition: "DENIED", EnforcedBy: "isolation"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	graph.Nodes[0].Label = "forged"
	if err := Verify(graph); !errors.Is(err, ErrInvalidGraph) {
		t.Fatalf("error=%v, want ErrInvalidGraph", err)
	}
}

func TestGraphVerificationRejectsInventedNodeEvenWithRehashedGraph(t *testing.T) {
	graph, err := New(Spec{
		RunID: "run-1", Task: "task", Agent: "fixture", Verification: "PASSED", VerificationPlan: "sha256:plan",
		Effects: []Effect{{Operation: "READ", Resource: "/workspace/.env", Disposition: "DENIED", EnforcedBy: "isolation"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	graph.Nodes = append(graph.Nodes, Node{ID: nodeID(graph.RunID, len(graph.Nodes)+1, "CLAIM", "invented", nil), Type: "CLAIM", Label: "invented"})
	graph.Hash = graphHash(graph)
	if err := Verify(graph); !errors.Is(err, ErrInvalidGraph) {
		t.Fatalf("error=%v, want ErrInvalidGraph", err)
	}
}
