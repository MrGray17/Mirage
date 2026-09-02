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

func TestGraphLinksOnlyCompetitionV1WriteAuthorityToModify(t *testing.T) {
	tests := []struct {
		name              string
		effectOperation   string
		effectResource    string
		mutationOperation string
		mutationResource  string
		wantProduced      int
	}{
		{"write same resource", "WRITE", "/workspace/README.md", "MODIFY", "/workspace/README.md", 1},
		{"read same resource", "READ", "/workspace/README.md", "MODIFY", "/workspace/README.md", 0},
		{"post same resource", "POST", "/workspace/README.md", "MODIFY", "/workspace/README.md", 0},
		{"write other resource", "WRITE", "/workspace/other.txt", "MODIFY", "/workspace/README.md", 0},
		{"write does not authorize create", "WRITE", "/workspace/README.md", "CREATE", "/workspace/README.md", 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			graph, err := New(Spec{
				RunID: "run-1", Task: "task", Agent: "fixture", Verification: "PASSED", VerificationPlan: "sha256:plan",
				Effects:   []Effect{{Operation: test.effectOperation, Resource: test.effectResource, Disposition: "AUTHORIZED", EnforcedBy: "contract"}},
				Mutations: []Mutation{{Operation: test.mutationOperation, Resource: test.mutationResource, AfterDigest: "sha256:after"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			produced := 0
			for _, edge := range graph.Edges {
				if edge.Type == "PRODUCED" {
					produced++
				}
			}
			if produced != test.wantProduced {
				t.Fatalf("PRODUCED edges=%d, want %d", produced, test.wantProduced)
			}
		})
	}
}

func TestGraphVerificationRejectsRehashedInvalidProducedCausality(t *testing.T) {
	t.Run("READ cannot produce MODIFY", func(t *testing.T) {
		graph, err := New(Spec{
			RunID: "run-1", Task: "task", Agent: "fixture", Verification: "PASSED", VerificationPlan: "sha256:plan",
			Effects:   []Effect{{Operation: "READ", Resource: "/workspace/README.md", Disposition: "AUTHORIZED", EnforcedBy: "contract"}},
			Mutations: []Mutation{{Operation: "MODIFY", Resource: "/workspace/README.md", AfterDigest: "sha256:after"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		var authority, mutation Node
		for _, node := range graph.Nodes {
			switch node.Type {
			case "EFFECT_AUTHORIZED":
				authority = node
			case "OBSERVED_MUTATION":
				mutation = node
			}
		}
		graph.Edges = append(graph.Edges, Edge{From: authority.ID, To: mutation.ID, Type: "PRODUCED"})
		graph.Hash = graphHash(graph)
		if err := Verify(graph); !errors.Is(err, ErrInvalidGraph) {
			t.Fatalf("error=%v, want ErrInvalidGraph", err)
		}
	})

	t.Run("WRITE to MODIFY link cannot be omitted", func(t *testing.T) {
		graph, err := New(Spec{
			RunID: "run-1", Task: "task", Agent: "fixture", Verification: "PASSED", VerificationPlan: "sha256:plan",
			Effects:   []Effect{{Operation: "WRITE", Resource: "/workspace/README.md", Disposition: "AUTHORIZED", EnforcedBy: "contract"}},
			Mutations: []Mutation{{Operation: "MODIFY", Resource: "/workspace/README.md", AfterDigest: "sha256:after"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		for index, edge := range graph.Edges {
			if edge.Type == "PRODUCED" {
				graph.Edges = append(graph.Edges[:index], graph.Edges[index+1:]...)
				break
			}
		}
		graph.Hash = graphHash(graph)
		if err := Verify(graph); !errors.Is(err, ErrInvalidGraph) {
			t.Fatalf("error=%v, want ErrInvalidGraph", err)
		}
	})
}
