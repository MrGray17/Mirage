// Package effectgraph builds a small deterministic causal graph from trusted
// Mirage execution evidence. It has no authority or mutation capabilities.
package effectgraph

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const Version = "mirage.effect-graph/v1"

var ErrInvalidGraph = errors.New("invalid effect graph")

type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Node struct {
	ID       string  `json:"id"`
	Type     string  `json:"type"`
	Label    string  `json:"label"`
	Metadata []Field `json:"metadata,omitempty"`
}

type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"`
}

type Effect struct {
	Operation   string
	Resource    string
	Disposition string
	EnforcedBy  string
}

type Mutation struct {
	Operation   string
	Resource    string
	AfterDigest string
}

type Spec struct {
	RunID             string
	Task              string
	Agent             string
	Effects           []Effect
	Mutations         []Mutation
	Verification      string
	VerificationPlan  string
	Committed         bool
	CommitPlan        string
	CommittedResource string
}

type Graph struct {
	Version string `json:"version"`
	RunID   string `json:"run_id"`
	Nodes   []Node `json:"nodes"`
	Edges   []Edge `json:"edges"`
	Hash    string `json:"hash"`
}

func New(spec Spec) (*Graph, error) {
	if strings.TrimSpace(spec.RunID) == "" || strings.TrimSpace(spec.Task) == "" || strings.TrimSpace(spec.Agent) == "" || len(spec.Effects) == 0 {
		return nil, fmt.Errorf("%w: run, task, agent, and effects are required", ErrInvalidGraph)
	}
	graph := &Graph{Version: Version, RunID: spec.RunID}
	run := graph.addNode("RUN", "Mirage run", fields(Field{"state", terminalState(spec.Committed)}))
	task := graph.addNode("TASK", spec.Task, nil)
	agent := graph.addNode("AGENT", spec.Agent, fields(Field{"trust", "UNTRUSTED"}))
	graph.addEdge(run, task, "CONTAINS")
	graph.addEdge(task, agent, "ASSIGNED_TO")

	type authorizedEffect struct {
		effect Effect
		node   Node
	}
	var authorizedEffects []authorizedEffect
	for _, effect := range spec.Effects {
		if strings.TrimSpace(effect.Operation) == "" || strings.TrimSpace(effect.Resource) == "" || (effect.Disposition != "AUTHORIZED" && effect.Disposition != "DENIED") || strings.TrimSpace(effect.EnforcedBy) == "" {
			return nil, fmt.Errorf("%w: effect is incomplete", ErrInvalidGraph)
		}
		attempt := graph.addNode("EFFECT_ATTEMPT", effect.Operation+" "+effect.Resource, fields(
			Field{"operation", effect.Operation}, Field{"resource", effect.Resource},
		))
		decisionType := "EFFECT_DENIED"
		edgeType := "DENIED_BY"
		if effect.Disposition == "AUTHORIZED" {
			decisionType = "EFFECT_AUTHORIZED"
			edgeType = "AUTHORIZED_BY"
		}
		decision := graph.addNode(decisionType, effect.Disposition, fields(Field{"enforced_by", effect.EnforcedBy}))
		graph.addEdge(agent, attempt, "ATTEMPTED")
		graph.addEdge(attempt, decision, edgeType)
		if effect.Disposition == "AUTHORIZED" {
			authorizedEffects = append(authorizedEffects, authorizedEffect{effect: effect, node: decision})
		}
	}

	var mutationNodes []Node
	for _, mutation := range spec.Mutations {
		if mutation.Operation == "" || mutation.Resource == "" || mutation.AfterDigest == "" {
			return nil, fmt.Errorf("%w: mutation is incomplete", ErrInvalidGraph)
		}
		observed := graph.addNode("OBSERVED_MUTATION", mutation.Operation+" "+mutation.Resource, fields(
			Field{"operation", mutation.Operation}, Field{"resource", mutation.Resource}, Field{"after_digest", mutation.AfterDigest},
		))
		for _, authority := range authorizedEffects {
			if CompetitionV1AuthorizesMutation(authority.effect.Operation, authority.effect.Resource, mutation.Operation, mutation.Resource) {
				graph.addEdge(authority.node, observed, "PRODUCED")
			}
		}
		mutationNodes = append(mutationNodes, observed)
	}
	verification := graph.addNode("VERIFICATION", spec.Verification, fields(Field{"plan", spec.VerificationPlan}))
	for _, mutation := range mutationNodes {
		graph.addEdge(mutation, verification, "VERIFIED_AS")
	}
	if spec.Committed {
		commit := graph.addNode("COMMIT", "Trusted real-world commit", fields(
			Field{"plan", spec.CommitPlan}, Field{"resource", spec.CommittedResource},
		))
		graph.addEdge(verification, commit, "COMMITTED_AS")
	}
	graph.Hash = graphHash(graph)
	return graph, nil
}

// CompetitionV1AuthorizesMutation encodes the only effect-to-mutation
// compatibility supported by the competition receipt: an authorized WRITE
// may produce a MODIFY of the same existing file.
func CompetitionV1AuthorizesMutation(effectOperation, effectResource, mutationOperation, mutationResource string) bool {
	return effectOperation == "WRITE" && mutationOperation == "MODIFY" && effectResource == mutationResource
}

func Verify(graph *Graph) error {
	if graph == nil || graph.Version != Version || graph.RunID == "" || graph.Hash == "" || len(graph.Nodes) == 0 {
		return ErrInvalidGraph
	}
	ids := make(map[string]struct{}, len(graph.Nodes))
	typeCounts := make(map[string]int)
	for index, node := range graph.Nodes {
		if node.ID == "" || node.Type == "" || node.Label == "" {
			return fmt.Errorf("%w: incomplete node", ErrInvalidGraph)
		}
		for fieldIndex, field := range node.Metadata {
			if field.Name == "" || field.Value == "" || (fieldIndex > 0 && node.Metadata[fieldIndex-1].Name >= field.Name) {
				return fmt.Errorf("%w: node metadata is not canonical", ErrInvalidGraph)
			}
		}
		if node.ID != nodeID(graph.RunID, index+1, node.Type, node.Label, node.Metadata) {
			return fmt.Errorf("%w: node identity mismatch", ErrInvalidGraph)
		}
		if _, duplicate := ids[node.ID]; duplicate {
			return fmt.Errorf("%w: duplicate node", ErrInvalidGraph)
		}
		ids[node.ID] = struct{}{}
		if !validNodeType(node.Type) {
			return fmt.Errorf("%w: unsupported node type", ErrInvalidGraph)
		}
		typeCounts[node.Type]++
	}
	if typeCounts["RUN"] != 1 || typeCounts["TASK"] != 1 || typeCounts["AGENT"] != 1 || typeCounts["VERIFICATION"] != 1 || typeCounts["EFFECT_ATTEMPT"] == 0 || typeCounts["EFFECT_ATTEMPT"] != typeCounts["EFFECT_AUTHORIZED"]+typeCounts["EFFECT_DENIED"] || typeCounts["COMMIT"] > 1 {
		return fmt.Errorf("%w: node cardinality is invalid", ErrInvalidGraph)
	}
	edges := make(map[Edge]struct{}, len(graph.Edges))
	for _, edge := range graph.Edges {
		if !validEdgeType(edge.Type) {
			return fmt.Errorf("%w: incomplete edge", ErrInvalidGraph)
		}
		if _, duplicate := edges[edge]; duplicate {
			return fmt.Errorf("%w: duplicate edge", ErrInvalidGraph)
		}
		edges[edge] = struct{}{}
		if _, ok := ids[edge.From]; !ok {
			return fmt.Errorf("%w: edge source is absent", ErrInvalidGraph)
		}
		if _, ok := ids[edge.To]; !ok {
			return fmt.Errorf("%w: edge target is absent", ErrInvalidGraph)
		}
	}
	if err := verifyCompetitionV1Causality(graph, nodesByID(graph.Nodes), edges); err != nil {
		return err
	}
	if graphHash(graph) != graph.Hash {
		return fmt.Errorf("%w: hash mismatch", ErrInvalidGraph)
	}
	return nil
}

func verifyCompetitionV1Causality(graph *Graph, nodes map[string]Node, edges map[Edge]struct{}) error {
	expected := make(map[Edge]struct{})
	for _, authorityEdge := range graph.Edges {
		if authorityEdge.Type != "AUTHORIZED_BY" {
			continue
		}
		attempt := nodes[authorityEdge.From]
		authority := nodes[authorityEdge.To]
		if attempt.Type != "EFFECT_ATTEMPT" || authority.Type != "EFFECT_AUTHORIZED" {
			continue
		}
		for _, mutation := range graph.Nodes {
			if mutation.Type == "OBSERVED_MUTATION" && CompetitionV1AuthorizesMutation(
				fieldValue(attempt, "operation"), fieldValue(attempt, "resource"),
				fieldValue(mutation, "operation"), fieldValue(mutation, "resource"),
			) {
				expected[Edge{From: authority.ID, To: mutation.ID, Type: "PRODUCED"}] = struct{}{}
			}
		}
	}
	for _, edge := range graph.Edges {
		if edge.Type == "PRODUCED" {
			if _, ok := expected[edge]; !ok {
				return fmt.Errorf("%w: produced edge lacks WRITE-to-MODIFY authority", ErrInvalidGraph)
			}
		}
	}
	for edge := range expected {
		if _, ok := edges[edge]; !ok {
			return fmt.Errorf("%w: authorized WRITE-to-MODIFY causality is absent", ErrInvalidGraph)
		}
	}
	return nil
}

func nodesByID(nodes []Node) map[string]Node {
	indexed := make(map[string]Node, len(nodes))
	for _, node := range nodes {
		indexed[node.ID] = node
	}
	return indexed
}

func fieldValue(node Node, name string) string {
	for _, field := range node.Metadata {
		if field.Name == name {
			return field.Value
		}
	}
	return ""
}

func validNodeType(kind string) bool {
	switch kind {
	case "RUN", "TASK", "AGENT", "EFFECT_ATTEMPT", "EFFECT_DENIED", "EFFECT_AUTHORIZED", "OBSERVED_MUTATION", "VERIFICATION", "COMMIT":
		return true
	default:
		return false
	}
}

func validEdgeType(kind string) bool {
	switch kind {
	case "CONTAINS", "ASSIGNED_TO", "ATTEMPTED", "DENIED_BY", "AUTHORIZED_BY", "PRODUCED", "VERIFIED_AS", "COMMITTED_AS":
		return true
	default:
		return false
	}
}

func (g *Graph) addNode(kind, label string, metadata []Field) Node {
	node := Node{ID: nodeID(g.RunID, len(g.Nodes)+1, kind, label, metadata), Type: kind, Label: label, Metadata: metadata}
	g.Nodes = append(g.Nodes, node)
	return node
}

func nodeID(runID string, ordinal int, kind, label string, metadata []Field) string {
	canonical := struct {
		RunID    string  `json:"run_id"`
		Ordinal  int     `json:"ordinal"`
		Type     string  `json:"type"`
		Label    string  `json:"label"`
		Metadata []Field `json:"metadata,omitempty"`
	}{runID, ordinal, kind, label, metadata}
	encoded, _ := json.Marshal(canonical)
	return hash(encoded)
}

func (g *Graph) addEdge(from, to Node, kind string) {
	g.Edges = append(g.Edges, Edge{From: from.ID, To: to.ID, Type: kind})
}

func fields(values ...Field) []Field {
	sort.Slice(values, func(i, j int) bool { return values[i].Name < values[j].Name })
	return values
}

func graphHash(graph *Graph) string {
	canonical := struct {
		Version string `json:"version"`
		RunID   string `json:"run_id"`
		Nodes   []Node `json:"nodes"`
		Edges   []Edge `json:"edges"`
	}{graph.Version, graph.RunID, graph.Nodes, graph.Edges}
	encoded, _ := json.Marshal(canonical)
	return hash(encoded)
}

func hash(value []byte) string {
	digest := sha256.Sum256(value)
	return fmt.Sprintf("sha256:%x", digest)
}

func terminalState(committed bool) string {
	if committed {
		return "COMMITTED"
	}
	return "NOT_COMMITTED"
}
