// Package receipt serializes and verifies deterministic competition evidence.
// Receipts describe completed facts; they cannot authorize any effect.
package receipt

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/MrGray17/Mirage/internal/effectgraph"
)

const Version = "mirage.execution-receipt/v1"

var ErrInvalidReceipt = errors.New("invalid Mirage receipt")

type Effect struct {
	Operation  string `json:"operation"`
	Resource   string `json:"resource"`
	EnforcedBy string `json:"enforced_by"`
}

type Mutation struct {
	Operation    string `json:"operation"`
	Resource     string `json:"resource"`
	BeforeDigest string `json:"before_digest"`
	AfterDigest  string `json:"after_digest"`
}

type Spec struct {
	RunID              string
	ContractHash       string
	StartedAt          time.Time
	CompletedAt        time.Time
	AttemptedEffects   []Effect
	AuthorizedEffects  []Effect
	DeniedEffects      []Effect
	ObservedMutations  []Mutation
	Verification       string
	VerificationPlan   string
	CommittedMutations []Mutation
	CommitOID          string
	CommitPlan         string
	Graph              *effectgraph.Graph
}

type Receipt struct {
	Version            string             `json:"version"`
	RunID              string             `json:"run_id"`
	ContractHash       string             `json:"contract_hash"`
	StartedAt          string             `json:"started_at"`
	CompletedAt        string             `json:"completed_at"`
	AttemptedEffects   []Effect           `json:"attempted_effects"`
	AuthorizedEffects  []Effect           `json:"authorized_effects"`
	DeniedEffects      []Effect           `json:"denied_effects"`
	ObservedMutations  []Mutation         `json:"observed_mutations"`
	Verification       string             `json:"verification"`
	VerificationPlan   string             `json:"verification_plan"`
	CommittedMutations []Mutation         `json:"committed_mutations"`
	CommitOID          string             `json:"commit_oid,omitempty"`
	CommitPlan         string             `json:"commit_plan"`
	EffectGraphHash    string             `json:"effect_graph_hash"`
	EffectGraph        *effectgraph.Graph `json:"effect_graph"`
	SHA256             string             `json:"receipt_sha256"`
}

func New(spec Spec) (*Receipt, error) {
	if strings.TrimSpace(spec.RunID) == "" || strings.TrimSpace(spec.ContractHash) == "" || spec.StartedAt.IsZero() || spec.CompletedAt.IsZero() || spec.CompletedAt.Before(spec.StartedAt) || spec.Graph == nil {
		return nil, fmt.Errorf("%w: identity, time, and graph are required", ErrInvalidReceipt)
	}
	if spec.Graph.RunID != spec.RunID || effectgraph.Verify(spec.Graph) != nil {
		return nil, fmt.Errorf("%w: effect graph is not bound to the run", ErrInvalidReceipt)
	}
	receipt := &Receipt{
		Version:            Version,
		RunID:              spec.RunID,
		ContractHash:       spec.ContractHash,
		StartedAt:          spec.StartedAt.UTC().Format(time.RFC3339Nano),
		CompletedAt:        spec.CompletedAt.UTC().Format(time.RFC3339Nano),
		AttemptedEffects:   append([]Effect(nil), spec.AttemptedEffects...),
		AuthorizedEffects:  append([]Effect(nil), spec.AuthorizedEffects...),
		DeniedEffects:      append([]Effect(nil), spec.DeniedEffects...),
		ObservedMutations:  append([]Mutation(nil), spec.ObservedMutations...),
		Verification:       spec.Verification,
		VerificationPlan:   spec.VerificationPlan,
		CommittedMutations: append([]Mutation(nil), spec.CommittedMutations...),
		CommitOID:          spec.CommitOID,
		CommitPlan:         spec.CommitPlan,
		EffectGraphHash:    spec.Graph.Hash,
		EffectGraph:        spec.Graph,
	}
	if err := validate(receipt); err != nil {
		return nil, err
	}
	receipt.SHA256 = receiptHash(receipt)
	return receipt, nil
}

func Marshal(receipt *Receipt) ([]byte, error) {
	if err := Verify(receipt); err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal receipt: %w", err)
	}
	return append(encoded, '\n'), nil
}

func ParseAndVerify(encoded []byte) (*Receipt, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var receipt Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrInvalidReceipt, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing JSON value", ErrInvalidReceipt)
	}
	if err := Verify(&receipt); err != nil {
		return nil, err
	}
	return &receipt, nil
}

func Verify(receipt *Receipt) error {
	if err := validate(receipt); err != nil {
		return err
	}
	if receipt.SHA256 == "" || receiptHash(receipt) != receipt.SHA256 {
		return fmt.Errorf("%w: SHA-256 mismatch", ErrInvalidReceipt)
	}
	return nil
}

func validate(receipt *Receipt) error {
	if receipt == nil || receipt.Version != Version || receipt.RunID == "" || receipt.ContractHash == "" || receipt.StartedAt == "" || receipt.CompletedAt == "" || receipt.Verification != "PASSED" || receipt.VerificationPlan == "" || receipt.CommitPlan == "" || receipt.EffectGraph == nil || receipt.EffectGraphHash == "" {
		return fmt.Errorf("%w: required field is absent", ErrInvalidReceipt)
	}
	started, startErr := time.Parse(time.RFC3339Nano, receipt.StartedAt)
	completed, completedErr := time.Parse(time.RFC3339Nano, receipt.CompletedAt)
	if startErr != nil || completedErr != nil || completed.Before(started) {
		return fmt.Errorf("%w: timestamps are invalid", ErrInvalidReceipt)
	}
	if receipt.EffectGraph.RunID != receipt.RunID || receipt.EffectGraph.Hash != receipt.EffectGraphHash {
		return fmt.Errorf("%w: effect graph binding differs", ErrInvalidReceipt)
	}
	if err := effectgraph.Verify(receipt.EffectGraph); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidReceipt, err)
	}
	if len(receipt.AttemptedEffects) != len(receipt.AuthorizedEffects)+len(receipt.DeniedEffects) {
		return fmt.Errorf("%w: effect accounting is incomplete", ErrInvalidReceipt)
	}
	if len(receipt.ObservedMutations) != 1 || len(receipt.CommittedMutations) != 1 {
		return fmt.Errorf("%w: competition v1 requires one observed and committed mutation", ErrInvalidReceipt)
	}
	partition := make(map[Effect]string, len(receipt.AttemptedEffects))
	for _, effect := range receipt.AttemptedEffects {
		if effect.Operation == "" || effect.Resource == "" || effect.EnforcedBy == "" {
			return fmt.Errorf("%w: attempted effect is incomplete", ErrInvalidReceipt)
		}
		if _, duplicate := partition[effect]; duplicate {
			return fmt.Errorf("%w: duplicate attempted effect", ErrInvalidReceipt)
		}
		partition[effect] = "ATTEMPTED"
	}
	for _, effect := range receipt.AuthorizedEffects {
		if partition[effect] != "ATTEMPTED" {
			return fmt.Errorf("%w: authorized effect was not attempted", ErrInvalidReceipt)
		}
		partition[effect] = "AUTHORIZED"
	}
	for _, effect := range receipt.DeniedEffects {
		if partition[effect] != "ATTEMPTED" {
			return fmt.Errorf("%w: denied effect was not attempted", ErrInvalidReceipt)
		}
		partition[effect] = "DENIED"
	}
	for _, disposition := range partition {
		if disposition == "ATTEMPTED" {
			return fmt.Errorf("%w: attempted effect has no terminal disposition", ErrInvalidReceipt)
		}
	}
	for _, mutation := range receipt.CommittedMutations {
		if !containsMutation(receipt.ObservedMutations, mutation) || !authorizedResource(receipt.AuthorizedEffects, mutation.Resource) {
			return fmt.Errorf("%w: committed mutation lacks observed authorized authority", ErrInvalidReceipt)
		}
	}
	if err := validateGraphBindings(receipt, partition); err != nil {
		return err
	}
	return nil
}

func receiptHash(receipt *Receipt) string {
	canonical := struct {
		Version            string             `json:"version"`
		RunID              string             `json:"run_id"`
		ContractHash       string             `json:"contract_hash"`
		StartedAt          string             `json:"started_at"`
		CompletedAt        string             `json:"completed_at"`
		AttemptedEffects   []Effect           `json:"attempted_effects"`
		AuthorizedEffects  []Effect           `json:"authorized_effects"`
		DeniedEffects      []Effect           `json:"denied_effects"`
		ObservedMutations  []Mutation         `json:"observed_mutations"`
		Verification       string             `json:"verification"`
		VerificationPlan   string             `json:"verification_plan"`
		CommittedMutations []Mutation         `json:"committed_mutations"`
		CommitOID          string             `json:"commit_oid,omitempty"`
		CommitPlan         string             `json:"commit_plan"`
		EffectGraphHash    string             `json:"effect_graph_hash"`
		EffectGraph        *effectgraph.Graph `json:"effect_graph"`
	}{
		receipt.Version, receipt.RunID, receipt.ContractHash, receipt.StartedAt, receipt.CompletedAt,
		receipt.AttemptedEffects, receipt.AuthorizedEffects, receipt.DeniedEffects,
		receipt.ObservedMutations, receipt.Verification, receipt.VerificationPlan, receipt.CommittedMutations,
		receipt.CommitOID, receipt.CommitPlan, receipt.EffectGraphHash, receipt.EffectGraph,
	}
	encoded, _ := json.Marshal(canonical)
	digest := sha256.Sum256(encoded)
	return fmt.Sprintf("sha256:%x", digest)
}

func containsMutation(mutations []Mutation, wanted Mutation) bool {
	for _, mutation := range mutations {
		if mutation == wanted {
			return true
		}
	}
	return false
}

func validateGraphBindings(evidence *Receipt, partition map[Effect]string) error {
	nodes := make(map[string]effectgraph.Node, len(evidence.EffectGraph.Nodes))
	var attempts, observed, verifications, commits []effectgraph.Node
	for _, node := range evidence.EffectGraph.Nodes {
		nodes[node.ID] = node
		switch node.Type {
		case "EFFECT_ATTEMPT":
			attempts = append(attempts, node)
		case "OBSERVED_MUTATION":
			observed = append(observed, node)
		case "VERIFICATION":
			verifications = append(verifications, node)
		case "COMMIT":
			commits = append(commits, node)
		}
	}
	if len(attempts) != len(evidence.AttemptedEffects) || len(observed) != len(evidence.ObservedMutations) || len(verifications) != 1 || verifications[0].Label != evidence.Verification || nodeField(verifications[0], "plan") != evidence.VerificationPlan {
		return fmt.Errorf("%w: graph execution summary differs", ErrInvalidReceipt)
	}
	for _, effect := range evidence.AttemptedEffects {
		var attempt *effectgraph.Node
		for index := range attempts {
			if nodeField(attempts[index], "operation") == effect.Operation && nodeField(attempts[index], "resource") == effect.Resource {
				if attempt != nil {
					return fmt.Errorf("%w: graph effect is ambiguous", ErrInvalidReceipt)
				}
				attempt = &attempts[index]
			}
		}
		if attempt == nil {
			return fmt.Errorf("%w: graph omitted attempted effect", ErrInvalidReceipt)
		}
		edgeType, nodeType := "DENIED_BY", "EFFECT_DENIED"
		if partition[effect] == "AUTHORIZED" {
			edgeType, nodeType = "AUTHORIZED_BY", "EFFECT_AUTHORIZED"
		}
		matched := 0
		for _, edge := range evidence.EffectGraph.Edges {
			decision := nodes[edge.To]
			if edge.From == attempt.ID && edge.Type == edgeType && decision.Type == nodeType && nodeField(decision, "enforced_by") == effect.EnforcedBy {
				matched++
			}
		}
		if matched != 1 {
			return fmt.Errorf("%w: graph effect disposition differs", ErrInvalidReceipt)
		}
	}
	for _, mutation := range evidence.ObservedMutations {
		matched := 0
		for _, node := range observed {
			if nodeField(node, "operation") == mutation.Operation && nodeField(node, "resource") == mutation.Resource && nodeField(node, "after_digest") == mutation.AfterDigest {
				matched++
			}
		}
		if matched != 1 {
			return fmt.Errorf("%w: graph mutation differs", ErrInvalidReceipt)
		}
	}
	wantCommits := 0
	if len(evidence.CommittedMutations) > 0 {
		wantCommits = 1
	}
	if len(commits) != wantCommits {
		return fmt.Errorf("%w: graph commit accounting differs", ErrInvalidReceipt)
	}
	if wantCommits == 1 && (nodeField(commits[0], "plan") != evidence.CommitPlan || nodeField(commits[0], "resource") != evidence.CommittedMutations[0].Resource) {
		return fmt.Errorf("%w: graph commit binding differs", ErrInvalidReceipt)
	}
	return nil
}

func nodeField(node effectgraph.Node, name string) string {
	for _, field := range node.Metadata {
		if field.Name == name {
			return field.Value
		}
	}
	return ""
}

func authorizedResource(effects []Effect, resource string) bool {
	for _, effect := range effects {
		if effect.Resource == resource {
			return true
		}
	}
	return false
}
