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
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/MrGray17/Mirage/internal/effectgraph"
)

const (
	Version   = "mirage.execution-receipt/v1"
	VersionV2 = "mirage.execution-receipt/v2"

	OutcomeCommitted = "COMMITTED"
	OutcomeRejected  = "REJECTED"
)

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

// AgentAction is bounded agent-level evidence emitted after the constrained
// Qwen driver successfully completes one structured action. It is not trusted
// filesystem-mutation evidence and grants no authority.
type AgentAction struct {
	Sequence int    `json:"sequence"`
	Tool     string `json:"tool"`
	Resource string `json:"resource,omitempty"`
}

// Rejection records a trusted reconciliation denial. Model narration is never
// accepted as a rejection reason.
type Rejection struct {
	Operation string `json:"operation,omitempty"`
	Resource  string `json:"resource,omitempty"`
	Rule      string `json:"rule"`
	Reason    string `json:"reason"`
}

type Spec struct {
	Version            string
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
	Outcome            string
	AgentImage         string
	SandboxIdentity    string
	AgentActions       []AgentAction
	Rejections         []Rejection
	ProcessTreeStopped bool
	CleanupComplete    bool
	Reality            string
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
	Outcome            string             `json:"outcome,omitempty"`
	AgentImage         string             `json:"agent_image,omitempty"`
	SandboxIdentity    string             `json:"sandbox_identity,omitempty"`
	AgentActions       []AgentAction      `json:"agent_actions,omitempty"`
	Rejections         []Rejection        `json:"rejections,omitempty"`
	ProcessTreeStopped bool               `json:"process_tree_stopped,omitempty"`
	CleanupComplete    bool               `json:"cleanup_complete,omitempty"`
	Reality            string             `json:"reality,omitempty"`
	SHA256             string             `json:"receipt_sha256"`
}

func New(spec Spec) (*Receipt, error) {
	if spec.Version == "" {
		spec.Version = Version
	}
	if strings.TrimSpace(spec.RunID) == "" || strings.TrimSpace(spec.ContractHash) == "" || spec.StartedAt.IsZero() || spec.CompletedAt.IsZero() || spec.CompletedAt.Before(spec.StartedAt) || spec.Graph == nil {
		return nil, fmt.Errorf("%w: identity, time, and graph are required", ErrInvalidReceipt)
	}
	if spec.Graph.RunID != spec.RunID || effectgraph.Verify(spec.Graph) != nil {
		return nil, fmt.Errorf("%w: effect graph is not bound to the run", ErrInvalidReceipt)
	}
	receipt := &Receipt{
		Version:            spec.Version,
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
		Outcome:            spec.Outcome,
		AgentImage:         spec.AgentImage,
		SandboxIdentity:    spec.SandboxIdentity,
		AgentActions:       append([]AgentAction(nil), spec.AgentActions...),
		Rejections:         append([]Rejection(nil), spec.Rejections...),
		ProcessTreeStopped: spec.ProcessTreeStopped,
		CleanupComplete:    spec.CleanupComplete,
		Reality:            spec.Reality,
	}
	if receipt.Version == VersionV2 {
		if receipt.AuthorizedEffects == nil {
			receipt.AuthorizedEffects = []Effect{}
		}
		if receipt.DeniedEffects == nil {
			receipt.DeniedEffects = []Effect{}
		}
		if receipt.ObservedMutations == nil {
			receipt.ObservedMutations = []Mutation{}
		}
		if receipt.CommittedMutations == nil {
			receipt.CommittedMutations = []Mutation{}
		}
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
	if receipt == nil || (receipt.Version != Version && receipt.Version != VersionV2) || receipt.RunID == "" || receipt.ContractHash == "" || receipt.StartedAt == "" || receipt.CompletedAt == "" || receipt.VerificationPlan == "" || receipt.EffectGraph == nil || receipt.EffectGraphHash == "" {
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
		if !containsMutation(receipt.ObservedMutations, mutation) || !authorizedMutation(receipt.AuthorizedEffects, mutation) {
			return fmt.Errorf("%w: committed mutation lacks observed authorized authority", ErrInvalidReceipt)
		}
	}
	if err := validateGraphBindings(receipt, partition); err != nil {
		return err
	}
	if receipt.Version == Version {
		if receipt.Verification != "PASSED" || receipt.CommitPlan == "" || len(receipt.ObservedMutations) != 1 || len(receipt.CommittedMutations) != 1 || receipt.Outcome != "" || receipt.AgentImage != "" || receipt.SandboxIdentity != "" || len(receipt.AgentActions) != 0 || len(receipt.Rejections) != 0 || receipt.ProcessTreeStopped || receipt.CleanupComplete || receipt.Reality != "" {
			return fmt.Errorf("%w: competition v1 requires one passed observed and committed mutation", ErrInvalidReceipt)
		}
		return nil
	}
	return validateV2(receipt)
}

func receiptHash(receipt *Receipt) string {
	if receipt.Version == VersionV2 {
		return receiptHashV2(receipt)
	}
	return receiptHashV1(receipt)
}

func receiptHashV1(receipt *Receipt) string {
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

func receiptHashV2(receipt *Receipt) string {
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
		Outcome            string             `json:"outcome"`
		AgentImage         string             `json:"agent_image"`
		SandboxIdentity    string             `json:"sandbox_identity"`
		AgentActions       []AgentAction      `json:"agent_actions"`
		Rejections         []Rejection        `json:"rejections,omitempty"`
		ProcessTreeStopped bool               `json:"process_tree_stopped"`
		CleanupComplete    bool               `json:"cleanup_complete"`
		Reality            string             `json:"reality"`
	}{
		receipt.Version, receipt.RunID, receipt.ContractHash, receipt.StartedAt, receipt.CompletedAt,
		receipt.AttemptedEffects, receipt.AuthorizedEffects, receipt.DeniedEffects,
		receipt.ObservedMutations, receipt.Verification, receipt.VerificationPlan, receipt.CommittedMutations,
		receipt.CommitOID, receipt.CommitPlan, receipt.EffectGraphHash, receipt.EffectGraph,
		receipt.Outcome, receipt.AgentImage, receipt.SandboxIdentity, receipt.AgentActions, receipt.Rejections,
		receipt.ProcessTreeStopped, receipt.CleanupComplete, receipt.Reality,
	}
	encoded, _ := json.Marshal(canonical)
	digest := sha256.Sum256(encoded)
	return fmt.Sprintf("sha256:%x", digest)
}

func validateV2(receipt *Receipt) error {
	if receipt.AgentImage == "" || receipt.SandboxIdentity == "" || len(receipt.AgentActions) != 4 || len(receipt.AttemptedEffects) != 1 || !receipt.ProcessTreeStopped || !receipt.CleanupComplete {
		return fmt.Errorf("%w: agent v2 identity or bounded action evidence is incomplete", ErrInvalidReceipt)
	}
	wantTools := []string{"list_files", "read_file", "patch_file", "finish"}
	readResource := ""
	for index, action := range receipt.AgentActions {
		if action.Sequence != index+1 || action.Tool != wantTools[index] {
			return fmt.Errorf("%w: agent v2 action sequence is invalid", ErrInvalidReceipt)
		}
		switch action.Tool {
		case "list_files":
			if action.Resource != "/workspace" {
				return fmt.Errorf("%w: agent v2 list action is invalid", ErrInvalidReceipt)
			}
		case "read_file":
			readResource = action.Resource
			if !canonicalWorkspaceResource(readResource) {
				return fmt.Errorf("%w: agent v2 read action is invalid", ErrInvalidReceipt)
			}
		case "patch_file":
			if action.Resource != readResource {
				return fmt.Errorf("%w: agent v2 patch was not bound to the read resource", ErrInvalidReceipt)
			}
		case "finish":
			if action.Resource != "" {
				return fmt.Errorf("%w: agent v2 finish action has a resource", ErrInvalidReceipt)
			}
		}
	}
	patchEffect := Effect{Operation: "WRITE", Resource: readResource, EnforcedBy: receipt.AttemptedEffects[0].EnforcedBy}
	if receipt.AttemptedEffects[0] != patchEffect {
		return fmt.Errorf("%w: agent v2 patch effect differs from completed action evidence", ErrInvalidReceipt)
	}
	switch receipt.Outcome {
	case OutcomeCommitted:
		if receipt.Verification != "PASSED" || receipt.CommitPlan == "" || len(receipt.ObservedMutations) != 1 || len(receipt.CommittedMutations) != 1 || len(receipt.AuthorizedEffects) != 1 || len(receipt.DeniedEffects) != 0 || len(receipt.Rejections) != 0 || receipt.Reality != "COMMITTED_RESOURCE_VERIFIED" {
			return fmt.Errorf("%w: committed agent v2 outcome is inconsistent", ErrInvalidReceipt)
		}
	case OutcomeRejected:
		if receipt.Verification != "REJECTED" || receipt.CommitPlan != "" || len(receipt.CommittedMutations) != 0 || len(receipt.AuthorizedEffects) != 0 || len(receipt.DeniedEffects) != 1 || len(receipt.Rejections) == 0 || receipt.Reality != "M4_VISIBLE_BASELINE_UNCHANGED" {
			return fmt.Errorf("%w: rejected agent v2 outcome is inconsistent", ErrInvalidReceipt)
		}
		for _, rejection := range receipt.Rejections {
			if rejection.Rule == "" || rejection.Reason == "" || ((rejection.Operation == "") != (rejection.Resource == "")) || (rejection.Operation != "" && !rejectionMatchesObserved(rejection, receipt.ObservedMutations)) {
				return fmt.Errorf("%w: rejected agent v2 reason is incomplete", ErrInvalidReceipt)
			}
		}
	default:
		return fmt.Errorf("%w: agent v2 outcome is invalid", ErrInvalidReceipt)
	}
	return nil
}

func canonicalWorkspaceResource(resource string) bool {
	const prefix = "/workspace/"
	if !strings.HasPrefix(resource, prefix) {
		return false
	}
	relative := strings.TrimPrefix(resource, prefix)
	if relative == "" || path.IsAbs(relative) || path.Clean(relative) != relative || !fs.ValidPath(relative) || strings.Contains(relative, "\\") {
		return false
	}
	for _, character := range relative {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func rejectionMatchesObserved(rejection Rejection, observed []Mutation) bool {
	for _, mutation := range observed {
		if rejection.Operation == mutation.Operation && rejection.Resource == mutation.Resource {
			return true
		}
	}
	return false
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

func authorizedMutation(effects []Effect, mutation Mutation) bool {
	for _, effect := range effects {
		if effectgraph.CompetitionV1AuthorizesMutation(effect.Operation, effect.Resource, mutation.Operation, mutation.Resource) {
			return true
		}
	}
	return false
}
