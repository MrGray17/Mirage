// Package agentproduct maps completed Qwen runtime facts into read-only product
// evidence. It has no authority or mutation capability.
package agentproduct

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/MrGray17/Mirage/internal/effectgraph"
	"github.com/MrGray17/Mirage/internal/receipt"
	"github.com/MrGray17/Mirage/internal/runtime/qwenagent"
	"github.com/MrGray17/Mirage/internal/runtime/reconcile"
	"github.com/MrGray17/Mirage/internal/runtime/tree"
)

var ErrInvalidEvidence = errors.New("invalid coding-agent product evidence")

type Spec struct {
	RunID              string
	Task               string
	ContractHash       string
	ManifestHash       string
	StartedAt          time.Time
	CompletedAt        time.Time
	AgentImage         string
	SandboxIdentity    string
	Actions            []qwenagent.CompletedAction
	Plan               *tree.Plan
	Decision           reconcile.Decision
	Committed          bool
	CommitPlan         string
	ProcessTreeStopped bool
	CleanupComplete    bool
	Reality            string
}

// Build constructs self-hashed evidence only from completed driver actions and
// trusted reconciliation/commit facts supplied after process-tree stop.
func Build(spec Spec) (*effectgraph.Graph, *receipt.Receipt, error) {
	if strings.TrimSpace(spec.RunID) == "" || strings.TrimSpace(spec.Task) == "" || strings.TrimSpace(spec.AgentImage) == "" || strings.TrimSpace(spec.SandboxIdentity) == "" || spec.Plan == nil || spec.StartedAt.IsZero() || spec.CompletedAt.IsZero() || spec.CompletedAt.Before(spec.StartedAt) || !spec.ProcessTreeStopped || !spec.CleanupComplete {
		return nil, nil, fmt.Errorf("%w: identity, time, actions, and plan are required", ErrInvalidEvidence)
	}
	if spec.ContractHash == "" || spec.ManifestHash == "" || !spec.Decision.BoundTo(spec.ManifestHash, spec.ContractHash, spec.Plan.Hash()) {
		return nil, nil, fmt.Errorf("%w: reconciliation authority binding differs", ErrInvalidEvidence)
	}
	actions, patchResource, err := receiptActions(spec.Actions)
	if err != nil {
		return nil, nil, err
	}
	mutations := spec.Plan.Mutations()
	graphMutations := make([]effectgraph.Mutation, 0, len(mutations))
	receiptMutations := make([]receipt.Mutation, 0, len(mutations))
	for _, mutation := range mutations {
		graphMutations = append(graphMutations, effectgraph.Mutation{Operation: string(mutation.Operation), Resource: mutation.Resource, AfterDigest: mutation.AfterDigest})
		receiptMutations = append(receiptMutations, receipt.Mutation{Operation: string(mutation.Operation), Resource: mutation.Resource, BeforeDigest: mutation.BeforeDigest, AfterDigest: mutation.AfterDigest})
	}
	effect := receipt.Effect{Operation: "WRITE", Resource: patchResource, EnforcedBy: "trusted-reconciliation"}
	disposition := "DENIED"
	verification := "REJECTED"
	outcome := receipt.OutcomeRejected
	var authorized, denied []receipt.Effect
	var committed []receipt.Mutation
	var rejections []receipt.Rejection
	if spec.Committed {
		if !spec.Decision.Allowed || spec.CommitPlan == "" || len(receiptMutations) != 1 || !effectgraph.CompetitionV1AuthorizesMutation(effect.Operation, effect.Resource, receiptMutations[0].Operation, receiptMutations[0].Resource) {
			return nil, nil, fmt.Errorf("%w: commit claim lacks exact trusted authority", ErrInvalidEvidence)
		}
		effect.EnforcedBy = "effect-contract"
		disposition = "AUTHORIZED"
		verification = "PASSED"
		outcome = receipt.OutcomeCommitted
		authorized = []receipt.Effect{effect}
		committed = append(committed, receiptMutations...)
	} else {
		if spec.Decision.Allowed || spec.CommitPlan != "" {
			return nil, nil, fmt.Errorf("%w: rejection claim conflicts with trusted decision", ErrInvalidEvidence)
		}
		denied = []receipt.Effect{effect}
		for _, violation := range spec.Decision.Violations() {
			rejections = append(rejections, receipt.Rejection{Operation: string(violation.Operation), Resource: violation.Resource, Rule: violation.RuleID, Reason: violation.Reason})
		}
		if len(rejections) == 0 {
			return nil, nil, fmt.Errorf("%w: rejected run lacks trusted denial evidence", ErrInvalidEvidence)
		}
	}
	graph, err := effectgraph.New(effectgraph.Spec{
		RunID: spec.RunID, Task: spec.Task, Agent: "structured-qwen-agent", Verification: verification,
		VerificationPlan: spec.Plan.Hash(), Committed: spec.Committed, CommitPlan: spec.CommitPlan,
		CommittedResource: patchResource,
		Effects:           []effectgraph.Effect{{Operation: effect.Operation, Resource: effect.Resource, Disposition: disposition, EnforcedBy: effect.EnforcedBy}},
		Mutations:         graphMutations,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("%w: build effect graph: %v", ErrInvalidEvidence, err)
	}
	executionReceipt, err := receipt.New(receipt.Spec{
		Version: receipt.VersionV2, RunID: spec.RunID, ContractHash: spec.ContractHash,
		StartedAt: spec.StartedAt, CompletedAt: spec.CompletedAt,
		AttemptedEffects: []receipt.Effect{effect}, AuthorizedEffects: authorized, DeniedEffects: denied,
		ObservedMutations: receiptMutations, Verification: verification, VerificationPlan: spec.Plan.Hash(),
		CommittedMutations: committed, CommitPlan: spec.CommitPlan, Graph: graph, Outcome: outcome,
		AgentImage: spec.AgentImage, SandboxIdentity: spec.SandboxIdentity, AgentActions: actions, Rejections: rejections,
		ProcessTreeStopped: spec.ProcessTreeStopped, CleanupComplete: spec.CleanupComplete, Reality: spec.Reality,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("%w: build receipt: %v", ErrInvalidEvidence, err)
	}
	return graph, executionReceipt, nil
}

func receiptActions(actions []qwenagent.CompletedAction) ([]receipt.AgentAction, string, error) {
	if len(actions) != 4 {
		return nil, "", fmt.Errorf("%w: constrained action evidence is incomplete", ErrInvalidEvidence)
	}
	converted := make([]receipt.AgentAction, 0, len(actions))
	patchResource := ""
	for _, action := range actions {
		resource := ""
		switch action.Tool {
		case "list_files":
			resource = "/workspace"
		case "read_file", "patch_file":
			if action.Resource == "" || path.IsAbs(action.Resource) || path.Clean(action.Resource) != action.Resource || strings.HasPrefix(action.Resource, "../") {
				return nil, "", fmt.Errorf("%w: action resource is invalid", ErrInvalidEvidence)
			}
			resource = path.Join("/workspace", action.Resource)
			if action.Tool == "patch_file" {
				patchResource = resource
			}
		case "finish":
		default:
			return nil, "", fmt.Errorf("%w: unsupported completed action", ErrInvalidEvidence)
		}
		converted = append(converted, receipt.AgentAction{Sequence: action.Sequence, Tool: action.Tool, Resource: resource})
	}
	if patchResource == "" {
		return nil, "", fmt.Errorf("%w: patch action is absent", ErrInvalidEvidence)
	}
	return converted, patchResource, nil
}
