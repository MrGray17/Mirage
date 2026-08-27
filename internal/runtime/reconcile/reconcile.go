// Package reconcile converts a proven-frozen disposable tree into exact,
// deterministic contract evidence. It grants no authority to mutate reality.
package reconcile

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	runtimedocker "github.com/MrGray17/Mirage/internal/runtime/docker"
	"github.com/MrGray17/Mirage/internal/runtime/tree"
)

var ErrInvalidReconciliation = errors.New("invalid frozen-tree reconciliation")

type Violation struct {
	Operation tree.Operation
	Resource  string
	RuleID    string
	Reason    string
	Evidence  string
}

type Decision struct {
	Allowed       bool
	ManifestHash  string
	ContractHash  string
	PlanHash      string
	AuthorityHash string
	violations    []Violation
}

func (d Decision) Violations() []Violation {
	return append([]Violation(nil), d.violations...)
}

func (d Decision) BoundTo(manifestHash, contractHash, planHash string) bool {
	return d.ManifestHash == manifestHash &&
		d.ContractHash == contractHash &&
		d.PlanHash == planHash &&
		d.AuthorityHash == authorityHash(manifestHash, contractHash, planHash)
}

// Verify scans the final frozen tree without exclusions, derives the complete
// normalized mutation plan, and requires exact WRITE authority for every
// mutation. A policy rejection is returned as a Decision, not as uncertainty.
func Verify(manifestHash string, baseline *tree.Snapshot, frozenWorkspace string, contract *contracts.Contract, at time.Time) (*tree.Plan, Decision, error) {
	if manifestHash == "" || baseline == nil || contract == nil || frozenWorkspace == "" {
		return nil, Decision{}, fmt.Errorf("%w: manifest, baseline, workspace, and contract are required", ErrInvalidReconciliation)
	}
	if err := tree.ValidateBaseline(baseline); err != nil {
		return nil, Decision{}, fmt.Errorf("%w: baseline: %v", ErrInvalidReconciliation, err)
	}
	final, err := tree.Scan(frozenWorkspace, tree.ScanOptions{})
	if err != nil {
		return nil, Decision{}, fmt.Errorf("scan frozen workspace: %w", err)
	}
	plan, err := tree.Diff(baseline, final)
	if err != nil {
		return nil, Decision{}, fmt.Errorf("diff frozen workspace: %w", err)
	}
	decision := Decision{
		ManifestHash: manifestHash,
		ContractHash: contract.Hash(),
		PlanHash:     plan.Hash(),
	}
	decision.AuthorityHash = authorityHash(decision.ManifestHash, decision.ContractHash, decision.PlanHash)

	if at.IsZero() {
		decision.violations = append(decision.violations, Violation{
			RuleID: "contract.invalid_time",
			Reason: "trusted reconciliation time is unavailable",
		})
		return plan, decision, nil
	}
	if contract.ExpiredAt(at) {
		decision.violations = append(decision.violations, Violation{
			RuleID:   "contract.expired",
			Reason:   "effect contract has expired",
			Evidence: contract.ExpiresAt().Format(time.RFC3339Nano),
		})
		return plan, decision, nil
	}

	mutations := plan.Mutations()
	for _, mutation := range mutations {
		if violation, denied := intrinsicViolation(mutation); denied {
			decision.violations = append(decision.violations, violation)
			continue
		}
		contractDecision := contract.EvaluateFilesystem(contracts.FilesystemWrite, mutation.Resource, at)
		if !contractDecision.Allowed {
			decision.violations = append(decision.violations, Violation{
				Operation: mutation.Operation,
				Resource:  mutation.Resource,
				RuleID:    contractDecision.RuleID,
				Reason:    contractDecision.Reason,
				Evidence:  contractDecision.Evidence,
			})
		}
	}
	if len(mutations) != 1 {
		decision.violations = append(decision.violations, Violation{
			RuleID:   "filesystem.single_modify_required",
			Reason:   "M4.3 requires exactly one existing regular-file content modification",
			Evidence: fmt.Sprintf("mutations=%d", len(mutations)),
		})
	}
	decision.Allowed = len(decision.violations) == 0
	return plan, decision, nil
}

func intrinsicViolation(mutation tree.Mutation) (Violation, bool) {
	violation := Violation{Operation: mutation.Operation, Resource: mutation.Resource, Evidence: mutation.Resource}
	switch {
	case mutation.Resource == "/workspace/"+runtimedocker.DisposableMarker:
		violation.RuleID = "runtime.reserved_resource"
		violation.Reason = "Mirage runtime marker is not agent-authorized"
		return violation, true
	case mutation.Operation == tree.OperationSymlink:
		violation.RuleID = "filesystem.symlink_denied"
		violation.Reason = "symlinks are unsupported in the M4 commit model"
		return violation, true
	case mutation.Operation == tree.OperationUnsupported:
		violation.RuleID = "filesystem.unsupported_object"
		violation.Reason = "hard links and special filesystem objects are unsupported"
		return violation, true
	case mutation.Operation != tree.OperationModify || mutation.BeforeKind != tree.KindFile || mutation.AfterKind != tree.KindFile || mutation.BeforeMode != mutation.AfterMode:
		violation.RuleID = "filesystem.v1_write_content_modify_only"
		violation.Reason = "contract v1 WRITE authorizes only content modification of an existing independent regular file"
		return violation, true
	default:
		return Violation{}, false
	}
}

func authorityHash(manifestHash, contractHash, planHash string) string {
	digest := sha256.Sum256([]byte(manifestHash + "\n" + contractHash + "\n" + planHash))
	return fmt.Sprintf("sha256:%x", digest)
}
