package agentproduct

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/observatory"
	"github.com/MrGray17/Mirage/internal/receipt"
	"github.com/MrGray17/Mirage/internal/runtime/qwenagent"
	"github.com/MrGray17/Mirage/internal/runtime/reconcile"
	"github.com/MrGray17/Mirage/internal/runtime/tree"
)

func TestCommittedQwenEvidenceBindsActionsObservationAndCommit(t *testing.T) {
	spec := evidenceSpec(t, "/workspace/README.md", true)
	graph, evidence, err := Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Version != receipt.VersionV2 || evidence.Outcome != receipt.OutcomeCommitted || evidence.Verification != "PASSED" || len(evidence.CommittedMutations) != 1 || len(evidence.AgentActions) != 4 || graph.Hash != evidence.EffectGraphHash {
		t.Fatalf("evidence=%#v", evidence)
	}
	encoded, err := receipt.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receipt.ParseAndVerify(encoded); err != nil {
		t.Fatal(err)
	}
	page, err := observatory.Render(evidence)
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{"COMMITTED", "Completed agent actions", "read_file", "patch_file", "Receipt <strong>VALID</strong>"} {
		if !strings.Contains(string(page), wanted) {
			t.Errorf("Observatory omitted %q", wanted)
		}
	}
}

func TestRejectedQwenEvidenceCannotClaimRealityChanged(t *testing.T) {
	spec := evidenceSpec(t, "/workspace/protected.txt", true)
	spec.Committed = false
	spec.CommitPlan = ""
	_, evidence, err := Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Outcome != receipt.OutcomeRejected || evidence.Verification != "REJECTED" || len(evidence.CommittedMutations) != 0 || len(evidence.Rejections) == 0 || evidence.Rejections[0].Rule != "filesystem.default_deny" {
		t.Fatalf("evidence=%#v", evidence)
	}
	evidence.Outcome = receipt.OutcomeCommitted
	if err := receipt.Verify(evidence); !errors.Is(err, receipt.ErrInvalidReceipt) {
		t.Fatalf("tampered evidence error=%v", err)
	}
}

func TestCompletedPatchWithoutFilesystemChangeCannotAppearCommitted(t *testing.T) {
	spec := evidenceSpec(t, "/workspace/README.md", false)
	spec.Committed = false
	spec.CommitPlan = ""
	_, evidence, err := Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Outcome != receipt.OutcomeRejected || len(evidence.ObservedMutations) != 0 || len(evidence.CommittedMutations) != 0 {
		t.Fatalf("evidence=%#v", evidence)
	}
	spec.Committed = true
	spec.CommitPlan = "sha256:commit"
	if _, _, err := Build(spec); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("false commit error=%v", err)
	}
}

func evidenceSpec(t *testing.T, allowed string, changed bool) Spec {
	t.Helper()
	baselineRoot := t.TempDir()
	finalRoot := t.TempDir()
	for _, root := range []string{baselineRoot, finalRoot} {
		if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("before\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "protected.txt"), []byte("protected\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if changed {
		if err := os.WriteFile(filepath.Join(finalRoot, "README.md"), []byte("after\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	baseline, err := tree.Scan(baselineRoot, tree.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	contract, err := contracts.New(contracts.Spec{
		Version: contracts.VersionV1, RunID: "coding-agent-test", ActorID: "coding-agent", ExpiresAt: start.Add(time.Hour),
		Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{Allow: []string{allowed}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, decision, err := reconcile.Verify("sha256:manifest", baseline, finalRoot, contract, start)
	if err != nil {
		t.Fatal(err)
	}
	return Spec{
		RunID: "coding-agent-test", Task: "edit README", ContractHash: contract.Hash(), ManifestHash: "sha256:manifest",
		StartedAt: start, CompletedAt: start.Add(time.Second), AgentImage: "agent@sha256:test", SandboxIdentity: "sha256:sandbox",
		Actions: []qwenagent.CompletedAction{
			{Sequence: 1, Tool: "list_files"},
			{Sequence: 2, Tool: "read_file", Resource: "README.md"},
			{Sequence: 3, Tool: "patch_file", Resource: "README.md"},
			{Sequence: 4, Tool: "finish"},
		},
		Plan: plan, Decision: decision, Committed: decision.Allowed, CommitPlan: "sha256:commit",
		ProcessTreeStopped: true, CleanupComplete: true, Reality: map[bool]string{true: "COMMITTED_RESOURCE_VERIFIED", false: "M4_VISIBLE_BASELINE_UNCHANGED"}[decision.Allowed],
	}
}
