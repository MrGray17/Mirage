package reconcile

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/runtime/tree"
)

func TestVerifyAllowsOnlyCompleteExactAuthorizedDiff(t *testing.T) {
	workspace := t.TempDir()
	writeFile(t, workspace, "README.md", "before")
	baseline := scan(t, workspace)
	writeFile(t, workspace, "README.md", "after")

	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	contract := newContract(t, now.Add(time.Hour), "/workspace/README.md")
	plan, decision, err := Verify(baseline, workspace, contract, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !decision.Allowed || len(decision.Violations()) != 0 {
		t.Fatalf("decision = %#v, violations = %#v", decision, decision.Violations())
	}
	changes := plan.Mutations()
	if len(changes) != 1 || changes[0].Operation != tree.OperationModify || changes[0].Resource != "/workspace/README.md" {
		t.Fatalf("changes = %#v", changes)
	}
	if decision.PlanHash != plan.Hash() || decision.ContractHash != contract.Hash() || decision.AuthorityHash == "" {
		t.Fatalf("unbound decision = %#v", decision)
	}
}

func TestVerifyRejectsUnobservedForbiddenExtraFile(t *testing.T) {
	workspace := t.TempDir()
	writeFile(t, workspace, "README.md", "before")
	baseline := scan(t, workspace)
	writeFile(t, workspace, "README.md", "allowed update")
	writeFile(t, workspace, "forbidden.txt", "bypass attempt")

	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	plan, decision, err := Verify(baseline, workspace, newContract(t, now.Add(time.Hour), "/workspace/README.md"), now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if decision.Allowed {
		t.Fatal("forbidden final mutation was allowed")
	}
	if len(plan.Mutations()) != 2 {
		t.Fatalf("mutations = %#v", plan.Mutations())
	}
	violations := decision.Violations()
	if len(violations) != 1 || violations[0].Resource != "/workspace/forbidden.txt" || violations[0].RuleID != "filesystem.default_deny" {
		t.Fatalf("violations = %#v", violations)
	}
}

func TestVerifyIntrinsicallyRejectsSymlinkAndReservedMarker(t *testing.T) {
	workspace := t.TempDir()
	writeFile(t, workspace, ".mirage-disposable-workspace", "token")
	baseline := scan(t, workspace)
	writeFile(t, workspace, ".mirage-disposable-workspace", "tampered")
	if err := os.Symlink("README.md", filepath.Join(workspace, "hostile-link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	contract := newContract(t, now.Add(time.Hour), "/workspace/.mirage-disposable-workspace", "/workspace/hostile-link")
	_, decision, err := Verify(baseline, workspace, contract, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	violations := decision.Violations()
	if decision.Allowed || len(violations) != 2 {
		t.Fatalf("decision = %#v, violations = %#v", decision, violations)
	}
	if violations[0].RuleID != "runtime.reserved_resource" || violations[1].RuleID != "filesystem.symlink_denied" {
		t.Fatalf("violations = %#v", violations)
	}
}

func TestVerifyRejectsExpiredContractEvenWithNoMutation(t *testing.T) {
	workspace := t.TempDir()
	writeFile(t, workspace, "README.md", "same")
	baseline := scan(t, workspace)
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

	plan, decision, err := Verify(baseline, workspace, newContract(t, now, "/workspace/README.md"), now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(plan.Mutations()) != 0 || decision.Allowed || len(decision.Violations()) != 1 || decision.Violations()[0].RuleID != "contract.expired" {
		t.Fatalf("plan = %#v, decision = %#v, violations = %#v", plan.Mutations(), decision, decision.Violations())
	}
}

func TestVerifyNormalizesRenameAndRejectsProtectedDelete(t *testing.T) {
	workspace := t.TempDir()
	writeFile(t, workspace, "protected.txt", "protected")
	baseline := scan(t, workspace)
	if err := os.Rename(filepath.Join(workspace, "protected.txt"), filepath.Join(workspace, "renamed.txt")); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	plan, decision, err := Verify(baseline, workspace, newContract(t, now.Add(time.Hour), "/workspace/renamed.txt"), now)
	if err != nil {
		t.Fatal(err)
	}
	changes := plan.Mutations()
	if len(changes) != 2 || changes[0].Operation != tree.OperationDelete || changes[1].Operation != tree.OperationCreate {
		t.Fatalf("rename changes = %#v", changes)
	}
	violations := decision.Violations()
	if decision.Allowed || len(violations) != 1 || violations[0].Resource != "/workspace/protected.txt" {
		t.Fatalf("decision = %#v, violations = %#v", decision, violations)
	}
}

func TestVerifyRejectsHardlinkEvenWhenPathIsAllowed(t *testing.T) {
	workspace := t.TempDir()
	writeFile(t, workspace, "source.txt", "content")
	baseline := scan(t, workspace)
	if err := os.Link(filepath.Join(workspace, "source.txt"), filepath.Join(workspace, "alias.txt")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	_, decision, err := Verify(baseline, workspace, newContract(t, now.Add(time.Hour), "/workspace/alias.txt"), now)
	if err != nil {
		t.Fatal(err)
	}
	violations := decision.Violations()
	if decision.Allowed || len(violations) == 0 {
		t.Fatalf("decision = %#v, violations = %#v", decision, violations)
	}
	for _, violation := range violations {
		if violation.RuleID != "filesystem.unsupported_object" {
			t.Fatalf("decision = %#v, violations = %#v", decision, violations)
		}
	}
}

func TestVerifyRejectsWorkspaceRootModeChange(t *testing.T) {
	workspace := t.TempDir()
	baseline := scan(t, workspace)
	before := baseline.RootMode()
	changed := os.FileMode(before) ^ 0o020
	if err := os.Chmod(workspace, changed); err != nil {
		t.Skipf("chmod unavailable: %v", err)
	}
	final := scan(t, workspace)
	if final.RootMode() == before {
		t.Skip("filesystem does not expose root permission changes")
	}
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	_, decision, err := Verify(baseline, workspace, newContract(t, now.Add(time.Hour)), now)
	if err != nil {
		t.Fatal(err)
	}
	violations := decision.Violations()
	if decision.Allowed || len(violations) != 1 || violations[0].Resource != "/workspace" || violations[0].RuleID != "filesystem.unsupported_object" {
		t.Fatalf("decision = %#v, violations = %#v", decision, violations)
	}
}

func scan(t *testing.T, workspace string) *tree.Snapshot {
	t.Helper()
	snapshot, err := tree.Scan(workspace, tree.ScanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return snapshot
}

func writeFile(t *testing.T, root, relative, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, relative), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newContract(t *testing.T, expires time.Time, allowed ...string) *contracts.Contract {
	t.Helper()
	contract, err := contracts.New(contracts.Spec{
		Version:   contracts.VersionV1,
		RunID:     "m42-test-run",
		ActorID:   "hostile-fixture",
		ExpiresAt: expires,
		Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{
			Allow: allowed,
		}},
	})
	if err != nil {
		t.Fatalf("contract: %v", err)
	}
	return contract
}
