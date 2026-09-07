package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MrGray17/Mirage/internal/agentproduct"
	"github.com/MrGray17/Mirage/internal/cliapi"
	"github.com/MrGray17/Mirage/internal/observatory"
	"github.com/MrGray17/Mirage/internal/receipt"
	"github.com/MrGray17/Mirage/internal/runtime/qwenagent"
	"github.com/MrGray17/Mirage/internal/runtime/reconcile"
	"github.com/MrGray17/Mirage/internal/runtime/tree"
	"github.com/MrGray17/Mirage/internal/runtime/workspace"
)

type qwenProductSpec struct {
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
	RealWorkspace      string
	CleanupComplete    bool
	ProcessTreeStopped bool
	Reality            string
	EvidenceOut        string
	ObservatoryOut     string
	OutputDir          string
}

func persistQwenProductEvidence(spec qwenProductSpec) (cliapi.AgentRunSummary, error) {
	if !spec.CleanupComplete {
		return cliapi.AgentRunSummary{}, errors.New("refuse to persist Qwen evidence before complete runtime cleanup")
	}
	graph, executionReceipt, err := agentproduct.Build(agentproduct.Spec{
		RunID: spec.RunID, Task: spec.Task, ContractHash: spec.ContractHash, ManifestHash: spec.ManifestHash,
		StartedAt: spec.StartedAt, CompletedAt: spec.CompletedAt, AgentImage: spec.AgentImage,
		SandboxIdentity: spec.SandboxIdentity, Actions: spec.Actions, Plan: spec.Plan, Decision: spec.Decision,
		Committed: spec.Committed, CommitPlan: spec.CommitPlan,
		ProcessTreeStopped: spec.ProcessTreeStopped, CleanupComplete: spec.CleanupComplete, Reality: spec.Reality,
	})
	if err != nil {
		return cliapi.AgentRunSummary{}, err
	}
	encoded, err := receipt.Marshal(executionReceipt)
	if err != nil {
		return cliapi.AgentRunSummary{}, err
	}
	receiptPath, pagePath, err := qwenEvidencePaths(spec)
	if err != nil {
		return cliapi.AgentRunSummary{}, err
	}
	if err := writeNewEvidence(receiptPath, encoded); err != nil {
		return cliapi.AgentRunSummary{}, err
	}
	persisted, err := readBoundedRegular(receiptPath, 4<<20)
	if err != nil {
		return cliapi.AgentRunSummary{}, fmt.Errorf("read persisted Qwen receipt: %w", err)
	}
	verified, err := receipt.ParseAndVerify(persisted)
	if err != nil {
		return cliapi.AgentRunSummary{}, fmt.Errorf("verify persisted Qwen receipt: %w", err)
	}
	page, err := observatory.Render(verified)
	if err != nil {
		return cliapi.AgentRunSummary{}, err
	}
	if err := writeNewEvidence(pagePath, page); err != nil {
		return cliapi.AgentRunSummary{}, err
	}
	summary := cliapi.AgentRunSummary{
		Schema: cliapi.AgentRunSchemaV2, RunID: spec.RunID, Agent: "structured-qwen-agent", Outcome: verified.Outcome,
		Attempted: len(verified.AttemptedEffects), Authorized: len(verified.AuthorizedEffects), Denied: len(verified.DeniedEffects),
		Observed: len(verified.ObservedMutations), Committed: len(verified.CommittedMutations), Verification: verified.Verification,
		ReceiptValid: true, GraphHash: graph.Hash, ReceiptHash: verified.SHA256, ReceiptPath: receiptPath,
		ObservatoryPath: pagePath, WorkspacePath: spec.RealWorkspace, CleanupComplete: true,
	}
	if err := summary.Validate(); err != nil {
		return cliapi.AgentRunSummary{}, err
	}
	return summary, nil
}

func qwenEvidencePaths(spec qwenProductSpec) (string, string, error) {
	receiptPath := strings.TrimSpace(spec.EvidenceOut)
	if strings.TrimSpace(spec.OutputDir) != "" {
		receiptPath = filepath.Join(spec.OutputDir, spec.RunID, "receipt.json")
	} else if receiptPath == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			return "", "", fmt.Errorf("locate Qwen evidence root: %w", err)
		}
		receiptPath = filepath.Join(cache, "mirage", "runs", spec.RunID, "receipt.json")
	}
	receiptPath, err := filepath.Abs(receiptPath)
	if err != nil {
		return "", "", fmt.Errorf("resolve Qwen receipt output: %w", err)
	}
	pagePath := strings.TrimSpace(spec.ObservatoryOut)
	if pagePath == "" {
		pagePath = strings.TrimSuffix(receiptPath, filepath.Ext(receiptPath)) + ".observatory.html"
	}
	pagePath, err = filepath.Abs(pagePath)
	if err != nil {
		return "", "", fmt.Errorf("resolve Qwen Observatory output: %w", err)
	}
	if strings.TrimSpace(spec.RealWorkspace) != "" {
		for _, target := range []string{receiptPath, pagePath} {
			inside, err := pathResolvesWithin(spec.RealWorkspace, target)
			if err != nil {
				return "", "", fmt.Errorf("establish Qwen evidence output isolation: %w", err)
			}
			if inside {
				return "", "", errors.New("Qwen evidence output must remain outside the trusted real workspace")
			}
		}
	}
	return receiptPath, pagePath, nil
}

func pathResolvesWithin(rootPath, targetPath string) (bool, error) {
	rootPath, err := filepath.Abs(rootPath)
	if err != nil {
		return false, err
	}
	rootPath, err = filepath.EvalSymlinks(rootPath)
	if err != nil {
		return false, err
	}
	targetPath, err = resolveThroughExistingAncestor(targetPath)
	if err != nil {
		return false, err
	}
	relative, err := filepath.Rel(rootPath, targetPath)
	if err != nil {
		return false, err
	}
	return relative == "." || (!filepath.IsAbs(relative) && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))), nil
}

func resolveThroughExistingAncestor(target string) (string, error) {
	target, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	ancestor := target
	var suffix []string
	for {
		if _, err := os.Lstat(ancestor); err == nil {
			resolved, err := filepath.EvalSymlinks(ancestor)
			if err != nil {
				return "", err
			}
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			return filepath.Clean(resolved), nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return "", errors.New("Qwen evidence output has no existing ancestor")
		}
		suffix = append(suffix, filepath.Base(ancestor))
		ancestor = parent
	}
}

func preflightQwenEvidence(spec qwenProductSpec) error {
	receiptPath, pagePath, err := qwenEvidencePaths(spec)
	if err != nil {
		return err
	}
	if receiptPath == pagePath {
		return errors.New("Qwen receipt and Observatory paths must differ")
	}
	for _, target := range []string{receiptPath, pagePath} {
		if _, err := os.Lstat(target); err == nil {
			return fmt.Errorf("Qwen evidence target already exists: %s", target)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("establish Qwen evidence target absence: %w", err)
		}
	}
	return nil
}

func emitQwenSummary(writer io.Writer, summary cliapi.AgentRunSummary, format string) error {
	if format == "json" {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(summary)
	}
	fmt.Fprintf(writer, "\nQwen Evidence:\noutcome=%s attempted=%d authorized=%d denied=%d observed=%d committed=%d\n", summary.Outcome, summary.Attempted, summary.Authorized, summary.Denied, summary.Observed, summary.Committed)
	fmt.Fprintf(writer, "effect_graph=%s\nreceipt=%s\nreceipt_file=%s\nobservatory=%s\nreceipt_status=VALID\n", summary.GraphHash, summary.ReceiptHash, summary.ReceiptPath, summary.ObservatoryPath)
	return nil
}

func verifyCommittedReality(realWorkspace string, plan *tree.Plan) error {
	if plan == nil || len(plan.Mutations()) != 1 {
		return errors.New("committed Qwen evidence requires exactly one trusted mutation")
	}
	mutation := plan.Mutations()[0]
	prefix := "/workspace/"
	if mutation.Operation != tree.OperationModify || !strings.HasPrefix(mutation.Resource, prefix) {
		return errors.New("committed Qwen evidence has an unsupported mutation")
	}
	name := strings.TrimPrefix(mutation.Resource, prefix)
	root, err := os.OpenRoot(realWorkspace)
	if err != nil {
		return fmt.Errorf("open real workspace for evidence readback: %w", err)
	}
	defer root.Close()
	file, err := root.Open(name)
	if err != nil {
		return fmt.Errorf("open committed real file for evidence readback: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.Join(errors.New("committed real resource is not a regular file"), err)
	}
	content, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil || len(content) > 1<<20 {
		return errors.Join(errors.New("committed real resource exceeds evidence readback bound"), err)
	}
	digest := sha256.Sum256(content)
	if fmt.Sprintf("sha256:%x", digest) != mutation.AfterDigest {
		return errors.New("real resource differs from trusted committed mutation")
	}
	return nil
}

func verifyRejectedReality(binding workspace.Binding) error {
	baseline := binding.RealBaseline()
	current, err := binding.ObserveReal()
	if err != nil {
		return fmt.Errorf("observe rejected real workspace: %w", err)
	}
	if baseline == nil || current.Identity() != baseline.Identity() {
		return errors.New("real workspace changed during rejected Qwen run")
	}
	return nil
}
