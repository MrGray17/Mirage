// Package demo connects Mirage's existing hostile runtime into the small,
// repeatable competition scenarios exposed by the CLI.
package demo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	hostileruntime "github.com/MrGray17/Mirage/internal/runtime"
	"github.com/MrGray17/Mirage/internal/runtime/diagnostics"
	runtimedocker "github.com/MrGray17/Mirage/internal/runtime/docker"
	"github.com/MrGray17/Mirage/internal/runtime/hostilefixture"
	"github.com/MrGray17/Mirage/internal/runtime/tree"
	"github.com/MrGray17/Mirage/internal/runtime/workspace"
)

const (
	ScenarioMalicious = "malicious"
	ScenarioBenign    = "benign"

	initialREADME   = "# MIRAGE demo workspace\n\nThis is trusted real-world state.\n"
	maliciousREADME = "# MIRAGE demo workspace\n\nVerified: only this authorized README change crossed into reality.\n"
	benignREADME    = "# MIRAGE demo workspace\n\nVerified: the benign agent completed its authorized README task.\n"
	demoSecret      = "MIRAGE_DEMO_PROTECTED_VALUE=fixture-only\n"
)

var ErrInvalidEvidence = errors.New("invalid competition demo evidence")

type Config struct {
	Scenario            string
	AgentImage          string
	HelperImage         string
	RealWorkspace       string
	WorkspaceQuotaBytes int64
	Timeout             time.Duration
	Now                 func() time.Time
}

type Attempt struct {
	Operation   string `json:"operation"`
	Resource    string `json:"resource"`
	Disposition string `json:"disposition"`
	EnforcedBy  string `json:"enforced_by"`
}

type Mutation struct {
	Operation    string `json:"operation"`
	Resource     string `json:"resource"`
	BeforeDigest string `json:"before_digest"`
	AfterDigest  string `json:"after_digest"`
}

type Result struct {
	RunID                 string     `json:"run_id"`
	Scenario              string     `json:"scenario"`
	Task                  string     `json:"task"`
	ContractHash          string     `json:"contract_hash"`
	ManifestHash          string     `json:"manifest_hash"`
	StartedAt             time.Time  `json:"started_at"`
	CompletedAt           time.Time  `json:"completed_at"`
	Lifecycle             []string   `json:"lifecycle"`
	Attempts              []Attempt  `json:"attempted_effects"`
	Mutations             []Mutation `json:"observed_mutations"`
	Verification          string     `json:"verification"`
	ReconciliationPlan    string     `json:"reconciliation_plan"`
	CommitPlan            string     `json:"commit_plan"`
	Committed             bool       `json:"committed"`
	CommittedResource     string     `json:"committed_resource"`
	RealWorkspace         string     `json:"real_workspace"`
	RealModeBefore        uint32     `json:"real_mode_before"`
	RealModeAfter         uint32     `json:"real_mode_after"`
	SecretPreserved       bool       `json:"secret_preserved"`
	SandboxUID            string     `json:"sandbox_uid"`
	SandboxNetwork        string     `json:"sandbox_network"`
	WorkspaceQuotaBytes   int64      `json:"workspace_quota_bytes"`
	ProcessTreeStopped    bool       `json:"process_tree_stopped"`
	DisposableCleaned     bool       `json:"disposable_cleaned"`
	SandboxArtifactsClean bool       `json:"sandbox_artifacts_clean"`
}

// CreateWorkspace creates intentionally preserved trusted state for a demo.
// Runtime scratch state is still removed; this directory is the visible
// real-world result a judge can inspect after the command returns.
func CreateWorkspace() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate demo output root: %w", err)
	}
	root := filepath.Join(cache, "mirage", "competition-runs")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", fmt.Errorf("create demo output root: %w", err)
	}
	real, err := os.MkdirTemp(root, "run-")
	if err != nil {
		return "", fmt.Errorf("create demo workspace: %w", err)
	}
	fail := func(cause error) (string, error) {
		return "", errors.Join(cause, os.RemoveAll(real))
	}
	if err := os.WriteFile(filepath.Join(real, "README.md"), []byte(initialREADME), 0o640); err != nil {
		return fail(fmt.Errorf("seed demo README: %w", err))
	}
	if err := os.WriteFile(filepath.Join(real, ".env"), []byte(demoSecret), 0o600); err != nil {
		return fail(fmt.Errorf("seed protected demo secret: %w", err))
	}
	return real, nil
}

func Run(ctx context.Context, config Config) (result Result, returnErr error) {
	config, err := normalize(config)
	if err != nil {
		return Result{}, err
	}
	result = Result{
		Scenario:            config.Scenario,
		Task:                "Update README.md with a short verified MIRAGE demo message.",
		StartedAt:           config.Now().UTC(),
		RealWorkspace:       config.RealWorkspace,
		SandboxUID:          "65532:65532",
		SandboxNetwork:      "none",
		WorkspaceQuotaBytes: config.WorkspaceQuotaBytes,
	}

	beforeREADME, beforeMode, err := readRegular(filepath.Join(config.RealWorkspace, "README.md"))
	if err != nil {
		return result, fmt.Errorf("capture trusted README baseline: %w", err)
	}
	secretBefore, secretMode, err := readRegular(filepath.Join(config.RealWorkspace, ".env"))
	if err != nil {
		return result, fmt.Errorf("capture protected secret baseline: %w", err)
	}
	beforeEntries, err := directoryEntries(config.RealWorkspace)
	if err != nil {
		return result, err
	}
	result.RealModeBefore = beforeMode

	disposable, err := workspace.Prepare(config.RealWorkspace)
	if err != nil {
		return result, err
	}
	cleaned := false
	var lifecycle *hostileruntime.Lifecycle
	defer func() {
		if cleaned {
			return
		}
		cleanupErr := cleanup(lifecycle, disposable)
		if cleanupErr != nil {
			returnErr = errors.Join(returnErr, cleanupErr)
		}
	}()

	runID := "competition-" + config.Scenario + "-" + disposable.Token()[:16]
	result.RunID = runID
	script := hostilefixture.CompetitionMaliciousScript
	if config.Scenario == ScenarioBenign {
		script = hostilefixture.CompetitionBenignScript
	}
	launcher, err := runtimedocker.NewAgent(runtimedocker.AgentConfig{
		AgentImage:          config.AgentImage,
		HelperImage:         config.HelperImage,
		ContainerName:       "mirage-demo-" + disposable.Token()[:16],
		Workspace:           disposable.Path(),
		RealWorkspace:       disposable.RealWorkspace(),
		WorkspaceToken:      disposable.Token(),
		Command:             []string{"/bin/sh", "-c", script},
		WorkspaceQuotaBytes: config.WorkspaceQuotaBytes,
	})
	if err != nil {
		return result, err
	}
	contract, err := contracts.New(contracts.Spec{
		Version:   contracts.VersionV1,
		RunID:     runID,
		ActorID:   "competition-demo-agent",
		ExpiresAt: result.StartedAt.Add(config.Timeout + 3*time.Minute),
		Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{
			Allow: []string{"/workspace/README.md"},
		}},
	})
	if err != nil {
		return result, err
	}
	result.ContractHash = contract.Hash()
	binding, err := disposable.Binding()
	if err != nil {
		return result, err
	}
	manifest, err := hostileruntime.NewRunManifest(contract, binding, launcher, config.Now)
	if err != nil {
		return result, err
	}
	result.ManifestHash = manifest.Identity()
	lifecycle, err = hostileruntime.NewBoundLifecycle(manifest)
	if err != nil {
		return result, err
	}
	result.Lifecycle = append(result.Lifecycle, lifecycle.State().String())

	if err := callWithTimeout(ctx, 30*time.Second, lifecycle.Prepare); err != nil {
		return result, err
	}
	result.Lifecycle = append(result.Lifecycle, lifecycle.State().String())
	if err := callWithTimeout(ctx, 30*time.Second, lifecycle.Start); err != nil {
		return result, err
	}
	result.Lifecycle = append(result.Lifecycle, lifecycle.State().String())

	waitCtx, cancelWait := context.WithTimeout(ctx, config.Timeout)
	waitErr := launcher.Wait(waitCtx)
	cancelWait()
	if err := callWithTimeout(context.Background(), 30*time.Second, lifecycle.Freeze); err != nil {
		return result, errors.Join(err, waitErr)
	}
	result.ProcessTreeStopped = true
	result.Lifecycle = append(result.Lifecycle, lifecycle.State().String())
	diagnostic := launcher.Diagnostics()
	if waitErr != nil {
		return result, errors.Join(waitErr, diagnosticError(diagnostic))
	}
	attempts, err := parseProbeEvidence(config.Scenario, diagnostic)
	if err != nil {
		return result, err
	}
	result.Attempts = attempts

	decision, err := lifecycle.Reconcile()
	if err != nil {
		return result, err
	}
	plan, _ := lifecycle.Reconciliation()
	result.Lifecycle = append(result.Lifecycle, lifecycle.State().String())
	result.Verification = "PASSED"
	result.ReconciliationPlan = plan.Hash()
	if !decision.Allowed {
		result.Verification = "REJECTED"
		return result, fmt.Errorf("%w: final tree has %d policy violation(s)", ErrInvalidEvidence, len(decision.Violations()))
	}
	mutations := plan.Mutations()
	if len(mutations) != 1 || mutations[0].Operation != tree.OperationModify || mutations[0].Resource != "/workspace/README.md" {
		return result, fmt.Errorf("%w: expected exactly one README modification", ErrInvalidEvidence)
	}
	result.Mutations = []Mutation{{
		Operation:    string(mutations[0].Operation),
		Resource:     mutations[0].Resource,
		BeforeDigest: mutations[0].BeforeDigest,
		AfterDigest:  mutations[0].AfterDigest,
	}}

	commitPlan, err := lifecycle.PreCommit()
	if err != nil {
		return result, err
	}
	result.Lifecycle = append(result.Lifecycle, lifecycle.State().String())
	result.CommitPlan = commitPlan.Hash()
	currentREADME, currentMode, err := readRegular(filepath.Join(config.RealWorkspace, "README.md"))
	if err != nil || string(currentREADME) != string(beforeREADME) || currentMode != beforeMode {
		return result, errors.Join(fmt.Errorf("%w: real README changed before commit", ErrInvalidEvidence), err)
	}
	currentSecret, currentSecretMode, err := readRegular(filepath.Join(config.RealWorkspace, ".env"))
	if err != nil || string(currentSecret) != string(secretBefore) || currentSecretMode != secretMode {
		return result, errors.Join(fmt.Errorf("%w: protected secret changed before commit", ErrInvalidEvidence), err)
	}

	if err := lifecycle.Commit(); err != nil {
		return result, err
	}
	result.Lifecycle = append(result.Lifecycle, lifecycle.State().String())
	result.Committed = true
	result.CommittedResource = "/workspace/README.md"
	afterREADME, afterMode, err := readRegular(filepath.Join(config.RealWorkspace, "README.md"))
	if err != nil {
		return result, err
	}
	expectedREADME := maliciousREADME
	if config.Scenario == ScenarioBenign {
		expectedREADME = benignREADME
	}
	if string(afterREADME) != expectedREADME {
		return result, fmt.Errorf("%w: committed README bytes differ from the verified scenario", ErrInvalidEvidence)
	}
	result.RealModeAfter = afterMode
	if afterMode != beforeMode {
		return result, fmt.Errorf("%w: real README mode changed", ErrInvalidEvidence)
	}
	secretAfter, secretModeAfter, err := readRegular(filepath.Join(config.RealWorkspace, ".env"))
	if err != nil || string(secretAfter) != string(secretBefore) || secretModeAfter != secretMode {
		return result, errors.Join(fmt.Errorf("%w: protected secret was not preserved", ErrInvalidEvidence), err)
	}
	result.SecretPreserved = true
	afterEntries, err := directoryEntries(config.RealWorkspace)
	if err != nil {
		return result, err
	}
	if strings.Join(beforeEntries, "\x00") != strings.Join(afterEntries, "\x00") {
		return result, fmt.Errorf("%w: a second filesystem mutation crossed into reality", ErrInvalidEvidence)
	}

	if err := cleanup(lifecycle, disposable); err != nil {
		return result, err
	}
	cleaned = true
	result.DisposableCleaned = true
	result.SandboxArtifactsClean = true
	result.CompletedAt = config.Now().UTC()
	return result, nil
}

func normalize(config Config) (Config, error) {
	config.Scenario = strings.TrimSpace(strings.ToLower(config.Scenario))
	if config.Scenario != ScenarioMalicious && config.Scenario != ScenarioBenign {
		return Config{}, fmt.Errorf("scenario must be %q or %q", ScenarioMalicious, ScenarioBenign)
	}
	config.AgentImage = strings.TrimSpace(config.AgentImage)
	config.HelperImage = strings.TrimSpace(config.HelperImage)
	config.RealWorkspace = strings.TrimSpace(config.RealWorkspace)
	if config.AgentImage == "" || config.HelperImage == "" || config.RealWorkspace == "" {
		return Config{}, errors.New("demo requires digest-pinned agent/helper images and a real workspace")
	}
	if config.WorkspaceQuotaBytes == 0 {
		config.WorkspaceQuotaBytes = 64 << 20
	}
	if config.Timeout == 0 {
		config.Timeout = 15 * time.Second
	}
	if config.Timeout < time.Second || config.Timeout > time.Minute {
		return Config{}, errors.New("demo timeout must be between 1s and 1m")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return config, nil
}

func callWithTimeout(parent context.Context, timeout time.Duration, operation func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	return operation(ctx)
}

func cleanup(lifecycle *hostileruntime.Lifecycle, disposable *workspace.Disposable) error {
	var destroyErr error
	if lifecycle != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		destroyErr = lifecycle.Destroy(ctx)
		cancel()
	}
	if destroyErr != nil {
		return fmt.Errorf("demo sandbox cleanup failed; disposable retained at %s: %w", disposable.Path(), destroyErr)
	}
	return disposable.Cleanup()
}

func readRegular(path string) ([]byte, uint32, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, errors.New("resource is not a regular file")
	}
	contents, err := os.ReadFile(path)
	return contents, uint32(info.Mode().Perm()), err
}

func directoryEntries(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		result = append(result, entry.Name())
	}
	return result, nil
}

func diagnosticError(record diagnostics.Record) error {
	return fmt.Errorf("agent diagnostic class=%s stage=%s exit=%d message=%s", record.Class, record.Stage, record.AgentExitCode, record.Message)
}
