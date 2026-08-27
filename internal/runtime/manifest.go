package runtime

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/runtime/workspace"
	"github.com/MrGray17/Mirage/internal/trustedtime"
)

const (
	runManifestVersion    = "mirage.runtime-manifest/v1"
	trustedClockAuthority = "mirage.trustedtime/monotonic-wall-v1"
)

var (
	ErrInvalidManifest = errors.New("invalid hostile run manifest")
	ErrManifestExpired = errors.New("hostile run manifest contract expired")
)

// RunManifest binds all authority-bearing M4.3 inputs before hostile
// execution. Its fields are private and every exposed value is immutable.
type RunManifest struct {
	identity        string
	startedAt       time.Time
	contract        *contracts.Contract
	contractHash    string
	clock           *trustedtime.Clock
	workspace       workspace.Binding
	sandbox         Sandbox
	sandboxIdentity string
}

func NewRunManifest(contract *contracts.Contract, workspaceBinding workspace.Binding, sandbox Sandbox, now func() time.Time) (*RunManifest, error) {
	if contract == nil || sandbox == nil {
		return nil, fmt.Errorf("%w: contract and sandbox are required", ErrInvalidManifest)
	}
	if workspaceBinding.Identity() == "" || workspaceBinding.RealBaseline() == nil || workspaceBinding.DisposableBaseline() == nil {
		return nil, fmt.Errorf("%w: workspace binding is incomplete", ErrInvalidManifest)
	}
	sandboxIdentity := strings.TrimSpace(sandbox.Identity())
	if sandboxIdentity == "" {
		return nil, fmt.Errorf("%w: sandbox identity is empty", ErrInvalidManifest)
	}
	real, disposable, token := sandbox.BoundWorkspace()
	if real != workspaceBinding.RealWorkspace() || disposable != workspaceBinding.DisposableWorkspace() || token != workspaceBinding.Token() {
		return nil, fmt.Errorf("%w: sandbox and workspace binding differ", ErrInvalidManifest)
	}
	clock, err := trustedtime.New(now)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidManifest, err)
	}
	startedAt, err := clock.Observe()
	if err != nil {
		return nil, fmt.Errorf("%w: establish trusted start time: %w", ErrInvalidManifest, err)
	}
	if contract.ExpiredAt(startedAt) {
		return nil, fmt.Errorf("%w: %s", ErrManifestExpired, contract.ExpiresAt().Format(time.RFC3339Nano))
	}
	canonical := struct {
		Version            string `json:"version"`
		RunID              string `json:"run_id"`
		ActorID            string `json:"actor_id"`
		ContractHash       string `json:"contract_hash"`
		StartedAt          string `json:"started_at"`
		ClockAuthority     string `json:"clock_authority"`
		WorkspaceIdentity  string `json:"workspace_identity"`
		RealBaseline       string `json:"real_baseline"`
		DisposableBaseline string `json:"disposable_baseline"`
		SandboxIdentity    string `json:"sandbox_identity"`
	}{
		Version:            runManifestVersion,
		RunID:              contract.RunID(),
		ActorID:            contract.ActorID(),
		ContractHash:       contract.Hash(),
		StartedAt:          startedAt.Format(time.RFC3339Nano),
		ClockAuthority:     trustedClockAuthority,
		WorkspaceIdentity:  workspaceBinding.Identity(),
		RealBaseline:       workspaceBinding.RealBaseline().Identity(),
		DisposableBaseline: workspaceBinding.DisposableBaseline().Identity(),
		SandboxIdentity:    sandboxIdentity,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize: %v", ErrInvalidManifest, err)
	}
	digest := sha256.Sum256(encoded)
	return &RunManifest{
		identity:        fmt.Sprintf("sha256:%x", digest),
		startedAt:       startedAt,
		contract:        contract,
		contractHash:    contract.Hash(),
		clock:           clock,
		workspace:       workspaceBinding,
		sandbox:         sandbox,
		sandboxIdentity: sandboxIdentity,
	}, nil
}

func (m *RunManifest) Identity() string {
	if m == nil {
		return ""
	}
	return m.identity
}

func (m *RunManifest) RunID() string {
	if m == nil || m.contract == nil {
		return ""
	}
	return m.contract.RunID()
}

func (m *RunManifest) ActorID() string {
	if m == nil || m.contract == nil {
		return ""
	}
	return m.contract.ActorID()
}

func (m *RunManifest) ContractHash() string {
	if m == nil {
		return ""
	}
	return m.contractHash
}

func (m *RunManifest) RealBaselineIdentity() string {
	if m == nil || m.workspace.RealBaseline() == nil {
		return ""
	}
	return m.workspace.RealBaseline().Identity()
}

func (m *RunManifest) DisposableBaselineIdentity() string {
	if m == nil || m.workspace.DisposableBaseline() == nil {
		return ""
	}
	return m.workspace.DisposableBaseline().Identity()
}

func (m *RunManifest) validateSandbox() error {
	if m == nil || m.sandbox == nil || m.sandbox.Identity() != m.sandboxIdentity {
		return fmt.Errorf("%w: sandbox identity changed", ErrInvalidManifest)
	}
	real, disposable, token := m.sandbox.BoundWorkspace()
	if real != m.workspace.RealWorkspace() || disposable != m.workspace.DisposableWorkspace() || token != m.workspace.Token() {
		return fmt.Errorf("%w: sandbox workspace binding changed", ErrInvalidManifest)
	}
	return nil
}
