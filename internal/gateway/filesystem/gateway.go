// Package filesystem mediates the M3 prototype's shadow filesystem effects.
// It does not provide OS isolation; M4 must prevent an agent from bypassing it.
package filesystem

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/effects"
)

const ManagedResource = "/workspace/README.md"

var (
	ErrDenied          = errors.New("filesystem effect denied")
	ErrInvalidGateway  = errors.New("invalid filesystem gateway")
	ErrEffectRecording = errors.New("effect recording failed")
)

type DeniedError struct {
	Operation string
	Resource  string
	RuleID    string
	Reason    string
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("%s: %s %s: %s (%s)", ErrDenied, e.Operation, e.Resource, e.Reason, e.RuleID)
}

func (e *DeniedError) Unwrap() error { return ErrDenied }

// Gateway applies allowed operations only to the transaction-owned shadow and
// records every request, including denied and failed attempts.
type Gateway struct {
	mu       sync.Mutex
	contract *contracts.Contract
	log      *effects.Log
	shadow   string
	now      func() time.Time
	auditErr error
}

func New(contract *contracts.Contract, log *effects.Log, shadowWorkspace string, now func() time.Time) (*Gateway, error) {
	if contract == nil || log == nil || now == nil || strings.TrimSpace(shadowWorkspace) == "" {
		return nil, fmt.Errorf("%w: contract, event log, shadow workspace, and clock are required", ErrInvalidGateway)
	}
	absolute, err := filepath.Abs(shadowWorkspace)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve shadow workspace: %w", ErrInvalidGateway, err)
	}
	info, err := os.Stat(absolute)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("%w: shadow workspace is not a directory", ErrInvalidGateway)
	}
	return &Gateway{
		contract: contract,
		log:      log,
		shadow:   filepath.Clean(absolute),
		now:      now,
	}, nil
}

func (g *Gateway) ReadFile(requestedResource string) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	at := g.now().UTC()
	resource, policyDecision := g.authorize(contracts.FilesystemRead, requestedResource, at)
	if !policyDecision.Allowed {
		return nil, g.recordDenied(contracts.FilesystemRead, resource, policyDecision, requestedResource, at)
	}

	contents, err := readRegularFile(filepath.Join(g.shadow, "README.md"))
	outcome := effects.OutcomeSuccess
	metadata := policyMetadata(policyDecision)
	if err != nil {
		outcome = effects.OutcomeFailed
		metadata["error_class"] = "shadow_read_failed"
	}
	if recordErr := g.record(contracts.FilesystemRead, resource, effects.DecisionAllow, outcome, metadata, at); recordErr != nil {
		return nil, errors.Join(fmt.Errorf("%w: %w", ErrEffectRecording, recordErr), err)
	}
	if err != nil {
		return nil, fmt.Errorf("read shadow resource %s: %w", resource, err)
	}
	return contents, nil
}

func (g *Gateway) WriteFile(requestedResource string, contents []byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	at := g.now().UTC()
	resource, policyDecision := g.authorize(contracts.FilesystemWrite, requestedResource, at)
	if !policyDecision.Allowed {
		return g.recordDenied(contracts.FilesystemWrite, resource, policyDecision, requestedResource, at)
	}

	err := writeRegularFile(filepath.Join(g.shadow, "README.md"), contents)
	outcome := effects.OutcomeSuccessShadow
	metadata := policyMetadata(policyDecision)
	if err != nil {
		outcome = effects.OutcomeFailed
		metadata["error_class"] = "shadow_write_failed"
	}
	if recordErr := g.record(contracts.FilesystemWrite, resource, effects.DecisionAllow, outcome, metadata, at); recordErr != nil {
		return errors.Join(fmt.Errorf("%w: %w", ErrEffectRecording, recordErr), err)
	}
	if err != nil {
		return fmt.Errorf("write shadow resource %s: %w", resource, err)
	}
	return nil
}

// AuditError reports a recording failure that must reject verification even if
// the caller ignored the operation error.
func (g *Gateway) AuditError() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.auditErr
}

func (g *Gateway) authorize(operation contracts.FilesystemOperation, requested string, at time.Time) (string, contracts.Decision) {
	resource, err := canonicalResource(requested)
	if err != nil {
		return invalidResourceIdentity(requested), contracts.Decision{
			RuleID:   "filesystem.invalid_resource",
			Reason:   "resource path is not a canonical workspace path",
			Evidence: invalidResourceIdentity(requested),
		}
	}
	decision := g.contract.EvaluateFilesystem(operation, resource, at)
	if decision.Allowed && resource != ManagedResource {
		return resource, contracts.Decision{
			RuleID:   "filesystem.unsupported_resource",
			Reason:   "M3 filesystem adapter supports only README.md",
			Evidence: resource,
		}
	}
	return resource, decision
}

func (g *Gateway) recordDenied(operation contracts.FilesystemOperation, resource string, decision contracts.Decision, requested string, at time.Time) error {
	metadata := policyMetadata(decision)
	metadata["requested_resource_sha256"] = digestString(requested)
	recordErr := g.record(operation, resource, effects.DecisionDeny, effects.OutcomeBlocked, metadata, at)
	denied := &DeniedError{
		Operation: string(operation),
		Resource:  resource,
		RuleID:    decision.RuleID,
		Reason:    decision.Reason,
	}
	if recordErr != nil {
		return errors.Join(denied, fmt.Errorf("%w: %w", ErrEffectRecording, recordErr))
	}
	return denied
}

func (g *Gateway) record(operation contracts.FilesystemOperation, resource string, decision effects.Decision, outcome effects.Outcome, metadata map[string]string, at time.Time) error {
	_, err := g.log.Append(effects.Attempt{
		Adapter:        effects.AdapterFilesystem,
		Operation:      string(operation),
		ResourceType:   effects.ResourceTypeFile,
		ResourceID:     resource,
		Classification: effects.ClassShadowLocal,
		Phase:          effects.PhaseExecution,
		Decision:       decision,
		Outcome:        outcome,
		Timestamp:      at,
		Metadata:       metadata,
	})
	if err != nil {
		g.auditErr = errors.Join(g.auditErr, err)
	}
	return err
}

func canonicalResource(requested string) (string, error) {
	if requested == "" || strings.ContainsRune(requested, '\x00') {
		return "", errors.New("empty or NUL-containing resource")
	}
	normalized := strings.ReplaceAll(requested, "\\", "/")
	if strings.HasPrefix(normalized, "//") || (len(normalized) >= 2 && normalized[1] == ':') {
		return "", errors.New("host-absolute resource")
	}
	var relative string
	switch {
	case strings.HasPrefix(normalized, "/workspace/"):
		relative = strings.TrimPrefix(normalized, "/workspace/")
	case strings.HasPrefix(normalized, "/"):
		return "", errors.New("resource is outside virtual workspace")
	default:
		relative = normalized
	}
	cleaned := path.Clean(relative)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", errors.New("resource traverses virtual workspace")
	}
	return "/workspace/" + cleaned, nil
}

func readRegularFile(filePath string) ([]byte, error) {
	info, err := os.Lstat(filePath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("resource type %s is not regular", info.Mode().Type())
	}
	return os.ReadFile(filePath)
}

func writeRegularFile(filePath string, contents []byte) error {
	info, err := os.Lstat(filePath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("resource type %s is not regular", info.Mode().Type())
	}
	return os.WriteFile(filePath, contents, info.Mode().Perm())
}

func policyMetadata(decision contracts.Decision) map[string]string {
	return map[string]string{
		"rule_id": decision.RuleID,
		"reason":  decision.Reason,
	}
}

func invalidResourceIdentity(requested string) string {
	return "invalid:" + digestString(requested)
}

func digestString(value string) string {
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("sha256:%x", digest)
}
