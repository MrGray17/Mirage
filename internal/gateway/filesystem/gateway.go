// Package filesystem mediates the M3 prototype's shadow filesystem effects.
// It does not provide OS isolation; M4 must prevent an agent from bypassing it.
package filesystem

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
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
	ErrUnsafeResource  = errors.New("unsafe filesystem resource")
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
	auditErr error
}

func New(contract *contracts.Contract, log *effects.Log, shadowWorkspace string) (*Gateway, error) {
	if contract == nil || log == nil || strings.TrimSpace(shadowWorkspace) == "" {
		return nil, fmt.Errorf("%w: contract, event log, and shadow workspace are required", ErrInvalidGateway)
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
	}, nil
}

func (g *Gateway) ReadFile(requestedResource string) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	at, err := g.log.TrustedTime()
	if err != nil {
		return nil, g.recordTimeFailure(err)
	}
	resource, policyDecision := g.authorize(contracts.FilesystemRead, requestedResource, at)
	if !policyDecision.Allowed {
		return nil, g.recordDenied(contracts.FilesystemRead, resource, policyDecision, requestedResource)
	}

	contents, err := readRegularFile(g.shadow)
	outcome := effects.OutcomeSuccess
	metadata := policyMetadata(policyDecision)
	if err != nil {
		outcome = effects.OutcomeFailed
		metadata["error_class"] = "shadow_read_failed"
	}
	if recordErr := g.record(contracts.FilesystemRead, resource, effects.DecisionAllow, outcome, metadata); recordErr != nil {
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

	at, err := g.log.TrustedTime()
	if err != nil {
		return g.recordTimeFailure(err)
	}
	resource, policyDecision := g.authorize(contracts.FilesystemWrite, requestedResource, at)
	if !policyDecision.Allowed {
		return g.recordDenied(contracts.FilesystemWrite, resource, policyDecision, requestedResource)
	}

	err = writeRegularFile(g.shadow, contents)
	outcome := effects.OutcomeSuccessShadow
	metadata := policyMetadata(policyDecision)
	if err != nil {
		outcome = effects.OutcomeFailed
		metadata["error_class"] = "shadow_write_failed"
	}
	if recordErr := g.record(contracts.FilesystemWrite, resource, effects.DecisionAllow, outcome, metadata); recordErr != nil {
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

func (g *Gateway) recordDenied(operation contracts.FilesystemOperation, resource string, decision contracts.Decision, requested string) error {
	metadata := policyMetadata(decision)
	metadata["requested_resource_sha256"] = digestString(requested)
	recordErr := g.record(operation, resource, effects.DecisionDeny, effects.OutcomeBlocked, metadata)
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

func (g *Gateway) record(operation contracts.FilesystemOperation, resource string, decision effects.Decision, outcome effects.Outcome, metadata map[string]string) error {
	_, err := g.log.Append(effects.Attempt{
		Adapter:        effects.AdapterFilesystem,
		Operation:      string(operation),
		ResourceType:   effects.ResourceTypeFile,
		ResourceID:     resource,
		Classification: effects.ClassShadowLocal,
		Phase:          effects.PhaseExecution,
		Decision:       decision,
		Outcome:        outcome,
		Metadata:       metadata,
	})
	if err != nil {
		g.auditErr = errors.Join(g.auditErr, err)
	}
	return err
}

func (g *Gateway) recordTimeFailure(err error) error {
	g.auditErr = errors.Join(g.auditErr, err)
	return fmt.Errorf("%w: %w", ErrEffectRecording, err)
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

func readRegularFile(workspace string) ([]byte, error) {
	return readRegularFileWithHook(workspace, nil)
}

func readRegularFileWithHook(workspace string, afterInitialInspection func()) (contents []byte, returnErr error) {
	root, file, openedInfo, err := acquireRegularFile(workspace, os.O_RDONLY, afterInitialInspection)
	if err != nil {
		return nil, err
	}
	defer func() {
		returnErr = errors.Join(returnErr, closeAcquiredFile(root, file))
	}()

	contents, err = io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("read rooted README.md: %w", err)
	}
	afterReadInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect README.md after read: %w", err)
	}
	if err := validateCurrentEntry(root, openedInfo); err != nil {
		return nil, err
	}
	if openedInfo.Size() != afterReadInfo.Size() ||
		openedInfo.Mode() != afterReadInfo.Mode() ||
		!openedInfo.ModTime().Equal(afterReadInfo.ModTime()) {
		return nil, fmt.Errorf("%w: README.md changed during read", ErrUnsafeResource)
	}
	return contents, nil
}

func writeRegularFile(workspace string, contents []byte) error {
	return writeRegularFileWithHook(workspace, contents, nil)
}

func writeRegularFileWithHook(workspace string, contents []byte, afterInitialInspection func()) (returnErr error) {
	root, file, openedInfo, err := acquireRegularFile(workspace, os.O_WRONLY, afterInitialInspection)
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, closeAcquiredFile(root, file))
	}()

	if err := file.Truncate(0); err != nil {
		return fmt.Errorf("truncate rooted README.md: %w", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		return fmt.Errorf("seek rooted README.md: %w", err)
	}
	if _, err := file.Write(contents); err != nil {
		return fmt.Errorf("write rooted README.md: %w", err)
	}
	if err := validateCurrentEntry(root, openedInfo); err != nil {
		return err
	}
	return nil
}

func acquireRegularFile(workspace string, flag int, afterInitialInspection func()) (*os.Root, *os.File, os.FileInfo, error) {
	root, err := os.OpenRoot(workspace)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open shadow workspace root: %w", err)
	}
	fail := func(cause error, file *os.File) (*os.Root, *os.File, os.FileInfo, error) {
		return nil, nil, nil, errors.Join(cause, closeAcquiredFile(root, file))
	}

	initialInfo, err := root.Lstat("README.md")
	if err != nil {
		return fail(fmt.Errorf("inspect rooted README.md: %w", err), nil)
	}
	if !initialInfo.Mode().IsRegular() {
		return fail(fmt.Errorf("%w: README.md has type %s", ErrUnsafeResource, initialInfo.Mode().Type()), nil)
	}
	if afterInitialInspection != nil {
		afterInitialInspection()
	}

	file, err := root.OpenFile("README.md", flag, 0)
	if err != nil {
		if currentInfo, currentErr := root.Lstat("README.md"); currentErr == nil && !currentInfo.Mode().IsRegular() {
			return fail(fmt.Errorf("%w: README.md has type %s", ErrUnsafeResource, currentInfo.Mode().Type()), nil)
		}
		return fail(fmt.Errorf("open rooted README.md: %w", err), nil)
	}
	openedInfo, err := file.Stat()
	if err != nil {
		return fail(fmt.Errorf("inspect opened README.md: %w", err), file)
	}
	if !openedInfo.Mode().IsRegular() {
		return fail(fmt.Errorf("%w: opened README.md has type %s", ErrUnsafeResource, openedInfo.Mode().Type()), file)
	}
	if err := validateCurrentEntry(root, openedInfo); err != nil {
		return fail(err, file)
	}
	return root, file, openedInfo, nil
}

func validateCurrentEntry(root *os.Root, openedInfo os.FileInfo) error {
	currentInfo, err := root.Lstat("README.md")
	if err != nil {
		return fmt.Errorf("reinspect rooted README.md: %w", err)
	}
	if !currentInfo.Mode().IsRegular() {
		return fmt.Errorf("%w: README.md has type %s", ErrUnsafeResource, currentInfo.Mode().Type())
	}
	if !os.SameFile(openedInfo, currentInfo) {
		return fmt.Errorf("%w: README.md changed during object acquisition", ErrUnsafeResource)
	}
	return nil
}

func closeAcquiredFile(root *os.Root, file *os.File) error {
	var closeErr error
	if file != nil {
		closeErr = errors.Join(closeErr, file.Close())
	}
	if root != nil {
		closeErr = errors.Join(closeErr, root.Close())
	}
	return closeErr
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
