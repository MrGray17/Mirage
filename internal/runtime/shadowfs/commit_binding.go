package shadowfs

import (
	"errors"
	"fmt"
)

var ErrCommitAuthorization = errors.New("shadow state is not authorized for commit")

// ShadowContentIdentity returns the current validated managed-file content identity.
// Callers must freeze hostile execution before using this as commit evidence.
func (t *Transaction) ShadowContentIdentity() (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state != StateActive {
		return "", fmt.Errorf("%w: cannot inspect shadow in state %s", ErrInvalidTransition, t.state)
	}
	contents, _, err := readManagedFile(t.shadowWorkspace)
	if err != nil {
		return "", fmt.Errorf("validate shadow %s: %w", managedFile, err)
	}
	return identifyContent(contents).String(), nil
}

// FinalizeWithoutMutation completes an approved no-op run without touching the
// real workspace. It succeeds only when the shadow still matches the baseline.
func (t *Transaction) FinalizeWithoutMutation() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state != StateActive {
		return fmt.Errorf("%w: cannot finalize transaction in state %s", ErrInvalidTransition, t.state)
	}
	contents, _, err := readManagedFile(t.shadowWorkspace)
	if err != nil {
		return fmt.Errorf("validate no-op shadow %s: %w", managedFile, err)
	}
	if identifyContent(contents) != t.baseline {
		return fmt.Errorf("%w: %s changed without an approved write", ErrCommitAuthorization, managedFile)
	}
	t.state = StateCommitted
	if err := t.removeShadowWorkspace(); err != nil {
		return fmt.Errorf("%w: no-op committed but shadow remains: %w", ErrCleanup, err)
	}
	return nil
}
