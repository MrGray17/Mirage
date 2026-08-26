// Package securitylimits defines narrow hard limits for the pre-M4 trusted runtime.
// These are security boundaries, not tuning knobs: exceeding them must fail closed.
package securitylimits

const (
	// ManagedFileBytes bounds any single managed-file snapshot or write payload.
	// M3 manages README.md only; 1 MiB is intentionally generous for that scope.
	ManagedFileBytes int64 = 1 << 20

	// MaxEffectEvents bounds the in-memory audit stream for one run.
	MaxEffectEvents = 4096

	// MaxResourceIDBytes bounds attacker-controlled virtual resource spellings.
	MaxResourceIDBytes = 4096
)
