// Package limits defines narrow, explicit security budgets for the Mirage
// prototype. Exceeding a budget must fail closed; callers must not silently
// truncate security-relevant state.
package limits

const (
	// MaxManagedFileBytes bounds README.md reads and writes in the single-file
	// prototype. This protects the trusted Mirage process from unbounded file
	// allocation before hostile-process isolation exists.
	MaxManagedFileBytes int64 = 4 << 20 // 4 MiB

	// MaxEffectEventsPerRun bounds the in-memory audit stream. M4+ may replace
	// this with durable streaming storage, but the trusted process must remain
	// bounded in the meantime.
	MaxEffectEventsPerRun = 1024

	// MaxResourceIdentifierBytes bounds attacker-controlled virtual resource
	// strings before canonicalization/hashing.
	MaxResourceIdentifierBytes = 4096

	// M4 tree reconciliation budgets. The trusted scanner fails closed rather
	// than truncating when a frozen workspace exceeds any of these bounds.
	MaxTreeEntries    = 4096
	MaxTreeDepth      = 32
	MaxTreeFileBytes  = MaxManagedFileBytes
	MaxTreeTotalBytes = 32 << 20 // 32 MiB
	MaxTreeMutations  = 4096
)
