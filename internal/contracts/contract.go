// Package contracts defines immutable, deterministic authorization for a
// Mirage run. It contains no runtime, filesystem, or framework code.
package contracts

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

const VersionV1 = "mirage.contract/v1"

var ErrInvalidContract = errors.New("invalid effect contract")

// FilesystemOperation is an operation understood by the M3 filesystem policy.
type FilesystemOperation string

const (
	FilesystemRead  FilesystemOperation = "READ"
	FilesystemWrite FilesystemOperation = "WRITE"
)

// AccessRules contains exact canonical resource identifiers. M3 deliberately
// does not implement glob matching; broader matching semantics need their own
// security review.
type AccessRules struct {
	Allow []string
	Deny  []string
}

type FilesystemPolicy struct {
	Read  AccessRules
	Write AccessRules
}

// Spec is mutable construction input. New copies and canonicalizes every field
// so later mutation of Spec cannot change the resulting Contract.
type Spec struct {
	Version    string
	RunID      string
	ActorID    string
	ExpiresAt  time.Time
	Filesystem FilesystemPolicy
}

// Contract is immutable after construction. Its fields are intentionally
// private; callers receive values or copies through methods.
type Contract struct {
	version    string
	runID      string
	actorID    string
	expiresAt  time.Time
	filesystem canonicalFilesystemPolicy
	hash       string
}

type canonicalFilesystemPolicy struct {
	Read  canonicalAccessRules `json:"read"`
	Write canonicalAccessRules `json:"write"`
}

type canonicalAccessRules struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

type canonicalSpec struct {
	Version    string                    `json:"version"`
	RunID      string                    `json:"run_id"`
	ActorID    string                    `json:"actor_id"`
	ExpiresAt  string                    `json:"expires_at"`
	Filesystem canonicalFilesystemPolicy `json:"filesystem"`
}

// Decision is structured policy evidence. Denials are never represented as a
// bare boolean because callers must be able to reconstruct the rule applied.
type Decision struct {
	Allowed  bool
	RuleID   string
	Reason   string
	Evidence string
}

// New validates and canonicalizes a v1 contract.
func New(spec Spec) (*Contract, error) {
	if spec.Version != VersionV1 {
		return nil, fmt.Errorf("%w: unsupported version %q", ErrInvalidContract, spec.Version)
	}
	runID := strings.TrimSpace(spec.RunID)
	if runID == "" {
		return nil, fmt.Errorf("%w: run ID is empty", ErrInvalidContract)
	}
	actorID := strings.TrimSpace(spec.ActorID)
	if actorID == "" {
		return nil, fmt.Errorf("%w: actor ID is empty", ErrInvalidContract)
	}
	if spec.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("%w: expiry is missing", ErrInvalidContract)
	}

	filesystem, err := canonicalizeFilesystemPolicy(spec.Filesystem)
	if err != nil {
		return nil, err
	}
	expiresAt := spec.ExpiresAt.UTC()
	canonical := canonicalSpec{
		Version:    VersionV1,
		RunID:      runID,
		ActorID:    actorID,
		ExpiresAt:  expiresAt.Format(time.RFC3339Nano),
		Filesystem: filesystem,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize: %w", ErrInvalidContract, err)
	}
	digest := sha256.Sum256(encoded)

	return &Contract{
		version:    VersionV1,
		runID:      runID,
		actorID:    actorID,
		expiresAt:  expiresAt,
		filesystem: filesystem,
		hash:       fmt.Sprintf("sha256:%x", digest),
	}, nil
}

func (c *Contract) Version() string      { return c.version }
func (c *Contract) RunID() string        { return c.runID }
func (c *Contract) ActorID() string      { return c.actorID }
func (c *Contract) ExpiresAt() time.Time { return c.expiresAt }
func (c *Contract) Hash() string         { return c.hash }

// ExpiredAt reports whether authorization is no longer valid at the supplied
// trusted control-plane time. Equality is expired: the bound is exclusive.
func (c *Contract) ExpiredAt(at time.Time) bool {
	return !at.UTC().Before(c.expiresAt)
}

// EvaluateFilesystem deterministically applies deny-overrides-allow semantics.
// Unknown operations and unmatched resources fail closed.
func (c *Contract) EvaluateFilesystem(operation FilesystemOperation, resource string, at time.Time) Decision {
	if at.IsZero() {
		return Decision{
			RuleID: "contract.invalid_time",
			Reason: "trusted evaluation time is unavailable",
		}
	}
	if c.ExpiredAt(at) {
		return Decision{
			RuleID:   "contract.expired",
			Reason:   "effect contract has expired",
			Evidence: c.expiresAt.Format(time.RFC3339Nano),
		}
	}

	var rules canonicalAccessRules
	switch operation {
	case FilesystemRead:
		rules = c.filesystem.Read
	case FilesystemWrite:
		rules = c.filesystem.Write
	default:
		return Decision{
			RuleID:   "filesystem.unknown_operation",
			Reason:   "filesystem operation is not recognized",
			Evidence: string(operation),
		}
	}

	if contains(rules.Deny, resource) {
		return Decision{
			RuleID:   "filesystem.explicit_deny",
			Reason:   "resource is explicitly denied",
			Evidence: resource,
		}
	}
	if contains(rules.Allow, resource) {
		return Decision{
			Allowed:  true,
			RuleID:   "filesystem.explicit_allow",
			Reason:   "resource is explicitly allowed",
			Evidence: resource,
		}
	}
	return Decision{
		RuleID:   "filesystem.default_deny",
		Reason:   "resource is not in the operation allowlist",
		Evidence: resource,
	}
}

func canonicalizeFilesystemPolicy(policy FilesystemPolicy) (canonicalFilesystemPolicy, error) {
	read, err := canonicalizeAccessRules("filesystem.read", policy.Read)
	if err != nil {
		return canonicalFilesystemPolicy{}, err
	}
	write, err := canonicalizeAccessRules("filesystem.write", policy.Write)
	if err != nil {
		return canonicalFilesystemPolicy{}, err
	}
	return canonicalFilesystemPolicy{Read: read, Write: write}, nil
}

func canonicalizeAccessRules(name string, rules AccessRules) (canonicalAccessRules, error) {
	allow, err := canonicalizeResources(name+".allow", rules.Allow)
	if err != nil {
		return canonicalAccessRules{}, err
	}
	deny, err := canonicalizeResources(name+".deny", rules.Deny)
	if err != nil {
		return canonicalAccessRules{}, err
	}
	return canonicalAccessRules{Allow: allow, Deny: deny}, nil
}

func canonicalizeResources(field string, resources []string) ([]string, error) {
	canonical := make([]string, 0, len(resources))
	seen := make(map[string]struct{}, len(resources))
	for _, resource := range resources {
		if !isCanonicalWorkspaceResource(resource) {
			return nil, fmt.Errorf("%w: %s contains non-canonical resource %q", ErrInvalidContract, field, resource)
		}
		if _, exists := seen[resource]; exists {
			continue
		}
		seen[resource] = struct{}{}
		canonical = append(canonical, resource)
	}
	sort.Strings(canonical)
	return canonical, nil
}

func isCanonicalWorkspaceResource(resource string) bool {
	if !strings.HasPrefix(resource, "/workspace/") || strings.Contains(resource, "\\") {
		return false
	}
	if path.Clean(resource) != resource {
		return false
	}
	relative := strings.TrimPrefix(resource, "/workspace/")
	return relative != "" && relative != "." && relative != ".." && !strings.HasPrefix(relative, "../")
}

func contains(sorted []string, value string) bool {
	index := sort.SearchStrings(sorted, value)
	return index < len(sorted) && sorted[index] == value
}
