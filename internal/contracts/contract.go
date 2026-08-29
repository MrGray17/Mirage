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
	"unicode"
	"unicode/utf8"

	"github.com/MrGray17/Mirage/internal/gitrefs"
	"github.com/MrGray17/Mirage/internal/limits"
)

const (
	VersionV1 = "mirage.contract/v1"
	VersionV2 = "mirage.contract/v2"
)

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

// GitHubPublicationOperation is deliberately not a generic Git operation.
// M5.3 recognizes only creation of one previously absent branch.
type GitHubPublicationOperation string

const GitHubCreateBranch GitHubPublicationOperation = "CREATE_BRANCH"

// GitHubPublicationPolicy authorizes one exact GitHub destination. Repository
// is canonical owner/repo data, never a URL or credential-bearing locator.
type GitHubPublicationPolicy struct {
	RepositoryFullName string
	TargetRef          string
	Operation          GitHubPublicationOperation
}

// Spec is mutable construction input. New copies and canonicalizes every field
// so later mutation of Spec cannot change the resulting Contract.
type Spec struct {
	Version    string
	RunID      string
	ActorID    string
	ExpiresAt  time.Time
	Filesystem FilesystemPolicy
	GitHub     GitHubPublicationPolicy
}

// Contract is immutable after construction. Its fields are intentionally
// private; callers receive values or copies through methods.
type Contract struct {
	version    string
	runID      string
	actorID    string
	expiresAt  time.Time
	filesystem canonicalFilesystemPolicy
	github     canonicalGitHubPublicationPolicy
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

type canonicalGitHubPublicationPolicy struct {
	RepositoryFullName string                     `json:"repository_full_name"`
	TargetRef          string                     `json:"target_ref"`
	Operation          GitHubPublicationOperation `json:"operation"`
}

type canonicalSpecV2 struct {
	Version    string                           `json:"version"`
	RunID      string                           `json:"run_id"`
	ActorID    string                           `json:"actor_id"`
	ExpiresAt  string                           `json:"expires_at"`
	Filesystem canonicalFilesystemPolicy        `json:"filesystem"`
	GitHub     canonicalGitHubPublicationPolicy `json:"github_publication"`
}

// Decision is structured policy evidence. Denials are never represented as a
// bare boolean because callers must be able to reconstruct the rule applied.
type Decision struct {
	Allowed  bool
	RuleID   string
	Reason   string
	Evidence string
}

// New validates and canonicalizes a v1 or v2 contract. The v1 serialization
// path is intentionally unchanged so all pre-M5.3 hashes remain compatible.
func New(spec Spec) (*Contract, error) {
	if spec.Version != VersionV1 && spec.Version != VersionV2 {
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
	github := canonicalGitHubPublicationPolicy{}
	var encoded []byte
	if spec.Version == VersionV1 {
		canonical := canonicalSpec{
			Version: VersionV1, RunID: runID, ActorID: actorID,
			ExpiresAt: expiresAt.Format(time.RFC3339Nano), Filesystem: filesystem,
		}
		encoded, err = json.Marshal(canonical)
	} else {
		github, err = canonicalizeGitHubPublicationPolicy(runID, spec.GitHub)
		if err == nil {
			canonical := canonicalSpecV2{
				Version: VersionV2, RunID: runID, ActorID: actorID,
				ExpiresAt: expiresAt.Format(time.RFC3339Nano), Filesystem: filesystem, GitHub: github,
			}
			encoded, err = json.Marshal(canonical)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize: %w", ErrInvalidContract, err)
	}
	digest := sha256.Sum256(encoded)

	return &Contract{
		version:    spec.Version,
		runID:      runID,
		actorID:    actorID,
		expiresAt:  expiresAt,
		filesystem: filesystem,
		github:     github,
		hash:       fmt.Sprintf("sha256:%x", digest),
	}, nil
}

// EvaluateGitHubPublication deterministically evaluates one remote effect. It
// never contacts GitHub. Contract v1 and every non-exact operation default deny.
func (c *Contract) EvaluateGitHubPublication(operation GitHubPublicationOperation, repository, targetRef string, at time.Time) Decision {
	if c == nil {
		return Decision{RuleID: "github.invalid_contract", Reason: "effect contract is unavailable"}
	}
	if at.IsZero() {
		return Decision{RuleID: "contract.invalid_time", Reason: "trusted evaluation time is unavailable"}
	}
	if c.ExpiredAt(at) {
		return Decision{RuleID: "contract.expired", Reason: "effect contract has expired", Evidence: c.expiresAt.Format(time.RFC3339Nano)}
	}
	if c.version != VersionV2 {
		return Decision{RuleID: "github.version_default_deny", Reason: "contract version has no remote publication authority", Evidence: c.version}
	}
	canonicalRepository, err := CanonicalGitHubRepository(repository)
	if err != nil {
		return Decision{RuleID: "github.invalid_repository", Reason: "repository identity is not canonical", Evidence: "invalid owner/repo"}
	}
	if operation != GitHubCreateBranch {
		return Decision{RuleID: "github.operation_default_deny", Reason: "GitHub operation is not authorized", Evidence: string(operation)}
	}
	if canonicalRepository != c.github.RepositoryFullName {
		return Decision{RuleID: "github.repository_default_deny", Reason: "GitHub repository is not authorized", Evidence: canonicalRepository}
	}
	if targetRef != c.github.TargetRef {
		return Decision{RuleID: "github.ref_default_deny", Reason: "Git ref is not authorized", Evidence: targetRef}
	}
	return Decision{Allowed: true, RuleID: "github.exact_create_branch", Reason: "exact create-only GitHub branch is authorized", Evidence: canonicalRepository + "@" + targetRef}
}

// GitHubPublication returns a value copy of the canonical v2 policy.
func (c *Contract) GitHubPublication() GitHubPublicationPolicy {
	if c == nil || c.version != VersionV2 {
		return GitHubPublicationPolicy{}
	}
	return GitHubPublicationPolicy{RepositoryFullName: c.github.RepositoryFullName, TargetRef: c.github.TargetRef, Operation: c.github.Operation}
}

func canonicalizeGitHubPublicationPolicy(runID string, policy GitHubPublicationPolicy) (canonicalGitHubPublicationPolicy, error) {
	repository, err := CanonicalGitHubRepository(policy.RepositoryFullName)
	if err != nil {
		return canonicalGitHubPublicationPolicy{}, err
	}
	if policy.Operation != GitHubCreateBranch {
		return canonicalGitHubPublicationPolicy{}, fmt.Errorf("%w: only GitHub CREATE_BRANCH is supported", ErrInvalidContract)
	}
	if !gitrefs.IsRunTarget(runID, policy.TargetRef) {
		return canonicalGitHubPublicationPolicy{}, fmt.Errorf("%w: GitHub target ref is not the deterministic run branch", ErrInvalidContract)
	}
	return canonicalGitHubPublicationPolicy{RepositoryFullName: repository, TargetRef: policy.TargetRef, Operation: policy.Operation}, nil
}

// CanonicalGitHubRepository validates owner/repo data for github.com and
// returns its documented lower-case M5.3 canonical representation.
func CanonicalGitHubRepository(value string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 201 || !utf8.ValidString(value) || strings.Count(value, "/") != 1 {
		return "", fmt.Errorf("%w: GitHub repository must be exact owner/repo data", ErrInvalidContract)
	}
	for _, r := range value {
		if r > unicode.MaxASCII || unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", fmt.Errorf("%w: GitHub repository contains unsafe characters", ErrInvalidContract)
		}
	}
	owner, repository, _ := strings.Cut(strings.ToLower(value), "/")
	if !validGitHubOwner(owner) || !validGitHubRepositoryName(repository) {
		return "", fmt.Errorf("%w: invalid GitHub owner or repository name", ErrInvalidContract)
	}
	return owner + "/" + repository, nil
}

func validGitHubOwner(value string) bool {
	if len(value) < 1 || len(value) > 100 || value[0] == '-' || value[len(value)-1] == '-' || strings.Contains(value, "--") {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

func validGitHubRepositoryName(value string) bool {
	if len(value) < 1 || len(value) > 100 || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return true
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
		if len(resource) > limits.MaxResourceIdentifierBytes {
			return nil, fmt.Errorf("%w: %s resource exceeds %d bytes", ErrInvalidContract, field, limits.MaxResourceIdentifierBytes)
		}
		if strings.ContainsRune(resource, '\x00') || !isCanonicalWorkspaceResource(resource) {
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
