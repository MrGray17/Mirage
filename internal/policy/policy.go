// Package policy restricts one explicitly requested local write. Policies
// cannot grant additional effects or bypass the runtime's reconciliation.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/MrGray17/Mirage/internal/contracts"
)

const (
	Schema              = "mirage.write-policy/v1"
	MaxBytes            = 64 << 10
	MaxRules            = 256
	MaxAuthoritySeconds = 1890
)

var (
	ErrInvalidPolicy = errors.New("invalid Mirage write policy")
	ErrDenied        = errors.New("operator policy denied requested effect")
)

type Policy struct {
	allow        []string
	deny         []string
	maxAuthority time.Duration
}

// Parse rejects unknown and duplicate keys, missing fields and unsupported
// resource syntax. The input is bounded before decoding.
func Parse(data []byte) (*Policy, error) {
	if len(data) == 0 || len(data) > MaxBytes || !utf8.Valid(data) {
		return nil, ErrInvalidPolicy
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrInvalidPolicy
	}
	var version string
	var allow, deny []string
	var seconds int
	seen := map[string]bool{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, ErrInvalidPolicy
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return nil, fmt.Errorf("%w: duplicate or invalid key", ErrInvalidPolicy)
		}
		seen[name] = true
		switch name {
		case "version":
			err = dec.Decode(&version)
		case "write_allow":
			err = dec.Decode(&allow)
		case "write_deny":
			err = dec.Decode(&deny)
		case "max_authority_seconds":
			err = dec.Decode(&seconds)
		default:
			return nil, fmt.Errorf("%w: unknown key %q", ErrInvalidPolicy, name)
		}
		if err != nil {
			return nil, fmt.Errorf("%w: invalid value for %s", ErrInvalidPolicy, name)
		}
	}
	if token, err = dec.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrInvalidPolicy
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing input", ErrInvalidPolicy)
	}
	if version != Schema || allow == nil || deny == nil || seconds < 1 || seconds > MaxAuthoritySeconds || len(allow)+len(deny) > MaxRules {
		return nil, fmt.Errorf("%w: schema, explicit arrays, rule count or duration", ErrInvalidPolicy)
	}
	for _, resources := range [][]string{allow, deny} {
		for _, resource := range resources {
			for _, ch := range resource {
				if unicode.IsControl(ch) || ch == unicode.ReplacementChar || ch == '*' || ch == '?' || ch == '[' || ch == ']' {
					return nil, fmt.Errorf("%w: unsupported resource syntax", ErrInvalidPolicy)
				}
			}
		}
	}
	_, err = contracts.New(contracts.Spec{
		Version: contracts.VersionV1, RunID: "policy-validation", ActorID: "operator",
		ExpiresAt:  time.Unix(1, 0),
		Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{Allow: allow, Deny: deny}},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	return &Policy{allow: allow, deny: deny, maxAuthority: time.Duration(seconds) * time.Second}, nil
}

// Restrict returns an exact intersection of the request and policy, plus
// a deadline budget that can only be shorter than the requested budget.
func (p *Policy) Restrict(resource string, requested time.Duration) (contracts.AccessRules, time.Duration, error) {
	if p == nil || requested <= 0 {
		return contracts.AccessRules{}, 0, ErrInvalidPolicy
	}
	if slices.Contains(p.deny, resource) || !slices.Contains(p.allow, resource) {
		return contracts.AccessRules{}, 0, ErrDenied
	}
	return contracts.AccessRules{Allow: []string{resource}, Deny: slices.Clone(p.deny)}, min(requested, p.maxAuthority), nil
}
