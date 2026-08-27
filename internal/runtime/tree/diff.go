package tree

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/MrGray17/Mirage/internal/limits"
)

// Diff normalizes a baseline/final snapshot pair into a deterministic plan.
// Renames deliberately appear as DELETE plus CREATE because no inode identity
// is trusted as contract authority.
func Diff(baseline, final *Snapshot) (*Plan, error) {
	if baseline == nil || final == nil || baseline.identity == "" || final.identity == "" {
		return nil, ErrInvalidSnapshot
	}
	before := indexEntries(baseline.entries)
	after := indexEntries(final.entries)
	resources := make([]string, 0, len(before)+len(after))
	for resource := range before {
		resources = append(resources, resource)
	}
	for resource := range after {
		if _, exists := before[resource]; !exists {
			resources = append(resources, resource)
		}
	}
	sort.Strings(resources)

	mutations := make([]Mutation, 0)
	appendMutation := func(mutation Mutation) error {
		if len(mutations) >= limits.MaxTreeMutations {
			return fmt.Errorf("%w: mutations exceed %d", ErrMutationBudget, limits.MaxTreeMutations)
		}
		mutations = append(mutations, mutation)
		return nil
	}
	if baseline.rootMode != final.rootMode {
		if err := appendMutation(Mutation{
			Operation:  OperationUnsupported,
			Resource:   "/workspace",
			BeforeKind: KindDirectory,
			AfterKind:  KindDirectory,
			BeforeMode: baseline.rootMode,
			AfterMode:  final.rootMode,
		}); err != nil {
			return nil, err
		}
	}
	for _, resource := range resources {
		old, oldExists := before[resource]
		current, currentExists := after[resource]
		switch {
		case !oldExists:
			if err := appendMutation(createMutation(current)); err != nil {
				return nil, err
			}
		case !currentExists:
			if err := appendMutation(deleteMutation(old)); err != nil {
				return nil, err
			}
		case old.Kind != current.Kind:
			if current.Kind == KindSymlink {
				if err := appendMutation(specialMutation(OperationSymlink, old, current)); err != nil {
					return nil, err
				}
				continue
			}
			if current.Kind == KindHardlink || current.Kind == KindUnsupported {
				if err := appendMutation(specialMutation(OperationUnsupported, old, current)); err != nil {
					return nil, err
				}
				continue
			}
			if err := appendMutation(deleteMutation(old)); err != nil {
				return nil, err
			}
			if err := appendMutation(createMutation(current)); err != nil {
				return nil, err
			}
		default:
			if current.Kind == KindSymlink {
				if old.LinkTarget != current.LinkTarget || old.Mode != current.Mode {
					if err := appendMutation(specialMutation(OperationSymlink, old, current)); err != nil {
						return nil, err
					}
				}
				continue
			}
			if current.Kind == KindHardlink || current.Kind == KindUnsupported {
				if old.LinkTarget != current.LinkTarget || old.Mode != current.Mode || old.Size != current.Size {
					if err := appendMutation(specialMutation(OperationUnsupported, old, current)); err != nil {
						return nil, err
					}
				}
				continue
			}
			if current.Kind == KindFile && old.Digest != current.Digest {
				if err := appendMutation(Mutation{
					Operation:    OperationModify,
					Resource:     resource,
					BeforeKind:   old.Kind,
					AfterKind:    current.Kind,
					BeforeMode:   old.Mode,
					AfterMode:    current.Mode,
					BeforeDigest: old.Digest,
					AfterDigest:  current.Digest,
					content:      append([]byte(nil), current.content...),
				}); err != nil {
					return nil, err
				}
			}
			if old.Mode != current.Mode {
				if err := appendMutation(Mutation{
					Operation:    OperationModeChange,
					Resource:     resource,
					BeforeKind:   old.Kind,
					AfterKind:    current.Kind,
					BeforeMode:   old.Mode,
					AfterMode:    current.Mode,
					BeforeDigest: old.Digest,
					AfterDigest:  current.Digest,
				}); err != nil {
					return nil, err
				}
			}
		}
	}

	sort.SliceStable(mutations, func(i, j int) bool {
		if mutations[i].Resource != mutations[j].Resource {
			return mutations[i].Resource < mutations[j].Resource
		}
		return operationRank(mutations[i].Operation) < operationRank(mutations[j].Operation)
	})
	canonical := struct {
		Baseline string     `json:"baseline"`
		Final    string     `json:"final"`
		Changes  []Mutation `json:"mutations"`
	}{baseline.identity, final.identity, mutations}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize plan: %v", ErrInvalidSnapshot, err)
	}
	digest := sha256.Sum256(encoded)
	return &Plan{
		baselineIdentity: baseline.identity,
		finalIdentity:    final.identity,
		mutations:        cloneMutations(mutations),
		hash:             fmt.Sprintf("sha256:%x", digest),
	}, nil
}

func indexEntries(entries []Entry) map[string]Entry {
	indexed := make(map[string]Entry, len(entries))
	for _, entry := range entries {
		indexed[entry.Resource] = entry
	}
	return indexed
}

func createMutation(entry Entry) Mutation {
	operation := OperationCreate
	if entry.Kind == KindSymlink {
		operation = OperationSymlink
	} else if entry.Kind == KindHardlink || entry.Kind == KindUnsupported {
		operation = OperationUnsupported
	}
	return Mutation{
		Operation:   operation,
		Resource:    entry.Resource,
		AfterKind:   entry.Kind,
		AfterMode:   entry.Mode,
		AfterDigest: entry.Digest,
		content:     append([]byte(nil), entry.content...),
	}
}

func deleteMutation(entry Entry) Mutation {
	return Mutation{
		Operation:    OperationDelete,
		Resource:     entry.Resource,
		BeforeKind:   entry.Kind,
		BeforeMode:   entry.Mode,
		BeforeDigest: entry.Digest,
	}
}

func specialMutation(operation Operation, before, after Entry) Mutation {
	return Mutation{
		Operation:    operation,
		Resource:     after.Resource,
		BeforeKind:   before.Kind,
		AfterKind:    after.Kind,
		BeforeMode:   before.Mode,
		AfterMode:    after.Mode,
		BeforeDigest: before.Digest,
		AfterDigest:  after.Digest,
	}
}

func operationRank(operation Operation) int {
	switch operation {
	case OperationDelete:
		return 0
	case OperationCreate:
		return 1
	case OperationModify:
		return 2
	case OperationModeChange:
		return 3
	case OperationSymlink:
		return 4
	default:
		return 5
	}
}
