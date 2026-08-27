// Package tree provides bounded canonical snapshots and normalized diffs for
// frozen M4 workspaces. It never follows symlinks as snapshot content.
package tree

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

var (
	ErrInvalidRoot     = errors.New("invalid tree root")
	ErrUnsafePath      = errors.New("unsafe tree path")
	ErrTreeBudget      = errors.New("tree budget exceeded")
	ErrTreeChanged     = errors.New("tree changed during scan")
	ErrUnsafeBaseline  = errors.New("unsafe baseline object")
	ErrInvalidSnapshot = errors.New("invalid tree snapshot")
	ErrMutationBudget  = errors.New("mutation budget exceeded")
)

type Kind string

const (
	KindFile        Kind = "FILE"
	KindDirectory   Kind = "DIRECTORY"
	KindSymlink     Kind = "SYMLINK"
	KindHardlink    Kind = "HARDLINK"
	KindUnsupported Kind = "UNSUPPORTED"
)

type Entry struct {
	Resource   string `json:"resource"`
	Kind       Kind   `json:"kind"`
	Mode       uint32 `json:"mode"`
	Size       int64  `json:"size,omitempty"`
	Digest     string `json:"digest,omitempty"`
	LinkTarget string `json:"link_target,omitempty"`
	content    []byte
}

func (e Entry) Content() []byte { return append([]byte(nil), e.content...) }

type Snapshot struct {
	entries  []Entry
	identity string
	rootMode uint32
}

func newSnapshot(entries []Entry) (*Snapshot, error) {
	return newSnapshotWithRoot(entries, 0)
}

func newSnapshotWithRoot(entries []Entry, rootMode uint32) (*Snapshot, error) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Resource < entries[j].Resource })
	canonical := struct {
		RootMode uint32  `json:"root_mode"`
		Entries  []Entry `json:"entries"`
	}{rootMode, entries}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize: %w", ErrInvalidSnapshot, err)
	}
	digest := sha256.Sum256(encoded)
	return &Snapshot{
		entries:  cloneEntries(entries),
		identity: fmt.Sprintf("sha256:%x", digest),
		rootMode: rootMode,
	}, nil
}

func (s *Snapshot) RootMode() uint32 {
	if s == nil {
		return 0
	}
	return s.rootMode
}

func (s *Snapshot) Identity() string {
	if s == nil {
		return ""
	}
	return s.identity
}

func (s *Snapshot) Entries() []Entry {
	if s == nil {
		return nil
	}
	return cloneEntries(s.entries)
}

func cloneEntries(entries []Entry) []Entry {
	cloned := make([]Entry, len(entries))
	for index, entry := range entries {
		entry.content = append([]byte(nil), entry.content...)
		cloned[index] = entry
	}
	return cloned
}

type Operation string

const (
	OperationCreate      Operation = "CREATE"
	OperationModify      Operation = "MODIFY"
	OperationDelete      Operation = "DELETE"
	OperationModeChange  Operation = "MODE_CHANGE"
	OperationSymlink     Operation = "SYMLINK"
	OperationUnsupported Operation = "UNSUPPORTED"
)

type Mutation struct {
	Operation    Operation `json:"operation"`
	Resource     string    `json:"resource"`
	BeforeKind   Kind      `json:"before_kind,omitempty"`
	AfterKind    Kind      `json:"after_kind,omitempty"`
	BeforeMode   uint32    `json:"before_mode,omitempty"`
	AfterMode    uint32    `json:"after_mode,omitempty"`
	BeforeDigest string    `json:"before_digest,omitempty"`
	AfterDigest  string    `json:"after_digest,omitempty"`
	content      []byte
}

func (m Mutation) Content() []byte { return append([]byte(nil), m.content...) }

type Plan struct {
	baselineIdentity string
	finalIdentity    string
	mutations        []Mutation
	hash             string
}

func (p *Plan) BaselineIdentity() string {
	if p == nil {
		return ""
	}
	return p.baselineIdentity
}

func (p *Plan) FinalIdentity() string {
	if p == nil {
		return ""
	}
	return p.finalIdentity
}

func (p *Plan) Hash() string {
	if p == nil {
		return ""
	}
	return p.hash
}

func (p *Plan) Mutations() []Mutation {
	if p == nil {
		return nil
	}
	return cloneMutations(p.mutations)
}

func cloneMutations(mutations []Mutation) []Mutation {
	cloned := make([]Mutation, len(mutations))
	for index, mutation := range mutations {
		mutation.content = append([]byte(nil), mutation.content...)
		cloned[index] = mutation
	}
	return cloned
}
