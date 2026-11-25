// Package modelcheck contains a finite reference model of a local Mirage
// transaction, independent of the production runtime implementation.
package modelcheck

import "fmt"

type Phase uint8

const (
	Created Phase = iota
	Running
	Frozen
	Verified
	Prepared
	Applying
	Replaced
	Committed
	Rejected
	Uncertain
)

// Effects are a bit set: 1 is the authorized file, 2 a protected file.
// Revision models one competing baseline change, not arbitrary host races.
type State struct {
	Phase            Phase
	Proposed         uint8
	Expired          bool
	Revision         uint8
	Applied          uint8
	DispatchExpired  bool
	DispatchRevision uint8
}

type Edge struct {
	Action string
	To     State
}

type Result struct {
	States         int
	Transitions    int
	Counterexample []string
	Violation      string
}

// successors enumerates interleavings of expiry, a competing baseline change,
// verification, durable intent, replacement, acknowledgement and interruption.
// The mutant models a faulty implementation that omits final freshness.
func successors(s State, omitFinalFreshness bool) []Edge {
	var edges []Edge
	add := func(action string, next State) {
		edges = append(edges, Edge{Action: action, To: next})
	}
	terminal := s.Phase == Committed || s.Phase == Rejected || s.Phase == Uncertain
	if !terminal && !s.Expired {
		n := s
		n.Expired = true
		add("contract expires", n)
	}
	// A competing writer changes the baseline before the cooperative commit
	// lock is acquired. Noncooperating host writers are outside this model.
	if s.Phase < Prepared && s.Revision == 0 {
		n := s
		n.Revision = 1
		add("competing baseline change", n)
	}
	switch s.Phase {
	case Created:
		n := s
		n.Phase = Running
		add("start", n)
	case Running:
		for mask := uint8(0); mask <= 3; mask++ {
			n := s
			n.Phase, n.Proposed = Frozen, mask
			add(fmt.Sprintf("freeze effects=%d", mask), n)
		}
	case Frozen:
		n := s
		if s.Proposed == 1 && !s.Expired {
			n.Phase = Verified
		} else {
			n.Phase = Rejected
		}
		add("verify exact effect", n)
	case Verified:
		n := s
		if s.Revision == 0 && !s.Expired {
			n.Phase = Prepared
		} else {
			n.Phase = Rejected
		}
		add("lock and revalidate baseline", n)
	case Prepared:
		n := s
		n.Phase = Applying
		add("persist APPLYING intent", n)
	case Applying:
		n := s
		if omitFinalFreshness || (!s.Expired && s.Revision == 0) {
			n.Phase = Replaced
			n.Applied = s.Proposed
			n.DispatchExpired = s.Expired
			n.DispatchRevision = s.Revision
			add("replace verified file", n)
		} else {
			n.Phase = Uncertain
			add("deny dispatch after durable intent", n)
		}
	case Replaced:
		n := s
		n.Phase = Committed
		add("sync and persist COMMITTED", n)
	}
	if !terminal {
		n := s
		switch s.Phase {
		case Applying, Replaced:
			n.Phase = Uncertain
		default:
			n.Phase = Rejected
		}
		add("interrupt process", n)
	}
	return edges
}

// invariant checks historical dispatch facts, not the current clock: an
// authorization can expire after a valid replacement but before acknowledgement.
func invariant(s State) string {
	if s.Applied&^uint8(1) != 0 {
		return "unauthorized committed effect"
	}
	if s.Applied != 0 && (s.DispatchExpired || s.DispatchRevision != 0) {
		return "replacement dispatched without fresh authority or baseline"
	}
	if s.Phase == Rejected && s.Applied != 0 {
		return "rejected transaction changed reality"
	}
	if s.Phase == Committed && s.Applied != 1 {
		return "committed outcome lacks its exact effect"
	}
	if s.Applied != 0 && s.Phase != Replaced && s.Phase != Committed && s.Phase != Uncertain {
		return "effect crossed outside replacement boundary"
	}
	return ""
}

type predecessor struct {
	from   State
	action string
}

// Explore performs breadth-first exhaustive exploration of this finite model.
// If a property fails, the first result contains a shortest counterexample.
func Explore(omitFinalFreshness bool) Result {
	initial := State{}
	queue := []State{initial}
	seen := map[State]predecessor{initial: {}}
	result := Result{States: 1}
	for index := 0; index < len(queue); index++ {
		state := queue[index]
		if violation := invariant(state); violation != "" {
			result.Violation = violation
			for state != initial {
				step := seen[state]
				result.Counterexample = append(result.Counterexample, step.action)
				state = step.from
			}
			for i, j := 0, len(result.Counterexample)-1; i < j; i, j = i+1, j-1 {
				result.Counterexample[i], result.Counterexample[j] = result.Counterexample[j], result.Counterexample[i]
			}
			return result
		}
		for _, edge := range successors(state, omitFinalFreshness) {
			result.Transitions++
			if _, exists := seen[edge.To]; exists {
				continue
			}
			seen[edge.To] = predecessor{from: state, action: edge.Action}
			queue = append(queue, edge.To)
			result.States++
		}
	}
	return result
}
