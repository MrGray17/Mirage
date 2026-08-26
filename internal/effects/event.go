// Package effects defines Mirage's canonical, append-only Effect Event stream.
package effects

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidEvent = errors.New("invalid effect event")
	ErrEventTime    = errors.New("trusted event time unavailable")
)

type Decision string

const (
	DecisionAllow Decision = "ALLOW"
	DecisionDeny  Decision = "DENY"
)

type Outcome string

const (
	OutcomeSuccess       Outcome = "SUCCESS"
	OutcomeSuccessShadow Outcome = "SUCCESS_SHADOW"
	OutcomeBlocked       Outcome = "BLOCKED"
	OutcomeFailed        Outcome = "FAILED"
)

const (
	AdapterFilesystem = "filesystem"
	ResourceTypeFile  = "file"
	PhaseExecution    = "EXECUTION"
	ClassShadowLocal  = "SHADOW_LOCAL"
)

// Event is the fixed v0 Effect Event schema. PreviousEventHash and EventHash
// are reserved for M7; M3 establishes canonical events without claiming a
// tamper-evident chain yet.
type Event struct {
	ID                string            `json:"id"`
	Sequence          uint64            `json:"sequence"`
	RunID             string            `json:"run_id"`
	ActorID           string            `json:"actor_id"`
	Adapter           string            `json:"adapter"`
	Operation         string            `json:"operation"`
	ResourceType      string            `json:"resource_type"`
	ResourceID        string            `json:"resource_id"`
	Source            string            `json:"source"`
	Destination       string            `json:"destination"`
	Classification    string            `json:"classification"`
	Phase             string            `json:"phase"`
	Decision          Decision          `json:"decision"`
	Outcome           Outcome           `json:"outcome"`
	Timestamp         time.Time         `json:"timestamp"`
	Metadata          map[string]string `json:"metadata"`
	PreviousEventHash string            `json:"previous_event_hash"`
	EventHash         string            `json:"event_hash"`
}

// Attempt is trusted adapter input to the append-only log. The log owns run
// identity, actor identity, sequence, event ID, and timestamp validation.
type Attempt struct {
	Adapter        string
	Operation      string
	ResourceType   string
	ResourceID     string
	Source         string
	Destination    string
	Classification string
	Phase          string
	Decision       Decision
	Outcome        Outcome
	Metadata       map[string]string
}

// Log owns an in-memory append-only stream for one run. M3 intentionally adds
// no persistence or mutation API.
type Log struct {
	mu      sync.Mutex
	runID   string
	actorID string
	now     func() (time.Time, error)
	events  []Event
}

func NewLog(runID, actorID string, now func() (time.Time, error)) (*Log, error) {
	runID = strings.TrimSpace(runID)
	actorID = strings.TrimSpace(actorID)
	if runID == "" || actorID == "" || now == nil {
		return nil, fmt.Errorf("%w: run ID, actor ID, and trusted clock are required", ErrInvalidEvent)
	}
	return &Log{runID: runID, actorID: actorID, now: now}, nil
}

// Append validates, sequences, and stores one immutable event.
func (l *Log) Append(attempt Attempt) (Event, error) {
	if err := validateAttempt(attempt); err != nil {
		return Event{}, err
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	at, err := l.trustedTime()
	if err != nil {
		return Event{}, err
	}
	sequence := uint64(len(l.events) + 1)
	event := Event{
		ID:             fmt.Sprintf("%s:%020d", l.runID, sequence),
		Sequence:       sequence,
		RunID:          l.runID,
		ActorID:        l.actorID,
		Adapter:        attempt.Adapter,
		Operation:      attempt.Operation,
		ResourceType:   attempt.ResourceType,
		ResourceID:     attempt.ResourceID,
		Source:         attempt.Source,
		Destination:    attempt.Destination,
		Classification: attempt.Classification,
		Phase:          attempt.Phase,
		Decision:       attempt.Decision,
		Outcome:        attempt.Outcome,
		Timestamp:      at,
		Metadata:       cloneMetadata(attempt.Metadata),
	}
	l.events = append(l.events, event)
	return cloneEvent(event), nil
}

// TrustedTime exposes the same trusted run clock used to assign event
// timestamps so policy checks and event creation share one time authority.
func (l *Log) TrustedTime() (time.Time, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.trustedTime()
}

// Events returns a snapshot. Mutating the result cannot rewrite log history.
func (l *Log) Events() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	events := make([]Event, len(l.events))
	for index, event := range l.events {
		events[index] = cloneEvent(event)
	}
	return events
}

// CanonicalJSON returns the stable JSON representation used when M7 adds event
// hashing. encoding/json sorts string map keys, and all timestamps are UTC.
func CanonicalJSON(event Event) ([]byte, error) {
	if err := validateEvent(event); err != nil {
		return nil, err
	}
	return json.Marshal(cloneEvent(event))
}

func validateAttempt(attempt Attempt) error {
	if strings.TrimSpace(attempt.Adapter) == "" ||
		strings.TrimSpace(attempt.Operation) == "" ||
		strings.TrimSpace(attempt.ResourceType) == "" ||
		strings.TrimSpace(attempt.ResourceID) == "" ||
		strings.TrimSpace(attempt.Classification) == "" ||
		strings.TrimSpace(attempt.Phase) == "" {
		return fmt.Errorf("%w: required field is empty", ErrInvalidEvent)
	}
	if attempt.Decision != DecisionAllow && attempt.Decision != DecisionDeny {
		return fmt.Errorf("%w: decision %q", ErrInvalidEvent, attempt.Decision)
	}
	switch attempt.Outcome {
	case OutcomeSuccess, OutcomeSuccessShadow, OutcomeBlocked, OutcomeFailed:
	default:
		return fmt.Errorf("%w: outcome %q", ErrInvalidEvent, attempt.Outcome)
	}
	if attempt.Decision == DecisionDeny && attempt.Outcome != OutcomeBlocked {
		return fmt.Errorf("%w: denied effect must be blocked", ErrInvalidEvent)
	}
	return nil
}

func validateEvent(event Event) error {
	if event.ID == "" || event.Sequence == 0 || event.RunID == "" || event.ActorID == "" {
		return fmt.Errorf("%w: event identity is incomplete", ErrInvalidEvent)
	}
	if event.Timestamp.Location() != time.UTC {
		return fmt.Errorf("%w: timestamp is not canonical UTC", ErrInvalidEvent)
	}
	return validateAttempt(Attempt{
		Adapter:        event.Adapter,
		Operation:      event.Operation,
		ResourceType:   event.ResourceType,
		ResourceID:     event.ResourceID,
		Classification: event.Classification,
		Phase:          event.Phase,
		Decision:       event.Decision,
		Outcome:        event.Outcome,
	})
}

func (l *Log) trustedTime() (time.Time, error) {
	at, err := l.now()
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", ErrEventTime, err)
	}
	if at.IsZero() {
		return time.Time{}, fmt.Errorf("%w: trusted clock returned zero time", ErrEventTime)
	}
	return at.UTC(), nil
}

func cloneEvent(event Event) Event {
	event.Metadata = cloneMetadata(event.Metadata)
	return event
}

func cloneMetadata(metadata map[string]string) map[string]string {
	if len(metadata) == 0 {
		return map[string]string{}
	}
	copy := make(map[string]string, len(metadata))
	for key, value := range metadata {
		copy[key] = value
	}
	return copy
}
