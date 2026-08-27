// Package trustedtime provides one monotonic-observation guard for a Mirage
// run. It establishes monotonicity of observed trusted wall time, not global
// clock correctness.
package trustedtime

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrUnavailable = errors.New("trusted run time unavailable")
	ErrRollback    = errors.New("trusted run clock moved backward")
)

// RollbackError reports wall-clock rollback without allowing the clock's
// greatest observed time to move backward.
type RollbackError struct {
	Greatest time.Time
	Observed time.Time
}

func (e *RollbackError) Error() string {
	return fmt.Sprintf("%s: greatest %s, observed %s", ErrRollback, e.Greatest.Format(time.RFC3339Nano), e.Observed.Format(time.RFC3339Nano))
}

func (e *RollbackError) Unwrap() error { return ErrRollback }

// Clock is the single wall-time authority for one run. Comparisons use UTC
// wall instants deliberately because contract expiry is a wall-time bound.
type Clock struct {
	mu       sync.Mutex
	source   func() time.Time
	greatest time.Time
}

func New(source func() time.Time) (*Clock, error) {
	if source == nil {
		return nil, fmt.Errorf("%w: clock source is nil", ErrUnavailable)
	}
	return &Clock{source: source}, nil
}

// Observe returns the current UTC wall instant if it is not earlier than any
// instant previously observed by this clock. Equality is valid.
func (c *Clock) Observe() (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	observed := c.source()
	if observed.IsZero() {
		return time.Time{}, fmt.Errorf("%w: clock returned zero time", ErrUnavailable)
	}
	observed = observed.UTC()
	if !c.greatest.IsZero() && observed.Before(c.greatest) {
		return time.Time{}, &RollbackError{
			Greatest: c.greatest,
			Observed: observed,
		}
	}
	if c.greatest.IsZero() || observed.After(c.greatest) {
		c.greatest = observed
	}
	return observed, nil
}
