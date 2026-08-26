package runs

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrTrustedTime   = errors.New("trusted run time unavailable")
	ErrClockRollback = errors.New("trusted run clock moved backward")
)

// ClockRollbackError reports wall-clock rollback without allowing the run's
// greatest observed time to move backward.
type ClockRollbackError struct {
	Greatest time.Time
	Observed time.Time
}

func (e *ClockRollbackError) Error() string {
	return fmt.Sprintf("%s: greatest %s, observed %s", ErrClockRollback, e.Greatest.Format(time.RFC3339Nano), e.Observed.Format(time.RFC3339Nano))
}

func (e *ClockRollbackError) Unwrap() error { return ErrClockRollback }

// trustedClock is the single wall-time authority for one run. Comparisons use
// UTC wall instants deliberately because contract expiry is a wall-time bound.
type trustedClock struct {
	mu       sync.Mutex
	source   func() time.Time
	greatest time.Time
}

func newTrustedClock(source func() time.Time) (*trustedClock, error) {
	if source == nil {
		return nil, fmt.Errorf("%w: clock source is nil", ErrTrustedTime)
	}
	return &trustedClock{source: source}, nil
}

func (c *trustedClock) Observe() (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	observed := c.source()
	if observed.IsZero() {
		return time.Time{}, fmt.Errorf("%w: clock returned zero time", ErrTrustedTime)
	}
	observed = observed.UTC()
	if !c.greatest.IsZero() && observed.Before(c.greatest) {
		return time.Time{}, &ClockRollbackError{
			Greatest: c.greatest,
			Observed: observed,
		}
	}
	if c.greatest.IsZero() || observed.After(c.greatest) {
		c.greatest = observed
	}
	return observed, nil
}
