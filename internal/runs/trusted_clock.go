package runs

import (
	"time"

	"github.com/MrGray17/Mirage/internal/trustedtime"
)

var (
	ErrTrustedTime   = trustedtime.ErrUnavailable
	ErrClockRollback = trustedtime.ErrRollback
)

type ClockRollbackError = trustedtime.RollbackError
type trustedClock = trustedtime.Clock

func newTrustedClock(source func() time.Time) (*trustedClock, error) {
	return trustedtime.New(source)
}
