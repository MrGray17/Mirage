package trustedtime

import (
	"errors"
	"testing"
	"time"
)

func TestClockTracksGreatestObservedUTCInstant(t *testing.T) {
	first := time.Date(2026, 8, 27, 12, 0, 0, 0, time.FixedZone("test", 2*60*60))
	readings := []time.Time{first, first, first.Add(time.Minute)}
	index := 0
	clock, err := New(func() time.Time {
		reading := readings[index]
		index++
		return reading
	})
	if err != nil {
		t.Fatal(err)
	}
	for range readings {
		observed, err := clock.Observe()
		if err != nil {
			t.Fatal(err)
		}
		if observed.Location() != time.UTC {
			t.Fatalf("observation is not UTC: %v", observed)
		}
	}
}

func TestClockRollbackDoesNotMoveGreatestBackward(t *testing.T) {
	base := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	readings := []time.Time{base.Add(10 * time.Minute), base.Add(time.Minute), base.Add(5 * time.Minute)}
	index := 0
	clock, err := New(func() time.Time {
		reading := readings[index]
		index++
		return reading
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clock.Observe(); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		_, err := clock.Observe()
		if !errors.Is(err, ErrRollback) {
			t.Fatalf("rollback error = %v", err)
		}
		var rollback *RollbackError
		if !errors.As(err, &rollback) || !rollback.Greatest.Equal(readings[0]) {
			t.Fatalf("rollback evidence = %#v", rollback)
		}
	}
}

func TestClockRejectsUnavailableSourceAndZeroReading(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil source error = %v", err)
	}
	clock, err := New(func() time.Time { return time.Time{} })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clock.Observe(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("zero reading error = %v", err)
	}
}
