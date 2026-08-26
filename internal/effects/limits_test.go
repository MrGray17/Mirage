package effects_test

import (
	"errors"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/effects"
	"github.com/MrGray17/Mirage/internal/securitylimits"
)

func TestEventLimitFailsClosedWithoutGrowingLog(t *testing.T) {
	at := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	log, err := effects.NewLog("run-limit", "agent-limit", fixedClock(at))
	if err != nil {
		t.Fatalf("new log: %v", err)
	}
	for i := 0; i < securitylimits.MaxEffectEvents; i++ {
		if _, err := log.Append(filesystemAttempt(effects.DecisionAllow, effects.OutcomeSuccess, nil)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if _, err := log.Append(filesystemAttempt(effects.DecisionAllow, effects.OutcomeSuccess, nil)); !errors.Is(err, effects.ErrEventLimit) {
		t.Fatalf("overflow error = %v, want ErrEventLimit", err)
	}
	if got := len(log.Events()); got != securitylimits.MaxEffectEvents {
		t.Fatalf("event count = %d, want %d", got, securitylimits.MaxEffectEvents)
	}
}
