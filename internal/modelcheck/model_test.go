package modelcheck

import (
	"strings"
	"testing"
)

func TestExhaustiveTransactionModel(t *testing.T) {
	result := Explore(false)
	t.Logf("states=%d transitions=%d", result.States, result.Transitions)
	if result.States < 20 || result.Transitions < result.States-1 || result.Violation != "" {
		t.Fatalf("model exploration: %#v", result)
	}
}

func TestCheckerFindsMissingFreshnessCounterexample(t *testing.T) {
	result := Explore(true)
	t.Logf("violation=%s trace=%s", result.Violation, strings.Join(result.Counterexample, " -> "))
	if result.Violation != "replacement dispatched without fresh authority or baseline" ||
		!strings.Contains(strings.Join(result.Counterexample, " "), "contract expires") {
		t.Fatalf("checker missed seeded protocol bug: %#v", result)
	}
}
