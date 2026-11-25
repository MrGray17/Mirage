package main

import (
	"errors"
	"strings"
	"testing"
)

func TestCommittedRunErrorPreservesMutationOutcome(t *testing.T) {
	cause := errors.New("receipt write failed")
	err := committedRunError("test-run", cause)
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "COMMITTED_INCOMPLETE run=test-run") || !strings.Contains(err.Error(), "do not retry automatically") {
		t.Fatalf("error=%v", err)
	}
	if committedRunError("test-run", nil) != nil {
		t.Fatal("successful run was converted into an error")
	}
}
