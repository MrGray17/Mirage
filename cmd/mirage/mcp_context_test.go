package main

import (
	"context"
	"errors"
	"io"
	"testing"
)

func TestMCPContextRunnerObservesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	_, _, err := executeMCPCommandContext(ctx, func(context.Context, []string, io.Writer, io.Writer) error {
		called = true
		return nil
	}, []string{"edit"})
	if called || !errors.Is(err, context.Canceled) {
		t.Fatalf("called=%t err=%v", called, err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	_, _, err = executeMCPCommandContext(ctx, func(actual context.Context, _ []string, _, _ io.Writer) error {
		cancel()
		return actual.Err()
	}, []string{"edit"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runner did not receive cancellation: %v", err)
	}
}
