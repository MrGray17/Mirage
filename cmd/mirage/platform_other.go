//go:build !windows

package main

import (
	"context"
	"io"
)

func runEntrypoint(args []string, stdout, stderr io.Writer) error { return run(args, stdout, stderr) }

func runAutomationEntrypoint(args []string, stdout, stderr io.Writer) error {
	return run(args, stdout, stderr)
}

func runAutomationEntrypointContext(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(args) != 0 {
		switch args[0] {
		case "edit":
			return runQuickEditContext(ctx, args[1:], stdout, stderr)
		case "doctor":
			return runDoctorContext(ctx, args[1:], stdout, stderr)
		}
	}
	return run(args, stdout, stderr)
}
