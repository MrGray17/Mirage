//go:build !windows

package main

import "io"

func runEntrypoint(args []string, stdout, stderr io.Writer) error { return run(args, stdout, stderr) }
