//go:build windows

package main

import (
	"fmt"
	"os/exec"
)

func openDocument(path string) error {
	if err := exec.Command("explorer.exe", path).Start(); err != nil {
		return fmt.Errorf("start explorer: %w", err)
	}
	return nil
}
