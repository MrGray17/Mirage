package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/MrGray17/Mirage/internal/policy"
)

// Load the trusted caller's policy once before sandbox preparation.
func loadWritePolicy(workspace, filename string) (*policy.Policy, error) {
	root, err := filepath.Abs(workspace)
	if err != nil {
		return nil, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	name, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.Join(errors.New("policy must be a regular file, not a symlink"), err)
	}
	name, err = filepath.EvalSymlinks(name)
	if err != nil {
		return nil, err
	}
	relative, err := filepath.Rel(root, name)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("operator policy must be outside the workspace")
	}
	data, err := readBoundedRegular(name, policy.MaxBytes)
	if err != nil {
		return nil, fmt.Errorf("read operator policy: %w", err)
	}
	return policy.Parse(data)
}
