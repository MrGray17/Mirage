package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/policy"
)

func TestOperatorPolicyMustBeOutsideWorkspace(t *testing.T) {
	root := t.TempDir()
	encoded := []byte(`{"version":"mirage.write-policy/v1","write_allow":["/workspace/a.txt"],"write_deny":[],"max_authority_seconds":60}`)
	inside := filepath.Join(root, "policy.json")
	if err := os.WriteFile(inside, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadWritePolicy(root, inside); err == nil {
		t.Fatal("workspace policy accepted")
	}
	outside := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(outside, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := loadWritePolicy(root, outside)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Restrict("/workspace/b.txt", time.Minute); !errors.Is(err, policy.ErrDenied) {
		t.Fatalf("unlisted resource: %v", err)
	}
}
