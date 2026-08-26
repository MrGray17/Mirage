package filesystem_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/effects"
	filesystemgateway "github.com/MrGray17/Mirage/internal/gateway/filesystem"
)

func TestAllowedFilesystemFailureIsRecorded(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	contract := gatewayContract(t, now.Add(time.Hour), []string{filesystemgateway.ManagedResource})
	log, err := effects.NewLog(contract.RunID(), contract.ActorID())
	if err != nil {
		t.Fatalf("new log: %v", err)
	}
	shadow := t.TempDir()
	if err := os.WriteFile(filepath.Join(shadow, "README.md"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	gateway, err := filesystemgateway.New(contract, log, shadow, func() time.Time { return now })
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	if err := os.Remove(filepath.Join(shadow, "README.md")); err != nil {
		t.Fatalf("remove README: %v", err)
	}

	if _, err := gateway.ReadFile("README.md"); err == nil {
		t.Fatal("read unexpectedly succeeded")
	}
	events := log.Events()
	if len(events) != 1 || events[0].Decision != effects.DecisionAllow || events[0].Outcome != effects.OutcomeFailed {
		t.Fatalf("events = %+v", events)
	}
}

func TestContractCannotAuthorizeUnsupportedM3Resource(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	resource := "/workspace/docs/install.md"
	contract := gatewayContract(t, now.Add(time.Hour), []string{resource})
	log, err := effects.NewLog(contract.RunID(), contract.ActorID())
	if err != nil {
		t.Fatalf("new log: %v", err)
	}
	shadow := t.TempDir()
	if err := os.WriteFile(filepath.Join(shadow, "README.md"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	gateway, err := filesystemgateway.New(contract, log, shadow, func() time.Time { return now })
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}

	if _, err := gateway.ReadFile(resource); !errors.Is(err, filesystemgateway.ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied", err)
	}
	events := log.Events()
	if len(events) != 1 || events[0].Metadata["rule_id"] != "filesystem.unsupported_resource" {
		t.Fatalf("events = %+v", events)
	}
}

func gatewayContract(t *testing.T, expires time.Time, readAllow []string) *contracts.Contract {
	t.Helper()
	contract, err := contracts.New(contracts.Spec{
		Version:   contracts.VersionV1,
		RunID:     "run-1",
		ActorID:   "agent-1",
		ExpiresAt: expires,
		Filesystem: contracts.FilesystemPolicy{
			Read: contracts.AccessRules{Allow: readAllow},
		},
	})
	if err != nil {
		t.Fatalf("new contract: %v", err)
	}
	return contract
}
