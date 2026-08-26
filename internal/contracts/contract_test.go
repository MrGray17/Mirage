package contracts_test

import (
	"errors"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
)

func TestContractIsImmutableAndCanonical(t *testing.T) {
	expires := time.Date(2026, 8, 26, 15, 0, 0, 123, time.FixedZone("test", 60*60))
	spec := contracts.Spec{
		Version:   contracts.VersionV1,
		RunID:     " run-17 ",
		ActorID:   " coding-agent-17 ",
		ExpiresAt: expires,
		Filesystem: contracts.FilesystemPolicy{
			Read: contracts.AccessRules{
				Allow: []string{"/workspace/README.md", "/workspace/docs/install.md"},
				Deny:  []string{"/workspace/.env"},
			},
			Write: contracts.AccessRules{Allow: []string{"/workspace/README.md"}},
		},
	}
	contract, err := contracts.New(spec)
	if err != nil {
		t.Fatalf("new contract: %v", err)
	}

	reordered, err := contracts.New(contracts.Spec{
		Version:   contracts.VersionV1,
		RunID:     "run-17",
		ActorID:   "coding-agent-17",
		ExpiresAt: expires.UTC(),
		Filesystem: contracts.FilesystemPolicy{
			Read: contracts.AccessRules{
				Allow: []string{"/workspace/docs/install.md", "/workspace/README.md"},
				Deny:  []string{"/workspace/.env"},
			},
			Write: contracts.AccessRules{Allow: []string{"/workspace/README.md"}},
		},
	})
	if err != nil {
		t.Fatalf("new reordered contract: %v", err)
	}
	if contract.Hash() != reordered.Hash() {
		t.Fatalf("canonical hashes differ: %s != %s", contract.Hash(), reordered.Hash())
	}
	if contract.RunID() != "run-17" || contract.ActorID() != "coding-agent-17" {
		t.Fatalf("identity = %q/%q", contract.RunID(), contract.ActorID())
	}
	if !contract.ExpiresAt().Equal(expires) || contract.ExpiresAt().Location() != time.UTC {
		t.Fatalf("expiry = %s, want equivalent UTC instant", contract.ExpiresAt())
	}

	// Mutating construction input cannot add authority or change the hash.
	originalHash := contract.Hash()
	spec.Filesystem.Read.Allow[0] = "/workspace/.env"
	spec.Filesystem.Write.Allow = append(spec.Filesystem.Write.Allow, "/workspace/.github/workflows/deploy.yml")
	if contract.Hash() != originalHash {
		t.Fatal("contract hash changed after construction input mutation")
	}
	decision := contract.EvaluateFilesystem(contracts.FilesystemRead, "/workspace/.env", expires.Add(-time.Minute))
	if decision.Allowed || decision.RuleID != "filesystem.explicit_deny" {
		t.Fatalf("decision = %+v, want explicit deny", decision)
	}
}

func TestContractDenyOverridesAllowAndDefaultsClosed(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	contract := newContract(t, now.Add(time.Hour), contracts.FilesystemPolicy{
		Read: contracts.AccessRules{
			Allow: []string{"/workspace/README.md"},
			Deny:  []string{"/workspace/README.md"},
		},
	})

	denied := contract.EvaluateFilesystem(contracts.FilesystemRead, "/workspace/README.md", now)
	if denied.Allowed || denied.RuleID != "filesystem.explicit_deny" {
		t.Fatalf("deny override = %+v", denied)
	}
	defaultDenied := contract.EvaluateFilesystem(contracts.FilesystemWrite, "/workspace/README.md", now)
	if defaultDenied.Allowed || defaultDenied.RuleID != "filesystem.default_deny" {
		t.Fatalf("default decision = %+v", defaultDenied)
	}
	expired := contract.EvaluateFilesystem(contracts.FilesystemRead, "/workspace/README.md", now.Add(time.Hour))
	if expired.Allowed || expired.RuleID != "contract.expired" {
		t.Fatalf("expired decision = %+v", expired)
	}
	invalidTime := contract.EvaluateFilesystem(contracts.FilesystemRead, "/workspace/README.md", time.Time{})
	if invalidTime.Allowed || invalidTime.RuleID != "contract.invalid_time" {
		t.Fatalf("zero-time decision = %+v", invalidTime)
	}
}

func TestMalformedContractFailsClosed(t *testing.T) {
	valid := contracts.Spec{
		Version:   contracts.VersionV1,
		RunID:     "run-1",
		ActorID:   "agent-1",
		ExpiresAt: time.Date(2026, 8, 26, 13, 0, 0, 0, time.UTC),
	}
	tests := map[string]func(*contracts.Spec){
		"unknown version":       func(spec *contracts.Spec) { spec.Version = "mirage.contract/v2" },
		"missing run":           func(spec *contracts.Spec) { spec.RunID = "" },
		"missing actor":         func(spec *contracts.Spec) { spec.ActorID = "" },
		"missing expiry":        func(spec *contracts.Spec) { spec.ExpiresAt = time.Time{} },
		"noncanonical resource": func(spec *contracts.Spec) { spec.Filesystem.Read.Allow = []string{"README.md"} },
		"traversal resource":    func(spec *contracts.Spec) { spec.Filesystem.Read.Allow = []string{"/workspace/../.env"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			spec := valid
			mutate(&spec)
			if _, err := contracts.New(spec); !errors.Is(err, contracts.ErrInvalidContract) {
				t.Fatalf("error = %v, want ErrInvalidContract", err)
			}
		})
	}
}

func newContract(t *testing.T, expires time.Time, filesystem contracts.FilesystemPolicy) *contracts.Contract {
	t.Helper()
	contract, err := contracts.New(contracts.Spec{
		Version:    contracts.VersionV1,
		RunID:      "run-1",
		ActorID:    "agent-1",
		ExpiresAt:  expires,
		Filesystem: filesystem,
	})
	if err != nil {
		t.Fatalf("new contract: %v", err)
	}
	return contract
}
