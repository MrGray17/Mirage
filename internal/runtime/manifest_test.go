package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/runtime/workspace"
)

func TestRunManifestBindsAllAuthoritySubjects(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	binding, disposable := manifestWorkspace(t)
	stub := &sandboxStub{
		identity:   "sandbox:rootless-config-v1",
		real:       binding.RealWorkspace(),
		disposable: binding.DisposableWorkspace(),
		token:      binding.Token(),
	}
	contract := lifecycleContract(t, now.Add(time.Hour), "/workspace/README.md")
	manifest, err := NewRunManifest(contract, binding, stub, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Identity() == "" || manifest.RunID() != contract.RunID() || manifest.ActorID() != contract.ActorID() {
		t.Fatalf("incomplete manifest identity: %#v", manifest)
	}
	if manifest.ContractHash() != contract.Hash() || manifest.RealBaselineIdentity() != binding.RealBaseline().Identity() || manifest.DisposableBaselineIdentity() != binding.DisposableBaseline().Identity() {
		t.Fatalf("manifest authority subjects are not bound: %#v", manifest)
	}
	second, err := NewRunManifest(contract, binding, stub, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if second.Identity() != manifest.Identity() {
		t.Fatalf("same immutable subject produced identities %q and %q", manifest.Identity(), second.Identity())
	}
	stub.identity = "sandbox:different-config"
	if err := manifest.validateSandbox(); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("changed sandbox identity error = %v", err)
	}
	_ = disposable
}

func TestRunManifestRejectsMixedWorkspaceSandboxBinding(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	binding, _ := manifestWorkspace(t)
	stub := &sandboxStub{
		identity:   "sandbox:test",
		real:       binding.RealWorkspace(),
		disposable: binding.DisposableWorkspace() + "-other",
		token:      binding.Token(),
	}
	_, err := NewRunManifest(lifecycleContract(t, now.Add(time.Hour), "/workspace/README.md"), binding, stub, func() time.Time { return now })
	if !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("mixed binding error = %v", err)
	}
}

func TestRunManifestRejectsExpiredContractAndUnavailableClock(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	binding, _ := manifestWorkspace(t)
	stub := &sandboxStub{
		identity:   "sandbox:test",
		real:       binding.RealWorkspace(),
		disposable: binding.DisposableWorkspace(),
		token:      binding.Token(),
	}
	contract := lifecycleContract(t, now, "/workspace/README.md")
	if _, err := NewRunManifest(contract, binding, stub, func() time.Time { return now }); !errors.Is(err, ErrManifestExpired) {
		t.Fatalf("expired manifest error = %v", err)
	}
	contract = lifecycleContract(t, now.Add(time.Hour), "/workspace/README.md")
	if _, err := NewRunManifest(contract, binding, stub, nil); !errors.Is(err, ErrTrustedTime) {
		t.Fatalf("unavailable clock error = %v", err)
	}
}

func manifestWorkspace(t *testing.T) (workspace.Binding, *workspace.Disposable) {
	t.Helper()
	real := lifecycleRealWorkspace(t)
	if err := os.WriteFile(filepath.Join(real, "README.md"), []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	disposable, err := workspace.Prepare(real)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := disposable.Cleanup(); err != nil {
			t.Errorf("cleanup disposable: %v", err)
		}
	})
	binding, err := disposable.Binding()
	if err != nil {
		t.Fatal(err)
	}
	return binding, disposable
}
