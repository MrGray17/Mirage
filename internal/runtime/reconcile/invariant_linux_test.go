//go:build linux

package reconcile

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
	"github.com/MrGray17/Mirage/internal/runtime/tree"
)

// The oracle uses generated actions and policy bits, not the verifier's
// contract evaluator or mutation classification. It checks both soundness
// (forbidden states never pass) and completeness within the narrow v1 model.
func FuzzVerifyExactAuthorization(f *testing.F) {
	// Two existing files, one optional creation, policy masks, and expiry.
	f.Add(uint8(1), uint8(0), false, uint8(1), uint8(0), false)
	f.Add(uint8(0), uint8(1), false, uint8(2), uint8(0), false)
	f.Add(uint8(1), uint8(0), false, uint8(1), uint8(1), false)
	f.Add(uint8(1), uint8(1), false, uint8(3), uint8(0), false)
	f.Add(uint8(1), uint8(0), true, uint8(7), uint8(0), false)
	f.Add(uint8(2), uint8(0), false, uint8(1), uint8(0), false)
	f.Add(uint8(3), uint8(0), false, uint8(1), uint8(0), false)
	f.Add(uint8(1), uint8(0), false, uint8(1), uint8(0), true)
	f.Add(uint8(0), uint8(0), false, uint8(7), uint8(0), false)

	f.Fuzz(func(t *testing.T, rawA, rawB uint8, create bool, allowMask, denyMask uint8, expired bool) {
		root := t.TempDir()
		names := []string{"a.txt", "b.txt", "new.txt"}
		actions := []uint8{rawA % 4, rawB % 4}
		for _, name := range names[:2] {
			if err := os.WriteFile(filepath.Join(root, name), []byte("before"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		baseline, err := tree.Scan(root, tree.ScanOptions{})
		if err != nil {
			t.Fatal(err)
		}
		for i, action := range actions {
			path := filepath.Join(root, names[i])
			var err error
			switch action {
			case 1:
				err = os.WriteFile(path, []byte("after"), 0o600)
			case 2:
				err = os.Remove(path)
			case 3:
				err = os.Chmod(path, 0o644)
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		if create {
			if err := os.WriteFile(filepath.Join(root, names[2]), []byte("new"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		var allow, deny []string
		for i, name := range names {
			resource := "/workspace/" + name
			bit := uint8(1 << i)
			if allowMask&bit != 0 {
				allow = append(allow, resource)
			}
			if denyMask&bit != 0 {
				deny = append(deny, resource)
			}
		}
		now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
		expires := now.Add(time.Hour)
		if expired {
			expires = now
		}
		contract, err := contracts.New(contracts.Spec{
			Version: contracts.VersionV1, RunID: "fuzz-run", ActorID: "fuzz-agent", ExpiresAt: expires,
			Filesystem: contracts.FilesystemPolicy{Write: contracts.AccessRules{Allow: allow, Deny: deny}},
		})
		if err != nil {
			t.Fatal(err)
		}

		// Independent reference model: only one existing content change,
		// no creation, no other change, live contract, allow without deny.
		wantIndex := -1
		if !expired && !create {
			switch {
			case actions[0] == 1 && actions[1] == 0 && allowMask&1 != 0 && denyMask&1 == 0:
				wantIndex = 0
			case actions[0] == 0 && actions[1] == 1 && allowMask&2 != 0 && denyMask&2 == 0:
				wantIndex = 1
			}
		}
		const manifest = "sha256:fuzz-manifest"
		plan, decision, err := Verify(manifest, baseline, root, contract, now)
		if err != nil {
			t.Fatal(err)
		}
		if decision.Allowed != (wantIndex >= 0) {
			t.Fatalf("actions=%v create=%t allow=%03b deny=%03b expired=%t: allowed=%t want=%t violations=%v", actions, create, allowMask, denyMask, expired, decision.Allowed, wantIndex >= 0, decision.Violations())
		}
		if !decision.BoundTo(manifest, contract.Hash(), plan.Hash()) {
			t.Fatal("decision not bound to its inputs")
		}
		if decision.Allowed {
			mutations := plan.Mutations()
			if len(mutations) != 1 || mutations[0].Resource != "/workspace/"+names[wantIndex] ||
				mutations[0].Operation != tree.OperationModify || mutations[0].BeforeMode != mutations[0].AfterMode ||
				string(mutations[0].Content()) != "after" {
				t.Fatalf("allowed plan differs from reference action: %v", mutations)
			}
		}
		again, second, err := Verify(manifest, baseline, root, contract, now)
		if err != nil || again.Hash() != plan.Hash() || second.AuthorityHash != decision.AuthorityHash || second.Allowed != decision.Allowed {
			t.Fatalf("non-deterministic reconciliation: %v", err)
		}
	})
}
