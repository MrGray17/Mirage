package proof

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/attestation"
	"github.com/MrGray17/Mirage/internal/effectgraph"
	"github.com/MrGray17/Mirage/internal/receipt"
)

func signedFixture(t testing.TB) ([]byte, []byte, ed25519.PublicKey) {
	t.Helper()
	const resource = "/workspace/README.md"
	graph, err := effectgraph.New(effectgraph.Spec{
		RunID: "proof-run", Task: "edit", Agent: "fixture", Verification: "PASSED", VerificationPlan: "sha256:plan", Committed: true, CommitPlan: "sha256:commit", CommittedResource: resource,
		Effects:   []effectgraph.Effect{{Operation: "WRITE", Resource: resource, Disposition: "AUTHORIZED", EnforcedBy: "contract"}},
		Mutations: []effectgraph.Mutation{{Operation: "MODIFY", Resource: resource, AfterDigest: "sha256:after"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	effect := receipt.Effect{Operation: "WRITE", Resource: resource, EnforcedBy: "contract"}
	mutation := receipt.Mutation{Operation: "MODIFY", Resource: resource, BeforeDigest: "sha256:before", AfterDigest: "sha256:after"}
	now := time.Unix(100, 0)
	r, err := receipt.New(receipt.Spec{
		RunID: "proof-run", ContractHash: "sha256:contract", StartedAt: now, CompletedAt: now.Add(time.Second),
		AttemptedEffects: []receipt.Effect{effect}, AuthorizedEffects: []receipt.Effect{effect},
		ObservedMutations: []receipt.Mutation{mutation}, CommittedMutations: []receipt.Mutation{mutation},
		Verification: "PASSED", VerificationPlan: "sha256:plan", CommitPlan: "sha256:commit", Graph: graph,
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := receipt.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	sig, err := attestation.Sign(data, private)
	if err != nil {
		t.Fatal(err)
	}
	return data, sig, private.Public().(ed25519.PublicKey)
}

func TestPortableProof(t *testing.T) {
	data, sig, key := signedFixture(t)
	bundle, err := Create(data, sig, key)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Create(data, sig, key)
	if err != nil || !bytes.Equal(bundle, again) {
		t.Fatal("non-deterministic proof archive")
	}
	got, err := Verify(bundle, key)
	if err != nil || got.RunID != "proof-run" {
		t.Fatalf("receipt=%v err=%v", got, err)
	}
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if _, err := Verify(bundle, wrong); err == nil {
		t.Fatal("wrong signer accepted")
	}
	for _, name := range []string{"../proof.json", "receipt.json", "public.pem", "observatory.html"} {
		var output bytes.Buffer
		w := zip.NewWriter(&output)
		for i, n := range []string{"receipt.json", name} {
			p, err := w.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Store})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.Write([][]byte{data, sig}[i]); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(output.Bytes(), key); err == nil {
			t.Fatalf("unexpected entry %q accepted", name)
		}
	}
}
