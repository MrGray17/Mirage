package attestation

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/effectgraph"
	"github.com/MrGray17/Mirage/internal/receipt"
)

func fixture(t testing.TB) []byte {
	t.Helper()
	const resource = "/workspace/README.md"
	graph, err := effectgraph.New(effectgraph.Spec{
		RunID: "run-1", Task: "edit", Agent: "fixture", Verification: "PASSED", VerificationPlan: "sha256:plan", Committed: true, CommitPlan: "sha256:commit", CommittedResource: resource,
		Effects:   []effectgraph.Effect{{Operation: "WRITE", Resource: resource, Disposition: "AUTHORIZED", EnforcedBy: "contract"}},
		Mutations: []effectgraph.Mutation{{Operation: "MODIFY", Resource: resource, AfterDigest: "sha256:after"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	effect := receipt.Effect{Operation: "WRITE", Resource: resource, EnforcedBy: "contract"}
	mutation := receipt.Mutation{Operation: "MODIFY", Resource: resource, BeforeDigest: "sha256:before", AfterDigest: "sha256:after"}
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	r, err := receipt.New(receipt.Spec{
		RunID: "run-1", ContractHash: "sha256:contract", StartedAt: now, CompletedAt: now.Add(time.Second),
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
	return data
}

func TestProofBindsExactBytesAndTrustedSigner(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data := fixture(t)
	proof, err := Sign(data, private)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Verify(data, proof, public); err != nil || got.RunID != "run-1" {
		t.Fatalf("verified=%v err=%v", got, err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(data, proof, other); err == nil {
		t.Fatal("wrong trusted signer accepted")
	}
	changed := append(append([]byte(nil), data...), ' ')
	if _, err := receipt.ParseAndVerify(changed); err != nil {
		t.Fatal("whitespace change should retain semantic receipt validity")
	}
	if _, err := Verify(changed, proof, public); err == nil {
		t.Fatal("changed receipt bytes accepted")
	}
	var parsed Proof
	if err := json.Unmarshal(proof, &parsed); err != nil {
		t.Fatal(err)
	}
	parsed.ReceiptHash = "sha256:forged"
	forged, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(data, forged, public); err == nil {
		t.Fatal("forged receipt identity accepted")
	}
	if _, err := Sign([]byte("{}"), private); err == nil {
		t.Fatal("invalid receipt signed")
	}
}

func TestVerifyRejectsOversizedReceiptBeforeProofProcessing(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oversized := make([]byte, MaxReceiptBytes+1)
	proof, err := json.Marshal(Proof{
		Schema: Schema, KeyID: KeyID(public), ReceiptDigest: digest(oversized),
		ReceiptHash: "sha256:unused", Signature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(oversized, proof, public); err != ErrInvalidAttestation {
		t.Fatalf("verify oversized receipt: %v", err)
	}
}

func TestPEMKeyRoundTrip(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	gotPrivate, err := ParsePrivateKey(privPEM)
	if err != nil || !private.Equal(gotPrivate) {
		t.Fatalf("private key parse: %v", err)
	}
	gotPublic, err := ParsePublicKey(pubPEM)
	if err != nil || !public.Equal(gotPublic) {
		t.Fatalf("public key parse: %v", err)
	}
	if _, err := ParsePublicKey(privPEM); err == nil {
		t.Fatal("private key accepted as a public key")
	}
	if _, err := ParsePublicKey(append(pubPEM, pubPEM...)); err == nil {
		t.Fatal("multiple PEM blocks accepted")
	}
}

func FuzzVerifyAttestation(f *testing.F) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	data := fixture(f)
	proof, err := Sign(data, private)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(proof)
	f.Add([]byte("{}"))
	f.Add([]byte("not json"))
	f.Fuzz(func(t *testing.T, input []byte) {
		got, err := Verify(data, input, public)
		if err == nil && (got == nil || got.RunID != "run-1") {
			t.Fatal("accepted proof returned a different receipt")
		}
	})
}
