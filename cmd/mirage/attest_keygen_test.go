package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MrGray17/Mirage/internal/attestation"
)

func TestAttestKeygenCreatesMatchingKeysWithoutOverwrite(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "signing.pem")
	publicPath := filepath.Join(dir, "trusted.pem")
	var stdout bytes.Buffer
	if err := runAttest([]string{"keygen", "--private", privatePath, "--public", publicPath}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	privatePEM, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	private, err := attestation.ParsePrivateKey(privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	public, err := attestation.ParsePublicKey(publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(private.Public().(ed25519.PublicKey), public) {
		t.Fatal("generated public key does not match private key")
	}
	if !strings.Contains(stdout.String(), attestation.KeyID(public)) {
		t.Fatalf("output does not identify generated signer: %q", stdout.String())
	}
	if err := runAttest([]string{"keygen", "--private", privatePath, "--public", filepath.Join(dir, "other.pem")}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("keygen overwrote an existing private key")
	}
}

func TestAttestKeygenRejectsSameDestination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	err := runAttest([]string{"keygen", "--private", path, "--public", path}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "must be different") {
		t.Fatalf("error=%v", err)
	}
}
