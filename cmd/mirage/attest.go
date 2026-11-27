package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/MrGray17/Mirage/internal/attestation"
)

func runAttest(args []string, stdout, stderr io.Writer) error {
	const usage = "usage: mirage attest keygen --private PRIVATE.pem --public PUBLIC.pem | mirage attest sign --key PRIVATE.pem --out PROOF.json RECEIPT.json | mirage attest verify --key PUBLIC.pem --proof PROOF.json RECEIPT.json"
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, usage)
		return nil
	}
	mode := args[0]
	if mode == "keygen" {
		return runAttestKeygen(args[1:], stdout, stderr)
	}
	if mode != "sign" && mode != "verify" {
		return errors.New(usage)
	}
	flags := flag.NewFlagSet("attest "+mode, flag.ContinueOnError)
	flags.SetOutput(stderr)
	keyPath := flags.String("key", "", "explicit Ed25519 PEM key path")
	proofPath := flags.String("proof", "", "detached proof to verify")
	outputPath := flags.String("out", "", "new detached proof file")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 1 || strings.TrimSpace(*keyPath) == "" ||
		(mode == "sign" && (*outputPath == "" || *proofPath != "")) ||
		(mode == "verify" && (*proofPath == "" || *outputPath != "")) {
		return errors.New(usage)
	}
	encoded, err := readBoundedRegular(flags.Arg(0), attestation.MaxReceiptBytes)
	if err != nil {
		return err
	}
	keyBytes, err := readBoundedRegular(*keyPath, attestation.MaxKeyBytes)
	if err != nil {
		return fmt.Errorf("read attestation key: %w", err)
	}
	defer clear(keyBytes)
	if mode == "sign" {
		private, err := attestation.ParsePrivateKey(keyBytes)
		if err != nil {
			return err
		}
		defer clear(private)
		proof, err := attestation.Sign(encoded, private)
		if err != nil {
			return err
		}
		path, err := filepath.Abs(*outputPath)
		if err != nil {
			return err
		}
		if err := writeNewEvidence(path, proof); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "SIGNED proof=%s\n", path)
		return nil
	}
	public, err := attestation.ParsePublicKey(keyBytes)
	if err != nil {
		return err
	}
	proof, err := readBoundedRegular(*proofPath, attestation.MaxProofBytes)
	if err != nil {
		return err
	}
	verified, err := attestation.Verify(encoded, proof, public)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "SIGNATURE_VALID signer=%s receipt=%s run=%s committed=%d\n", attestation.KeyID(public), verified.SHA256, verified.RunID, len(verified.CommittedMutations))
	return nil
}

func runAttestKeygen(args []string, stdout, stderr io.Writer) error {
	const usage = "usage: mirage attest keygen --private PRIVATE.pem --public PUBLIC.pem"
	flags := flag.NewFlagSet("attest keygen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	privatePath := flags.String("private", "", "new Ed25519 PKCS#8 private key PEM")
	publicPath := flags.String("public", "", "new Ed25519 PKIX public key PEM")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*privatePath) == "" || strings.TrimSpace(*publicPath) == "" {
		return errors.New(usage)
	}
	privateAbsolute, err := filepath.Abs(*privatePath)
	if err != nil {
		return err
	}
	publicAbsolute, err := filepath.Abs(*publicPath)
	if err != nil {
		return err
	}
	if filepath.Clean(privateAbsolute) == filepath.Clean(publicAbsolute) {
		return errors.New("private and public key paths must be different")
	}
	for _, path := range []string{privateAbsolute, publicAbsolute} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("refusing to overwrite existing key file %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect key destination %s: %w", path, err)
		}
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate Ed25519 key: %w", err)
	}
	defer clear(private)
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return fmt.Errorf("encode private key: %w", err)
	}
	defer clear(privateDER)
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return fmt.Errorf("encode public key: %w", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	defer clear(privatePEM)
	// Write the non-secret half first. A partial failure never leaves an
	// unreported private key without its matching public key.
	if err := writeNewEvidence(publicAbsolute, publicPEM); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	if err := writeNewEvidence(privateAbsolute, privatePEM); err != nil {
		return fmt.Errorf("write private key (public key remains at %s): %w", publicAbsolute, err)
	}
	fmt.Fprintf(stdout, "KEYPAIR_CREATED signer=%s private=%s public=%s\n", attestation.KeyID(public), privateAbsolute, publicAbsolute)
	return nil
}
