package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/MrGray17/Mirage/internal/attestation"
)

func runAttest(args []string, stdout, stderr io.Writer) error {
	const usage = "usage: mirage attest sign --key PRIVATE.pem --out PROOF.json RECEIPT.json | mirage attest verify --key PUBLIC.pem --proof PROOF.json RECEIPT.json"
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, usage)
		return nil
	}
	mode := args[0]
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
