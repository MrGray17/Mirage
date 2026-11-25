package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/MrGray17/Mirage/internal/attestation"
	"github.com/MrGray17/Mirage/internal/observatory"
	"github.com/MrGray17/Mirage/internal/proof"
)

func runProof(args []string, stdout, stderr io.Writer) error {
	const usage = "usage: mirage proof pack --key PUBLIC.pem --proof PROOF.json --out BUNDLE.zip RECEIPT.json | mirage proof verify --key PUBLIC.pem [--report REPORT.html] BUNDLE.zip"
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(stdout, usage)
		return nil
	}
	mode := args[0]
	if mode != "pack" && mode != "verify" {
		return errors.New(usage)
	}
	flags := flag.NewFlagSet("proof "+mode, flag.ContinueOnError)
	flags.SetOutput(stderr)
	key := flags.String("key", "", "independently trusted Ed25519 public key")
	sig := flags.String("proof", "", "detached receipt signature")
	out := flags.String("out", "", "new proof archive")
	report := flags.String("report", "", "new locally rendered Observatory HTML")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 1 || *key == "" ||
		(mode == "pack" && (*sig == "" || *out == "" || *report != "")) ||
		(mode == "verify" && (*sig != "" || *out != "")) {
		return errors.New(usage)
	}
	keyBytes, err := readBoundedRegular(*key, attestation.MaxKeyBytes)
	if err != nil {
		return err
	}
	public, err := attestation.ParsePublicKey(keyBytes)
	if err != nil {
		return err
	}
	if mode == "pack" {
		encoded, err := readBoundedRegular(flags.Arg(0), attestation.MaxReceiptBytes)
		if err != nil {
			return err
		}
		signature, err := readBoundedRegular(*sig, attestation.MaxProofBytes)
		if err != nil {
			return err
		}
		bundle, err := proof.Create(encoded, signature, public)
		if err != nil {
			return err
		}
		if err := writeNewEvidence(*out, bundle); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "PACKED proof=%q\n", *out)
		return nil
	}
	bundle, err := readBoundedRegular(flags.Arg(0), proof.MaxBundleBytes)
	if err != nil {
		return err
	}
	verified, err := proof.Verify(bundle, public)
	if err != nil {
		return err
	}
	if *report != "" {
		page, err := observatory.Render(verified)
		if err != nil {
			return err
		}
		if err := writeNewEvidence(*report, page); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "PROOF_VALID signer=%s receipt=%s run=%q committed=%d\n", attestation.KeyID(public), verified.SHA256, verified.RunID, len(verified.CommittedMutations))
	return nil
}
