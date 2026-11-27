// Package proof packages exact receipt bytes and their detached endorsement.
// Verification is offline and never extracts archive entries to disk.
package proof

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"

	"github.com/MrGray17/Mirage/internal/attestation"
	"github.com/MrGray17/Mirage/internal/receipt"
)

const MaxBundleBytes = attestation.MaxReceiptBytes + attestation.MaxProofBytes + 4096

var ErrInvalidBundle = errors.New("invalid Mirage proof bundle")

// Create verifies both inputs against the independently supplied trusted key
// before writing a deterministic, uncompressed two-entry archive.
func Create(encoded, signature []byte, public ed25519.PublicKey) ([]byte, error) {
	if _, err := attestation.Verify(encoded, signature, public); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, entry := range []struct {
		name string
		data []byte
	}{{"receipt.json", encoded}, {"proof.json", signature}} {
		part, err := writer.CreateHeader(&zip.FileHeader{Name: entry.name, Method: zip.Store})
		if err != nil {
			return nil, err
		}
		if _, err := part.Write(entry.data); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

// Verify accepts only two named, bounded, regular, stored entries. It never
// trusts HTML, embedded keys, filenames, metadata or extra archive members.
func Verify(bundle []byte, public ed25519.PublicKey) (*receipt.Receipt, error) {
	if len(bundle) == 0 || len(bundle) > MaxBundleBytes {
		return nil, ErrInvalidBundle
	}
	reader, err := zip.NewReader(bytes.NewReader(bundle), int64(len(bundle)))
	if err != nil || len(reader.File) != 2 {
		return nil, ErrInvalidBundle
	}
	entries := make(map[string][]byte, 2)
	for _, entry := range reader.File {
		var limit int64
		switch entry.Name {
		case "receipt.json":
			limit = attestation.MaxReceiptBytes
		case "proof.json":
			limit = attestation.MaxProofBytes
		default:
			return nil, ErrInvalidBundle
		}
		if _, exists := entries[entry.Name]; exists || !entry.Mode().IsRegular() ||
			entry.Method != zip.Store || entry.UncompressedSize64 == 0 ||
			entry.UncompressedSize64 > uint64(limit) || entry.CompressedSize64 != entry.UncompressedSize64 {
			return nil, ErrInvalidBundle
		}
		part, err := entry.Open()
		if err != nil {
			return nil, ErrInvalidBundle
		}
		data, err := io.ReadAll(io.LimitReader(part, limit+1))
		closeErr := part.Close()
		if err != nil || closeErr != nil || uint64(len(data)) != entry.UncompressedSize64 || int64(len(data)) > limit {
			return nil, fmt.Errorf("%w: entry acquisition", ErrInvalidBundle)
		}
		entries[entry.Name] = data
	}
	return attestation.Verify(entries["receipt.json"], entries["proof.json"], public)
}
