// Package attestation implements optional detached signatures for verified
// Mirage receipts. Signing is an explicit offline endorsement; it neither
// grants execution authority nor proves that the signer observed a real run.
package attestation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/MrGray17/Mirage/internal/receipt"
)

const (
	Schema          = "mirage.receipt-attestation/v1"
	MaxReceiptBytes = 4 << 20
	MaxProofBytes   = 4096
	MaxKeyBytes     = 16384
	signingDomain   = "MIRAGE RECEIPT ATTESTATION V1\x00"
)

var ErrInvalidAttestation = errors.New("invalid Mirage receipt attestation")

type Proof struct {
	Schema        string `json:"schema"`
	KeyID         string `json:"key_id"`
	ReceiptDigest string `json:"receipt_digest"`
	ReceiptHash   string `json:"receipt_hash"`
	Signature     string `json:"signature"`
}

func digest(data []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(data))
}

func KeyID(public ed25519.PublicKey) string {
	return digest(public)
}

// The fixed-length SHA-256 digest commits to the exact receipt file bytes,
// including its formatting. Domain separation prevents cross-protocol use.
func message(encoded []byte) []byte {
	hash := sha256.Sum256(encoded)
	return append([]byte(signingDomain), hash[:]...)
}

func verifiedReceipt(encoded []byte) (*receipt.Receipt, error) {
	if len(encoded) == 0 || len(encoded) > MaxReceiptBytes {
		return nil, fmt.Errorf("%w: receipt size", ErrInvalidAttestation)
	}
	return receipt.ParseAndVerify(encoded)
}

func Sign(encoded []byte, private ed25519.PrivateKey) ([]byte, error) {
	if len(private) != ed25519.PrivateKeySize || !bytes.Equal(private, ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])) {
		return nil, fmt.Errorf("%w: Ed25519 private key", ErrInvalidAttestation)
	}
	verified, err := verifiedReceipt(encoded)
	if err != nil {
		return nil, err
	}
	public := private.Public().(ed25519.PublicKey)
	proof := Proof{
		Schema:        Schema,
		KeyID:         KeyID(public),
		ReceiptDigest: digest(encoded),
		ReceiptHash:   verified.SHA256,
		Signature:     base64.StdEncoding.EncodeToString(ed25519.Sign(private, message(encoded))),
	}
	out, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// Verify requires a public key supplied independently of the proof. An
// embedded or attacker-selected key must never establish signer trust.
func Verify(encoded, proofBytes []byte, trusted ed25519.PublicKey) (*receipt.Receipt, error) {
	if len(trusted) != ed25519.PublicKeySize || len(encoded) == 0 || len(encoded) > MaxReceiptBytes ||
		len(proofBytes) == 0 || len(proofBytes) > MaxProofBytes {
		return nil, ErrInvalidAttestation
	}
	var proof Proof
	if err := json.Unmarshal(proofBytes, &proof); err != nil {
		return nil, ErrInvalidAttestation
	}
	canonical, err := json.Marshal(proof)
	if err != nil || !bytes.Equal(bytes.TrimSpace(proofBytes), canonical) {
		return nil, fmt.Errorf("%w: proof is not canonical", ErrInvalidAttestation)
	}
	if proof.Schema != Schema || proof.KeyID != KeyID(trusted) || proof.ReceiptDigest != digest(encoded) {
		return nil, fmt.Errorf("%w: schema, signer or receipt binding", ErrInvalidAttestation)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(proof.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature) != proof.Signature {
		return nil, fmt.Errorf("%w: signature encoding", ErrInvalidAttestation)
	}
	if !ed25519.Verify(trusted, message(encoded), signature) {
		return nil, fmt.Errorf("%w: signature mismatch", ErrInvalidAttestation)
	}
	verified, err := verifiedReceipt(encoded)
	if err != nil {
		return nil, err
	}
	if proof.ReceiptHash != verified.SHA256 {
		return nil, fmt.Errorf("%w: semantic receipt identity mismatch", ErrInvalidAttestation)
	}
	return verified, nil
}

func parsePEM(encoded []byte, kind string) ([]byte, error) {
	if len(encoded) == 0 || len(encoded) > MaxKeyBytes {
		return nil, ErrInvalidAttestation
	}
	block, rest := pem.Decode(bytes.TrimSpace(encoded))
	if block == nil || block.Type != kind || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%w: expected one %s PEM block", ErrInvalidAttestation, kind)
	}
	return block.Bytes, nil
}

func ParsePrivateKey(encoded []byte) (ed25519.PrivateKey, error) {
	der, err := parsePEM(encoded, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	value, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: private key format", ErrInvalidAttestation)
	}
	key, ok := value.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: expected Ed25519 private key", ErrInvalidAttestation)
	}
	return key, nil
}

func ParsePublicKey(encoded []byte) (ed25519.PublicKey, error) {
	der, err := parsePEM(encoded, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	value, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: public key format", ErrInvalidAttestation)
	}
	key, ok := value.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: expected Ed25519 public key", ErrInvalidAttestation)
	}
	return key, nil
}
