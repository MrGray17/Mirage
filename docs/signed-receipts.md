# Portable signed receipt evidence

Mirage receipts have a deterministic self-checksum and independent structural verification. An optional detached Ed25519 proof adds signer authentication and exact-file integrity to a receipt that an operator has chosen to endorse.

## Offline workflow

Generate an Ed25519 key outside the project and sandbox. Keep the private key protected; distribute the public key through a separate trusted channel.

```sh
umask 077
openssl genpkey -algorithm ED25519 -out signer.pem
openssl pkey -in signer.pem -pubout -out signer.pub.pem

mirage attest sign --key signer.pem --out proof.json receipt.json
mirage attest verify --key signer.pub.pem --proof proof.json receipt.json
```

The verifier needs only the receipt, detached proof and a separately trusted public key. No Docker, model, network, or private key is required. Modifying even the receipt's whitespace invalidates the signature, although the receipt's internal canonical hash may still pass. The proof uses a domain-separated Ed25519 signature over a SHA-256 digest of the exact receipt bytes, and binds the public-key fingerprint and canonical receipt identity. Existing receipt formats are unchanged.

## Trust boundary

This is **explicit operator endorsement**, not automated execution attestation, a hardware root of trust, a timestamp authority, a transparency log, or proof that a particular machine actually ran an agent. A signer could endorse a fabricated but structurally valid receipt. An attacker who controls the signing key can forge endorsements. Never trust a public key obtained only from the same untrusted sender as the receipt. The signature never grants mutation authority.

The private key is never needed by the agent container. Do not place it in the project snapshot, repository, or evidence bundle. The CLI does not create or rotate keys or provide revocation; those responsibilities belong to the operator. Proof output is create-only.
