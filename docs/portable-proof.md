# Mirage Proof: take the evidence with you

```sh
mirage attest sign --key signer.pem --out proof.json receipt.json
mirage proof pack --key signer.pub.pem --proof proof.json --out mirage-proof.zip receipt.json
mirage proof verify --key signer.pub.pem --report verified.html mirage-proof.zip
```

The bundle has exactly two entries: the original receipt and detached signature.
The independently distributed public key is intentionally absent. Verification
requires no model, Docker, network or private key. Observatory HTML is generated
locally from the verified receipt instead of trusting an archive-supplied page.

The ZIP reader never extracts to disk, accepts only exact entry names, rejects
duplicate and extra files, compression and oversized entries, and checks the
signature over exact receipt bytes. The same inputs produce the same archive.
The signature authenticates explicit operator endorsement, not actual execution
on an independently attested machine. This first bundle does not include the
raw contract, manifest or full mutation plan; those need additional bindings
before they can be trusted.
