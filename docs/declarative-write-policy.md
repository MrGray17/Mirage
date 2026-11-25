# Declarative write policy (milestone P1)

An operator may select a restrictive policy from a trusted location outside the
project. All four fields are required:

```json
{
  "version": "mirage.write-policy/v1",
  "write_allow": ["/workspace/README.md", "/workspace/docs/guide.md"],
  "write_deny": ["/workspace/docs/guide.md"],
  "max_authority_seconds": 300
}
```

```sh
mirage edit --policy /trusted/policy.json README.md "Improve the introduction"
```

The policy is loaded before sandbox preparation. Exact allow and deny lists are
validated; deny wins, unlisted targets are rejected, and the actual contract
only permits the one requested target. Authority duration is capped at contract
issuance, including subsequent runtime overhead. Expiry is exclusive. Intrinsic
filesystem restrictions and mutation count still apply. This local policy cannot
authorize remote GitHub publication.

The effective contract participates in the existing manifest and receipt binding.
The raw policy document is not separately signed or retained in the receipt.
This is an opt-in restriction, not mandatory policy enforcement: a trusted
caller must select it. A future trusted approval service must own policy
selection. Confidentiality, glob rules, semantic code correctness and multi-file
transactions are not claimed.
