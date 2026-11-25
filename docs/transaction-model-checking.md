# Finite model checking of local effect transactions

The reference model is deliberately independent of runtime code. Run:

```sh
go test -v ./internal/modelcheck
```

Breadth-first exploration checks every reachable state of a finite abstraction
of one transaction, its exact effect set (authorized, protected, both, none),
exclusive authority expiry, one competing baseline change before lock
acquisition, durable intent, replacement, acknowledgement and interruption.

Safety properties:
- committed effects are a subset of authorized effects;
- no replacement dispatch after expiry or against a stale baseline;
- a rejected transaction has not applied an effect;
- a committed terminal outcome has its exact effect;
- interrupted durable intent or replacement is uncertain, not silently retried.

A negative-control model removes the final freshness guard. The checker must
produce a shortest trace demonstrating an invalid replacement after expiry.
The ordinary Go test suite runs both models; the counts are printed by the
test, not hard-coded into a demo.

This is executable finite-state model checking, not proof of the Go runtime
or full ACID compliance. The model assumes the baseline is initially captured
and cooperating writers cannot change it after the commit lock is acquired.
It abstracts away actual disk persistence, untrusted host writers, root
identity races, network effects, multiple transactions, and key compromise.
The durable-intent states describe the intended recovery protocol in PR #39;
they are not a claim that the PR has merged. A future refinement should model
multiple transactions and map each abstract step to runtime regression tests.
