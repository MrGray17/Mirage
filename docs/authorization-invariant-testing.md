# Authorization invariant testing

The Linux reconciliation fuzz target generates two existing files, independent
content/deletion/mode actions, optional file creation, exact allow/deny masks,
and an exclusive contract expiry boundary. A separate reference model permits
only one existing-file content change with an unexpired exact allow and no
deny. The target checks the decision, authority binding, authorized bytes and
determinism of a repeated scan.

Run a bounded campaign:

```sh
go test ./internal/runtime/reconcile -run '^$' -fuzz '^FuzzVerifyExactAuthorization$' -fuzztime 60s -parallel 2
```

CI executes a short campaign on Linux, in addition to ordinary seed tests and
the existing race-enabled suite. This is bounded dynamic evidence, not a
formal proof. It does not model every filesystem object, hostile daemon,
noncooperating host race or remote Git operation. Preserve minimized failing
inputs in the Go fuzz corpus as regression fixtures.
