# Attack Lab: reproducible competition evaluation

After installing the official fixture (`mirage setup`), run:

```sh
mirage lab --scenario malicious --trials 1
mirage lab --scenario both --trials 5
```

Every trial creates a fresh demo workspace, executes the existing real rootless
Docker fixture and persists its own verified receipt and Observatory. The lab
re-reads each receipt and cross-checks identity and accounting. It generates a
local HTML index and JSON report with actual elapsed wall-clock durations, not
simulated measurements. A failed or uncertain trial terminates the campaign
with a nonzero exit and a partial report; it is never retried automatically.

The malicious fixture demonstrates blocked secret read, direct network request
and read-only root write while an authorized README edit commits. It is not a
general attack generator or a claim about all possible agents. The benign
fixture is a control. All files use generated fixture content; no real user
secrets or repositories are targeted. The output directory is generated under
the backend's user cache. On Windows, inspect the printed Linux path via WSL.

Report elapsed time includes the full demo call, not isolated model latency.
Record runner hardware and Docker configuration separately for comparisons;
this is an initial reproducible evaluation harness, not a full benchmark.
