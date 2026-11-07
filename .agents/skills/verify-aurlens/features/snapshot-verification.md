# Snapshot verification

## Sub-features

Compare a checkout with a saved scan digest. `matched` exits 0. Changed or unsupported inputs exit 3. Human and JSON reports describe equality independently of the original security decision.

## How to get to it (user POV)

Run `aurlens verify PATH --snapshot-digest HEX`, optionally with `--json`. Save `HEX` from a completed scan. There is no AI configuration option for verification.

## Driving it with the CLI harness

`scripts/verify.sh run` drives five additional journeys through `scripts/verify-snapshot.py`. Inspect `verification/summary.json` and each action, stdout, and stderr artifact. The initial and blocked scan reports show where the two expected digests came from.

The journeys verify an unchanged checkout in JSON and text, an added helper, an unsupported binary, and a blocked recipe that still matches. The inert recipe's marker stays absent, and temporary files disappear before the summary is written.

## Gotchas

Matching is not approval. The initial scan can be blocked while verification matches. A later process does not recover the original scan's inode identities or lock the filesystem. Normal build outputs can invalidate whole-checkout coverage.
