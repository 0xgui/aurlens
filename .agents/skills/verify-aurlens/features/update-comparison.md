# Update comparison

Users compare a new local checkout against an earlier checkout and see files added, deleted, modified, or changed in mode.

## Sub-features

- `update-diff` detects an added installation helper.
- `baseline-revalidation` rejects a baseline modified during a review, covered by the broader Rust suite.

## How to get to it (user POV)

Run `aurlens scan /path/to/new --baseline /path/to/old --json`. Both roots must contain a supported regular `PKGBUILD`.

## Driving it with the CLI harness

Preconditions: Doctor passes and both fixture checkouts are isolated from the working tree.

- Run the helper's complete journeys.
- Inspect `update-diff.action.json` for the actual `--baseline` argument.
- Require `update-diff.stdout.json` to contain a `changes` item with `path = helper.install` and `kind = added`, plus a non-null baseline digest.
- For changes to baseline handling, also run `cargo test --locked --test review changed_source_or_baseline_during_ai_prevents_completion` and retain the terminal transcript.

## Gotchas

No baseline produces `changes = null`; a successfully compared unchanged baseline produces an empty list. Root directory modes are part of the digest. A comparison does not fetch AUR history or authorize a later build.
