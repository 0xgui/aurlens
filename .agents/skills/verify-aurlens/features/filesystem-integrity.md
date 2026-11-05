# Filesystem integrity

Users receive an incomplete report when a checkout includes unsupported links or changes while it is being reviewed.

## Sub-features

- `external-symlink` rejects a link to an unrelated sentinel without disclosing its contents.
- `changed-during-ai` detects package modification before the model response completes.

## How to get to it (user POV)

Use the ordinary `aurlens scan` command. Integrity checks also run when `--config` or `--baseline` is supplied.

## Driving it with the CLI harness

Preconditions: Linux procfs is available and the fixture model can bind a loopback port.

- Run the helper's journeys. The model fixture synchronizes a package edit before returning its response.
- Inspect `changed-during-ai.stdout.json`. Require exit 3, `revalidated = false`, and a `snapshot_changed` coverage issue.
- Inspect `external-symlink.stdout.json`. Require incomplete coverage, exit 3, and absence of `UNRELATED_PRIVATE_SENTINEL` from the output.
- Read `summary.json` after the helper exits. `scratch_removed = true` proves fixture cleanup; the evidence files must still exist.

## Gotchas

The scanner detects changes observed during its bounded checks. It does not lock the directory against later mutation. Shell aliases and pacman hooks are not substitutes for a future native Shelly build-input check.
