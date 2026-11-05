# Static package review

Users scan a local package checkout and inspect source evidence before deciding whether to build it separately.

## Sub-features

- `static-clean` returns no findings and explicitly marks AI not run.
- `static-block` identifies a remote-shell pattern with source evidence and exit 2.
- `no-execution` leaves the inert recipe's marker absent.

## How to get to it (user POV)

Run `aurlens scan /path/to/package` for text or append `--json` for the machine report. Use `aurlens scan --help` for the command contract.

## Driving it with the CLI harness

Preconditions: a release build passes Doctor and the helper has a new evidence destination.

- Run `scripts/verify.sh run` from the skill directory or use the full helper path from the repo root.
- Inspect `static-clean.action.json` and `static-clean.stdout.json`. Exit 0, `decision = no_findings`, complete local coverage, and `ai.state = not_run` prove the static path.
- Inspect `static-block.action.json` and `static-block.stdout.json`. Exit 2 and a `REMOTE-SHELL` finding citing `PKGBUILD` prove blocking behavior.
- `summary.json` records the verified absence of recipe execution after the fixture directory is removed.

## Gotchas

JSON mode still uses nonzero exit codes for findings. A shell using `set -e` needs to capture expected nonzero statuses. No findings is not a safety certificate; dependency packages and upstream downloads are outside the review.
