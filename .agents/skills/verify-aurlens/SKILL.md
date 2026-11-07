---
name: verify-aurlens
description: Verify AURLens CLI behavior after scanner, AI-client, report, or command changes. Drive real scans with isolated package and local model fixtures and retain evidence.
---

# Verify AURLens

Use the real CLI and the [feature map](features/README.md). AURLens is a short-lived Linux CLI, with a library as a secondary interface. The experimental Shelly patch has a separate [native verification route](features/shelly-adapter.md). Stock Shelly remains unchanged.

## Launch

Run from the repository root with Rust stable, Bash, Python 3, jq, and sha256sum available. The source `Cargo.lock` must exist. For this workspace, when `cargo` is absent from PATH, set:

```sh
export CARGO_HOME="$HOME/.cache/aurlens-toolchain/cargo"
export RUSTUP_HOME="$HOME/.cache/aurlens-toolchain/rustup"
export CARGO="$CARGO_HOME/bin/cargo"
```

That cache is a workspace setup aid, not a project prerequisite on other machines. Use their installed Cargo instead.

Build once with `cargo build --locked --release`, or let the helper build it. With the workspace exports, use `"$CARGO" build --locked --release`. A usable binary answers `aurlens --version` and `aurlens scan --help`. There is no persistent app server or database.

## Doctor

Run the read-only check first when a journey behaves unexpectedly:

```sh
.agents/skills/verify-aurlens/scripts/verify.sh doctor
```

It verifies the Cargo package version against the release binary, checks scan and verification help, and records binary and lockfile hashes. Missing or mismatched builds fail. Build again before proceeding.

## Drive

Run the complete mapped CLI journeys:

```sh
.agents/skills/verify-aurlens/scripts/verify.sh run
```

The helper prints a newly created evidence directory. To choose a destination, supply a path that does not exist:

```sh
.agents/skills/verify-aurlens/scripts/verify.sh run /tmp/aurlens-review-proof
```

It builds the release binary and runs the Rust `user_journey_evidence` test against that exact executable. Journeys launch fresh CLI subprocesses, temporary package directories, explicit trusted configuration, and owned loopback HTTP fixtures. The model fixture is the only substituted boundary. It exercises the production HTTP client and response parser without a real model, credentials, or cloud charges.

With dependencies already cached, set `AURLENS_VERIFY_OFFLINE=1` to use Cargo's offline mode. A sandbox that forbids local socket binding cannot run the AI journeys; report that restriction and use the environment's normal approval mechanism. A bind failure is not a successful verification.

## Evidence

Each journey saves its action arguments and exit code, stdout, and stderr. The `static-text` journey records a plain-text report; the other journeys record JSON. `doctor.txt` identifies the tested executable and lockfile. `ai-valid.request.json` records the inert source actually sent to the local model fixture. `summary.json` appears only after assertions and fixture cleanup succeed.

Require all eight mapped journeys in `summary.json`, `passed = true`, and `scratch_removed = true`. Inspect the corresponding action and output artifacts for the feature under review. Source hashes and reported AI status must match the exercised path. A test count or successful compile alone does not prove CLI behavior.

Also require five snapshot journeys in `verification/summary.json`, `passed = true`, and `scratch_removed = true`. These use the same release executable. Their action and stdout files prove unchanged, changed, unsupported, text, and blocked-but-matching behavior. A passing scan summary alone does not cover the `verify` command.

The harness checks that inert recipe text never creates its marker, an external symlink's sentinel never enters output, blocking findings survive a clean AI reply, invalid AI evidence fails, and changed source prevents completion. Reports are about local text only. Local CLI fixtures do not evaluate real-model accuracy, cloud TLS behavior, upstream-source analysis, or the native Shelly adapter.

## Cleanup

Rust temporary directories are removed after the run; each model-fixture thread is joined and its socket closes. Failed test processes release their own resources. No package build, installation, user configuration edit, or shell execution is part of a journey. Never kill processes by name.

Evidence remains in the printed directory. After the helper exits, read `summary.json` from that location and confirm the action and stdout files still exist. Keep failed-run evidence too; a run without a passing summary remains failed.

## Helpers

`scripts/verify.sh doctor` checks an existing build. `scripts/verify.sh run [new-evidence-directory]` builds and drives the mapped CLI journeys. The behavioral driver lives in `tests/review.rs`, so normal `cargo test --locked` exercises it too.
