# AURLens

See what you install.

AURLens reviews local AUR build recipes with deterministic checks and optional AI analysis. It reads package files without executing them, reports suspicious behavior with source evidence, and compares updates against a previous checkout.

This is an early Rust prototype for Linux. It does not yet integrate with Shelly, build packages, fetch AUR dependencies, scan upstream archives, or certify that software is safe. A clean report means no findings within the stated coverage.

## Run a review

Install a current stable Rust toolchain, then build the project:

```sh
cargo build --locked --release
./target/release/aurlens scan examples/clean
./target/release/aurlens scan examples/flagged --json
```

The flagged example contains inert suspicious text. AURLens reads it and returns exit code 2. It never runs the commands in the example.

Review a checkout you downloaded yourself:

```sh
./target/release/aurlens scan /path/to/package
./target/release/aurlens scan /path/to/new --baseline /path/to/old --json
```

Both paths must contain a regular `PKGBUILD`. Directory symlinks, including symlinks in the supplied root path, are rejected. Relative paths containing `..` are rejected; use an absolute path instead.

## Enable AI review

AURLens supports a configurable Chat Completions compatible HTTP endpoint. Use a local model server or an HTTPS cloud provider that implements the documented response protocol. You select the endpoint and model; AURLens does not discover a provider or send requests by default.

Copy `examples/ai.toml` to a trusted location outside the package checkout. Set `endpoint` to the full completion URL and `model` to your server's model name. Set `send_source = true` to opt in to sending the reviewed package text to that endpoint.

```sh
./target/release/aurlens scan /path/to/package --config /path/to/trusted/ai.toml
```

For a cloud provider, use HTTPS and name an environment variable containing its API key with `api_key_env`. Do not put the key itself in the configuration or command line. Plain HTTP requires `allow_loopback_http = true` and a numeric loopback address. Model servers must support JSON output; incompatible or ungrounded responses make the review incomplete.

The model receives the current package text, relative file names, hashes, and a baseline change summary when requested. Baseline file bodies are not sent. Model responses are untrusted. Each AI finding must cite a real file, line, and matching excerpt. AI can add findings but cannot clear deterministic findings. See [the AI protocol](docs/ai-protocol.md).

## Read the result

The text report separates deterministic findings from AI analysis. `--json` returns schema version 1 with file hashes, a snapshot digest, coverage, findings, change metadata, AI status, and the final decision. JSON reports contain source excerpts used as evidence, but not complete source files or API keys.

| Exit code | Decision | Meaning |
| --- | --- | --- |
| 0 | `no_findings` | No findings within the declared coverage. AI status shows whether a model ran. |
| 1 | `manual_review` | At least one finding needs review. |
| 2 | `blocked` | At least one blocking pattern was found. |
| 3 | `incomplete` | Inputs changed, coverage failed, AI failed, or configuration was invalid. |

Every nonzero result requires attention. These codes are not a risk ranking. Incomplete reviews retain any findings already observed. Never treat a successful HTTP request or JSON parse as an approval to build.

AURLens reviews all supported files in the checkout, including hidden files, helper scripts, `src`, and `pkg`. Git ignore files do not hide content. Only the actual root `.git` metadata directory is excluded and reported. Binary or unsupported text, symlinks, hardlinks, special files, and exceeded limits make coverage incomplete. Prefer a fresh checkout rather than a directory containing build outputs.

The default limits are 256 files, 1,024 directory entries, 16 directory levels, 256 KiB per file, and 2 MiB total text. [The threat model](docs/threat-model.md) describes these boundaries and the limits of source-pattern matching.

## Develop

```sh
cargo test --locked
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
```

Tests use temporary directories and local HTTP fixtures. They do not call a paid model, install a package, or execute a recipe. The CLI and library share one review operation.

The project-local [verify-aurlens skill](.agents/skills/verify-aurlens/SKILL.md) drives eight user journeys through the release CLI and retains commands, text and JSON reports, and fixture evidence. Run its helper with Bash and jq available:

```sh
.agents/skills/verify-aurlens/scripts/verify.sh run
```

Keep the map current as behavior changes with pstack's `maintain-verification-skill` workflow. This does not schedule any recurring work.

The next milestone is [native Shelly integration](docs/shelly-integration.md), including scans before package evaluation, dependency coverage, and an immediate check that build inputs match the reviewed snapshot.

MIT licensed. All scanner rules in this project are original, limited pattern checks, not copied from other scanners.
