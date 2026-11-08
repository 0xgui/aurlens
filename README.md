# AURLens

See what you install.

AURLens reviews local AUR build recipes with deterministic checks and optional AI analysis. It reads package files without executing them, reports suspicious behavior with source evidence, and compares updates against a previous checkout.

This is an early Rust prototype for Linux. An [experimental Shelly 3.2.0 patch](docs/shelly-integration.md) adds native review gates. Your installed Shelly is unaffected. AURLens does not build packages, fetch AUR dependencies, scan upstream archives, or certify that software is safe. A clean report means no findings within the stated coverage.

## Run a review

For installation instructions, see [Install AURLens](docs/install.md). To build and try the source checkout with a current stable Rust toolchain:

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

```sh
./target/release/aurlens setup
./target/release/aurlens scan /path/to/package
```

Choose one connection:

- **Codex:** install the Codex CLI. Setup reuses its login or opens its login flow. AURLens uses the CLI's default model.
- **API provider:** enter a Chat Completions compatible HTTPS endpoint, model name, and API key. Key entry is hidden.
- **Local model:** enter the server's full Chat Completions endpoint and model name. The default endpoint is `http://127.0.0.1:11434/v1/chat/completions`.

Setup asks before sending package text and tests the connection with an inert recipe. It saves settings in `$XDG_CONFIG_HOME/aurlens/config.toml`, or `~/.config/aurlens/config.toml`. Credentials are stored separately in private files in that directory. Configuration files have mode `0600`; the directory has mode `0700`. Failed setup preserves the previous connection. Keep this directory outside Git repositories and package checkouts.

Subsequent scans use the saved connection automatically. Run setup again to change it. Use `scan PATH --no-ai` for static checks alone, or `--config /path/to/trusted/ai.toml` for an explicit connection. Without saved or explicit settings, scans run static checks alone. AURLens never discovers settings from a package checkout.

Setup also saves the preferences used by the experimental Shelly hook in the same file. Run `aurlens setup --disable-shelly` to disable automatic review while keeping your AI connection. Stock Shelly still requires upstream hook support before these preferences have any effect.

Codex reviews run through a restricted CLI profile with shell execution disabled. API and local model servers must support JSON output. Unsupported CLI versions, incompatible responses, and unavailable models make the review incomplete. For manual configuration and backend limits, see [the AI protocol](docs/ai-protocol.md).

The model receives the current package text, relative file names, hashes, and a baseline change summary when requested. Baseline file bodies are not sent. Model responses are untrusted. Each AI finding must cite a real file, line, and matching excerpt. AI can add findings but cannot clear deterministic findings. See [the AI protocol](docs/ai-protocol.md).

## Check a reviewed snapshot

Save the `snapshot_digest` from a completed scan, then check the checkout again before consuming its files:

```sh
./target/release/aurlens verify /path/to/package --snapshot-digest "$digest" --json
```

`verify` uses the same filesystem policy and default limits as `scan`. It returns `matched` with exit 0, or `changed` or `incomplete` with exit 3. It never runs AI, reads AI configuration, or executes package code. See [the verification protocol](docs/verification-protocol.md).

A match means the supported contents and modes match the supplied digest. Check the original scan decision separately. A blocked recipe can still match its digest. Verification does not lock files against subsequent changes.

## Read the result

The text report separates deterministic findings from AI analysis. `--json` returns schema version 1 with file hashes, a snapshot digest, coverage, findings, change metadata, AI status, and the final decision. Reports contain source excerpts used as evidence. They do not include configured authentication headers, but source excerpts can contain sensitive material. Keep reports private. See [the sensitive-information policy](SECURITY.md).

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

The project-local [verify-aurlens skill](.agents/skills/verify-aurlens/SKILL.md) drives scans and snapshot checks through the release CLI and retains commands, text and JSON reports, and fixture evidence. Run its helper with Bash, Python 3, and jq available:

```sh
.agents/skills/verify-aurlens/scripts/verify.sh run
```

Keep the map current as behavior changes with pstack's `maintain-verification-skill` workflow. This does not schedule any recurring work.

The [Shelly integration guide](docs/shelly-integration.md) documents its native test driver and current limits. Normal build paths are the first-release target. Advanced chroot and isolated execution remain experimental. Automatic review in stock Shelly requires upstream support.

MIT licensed. All scanner rules in this project are original, limited pattern checks, not copied from other scanners.
