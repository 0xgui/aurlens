# AI-assisted review

Users opt into source disclosure through a trusted configuration and receive AI findings grounded in the reviewed files.

## Sub-features

- `ai-block-preserved` completes a configured model request without clearing deterministic findings.
- `ai-unverified-evidence` keeps a finding whose citation names a missing file as `AI-UNVERIFIED-001` at `review`, with AI complete, and keeps the deterministic block.
- `config-location` rejects AI configuration inside the checkout, covered by the broader Rust suite.

## How to get to it (user POV)

Run `aurlens scan /path/to/package --config /path/to/trusted/ai.toml --json`. The configuration must select an endpoint and model and set `send_source = true`.

## Driving it with the CLI harness

Preconditions: local socket binding is allowed. The fixture endpoint is owned by this run; no cloud credentials are required.

- Run the helper. It writes temporary trusted TOML outside the package checkout and invokes the actual CLI with `--config`.
- Inspect `ai-valid.request.json` for source text and snapshot identity actually sent through the production HTTP client.
- Require `ai-block-preserved.stdout.json` to have `ai.state = complete`, a retained deterministic `REMOTE-SHELL` finding, and exit 2.
- Require `ai-unverified-evidence.stdout.json` to have `ai.state = complete`, a retained deterministic `REMOTE-SHELL` finding, an `AI-UNVERIFIED-001` finding with severity `review` and empty evidence, and exit 2.
- For configuration changes, also run `cargo test --locked --test review cli_rejects_configuration_from_checkout_and_emits_json` and retain its output.

## Gotchas

A valid HTTP response is not sufficient for a completed AI review. The mock completion includes ordinary null refusal metadata to test compatibility. Real-model accuracy, cloud TLS, credentials, and provider retention remain unverified by this local fixture.
