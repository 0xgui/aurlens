# AI-assisted review

Users opt into source disclosure through a trusted configuration and receive AI findings grounded in the reviewed files.

## Sub-features

- `ai-block-preserved` completes a configured model request without clearing deterministic findings.
- `ai-invalid-evidence` reports incomplete review when the model cites a missing file.
- `config-location` rejects AI configuration inside the checkout, covered by the broader Rust suite.

## How to get to it (user POV)

Run `aurlens scan /path/to/package --config /path/to/trusted/ai.toml --json`. The configuration must select an endpoint and model and set `send_source = true`.

## Driving it with the CLI harness

Preconditions: local socket binding is allowed. The fixture endpoint is owned by this run; no cloud credentials are required.

- Run the helper. It writes temporary trusted TOML outside the package checkout and invokes the actual CLI with `--config`.
- Inspect `ai-valid.request.json` for source text and snapshot identity actually sent through the production HTTP client.
- Require `ai-block-preserved.stdout.json` to have `ai.state = complete`, a retained deterministic `REMOTE-SHELL` finding, and exit 2.
- Require `ai-invalid-evidence.stdout.json` to have `ai.state = incomplete`, reason `ai_evidence`, and exit 3.
- For configuration changes, also run `cargo test --locked --test review cli_rejects_configuration_from_checkout_and_emits_json` and retain its output.

## Gotchas

A valid HTTP response is not sufficient for a completed AI review. The mock completion includes ordinary null refusal metadata to test compatibility. Real-model accuracy, cloud TLS, credentials, and provider retention remain unverified by this local fixture.
