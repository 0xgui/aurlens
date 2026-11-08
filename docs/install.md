# Install AURLens

AURLens runs on Linux. The prebuilt package supports x86-64 systems with glibc 2.35 or later. Other Linux architectures can build from source with Rust 1.85 or later.

## Install a release package

Download the Linux package and `SHA256SUMS` from the same [AURLens release](https://github.com/0xgui/aurlens/releases). In the download directory, check the package before extracting it:

```sh
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf aurlens-vVERSION-x86_64-unknown-linux-gnu.tar.gz
install -Dm755 aurlens-vVERSION-x86_64-unknown-linux-gnu/bin/aurlens "$HOME/.local/bin/aurlens"
```

Replace `VERSION` with the downloaded version. Add `~/.local/bin` to your shell's `PATH` if needed. Release checksums detect changed downloads; they do not replace trust in the release publisher.

The package also includes the source, documentation, license, and a `release.json` file with the exact source commit and binary hash. Your settings are separate from the installed binary, so replacing the binary preserves your connection.

## Install from source

Check out a reviewed release tag, then run:

```sh
cargo install --locked --path .
```

Cargo installs the executable in `~/.cargo/bin` by default. Keep that directory on your `PATH`.

## Connect and scan

```sh
aurlens setup
aurlens scan /path/to/package
```

Choose Codex, an API provider, or a local model. Setup tests the connection and saves it privately. Codex requires a compatible installed Codex CLI. Local models require a running server with a Chat Completions compatible endpoint. AURLens does not download model weights or start a model server.

Use `aurlens scan /path/to/package --no-ai` for static checks alone. Without saved settings, scans also run static checks alone. Installation does not enable automatic scanning in stock Shelly. See [Shelly integration](shelly-integration.md) for its current limits.
