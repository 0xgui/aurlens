# Experimental Shelly adapter

## Sub-features

The development patch adds native AUR approval, cached-approval verification, dependency metadata gates, and pre-build checks to Shelly 3.2.0. It does not modify the installed Shelly or enable scanning in the stock GUI.

## How to get to it (user POV)

Use the separate driver documented in [the integration guide](../../../../docs/shelly-integration.md). It requires Zig 0.17.0, unmodified Shelly 3.2.0 source, native development libraries including libalpm, and a built AURLens binary.

## Driving it with the native harness

Run `ZIG=/absolute/path/to/zig integrations/shelly/verify.sh SOURCE BINARY NEW_EVIDENCE` from the repo root. Inspect `source-check.txt`, `artifacts.sha256`, `protocol.log`, `gates.log`, `native.log`, and `summary.json` after cleanup. The focused target and wider AUR target must both pass. The driver supplies `AURLENS_TEST_BIN`, so the manager cases run instead of skipping for a missing executable.

Native fixtures call the real scanner, reject changed helpers on cached approvals before five build dispatch choices, scan a dependency separately, stop blocked or binary helper inputs before metadata evaluation, and present manual findings to an approval handler. Protocol tests reject disagreement, unsupported coverage, and missing requested AI completion.

## Gotchas

This is an isolated source-copy proof. It does not prove GUI rendering, privilege-elevation configuration preservation, an end-to-end recursive install, clean workspace operation through a complete real build, or compatibility with another Shelly release. Dependency downloads and GPG-agent sockets may require environment approval. Dirty caches can stop legitimate operations. Keep ordinary Shelly use and updates unchanged.
