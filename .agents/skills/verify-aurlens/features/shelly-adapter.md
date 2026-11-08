# Experimental Shelly adapter

## Sub-features

The development patch adds native AUR approval, cached-approval verification, dependency metadata gates, and pre-build checks to Shelly 3.2.0. It does not modify the installed Shelly or enable scanning in the stock GUI.

## How to get to it (user POV)

Use the separate driver documented in [the integration guide](../../../../docs/shelly-integration.md). It requires Zig 0.17.0, unmodified Shelly 3.2.0 source, makepkg/fakeroot, native development libraries including libalpm, and a built AURLens binary.

## Driving it with the native harness

Run `ZIG=/absolute/path/to/zig integrations/shelly/verify.sh SOURCE BINARY NEW_EVIDENCE` from the repo root. Inspect `source-check.txt`, `artifacts.sha256`, `protocol.log`, `cli-tests.log`, `cli-build.log`, `gates.log`, `native.log`, and `summary.json` after cleanup. CLI tests, the focused target, and the wider AUR target must all pass. The driver supplies all three executable fixture variables, so real scanner, child CLI, and makepkg cases run instead of skipping. Require `real_aurlens`, `real_shelly_child`, and `real_makepkg` to be true in the successful summary.

Native fixtures call the real scanner, reject changed helpers on cached approvals before five build dispatch choices, scan a dependency separately, stop blocked or binary helper inputs before metadata evaluation, and present manual findings to an approval handler. Protocol tests reject disagreement, unsupported coverage, and missing requested AI completion.

The saved-settings fixture enables production discovery explicitly, without developer environment switches. It loads the same private configuration as setup, invokes the real scanner with a simulated Codex response, and completes metadata, review, build, and payload inspection. This verifies adapter composition without calling a live model. Settings loader tests reject wrong ownership and symlinks and recognize disabled preferences. GUI serialization and CLI receiver tests separately cover a custom absolute configuration directory through the existing privilege-elevation frame; they do not prove an interactive GUI session.

The successful lifecycle fixture performs repeated in-process metadata and complete native builds with real prepare, build, check, and package functions. It inspects exact payload and `.PKGINFO` contents with `bsdtar`, verifies the original recipe afterward, and checks artifact lifetime through cleanup. A real non-Git local constructor exercises repeated metadata with generated `srcdir` data. Metadata and prepare functions that write an undeclared recipe helper must fail before returning metadata or archives. Failure and cancellation clean owned scratch; configured package and log outputs survive.

Real child CLI metadata and repeated builds preserve the recipe and the child's loaded packager policy. Real makepkg preserves configured compiler flags, packager, and uncompressed archive output. Mutation rejection runs through native, child, and makepkg paths. CLI transport tests require every host helper to preserve destination options and the isolated guest to omit all host paths in both option spellings. Those transport tests do not prove a real guest ran.

## Gotchas

This is an isolated source-copy proof. It does not prove GUI rendering, an end-to-end recursive install, successful real chroot or isolated builds, changed `pkgver` workflows, or compatibility with another Shelly release. Dependency downloads, GPG-agent sockets, and fakeroot IPC may require environment approval. Dirty preexisting recipe caches still fail; they are never hidden from review. Keep ordinary stock Shelly use and updates unchanged.
