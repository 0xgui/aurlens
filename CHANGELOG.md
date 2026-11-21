# Changelog

## Unreleased

### Added

- Rules for high-risk behaviour. `REVERSE-SHELL` blocks. `RAW-SOCKET`, `SETUID`, `PRIVILEGE-CONFIG`, `STARTUP-FILE`, `CREDENTIAL-STORE`, `DROP-HOST`, `NUMERIC-HOST`, `PACKAGE-MANAGER`, `DISABLE-PROTECTION`, `DESTRUCTIVE`, `BUILD-DOWNLOAD`, `OUTSIDE-WRITE` and `INSTALL-DOWNLOAD` need review. `INSTALL-SERVICE`, `SANDBOX-HELPER` and `PRELOAD` are informational. See [rules and severities](docs/rules.md).
- AI findings can have severity `info`. Such a finding is listed and does not change the decision. The instructions sent to the model now say what each severity is for, so a remark about packaging style no longer asks for a manual review.

### Changed

- `.SRCINFO` is no longer inspected for commands. It repeats the PKGBUILD and makepkg does not read it. `PROMPT-INJECTION` still covers it.
- `PLAIN-HTTP` and `DYNAMIC-EVAL` apply to shell that runs (the PKGBUILD, install scripts, `*.sh`, files with a `#!` line), not to patches, licence texts or images. The homepage in `url=` and XML namespaces are not reported.
- A skipped checksum is judged by its source. A version-control source and a file verified by a pinned PGP signature are `info`; a signature file is not reported; anything else needs review as before. `SKIP` items in arrays that span lines are now found.
- A line that matches a blocking rule is reported for that rule alone.

### Fixed

- A test ran `scan` without `--no-ai`, so it used the saved AI connection of whoever ran the tests.

- Rules no longer skip a line just because it begins with `#`. Such a line is not a comment to the shell when it starts inside a string that spans lines, inside a here-document, after a backslash-newline, or after a character that is not a space or tab. A command on such a line ran without a finding. A line is now skipped only when it is certainly a comment. In a recipe that uses shell constructs the scanner does not model exactly, text in later comments is inspected too, so a recipe can now get a finding from a comment.

## 0.2.0

### Changed

- Command-line usage errors now exit 64. They exited 2 before, which collided with the `blocked` decision. Decision exit codes 0 to 3 are unchanged, and `--help` and `--version` still exit 0.

### Added

- `aurlens::cli::run` hosts the whole command line in the library, so another Rust binary can expose it under its own name. See [Embed the AURLens CLI](docs/embedding.md).
- `aurlens schema review` and `aurlens schema verify` print the JSON Schema of the version 1 reports. The files are in [`schemas/`](schemas).
- The report types implement `Deserialize` and ignore unknown fields. `Change`, `Coverage`, `Evidence`, `FileSummary`, and `Finding` are also exported from the crate root.

The JSON reports and their `schema_version` are unchanged.
