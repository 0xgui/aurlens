# Changelog

## Unreleased

### Fixed

- Rules no longer skip a line just because it begins with `#`. Such a line is not a comment to the shell when it starts inside a string that spans lines, inside a here-document, after a backslash-newline, or after a character that is not a space or tab. A command on such a line ran without a finding. A line is now skipped only when it is certainly a comment. In a recipe that uses shell constructs the scanner does not model exactly, text in later comments is inspected too, so a recipe can now get a finding from a comment.

## 0.2.0

### Changed

- Command-line usage errors now exit 64. They exited 2 before, which collided with the `blocked` decision. Decision exit codes 0 to 3 are unchanged, and `--help` and `--version` still exit 0.

### Added

- `aurlens::cli::run` hosts the whole command line in the library, so another Rust binary can expose it under its own name. See [Embed the AURLens CLI](docs/embedding.md).
- `aurlens schema review` and `aurlens schema verify` print the JSON Schema of the version 1 reports. The files are in [`schemas/`](schemas).
- The report types implement `Deserialize` and ignore unknown fields. `Change`, `Coverage`, `Evidence`, `FileSummary`, and `Finding` are also exported from the crate root.

The JSON reports and their `schema_version` are unchanged.
