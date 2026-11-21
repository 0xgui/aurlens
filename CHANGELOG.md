# Changelog

## Unreleased

### Added

- Every report carries a grade, `risk`, for the review and for each finding: `low`, `medium`, `high`, `critical`, or `unknown` when the review is incomplete. The text report prints it as advice: "Looks fine", "Check first", "Be careful", "Do not install", "Could not check". It is computed from the rules; a model's finding is `medium` and cannot lower it. See [rules and severities](docs/rules.md#advice).
- Rules for high-risk behaviour. `REVERSE-SHELL` blocks. `RAW-SOCKET`, `SETUID`, `PRIVILEGE-CONFIG`, `STARTUP-FILE`, `CREDENTIAL-STORE`, `DROP-HOST`, `NUMERIC-HOST`, `PACKAGE-MANAGER`, `DISABLE-PROTECTION`, `DESTRUCTIVE`, `BUILD-DOWNLOAD`, `OUTSIDE-WRITE`, `INSTALL-DOWNLOAD`, `INSTALL-WRITE`, `PACKAGE-TRUST`, `ACCOUNT`, `SCRIPT-DOWNLOAD` and `PIPED-SHELL` need review. `INSTALL-SERVICE`, `SANDBOX-HELPER` and `PRELOAD` are informational. See [rules and severities](docs/rules.md).
- AI findings can have severity `info`. Such a finding is listed and does not change the decision. The instructions sent to the model now say what each severity is for, so a remark about packaging style no longer asks for a manual review.

- An image (PNG, JPEG, GIF, WebP, ICO), a PDF or a binary OpenPGP key no longer makes the review `incomplete`. It is recognised by how it starts; any other file that is not text is refused as before. Its hash is part of the snapshot digest and it is reported in `coverage.uninspected`, in `files` with `"opaque": true`, and by an `OPAQUE-FILE` finding: `review` when it is new or changed, `info` when the baseline has the same bytes. `OPAQUE-RUN` reports a recipe that runs such a file, and blocks one that names it in `install=`. Files that have to be text to be reviewed (the PKGBUILD, install scripts, patches, anything with a `#!` line, and others listed in [rules and severities](docs/rules.md)) are refused as before when they are not.

### Changed

- The snapshot digest of a checkout that contains only text files is unchanged. A checkout with a file that is not text had no digest before.
- `PackageFile`, `FileSummary` and `Coverage` have new public fields (`opaque`, `size`, `format`, `uninspected`). Code that builds these structs by hand needs them; code that parses reports does not.
- `.SRCINFO` is no longer inspected for commands. It repeats the PKGBUILD and makepkg does not read it. `PROMPT-INJECTION` still covers it.
- `PLAIN-HTTP` and `DYNAMIC-EVAL` apply to shell that runs (the PKGBUILD, install scripts, `*.sh`, files with a `#!` line), not to patches, licence texts or images. The homepage in `url=` and XML namespaces are not reported.
- A skipped checksum is judged by its source. A version-control source and a file verified by a pinned PGP signature are `info`; a signature file is not reported; anything else needs review as before. `SKIP` items in arrays that span lines are now found.
- A line that matches a blocking rule is reported for that rule alone.
- `REMOTE-SHELL` also blocks a download handed to a shell by process or command substitution (`sh <(curl …)`, `sh -c "$(curl …)"`, `eval "$(curl …)"`) and a shell named by path or run through `sudo`. `ENCODED-SHELL` also blocks decompressed or reversed content piped into a shell.
- `PRIVILEGE` applies to commands in scripts. The word `sudo` in a dependency list, a description, printed advice, release notes or a patch is no longer reported. `su` with an option is.
- Rules about a command find it after a path, a `NAME=value` setting, `!`, a subshell, a `case` arm or `-c "…"`, and no longer take the items of an array for commands.
- Printed advice is recognised by following the quoting: a message that spans lines, a `>` inside a quoted message, and notes printed with `cat <<EOF` are text. A blocked command that only appears in printed advice needs review instead of blocking.
- `SETUID` finds modes written with a leading zero, with `=`, or as `--mode=`. A directory created setgid is not reported.
- The sandbox-helper note needs every file of the command to be named as a helper and none to be in a `bin` directory.
- `DROP-HOST` needs the host to appear as a host. `NUMERIC-HOST` ignores private networks. An `http://` source with a SHA-2 or BLAKE2 checksum is `info`.

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
