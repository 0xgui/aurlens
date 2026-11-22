# Changelog

## Unreleased

### Changed

- A model finding whose citation does not match the recipe no longer makes the AI review, and so the whole review, `incomplete` (`ai_evidence`). The finding is kept: the citations that do not match are dropped, its `rule_id` is `AI-UNVERIFIED-` and its position (`AI-UNVERIFIED-002`), `source` stays `ai`, and its message starts with "The citation the model gave for this could not be verified against the recipe." A model's `block` becomes `review` when its citation cannot be verified; `review` and `info` are unchanged. A clean recipe with one misquoted model finding is now `manual_review` instead of `incomplete`. Evidence of the wrong shape, exceeded limits, a wrong snapshot digest and every other AI failure still make the review `incomplete`. An evidence path longer than 4,096 bytes or a quote longer than 2,048 bytes is now reported as `ai_opinion_bounds` instead of `ai_evidence`. See [the AI protocol](docs/ai-protocol.md#http-request-and-shared-opinion-schema).

## 0.3.0 - 2026-11-22

The first tagged release. It also contains the changes listed under 0.2.0, which was never tagged or published.

### Added

- Every report carries a grade, `risk`, for the review and for each finding: `low`, `medium`, `high`, `critical`, or `unknown` when the review is incomplete. The text report prints it as advice: "Looks fine", "Check first", "Be careful", "Do not install", "Could not check". It is computed from the rules. A finding's grade can depend on the line it matched, not only on its rule. A model's `review` finding is `medium` whatever grade or rule name it carries, and cannot lower the grade. The sentences behind the advice describe the recipe's findings: `low` means that no rule asked for a decision; it is not an assessment of the software. See [rules and severities](docs/rules.md#advice).
- Rules for high-risk behaviour. `REVERSE-SHELL` blocks. `RAW-SOCKET`, `SETUID`, `PRIVILEGE-CONFIG`, `STARTUP-FILE`, `CREDENTIAL-STORE`, `DROP-HOST`, `NUMERIC-HOST`, `PACKAGE-MANAGER`, `DISABLE-PROTECTION`, `DESTRUCTIVE`, `BUILD-DOWNLOAD`, `OUTSIDE-WRITE`, `INSTALL-DOWNLOAD`, `INSTALL-WRITE`, `PACKAGE-TRUST`, `ACCOUNT`, `SCRIPT-DOWNLOAD` and `PIPED-SHELL` need review. `INSTALL-SERVICE`, `SANDBOX-HELPER` and `PRELOAD` are informational. See [rules and severities](docs/rules.md). Among them:
  - `BUILD-DOWNLOAD` and `SCRIPT-DOWNLOAD` are `high` when what is downloaded is run: an interpreter one-liner that fetches, a download piped into or substituted for a shell or an interpreter, or the saved file (`-o NAME`, `-O`, `> NAME`, wget's default name) run on the same or a later line of the file by a shell, an interpreter, `./NAME`, `source` or `chmod +x`. A plain download, or a tarball that is unpacked and built, is `medium`.
  - `OUTSIDE-WRITE` includes a write into `~` or `$HOME`, and is `high` when the target is under `/home`, `/root` or `~`. `STARTUP-FILE` covers any user's `.ssh/authorized_keys`, including `~user/`.
  - `SETUID` finds modes written with a leading zero, with `=`, or as `--mode=`. It is `high` for setuid and for capabilities, and `medium` for setgid without setuid on a file and for `setcap` whose only capability is `cap_net_bind_service`. A directory created setgid, and `setcap -r`, which removes capabilities, are not reported.
  - The sandbox-helper note needs every file of the command to be named as a helper and none to be in a `bin` directory.
  - `DROP-HOST` needs the host to appear as a host. `NUMERIC-HOST` is `high` and ignores private networks.
- AI findings can have severity `info`. Such a finding is listed and does not change the decision. The instructions sent to the model now say what each severity is for, so a remark about packaging style no longer asks for a manual review.
- An image (PNG, JPEG, GIF, WebP, ICO), a PDF or a binary OpenPGP key no longer makes the review `incomplete`. It is recognised by how it starts; any other file that is not text is refused as before. Files that have to be text to be reviewed (the PKGBUILD, install scripts, patches, anything with a `#!` line, and others listed in [rules and severities](docs/rules.md#files-that-are-not-text)) are refused as before when they are not. An accepted file is never read by a rule or sent to a model: its hash is part of the snapshot digest, it is listed in `coverage.uninspected` and in `files` with `"opaque": true`, a changed file is reported in `changes`, and an `OPAQUE-FILE` finding names its format.
  - `OPAQUE-FILE` is `info` when the baseline has the same bytes, or when the recipe only copies the file into place by name: `install`, `cp`, `ln` or `mv` with no executable mode, not where `OPAQUE-RUN` looks, to a directory, to its own name or to a name with an extension of its format, and perhaps listed in `source`, `noextract` or a checksum array. A recipe that ships only an icon or a licence PDF this way is `no_findings` and "Looks fine".
  - Any other use of a new or changed file needs review: a script that names it in another way (`cat`, `tail`, `dd`, `bsdtar`, `base64`, a variable, a copy to `x.tar` or `helper`), with that line as evidence; another text file, such as a unit or a `.desktop` file, that names it; or no script that copies it by name. A copy under a new name of the same kind is followed: what is done with `plugin.png` after `install -Dm644 logo.png …/plugin.png` counts as done with `logo.png`, two renames deep.
  - `OPAQUE-RUN` reports a recipe that runs such a file, and blocks one that names it in `install=`.

### Changed

- The snapshot digest of a checkout that contains only text files is unchanged. A checkout with a file that is not text had no digest before.
- `PackageFile`, `FileSummary` and `Coverage` have new public fields (`opaque`, `size`, `format`, `uninspected`). Code that builds these structs by hand needs them; code that parses reports does not.
- `.SRCINFO` is no longer inspected for commands. It repeats the PKGBUILD and makepkg does not read it.
- `PROMPT-INJECTION` looks only at the scripts and `.SRCINFO`, comments included. A prompt in a data file the package ships (`*.txt`, `*.md`, `*.json`, `*.yaml`, `*.toml`), such as the system prompt of an AI tool, is content and is not reported.
- `PLAIN-HTTP` and `DYNAMIC-EVAL` apply to shell that runs (the PKGBUILD, install scripts, `*.sh`, files with a `#!` line), not to patches, licence texts or images. The homepage in `url=` and XML namespaces are not reported. An `http://` source with a SHA-2 or BLAKE2 checksum is `info`.
- A skipped checksum is judged by its source. A version-control source and a file verified by a pinned PGP signature are `info`; a signature file is not reported; anything else needs review as before. `SKIP` items in arrays that span lines are now found.
- A line that matches a blocking rule is reported for that rule alone.
- `REMOTE-SHELL` also blocks a download handed to a shell by process or command substitution (`sh <(curl …)`, `sh -c "$(curl …)"`, `eval "$(curl …)"`) and a shell named by path or run through `sudo`. `ENCODED-SHELL` also blocks decompressed or reversed content piped into a shell.
- `PRIVILEGE` applies to commands in scripts. The word `sudo` in a dependency list, a description, printed advice, release notes or a patch is no longer reported. `su` with an option is.
- Rules about a command find it after a path, a `NAME=value` setting, `!`, a subshell, a `case` arm or `-c "…"`, and no longer take the items of an array for commands.
- Printed advice is recognised by following the quoting: a message that spans lines, a `>` inside a quoted message, and notes printed with `cat <<EOF` are text. A blocked command that only appears in printed advice needs review instead of blocking.

### Fixed

- A test ran `scan` without `--no-ai`, so it used the saved AI connection of whoever ran the tests.
- Rules no longer skip a line just because it begins with `#`. Such a line is not a comment to the shell when it starts inside a string that spans lines, inside a here-document, after a backslash-newline, or after a character that is not a space or tab. A command on such a line ran without a finding. A line is now skipped only when it is certainly a comment. In a recipe that uses shell constructs the scanner does not model exactly, text in later comments is inspected too, so a recipe can now get a finding from a comment. A `${…}` outside quotes that contains an empty pair of quotes (`${pkgname//-bin/""}`) is not such a construct.

## 0.2.0 - not released

This version was set in `Cargo.toml` but never tagged or published. Builds from source between these changes and 0.3.0 report it.

### Changed

- Command-line usage errors now exit 64. They exited 2 before, which collided with the `blocked` decision. Decision exit codes 0 to 3 are unchanged, and `--help` and `--version` still exit 0.

### Added

- `aurlens::cli::run` hosts the whole command line in the library, so another Rust binary can expose it under its own name. See [Embed the AURLens CLI](docs/embedding.md).
- `aurlens schema review` and `aurlens schema verify` print the JSON Schema of the version 1 reports. The files are in [`schemas/`](schemas).
- The report types implement `Deserialize` and ignore unknown fields. `Change`, `Coverage`, `Evidence`, `FileSummary`, and `Finding` are also exported from the crate root.

The JSON reports and their `schema_version` are unchanged.
