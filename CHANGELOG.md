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
- An image, a PDF or a binary key that the recipe only copies into place by name is an `info` finding even when it is new or changed: `install`, `cp`, `ln` or `mv` with no executable mode, not where `OPAQUE-RUN` looks, to a directory, to its own name or to a name with an extension of its format, and perhaps listed in `source`, `noextract` or a checksum array. A recipe that ships only an icon or a licence PDF this way is `no_findings` and "Looks fine" instead of "Check first". `OPAQUE-FILE` is still `review` when a script names the file in any other way (`cat`, `tail`, `dd`, `bsdtar`, `base64`, a variable, a copy to `x.tar` or `helper`), with that line as evidence; when another text file such as a unit or a `.desktop` file names it; and when no script copies it by name. A copy under a new name of the same kind is followed: what is done with `plugin.png` after `install -Dm644 logo.png …/plugin.png` counts as done with `logo.png`, two renames deep. The file is still listed as uninspected, bound into the snapshot digest and reported in `changes`.
- A finding's grade can depend on the line it matched, not only on its rule. A model's `review` finding stays `medium` whatever grade or rule name it carries.
- `BUILD-DOWNLOAD` and `SCRIPT-DOWNLOAD` are `high` when what is downloaded is run: an interpreter one-liner that fetches, a download piped into or substituted for a shell or an interpreter, or the saved file (`-o NAME`, `-O`, `> NAME`, wget's default name) run on the same or a later line of the file by a shell, an interpreter, `./NAME`, `source` or `chmod +x`. A plain download, or a tarball that is unpacked and built, stays `medium`.
- `OUTSIDE-WRITE` also reports a write into `~` or `$HOME`, and is `high` when the target is under `/home`, `/root` or `~`. `STARTUP-FILE` also covers any user's `.ssh/authorized_keys`, including `~user/`.
- `PROMPT-INJECTION` looks only at the scripts and `.SRCINFO`, comments included. A prompt in a data file the package ships (`*.txt`, `*.md`, `*.json`, `*.yaml`, `*.toml`), such as the system prompt of an AI tool, is content and is not reported.
- `NUMERIC-HOST` is `high`.
- `SETUID` is `medium` for setgid without setuid on a file and for `setcap` whose only capability is `cap_net_bind_service`; setuid and other capabilities stay `high`. `setcap -r`, which removes capabilities, is not reported.
- The sentences behind the advice describe the recipe's findings. `low` means that no rule asked for a decision; it is not an assessment of the software. The five advice labels are unchanged.
- A `${…}` outside quotes that contains an empty pair of quotes (`${pkgname//-bin/""}`) no longer stops the scanner from trusting later comments.

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
