# Rules and severities

Every finding has one of three severities. The severity is the whole policy: it decides whether a person is asked anything.

| Severity | Meaning | Effect on the decision |
| --- | --- | --- |
| `block` | Behaviour with no honest use in a package recipe. | `blocked` |
| `review` | A concrete security risk that a person has to decide about. | `manual_review` |
| `info` | Worth a line in the report. | None. The finding is listed and the decision is unchanged. |

## Advice

Every report also carries one word of advice, `risk` in the JSON. The decision says what has to happen; the advice says how hard to look.

| Advice | `risk` | When | Decision |
| --- | --- | --- | --- |
| Looks fine | `low` | Nothing found, or notes only. | `no_findings` |
| Check first | `medium` | A `review` finding of a kind legitimate recipes also have: an unverified or unencrypted download, a download during the build, `eval`, a file nobody read, a model's opinion. | `manual_review` |
| Be careful | `high` | A `review` finding that gives the package root-level or lasting power, reaches for credentials, or hides what runs. Marked **high** in the table below. | `manual_review` |
| Do not install | `critical` | A `block` finding. | `blocked` |
| Could not check | `unknown` | The review is incomplete. | `incomplete` |

The review's advice is the highest among its findings, and each finding carries its own `risk`. A model's `review` finding is always `medium`: it is an opinion, and when a model thinks something has no honest use it says `block`. A model cannot lower the advice.

"Looks fine" is about the recipe. It says nothing about the software the recipe downloads, which no rule reads.

Rules are text patterns over one line. They do not parse or run shell, so they can be evaded and they can match harmless text. [The threat model](threat-model.md) states the limits.

## Where a rule looks

- **Code**: every text file except `.SRCINFO`. That file is generated from the PKGBUILD and makepkg does not read it, so inspecting it for commands would only repeat the PKGBUILD's findings.
- **Scripts**: the PKGBUILD, `*.install`, `*.sh`, `*.bash`, and any file that starts with `#!`. Patches, licence texts and images are not scripts: a URL or the word `eval` in them is content, not a command.
- **Recipe**: the PKGBUILD, which runs while the package is built.
- **Install script**: `*.install`, which pacman runs as root when the package is installed, upgraded or removed.
- **Helper**: the other scripts: what the recipe ships or runs.
- **Everything**: every text file, `.SRCINFO` included.

Whole-line shell comments are skipped unless the rule says otherwise.

### Printed text

A rule marked **commands** in the tables skips a line that only prints text, such as `echo "now run: pacman -S foo"`. A line is printed text when:

- its first word is `echo`, `printf`, `msg`, `msg2`, `warning`, `error` or `plain`, or it continues a quoted message that such a line left open; and
- outside quotes it has none of `|`, `` ` ``, `>`, `<`, `;`, `&`, `(`, `)`; and
- it has no `$(…)`, no backtick, no `$'…'` string and no `${…}` with quoting inside; and
- it does not end in a backslash that joins it to the next line.

Inside quotes `>` is a character, so `echo "==> add this to ~/.bashrc"` is printed text and `echo x >> ~/.bashrc` is not. A comment after the message ends the line: a quote character in it opens nothing. Anything this cannot read with certainty is treated as an ordinary line, and a message that spans lines and ends on a line that does more than print (`" | sh`) is not printed text on any of its lines.

The body of a here-document that `cat` prints (`cat <<'EOF'`, to the terminal or to standard error) is printed text too, line by line, unless the line has a `$(…)` or a backtick. A here-document that is written to a file, piped on, or handed to anything other than `cat` is not.

If any file of the checkout gives one of the printing commands another meaning (`msg() { "$@"; }`, `alias echo=…`), no line of the checkout is treated as printed text.

A `block` rule that matches printed text is reported as `review`, with a message that says so: advice such as "to install, run `curl … | sh`" is not that command being run, and it is still something a person should see. This holds only where nothing in the checkout could run text it is handed: with a pipe into a shell, `eval`, `source` or `.`, a shell's `-c`, `<<<` or `xargs` anywhere in it, the match blocks as usual.

A message printed inside a subshell or function whose output is piped elsewhere is still taken for a message: the rules read one line at a time.

### Where a command starts

A rule marked **command start** matches a program only where the shell would run it: at the start of a line; after `;`, `&`, `|`, `{`, a backtick, `$(`, `<(`, a subshell's `(` or a `case` arm's `)`; as the string given to `-c` or `trap`; or after `if`, `then`, `do`, `else`, `elif`, `while`, `until`, `!`, `exec`, `eval`, `time`, `command`, `env`, `nice`, `nohup`, `timeout`, `xargs`, `sudo`, `doas`, `pkexec` or `run0`. `NAME=value` settings and a directory such as `/usr/bin/` may come before the program.

Two kinds of line have no command in them and are skipped by these rules:

- A line that is nothing but an array or part of one: `makedepends=(curl)`, or `curl` on a line of its own inside `makedepends=(` … `)`. A line with `;`, `|`, `&`, `<`, a backtick or `$(` on it, or with anything after the closing `)`, is not such a line. Neither is the body of a here-document, nor any line after a construct whose quoting the scanner does not follow.
- A line that gives a variable one word of text: `pkgdesc="Download tool (wget replacement)"`. A second word (`pkgdesc="x" curl …`) is a command, and so is a substitution.

A line that matches a `block` rule is reported for that rule alone.

## Block

| Rule | Looks in | Matches |
| --- | --- | --- |
| `REMOTE-SHELL` | Code | A download piped into a shell, or handed to one as `sh <(curl …)`, `sh -c "$(curl …)"`, `source <(…)` or `eval "$(…)"`. The shell may be named by path or run through `sudo`. |
| `ENCODED-SHELL` | Code | Decoded or decompressed content piped into a shell (`base64`, `base32`, `xxd`, `openssl`, `gunzip`, `zcat`, `xz -d`, `rev` and the like). |
| `KNOWN-PAYLOAD` | Code | A package name used in known AUR malware campaigns. |
| `PRIVATE-KEY` | Code | A path to SSH, AWS or GnuPG private key material. |
| `REVERSE-SHELL` | Code | A shell connected to a network socket (`sh -i` with `/dev/tcp`, `nc -e`, `nc -c /bin/sh`, `socat … exec:`). |

## Review

A rule marked **High** gives the advice "Be careful"; the others give "Check first". A `block` rule that matches printed text (see above) is reported here as high.

| Rule | Looks in | Matches |
| --- | --- | --- |
| `DYNAMIC-EVAL` | Scripts | `eval`. |
| `PIPED-SHELL` | Scripts | **High.** Anything else piped into a shell: a `|` with a space on either side of it, then a shell's name as a word. `bash|zsh)` in a `case` and `"bash|sh"` in a pattern are not pipes. |
| `PRIVILEGE` | Scripts, commands, command start | **High.** `sudo`, `doas`, `pkexec`, `run0`, or `su` with an option. |
| `SKIPPED-CHECKSUM` | Recipe | A `SKIP` checksum for a source that nothing else verifies. See below. |
| `PLAIN-HTTP` | Scripts, commands | An `http://` URL. Not in `url=` or `pkgdesc=`, not an XML namespace, not the local machine. |
| `PROMPT-INJECTION` | Everything, comments included | **High.** Text addressed to an AI reviewer. |
| `RAW-SOCKET` | Code | **High.** A connection through the shell's `/dev/tcp` or `/dev/udp`. |
| `SETUID` | Code | **High.** `chmod` with a setuid or setgid mode, in octal (`4755`, `04755`) or symbols (`u+s`, `u=rwxs`); `install` with such a mode (`-m4755`, `--mode=4755`); `setcap`. Not a directory created setgid, and not `g+s` on a directory under `/var`. |
| `PRIVILEGE-CONFIG` | Code | **High.** sudoers, `doas.conf`, PAM or polkit rules. |
| `STARTUP-FILE` | Code, commands | **High.** A user's shell startup or autostart file, or `/etc/ld.so.preload`. |
| `CREDENTIAL-STORE` | Code, commands | **High.** Where browsers, password managers and developer tools keep credentials. |
| `DROP-HOST` | Code | **High.** A paste, file-drop, webhook or tunnel service, as a host: after `://`, or followed by `/`. A file called `temp.sh` is not the host. |
| `NUMERIC-HOST` | Code | A URL with a numeric address. Not the local machine or a private network. |
| `PACKAGE-MANAGER` | Scripts, commands, command start | **High.** pacman or an AUR helper installing, upgrading or removing. Not a query that changes nothing (`-Si`, `-Ss`, `-Q…`); `-Syi` refreshes the databases and is reported. |
| `PACKAGE-TRUST` | Scripts, commands | **High.** `pacman-key` adding, importing or signing keys; `/etc/pacman.conf`, `/etc/pacman.d/` (not a file placed under `$pkgdir`); `SigLevel`. |
| `ACCOUNT` | Scripts, commands | **High.** An account added to `wheel`, `sudo`, `root`, `adm` or `docker`; a user created with uid 0 or a duplicate uid; `chpasswd`; `passwd` run as a command (`getent passwd name` is a lookup). |
| `DISABLE-PROTECTION` | Code, commands | **High.** A firewall, SELinux, AppArmor, auditing or a kernel hardening setting switched off. |
| `DESTRUCTIVE` | Scripts, commands, command start | **High.** `rm` with options aimed at `/`, a top-level system directory or a home directory; `dd` onto a disk; `mkfs`, `wipefs`, `shred`. |
| `BUILD-DOWNLOAD` | Recipe, commands, command start | `curl`, `wget` or `aria2c`; `git clone` of a URL; an interpreter's one-liner that names a URL or `urlopen`. |
| `OUTSIDE-WRITE` | Recipe, commands | A redirect or `tee` into a system directory instead of the package directory. Not the body of a here-document that `cat` or `tee` writes to a file. |
| `INSTALL-DOWNLOAD` | Install script, commands, command start | **High.** A download, or a language package manager, run as root at install time. |
| `INSTALL-WRITE` | Install script, commands | **High.** A redirect, `tee` or `sed -i` into `/etc`, `/usr`, `/root` or `/boot`; standard output redirected to a path held in a variable; `cp`, `mv`, `ln` or `install` into the places that are read at login, at boot or by pacman (`/etc/profile.d`, udev rules, cron, `ld.so.conf`, ssh, alpm hooks, `/root/.ssh`); `authorized_keys`; `sshd_config`. |
| `SCRIPT-DOWNLOAD` | Helper, commands, command start | `curl`, `wget` or `aria2c` in a script that comes with the recipe. |
| `OPAQUE-FILE` | The checkout | An image, a PDF or a binary key, when it is new or has changed since the baseline. |
| `OPAQUE-RUN` | Scripts | **High.** Such a file handed to an interpreter, sourced, made executable, installed with an executable mode, or installed into a `bin` directory, under a script or settings name, or where the system reads scripts and settings (`profile.d`, alpm hooks, systemd, udev, cron). Piped into a shell, or named by `install=`, it blocks. |

## Info

| Rule | Looks in | Matches |
| --- | --- | --- |
| `SKIPPED-CHECKSUM` | Recipe | A `SKIP` checksum for a version-control source, for a file verified by a pinned PGP signature, or for a file of the checkout itself. |
| `PLAIN-HTTP` | Recipe | An `http://` source that has a SHA-2 or BLAKE2 checksum in the same position. |
| `OPAQUE-FILE` | The checkout | An image, a PDF or a binary key that is byte for byte the file of the baseline. |
| `SANDBOX-HELPER` | Code | A Chromium sandbox helper made setuid root. See below. |
| `INSTALL-SERVICE` | Install script, commands, command start | `systemctl` enabling, starting or stopping a service, or a unit linked into a `.wants` directory by hand. |
| `PRELOAD` | Code | `LD_PRELOAD=`. |

### The sandbox helper

Chromium-based applications ship a helper that must be setuid root. A command that sets a privilege bit is a `SANDBOX-HELPER` note instead of a `SETUID` finding when every file it names is called `…-sandbox` or `…_sandbox` and none is in a `bin` directory. `setcap` never qualifies. The name is all there is to go by: a different program installed under that name inside an application's own directory would be a note too.

## Files that are not text

A recipe has reason to carry a few kinds of file that are not text: an icon, a licence as a PDF, a binary OpenPGP key. A file is accepted as one of these only when it starts the way that format starts (PNG, JPEG, GIF, WebP, ICO, PDF, an OpenPGP public key) and is not mostly readable text behind that start. It is then kept by its hash and listed in `coverage.uninspected`. No rule reads it and no model receives it.

- `OPAQUE-FILE` names the format and asks for a decision when the file is new to the reader or its bytes changed. It is a note when the baseline has the same file.
- `OPAQUE-RUN` looks at what the scripts of the recipe do with such a file. If `install=` names it, or cannot be read while such a file is present, the review does not pass without a person, and a file named by `install=` blocks.

Every other file that is not text makes the review `incomplete`, as it always did: a text file with a stray byte, an archive, a program. So does any file that has to be text to be reviewed at all, whatever it starts with: the PKGBUILD, `.SRCINFO`, `*.install`, `*.sh`, `*.bash`, `*.zsh`, `*.py`, `*.pl`, `*.rb`, `*.lua`, `*.js`, `*.patch`, `*.diff`, `*.desktop`, `*.conf`, `*.hook`, `*.rules`, systemd units, anything below a directory named `.git`, and any file that starts with `#!`.

Accepting a format by how it starts is not proof of what the rest is: a file can start as a PNG and carry a script behind enough padding. What stops such a file from mattering is that nothing in the recipe may run it unseen: the hash binds its bytes to the review, and a later change to them asks again. A recipe that reaches it in a way the patterns miss is the same risk as a download in `source=`, which is never inspected either.

## What the rules do not see

The rules read one line at a time and do not run or parse shell. Known gaps:

- A function of the recipe's own that runs its arguments (`run() { "$@"; }`, then `run usermod …`): the command is not at a command start. Only the printing commands are checked for another meaning.
- A path or command assembled from pieces (`/etc/sud""oers.d`, `c=cu; ${c}rl …`) is not recognised. A write as root to a path held in a variable is the one case caught.
- What a downloaded source does when it is built or run. That is true of every package.
- A file the package ships (a unit, a udev rule, an alpm hook, a `profile.d` script) is not a finding by itself: it is in the package's file list, and its text is in the review if it is in the checkout.
- `git clone` of a location held in a variable, and downloads made by a build system (`cargo`, `npm`, `go`) rather than by the recipe.

## Skipped checksums

A `SKIP` in a checksum array of the PKGBUILD is judged by the source in the same position of the matching `source` array (`sha256sums_x86_64` pairs with `source_x86_64`). Arrays may span lines, and `name{,.sig}` is expanded as the shell would.

- The source is a signature file (`.sig`, `.asc`, `.sign`): not reported. The signature is the check.
- The source is a version-control URL (`git+…`, `svn+…`, `hg+…`, `bzr+…`, `fossil+…`): `info`. Such a source cannot have a checksum.
- The source's signature file is also a source and `validpgpkeys` is not empty: `info`. makepkg verifies the file against the pinned key.
- The source is a file of the checkout itself: `info`. The snapshot covers it.
- Anything else, including a `SKIP` that cannot be paired with a source or is written some other way: `review`.

A checksum set by position (`sha256sums[4]='SKIP'`) is judged by the source at that position. A signature is recognised by the name it is saved under (`x.sig::https://…/x.gpg`) as well as by its location, and a source that is a single variable is read through to its assignment.

## AI findings

A model can add findings at any of the three severities and cannot change or remove a finding from a rule. Its instructions reserve `review` for a concrete security risk and `block` for behaviour with no honest use; packaging style and facts true of every source build are `info` or left out. See [the AI protocol](ai-protocol.md).

Because a model's `info` finding does not change the decision, a recipe written to talk the model down can at worst silence the model. The rules are unaffected, which is the reason the high-risk behaviours above are rules.
