# Rules and severities

Every finding has one of three severities. The severity is the whole policy: it decides whether a person is asked anything.

| Severity | Meaning | Effect on the decision |
| --- | --- | --- |
| `block` | Behaviour with no honest use in a package recipe. | `blocked` |
| `review` | A concrete security risk that a person has to decide about. | `manual_review` |
| `info` | Worth a line in the report. | None. The finding is listed and the decision is unchanged. |

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

- its first word is `echo`, `printf`, `msg`, `msg2`, `warning`, `error`, `plain` or `note`, or it continues a quoted message that such a line left open; and
- outside quotes it has none of `|`, `` ` ``, `>`, `<`, `;`, `&`, `(`, `)`; and
- it has no `$(…)`, no backtick, no `$'…'` string and no `${…}` with quoting inside; and
- it does not end in a backslash that joins it to the next line.

Inside quotes `>` is a character, so `echo "==> add this to ~/.bashrc"` is printed text and `echo x >> ~/.bashrc` is not. Anything this cannot read with certainty is treated as an ordinary line. A message printed inside a subshell or function whose output is piped elsewhere is still taken for a message: the rules read one line at a time.

### Where a command starts

A rule marked **command start** matches a program only where the shell would run it: at the start of a line; after `;`, `&`, `|`, `{`, a backtick, `$(`, `<(`, a subshell's `(` or a `case` arm's `)`; as the string given to `-c`; or after `if`, `then`, `do`, `else`, `elif`, `while`, `until`, `!`, `exec`, `eval`, `time`, `command`, `env`, `nice`, `nohup`, `sudo`, `doas`, `pkexec` or `run0`. `NAME=value` settings and a directory such as `/usr/bin/` may come before the program. The items of an array (`makedepends=(curl)`, on one line or several) are names, not commands.

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

| Rule | Looks in | Matches |
| --- | --- | --- |
| `DYNAMIC-EVAL` | Scripts | `eval`. |
| `PIPED-SHELL` | Scripts | Anything else piped into a shell. |
| `PRIVILEGE` | Scripts, commands, command start | `sudo`, `doas`, `pkexec`, `run0`, or `su` with an option. |
| `SKIPPED-CHECKSUM` | Recipe | A `SKIP` checksum for a source that nothing else verifies. See below. |
| `PLAIN-HTTP` | Scripts, commands | An `http://` URL. Not in `url=` or `pkgdesc=`, not an XML namespace, not the local machine. |
| `PROMPT-INJECTION` | Everything, comments included | Text addressed to an AI reviewer. |
| `RAW-SOCKET` | Code | A connection through the shell's `/dev/tcp` or `/dev/udp`. |
| `SETUID` | Code | `chmod` with a setuid or setgid mode, in octal (`4755`, `04755`) or symbols (`u+s`, `u=rwxs`); `install` with such a mode (`-m4755`, `--mode=4755`); `setcap`. Not a directory created setgid, and not `g+s` on a directory under `/var`. |
| `PRIVILEGE-CONFIG` | Code | sudoers, `doas.conf`, PAM or polkit rules. |
| `STARTUP-FILE` | Code, commands | A user's shell startup or autostart file, or `/etc/ld.so.preload`. |
| `CREDENTIAL-STORE` | Code, commands | Where browsers, password managers and developer tools keep credentials. |
| `DROP-HOST` | Code | A paste, file-drop, webhook or tunnel service, as a host: after `://`, or followed by `/`. A file called `temp.sh` is not the host. |
| `NUMERIC-HOST` | Code | A URL with a numeric address. Not the local machine or a private network. |
| `PACKAGE-MANAGER` | Code, commands, command start | pacman or an AUR helper installing, upgrading or removing. Not a query (`-Si`, `-Ss`, `-Q…`). |
| `PACKAGE-TRUST` | Scripts, commands | `pacman-key` adding, importing or signing keys; `/etc/pacman.conf`, `/etc/pacman.d/`; `SigLevel`. |
| `ACCOUNT` | Scripts, commands | An account added to `wheel`, `sudo`, `root`, `adm` or `docker`; a user created with uid 0 or a duplicate uid; `chpasswd`; `passwd`. |
| `DISABLE-PROTECTION` | Code, commands | A firewall, SELinux, AppArmor, auditing or a kernel hardening setting switched off. |
| `DESTRUCTIVE` | Code, commands, command start | `rm` with options aimed at `/`, a top-level system directory or a home directory; `dd` onto a disk; `mkfs`, `wipefs`, `shred`. |
| `BUILD-DOWNLOAD` | Recipe, commands, command start | `curl`, `wget` or `aria2c`; `git clone` of a URL; an interpreter's one-liner that names a URL or `urlopen`. |
| `OUTSIDE-WRITE` | Recipe, commands | A redirect or `tee` into a system directory instead of the package directory. Not the body of a here-document that `cat` or `tee` writes to a file. |
| `INSTALL-DOWNLOAD` | Install script, commands, command start | A download, or a language package manager, run as root at install time. |
| `INSTALL-WRITE` | Install script, commands | A redirect, `tee` or `sed -i` into `/etc`, `/usr`, `/root` or `/boot`, or to a path held in a variable; `cp`, `mv`, `ln` or `install` into the places that are read at login, at boot or by pacman (`/etc/profile.d`, udev rules, cron, `ld.so.conf`, ssh, alpm hooks, `/root/.ssh`); `authorized_keys`; `sshd_config`. |
| `SCRIPT-DOWNLOAD` | Helper, commands, command start | `curl`, `wget` or `aria2c` in a script that comes with the recipe. |

## Info

| Rule | Looks in | Matches |
| --- | --- | --- |
| `SKIPPED-CHECKSUM` | Recipe | A `SKIP` checksum for a version-control source, for a file verified by a pinned PGP signature, or for a file of the checkout itself. |
| `PLAIN-HTTP` | Recipe | An `http://` source that has a SHA-2 or BLAKE2 checksum in the same position. |
| `SANDBOX-HELPER` | Code | A Chromium sandbox helper made setuid root. See below. |
| `INSTALL-SERVICE` | Install script, commands, command start | `systemctl` enabling, starting or stopping a service, or a unit linked into a `.wants` directory by hand. |
| `PRELOAD` | Code | `LD_PRELOAD=`. |

### The sandbox helper

Chromium-based applications ship a helper that must be setuid root. A command that sets a privilege bit is a `SANDBOX-HELPER` note instead of a `SETUID` finding when every file it names is called `…-sandbox` or `…_sandbox` and none is in a `bin` directory. `setcap` never qualifies. The name is all there is to go by: a different program installed under that name inside an application's own directory would be a note too.

## What the rules do not see

The rules read one line at a time and do not run or parse shell. Known gaps:

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
