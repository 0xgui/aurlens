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
- **Everything**: every text file, `.SRCINFO` included.

Whole-line shell comments are skipped unless the rule says otherwise. A rule about a command being run also skips a line that only prints text (`echo "now run: pacman -S foo"`), unless that line pipes, redirects or substitutes.

A line that matches a `block` rule is reported for that rule alone.

## Block

| Rule | Looks in | Matches |
| --- | --- | --- |
| `REMOTE-SHELL` | Code | A download piped into a shell. |
| `ENCODED-SHELL` | Code | Decoded content piped into a shell. |
| `KNOWN-PAYLOAD` | Code | A package name used in known AUR malware campaigns. |
| `PRIVATE-KEY` | Code | A path to SSH, AWS or GnuPG private key material. |
| `REVERSE-SHELL` | Code | A shell connected to a network socket (`sh -i` with `/dev/tcp`, `nc -e`, `socat … exec:`). |

## Review

| Rule | Looks in | Matches |
| --- | --- | --- |
| `DYNAMIC-EVAL` | Scripts | `eval`. |
| `PRIVILEGE` | Code | `sudo`, `doas`, `pkexec` or `run0`. |
| `SKIPPED-CHECKSUM` | Recipe | A `SKIP` checksum for a source that nothing else verifies. See below. |
| `PLAIN-HTTP` | Scripts | An `http://` URL. Not the homepage in `url=`, and not an XML namespace. |
| `PROMPT-INJECTION` | Everything, comments included | Text addressed to an AI reviewer. |
| `RAW-SOCKET` | Code | A connection through the shell's `/dev/tcp` or `/dev/udp`. |
| `SETUID` | Code | A setuid or setgid mode, or `setcap`. |
| `PRIVILEGE-CONFIG` | Code | sudoers, `doas.conf`, PAM or polkit rules. |
| `STARTUP-FILE` | Code | A user's shell startup or autostart file, or `/etc/ld.so.preload`. |
| `CREDENTIAL-STORE` | Code | Where browsers, password managers and developer tools keep credentials. |
| `DROP-HOST` | Code | A paste, file-drop, webhook or tunnel service. |
| `NUMERIC-HOST` | Code | A URL with a numeric address. Not the loopback address. |
| `PACKAGE-MANAGER` | Code | The recipe running pacman or an AUR helper to install or remove packages. |
| `DISABLE-PROTECTION` | Code | A firewall, SELinux, AppArmor, auditing or a kernel hardening setting switched off. |
| `DESTRUCTIVE` | Code | `rm` aimed at the filesystem root or a home directory. |
| `BUILD-DOWNLOAD` | Recipe | `curl`, `wget` or `aria2c` run as a command during the build. |
| `OUTSIDE-WRITE` | Recipe | A redirect or `tee` into a system directory instead of the package directory. |
| `INSTALL-DOWNLOAD` | Install script | A download or a language package manager run as root at install time. |

## Info

| Rule | Looks in | Matches |
| --- | --- | --- |
| `SKIPPED-CHECKSUM` | Recipe | A `SKIP` checksum for a version-control source, or for a file verified by a pinned PGP signature. |
| `SANDBOX-HELPER` | Code | Chromium's `chrome-sandbox` helper made setuid root. |
| `INSTALL-SERVICE` | Install script | `systemctl` enabling, starting or stopping a service. |
| `PRELOAD` | Code | `LD_PRELOAD=`. |

## Skipped checksums

A `SKIP` in a checksum array of the PKGBUILD is judged by the source in the same position of the matching `source` array (`sha256sums_x86_64` pairs with `source_x86_64`). Arrays may span lines, and `name{,.sig}` is expanded as the shell would.

- The source is a signature file (`.sig`, `.asc`, `.sign`): not reported. The signature is the check.
- The source is a version-control URL (`git+…`, `svn+…`, `hg+…`, `bzr+…`, `fossil+…`): `info`. Such a source cannot have a checksum.
- The source's signature file is also a source and `validpgpkeys` is not empty: `info`. makepkg verifies the file against the pinned key.
- Anything else, including a `SKIP` that cannot be paired with a source or is written some other way: `review`.

## AI findings

A model can add findings at any of the three severities and cannot change or remove a finding from a rule. Its instructions reserve `review` for a concrete security risk and `block` for behaviour with no honest use; packaging style and facts true of every source build are `info` or left out. See [the AI protocol](ai-protocol.md).

Because a model's `info` finding does not change the decision, a recipe written to talk the model down can at worst silence the model. The rules are unaffected, which is the reason the high-risk behaviours above are rules.
