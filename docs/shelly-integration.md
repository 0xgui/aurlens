# Experimental Shelly integration

The [Shelly 3.2.0 patch](../integrations/shelly/shelly-3.2.0.patch) adds AURLens gates to the shared AUR manager. It is a development patch, not an installed extension. The normal Shelly binary and GUI do not automatically run AURLens.

Keeping ordinary Shelly use and package updates unchanged is a delivery requirement. This patch proves the protocol and hook placement in an isolated copy. Daily use must not depend on maintaining a patched Shelly fork. Automatic scanning in stock Shelly needs upstream hook support, which was absent in the reviewed 3.2.0 source.

## Review and execution boundaries

The adapter runs `aurlens scan CHECKOUT --json` at `requirePkgbuildApproval`. Review findings join Shelly's existing approval payload. Blocked and incomplete results abort the operation. An explicitly configured AI backend must finish successfully. It cannot silently fall back to static analysis.

After acceptance, the operation-local approval stores AURLens's digest separately from Shelly's digest. Cached approvals run `aurlens verify` before reuse. `verifyPreparedPackage` checks the AURLens binding before build dispatch. `generateReviewedSrcinfoUsing` also enforces approval before dependency metadata or version evaluation, where top-level PKGBUILD code can first execute.

The manager gates precede native, child-command, makepkg, chroot, and isolated build dispatch. Each AUR dependency entering this manager gets its own review. Controlled PKGBUILD version edits invalidate the external binding. No external approval is inherited across changed recipe bytes.

In-process metadata, native builds, Shelly child builds, and makepkg use a shared output owner. Work, source-cache, package, and log paths sit outside the reviewed recipe. Dependency metadata is checked again before it returns. Successful builds verify the complete recipe again before returning archives for installation. Undeclared recipe writes therefore fail these return boundaries.

Child commands receive internal destination arguments without broadening their clean user environment. Review, metadata, source-key, and version helpers keep host outputs external; isolated guest arguments omit those host paths. Makepkg receives destination environment variables while retaining its normal policy loading. Archive selection reads the effective package destination, including uncompressed `.pkg.tar` packages.

The patch does not cover standalone `shelly build`, official repository package hooks, remote downloads, or commands that bypass this AUR manager. It does not supply an old checkout for `--baseline`. GUI configuration-path transport has a focused test; interactive GUI rendering still needs verification.

## Configuration

Run `aurlens setup` once. The hook reads the private `[shelly]` preferences from the same user configuration file as the AI connection. It passes that file explicitly to AURLens and requires the configured AI review to complete. Run `aurlens setup --disable-shelly` to turn off automatic review without changing the connection used by manual scans.

Settings must be a regular file owned by the invoking user with no group or other permissions. The loader rejects symlinks, oversized files, unsupported settings, and relative executable paths. A custom absolute `XDG_CONFIG_HOME` is preserved through Shelly's existing GUI elevation frame. No credentials are added to that frame.

For development without saved Shelly preferences, set `SHELLY_AURLENS` to an absolute trusted AURLens executable path. Omission disables the experiment. An empty or relative value fails. Set `SHELLY_AURLENS_CONFIG` to an absolute trusted AI configuration path to require AI review. Saved disabled preferences take precedence over these variables. The existing AURLens rules reject configuration inside the reviewed checkout.

These development variables must reach the manager process; a launcher may remove them. User preferences are not a system-wide enforcement policy.

The adapter starts an argv process as the invoking user. It uses Shelly's bounded process runner with a 120-second scan timeout and a 30-second verification timeout. It accepts reports up to 4 MiB after the runner's 16 MiB stream limits. Missing executables, timeouts, invalid JSON, unsupported versions or coverage, mismatched exit codes, incomplete requested AI, and changed files stop the operation.

The [adapter module](../integrations/shelly/aurlens.zig) validates the protocol. Shelly owns approval and execution timing. Rust owns traversal and hashing. The tools do not compare their different digest formats.

## Run the native verification

Use an unmodified checkout of [Shelly v3.2.0](https://github.com/Seafoam-Labs/Shelly-ALPM/tree/v3.2.0), Zig 0.17.0, makepkg with fakeroot, and the native development libraries required by Shelly, including libalpm. Build AURLens first:

```sh
cargo build --locked --release
ZIG=/absolute/path/to/zig integrations/shelly/verify.sh \
    /path/to/Shelly-ALPM-3.2.0 "$PWD/target/release/aurlens" /tmp/aurlens-shelly-evidence
```

The evidence directory must not exist. The driver checks the original hashes of the patched files, copies the source into a private directory, applies the patch, and adds the integration modules. It builds a private Shelly CLI, runs its builder and isolated-configuration tests, then runs the protocol tests, the focused `aurlens-test` target, and Shelly's broader `aur-test` target. Manager fixtures use the real AURLens binary, the newly built child CLI, and makepkg. Pinned Zig dependencies may require network access on the first run. Existing upstream signing tests require local GPG-agent sockets. Makepkg needs fakeroot IPC. No fixture installs packages into the host.

The focused tests check complete scan and verification responses, status disagreement, unsupported coverage, requested AI completeness, changed helpers on cached approvals, all five build dispatch choices, independent dependency review, blocked and binary inputs before metadata evaluation, and manual finding presentation and rejection. They also run repeated real in-process metadata and native prepare, build, check, and package functions, then inspect archive contents and metadata. Child CLI builds exercise real metadata and repeated builds. Makepkg builds check loaded compiler flags, packager, archive format, and payload. All three available build paths reject undeclared recipe writes before returning results. A non-Git local recipe exercises its actual constructor and repeated metadata path. Source mutations, configured destination aliases, failure, cancellation, and cleanup are checked. Dependency discovery itself is not an end-to-end install test.

Upstream fixtures build packages in private directories. They do not install those packages into the system. The driver retains logs and executable hashes, removes its copied source, and writes `summary.json` only after all checks pass. It never replaces the installed Shelly.

## Limits of this experiment

Whole-checkout coverage includes hidden and untracked helpers, empty directories, modes, `src`, and `pkg`. Binary outputs, links, unsupported text, and exceeded limits cause an incomplete review. The adapter neither hides generated files nor deletes them to get a passing scan.

For reviewed in-process operations, default generated files live under `<cache_root>/.reviewed-outputs/<package>-<random>/`. Each prepared package owns this allocation, and each metadata or build call gets a fresh work directory. Archives survive until their install consumer finishes. Destroying the prepared package removes its owned output tree. Explicit configured package and log destinations remain untouched. Configured destinations equal to, inside, or containing the recipe, including symlink aliases, are rejected before creation.

Abrupt process termination can leave owned scratch directories. The patch does not yet provide crash-recovery cleanup. Existing dirty recipe caches still fail review; they are never cleaned or excluded automatically.

Real command and makepkg builds have been exercised. Chroot destination mapping and isolated host/guest argument transport have code and transport tests, but successful real chroot and isolated builds remain unverified. The driver does not claim that a fake coordinator exit proves either mode. Controlled `pkgver` changes still need a complete re-review workflow. These gaps prevent this patch from being suitable for daily installs and updates across all modes.

Shelly's existing build-policy parent/child configuration path mismatch under elevation remains unresolved: the parent ignores `XDG_CONFIG_HOME` when elevation markers exist, while a clean child removes those markers and can preserve that variable. Destination overrides retain the policy each child loads, but do not prove it is identical to the parent's policy. AURLens's own settings use the invoking user's absolute configuration path independently.

A process-external digest check also leaves a race before later filesystem reads. It does not freeze the checkout against a concurrent writer. Immutable execution inputs or operating-system isolation are needed for that stronger guarantee.
