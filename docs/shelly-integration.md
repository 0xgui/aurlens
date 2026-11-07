# Experimental Shelly integration

The [Shelly 3.2.0 patch](../integrations/shelly/shelly-3.2.0.patch) adds AURLens gates to the shared AUR manager. It is a development patch, not an installed extension. The normal Shelly binary and GUI do not automatically run AURLens.

Keeping ordinary Shelly use and package updates unchanged is a delivery requirement. This patch proves the protocol and hook placement in an isolated copy. Daily use must not depend on maintaining a patched Shelly fork. Automatic scanning in stock Shelly needs upstream hook support, which was absent in the reviewed 3.2.0 source.

## Review and execution boundaries

The adapter runs `aurlens scan CHECKOUT --json` at `requirePkgbuildApproval`. Review findings join Shelly's existing approval payload. Blocked and incomplete results abort the operation. An explicitly configured AI backend must finish successfully. It cannot silently fall back to static analysis.

After acceptance, the operation-local approval stores AURLens's digest separately from Shelly's digest. Cached approvals run `aurlens verify` before reuse. `verifyPreparedPackage` checks the AURLens binding before build dispatch. `generateReviewedSrcinfoUsing` also enforces approval before dependency metadata or version evaluation, where top-level PKGBUILD code can first execute.

The manager gates precede native, child-command, makepkg, chroot, and isolated build dispatch. Each AUR dependency entering this manager gets its own review. Controlled PKGBUILD version edits invalidate the external binding. No external approval is inherited across changed recipe bytes.

The patch does not cover standalone `shelly build`, official repository package hooks, remote downloads, or commands that bypass this AUR manager. It does not supply an old checkout for `--baseline`. GUI rendering and preservation of configuration across privilege elevation remain unverified.

## Development configuration

In a patched development build, set `SHELLY_AURLENS` to an absolute trusted AURLens executable path. Omission disables the experiment. An empty or relative value fails. Set `SHELLY_AURLENS_CONFIG` to an absolute trusted AI configuration path to require AI review. The existing AURLens rules reject configuration inside the reviewed checkout.

These variables must reach the manager process. A launcher or privilege-elevation tool may remove them. This development mechanism is not a system-wide enforcement policy. A production integration needs trusted persistent settings and visible enabled status.

The adapter starts an argv process as the invoking user. It uses Shelly's bounded process runner with a 120-second scan timeout and a 30-second verification timeout. It accepts reports up to 4 MiB after the runner's 16 MiB stream limits. Missing executables, timeouts, invalid JSON, unsupported versions or coverage, mismatched exit codes, incomplete requested AI, and changed files stop the operation.

The [adapter module](../integrations/shelly/aurlens.zig) validates the protocol. Shelly owns approval and execution timing. Rust owns traversal and hashing. The tools do not compare their different digest formats.

## Run the native verification

Use an unmodified checkout of [Shelly v3.2.0](https://github.com/Seafoam-Labs/Shelly-ALPM/tree/v3.2.0), Zig 0.17.0, and the native development libraries required by Shelly, including libalpm. Build AURLens first:

```sh
cargo build --locked --release
ZIG=/absolute/path/to/zig integrations/shelly/verify.sh \
    /path/to/Shelly-ALPM-3.2.0 "$PWD/target/release/aurlens" /tmp/aurlens-shelly-evidence
```

The evidence directory must not exist. The driver checks the original hashes of the patched files, copies the source into a private directory, applies the patch, and adds the adapter module. It runs the protocol tests, the focused `aurlens-test` target, and Shelly's broader `aur-test` target with the real AURLens binary. Pinned Zig dependencies may require network access on the first run. Existing upstream signing tests require local GPG-agent sockets.

The focused tests check complete scan and verification responses, status disagreement, unsupported coverage, requested AI completeness, changed helpers on cached approvals, all five build dispatch choices, independent dependency review, blocked and binary inputs before metadata evaluation, and manual finding presentation and rejection. Dependency discovery itself is not an end-to-end install test. A failure at the gate must occur before the test evaluator can run.

Upstream fixtures build packages in private directories. They do not install those packages into the system. The driver retains logs and executable hashes, removes its copied source, and writes `summary.json` only after all checks pass. It never replaces the installed Shelly.

## Limits of this experiment

Whole-checkout coverage includes hidden and untracked helpers, empty directories, modes, `src`, and `pkg`. Binary outputs, links, unsupported text, and exceeded limits cause an incomplete review. The adapter neither hides generated files nor deletes them to get a passing scan.

Shelly can modify its checkout during metadata or build preparation. Later checks can therefore refuse a legitimate operation. A fresh recipe workspace separated from generated outputs is required before this patch is suitable for daily installs and updates.

A process-external digest check also leaves a race before later filesystem reads. It does not freeze the checkout against a concurrent writer. Immutable execution inputs or operating-system isolation are needed for that stronger guarantee.
