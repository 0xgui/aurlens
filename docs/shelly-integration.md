# Planned Shelly integration

AURLens 0.1 is a standalone local review engine. It does not intercept Shelly installs or updates.

The source review used Shelly 3.2.0. Its AUR manager prepares package checkouts, collects built-in findings, requests approval, and verifies prepared inputs before building. The shared package-review payload already carries findings for both CLI and GUI consumers. No configurable external-scanner hook was found in that release.

The proposed integration adds an optional native adapter at the static review boundary, before any PKGBUILD shell evaluation. The adapter passes the exact local checkout to AURLens, displays deterministic and AI findings in Shelly's review dialog, and distinguishes incomplete review from no findings. The same path must cover updates, recursive AUR dependencies, and every relevant build mode.

The adapter must bind the result to the actual files it builds. Shelly's existing review digests and AURLens's digest use different formats; they cannot be compared directly. The implementation must share or explicitly translate a documented manifest contract, then verify the reviewed inputs immediately before execution. No approved result can authorize subsequently changed files.

Scanner absence, timeout, invalid output, changed input, or unsupported coverage must not silently pass. JSON exit status and report fields must agree. The GUI owns the user's decision; an unattended scanner must not open a separate terminal prompt.

Next work requires a tested Shelly patch and agreement on the adapter interface. A shell alias or a pacman transaction hook cannot provide this pre-build guarantee for Shelly's native builder. The standalone CLI intentionally does not pretend to provide that integration.
