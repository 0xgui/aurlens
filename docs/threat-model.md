# What AURLens reviews

AURLens reads a bounded local package checkout and reports evidence for review. The checkout and every model response are untrusted. The executable, kernel, Rust dependencies, trusted AI configuration, and selected model service are outside the inspected input.

## Filesystem boundary

The Linux collector opens each path component and checkout entry with `O_PATH` and `O_NOFOLLOW`. It checks the pinned inode before opening a regular file for reading through `/proc/self/fd`. This avoids following a package-controlled link or IO-opening a substituted special file. Owned file descriptors close on error paths. A working, trusted procfs is required.

All supported text is read into an owned snapshot. The digest binds relative paths, entry types, permission modes, and exact bytes with length-prefixed fields. Private inode identities bind final checks to the original entries. Before returning a report, AURLens captures the checkout again and compares content, inventory, identity, and ancestor identity. The same checks apply to an optional baseline.

This is not an atomic filesystem snapshot or a lock. Another process can modify files after the final check. A future build integration must check its actual inputs immediately before execution. Filesystems with unusual or hostile behavior are outside this prototype's guarantees.

The collector rejects links, special files, non-UTF-8 content, unsupported control characters, and exhausted byte, entry, or depth limits. An unsupported binary produces incomplete coverage. Only an actual root `.git` directory is excluded. `.gitignore` is ordinary text and cannot hide files from review. Run against fresh checkouts to avoid unsupported build outputs.

## Analysis boundary

Deterministic checks are a small set of text patterns. They do not parse or emulate Bash. A command split over lines, constructed through variables, or hidden in upstream code can evade them. Conversely, legitimate data or quoted documentation can match a pattern. Findings describe observed text, not proof that malware ran.

Upstream source archives, prebuilt executables, fetched scripts, package dependencies, installed system files, and runtime behavior are not analyzed. AURLens never executes a recipe, downloads its sources, installs a package, or makes a network request to a URL found in package text.

## AI boundary

AI review requires an explicit trusted configuration and `send_source = true`. Current package text, relative paths, hashes, and a change summary go to that chosen endpoint. The provider's data retention and handling apply. Baseline bodies, home-directory files, and API keys are not part of the model prompt.

The HTTP client verifies TLS, refuses redirects, disables proxies and retries, and caps request size, response size, and request duration. Plain HTTP is restricted to an explicitly opted-in numeric loopback address. Credentials come from a named environment variable and are not included in reports or diagnostic bodies.

The model receives source as data and has no tools. Every returned finding must identify the current snapshot and quote an existing source line. Invalid JSON, unsupported operations, ungrounded evidence, unavailable endpoints, and truncated answers make AI review incomplete. Model opinions cannot remove deterministic findings. Grounded quotations establish that text exists; they do not establish that the model interpreted it correctly.

## Result boundary

No findings means only that supported checks reported no findings in the declared scope. It is not a safety certificate. The report records whether AI ran and whether the files were revalidated. Every nonzero exit requires attention. An incomplete result takes precedence over a blocked result while retaining observed blocking findings.

Evidence excerpts can themselves contain sensitive text supplied by the package. Review reports before sharing them. Human-readable output escapes terminal controls; JSON consumers must render untrusted text safely too.
