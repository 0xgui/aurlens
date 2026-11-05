# Review architecture

The public `review()` operation returns one finalized report. An owned `Snapshot` contains supported source text and file metadata. Analysis reads those owned values rather than reopening package paths. The collector owns filesystem capture and final verification, deterministic rules own their findings, and the AI adapter owns configuration, network transport, and response validation.

The report distinguishes no findings, manual review, blocking findings, and incomplete review. AI uses a tagged result for not-run, complete, and incomplete states. One decision function combines those facts after the filesystem is revalidated. AI findings are appended and never replace deterministic findings.

Two design candidates were compared. A public session object retained file descriptors across the AI request; an immutable snapshot with one review facade hid the same lifecycle with fewer caller obligations. The snapshot design was selected. The final design borrowed explicit inode and ancestor checks, source-disclosure consent, and safe terminal rendering from the comparison.

The design candidates and separate judge ran on the available native model. External Claude and Grok review processes could not launch because their runner required an unavailable `bun` executable. This was not a cross-provider review.

Rust replaced the initial Python sketch at the user's request before publication. Owned file descriptors provide cleanup through RAII, enums describe result states, and `unsafe` code is forbidden. Runtime bounds remain necessary for untrusted package files and external model responses.

The first implementation owns local checkout review only. Dependency fetching, remote-source analysis, approval persistence, and Shelly execution are separate work. The [threat model](threat-model.md) defines the current limits.
