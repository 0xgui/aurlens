# Review architecture

The public `review()` operation returns one finalized report. An owned `Snapshot` contains supported source text and file metadata. Analysis reads those owned values rather than reopening package paths. The collector owns filesystem capture and final verification, deterministic rules own their findings, and the AI adapter owns configuration, network transport, and response validation.

The report distinguishes no findings, manual review, blocking findings, and incomplete review. AI uses a tagged result for not-run, complete, and incomplete states. One decision function combines those facts after the filesystem is revalidated. AI findings are appended and never replace deterministic findings.

Two design candidates were compared. A public session object retained file descriptors across the AI request; an immutable snapshot with one review facade hid the same lifecycle with fewer caller obligations. The snapshot design was selected. The final design borrowed explicit inode and ancestor checks, source-disclosure consent, and safe terminal rendering from the comparison.

The design candidates and separate judge ran on the available native model. External Claude and Grok review processes could not launch because their runner required an unavailable `bun` executable. This was not a cross-provider review.

Rust replaced the initial Python sketch at the user's request before publication. Owned file descriptors provide cleanup through RAII, enums describe result states, and `unsafe` code is forbidden. Runtime bounds remain necessary for untrusted package files and external model responses.

The scanner owns local checkout review and a separate digest-verification operation. Dependency fetching, remote-source analysis, and Shelly execution remain outside the scanner. The [threat model](threat-model.md) defines the current limits.

## Binding a native manager to a review

The experimental Shelly adapter keeps the accepted external digest in an operation-local approval. A typed verification result distinguishes matched, changed, and incomplete observations. The initial security decision remains separate. This prevents equality from becoming an accidental approval for a blocked recipe.

Two integration shapes were compared. A filesystem gate reuses Rust's existing no-follow traversal and digest algorithm. An owned-input protocol would let Shelly send immutable bytes, but its existing review snapshots contain only declared related files. They omit undeclared helpers and directory inventory. Claiming whole-checkout coverage from those snapshots would be false.

The filesystem gate was selected for the experiment because it needs no second traversal implementation or cross-language hash algorithm. The owned-input comparison contributed explicit metadata-evaluation enforcement and invalidation after controlled version edits. Both shapes still need a stable execution workspace. Whole-checkout coverage deliberately refuses dirty caches rather than silently omitting build outputs.

The native lifecycle now separates generated outputs from the reviewed checkout through a per-prepared-package `ReviewedOutputs` owner. Metadata and builds share that policy. Default outputs are temporary until installation consumes the archives; configured final package and log directories persist. Canonical destination checks reject aliases into the recipe. This fixes repeated in-process metadata and complete native builds without weakening the input inventory. Other execution modes and controlled version updates still need the same verified lifecycle.

Two native Codex directional candidates informed this integration design. Claude and Grok lanes could not start because their launcher required Bun. No cross-provider judge ran. This is a review limitation, not evidence of multi-provider agreement.

Normal Shelly use and package updates are a delivery constraint. The development patch proves an interface in an isolated copy. It is not a distribution strategy for a maintained Shelly fork. The production path needs a supported native hook and a recipe workspace separated from build outputs.
