# AURLens verification map

The release CLI is the primary user interface. All mapped journeys run through `scan`, including explicit AI configuration. The library tests provide additional coverage but do not replace these entry points.

Run the skill's Launch and Doctor instructions, then use `scripts/verify.sh run`. Each run has private fixtures, random loopback ports, and a fresh evidence directory. Concurrent runs may share Cargo's build lock but do not share package state or servers.

The maintained features are:

- [Static review](static-review.md) covers clean and blocking scans, evidence, JSON, and exit codes.
- [Update comparison](update-comparison.md) covers `--baseline` and helper-file changes.
- [AI review](ai-review.md) covers `--config`, source disclosure, valid completions, and invalid evidence.
- [Filesystem integrity](filesystem-integrity.md) covers external links and files changed during AI review.

Retain the action, stdout, stderr, and summary artifacts. A skipped or unreachable entry point is unverified. The fixture model proves transport and policy behavior, not model detection quality. Shelly integration is not implemented and is not part of this map.
