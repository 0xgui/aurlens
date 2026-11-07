# Snapshot verification protocol

`aurlens verify PATH --snapshot-digest HEX [--json]` compares a local checkout with a digest from `scan`. `HEX` is exactly 64 lowercase hexadecimal characters. Invalid digests produce an incomplete report before filesystem traversal. Missing required arguments remain CLI usage errors.

Verification uses the existing `whole-checkout-v1` collector and default limits. It captures supported contents and modes, then recaptures to check stability, inode identities, and ancestor identities within the verification process. It compares the portable digest with the caller's value. The original scan's inode identities are not part of that portable value.

The JSON report has these fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | `1`. |
| `operation` | `verify_snapshot`. |
| `status` | `matched`, `changed`, or `incomplete`. |
| `exit_code` | `0` for matched, `3` otherwise. |
| `expected_digest` | The exact supplied digest. |
| `snapshot_digest` | The captured digest, or `null` if capture failed. A failed revalidation can retain this value. |
| `issues` | Stable failure codes. Empty on a match. |
| `notice` | Explains the distinction between a match and execution approval. |

The command does not analyze patterns, invoke a model, load configuration, or execute recipes. A digest match can describe a recipe whose initial review was blocked. Consumers must check the initial review's decision, complete coverage, revalidation, requested AI state, and process exit status independently.

File and directory additions, removals, content changes, and mode changes invalidate the digest. The actual root `.git` metadata directory remains excluded. Unsupported inputs cause an incomplete result rather than a partial match.

Verification checks an observation of the checkout. It does not lock the filesystem or authorize future changes. The JSON schema of `scan` remains unchanged.
