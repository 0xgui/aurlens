# Sensitive information

Keep credentials, authentication files, private keys, local configuration, and scan evidence outside this repository. Examples contain placeholders and environment-variable names. AURLens never needs a credential value committed to source control.

AI source disclosure is explicit. Reports can contain excerpts from reviewed files, so treat reports and live model transcripts as potentially sensitive. The automated verification fixtures contain synthetic data. Do not replace them with private package files or real credentials.

CI scans Git history with checksum-pinned Gitleaks 8.30.1. Matches fail the job, and values are redacted. Inline `gitleaks:allow` comments do not bypass the gate. Run the same check locally before publishing:

```sh
gitleaks git --redact=100 --no-banner --ignore-gitleaks-allow --log-opts=--all .
```

The ignore rules reduce accidental staging of common credential files. They do not detect every sensitive value or prevent an explicit forced add. Review staged files before committing. Keep scan reports and any investigation of a suspected disclosure private.
