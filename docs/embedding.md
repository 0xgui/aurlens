# Embed the AURLens CLI

A Rust binary can compile AURLens in and expose its commands under its own name, for example `nest aurlens scan PATH`. The embedded commands behave like the standalone `aurlens` executable: same flags, same reports, same exit codes, same saved AI connection.

## Host the command line

Depend on the library at a commit you have reviewed:

```toml
[dependencies]
aurlens = { git = "https://github.com/0xgui/aurlens", rev = "REVIEWED_COMMIT" }
```

Pass the arguments that follow your subcommand to `aurlens::cli::run`, and return its exit status unchanged:

```rust
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    match args.next() {
        Some(command) if command == "aurlens" => aurlens::cli::run("nest aurlens", args),
        _ => ExitCode::from(aurlens::cli::USAGE_EXIT_CODE), // Your own commands go here.
    }
}
```

The first argument is the name shown in help, usage errors, and setup instructions. The second is the arguments after the program name. `--version` always prints `aurlens VERSION`, the version of the embedded library.

`run` prints to the process's standard output and standard error and returns only the exit status. It does not return a report.

## Run it as a separate process

To act on a review, start your own executable as a child process with the `aurlens` arguments and read its output. Do not call `run` inside the process that goes on to build or install.

- **The exit status is part of the protocol.** A report is valid only if the process status equals its `exit_code`. A child gives you that status. It also gives you one interface, tested by this project, instead of a second in-process path.
- **Standard output belongs to the report.** With `--json`, standard output is exactly one JSON document followed by a newline. Anything else your process prints there breaks that.
- **A child can be bounded.** A scan reads untrusted files and, with AI enabled, waits on a network request or a Codex process. You can enforce a time limit and an output limit on a child and stop it. A crash ends the child, not your operation.
- **Setup changes process-wide state.** `setup` reads from the terminal. During API key entry it changes terminal modes and installs handlers for `SIGINT`, `SIGTERM`, and `SIGHUP`. Those belong in a short-lived process.

A separate process is not a sandbox. AURLens never executes package code in either arrangement.

## Read the reports

Parse standard output into the library's types. They ignore fields they do not know.

```rust
use aurlens::ReviewReport;
use std::process::Command;

fn review(checkout: &std::path::Path) -> Option<ReviewReport> {
    let output = Command::new(std::env::current_exe().ok()?)
        .args(["aurlens", "scan"])
        .arg(checkout)
        .arg("--json")
        .output()
        .ok()?;
    let report: ReviewReport = serde_json::from_slice(&output.stdout).ok()?;
    let consistent = report.schema_version == 1
        && output.status.code() == Some(i32::from(report.exit_code))
        && report.exit_code == report.decision.exit_code();
    consistent.then_some(report)
}
```

This sketch has no time or output limit. Add both. It returns blocked and incomplete reports too, so apply the checks below.

Check these before you use a report:

| Check | Why |
| --- | --- |
| The process exited with 0, 1, 2, or 3. | 64 means your arguments were invalid and no report was printed. Any other status, or a signal, means no usable report. |
| `schema_version` is 1, and `exit_code` matches both the process status and `decision`. | An inconsistent report is not a decision. |
| `decision` is `no_findings`, or `manual_review` and the user accepted the findings. | `blocked` and `incomplete` must stop the operation. |
| `coverage.complete` and `revalidated` are true, `coverage.issues` is empty, and `coverage.policy` is one you support. | A report can only speak for inputs it covered. |
| `ai.state` is `complete` if you required AI review. | Without a connection, a scan runs static checks alone and reports `not_run`. |

A report that fails to parse must stop the operation. This includes a report with a decision, status, or AI state that this version of the types does not know.

Before you consume the reviewed files, run `aurlens verify PATH --snapshot-digest DIGEST --json` the same way and parse `aurlens::VerificationReport`. Require exit status 0, `status` `matched`, and both digests equal to the one you saved. A match is not an approval: check the original decision separately. See [the verification protocol](verification-protocol.md).

`aurlens schema review` and `aurlens schema verify` print the JSON Schema of each report for consumers that do not use the Rust types.

## Settings and trust

The embedded commands read the same saved connection as the standalone executable: `$XDG_CONFIG_HOME/aurlens/config.toml`, or `~/.config/aurlens/config.toml`. The name you pass to `run` does not change this path. Setup through either name writes the configuration with mode `0600` in a directory with mode `0700`.

The child inherits your process's environment and user. Start it as the user who owns the checkout and the saved connection, with `HOME` or `XDG_CONFIG_HOME` pointing at that user's configuration.
