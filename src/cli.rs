//! The AURLens command line, hosted by the library so another binary can expose it unchanged.
//!
//! The `aurlens` executable calls [`run`] with its own name. A host binary calls it with the
//! name its users type, for example `"nest aurlens"`. See `docs/embedding.md`.

use crate::{ReviewOptions, load_config, review, verify_snapshot};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod setup;

/// Exit status for command-line usage errors. It never overlaps a review decision (0 to 3).
pub const USAGE_EXIT_CODE: u8 = 64;

const REVIEW_REPORT_SCHEMA: &str = include_str!("../schemas/review-report.v1.schema.json");
const VERIFY_REPORT_SCHEMA: &str = include_str!("../schemas/verify-report.v1.schema.json");

#[derive(Parser)]
#[command(
    version,
    about = "See what you install. Review local AUR recipes without running them."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, ValueEnum)]
enum SchemaKind {
    /// The `scan --json` report.
    Review,
    /// The `verify --json` report.
    Verify,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect Codex, an API provider, or a local model once.
    Setup,
    /// Review a local package directory containing PKGBUILD.
    Scan {
        path: PathBuf,
        /// Compare against a previous local checkout.
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Use a trusted TOML file instead of your saved AI connection.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Run static checks without your saved AI connection.
        #[arg(long, conflicts_with = "config")]
        no_ai: bool,
        /// Emit the versioned machine-readable report.
        #[arg(long)]
        json: bool,
    },
    /// Check whether a local checkout still matches a previously reviewed snapshot.
    Verify {
        path: PathBuf,
        #[arg(long)]
        snapshot_digest: String,
        /// Emit the versioned machine-readable verification report.
        #[arg(long)]
        json: bool,
    },
    /// Print the JSON Schema of a machine-readable report.
    Schema {
        /// The report to describe.
        report: SchemaKind,
    },
}

/// Runs the AURLens CLI and returns its exit status.
///
/// `bin_name` is what help and usage text shows, such as `"aurlens"` or `"nest aurlens"`.
/// `args` are the arguments after the program name.
///
/// Reports go to the process's standard output and diagnostics to its standard error. The
/// status is 0 to 3 when a command ran, and [`USAGE_EXIT_CODE`] when the arguments could not
/// be parsed. `--help` and `--version` print to standard output and return 0.
///
/// A host forwards the arguments that follow its own subcommand:
///
/// ```no_run
/// use std::process::ExitCode;
///
/// let mut args = std::env::args_os().skip(1);
/// let status = match args.next() {
///     Some(command) if command == "aurlens" => aurlens::cli::run("nest aurlens", args),
///     _ => ExitCode::from(aurlens::cli::USAGE_EXIT_CODE), // The host's own commands.
/// };
/// ```
pub fn run<I, S>(bin_name: &str, args: I) -> ExitCode
where
    I: IntoIterator<Item = S>,
    S: Into<OsString> + Clone,
{
    let cli = match parse(bin_name, args) {
        Ok(cli) => cli,
        Err(error) => {
            // Clap sends help and version text to standard output and errors to standard error.
            let _ = error.print();
            return ExitCode::from(parse_exit_code(&error));
        }
    };
    match cli.command {
        Commands::Setup => match setup::run(bin_name) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("AURLens setup: {error}");
                ExitCode::from(3)
            }
        },
        Commands::Schema { report } => {
            let schema = match report {
                SchemaKind::Review => REVIEW_REPORT_SCHEMA,
                SchemaKind::Verify => VERIFY_REPORT_SCHEMA,
            };
            let mut stdout = io::stdout().lock();
            if stdout
                .write_all(schema.as_bytes())
                .and_then(|()| stdout.flush())
                .is_err()
            {
                eprintln!("AURLens could not write the schema.");
                return ExitCode::from(3);
            }
            ExitCode::SUCCESS
        }
        Commands::Scan {
            path,
            baseline,
            config,
            no_ai,
            json,
        } => scan(path, baseline, config, no_ai, json),
        Commands::Verify {
            path,
            snapshot_digest,
            json,
        } => verify(&path, &snapshot_digest, json),
    }
}

fn parse<I, S>(bin_name: &str, args: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString> + Clone,
{
    let mut command = Cli::command().bin_name(bin_name).no_binary_name(true);
    let matches = command.try_get_matches_from_mut(args)?;
    Cli::from_arg_matches(&matches).map_err(|error| error.format(&mut command))
}

fn parse_exit_code(error: &clap::Error) -> u8 {
    match error.kind() {
        clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => 0,
        _ => USAGE_EXIT_CODE,
    }
}

fn scan(
    path: PathBuf,
    baseline: Option<PathBuf>,
    config: Option<PathBuf>,
    no_ai: bool,
    json: bool,
) -> ExitCode {
    let config = if no_ai {
        None
    } else if config.is_some() {
        config
    } else {
        let default = match setup::config_path() {
            Ok(path) => path,
            Err(_) => return config_error("user_config_directory", json),
        };
        match default.try_exists() {
            Ok(true) => Some(default),
            Ok(false) => None,
            Err(_) => return config_error("user_config_read", json),
        }
    };
    let ai = match config {
        Some(config) => {
            if inside_checkout(&config, &path)
                || baseline
                    .as_ref()
                    .is_some_and(|base| inside_checkout(&config, base))
            {
                return config_error("config_inside_checkout", json);
            }
            match load_config(&config) {
                Ok(config) => {
                    if let crate::AiConfig::Http(http) = &config {
                        if http.api_key_file.as_ref().is_some_and(|key| {
                            inside_checkout(key, &path)
                                || baseline
                                    .as_ref()
                                    .is_some_and(|base| inside_checkout(key, base))
                        }) {
                            return config_error("credentials_inside_checkout", json);
                        }
                    }
                    Some(config)
                }
                Err(error) => return config_error(error.code, json),
            }
        }
        None => None,
    };
    let report = review(
        &path,
        &ReviewOptions {
            baseline,
            ai,
            ..Default::default()
        },
    );
    let text = if json {
        serde_json::to_string_pretty(&report).expect("review report is serializable")
    } else {
        render(&report)
    };
    if writeln!(io::stdout().lock(), "{text}").is_err() {
        eprintln!("AURLens could not write its report.");
        return ExitCode::from(3);
    }
    ExitCode::from(report.exit_code)
}

fn verify(path: &Path, expected_digest: &str, json: bool) -> ExitCode {
    let report = verify_snapshot(path, expected_digest);
    let text = if json {
        serde_json::to_string_pretty(&report).expect("verification report is serializable")
    } else {
        let status = match report.status {
            crate::VerificationStatus::Matched => "matched",
            crate::VerificationStatus::Changed => "changed",
            crate::VerificationStatus::Incomplete => "incomplete",
        };
        let mut lines = vec![format!("AURLens snapshot: {status}")];
        for issue in &report.issues {
            lines.push(format!("Issue: {}", issue.escape_debug()));
        }
        lines.push(report.notice.clone());
        lines.join("\n")
    };
    if writeln!(io::stdout().lock(), "{text}").is_err() {
        eprintln!("AURLens could not write its report.");
        return ExitCode::from(3);
    }
    ExitCode::from(report.exit_code)
}

fn inside_checkout(config: &Path, root: &Path) -> bool {
    config
        .canonicalize()
        .ok()
        .zip(root.canonicalize().ok())
        .is_some_and(|(config, root)| config.starts_with(root))
}

fn config_error(code: &str, json: bool) -> ExitCode {
    let report = crate::model::ReviewReport {
        schema_version: 1,
        tool_version: env!("CARGO_PKG_VERSION").into(),
        decision: crate::Decision::Incomplete,
        exit_code: 3,
        snapshot_digest: None,
        baseline_digest: None,
        files: vec![],
        findings: vec![],
        changes: None,
        coverage: crate::model::Coverage {
            complete: false,
            policy: "whole-checkout-v1".into(),
            scope: "The review did not run because its configuration was invalid.".into(),
            reviewed_files: 0,
            reviewed_bytes: 0,
            excluded: vec![],
            issues: vec![code.into()],
        },
        ai: crate::AiResult::NotRun {
            reason: "invalid_configuration".into(),
        },
        revalidated: false,
        notice: "Use a trusted AI configuration outside the checkout.".into(),
    };
    let message = if json {
        serde_json::to_string_pretty(&report).expect("review report is serializable")
    } else {
        format!("AURLens: incomplete\nConfiguration error: {code}\nThe review did not run.")
    };
    let _ = writeln!(io::stdout().lock(), "{message}");
    ExitCode::from(3)
}

fn render(report: &crate::ReviewReport) -> String {
    let mut lines = vec![
        format!("AURLens: {:?}", report.decision),
        format!(
            "Reviewed {} files ({} bytes).",
            report.coverage.reviewed_files, report.coverage.reviewed_bytes
        ),
    ];
    match &report.ai {
        crate::AiResult::NotRun { reason } => {
            lines.push(format!("AI: not run ({})", reason.escape_debug()))
        }
        crate::AiResult::Incomplete { reason } => {
            lines.push(format!("AI: incomplete ({})", reason.escape_debug()))
        }
        crate::AiResult::Complete { model, summary, .. } => {
            lines.push(format!("AI: complete ({})", model.escape_debug()));
            lines.push(format!("AI explanation: {}", summary.escape_debug()));
        }
    }
    for finding in &report.findings {
        lines.push(format!(
            "[{:?}] {}: {}",
            finding.severity,
            finding.rule_id.escape_debug(),
            finding.message.escape_debug()
        ));
        for evidence in &finding.evidence {
            lines.push(format!(
                "  {}:{}  {}",
                evidence.path.escape_debug(),
                evidence.line,
                evidence.quote.escape_debug()
            ));
        }
    }
    if let Some(changes) = &report.changes {
        lines.push(format!("Changes since baseline: {}", changes.len()));
        for change in changes {
            lines.push(format!(
                "  {} {}",
                change.kind.escape_debug(),
                change.path.escape_debug()
            ));
        }
    }
    lines.push(report.coverage.scope.clone());
    lines.push(report.notice.clone());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    fn parse_error(bin_name: &str, args: &[&str]) -> clap::Error {
        parse(bin_name, args.iter().copied())
            .err()
            .expect("arguments are rejected")
    }

    #[test]
    fn host_name_appears_in_help_and_usage() {
        let help = parse_error("nest aurlens", &["--help"]);
        assert_eq!(help.kind(), ErrorKind::DisplayHelp);
        assert_eq!(parse_exit_code(&help), 0);
        assert!(help.to_string().contains("Usage: nest aurlens <COMMAND>"));

        let help = parse_error("nest aurlens", &["scan", "--help"]);
        assert!(
            help.to_string()
                .contains("Usage: nest aurlens scan [OPTIONS] <PATH>")
        );

        let usage = parse_error("nest aurlens", &["verify", "checkout"]);
        assert_eq!(usage.kind(), ErrorKind::MissingRequiredArgument);
        assert_eq!(parse_exit_code(&usage), USAGE_EXIT_CODE);
        assert!(usage.to_string().contains("Usage: nest aurlens verify"));
    }

    #[test]
    fn version_names_aurlens_under_any_host() {
        for bin_name in ["aurlens", "nest aurlens"] {
            let version = parse_error(bin_name, &["--version"]);
            assert_eq!(version.kind(), ErrorKind::DisplayVersion);
            assert_eq!(parse_exit_code(&version), 0);
            assert_eq!(
                version.to_string(),
                concat!("aurlens ", env!("CARGO_PKG_VERSION"), "\n")
            );
        }
    }

    #[test]
    fn arguments_start_after_the_program_name() {
        let cli =
            parse("aurlens", ["scan", "checkout", "--json", "--no-ai"]).expect("arguments parse");
        assert!(matches!(
            cli.command,
            Commands::Scan {
                json: true,
                no_ai: true,
                baseline: None,
                config: None,
                ..
            }
        ));
        let usage = parse_error("aurlens", &["aurlens", "scan", "checkout"]);
        assert_eq!(usage.kind(), ErrorKind::InvalidSubcommand);
        assert_eq!(parse_exit_code(&usage), USAGE_EXIT_CODE);
    }

    #[test]
    fn every_rejection_except_help_and_version_is_a_usage_error() {
        for args in [
            &[][..],
            &["--bogus"],
            &["scan"],
            &["scan", "checkout", "--no-ai", "--config", "ai.toml"],
            &["verify", "checkout", "--snapshot-digest"],
            &["schema", "unknown"],
        ] {
            assert_eq!(
                parse_exit_code(&parse_error("aurlens", args)),
                USAGE_EXIT_CODE,
                "{args:?}"
            );
        }
    }
}
