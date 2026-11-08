use aurlens::{ReviewOptions, load_config, review, verify_snapshot};
use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod setup;

#[derive(Parser)]
#[command(
    version,
    about = "See what you install. Review local AUR recipes without running them."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect Codex, an API provider, or a local model once.
    Setup {
        /// Disable the optional Shelly hook while keeping your AI connection.
        #[arg(long)]
        disable_shelly: bool,
    },
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
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Commands::Setup { disable_shelly } => match if disable_shelly {
            setup::disable_shelly()
        } else {
            setup::run()
        } {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("AURLens setup: {error}");
                ExitCode::from(3)
            }
        },
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
                    if let aurlens::AiConfig::Http(http) = &config {
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
            aurlens::VerificationStatus::Matched => "matched",
            aurlens::VerificationStatus::Changed => "changed",
            aurlens::VerificationStatus::Incomplete => "incomplete",
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
    let report = aurlens::model::ReviewReport {
        schema_version: 1,
        tool_version: env!("CARGO_PKG_VERSION").into(),
        decision: aurlens::Decision::Incomplete,
        exit_code: 3,
        snapshot_digest: None,
        baseline_digest: None,
        files: vec![],
        findings: vec![],
        changes: None,
        coverage: aurlens::model::Coverage {
            complete: false,
            policy: "whole-checkout-v1".into(),
            scope: "The review did not run because its configuration was invalid.".into(),
            reviewed_files: 0,
            reviewed_bytes: 0,
            excluded: vec![],
            issues: vec![code.into()],
        },
        ai: aurlens::AiResult::NotRun {
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

fn render(report: &aurlens::ReviewReport) -> String {
    let mut lines = vec![
        format!("AURLens: {:?}", report.decision),
        format!(
            "Reviewed {} files ({} bytes).",
            report.coverage.reviewed_files, report.coverage.reviewed_bytes
        ),
    ];
    match &report.ai {
        aurlens::AiResult::NotRun { reason } => {
            lines.push(format!("AI: not run ({})", reason.escape_debug()))
        }
        aurlens::AiResult::Incomplete { reason } => {
            lines.push(format!("AI: incomplete ({})", reason.escape_debug()))
        }
        aurlens::AiResult::Complete { model, summary, .. } => {
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
