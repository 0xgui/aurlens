//! A report about a bounded local checkout. Reviewing never executes package code.

mod ai;
pub mod model;
mod rules;
mod snapshot;

use std::path::{Path, PathBuf};

pub use ai::{AiError, load_config};
pub use model::{
    AiConfig, AiResult, CodexConfig, Decision, HttpConfig, Limits, ReviewReport, Severity,
    VerificationReport, VerificationStatus,
};
use model::{Coverage, FileSummary, Finding, Snapshot};

#[derive(Clone, Debug, Default)]
pub struct ReviewOptions {
    pub baseline: Option<PathBuf>,
    pub ai: Option<AiConfig>,
    pub limits: Limits,
}

pub fn verify_snapshot(path: &Path, expected_digest: &str) -> VerificationReport {
    let mut report = VerificationReport {
        schema_version: 1,
        operation: "verify_snapshot".into(),
        status: VerificationStatus::Incomplete,
        exit_code: 3,
        expected_digest: expected_digest.into(),
        snapshot_digest: None,
        issues: Vec::new(),
        notice: "A matching snapshot is not a safety certificate or permission to execute package code. The initial review decision must be checked separately.".into(),
    };
    if expected_digest.len() != 64
        || !expected_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        report.issues.push("invalid_snapshot_digest".into());
        return report;
    }

    let limits = Limits::default();
    let result = snapshot::capture(path, &limits).and_then(|snapshot| {
        report.snapshot_digest = Some(snapshot.digest.clone());
        snapshot::verify(path, &snapshot, &limits)?;
        Ok(snapshot.digest)
    });
    report.status = match result {
        Ok(digest) if digest == expected_digest => VerificationStatus::Matched,
        Ok(_) => {
            report.issues.push("snapshot_changed".into());
            VerificationStatus::Changed
        }
        Err(error) => {
            report.issues.push(error.code.into());
            if error.code == "snapshot_changed" {
                VerificationStatus::Changed
            } else {
                VerificationStatus::Incomplete
            }
        }
    };
    report.exit_code = report.status.exit_code();
    report
}

pub fn review(path: &Path, options: &ReviewOptions) -> ReviewReport {
    let mut issues = Vec::new();
    let mut findings = Vec::new();
    let current = capture(path, &options.limits, &mut issues, &mut findings);
    if let Some(snapshot) = &current {
        findings.extend(rules::inspect(snapshot));
    }
    let previous = options
        .baseline
        .as_ref()
        .and_then(|path| capture(path, &options.limits, &mut issues, &mut findings));
    let changes = previous
        .as_ref()
        .zip(current.as_ref())
        .map(|(old, new)| snapshot::compare(old, new));

    let ai = match (&options.ai, &current, issues.is_empty()) {
        (Some(config), Some(snapshot), true) => {
            if credential_in_source(config, path, options.baseline.as_deref()) {
                AiResult::Incomplete {
                    reason: "ai_credentials_in_source".into(),
                }
            } else {
                ai::assess(snapshot, changes.as_deref(), config)
            }
        }
        (Some(_), _, _) => AiResult::NotRun {
            reason: "incomplete_inputs".into(),
        },
        _ => AiResult::default(),
    };
    if let AiResult::Complete {
        findings: additional,
        ..
    } = &ai
    {
        findings.extend(additional.iter().cloned());
    }

    if let Some(snapshot) = &current {
        verify(path, snapshot, &options.limits, &mut issues, &mut findings);
    }
    if let Some((path, snapshot)) = options.baseline.as_ref().zip(previous.as_ref()) {
        verify(path, snapshot, &options.limits, &mut issues, &mut findings);
    }

    let complete = issues.is_empty() && current.is_some();
    let decision = if !complete || matches!(ai, AiResult::Incomplete { .. }) {
        Decision::Incomplete
    } else if findings
        .iter()
        .any(|finding| finding.severity == Severity::Block)
    {
        Decision::Blocked
    } else if findings
        .iter()
        .any(|finding| finding.severity == Severity::Review)
    {
        Decision::ManualReview
    } else {
        Decision::NoFindings
    };

    let coverage = Coverage {
        complete,
        policy: "whole-checkout-v1".into(),
        scope: "Local UTF-8 text files only. Upstream downloads, binaries, and dependency packages are not reviewed.".into(),
        reviewed_files: current.as_ref().map_or(0, |s| s.files.len()),
        reviewed_bytes: current.as_ref().map_or(0, |s| s.files.iter().map(|f| f.text.len()).sum()),
        excluded: current.as_ref().map_or_else(Vec::new, |s| s.excluded.clone()),
        issues,
    };
    ReviewReport {
        schema_version: 1,
        tool_version: env!("CARGO_PKG_VERSION").into(),
        decision,
        exit_code: decision.exit_code(),
        snapshot_digest: current.as_ref().map(|s| s.digest.clone()),
        baseline_digest: previous.map(|s| s.digest),
        files: current.as_ref().map_or_else(Vec::new, |s| {
            s.files
                .iter()
                .map(|f| FileSummary {
                    path: f.path.clone(),
                    mode: f.mode,
                    size: f.text.len(),
                    sha256: f.sha256.clone(),
                })
                .collect()
        }),
        findings,
        changes,
        revalidated: complete,
        ai,
        coverage,
        notice: "No findings is not a safety certificate or permission to execute package code."
            .into(),
    }
}

fn credential_in_source(config: &AiConfig, root: &Path, baseline: Option<&Path>) -> bool {
    let AiConfig::Http(config) = config else {
        return false;
    };
    let Some(key) = config
        .api_key_file
        .as_ref()
        .and_then(|path| path.canonicalize().ok())
    else {
        return false;
    };
    std::iter::once(root)
        .chain(baseline)
        .any(|root| root.canonicalize().is_ok_and(|root| key.starts_with(root)))
}

fn capture(
    path: &Path,
    limits: &Limits,
    issues: &mut Vec<String>,
    findings: &mut Vec<Finding>,
) -> Option<Snapshot> {
    match snapshot::capture(path, limits) {
        Ok(snapshot) => Some(snapshot),
        Err(error) => {
            record_error(error, issues, findings);
            None
        }
    }
}

fn verify(
    path: &Path,
    expected: &Snapshot,
    limits: &Limits,
    issues: &mut Vec<String>,
    findings: &mut Vec<Finding>,
) {
    if let Err(error) = snapshot::verify(path, expected, limits) {
        record_error(error, issues, findings);
    }
}

fn record_error(
    error: snapshot::CaptureError,
    issues: &mut Vec<String>,
    findings: &mut Vec<Finding>,
) {
    issues.push(error.code.into());
    findings.push(Finding {
        rule_id: error.code.into(),
        source: "engine".into(),
        severity: Severity::Block,
        message: match error.path {
            Some(path) => format!("{}: {}", path, error.message),
            None => error.message.into(),
        },
        evidence: vec![],
    });
}
