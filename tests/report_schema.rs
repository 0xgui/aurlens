//! The JSON reports match their published schemas and parse back into the library's types.

use aurlens::{
    AiResult, Change, Coverage, Decision, Evidence, FileSummary, Finding, ReviewOptions,
    ReviewReport, Severity, VerificationReport, VerificationStatus, review, verify_snapshot,
};
use jsonschema::Validator;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

const CLEAN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/clean");
const FLAGGED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/flagged");

fn aurlens_json(args: &[&str], exit_code: i32) -> Value {
    let user_config = tempdir().unwrap();
    let output = Command::new(
        std::env::var_os("AURLENS_VERIFY_BIN")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_aurlens").into()),
    )
    .env("XDG_CONFIG_HOME", user_config.path())
    .args(args)
    .output()
    .unwrap();
    assert_eq!(output.status.code(), Some(exit_code), "{args:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

fn schema(file: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("schemas")
        .join(file);
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

/// Forbids properties the schema does not list, so an undocumented field fails the test.
/// The published schemas stay open because consumers must accept added fields.
fn closed(mut schema: Value) -> Value {
    fn close(value: &mut Value) {
        match value {
            Value::Object(map) => {
                if map.get("type") == Some(&json!("object")) && map.contains_key("properties") {
                    map.insert("additionalProperties".into(), json!(false));
                }
                map.values_mut().for_each(close);
            }
            Value::Array(items) => items.iter_mut().for_each(close),
            _ => {}
        }
    }
    close(&mut schema);
    schema
}

struct Contract {
    published: Validator,
    closed: Validator,
}

impl Contract {
    fn new(file: &str) -> Self {
        let schema = schema(file);
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        Self {
            published: jsonschema::draft202012::new(&schema).unwrap(),
            closed: jsonschema::draft202012::new(&closed(schema)).unwrap(),
        }
    }

    fn accepts(&self, name: &str, report: &Value) {
        for validator in [&self.published, &self.closed] {
            let errors: Vec<String> = validator
                .iter_errors(report)
                .map(|error| format!("{}: {error}", error.instance_path()))
                .collect();
            assert!(errors.is_empty(), "{name}: {errors:#?}");
        }
    }

    fn rejects(&self, name: &str, report: &Value) {
        assert!(!self.published.is_valid(report), "{name}");
    }
}

fn finding(source: &str, severity: Severity) -> Finding {
    Finding {
        rule_id: "AI-001".into(),
        source: source.into(),
        severity,
        message: "An observation.".into(),
        evidence: vec![Evidence {
            path: "PKGBUILD".into(),
            line: 1,
            quote: "pkgname=example".into(),
        }],
    }
}

/// A report that uses every optional shape: digests, changes, and a completed AI review.
fn full_review_report() -> ReviewReport {
    ReviewReport {
        schema_version: 1,
        tool_version: env!("CARGO_PKG_VERSION").into(),
        decision: Decision::ManualReview,
        exit_code: Decision::ManualReview.exit_code(),
        snapshot_digest: Some("a".repeat(64)),
        baseline_digest: Some("b".repeat(64)),
        files: vec![FileSummary {
            path: "PKGBUILD".into(),
            mode: 0o644,
            size: 16,
            sha256: "c".repeat(64),
        }],
        findings: vec![
            Finding {
                rule_id: "FINDING-LIMIT".into(),
                source: "engine".into(),
                severity: Severity::Info,
                message: "An engine notice.".into(),
                evidence: vec![],
            },
            finding("ai", Severity::Review),
        ],
        changes: Some(vec![
            Change {
                path: "helper.install".into(),
                kind: "added".into(),
                before: None,
                after: Some("d".repeat(64)),
            },
            Change {
                path: "PKGBUILD".into(),
                kind: "mode_changed".into(),
                before: Some("0644".into()),
                after: Some("0755".into()),
            },
        ]),
        coverage: Coverage {
            complete: true,
            policy: "whole-checkout-v1".into(),
            scope: "Local UTF-8 text files only.".into(),
            reviewed_files: 1,
            reviewed_bytes: 16,
            excluded: vec![".git".into()],
            issues: vec![],
        },
        ai: AiResult::Complete {
            model: "fixture-model".into(),
            endpoint_origin: "http://127.0.0.1:11434".into(),
            summary: "Untrusted model opinion: A package called example.".into(),
            findings: vec![finding("ai", Severity::Review)],
        },
        revalidated: true,
        notice: "No findings is not a safety certificate.".into(),
    }
}

#[test]
fn scan_json_matches_the_review_schema() {
    let contract = Contract::new("review-report.v1.schema.json");
    let scratch = tempdir().unwrap();
    let missing = scratch.path().join("missing");
    let configured = scratch.path().join("configured");
    fs::create_dir(&configured).unwrap();
    fs::write(configured.join("PKGBUILD"), "pkgname=example\n").unwrap();
    let config = configured.join("ai.toml");
    fs::write(
        &config,
        "[ai]\nendpoint='https://example.invalid'\nmodel='demo'\nsend_source=true\n",
    )
    .unwrap();
    let manual = scratch.path().join("manual");
    fs::create_dir(&manual).unwrap();
    fs::write(manual.join("PKGBUILD"), "eval \"$generated\"\n").unwrap();

    let clean = aurlens_json(&["scan", CLEAN, "--json"], 0);
    contract.accepts("clean", &clean);
    let flagged = aurlens_json(&["scan", FLAGGED, "--json"], 2);
    assert_eq!(flagged["findings"][0]["rule_id"], "REMOTE-SHELL");
    contract.accepts("flagged", &flagged);
    let compared = aurlens_json(&["scan", CLEAN, "--baseline", FLAGGED, "--json"], 0);
    assert!(!compared["changes"].as_array().unwrap().is_empty());
    contract.accepts("baseline", &compared);
    contract.accepts(
        "manual review",
        &aurlens_json(&["scan", manual.to_str().unwrap(), "--json"], 1),
    );
    let incomplete = aurlens_json(&["scan", missing.to_str().unwrap(), "--json"], 3);
    assert_eq!(incomplete["snapshot_digest"], Value::Null);
    contract.accepts("missing path", &incomplete);
    contract.accepts(
        "configuration error",
        &aurlens_json(
            &[
                "scan",
                configured.to_str().unwrap(),
                "--config",
                config.to_str().unwrap(),
                "--json",
            ],
            3,
        ),
    );

    // AI states that need a model are built from the library's own types.
    let mut report = full_review_report();
    contract.accepts("ai complete", &serde_json::to_value(&report).unwrap());
    report.ai = AiResult::Incomplete {
        reason: "ai_timeout".into(),
    };
    contract.accepts("ai incomplete", &serde_json::to_value(&report).unwrap());

    let mut broken = clean.clone();
    broken.as_object_mut().unwrap().remove("decision");
    contract.rejects("missing decision", &broken);
    for (pointer, value) in [
        ("/decision", json!("approved")),
        ("/exit_code", json!(64)),
        ("/schema_version", json!(2)),
        ("/snapshot_digest", json!("not-a-digest")),
        ("/ai/state", json!("skipped")),
        ("/coverage/complete", json!("yes")),
        ("/files/0/mode", json!("0644")),
    ] {
        let mut broken = clean.clone();
        *broken.pointer_mut(pointer).unwrap() = value;
        contract.rejects(pointer, &broken);
    }
}

#[test]
fn verify_json_matches_the_verify_schema() {
    let contract = Contract::new("verify-report.v1.schema.json");
    let digest = aurlens_json(&["scan", CLEAN, "--json"], 0)["snapshot_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    let verify = |digest: &str, exit_code| {
        aurlens_json(
            &["verify", CLEAN, "--snapshot-digest", digest, "--json"],
            exit_code,
        )
    };

    let matched = verify(&digest, 0);
    assert_eq!(matched["status"], "matched");
    contract.accepts("matched", &matched);
    let changed = verify(&"0".repeat(64), 3);
    assert_eq!(changed["status"], "changed");
    contract.accepts("changed", &changed);
    let invalid = verify("invalid", 3);
    assert_eq!(invalid["status"], "incomplete");
    assert_eq!(invalid["snapshot_digest"], Value::Null);
    contract.accepts("invalid digest", &invalid);

    for (pointer, value) in [
        ("/status", json!("approved")),
        ("/exit_code", json!(2)),
        ("/operation", json!("scan")),
        ("/issues", json!("none")),
    ] {
        let mut broken = matched.clone();
        *broken.pointer_mut(pointer).unwrap() = value;
        contract.rejects(pointer, &broken);
    }
}

#[test]
fn review_reports_round_trip_through_json() {
    let mut reports = vec![
        full_review_report(),
        review(Path::new(CLEAN), &ReviewOptions::default()),
        review(Path::new(FLAGGED), &ReviewOptions::default()),
        review(
            Path::new(CLEAN),
            &ReviewOptions {
                baseline: Some(FLAGGED.into()),
                ..Default::default()
            },
        ),
        review(Path::new("/nonexistent/aurlens"), &ReviewOptions::default()),
    ];
    let mut incomplete = full_review_report();
    incomplete.ai = AiResult::Incomplete {
        reason: "ai_timeout".into(),
    };
    reports.push(incomplete);
    for report in reports {
        let text = serde_json::to_string_pretty(&report).unwrap();
        let decoded: ReviewReport = serde_json::from_str(&text).unwrap();
        assert_eq!(decoded, report);
        assert_eq!(serde_json::to_string_pretty(&decoded).unwrap(), text);
    }

    // The CLI's document parses into the same type.
    let printed = aurlens_json(&["scan", FLAGGED, "--json"], 2);
    let decoded: ReviewReport = serde_json::from_value(printed.clone()).unwrap();
    assert_eq!(decoded.decision, Decision::Blocked);
    assert_eq!(decoded.exit_code, 2);
    assert_eq!(serde_json::to_value(&decoded).unwrap(), printed);
}

#[test]
fn verification_reports_round_trip_through_json() {
    let digest = review(Path::new(CLEAN), &ReviewOptions::default())
        .snapshot_digest
        .unwrap();
    for (expected, status) in [
        (digest.as_str(), VerificationStatus::Matched),
        (&"0".repeat(64), VerificationStatus::Changed),
        ("invalid", VerificationStatus::Incomplete),
    ] {
        let report = verify_snapshot(Path::new(CLEAN), expected);
        assert_eq!(report.status, status);
        let text = serde_json::to_string_pretty(&report).unwrap();
        let decoded: VerificationReport = serde_json::from_str(&text).unwrap();
        assert_eq!(decoded, report);
        assert_eq!(serde_json::to_string_pretty(&decoded).unwrap(), text);
    }

    let printed = aurlens_json(
        &["verify", CLEAN, "--snapshot-digest", &digest, "--json"],
        0,
    );
    let decoded: VerificationReport = serde_json::from_value(printed.clone()).unwrap();
    assert_eq!(decoded.status, VerificationStatus::Matched);
    assert_eq!(serde_json::to_value(&decoded).unwrap(), printed);
}

#[test]
fn report_types_ignore_fields_added_by_a_later_release() {
    let mut review = serde_json::to_value(full_review_report()).unwrap();
    for pointer in [
        "",
        "/files/0",
        "/findings/1",
        "/findings/1/evidence/0",
        "/changes/0",
        "/coverage",
        "/ai",
        "/ai/findings/0",
    ] {
        review
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("added_later".into(), json!({"nested": [1, 2, 3]}));
    }
    let decoded: ReviewReport = serde_json::from_value(review.clone()).unwrap();
    assert_eq!(decoded, full_review_report());
    // The published schema accepts the same additions.
    let contract = Contract::new("review-report.v1.schema.json");
    assert!(contract.published.is_valid(&review));
    assert!(!contract.closed.is_valid(&review));

    let mut verification =
        serde_json::to_value(verify_snapshot(Path::new(CLEAN), "invalid")).unwrap();
    verification["added_later"] = json!(true);
    let decoded: VerificationReport = serde_json::from_value(verification).unwrap();
    assert_eq!(decoded.status, VerificationStatus::Incomplete);
}
