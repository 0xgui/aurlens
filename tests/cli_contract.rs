//! The process contract a host relies on: exit statuses and what reaches standard output.

use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::tempdir;

const CLEAN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/clean");
const FLAGGED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/flagged");

fn aurlens(args: &[&str]) -> Output {
    let user_config = tempdir().unwrap();
    Command::new(
        std::env::var_os("AURLENS_VERIFY_BIN")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_aurlens").into()),
    )
    .env("XDG_CONFIG_HOME", user_config.path())
    .args(args)
    .output()
    .unwrap()
}

/// Asserts that standard output is one JSON document and one trailing newline, nothing else.
fn single_document(output: &Output, exit_code: i32) -> Value {
    assert_eq!(output.status.code(), Some(exit_code));
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    let document = stdout
        .strip_suffix('\n')
        .expect("a trailing newline ends the report");
    assert_eq!(document, document.trim(), "whitespace surrounds the report");
    // `from_str` rejects anything except whitespace after the first document.
    let report: Value = serde_json::from_str(document).expect("exactly one JSON document");
    assert!(report.is_object());
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["exit_code"], exit_code);
    report
}

fn usage_error(args: &[&str]) -> String {
    let output = aurlens(args);
    assert_eq!(output.status.code(), Some(64), "{args:?}");
    assert!(output.stdout.is_empty(), "{args:?}: {:?}", output.stdout);
    let message = String::from_utf8(output.stderr).unwrap();
    assert!(!message.trim().is_empty(), "{args:?}");
    message
}

#[test]
fn scan_json_prints_exactly_one_document_for_every_decision() {
    let report = single_document(&aurlens(&["scan", CLEAN, "--json"]), 0);
    assert_eq!(report["decision"], "no_findings");

    let report = single_document(&aurlens(&["scan", FLAGGED, "--json"]), 2);
    assert_eq!(report["decision"], "blocked");

    let scratch = tempdir().unwrap();
    let missing = scratch.path().join("missing");
    let report = single_document(&aurlens(&["scan", missing.to_str().unwrap(), "--json"]), 3);
    assert_eq!(report["decision"], "incomplete");
    assert_eq!(report["snapshot_digest"], Value::Null);
}

#[test]
fn configuration_error_prints_exactly_one_document() {
    let root = tempdir().unwrap();
    fs::write(root.path().join("PKGBUILD"), "pkgname=example\n").unwrap();
    let config = root.path().join("ai.toml");
    fs::write(
        &config,
        "[ai]\nendpoint='https://example.invalid'\nmodel='demo'\nsend_source=true\n",
    )
    .unwrap();
    let report = single_document(
        &aurlens(&[
            "scan",
            root.path().to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--json",
        ]),
        3,
    );
    assert_eq!(report["decision"], "incomplete");
    assert_eq!(report["coverage"]["issues"][0], "config_inside_checkout");
}

#[test]
fn verify_json_prints_exactly_one_document() {
    let scan = single_document(&aurlens(&["scan", CLEAN, "--json"]), 0);
    let digest = scan["snapshot_digest"].as_str().unwrap();
    let report = single_document(
        &aurlens(&["verify", CLEAN, "--snapshot-digest", digest, "--json"]),
        0,
    );
    assert_eq!(report["status"], "matched");

    let report = single_document(
        &aurlens(&["verify", CLEAN, "--snapshot-digest", "invalid", "--json"]),
        3,
    );
    assert_eq!(report["status"], "incomplete");
    assert_eq!(report["issues"][0], "invalid_snapshot_digest");
}

#[test]
fn usage_errors_exit_64_and_never_collide_with_a_decision() {
    let message = usage_error(&["scan"]);
    assert!(message.contains("Usage: aurlens scan"), "{message}");
    usage_error(&["scan", "--json"]);
    usage_error(&["--bogus"]);
    usage_error(&["unknown-command"]);
    usage_error(&["scan", FLAGGED, "--bogus"]);
    usage_error(&["scan", CLEAN, "--no-ai", "--config", "ai.toml"]);
    usage_error(&["verify", CLEAN, "--json"]);
    usage_error(&["schema"]);
    usage_error(&["schema", "unknown"]);
    // No arguments prints the help as an error.
    let message = usage_error(&[]);
    assert!(message.contains("Usage: aurlens <COMMAND>"), "{message}");
}

#[test]
fn help_and_version_print_to_stdout_and_exit_0() {
    for args in [
        &["--help"][..],
        &["-h"],
        &["help"],
        &["scan", "--help"],
        &["help", "verify"],
        &["schema", "--help"],
    ] {
        let output = aurlens(args);
        assert_eq!(output.status.code(), Some(0), "{args:?}");
        assert!(output.stderr.is_empty(), "{args:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("Usage: aurlens"), "{args:?}: {text}");
    }
    for flag in ["--version", "-V"] {
        let output = aurlens(&[flag]);
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            concat!("aurlens ", env!("CARGO_PKG_VERSION"), "\n")
        );
    }
}

#[test]
fn schema_command_prints_the_committed_schema_files() {
    for (kind, file) in [
        ("review", "schemas/review-report.v1.schema.json"),
        ("verify", "schemas/verify-report.v1.schema.json"),
    ] {
        let output = aurlens(&["schema", kind]);
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        let committed = fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(file)).unwrap();
        assert_eq!(output.stdout, committed, "{kind}");
        let schema: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(schema["properties"]["schema_version"]["const"], 1);
    }
}
