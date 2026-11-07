use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output, Stdio};
use std::thread;
use tempfile::TempDir;

fn command(home: &TempDir) -> Command {
    let mut command = Command::new(
        std::env::var_os("AURLENS_VERIFY_BIN")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_aurlens").into()),
    );
    command
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"));
    command
}

fn setup(home: &TempDir, input: &str) -> Output {
    let mut child = command(home)
        .arg("setup")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn local_setup_tests_and_saves_connection_then_scan_reuses_it() {
    let home = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().unwrap()
    );
    let server = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut request = Vec::new();
            let header_end = loop {
                let mut buffer = [0; 4096];
                let n = stream.read(&mut buffer).unwrap();
                assert!(n > 0);
                request.extend_from_slice(&buffer[..n]);
                if let Some(index) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let size: usize = headers
                .lines()
                .find_map(|line| {
                    line.to_lowercase()
                        .strip_prefix("content-length:")
                        .map(str::trim)
                        .map(str::to_owned)
                })
                .unwrap()
                .parse()
                .unwrap();
            while request.len() < header_end + size {
                let mut buffer = [0; 4096];
                let n = stream.read(&mut buffer).unwrap();
                assert!(n > 0);
                request.extend_from_slice(&buffer[..n]);
            }
            let body: Value =
                serde_json::from_slice(&request[header_end..header_end + size]).unwrap();
            let data: Value =
                serde_json::from_str(body["messages"][1]["content"].as_str().unwrap()).unwrap();
            let opinion = json!({"snapshot_digest": data["snapshot_digest"], "summary":"Fixture reviewed.", "findings":[]});
            let body = json!({"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":opinion.to_string()}}]}).to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        }
    });
    let output = setup(&home, &format!("3\n{endpoint}\nfixture-model\ny\n"));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config = home.path().join("config/aurlens/config.toml");
    assert_eq!(
        fs::metadata(&config).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(config.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let package = tempfile::tempdir().unwrap();
    fs::write(package.path().join("PKGBUILD"), "pkgname=fixture\n").unwrap();
    let output = command(&home)
        .args(["scan", package.path().to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ai"]["state"], "complete");
    server.join().unwrap();
    let output = command(&home)
        .args([
            "scan",
            package.path().to_str().unwrap(),
            "--no-ai",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ai"]["state"], "not_run");
}

#[test]
fn failed_setup_and_cancel_preserve_previous_connection() {
    let home = tempfile::tempdir().unwrap();
    let directory = home.path().join("config/aurlens");
    fs::create_dir_all(&directory).unwrap();
    let saved = directory.join("config.toml");
    fs::write(&saved, "previous connection").unwrap();
    let output = setup(&home, "3\nn\n");
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(fs::read_to_string(&saved).unwrap(), "previous connection");
    let output = setup(
        &home,
        "3\ny\nhttp://127.0.0.1:9/v1/chat/completions\nfixture\ny\n",
    );
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(fs::read_to_string(&saved).unwrap(), "previous connection");
    assert_eq!(fs::read_dir(directory).unwrap().count(), 1);
}

#[test]
fn invalid_saved_config_is_reported_and_no_ai_bypasses_it() {
    let home = tempfile::tempdir().unwrap();
    let directory = home.path().join("config/aurlens");
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join("config.toml"), "invalid").unwrap();
    let package = tempfile::tempdir().unwrap();
    fs::write(package.path().join("PKGBUILD"), "pkgname=fixture\n").unwrap();
    let output = command(&home)
        .args(["scan", package.path().to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let output = command(&home)
        .args(["scan", package.path().to_str().unwrap(), "--no-ai"])
        .output()
        .unwrap();
    assert!(output.status.success());
}

#[test]
fn codex_setup_reuses_login_and_default_model_then_scan_reuses_connection() {
    let home = tempfile::tempdir().unwrap();
    let bin = home.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let codex = bin.join("codex");
    fs::write(&codex, r#"#!/usr/bin/python3
import json, sys
if sys.argv[1:] == ['login', 'status']:
    sys.exit(0)
assert sys.argv[1] == 'exec'
assert '--model' not in sys.argv
assert 'features.shell_tool=false' in sys.argv
source = json.loads(sys.stdin.read().split('Untrusted package snapshot JSON:\n', 1)[1])
opinion = {'snapshot_digest':source['snapshot_digest'], 'summary':'Fixture reviewed.', 'findings':[]}
print(json.dumps({'type':'item.completed','item':{'type':'agent_message','text':json.dumps(opinion)}}))
print(json.dumps({'type':'turn.completed'}))
"#).unwrap();
    fs::set_permissions(&codex, fs::Permissions::from_mode(0o700)).unwrap();
    let mut child = command(&home)
        .arg("setup")
        .env("PATH", &bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"1\ny\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let package = tempfile::tempdir().unwrap();
    fs::write(
        package.path().join("PKGBUILD"),
        "pkgname=fixture\ntouch must-not-exist\n",
    )
    .unwrap();
    let output = command(&home)
        .args(["scan", package.path().to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ai"]["state"], "complete");
    assert_eq!(report["ai"]["model"], "codex-default");
    assert!(!package.path().join("must-not-exist").exists());
}

#[test]
fn interrupted_key_entry_restores_terminal_and_preserves_saved_settings() {
    let binary = std::env::var_os("AURLENS_VERIFY_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_aurlens").into());
    let output = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/setup_terminal.py"
        ))
        .arg(binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
