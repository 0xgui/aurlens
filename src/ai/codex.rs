use super::{AiError, INSTRUCTIONS, error};
use crate::model::CodexConfig;
use serde_json::{Value, json};
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// Ignore ambient configuration, then restrict the supported exec profile explicitly.
// Model metadata may still register utility tools (such as apply_patch); shell_tool
// disables the entire execution-tool registration path. Any tool activity fails.
const OVERRIDES: &[&str] = &[
    "features.shell_tool=false",
    "features.shell_snapshot=false",
    "features.shell_snapshot_v2=false",
    "features.deferred_executor=false",
    "features.request_permissions_tool=false",
    "features.request_rule=false",
    "features.token_budget=false",
    "features.current_time_reminder=false",
    "features.sleep_tool=false",
    "features.send_message_to_user_async=false",
    "features.recommended_plugins=false",
    "features.tool_suggest=false",
    "features.tool_search=false",
    "features.computer_use=false",
    "features.memory_tool=false",
    "features.external_agent_memory_import=false",
    "features.connectors=false",
    "features.skill_search=false",
    "features.skill_mcp_dependency_install=false",
    "features.skill_env_var_dependency_prompt=false",
    "features.code_mode_host=false",
    "features.code_mode_tool_search=false",
    "features.js_repl_tools_only=false",
    "features.remote_control=false",
    "features.skip_host_skill_discovery=true",
    "features.unified_exec=false",
    "features.plugins=false",
    "features.plugin_hooks=false",
    "features.hooks=false",
    "features.codex_hooks=false",
    "features.apps=false",
    "features.enable_mcp_apps=false",
    "features.apps_early_resource_discovery=false",
    "features.multi_agent=false",
    "features.multi_agent_v2=false",
    "features.multi_agent_v2_dynamic_tools=false",
    "features.memories=false",
    "features.view_image=false",
    "features.browser_use=false",
    "features.browser_use_external=false",
    "features.in_app_browser=false",
    "features.standalone_web_search=false",
    "features.web_search=false",
    "features.web_search_cached=false",
    "features.web_search_request=false",
    "features.image_generation=false",
    "features.code_mode=false",
    "features.js_repl=false",
    "features.request_permissions=false",
    "agents.enabled=false",
    "plugins._default.enabled=false",
    "apps._default.enabled=false",
    "cloud.skills.enabled=false",
    "skills.bundled.enabled=false",
    "skills.include_instructions=false",
    "tools.update_plan.enabled=false",
    "tools.experimental_request_user_input.enabled=false",
    "web_search=\"disabled\"",
    "mcp_servers={}",
    "hooks={}",
    "project_doc_max_bytes=0",
    "project_doc_fallback_filenames=[]",
    "approval_policy=\"never\"",
];

fn schema() -> Value {
    let evidence = json!({"type":"object","additionalProperties":false,
        "required":["path","line","quote"],"properties":{
            "path":{"type":"string"},"line":{"type":"integer"},"quote":{"type":"string"}}});
    let finding = json!({"type":"object","additionalProperties":false,
        "required":["severity","message","evidence"],"properties":{
            "severity":{"type":"string","enum":["review","block"]},
            "message":{"type":"string"},"evidence":{"type":"array","items":evidence}}});
    json!({"type":"object","additionalProperties":false,
        "required":["snapshot_digest","summary","findings"],"properties":{
            "snapshot_digest":{"type":"string"},"summary":{"type":"string"},
            "findings":{"type":"array","items":finding}}})
}

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        // Kill descendants too: a completed leader need not have closed their pipes.
        if let Some(pid) = rustix::process::Pid::from_raw(self.0.id() as i32) {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn nonblocking(pipe: &impl AsFd) -> Result<(), AiError> {
    let flags = rustix::fs::fcntl_getfl(pipe).map_err(|_| transport())?;
    rustix::fs::fcntl_setfl(pipe, flags | rustix::fs::OFlags::NONBLOCK).map_err(|_| transport())
}

fn transport() -> AiError {
    error(
        "ai_codex_transport",
        "Codex review failed. Check Codex login or run aurlens setup.",
    )
}

fn read_available(
    pipe: &mut impl Read,
    bytes: &mut Vec<u8>,
    limit: usize,
) -> Result<bool, AiError> {
    let mut buffer = [0; 8192];
    // A fixed batch keeps continuously writing processes subject to the deadline.
    for _ in 0..16 {
        match pipe.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                if count > limit.saturating_sub(bytes.len()) {
                    return Err(error(
                        "ai_response_size",
                        "Codex output exceeds its byte limit.",
                    ));
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
            Err(failure) if failure.kind() == io::ErrorKind::WouldBlock => break,
            Err(failure) if failure.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(transport()),
        }
    }
    Ok(false)
}

pub(super) fn review(source: &Value, config: &CodexConfig) -> Result<Vec<u8>, AiError> {
    let prompt =
        format!("{INSTRUCTIONS}\n\nUntrusted package snapshot JSON:\n{source}").into_bytes();
    if prompt.len() > config.max_request_bytes {
        return Err(error(
            "ai_request_size",
            "AI request exceeds its byte limit.",
        ));
    }
    let temporary = tempfile::Builder::new()
        .prefix("aurlens-codex-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .map_err(|_| transport())?;
    let cwd = temporary.path().join("review");
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&cwd)
        .map_err(|_| transport())?;
    let schema_path = temporary.path().join("opinion.schema.json");
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&schema_path)
        .and_then(|mut file| file.write_all(schema().to_string().as_bytes()))
        .map_err(|_| transport())?;
    let mut command = Command::new(&config.executable);
    command
        .args([
            "exec",
            "--ignore-user-config",
            "--ignore-rules",
            "--strict-config",
            "--ephemeral",
            "--sandbox",
            "read-only",
            "--skip-git-repo-check",
            "--json",
            "--color",
            "never",
            "--output-schema",
        ])
        .arg(&schema_path);
    if !config.model.is_empty() {
        command.arg("--model").arg(&config.model);
    }
    for value in OVERRIDES {
        command.arg("-c").arg(value);
    }
    command.arg("-").current_dir(cwd).env_clear();
    // Preserve supported login lookup and ordinary runtime/network settings only.
    // Never read auth material or inherit provider endpoint/configuration overrides.
    for name in [
        "HOME",
        "USER",
        "LOGNAME",
        "PATH",
        "CODEX_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "https_proxy",
        "http_proxy",
        "all_proxy",
        "no_proxy",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .env("NO_COLOR", "1")
        .env("TMPDIR", temporary.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let deadline = Instant::now() + Duration::from_secs(config.timeout_seconds);
    let mut process = Process(command.spawn().map_err(|_| {
        error(
            "ai_codex_start",
            "Could not start the restricted Codex profile. Update Codex or run aurlens setup.",
        )
    })?);
    let mut stdin = process.0.stdin.take();
    let mut stdout = process.0.stdout.take().ok_or_else(transport)?;
    let mut stderr = process.0.stderr.take().ok_or_else(transport)?;
    nonblocking(stdin.as_ref().ok_or_else(transport)?)?;
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let (mut output, mut diagnostic) = (Vec::new(), Vec::new());
    let (mut stdout_done, mut stderr_done) = (false, false);
    let mut written = 0;
    let mut status = None;
    loop {
        if Instant::now() >= deadline {
            return Err(error("ai_timeout", "Codex review timed out."));
        }
        if let Some(pipe) = &mut stdin {
            match pipe.write(&prompt[written..]) {
                Ok(count) => written += count,
                Err(failure)
                    if matches!(
                        failure.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(transport()),
            }
            if written == prompt.len() {
                stdin = None;
            }
        }
        if !stdout_done {
            stdout_done = read_available(
                &mut stdout,
                &mut output,
                config.max_response_bytes.saturating_mul(2) + 65_536,
            )?;
        }
        if !stderr_done {
            stderr_done = read_available(&mut stderr, &mut diagnostic, 65_536)?;
        }
        if status.is_none() {
            status = process.0.try_wait().map_err(|_| transport())?;
        }
        if let Some(status) = status {
            if !status.success() {
                return Err(error(
                    "ai_codex_exit",
                    "Codex could not complete the restricted review. Check login and update Codex, or run aurlens setup.",
                ));
            }
            if stdout_done && stderr_done {
                if written != prompt.len() {
                    return Err(transport());
                }
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    final_response(&output, config.max_response_bytes)
}

fn final_response(bytes: &[u8], limit: usize) -> Result<Vec<u8>, AiError> {
    let invalid = || {
        error(
            "ai_codex_events",
            "Codex returned unsupported or incomplete review events.",
        )
    };
    let mut final_message = None;
    let mut completed = false;
    for (index, line) in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        if index >= 1024 || completed {
            return Err(invalid());
        }
        let event: Value = serde_json::from_slice(line).map_err(|_| invalid())?;
        match event.get("type").and_then(Value::as_str) {
            Some("thread.started" | "turn.started") => {}
            Some("item.started" | "item.updated" | "item.completed") => {
                let item = event.get("item").ok_or_else(invalid)?;
                match item.get("type").and_then(Value::as_str) {
                    Some("reasoning") => {}
                    Some("agent_message") if event["type"] == "item.completed" => {
                        let text = item
                            .get("text")
                            .and_then(Value::as_str)
                            .ok_or_else(invalid)?;
                        if text.len() > limit {
                            return Err(error(
                                "ai_response_size",
                                "AI response exceeds its byte limit.",
                            ));
                        }
                        if final_message.replace(text.as_bytes().to_vec()).is_some() {
                            return Err(invalid());
                        }
                    }
                    _ => {
                        return Err(error(
                            "ai_codex_tool_activity",
                            "Codex attempted an unsupported operation; review is incomplete.",
                        ));
                    }
                }
            }
            Some("turn.completed") => completed = true,
            _ => return Err(invalid()),
        }
    }
    if !completed {
        return Err(invalid());
    }
    final_message.ok_or_else(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn config(executable: std::path::PathBuf) -> CodexConfig {
        CodexConfig {
            executable,
            model: "fixture-model".into(),
            send_source: true,
            timeout_seconds: 1,
            max_request_bytes: 4_194_304,
            max_response_bytes: 131_072,
        }
    }

    fn fixture(program: &str) -> (tempfile::TempDir, CodexConfig) {
        let temporary = tempfile::tempdir().unwrap();
        let executable = temporary.path().join("codex");
        fs::write(&executable, format!("#!/usr/bin/python3\n{program}\n")).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let cfg = config(executable);
        (temporary, cfg)
    }

    fn events(text: &str) -> String {
        format!(
            "{}\n{}\n{}\n{}\n",
            json!({"type":"thread.started","thread_id":"fixture"}),
            json!({"type":"turn.started"}),
            json!({"type":"item.completed","item":{"id":"item_0","type":"agent_message","text":text}}),
            json!({"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}})
        )
    }

    #[test]
    fn supported_profile_sends_only_stdin_and_cleans_private_cwd() {
        let output =
            events("{\"snapshot_digest\":\"abc\",\"summary\":\"Reviewed.\",\"findings\":[]}");
        let (temporary, cfg) = fixture(&format!(
            r#"
import os, sys, json
from pathlib import Path
args = sys.argv[1:]
assert args[0] == 'exec' and args[-1] == '-'
for flag in ['--ignore-user-config','--ignore-rules','--strict-config','--ephemeral','--skip-git-repo-check','--json']:
    assert flag in args
assert args[args.index('--sandbox')+1] == 'read-only'
assert args[args.index('--model')+1] == 'fixture-model'
assert list(Path.cwd().iterdir()) == []
assert Path.cwd().stat().st_mode & 0o077 == 0
assert Path.cwd().parent.stat().st_mode & 0o077 == 0
assert json.loads(Path(args[args.index('--output-schema')+1]).read_text())['additionalProperties'] is False
assert 'OPENAI_API_KEY' not in os.environ and 'OPENAI_BASE_URL' not in os.environ
assert 'features.shell_tool=false' in args
assert 'features.multi_agent_v2=false' in args
assert 'project_doc_max_bytes=0' in args
assert not any('dangerously' in arg for arg in args)
text = sys.stdin.read()
assert 'PRIVATE_FIXTURE_SOURCE' in text
Path(__file__).with_name('observed-cwd').write_text(str(Path.cwd()))
sys.stdout.write({output:?})
"#
        ));
        let result = review(&json!({"text":"PRIVATE_FIXTURE_SOURCE"}), &cfg);
        assert!(result.is_ok(), "{result:?}");
        let cwd = fs::read_to_string(temporary.path().join("observed-cwd")).unwrap();
        assert!(!std::path::Path::new(&cwd).exists());
    }

    #[test]
    fn optional_model_uses_codex_default() {
        let (_temporary, mut cfg) = fixture(&format!(
            "import sys\nassert '--model' not in sys.argv\nsys.stdin.read()\nsys.stdout.write({:?})",
            events("{}")
        ));
        cfg.model.clear();
        assert_eq!(review(&json!({}), &cfg).unwrap(), b"{}");
    }

    #[test]
    fn rejects_tools_duplicate_missing_malformed_and_oversized_packets() {
        let valid = events("{}");
        let tool = json!({"type":"item.started","item":{"type":"command_execution","command":"touch marker"}}).to_string();
        assert_eq!(
            final_response(tool.as_bytes(), 1024).unwrap_err().code,
            "ai_codex_tool_activity"
        );
        for bytes in [
            "not json".to_string(),
            String::new(),
            valid.replace("turn.completed", "turn.failed"),
            valid.replace("\"turn.completed\"", "\"unknown\""),
            format!("{valid}{valid}"),
        ] {
            assert!(final_response(bytes.as_bytes(), 1024).is_err());
        }
        assert_eq!(
            final_response(events("too long").as_bytes(), 2)
                .unwrap_err()
                .code,
            "ai_response_size"
        );
        let duplicate = format!(
            "{}\n{}\n{}\n",
            json!({"type":"item.completed","item":{"type":"agent_message","text":"{}"}}),
            json!({"type":"item.completed","item":{"type":"agent_message","text":"{}"}}),
            json!({"type":"turn.completed"})
        );
        assert!(final_response(duplicate.as_bytes(), 1024).is_err());
    }

    #[test]
    fn concurrent_floods_nonzero_and_blocked_stdin_are_bounded() {
        for program in [
            "import os\nwhile True:\n os.write(1,b'x'*8192)\n os.write(2,b'y'*8192)",
            "import os\nos.write(2,b'PRIVATE_SECRET_AND_SOURCE')\nraise SystemExit(7)",
            "import time\ntime.sleep(30)",
        ] {
            let (_temporary, cfg) = fixture(program);
            let start = Instant::now();
            let error = review(&json!({"text":"x".repeat(1_000_000)}), &cfg).unwrap_err();
            assert!(start.elapsed() < Duration::from_secs(3));
            assert!(!error.to_string().contains("PRIVATE_SECRET_AND_SOURCE"));
            assert!(
                [
                    "ai_response_size",
                    "ai_codex_exit",
                    "ai_codex_transport",
                    "ai_timeout"
                ]
                .contains(&error.code)
            );
        }
    }

    #[test]
    fn timeout_kills_descendants_and_cleans_cwd() {
        let (_temporary, cfg) = fixture(
            r#"
import os, time
from pathlib import Path
Path(__file__).with_name('observed-cwd').write_text(str(Path.cwd()))
if os.fork() == 0:
    time.sleep(2)
    Path(__file__).with_name('descendant-survived').write_text('bad')
    os._exit(0)
time.sleep(30)
"#,
        );
        assert_eq!(
            review(&json!({"text":"source"}), &cfg).unwrap_err().code,
            "ai_timeout"
        );
        let cwd = fs::read_to_string(cfg.executable.with_file_name("observed-cwd")).unwrap();
        assert!(!std::path::Path::new(&cwd).exists());
        std::thread::sleep(Duration::from_millis(1300));
        assert!(
            !cfg.executable
                .with_file_name("descendant-survived")
                .exists()
        );
    }

    #[test]
    fn source_limit_rejects_before_starting_executable() {
        let mut cfg = config("/does/not/exist".into());
        cfg.max_request_bytes = 1;
        assert_eq!(
            review(&json!({}), &cfg).unwrap_err().code,
            "ai_request_size"
        );
    }
}
