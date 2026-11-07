use aurlens::{AiResult, ReviewOptions, load_config, review};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::termios::{
    LocalModes, OptionalActions, SpecialCodeIndex, Termios, tcgetattr, tcsetattr,
};
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub fn config_path() -> Result<PathBuf, &'static str> {
    let base = match std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
        Some(base) => PathBuf::from(base),
        None => PathBuf::from(std::env::var_os("HOME").ok_or("Home directory is unavailable.")?)
            .join(".config"),
    };
    if !base.is_absolute() {
        return Err("The user configuration directory must be absolute.");
    }
    Ok(base.join("aurlens/config.toml"))
}

pub fn run() -> Result<(), String> {
    println!(
        "Choose your AI connection:\n  1. Codex (use your Codex login)\n  2. API provider\n  3. Local model"
    );
    let choice = prompt("Connection", Some("1"))?;
    if !matches!(choice.as_str(), "1" | "2" | "3") {
        return Err("Choose 1, 2, or 3.".into());
    }
    let config_path = config_path()?;
    let directory = config_path
        .parent()
        .ok_or("Invalid configuration directory.")?;
    fs::create_dir_all(directory).map_err(|_| "Could not create the configuration directory.")?;
    let metadata = fs::symlink_metadata(directory)
        .map_err(|_| "Could not inspect the configuration directory.")?;
    if !metadata.is_dir() || metadata.uid() != rustix::process::getuid().as_raw() {
        return Err("The configuration directory must be a directory owned by you.".into());
    }
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
        .map_err(|_| "Could not protect the configuration directory.")?;
    if config_path.symlink_metadata().is_ok()
        && prompt("Replace your saved AURLens connection? y/N", Some("n"))?.to_lowercase() != "y"
    {
        return Err("Setup cancelled; saved connection kept.".into());
    }
    let mut ai = toml::Table::new();
    let mut key_file = None;
    if choice == "1" {
        let executable = find_codex()
            .ok_or("Codex was not found. Install the Codex CLI, then run aurlens setup again.")?;
        let logged_in = Command::new(&executable)
            .args(["login", "status"])
            .output()
            .map_err(|_| "Could not check Codex login.")?
            .status
            .success();
        if !logged_in {
            println!("Opening the Codex login flow.");
            if !Command::new(&executable)
                .arg("login")
                .status()
                .map_err(|_| "Could not start Codex login.")?
                .success()
            {
                return Err(
                    "Codex login did not finish. Run codex login and try setup again.".into(),
                );
            }
        }
        ai.insert("backend".into(), "codex".into());
        ai.insert(
            "executable".into(),
            executable
                .to_str()
                .ok_or("Codex path must be UTF-8.")?
                .into(),
        );
    } else {
        let local = choice == "3";
        let endpoint = prompt(
            "Chat Completions endpoint",
            local.then_some("http://127.0.0.1:11434/v1/chat/completions"),
        )?;
        let model = prompt("Model name", None)?;
        ai.insert("backend".into(), "http".into());
        ai.insert("endpoint".into(), endpoint.into());
        ai.insert("model".into(), model.into());
        ai.insert("allow_loopback_http".into(), local.into());
        if !local {
            let key = secret()?;
            if !key.is_empty() {
                let mut file = tempfile::NamedTempFile::new_in(directory)
                    .map_err(|_| "Could not create private credential storage.")?;
                file.as_file()
                    .set_permissions(fs::Permissions::from_mode(0o600))
                    .map_err(|_| "Could not protect credential storage.")?;
                file.write_all(key.as_bytes())
                    .map_err(|_| "Could not save the API key.")?;
                file.as_file()
                    .sync_all()
                    .map_err(|_| "Could not save the API key.")?;
                ai.insert(
                    "api_key_file".into(),
                    file.path()
                        .to_str()
                        .ok_or("Configuration path must be UTF-8.")?
                        .into(),
                );
                key_file = Some(file);
            }
        }
    }
    println!(
        "AI review sends package recipe text to this connection. Setup will send only a small built-in test recipe."
    );
    if prompt("Enable this connection? y/N", Some("n"))?.to_lowercase() != "y" {
        return Err("Setup cancelled; saved connection kept.".into());
    }
    ai.insert("send_source".into(), true.into());
    ai.insert("timeout_seconds".into(), 120.into());
    let document = toml::Table::from_iter([("ai".into(), toml::Value::Table(ai))]);
    let text =
        toml::to_string_pretty(&document).map_err(|_| "Could not encode the configuration.")?;
    let mut pending = tempfile::NamedTempFile::new_in(directory)
        .map_err(|_| "Could not create the configuration.")?;
    pending
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| "Could not protect the configuration.")?;
    pending
        .write_all(text.as_bytes())
        .map_err(|_| "Could not write the configuration.")?;
    let config = load_config(pending.path()).map_err(|error| error.to_string())?;
    let fixture = tempfile::tempdir().map_err(|_| "Could not create the connection test.")?;
    fs::write(fixture.path().join("PKGBUILD"), "pkgname=aurlens-connection-test\npkgver=1\npkgrel=1\npkgdesc='Inert connection test'\narch=('any')\nlicense=('MIT')\npackage() { :; }\n")
        .map_err(|_| "Could not create the connection test.")?;
    println!("Testing the connection…");
    let report = review(
        fixture.path(),
        &ReviewOptions {
            ai: Some(config),
            ..Default::default()
        },
    );
    if !matches!(report.ai, AiResult::Complete { .. })
        || !report.coverage.complete
        || !report.revalidated
    {
        let reason = match report.ai {
            AiResult::Incomplete { reason } | AiResult::NotRun { reason } => reason,
            _ => "connection_test_incomplete".into(),
        };
        return Err(format!(
            "Connection test failed ({}). Saved connection kept. Run aurlens setup to retry.",
            reason.escape_debug()
        ));
    }
    pending
        .as_file()
        .sync_all()
        .map_err(|_| "Could not save the configuration.")?;
    let kept_key = key_file
        .map(|file| file.keep())
        .transpose()
        .map_err(|_| "Could not save the API key.")?;
    if pending.persist(&config_path).is_err() {
        if let Some((_, path)) = kept_key {
            let _ = fs::remove_file(path);
        }
        return Err("Could not save the configuration.".into());
    }
    println!("Connection ready. Run: aurlens scan /path/to/package");
    Ok(())
}

fn prompt(label: &str, default: Option<&str>) -> Result<String, String> {
    let suffix = default
        .map(|value| format!(" [{value}]"))
        .unwrap_or_default();
    print!("{label}{suffix}: ");
    io::stdout()
        .flush()
        .map_err(|_| "Could not write the setup prompt.")?;
    let mut value = String::new();
    if io::stdin()
        .read_line(&mut value)
        .map_err(|_| "Could not read setup input.")?
        == 0
    {
        return Err("Setup input ended; saved connection kept.".into());
    }
    let value = value.trim();
    if value.is_empty() {
        return default
            .map(str::to_owned)
            .ok_or_else(|| "A value is required.".into());
    }
    if value.len() > 4096 || value.chars().any(char::is_control) {
        return Err("Setup input contains invalid characters or is too long.".into());
    }
    Ok(value.into())
}

struct EchoGuard {
    terminal: Termios,
    default_signals: Arc<AtomicBool>,
}
impl Drop for EchoGuard {
    fn drop(&mut self) {
        let _ = tcsetattr(io::stdin(), OptionalActions::Flush, &self.terminal);
        self.default_signals.store(true, Ordering::SeqCst);
    }
}

fn secret() -> Result<String, String> {
    let default_signals = Arc::new(AtomicBool::new(true));
    for signal in [SIGINT, SIGTERM, SIGHUP] {
        signal_hook::flag::register_conditional_default(signal, default_signals.clone())
            .map_err(|_| "Could not prepare safe API key entry.")?;
    }
    let mut signals = Signals::new([SIGINT, SIGTERM, SIGHUP])
        .map_err(|_| "Could not prepare safe API key entry.")?;
    let original = tcgetattr(io::stdin())
        .map_err(|_| "Enter API keys in an interactive terminal. They are never accepted as command arguments.")?;
    let mut hidden = original.clone();
    hidden
        .local_modes
        .remove(LocalModes::ECHO | LocalModes::ECHONL | LocalModes::ICANON | LocalModes::ISIG);
    hidden.special_codes[SpecialCodeIndex::VMIN] = 0;
    hidden.special_codes[SpecialCodeIndex::VTIME] = 0;
    let guard = EchoGuard {
        terminal: original,
        default_signals: default_signals.clone(),
    };
    default_signals.store(false, Ordering::SeqCst);
    tcsetattr(io::stdin(), OptionalActions::Now, &hidden)
        .map_err(|_| "Could not hide API key input.")?;
    print!("API key (hidden; Enter for none): ");
    io::stdout()
        .flush()
        .map_err(|_| "Could not write the setup prompt.")?;
    let result = read_secret(&mut signals);
    drop(guard);
    println!();
    result
}

fn read_secret(signals: &mut Signals) -> Result<String, String> {
    let input = io::stdin();
    let mut descriptors = [PollFd::new(&input, PollFlags::IN)];
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: 100_000_000,
    };
    let mut bytes = Vec::new();
    loop {
        if signals.pending().next().is_some() {
            return Err("Setup cancelled; saved connection kept.".into());
        }
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(0) | Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return Err("Could not read API key input.".into()),
            Ok(_) => {}
        }
        let mut byte = [0];
        match rustix::io::read(&input, &mut byte) {
            Ok(0) => return Err("API key input ended; saved connection kept.".into()),
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return Err("Could not read API key input.".into()),
            Ok(_) => {}
        }
        match byte[0] {
            b'\n' | b'\r' => {
                return String::from_utf8(bytes).map_err(|_| "API key must be UTF-8.".into());
            }
            3 | 4 => return Err("Setup cancelled; saved connection kept.".into()),
            8 | 127 => {
                bytes.pop();
            }
            0..=31 => return Err("API key contains an invalid character.".into()),
            value if bytes.len() < 4096 => bytes.push(value),
            _ => return Err("API key is too long.".into()),
        }
    }
}

fn find_codex() -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| directory.join("codex"))
        .find(|path| {
            fs::metadata(path).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
        .and_then(|path| path.canonicalize().ok())
}
