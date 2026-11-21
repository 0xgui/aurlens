//! Report and configuration types.
//!
//! The report types serialize to the version 1 JSON documents described by the files in
//! `schemas/`. They also deserialize, so a consumer can parse a report into these types.
//! Deserialization ignores unknown fields: a later release may add fields without changing
//! `schema_version`.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    NoFindings,
    ManualReview,
    Blocked,
    Incomplete,
}

impl Decision {
    pub fn exit_code(self) -> u8 {
        match self {
            Self::NoFindings => 0,
            Self::ManualReview => 1,
            Self::Blocked => 2,
            Self::Incomplete => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Review,
    Block,
}

/// How much a finding, or a whole review, should weigh with the person
/// deciding. It is a reading of the findings, not of the package: `low`
/// says nothing was found in the recipe, not that the software is safe.
///
/// The decision says what has to happen (nothing, a person's yes, a stop).
/// The risk says how hard to look.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    /// Nothing found, or notes only.
    Low,
    /// Something a person has to decide about, of a kind that legitimate
    /// recipes also do: an unverified download, an unencrypted source, a
    /// file nobody read.
    Medium,
    /// The package takes root-level or lasting power, or reaches for
    /// credentials: a setuid file, a write to the system as root, sudoers,
    /// accounts, pacman's trust, a startup file.
    High,
    /// Behaviour with no honest use in a recipe. The review is blocked.
    Critical,
    /// The review could not be completed, so there is nothing to grade.
    #[default]
    Unknown,
}

impl Risk {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
            Self::Unknown => "unknown",
        }
    }

    /// The grade as advice, in two or three words.
    pub fn advice(self) -> &'static str {
        match self {
            Self::Low => "Looks fine",
            Self::Medium => "Check first",
            Self::High => "Be careful",
            Self::Critical => "Do not install",
            Self::Unknown => "Could not check",
        }
    }

    /// What the advice rests on, in one sentence.
    pub fn meaning(self) -> &'static str {
        match self {
            Self::Low => {
                "Nothing in the recipe needs a decision. That says nothing about the software it downloads."
            }
            Self::Medium => {
                "The recipe does something a person should look at, of a kind legitimate recipes also do."
            }
            Self::High => {
                "The package takes root-level or lasting power, reaches for credentials, or hides what it runs. Install it only if you trust where it comes from."
            }
            Self::Critical => "The recipe does something with no honest use in a package.",
            Self::Unknown => {
                "The review could not be completed, so nothing can be said about the recipe."
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub path: String,
    pub line: usize,
    pub quote: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub source: String,
    pub severity: Severity,
    pub message: String,
    pub evidence: Vec<Evidence>,
    /// Set when the report is assembled, from the rule and the severity.
    #[serde(default)]
    pub risk: Risk,
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub max_files: usize,
    pub max_entries: usize,
    pub max_depth: usize,
    pub max_file_bytes: usize,
    pub max_total_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_files: 256,
            max_entries: 1024,
            max_depth: 16,
            max_file_bytes: 262_144,
            max_total_bytes: 2_097_152,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct PackageFile {
    pub path: String,
    pub mode: u32,
    /// The content, for a text file. Empty for an opaque one.
    pub text: String,
    /// The hash of the file's bytes.
    pub sha256: String,
    /// The file is not text (an image, a binary key). Its content is not
    /// inspected and not sent anywhere; its hash is part of the snapshot.
    pub opaque: bool,
    /// The size of the file in bytes.
    pub size: usize,
    /// For an opaque file, the format its first bytes are those of
    /// ("PNG image"). Empty for a text file.
    pub format: &'static str,
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub files: Vec<PackageFile>,
    pub directories: Vec<(String, u32)>,
    pub digest: String,
    pub excluded: Vec<String>,
    pub(crate) identities: Vec<(String, u64, u64)>,
    pub(crate) ancestry: Vec<(u64, u64)>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Change {
    pub path: String,
    pub kind: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

#[derive(Clone, Debug)]
pub enum AiConfig {
    Http(HttpConfig),
    Codex(CodexConfig),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpConfig {
    pub endpoint: String,
    pub model: String,
    pub api_key_env: Option<String>,
    pub api_key_file: Option<std::path::PathBuf>,
    #[serde(default)]
    pub allow_loopback_http: bool,
    #[serde(default)]
    pub send_source: bool,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_request_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "default_response_bytes")]
    pub max_response_bytes: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexConfig {
    pub executable: std::path::PathBuf,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub send_source: bool,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_request_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "default_response_bytes")]
    pub max_response_bytes: usize,
}

fn default_timeout() -> u64 {
    30
}
fn default_request_bytes() -> usize {
    4_194_304
}
fn default_response_bytes() -> usize {
    131_072
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AiResult {
    NotRun {
        reason: String,
    },
    Complete {
        model: String,
        endpoint_origin: String,
        summary: String,
        findings: Vec<Finding>,
    },
    Incomplete {
        reason: String,
    },
}

impl Default for AiResult {
    fn default() -> Self {
        Self::NotRun {
            reason: "not_requested".into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Coverage {
    pub complete: bool,
    pub policy: String,
    pub scope: String,
    pub reviewed_files: usize,
    pub reviewed_bytes: usize,
    pub excluded: Vec<String>,
    pub issues: Vec<String>,
    /// Files that are not text. They are covered by the snapshot digest, so
    /// a change to one is noticed, but nothing looked inside them.
    #[serde(default)]
    pub uninspected: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileSummary {
    pub path: String,
    pub mode: u32,
    pub size: usize,
    pub sha256: String,
    /// True for a file that is not text and was not inspected.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub opaque: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewReport {
    pub schema_version: u32,
    pub tool_version: String,
    pub decision: Decision,
    /// The highest risk among the findings; `unknown` when incomplete.
    #[serde(default)]
    pub risk: Risk,
    pub exit_code: u8,
    pub snapshot_digest: Option<String>,
    pub baseline_digest: Option<String>,
    pub files: Vec<FileSummary>,
    pub findings: Vec<Finding>,
    pub changes: Option<Vec<Change>>,
    pub coverage: Coverage,
    pub ai: AiResult,
    pub revalidated: bool,
    pub notice: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Matched,
    Changed,
    Incomplete,
}

impl VerificationStatus {
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Matched => 0,
            Self::Changed | Self::Incomplete => 3,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub schema_version: u32,
    pub operation: String,
    pub status: VerificationStatus,
    pub exit_code: u8,
    pub expected_digest: String,
    pub snapshot_digest: Option<String>,
    pub issues: Vec<String>,
    pub notice: String,
}
