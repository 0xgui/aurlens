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

#[derive(Clone, Debug)]
pub struct PackageFile {
    pub path: String,
    pub mode: u32,
    pub text: String,
    pub sha256: String,
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
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileSummary {
    pub path: String,
    pub mode: u32,
    pub size: usize,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewReport {
    pub schema_version: u32,
    pub tool_version: String,
    pub decision: Decision,
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
