use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    Trusted,
    Untrusted,
    #[default]
    Unknown,
    NotApplicable,
}

impl fmt::Display for SignatureStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Trusted => "trusted",
            Self::Untrusted => "untrusted",
            Self::Unknown => "unknown",
            Self::NotApplicable => "not_applicable",
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    #[must_use]
    pub const fn from_score(score: u8) -> Self {
        match score {
            90..=u8::MAX => Self::Critical,
            65..=89 => Self::High,
            35..=64 => Self::Medium,
            15..=34 => Self::Low,
            _ => Self::Info,
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanVerdict {
    #[default]
    Clean,
    LowRisk,
    Suspicious,
    Malicious,
    Skipped,
    Error,
    Cancelled,
}

impl fmt::Display for ScanVerdict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Clean => "clean",
            Self::LowRisk => "low_risk",
            Self::Suspicious => "suspicious",
            Self::Malicious => "malicious",
            Self::Skipped => "skipped",
            Self::Error => "error",
            Self::Cancelled => "cancelled",
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanProfile {
    #[default]
    Quick,
    Full,
    Startup,
    Downloads,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskAssessment {
    pub score: u8,
    pub severity: Severity,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessRecord {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub path: String,
    pub thread_count: u32,
    pub working_set_bytes: u64,
    pub cpu_percent: f32,
    pub signature: SignatureStatus,
    pub accessible: bool,
    pub identity: String,
    pub is_new: bool,
    pub risk: RiskAssessment,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkEndpoint {
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: u32,
    pub process_name: String,
    pub process_path: String,
    pub remote_hostname: String,
    pub reputation: String,
    pub reputation_reason: String,
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
    pub send_rate_bps: Option<f64>,
    pub receive_rate_bps: Option<f64>,
    pub usage_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityEvent {
    pub id: Option<i64>,
    pub event_type: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub process_id: Option<u32>,
    pub path: String,
    pub created_at: String,
    pub resolved: bool,
}

/// One normalized historical observation shown in the investigation timeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimelineEvent {
    pub id: Option<i64>,
    pub category: String,
    pub action: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub process_id: Option<u32>,
    pub path: String,
    pub remote_address: String,
    pub correlation_id: String,
    pub occurred_at: String,
}

/// Cursor-paginated timeline result. `next_before_id` is passed to the next query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimelinePage {
    pub events: Vec<TimelineEvent>,
    pub next_before_id: Option<i64>,
}

/// A startup mechanism discovered by the native service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistenceItem {
    pub id: String,
    pub category: String,
    pub name: String,
    pub command: String,
    pub location: String,
    pub state: String,
    pub risk: Severity,
    pub evidence: Vec<String>,
    pub detected_at: String,
    pub response_capability: String,
}

/// Current persistence inventory plus honest per-source coverage notes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistenceInventory {
    pub items: Vec<PersistenceItem>,
    pub collected_at: String,
    pub coverage: Vec<CoverageNote>,
}

/// Explicit response operation selected by a local authenticated user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseActionKind {
    TerminateProcess,
    TerminateProcessTree,
    SuspendProcess,
    ResumeProcess,
    QuarantineFile,
    BlockRemoteAddress,
    UnblockRemoteAddress,
    DisablePersistence,
    RestorePersistence,
}

/// Narrow, identity-bound request for a privileged response operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseActionRequest {
    pub action: ResponseActionKind,
    pub process_id: Option<u32>,
    pub expected_path: String,
    pub target: String,
    pub remote_address: String,
    pub duration_minutes: Option<u32>,
    pub persistence_id: String,
    pub rollback_id: String,
    pub confirmation: String,
}

/// Auditable result returned after a privileged response operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseActionResult {
    pub action: ResponseActionKind,
    pub target: String,
    pub outcome: String,
    pub rollback_id: Option<String>,
    pub expires_at: Option<String>,
    pub audit_event_id: i64,
}

/// A bounded, explainable capability inferred from static content. Capabilities
/// are evidence, not a malware verdict: high-risk decisions require independent
/// runtime or trust signals as well.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatCapability {
    pub category: String,
    pub mitre_technique: String,
    pub confidence: u8,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanFinding {
    pub path: String,
    pub verdict: ScanVerdict,
    pub score: u8,
    pub reasons: Vec<String>,
    pub sha256: String,
    pub size_bytes: u64,
    pub signature: SignatureStatus,
    pub amsi_result: String,
    pub yara_status: String,
    pub yara_matches: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<ThreatCapability>,
    pub scanned_at: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanJobState {
    #[default]
    Queued,
    Running,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanJobStatus {
    pub scan_id: String,
    pub target: String,
    pub state: ScanJobState,
    pub finding: Option<ScanFinding>,
    pub findings: Vec<ScanFinding>,
    pub files_scanned: u64,
    pub total_files: u64,
    pub current_path: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineRecord {
    pub id: String,
    pub original_path: String,
    pub sha256: String,
    pub reason: String,
    pub created_at: String,
    pub restored_at: Option<String>,
    pub restored_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentStatus {
    pub active_version: String,
    pub previous_version: Option<String>,
    pub source: String,
    pub manifest_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExclusionRecord {
    pub path: String,
    pub recursive: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedHashRecord {
    pub sha256: String,
    pub label: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    Active,
    Limited,
    Unavailable,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageNote {
    pub source: String,
    pub state: CoverageState,
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemSnapshot {
    pub processes: Vec<ProcessRecord>,
    pub endpoints: Vec<NetworkEndpoint>,
    pub captured_at: String,
    pub elevated: bool,
    pub coverage: Vec<CoverageNote>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceHealth {
    pub version: String,
    pub protocol: u16,
    pub service_state: String,
    pub database_state: String,
    pub content_version: String,
    pub uptime_seconds: u64,
    pub coverage: Vec<CoverageNote>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_thresholds_preserve_v02_contract() {
        assert_eq!(Severity::from_score(14), Severity::Info);
        assert_eq!(Severity::from_score(15), Severity::Low);
        assert_eq!(Severity::from_score(35), Severity::Medium);
        assert_eq!(Severity::from_score(65), Severity::High);
        assert_eq!(Severity::from_score(90), Severity::Critical);
    }
}
