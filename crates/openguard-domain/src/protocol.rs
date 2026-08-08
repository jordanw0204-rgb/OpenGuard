use crate::{
    AllowedHashRecord, ContentStatus, ExclusionRecord, PersistenceInventory, QuarantineRecord,
    ResponseActionRequest, ResponseActionResult, ScanFinding, ScanJobStatus, ScanProfile,
    SecurityEvent, ServiceHealth, SystemSnapshot, TimelinePage,
};
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_LIST_LIMIT: u32 = 2_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    pub protocol: u16,
    pub request_id: String,
    pub body: Request,
}

impl RequestEnvelope {
    #[must_use]
    pub fn new(request_id: impl Into<String>, body: Request) -> Self {
        Self {
            protocol: PROTOCOL_VERSION,
            request_id: request_id.into(),
            body,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "payload", rename_all = "snake_case")]
pub enum Request {
    Ping,
    GetHealth,
    GetSnapshot,
    RecentEvents {
        limit: u32,
    },
    GetTimeline {
        before_id: Option<i64>,
        limit: u32,
        category: Option<String>,
        process_id: Option<u32>,
        search: Option<String>,
    },
    GetPersistence {
        refresh: bool,
    },
    ExecuteResponse {
        request: ResponseActionRequest,
    },
    StartScan {
        target: String,
        profile: Option<ScanProfile>,
    },
    CancelScan {
        scan_id: String,
    },
    GetScan {
        scan_id: String,
    },
    Quarantine {
        finding: ScanFinding,
    },
    ListQuarantine {
        limit: u32,
    },
    RestoreQuarantine {
        quarantine_id: String,
        destination: Option<String>,
    },
    GetContentStatus,
    InstallContentUpdate,
    RollbackContentUpdate,
    ListExclusions,
    AddExclusion {
        path: String,
        recursive: bool,
    },
    RemoveExclusion {
        path: String,
    },
    ListAllowedHashes,
    AllowHash {
        sha256: String,
        label: String,
    },
    RemoveAllowedHash {
        sha256: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEnvelope {
    pub protocol: u16,
    pub request_id: String,
    pub body: Response,
}

impl ResponseEnvelope {
    #[must_use]
    pub fn success(request_id: impl Into<String>, data: ResponseData) -> Self {
        Self {
            protocol: PROTOCOL_VERSION,
            request_id: request_id.into(),
            body: Response::Success {
                data: Box::new(data),
            },
        }
    }

    #[must_use]
    pub fn error(request_id: impl Into<String>, error: ApiError) -> Self {
        Self {
            protocol: PROTOCOL_VERSION,
            request_id: request_id.into(),
            body: Response::Error { error },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Success { data: Box<ResponseData> },
    Error { error: ApiError },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum ResponseData {
    Pong { service_version: String },
    Health(ServiceHealth),
    Snapshot(SystemSnapshot),
    Events(Vec<SecurityEvent>),
    Timeline(TimelinePage),
    Persistence(PersistenceInventory),
    ResponseAction(ResponseActionResult),
    ScanStarted { scan_id: String },
    ScanCancelled { scan_id: String },
    ScanStatus(ScanJobStatus),
    Quarantines(Vec<QuarantineRecord>),
    QuarantineChanged(QuarantineRecord),
    ContentStatus(ContentStatus),
    Exclusions(Vec<ExclusionRecord>),
    AllowedHashes(Vec<AllowedHashRecord>),
    PolicyChanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    UnsupportedProtocol,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Busy,
    LimitedCoverage,
    Internal,
}
