#![cfg(windows)]

mod eventlog;
mod file_monitor;
mod memory;
mod persistence;
mod response;
mod sysmon;

pub use eventlog::{NativeEventLogMonitor, WindowsEvent};
pub use file_monitor::{FileActivity, FileMonitor, FileMonitorSnapshot, UsnCheckpoint};
pub use memory::{MemoryInspection, inspect_process_memory};
pub use persistence::{PersistenceContext, collect_persistence};
pub use response::{
    ProcessControlResult, block_remote_address, control_process, remove_firewall_rule,
    set_persistence_enabled, terminate_process_tree,
};
pub use sysmon::{SysmonEvent, SysmonMonitor};

use openguard_detection::{RiskEnvironment, assess_process};
use openguard_domain::{
    CoverageNote, CoverageState, NetworkEndpoint, ProcessRecord, ScanFinding, ScanVerdict,
    SignatureStatus, SystemSnapshot,
};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    fs,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::windows::ffi::OsStrExt,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, Mutex, OnceLock, mpsc::SyncSender},
    thread,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, FILETIME, HANDLE, HWND},
        NetworkManagement::IpHelper::{
            GetExtendedTcpTable, GetExtendedUdpTable, GetPerTcp6ConnectionEStats,
            GetPerTcpConnectionEStats, MIB_TCP_STATE, MIB_TCP6ROW, MIB_TCP6ROW_OWNER_PID,
            MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCPROW_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
            MIB_UDPROW_OWNER_PID, SetPerTcp6ConnectionEStats, SetPerTcpConnectionEStats,
            TCP_ESTATS_DATA_ROD_v0, TCP_ESTATS_DATA_RW_v0, TCP_TABLE_OWNER_PID_ALL,
            TcpConnectionEstatsData, UDP_TABLE_OWNER_PID,
        },
        NetworkManagement::WindowsFilteringPlatform::{
            FWPM_NET_EVENT_SUBSCRIPTION0, FWPM_NET_EVENT1, FwpmEngineClose0, FwpmEngineOpen0,
            FwpmNetEventSubscribe0, FwpmNetEventUnsubscribe0,
        },
        Networking::WinSock::{
            AF_INET, AF_INET6, GetNameInfoW, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, NI_NAMEREQD,
            SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, WSADATA, WSAStartup, socklen_t,
        },
        Security::{
            GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
            WinTrust::{
                WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
                WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_IGNORE,
                WTD_UI_NONE, WinVerifyTrust,
            },
        },
        System::{
            Antimalware::{
                AMSI_RESULT_BLOCKED_BY_ADMIN_END, AMSI_RESULT_BLOCKED_BY_ADMIN_START,
                AMSI_RESULT_DETECTED, AmsiInitialize, AmsiScanBuffer, AmsiUninitialize,
                HAMSICONTEXT,
            },
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
                TH32CS_SNAPPROCESS,
            },
            ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
            Threading::{
                GetCurrentProcess, GetProcessTimes, OpenProcess, OpenProcessToken,
                PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
            },
        },
    },
    core::{HSTRING, PCWSTR, PWSTR},
};

const MAX_PROCESS_PATH: usize = 32_768;
const AMSI_MAXIMUM_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum WindowsError {
    #[error("Windows API failed: {0}")]
    Api(String),
    #[error("{api} failed with Win32 status {status}")]
    Status { api: &'static str, status: u32 },
    #[error("Windows returned an invalid table size")]
    InvalidTable,
}

impl From<windows::core::Error> for WindowsError {
    fn from(error: windows::core::Error) -> Self {
        Self::Api(error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformHealth {
    pub platform: &'static str,
    pub process_token_available: bool,
    pub elevated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmsiOutcome {
    pub status: &'static str,
    pub result: i32,
}

/// Applies Windows trust and installed-provider signals to a portable scanner
/// finding. Errors are represented as honest coverage statuses on the finding
/// rather than discarding the successful local scan.
pub fn apply_windows_scan_signals(finding: &mut ScanFinding) {
    let path = Path::new(&finding.path);
    if finding.signature == SignatureStatus::Unknown {
        finding
            .reasons
            .retain(|reason| reason != "Authenticode trust has not yet been evaluated");
        finding.signature = signature_status(path);
        match finding.signature {
            SignatureStatus::Trusted => finding.score = finding.score.saturating_sub(8),
            SignatureStatus::Untrusted => {
                finding.score = finding.score.saturating_add(22).min(100);
                finding
                    .reasons
                    .push("Authenticode trust verification failed".into());
            }
            SignatureStatus::Unknown => finding
                .reasons
                .push("No trusted Authenticode signature was confirmed".into()),
            SignatureStatus::NotApplicable => {}
        }
    }

    let size = path.metadata().map(|metadata| metadata.len());
    if matches!(size, Ok(length) if length > AMSI_MAXIMUM_BYTES) {
        finding.amsi_result = "skipped_size_limit".into();
    } else {
        finding.amsi_result = match fs::read(path) {
            Ok(content) => match AmsiScanner::new() {
                Ok(scanner) => {
                    let outcome = scanner.scan(&content, &finding.path);
                    match outcome.status {
                        "detected" => {
                            finding.score = 100;
                            finding.reasons.push(
                                "The installed Windows AMSI provider detected malware".into(),
                            );
                        }
                        "blocked_by_admin" => {
                            finding.score = finding.score.max(75);
                            finding.reasons.push(
                                "The installed Windows AMSI provider blocked this content by policy"
                                    .into(),
                            );
                        }
                        _ => {}
                    }
                    outcome.status.into()
                }
                Err(_) => "unavailable".into(),
            },
            Err(_) => "read_error".into(),
        };
    }

    finding.score = finding.score.min(100);
    finding.verdict = scan_verdict(finding.score);
    let mut seen = HashSet::new();
    finding.reasons.retain(|reason| seen.insert(reason.clone()));
}

/// Uses the Windows Authenticode policy provider for executable file trust.
#[must_use]
pub fn signature_status(path: &Path) -> SignatureStatus {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !["exe", "dll", "sys", "scr", "com", "cpl", "msi"].contains(&extension.as_str()) {
        return SignatureStatus::NotApplicable;
    }
    if !path.is_file() {
        return SignatureStatus::Unknown;
    }

    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: u32::try_from(size_of::<WINTRUST_FILE_INFO>()).unwrap_or(u32::MAX),
        pcwszFilePath: PCWSTR(wide_path.as_ptr()),
        ..Default::default()
    };
    let mut trust_data = WINTRUST_DATA {
        cbStruct: u32::try_from(size_of::<WINTRUST_DATA>()).unwrap_or(u32::MAX),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &raw mut file_info,
        },
        dwStateAction: WTD_STATEACTION_IGNORE,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            HWND((-1_isize) as *mut core::ffi::c_void),
            &raw mut action,
            (&raw mut trust_data).cast(),
        )
    };
    match status.cast_unsigned() {
        0 => SignatureStatus::Trusted,
        0x800B_0001 | 0x800B_0003 | 0x800B_0100 => SignatureStatus::Unknown,
        _ => SignatureStatus::Untrusted,
    }
}

struct AmsiScanner {
    context: HAMSICONTEXT,
}

impl AmsiScanner {
    fn new() -> Result<Self, WindowsError> {
        let context = unsafe { AmsiInitialize(windows::core::w!("OpenGuard/0.3"))? };
        Ok(Self { context })
    }

    fn scan(&self, content: &[u8], content_name: &str) -> AmsiOutcome {
        let Ok(length) = u32::try_from(content.len()) else {
            return AmsiOutcome {
                status: "skipped_size_limit",
                result: 0,
            };
        };
        let name = HSTRING::from(content_name);
        match unsafe { AmsiScanBuffer(self.context, content.as_ptr().cast(), length, &name, None) }
        {
            Ok(result) => AmsiOutcome {
                status: if result.0 >= AMSI_RESULT_DETECTED.0 {
                    "detected"
                } else if result.0 >= AMSI_RESULT_BLOCKED_BY_ADMIN_START.0
                    && result.0 <= AMSI_RESULT_BLOCKED_BY_ADMIN_END.0
                {
                    "blocked_by_admin"
                } else if result.0 == 0 {
                    "clean"
                } else {
                    "not_detected"
                },
                result: result.0,
            },
            Err(_) => AmsiOutcome {
                status: "scan_error",
                result: 0,
            },
        }
    }
}

impl Drop for AmsiScanner {
    fn drop(&mut self) {
        unsafe { AmsiUninitialize(self.context) };
    }
}

const fn scan_verdict(score: u8) -> ScanVerdict {
    match score {
        85..=u8::MAX => ScanVerdict::Malicious,
        45..=84 => ScanVerdict::Suspicious,
        15..=44 => ScanVerdict::LowRisk,
        _ => ScanVerdict::Clean,
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct TcpKey {
    local_address: String,
    local_port: u16,
    remote_address: String,
    remote_port: u16,
    pid: u32,
}

#[derive(Debug, Clone, Copy)]
struct TcpSample {
    sent: u64,
    received: u64,
    captured_at: Instant,
}

#[derive(Debug, Clone)]
struct ReputationIndicator {
    network: IpAddr,
    prefix: u8,
    verdict: String,
    label: String,
}

#[derive(Debug, Clone, Default)]
pub struct ReputationFeed {
    version: String,
    indicators: Vec<ReputationIndicator>,
}

#[derive(Debug, Deserialize)]
struct ReputationDocument {
    schema: u32,
    #[serde(default)]
    version: String,
    #[serde(default)]
    entries: Vec<ReputationEntry>,
}

#[derive(Debug, Deserialize)]
struct ReputationEntry {
    indicator: String,
    #[serde(default = "default_reputation_verdict")]
    verdict: String,
    #[serde(default)]
    label: String,
}

fn default_reputation_verdict() -> String {
    "suspicious".into()
}

impl ReputationFeed {
    /// Parses a schema-1 reputation feed whose authenticity has already been
    /// established by the signed security-content updater.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON, unsupported schemas, or invalid
    /// network indicators.
    pub fn from_json(data: &[u8]) -> Result<Self, WindowsError> {
        let document: ReputationDocument = serde_json::from_slice(data)
            .map_err(|error| WindowsError::Api(format!("parse reputation feed: {error}")))?;
        if document.schema != 1 {
            return Err(WindowsError::Api(format!(
                "unsupported reputation schema {}",
                document.schema
            )));
        }
        let mut indicators = Vec::with_capacity(document.entries.len());
        for entry in document.entries {
            let verdict = entry.verdict.trim().to_ascii_lowercase();
            if !matches!(verdict.as_str(), "suspicious" | "malicious") {
                continue;
            }
            let (address_text, prefix_text) = entry
                .indicator
                .split_once('/')
                .map_or((entry.indicator.as_str(), None), |(address, prefix)| {
                    (address, Some(prefix))
                });
            let network = address_text.parse::<IpAddr>().map_err(|error| {
                WindowsError::Api(format!(
                    "invalid reputation indicator '{}': {error}",
                    entry.indicator
                ))
            })?;
            let maximum_prefix = if network.is_ipv4() { 32 } else { 128 };
            let prefix = prefix_text
                .map_or(Ok(maximum_prefix), str::parse::<u8>)
                .map_err(|error| {
                    WindowsError::Api(format!(
                        "invalid reputation prefix '{}': {error}",
                        entry.indicator
                    ))
                })?;
            if prefix > maximum_prefix {
                return Err(WindowsError::Api(format!(
                    "reputation prefix is out of range: {}",
                    entry.indicator
                )));
            }
            let label = if entry.label.trim().is_empty() {
                entry.indicator.clone()
            } else {
                entry.label
            };
            indicators.push(ReputationIndicator {
                network,
                prefix,
                verdict,
                label,
            });
        }
        Ok(Self {
            version: document.version,
            indicators,
        })
    }

    /// Loads an already-authenticated reputation file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or parsed.
    pub fn from_path(path: &Path) -> Result<Self, WindowsError> {
        Self::from_json(&fs::read(path).map_err(|error| {
            WindowsError::Api(format!("read reputation feed {}: {error}", path.display()))
        })?)
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    fn classify(&self, address: &str) -> (String, String) {
        let normalized = address.split('%').next().unwrap_or(address);
        let Ok(address) = normalized.parse::<IpAddr>() else {
            return ("unknown".into(), "No remote IP address".into());
        };
        for indicator in &self.indicators {
            if network_contains(indicator.network, indicator.prefix, address) {
                return (
                    indicator.verdict.clone(),
                    format!("Signed local reputation feed: {}", indicator.label),
                );
            }
        }
        if address.is_loopback() {
            return ("local".into(), "Loopback address".into());
        }
        let local = match address {
            IpAddr::V4(value) => value.is_private() || value.is_link_local(),
            IpAddr::V6(value) => value.is_unique_local() || value.is_unicast_link_local(),
        };
        if local {
            return ("local".into(), "Private or link-local address".into());
        }
        if address.is_unspecified() {
            return ("local".into(), "Unspecified/listening address".into());
        }
        (
            "unknown".into(),
            "No match in the signed local reputation feed".into(),
        )
    }
}

fn network_contains(network: IpAddr, prefix: u8, candidate: IpAddr) -> bool {
    match (network, candidate) {
        (IpAddr::V4(network), IpAddr::V4(candidate)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(network) & mask == u32::from(candidate) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(candidate)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(network) & mask == u128::from(candidate) & mask
        }
        _ => false,
    }
}

#[derive(Debug, Clone)]
struct DnsCacheEntry {
    expires_at: Instant,
    hostname: String,
}

#[derive(Debug)]
struct DnsResolver {
    cache: Arc<Mutex<HashMap<String, DnsCacheEntry>>>,
    pending: Arc<Mutex<HashSet<String>>>,
    sender: SyncSender<String>,
}

impl Default for DnsResolver {
    fn default() -> Self {
        initialize_winsock();
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let pending = Arc::new(Mutex::new(HashSet::new()));
        let (sender, receiver) = std::sync::mpsc::sync_channel::<String>(256);
        let worker_cache = Arc::clone(&cache);
        let worker_pending = Arc::clone(&pending);
        let _ = thread::Builder::new()
            .name("OpenGuardDNS".into())
            .spawn(move || {
                while let Ok(address) = receiver.recv() {
                    let hostname = reverse_dns(&address);
                    worker_cache
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(
                            address.clone(),
                            DnsCacheEntry {
                                expires_at: Instant::now() + std::time::Duration::from_mins(10),
                                hostname,
                            },
                        );
                    worker_pending
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&address);
                }
            });
        Self {
            cache,
            pending,
            sender,
        }
    }
}

fn initialize_winsock() {
    static STATUS: OnceLock<i32> = OnceLock::new();
    let _ = STATUS.get_or_init(|| {
        let mut data = WSADATA::default();
        unsafe { WSAStartup(u16::from_le_bytes([2, 2]), &raw mut data) }
    });
}

impl DnsResolver {
    fn hostname(&self, address: &str) -> String {
        let normalized = address.split('%').next().unwrap_or(address);
        let Ok(parsed) = normalized.parse::<IpAddr>() else {
            return String::new();
        };
        if parsed.is_unspecified() {
            return String::new();
        }
        let now = Instant::now();
        {
            let mut cache = self
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if cache.len() > 4_096 {
                cache.retain(|_, value| value.expires_at > now);
            }
            if let Some(cached) = cache.get(normalized).filter(|value| value.expires_at > now) {
                return cached.hostname.clone();
            }
        }
        let should_queue = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(normalized.into());
        if should_queue && self.sender.try_send(normalized.into()).is_err() {
            self.pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(normalized);
        }
        String::new()
    }
}

fn reverse_dns(address: &str) -> String {
    let Ok(address) = address.parse::<IpAddr>() else {
        return String::new();
    };
    let mut hostname = [0_u16; 1_025];
    let status = match address {
        IpAddr::V4(address) => {
            let socket = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(address.octets()),
                    },
                },
                ..Default::default()
            };
            unsafe {
                GetNameInfoW(
                    std::ptr::from_ref(&socket).cast::<SOCKADDR>(),
                    socklen_t(i32::try_from(size_of::<SOCKADDR_IN>()).unwrap_or(i32::MAX)),
                    Some(&mut hostname),
                    None,
                    i32::try_from(NI_NAMEREQD).unwrap_or(i32::MAX),
                )
            }
        }
        IpAddr::V6(address) => {
            let socket = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 {
                        Byte: address.octets(),
                    },
                },
                ..Default::default()
            };
            unsafe {
                GetNameInfoW(
                    std::ptr::from_ref(&socket).cast::<SOCKADDR>(),
                    socklen_t(i32::try_from(size_of::<SOCKADDR_IN6>()).unwrap_or(i32::MAX)),
                    Some(&mut hostname),
                    None,
                    i32::try_from(NI_NAMEREQD).unwrap_or(i32::MAX),
                )
            }
        }
    };
    if status != 0 {
        return String::new();
    }
    utf16_string(&hostname)
}

unsafe extern "system" fn wfp_event_callback(
    context: *mut core::ffi::c_void,
    _event: *const FWPM_NET_EVENT1,
) {
    if let Some(counter) = unsafe { context.cast::<AtomicU64>().as_ref() } {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct WfpMonitor {
    engine: HANDLE,
    subscription: HANDLE,
    event_count: Box<AtomicU64>,
    status: &'static str,
    detail: String,
}

impl Default for WfpMonitor {
    fn default() -> Self {
        let mut engine = HANDLE::default();
        let open_status =
            unsafe { FwpmEngineOpen0(PCWSTR::null(), 10, None, None, &raw mut engine) };
        if open_status != 0 {
            return Self {
                engine: HANDLE::default(),
                subscription: HANDLE::default(),
                event_count: Box::new(AtomicU64::new(0)),
                status: "unavailable",
                detail: format!("WFP engine open returned 0x{open_status:08x}"),
            };
        }
        let event_count = Box::new(AtomicU64::new(0));
        let context = std::ptr::from_ref(event_count.as_ref())
            .cast::<core::ffi::c_void>()
            .cast_mut();
        let mut subscription = HANDLE::default();
        let subscribe_status = unsafe {
            FwpmNetEventSubscribe0(
                engine,
                &FWPM_NET_EVENT_SUBSCRIPTION0::default(),
                Some(wfp_event_callback),
                Some(context),
                &raw mut subscription,
            )
        };
        if subscribe_status == 0 {
            Self {
                engine,
                subscription,
                event_count,
                status: "subscribed",
                detail: "Read-only WFP net-event subscription active; no filters installed".into(),
            }
        } else {
            Self {
                engine,
                subscription: HANDLE::default(),
                event_count,
                status: "engine_only",
                detail: format!(
                    "WFP engine is accessible; event subscription returned 0x{subscribe_status:08x}"
                ),
            }
        }
    }
}

impl Drop for WfpMonitor {
    fn drop(&mut self) {
        if !self.subscription.is_invalid() {
            let _ = unsafe { FwpmNetEventUnsubscribe0(self.engine, self.subscription) };
        }
        if !self.engine.is_invalid() {
            let _ = unsafe { FwpmEngineClose0(self.engine) };
        }
    }
}

#[derive(Debug)]
pub struct WindowsCollector {
    process_cpu: HashMap<u32, (u64, Instant)>,
    signature_cache: HashMap<String, SignatureStatus>,
    tcp_previous: HashMap<TcpKey, TcpSample>,
    tcp_enable_attempted: HashSet<TcpKey>,
    reputation: ReputationFeed,
    dns: DnsResolver,
    wfp: WfpMonitor,
}

impl Default for WindowsCollector {
    fn default() -> Self {
        Self {
            process_cpu: HashMap::new(),
            signature_cache: HashMap::new(),
            tcp_previous: HashMap::new(),
            tcp_enable_attempted: HashSet::new(),
            reputation: ReputationFeed::from_json(include_bytes!(
                "../../../security-content/reputation.json"
            ))
            .unwrap_or_default(),
            dns: DnsResolver::default(),
            wfp: WfpMonitor::default(),
        }
    }
}

impl WindowsCollector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the in-memory network reputation feed after signed content
    /// validation and activation.
    pub fn set_reputation_feed(&mut self, feed: ReputationFeed) {
        self.reputation = feed;
    }

    #[must_use]
    pub fn reputation_version(&self) -> &str {
        self.reputation.version()
    }

    /// Collects one bounded point-in-time view from documented Windows APIs.
    ///
    /// # Errors
    ///
    /// Returns an error when the process snapshot itself cannot be created.
    /// Individual protected processes and optional network counters degrade to
    /// limited records instead of failing the complete snapshot.
    pub fn snapshot(&mut self) -> Result<SystemSnapshot, WindowsError> {
        let elevated = is_elevated();
        let processes = self.processes()?;
        let process_map = processes
            .iter()
            .cloned()
            .map(|process| (process.pid, process))
            .collect::<HashMap<_, _>>();
        let endpoints = self.endpoints(&process_map, elevated);
        let active_counters = endpoints
            .iter()
            .filter(|endpoint| endpoint.usage_status == "active")
            .count();
        let network_state = if active_counters > 0 || elevated {
            CoverageState::Active
        } else {
            CoverageState::Limited
        };
        let network_detail = if active_counters > 0 {
            format!(
                "Owner PID metadata is active; TCP byte counters are active on {active_counters} flows"
            )
        } else if elevated {
            "Owner PID metadata is active; TCP byte counters are warming up".to_owned()
        } else {
            "Owner PID metadata is active; TCP byte counters require the elevated service"
                .to_owned()
        };

        Ok(SystemSnapshot {
            processes,
            endpoints,
            captured_at: timestamp(),
            elevated,
            coverage: vec![
                CoverageNote {
                    source: "process_snapshot".into(),
                    state: CoverageState::Active,
                    detail: "Tool Help inventory with executable, memory, and sampled CPU data".into(),
                },
                CoverageNote {
                    source: "network_snapshot".into(),
                    state: network_state,
                    detail: network_detail,
                },
                CoverageNote {
                    source: "network_reputation".into(),
                    state: CoverageState::Active,
                    detail: format!(
                        "Signed local IP/CIDR reputation {} with bounded asynchronous PTR enrichment",
                        self.reputation.version()
                    ),
                },
                CoverageNote {
                    source: "wfp_net_events".into(),
                    state: if self.wfp.status == "subscribed" {
                        CoverageState::Active
                    } else {
                        CoverageState::Limited
                    },
                    detail: format!(
                        "{}; {} events observed",
                        self.wfp.detail,
                        self.wfp.event_count.load(Ordering::Relaxed)
                    ),
                },
                CoverageNote {
                    source: "content_engine".into(),
                    state: CoverageState::Active,
                    detail: "Native SHA-256, YARA-X, PE/script heuristics, Authenticode, and AMSI are active"
                        .into(),
                },
            ],
        })
    }

    fn processes(&mut self) -> Result<Vec<ProcessRecord>, WindowsError> {
        let snapshot =
            OwnedHandle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? });
        let sampled_at = Instant::now();
        let processor_count = f32::from(
            u16::try_from(std::thread::available_parallelism().map_or(1, std::num::NonZero::get))
                .unwrap_or(u16::MAX),
        );
        let environment = RiskEnvironment::from_process_environment();
        let mut entry = PROCESSENTRY32W {
            dwSize: u32::try_from(size_of::<PROCESSENTRY32W>()).unwrap_or(u32::MAX),
            ..Default::default()
        };
        let mut records = Vec::new();
        let mut active_pids = HashSet::new();
        let mut new_signature_checks = 0_u8;
        unsafe { Process32FirstW(snapshot.get(), &raw mut entry)? };

        loop {
            let pid = entry.th32ProcessID;
            active_pids.insert(pid);
            let name = utf16_string(&entry.szExeFile);
            let details = query_process(pid);
            let accessible = details.is_some();
            let (path, working_set_bytes, cpu_total) = details
                .map(|details| (details.path, details.working_set_bytes, details.cpu_total))
                .unwrap_or_default();
            let cpu_percent = cpu_total.map_or(0.0, |total| {
                self.cpu_percent(pid, total, sampled_at, processor_count)
            });
            let identity = executable_identity(&path);
            let signature = if path.is_empty() {
                SignatureStatus::Unknown
            } else if let Some(status) = self.signature_cache.get(&identity) {
                *status
            } else if new_signature_checks < 8 {
                new_signature_checks += 1;
                let status = signature_status(Path::new(&path));
                self.signature_cache.insert(identity.clone(), status);
                status
            } else {
                SignatureStatus::Unknown
            };
            let risk = assess_process(&name, &path, signature, accessible, &environment);
            records.push(ProcessRecord {
                pid,
                parent_pid: entry.th32ParentProcessID,
                name,
                path: path.clone(),
                thread_count: entry.cntThreads,
                working_set_bytes,
                cpu_percent,
                signature,
                accessible,
                identity,
                is_new: false,
                risk,
            });

            if unsafe { Process32NextW(snapshot.get(), &raw mut entry) }.is_err() {
                break;
            }
        }

        self.process_cpu.retain(|pid, _| active_pids.contains(pid));
        if self.signature_cache.len() > 8_192 {
            self.signature_cache.clear();
        }
        records.sort_by(|left, right| {
            right
                .risk
                .score
                .cmp(&left.risk.score)
                .then_with(|| {
                    left.name
                        .to_ascii_lowercase()
                        .cmp(&right.name.to_ascii_lowercase())
                })
                .then_with(|| left.pid.cmp(&right.pid))
        });
        Ok(records)
    }

    fn cpu_percent(
        &mut self,
        pid: u32,
        total_100ns: u64,
        sampled_at: Instant,
        processor_count: f32,
    ) -> f32 {
        let previous = self.process_cpu.insert(pid, (total_100ns, sampled_at));
        let Some((previous_total, previous_at)) = previous else {
            return 0.0;
        };
        let elapsed = sampled_at.duration_since(previous_at).as_secs_f32();
        if elapsed <= f32::EPSILON || total_100ns < previous_total {
            return 0.0;
        }
        let used_seconds = std::time::Duration::from_nanos(
            total_100ns
                .saturating_sub(previous_total)
                .saturating_mul(100),
        )
        .as_secs_f32();
        ((used_seconds / elapsed / processor_count) * 100.0).clamp(0.0, 100.0)
    }

    fn endpoints(
        &mut self,
        process_map: &HashMap<u32, ProcessRecord>,
        elevated: bool,
    ) -> Vec<NetworkEndpoint> {
        let sampled_at = Instant::now();
        let mut active_keys = HashSet::new();
        let mut endpoints =
            self.tcp4_endpoints(process_map, elevated, sampled_at, &mut active_keys);
        endpoints.extend(self.tcp6_endpoints(process_map, elevated, sampled_at, &mut active_keys));
        endpoints.extend(udp4_rows().unwrap_or_default().into_iter().map(|row| {
            udp_endpoint(
                "UDP4",
                ipv4(row.dwLocalAddr),
                network_port(row.dwLocalPort),
                row.dwOwningPid,
                process_map.get(&row.dwOwningPid),
            )
        }));
        endpoints.extend(udp6_rows().unwrap_or_default().into_iter().map(|row| {
            udp_endpoint(
                "UDP6",
                ipv6(row.ucLocalAddr, row.dwLocalScopeId),
                network_port(row.dwLocalPort),
                row.dwOwningPid,
                process_map.get(&row.dwOwningPid),
            )
        }));
        self.tcp_previous.retain(|key, _| active_keys.contains(key));
        self.tcp_enable_attempted
            .retain(|key| active_keys.contains(key));
        for endpoint in &mut endpoints {
            if endpoint.remote_address == "*" {
                continue;
            }
            (endpoint.reputation, endpoint.reputation_reason) =
                self.reputation.classify(&endpoint.remote_address);
            endpoint.remote_hostname = self.dns.hostname(&endpoint.remote_address);
        }
        endpoints.sort_by(|left, right| {
            left.process_name
                .to_ascii_lowercase()
                .cmp(&right.process_name.to_ascii_lowercase())
                .then_with(|| left.pid.cmp(&right.pid))
                .then_with(|| left.protocol.cmp(&right.protocol))
        });
        endpoints
    }

    fn tcp4_endpoints(
        &mut self,
        process_map: &HashMap<u32, ProcessRecord>,
        elevated: bool,
        sampled_at: Instant,
        active_keys: &mut HashSet<TcpKey>,
    ) -> Vec<NetworkEndpoint> {
        tcp4_rows()
            .unwrap_or_default()
            .into_iter()
            .map(|row| {
                let local_address = ipv4(row.dwLocalAddr);
                let remote_address = ipv4(row.dwRemoteAddr);
                let key = TcpKey {
                    local_address: local_address.clone(),
                    local_port: network_port(row.dwLocalPort),
                    remote_address: remote_address.clone(),
                    remote_port: network_port(row.dwRemotePort),
                    pid: row.dwOwningPid,
                };
                active_keys.insert(key.clone());
                let usage = self.tcp_usage(&row, &key, sampled_at, elevated);
                tcp_endpoint(
                    "TCP4",
                    local_address,
                    remote_address,
                    row.dwState,
                    &key,
                    process_map.get(&row.dwOwningPid),
                    usage,
                )
            })
            .collect()
    }

    fn tcp6_endpoints(
        &mut self,
        process_map: &HashMap<u32, ProcessRecord>,
        elevated: bool,
        sampled_at: Instant,
        active_keys: &mut HashSet<TcpKey>,
    ) -> Vec<NetworkEndpoint> {
        tcp6_rows()
            .unwrap_or_default()
            .into_iter()
            .map(|row| {
                let local_address = ipv6(row.ucLocalAddr, row.dwLocalScopeId);
                let remote_address = ipv6(row.ucRemoteAddr, row.dwRemoteScopeId);
                let key = TcpKey {
                    local_address: local_address.clone(),
                    local_port: network_port(row.dwLocalPort),
                    remote_address: remote_address.clone(),
                    remote_port: network_port(row.dwRemotePort),
                    pid: row.dwOwningPid,
                };
                active_keys.insert(key.clone());
                let usage = self.tcp6_usage(&row, &key, sampled_at, elevated);
                tcp_endpoint(
                    "TCP6",
                    local_address,
                    remote_address,
                    row.dwState,
                    &key,
                    process_map.get(&row.dwOwningPid),
                    usage,
                )
            })
            .collect()
    }

    fn tcp_usage(
        &mut self,
        row: &MIB_TCPROW_OWNER_PID,
        key: &TcpKey,
        sampled_at: Instant,
        elevated: bool,
    ) -> TcpUsage {
        if row.dwState != 5 {
            return TcpUsage::status("not_established");
        }
        let native_row = MIB_TCPROW_LH {
            Anonymous: MIB_TCPROW_LH_0 {
                dwState: row.dwState,
            },
            dwLocalAddr: row.dwLocalAddr,
            dwLocalPort: row.dwLocalPort,
            dwRemoteAddr: row.dwRemoteAddr,
            dwRemotePort: row.dwRemotePort,
        };
        let mut rw = TCP_ESTATS_DATA_RW_v0::default();
        let mut rod = TCP_ESTATS_DATA_ROD_v0::default();
        let result = unsafe {
            GetPerTcpConnectionEStats(
                &raw const native_row,
                TcpConnectionEstatsData,
                Some(bytes_of_mut(&mut rw)),
                0,
                None,
                0,
                Some(bytes_of_mut(&mut rod)),
                0,
            )
        };
        if result != 0 {
            return TcpUsage::status(format!("unavailable_{result}"));
        }
        if !rw.EnableCollection {
            if !elevated {
                return TcpUsage::status("service_required");
            }
            if self.tcp_enable_attempted.insert(key.clone()) {
                let enable = TCP_ESTATS_DATA_RW_v0 {
                    EnableCollection: true,
                };
                let result = unsafe {
                    SetPerTcpConnectionEStats(
                        &raw const native_row,
                        TcpConnectionEstatsData,
                        bytes_of(&enable),
                        0,
                        0,
                    )
                };
                if result != 0 {
                    return TcpUsage::status(format!("unavailable_{result}"));
                }
            }
            return TcpUsage::status("warming");
        }

        let current = TcpSample {
            sent: rod.DataBytesOut,
            received: rod.DataBytesIn,
            captured_at: sampled_at,
        };
        let previous = self.tcp_previous.insert(key.clone(), current);
        let (send_rate, receive_rate) = previous.map_or((None, None), |previous| {
            let elapsed = sampled_at
                .duration_since(previous.captured_at)
                .as_secs_f64()
                .max(0.000_001);
            (
                Some(counter_rate(current.sent, previous.sent, elapsed)),
                Some(counter_rate(current.received, previous.received, elapsed)),
            )
        });
        TcpUsage {
            sent: Some(current.sent),
            received: Some(current.received),
            send_rate,
            receive_rate,
            status: "active".into(),
        }
    }

    fn tcp6_usage(
        &mut self,
        row: &MIB_TCP6ROW_OWNER_PID,
        key: &TcpKey,
        sampled_at: Instant,
        elevated: bool,
    ) -> TcpUsage {
        if row.dwState != 5 {
            return TcpUsage::status("not_established");
        }
        let native_row = MIB_TCP6ROW {
            State: MIB_TCP_STATE(i32::try_from(row.dwState).unwrap_or(i32::MAX)),
            LocalAddr: IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: row.ucLocalAddr,
                },
            },
            dwLocalScopeId: row.dwLocalScopeId,
            dwLocalPort: row.dwLocalPort,
            RemoteAddr: IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: row.ucRemoteAddr,
                },
            },
            dwRemoteScopeId: row.dwRemoteScopeId,
            dwRemotePort: row.dwRemotePort,
        };
        let mut rw = TCP_ESTATS_DATA_RW_v0::default();
        let mut rod = TCP_ESTATS_DATA_ROD_v0::default();
        let result = unsafe {
            GetPerTcp6ConnectionEStats(
                &raw const native_row,
                TcpConnectionEstatsData,
                Some(bytes_of_mut(&mut rw)),
                0,
                None,
                0,
                Some(bytes_of_mut(&mut rod)),
                0,
            )
        };
        if result != 0 {
            return TcpUsage::status(format!("unavailable_{result}"));
        }
        if !rw.EnableCollection {
            if !elevated {
                return TcpUsage::status("service_required");
            }
            if self.tcp_enable_attempted.insert(key.clone()) {
                let enable = TCP_ESTATS_DATA_RW_v0 {
                    EnableCollection: true,
                };
                let result = unsafe {
                    SetPerTcp6ConnectionEStats(
                        &raw const native_row,
                        TcpConnectionEstatsData,
                        bytes_of(&enable),
                        0,
                        0,
                    )
                };
                if result != 0 {
                    return TcpUsage::status(format!("unavailable_{result}"));
                }
            }
            return TcpUsage::status("warming");
        }

        self.sample_tcp_usage(key, rod.DataBytesOut, rod.DataBytesIn, sampled_at)
    }

    fn sample_tcp_usage(
        &mut self,
        key: &TcpKey,
        sent: u64,
        received: u64,
        sampled_at: Instant,
    ) -> TcpUsage {
        let current = TcpSample {
            sent,
            received,
            captured_at: sampled_at,
        };
        let previous = self.tcp_previous.insert(key.clone(), current);
        let (send_rate, receive_rate) = previous.map_or((None, None), |previous| {
            let elapsed = sampled_at
                .duration_since(previous.captured_at)
                .as_secs_f64()
                .max(0.000_001);
            (
                Some(counter_rate(current.sent, previous.sent, elapsed)),
                Some(counter_rate(current.received, previous.received, elapsed)),
            )
        });
        TcpUsage {
            sent: Some(current.sent),
            received: Some(current.received),
            send_rate,
            receive_rate,
            status: "active".into(),
        }
    }
}

fn tcp_endpoint(
    protocol: &str,
    local_address: String,
    remote_address: String,
    state: u32,
    key: &TcpKey,
    owner: Option<&ProcessRecord>,
    usage: TcpUsage,
) -> NetworkEndpoint {
    NetworkEndpoint {
        protocol: protocol.into(),
        local_address,
        local_port: key.local_port,
        remote_address,
        remote_port: key.remote_port,
        state: tcp_state(state).into(),
        pid: key.pid,
        process_name: owner.map_or_else(String::new, |item| item.name.clone()),
        process_path: owner.map_or_else(String::new, |item| item.path.clone()),
        remote_hostname: String::new(),
        reputation: "unknown".into(),
        reputation_reason: "No signed local reputation match".into(),
        bytes_sent: usage.sent,
        bytes_received: usage.received,
        send_rate_bps: usage.send_rate,
        receive_rate_bps: usage.receive_rate,
        usage_status: usage.status,
    }
}

fn udp_endpoint(
    protocol: &str,
    local_address: String,
    local_port: u16,
    pid: u32,
    owner: Option<&ProcessRecord>,
) -> NetworkEndpoint {
    NetworkEndpoint {
        protocol: protocol.into(),
        local_address,
        local_port,
        remote_address: "*".into(),
        remote_port: 0,
        state: "BOUND".into(),
        pid,
        process_name: owner.map_or_else(String::new, |item| item.name.clone()),
        process_path: owner.map_or_else(String::new, |item| item.path.clone()),
        remote_hostname: String::new(),
        reputation: "not_applicable".into(),
        reputation_reason: "UDP owner metadata does not expose a destination".into(),
        bytes_sent: None,
        bytes_received: None,
        send_rate_bps: None,
        receive_rate_bps: None,
        usage_status: "metadata_only".into(),
    }
}

#[derive(Debug)]
struct ProcessDetails {
    path: String,
    working_set_bytes: u64,
    cpu_total: Option<u64>,
}

#[derive(Debug, Default)]
struct TcpUsage {
    sent: Option<u64>,
    received: Option<u64>,
    send_rate: Option<f64>,
    receive_rate: Option<f64>,
    status: String,
}

impl TcpUsage {
    fn status(value: impl Into<String>) -> Self {
        Self {
            status: value.into(),
            ..Self::default()
        }
    }
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    const fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    const fn get(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

#[must_use]
pub fn platform_health() -> PlatformHealth {
    let mut token = HANDLE::default();
    let available =
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token).is_ok() };
    if available {
        let _ = unsafe { CloseHandle(token) };
    }
    PlatformHealth {
        platform: "windows",
        process_token_available: available,
        elevated: is_elevated(),
    }
}

fn is_elevated() -> bool {
    let mut token = HANDLE::default();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }.is_err() {
        return false;
    }
    let token = OwnedHandle::new(token);
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0_u32;
    unsafe {
        GetTokenInformation(
            token.get(),
            TokenElevation,
            Some((&raw mut elevation).cast()),
            u32::try_from(size_of::<TOKEN_ELEVATION>()).unwrap_or(u32::MAX),
            &raw mut returned,
        )
        .is_ok()
            && elevation.TokenIsElevated != 0
    }
}

/// Resolves the current executable path for a process using limited query access.
///
/// # Errors
///
/// Returns an API error when the process exits, is protected, or denies query access.
pub fn process_image_path(pid: u32) -> Result<std::path::PathBuf, WindowsError> {
    let handle = OwnedHandle::new(
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
            .map_err(|error| WindowsError::Api(format!("open PID {pid}: {error}")))?,
    );
    let mut path_buffer = vec![0_u16; MAX_PROCESS_PATH];
    let mut path_length = u32::try_from(path_buffer.len()).unwrap_or(u32::MAX);
    unsafe {
        windows::Win32::System::Threading::QueryFullProcessImageNameW(
            handle.get(),
            windows::Win32::System::Threading::PROCESS_NAME_FORMAT::default(),
            PWSTR(path_buffer.as_mut_ptr()),
            &raw mut path_length,
        )
    }
    .map_err(|error| WindowsError::Api(format!("query PID {pid} image: {error}")))?;
    Ok(std::path::PathBuf::from(String::from_utf16_lossy(
        &path_buffer[..path_length as usize],
    )))
}

fn query_process(pid: u32) -> Option<ProcessDetails> {
    let handle = OwnedHandle::new(unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?
    });
    let mut path_buffer = vec![0_u16; MAX_PROCESS_PATH];
    let mut path_length = u32::try_from(path_buffer.len()).ok()?;
    unsafe {
        windows::Win32::System::Threading::QueryFullProcessImageNameW(
            handle.get(),
            windows::Win32::System::Threading::PROCESS_NAME_FORMAT::default(),
            PWSTR(path_buffer.as_mut_ptr()),
            &raw mut path_length,
        )
        .ok()?;
    }
    let path = String::from_utf16_lossy(&path_buffer[..path_length as usize]);

    let working_set_bytes =
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
            .ok()
            .map_or(0, |metrics_handle| {
                let metrics_handle = OwnedHandle::new(metrics_handle);
                let mut counters = PROCESS_MEMORY_COUNTERS {
                    cb: u32::try_from(size_of::<PROCESS_MEMORY_COUNTERS>()).unwrap_or(u32::MAX),
                    ..Default::default()
                };
                unsafe {
                    GetProcessMemoryInfo(
                        metrics_handle.get(),
                        &raw mut counters,
                        u32::try_from(size_of::<PROCESS_MEMORY_COUNTERS>()).unwrap_or(u32::MAX),
                    )
                }
                .map_or(0, |()| counters.WorkingSetSize as u64)
            });

    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let cpu_total = unsafe {
        GetProcessTimes(
            handle.get(),
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    }
    .ok()
    .map(|()| filetime_value(kernel).saturating_add(filetime_value(user)));

    Some(ProcessDetails {
        path,
        working_set_bytes,
        cpu_total,
    })
}

fn tcp4_rows() -> Result<Vec<MIB_TCPROW_OWNER_PID>, WindowsError> {
    table_rows("GetExtendedTcpTable", |buffer, size| unsafe {
        GetExtendedTcpTable(
            buffer,
            size,
            false,
            u32::from(AF_INET.0),
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    })
}

fn tcp6_rows() -> Result<Vec<MIB_TCP6ROW_OWNER_PID>, WindowsError> {
    table_rows("GetExtendedTcpTable", |buffer, size| unsafe {
        GetExtendedTcpTable(
            buffer,
            size,
            false,
            u32::from(AF_INET6.0),
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    })
}

fn udp4_rows() -> Result<Vec<MIB_UDPROW_OWNER_PID>, WindowsError> {
    table_rows("GetExtendedUdpTable", |buffer, size| unsafe {
        GetExtendedUdpTable(
            buffer,
            size,
            false,
            u32::from(AF_INET.0),
            UDP_TABLE_OWNER_PID,
            0,
        )
    })
}

fn udp6_rows() -> Result<Vec<MIB_UDP6ROW_OWNER_PID>, WindowsError> {
    table_rows("GetExtendedUdpTable", |buffer, size| unsafe {
        GetExtendedUdpTable(
            buffer,
            size,
            false,
            u32::from(AF_INET6.0),
            UDP_TABLE_OWNER_PID,
            0,
        )
    })
}

fn table_rows<T: Copy>(
    api: &'static str,
    call: impl Fn(Option<*mut core::ffi::c_void>, *mut u32) -> u32,
) -> Result<Vec<T>, WindowsError> {
    let mut size = 0_u32;
    let first = call(None, &raw mut size);
    if first != 0 && first != ERROR_INSUFFICIENT_BUFFER.0 {
        return Err(WindowsError::Status { api, status: first });
    }
    if size < 4 {
        return Err(WindowsError::InvalidTable);
    }
    let mut buffer = vec![0_u8; size as usize];
    let result = call(Some(buffer.as_mut_ptr().cast()), &raw mut size);
    if result != 0 {
        return Err(WindowsError::Status {
            api,
            status: result,
        });
    }
    let count = unsafe { core::ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) } as usize;
    let row_size = size_of::<T>();
    let required = 4_usize
        .checked_add(
            count
                .checked_mul(row_size)
                .ok_or(WindowsError::InvalidTable)?,
        )
        .ok_or(WindowsError::InvalidTable)?;
    if required > buffer.len() {
        return Err(WindowsError::InvalidTable);
    }
    let mut rows = Vec::with_capacity(count);
    for index in 0..count {
        let offset = 4 + index * row_size;
        rows.push(unsafe { core::ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<T>()) });
    }
    Ok(rows)
}

fn utf16_string(buffer: &[u16]) -> String {
    let length = buffer
        .iter()
        .position(|item| *item == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..length])
}

fn executable_identity(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    let normalized = path.replace('/', "\\").to_lowercase();
    let Ok(metadata) = fs::metadata(Path::new(path)) else {
        return normalized;
    };
    let modified = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |value| value.as_nanos());
    format!("{normalized}|{}|{modified}", metadata.len())
}

const fn filetime_value(value: FILETIME) -> u64 {
    ((value.dwHighDateTime as u64) << 32) | value.dwLowDateTime as u64
}

const fn network_port(value: u32) -> u16 {
    let bytes = value.to_ne_bytes();
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn ipv4(value: u32) -> String {
    Ipv4Addr::from(value.to_le_bytes()).to_string()
}

fn ipv6(value: [u8; 16], scope_id: u32) -> String {
    let address = Ipv6Addr::from(value);
    if scope_id == 0 {
        address.to_string()
    } else {
        format!("{address}%{scope_id}")
    }
}

const fn tcp_state(value: u32) -> &'static str {
    match value {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RECEIVED",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT_1",
        7 => "FIN_WAIT_2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

fn counter_rate(current: u64, previous: u64, elapsed_seconds: f64) -> f64 {
    std::time::Duration::from_nanos(current.saturating_sub(previous)).as_secs_f64()
        * 1_000_000_000.0
        / elapsed_seconds
}

fn bytes_of<T>(value: &T) -> &[u8] {
    unsafe { core::slice::from_raw_parts(std::ptr::from_ref(value).cast::<u8>(), size_of::<T>()) }
}

fn bytes_of_mut<T>(value: &mut T) -> &mut [u8] {
    unsafe {
        core::slice::from_raw_parts_mut(std::ptr::from_mut(value).cast::<u8>(), size_of::<T>())
    }
}

fn timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    format!("unix:{seconds}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_token_can_be_queried() {
        let health = platform_health();
        assert_eq!(health.platform, "windows");
        assert!(health.process_token_available);
    }

    #[test]
    fn process_and_network_snapshot_is_nonempty() {
        let snapshot = WindowsCollector::new().snapshot().expect("snapshot");
        assert!(!snapshot.processes.is_empty());
        assert!(
            snapshot
                .processes
                .iter()
                .any(|process| process.pid == std::process::id())
        );
        assert!(
            snapshot
                .coverage
                .iter()
                .any(|note| note.source == "network_snapshot")
        );
    }

    #[test]
    fn port_and_ipv4_conversion_match_windows_layout() {
        assert_eq!(network_port(0x5000), 80);
        assert_eq!(ipv4(0x0100_007f), "127.0.0.1");
        assert_eq!(ipv6(Ipv6Addr::LOCALHOST.octets(), 0), "::1");
        assert_eq!(
            ipv6("fe80::1".parse::<Ipv6Addr>().unwrap().octets(), 12),
            "fe80::1%12"
        );
    }

    #[test]
    fn signed_reputation_feed_classifies_ipv4_ipv6_and_local_addresses() {
        let feed = ReputationFeed::from_json(
            br#"{
                "schema": 1,
                "version": "test",
                "entries": [
                    {"indicator":"203.0.113.0/24","verdict":"malicious","label":"test range"},
                    {"indicator":"2001:db8::/32","verdict":"suspicious","label":"v6 test range"}
                ]
            }"#,
        )
        .expect("reputation feed");
        assert_eq!(feed.version(), "test");
        assert_eq!(feed.classify("203.0.113.42").0, "malicious");
        assert_eq!(feed.classify("2001:db8::1234").0, "suspicious");
        assert_eq!(feed.classify("127.0.0.1").0, "local");
        assert_eq!(feed.classify("8.8.8.8").0, "unknown");
    }

    #[test]
    fn reputation_feed_rejects_invalid_network_prefixes() {
        let invalid = br#"{
            "schema": 1,
            "version": "test",
            "entries": [{"indicator":"192.0.2.1/40","verdict":"malicious"}]
        }"#;
        assert!(ReputationFeed::from_json(invalid).is_err());
    }
}
