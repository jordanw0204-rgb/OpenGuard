use anyhow::{Context, Result, anyhow};
use clap::Parser;
use openguard_detection::{BehaviorContext, FileScanner, ScanError, correlate_behavior};
use openguard_domain::{
    AllowedHashRecord, ApiError, ContentStatus, CoverageNote, CoverageState, ErrorCode,
    ExclusionRecord, PROTOCOL_VERSION, QuarantineRecord, Request, RequestEnvelope, ResponseData,
    ResponseEnvelope, ScanFinding, ScanJobState, ScanJobStatus, ScanProfile, ScanVerdict,
    SecurityEvent, ServiceHealth, Severity, SignatureStatus, SystemSnapshot,
};
use openguard_ipc::{read_frame, validate_request, write_frame};
use openguard_storage::{Database, SeenExecutable};
use openguard_updates::{DEFAULT_MANIFEST_URL, SecurityContentUpdater};
use openguard_windows::{
    ReputationFeed, WindowsCollector, apply_windows_scan_signals, platform_health,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufRead, BufReader, Read, Write},
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle},
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_PIPE_CONNECTED, GetLastError, HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SDDL_REVISION_1,
            },
            DuplicateTokenEx, GetTokenInformation, ImpersonateLoggedOnUser, PSECURITY_DESCRIPTOR,
            RevertToSelf, SECURITY_ATTRIBUTES, SecurityImpersonation, TOKEN_DUPLICATE,
            TOKEN_IMPERSONATE, TOKEN_QUERY, TOKEN_USER, TokenImpersonation, TokenPrimary,
            TokenUser,
        },
        Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX},
        System::Com::CoTaskMemFree,
        System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
            ImpersonateNamedPipeClient, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
        },
        System::Threading::{CreateEventW, GetCurrentThread, OpenThreadToken, SetEvent},
        UI::Shell::{
            FOLDERID_CommonStartup, FOLDERID_Downloads, FOLDERID_LocalAppData, FOLDERID_Startup,
            KF_FLAG_DEFAULT, SHGetKnownFolderPath,
        },
    },
    core::{GUID, HSTRING, PWSTR, w},
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState as ScmServiceState,
        ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

const PIPE_BUFFER_BYTES: u32 = 4 * 1024 * 1024;
const QUARANTINE_MAGIC: &[u8] = b"OPENGUARD-QUARANTINE-V1\0";
const SERVICE_NAME: &str = "OpenGuardNative";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(service_entry, service_main);

#[derive(Debug, Parser)]
#[command(
    name = "OpenGuardService",
    version,
    about = "OpenGuard native monitoring service"
)]
struct Arguments {
    /// Run interactively for development and diagnostics.
    #[arg(long)]
    console: bool,

    /// Exit after serving one request. Intended for integration tests.
    #[arg(long)]
    once: bool,

    /// Override the native database path.
    #[arg(long)]
    database: Option<PathBuf>,
}

struct ServiceState {
    started_at: Instant,
    mode: &'static str,
    database: Database,
    collector: WindowsCollector,
    scanner: Arc<FileScanner>,
    scan_jobs: HashMap<String, ScanJob>,
    quarantine_root: PathBuf,
    reported_processes: HashSet<String>,
    updater: SecurityContentUpdater,
    content_version: String,
    content_source: String,
    etw_monitor: Option<EtwProcessMonitor>,
}

struct ScanJob {
    owner_sid: String,
    cancelled: Arc<AtomicBool>,
    status: Arc<Mutex<ScanJobStatus>>,
}

struct ClientContext {
    sid: String,
    process_id: u32,
    token: Option<ClientToken>,
}

struct ClientToken(HANDLE);

// Windows access-token handles may be transferred to another thread and used there for
// impersonation. The handle remains owned by this wrapper until it is closed in Drop.
unsafe impl Send for ClientToken {}

impl Drop for ClientToken {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

struct ImpersonationGuard;

#[derive(Debug, Default)]
struct EtwMonitorState {
    status: String,
    detail: String,
}

struct EtwProcessMonitor {
    child: Child,
    stop_event: HANDLE,
    state: Arc<Mutex<EtwMonitorState>>,
    event_count: Arc<std::sync::atomic::AtomicU64>,
}

impl EtwProcessMonitor {
    fn start(helper: &Path) -> Result<Self> {
        let stop_event_name = format!(
            "Local\\OpenGuardETWStop-{}-{}",
            std::process::id(),
            Uuid::new_v4().simple()
        );
        let stop_event =
            unsafe { CreateEventW(None, true, false, &HSTRING::from(stop_event_name.as_str())) }
                .map_err(|error| anyhow!("create ETW stop event: {error}"))?;
        let mut command = Command::new(helper);
        command
            .arg("--stop-event")
            .arg(&stop_event_name)
            .arg("--parent-pid")
            .arg(std::process::id().to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(0x0800_0000);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let _ = unsafe { CloseHandle(stop_event) };
                return Err(error)
                    .with_context(|| format!("start ETW helper {}", helper.display()));
            }
        };
        let state = Arc::new(Mutex::new(EtwMonitorState {
            status: "starting".into(),
            detail: format!("Starting {}", helper.display()),
        }));
        let event_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
        if let Some(stdout) = child.stdout.take() {
            spawn_etw_reader(stdout, Arc::clone(&state), Arc::clone(&event_count));
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_etw_reader(stderr, Arc::clone(&state), Arc::clone(&event_count));
        }
        Ok(Self {
            child,
            stop_event,
            state,
            event_count,
        })
    }

    fn coverage(&self) -> CoverageNote {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        CoverageNote {
            source: "etw_process_events".into(),
            state: if state.status == "running" {
                CoverageState::Active
            } else {
                CoverageState::Limited
            },
            detail: format!(
                "{}; {} process events observed",
                state.detail,
                self.event_count.load(Ordering::Relaxed)
            ),
        }
    }
}

impl Drop for EtwProcessMonitor {
    fn drop(&mut self) {
        let _ = unsafe { SetEvent(self.stop_event) };
        for _ in 0..20 {
            if self.child.try_wait().ok().flatten().is_some() {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(50));
        }
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        let _ = unsafe { CloseHandle(self.stop_event) };
    }
}

fn spawn_etw_reader(
    reader: impl Read + Send + 'static,
    state: Arc<Mutex<EtwMonitorState>>,
    event_count: Arc<std::sync::atomic::AtomicU64>,
) {
    let _ = thread::Builder::new()
        .name("OpenGuardETWReader".into())
        .spawn(move || {
            for line in BufReader::new(reader).lines().map_while(Result::ok) {
                let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
                    continue;
                };
                if value
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|kind| matches!(kind, "start" | "stop"))
                {
                    event_count.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if let Some(status) = value.get("status").and_then(serde_json::Value::as_str) {
                    let mut current = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    current.status = status.into();
                    current.detail = line;
                }
            }
        });
}

fn etw_helper_path() -> PathBuf {
    let adjacent = std::env::current_exe()
        .unwrap_or_default()
        .with_file_name("OpenGuardETW.exe");
    if adjacent.is_file() {
        adjacent
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(r"..\..\build\native\OpenGuardETW.exe")
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        if unsafe { RevertToSelf() }.is_err() {
            // Continuing as a client would cross a security boundary. Microsoft explicitly
            // recommends terminating the process if reverting impersonation fails.
            std::process::abort();
        }
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .try_init()
        .ok();
    let arguments = Arguments::parse();
    if !arguments.console && !arguments.once {
        service_dispatcher::start(SERVICE_NAME, service_entry)
            .context("register with the Windows Service Control Manager")?;
        return Ok(());
    }
    let database_path = arguments
        .database
        .unwrap_or_else(|| default_database_path(true));
    let mut state = create_state("console", &database_path)?;
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        protocol = PROTOCOL_VERSION,
        database = %database_path.display(),
        "OpenGuard native service ready"
    );

    run_pipe_loop(&mut state, arguments.once, &AtomicBool::new(false));
    Ok(())
}

fn service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(error) = run_windows_service() {
        tracing::error!(error = %error, "OpenGuard Windows service stopped with an error");
    }
}

fn run_windows_service() -> Result<()> {
    let stop_requested = Arc::new(AtomicBool::new(false));
    let handler_stop = Arc::clone(&stop_requested);
    let event_handler = move |event| match event {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop => {
            handler_stop.store(true, Ordering::Release);
            thread::spawn(wake_pipe_server);
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("register native service control handler")?;
    status_handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ScmServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::ZERO,
            process_id: None,
        })
        .context("report native service running")?;

    let database_path = default_database_path(false);
    let mut state = create_state("service", &database_path)?;
    run_pipe_loop(&mut state, false, &stop_requested);

    status_handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ScmServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::ZERO,
            process_id: None,
        })
        .context("report native service stopped")?;
    Ok(())
}

fn create_state(mode: &'static str, database_path: &Path) -> Result<ServiceState> {
    let database = Database::open(database_path)
        .with_context(|| format!("open native database at {}", database_path.display()))?;
    let state_root = database_path.parent().unwrap_or_else(|| Path::new("."));
    let updater = SecurityContentUpdater::new(state_root.join("SecurityContent"))
        .context("initialize signed security-content updater")?;
    let active_version = database.get_metadata("active_content_version")?;
    let (scanner, reputation, content_version, content_source) = active_version
        .as_deref()
        .and_then(|version| {
            let scanner = updater.scanner_for_version(version).ok()?;
            let reputation = ReputationFeed::from_path(
                &updater.version_directory(version).join("reputation.json"),
            )
            .ok()?;
            Some((
                scanner,
                reputation,
                version.to_owned(),
                "signed_update".to_owned(),
            ))
        })
        .unwrap_or((
            FileScanner::new().context("compile bundled native YARA-X rules")?,
            ReputationFeed::from_json(include_bytes!("../../../security-content/reputation.json"))
                .context("load bundled native reputation feed")?,
            "bundled-2026.08.06.1".into(),
            "bundled".into(),
        ));
    let mut collector = WindowsCollector::new();
    collector.set_reputation_feed(reputation);
    let helper = etw_helper_path();
    let etw_monitor = if helper.is_file() {
        match EtwProcessMonitor::start(&helper) {
            Ok(monitor) => Some(monitor),
            Err(error) => {
                tracing::warn!(error = %error, helper = %helper.display(), "ETW process monitor unavailable");
                None
            }
        }
    } else {
        tracing::warn!(helper = %helper.display(), "ETW process helper is missing");
        None
    };
    Ok(ServiceState {
        started_at: Instant::now(),
        mode,
        database,
        collector,
        scanner: Arc::new(scanner),
        scan_jobs: HashMap::new(),
        quarantine_root: database_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("Quarantine"),
        reported_processes: HashSet::new(),
        updater,
        content_version,
        content_source,
        etw_monitor,
    })
}

fn run_pipe_loop(state: &mut ServiceState, once: bool, stop_requested: &AtomicBool) {
    loop {
        if let Err(error) = serve_connection(state)
            && !stop_requested.load(Ordering::Acquire)
        {
            tracing::warn!(error = ?error, "named-pipe request failed");
        }
        if once || stop_requested.load(Ordering::Acquire) {
            break;
        }
    }
}

fn wake_pipe_server() {
    let request_id = "service-stop";
    let request = RequestEnvelope::new(request_id, Request::Ping);
    if let Ok(mut pipe) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(r"\\.\pipe\OpenGuard.v1")
    {
        let _ = write_frame(&mut pipe, &request);
        let _: Result<ResponseEnvelope, _> = read_frame(&mut pipe);
    }
}

fn serve_connection(state: &mut ServiceState) -> Result<()> {
    let descriptor = PipeSecurityDescriptor::new()?;
    let attributes = descriptor.attributes();
    let handle = unsafe {
        CreateNamedPipeW(
            w!(r"\\.\pipe\OpenGuard.v1"),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            2_000,
            Some(&raw const attributes),
        )
    };
    if handle.is_invalid() {
        return Err(anyhow!("CreateNamedPipeW failed: {}", unsafe {
            GetLastError().0
        }));
    }
    let connected = unsafe { ConnectNamedPipe(handle, None) };
    if let Err(error) = connected {
        let status = unsafe { GetLastError() };
        if status != ERROR_PIPE_CONNECTED {
            let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
            return Err(anyhow!("ConnectNamedPipe failed: {error}"));
        }
    }

    let mut stream = unsafe { File::from_raw_handle(handle.0) };
    let request: RequestEnvelope = read_frame(&mut stream).context("read request frame")?;
    let connected_handle = HANDLE(stream.as_raw_handle());
    let client =
        capture_client_context(connected_handle).context("authenticate named-pipe client")?;
    tracing::debug!(client_sid = %client.sid, client_pid = client.process_id, "authenticated local client");
    let response = match validate_request(&request) {
        Ok(()) => handle_request(state, &client, request),
        Err(error) => ResponseEnvelope::error(
            request.request_id,
            ApiError {
                code: ErrorCode::InvalidRequest,
                message: error.to_string(),
                retryable: false,
            },
        ),
    };
    write_frame(&mut stream, &response).context("write response frame")?;
    Ok(())
}

fn handle_request(
    state: &mut ServiceState,
    client: &ClientContext,
    request: RequestEnvelope,
) -> ResponseEnvelope {
    let request_id = request.request_id;
    let result = match request.body {
        Request::Ping => Ok(ResponseData::Pong {
            service_version: env!("CARGO_PKG_VERSION").into(),
        }),
        Request::GetHealth => Ok(ResponseData::Health(state.health())),
        Request::GetSnapshot => state
            .collect_snapshot(&client.sid)
            .map(ResponseData::Snapshot)
            .map_err(|error| ApiError {
                code: ErrorCode::LimitedCoverage,
                message: error.to_string(),
                retryable: true,
            }),
        Request::RecentEvents { limit } => state
            .database
            .recent_events(&client.sid, limit)
            .map(ResponseData::Events)
            .map_err(|error| ApiError {
                code: ErrorCode::Internal,
                message: error.to_string(),
                retryable: true,
            }),
        Request::StartScan { target, profile } => state
            .start_scan(client, &target, profile)
            .map(|scan_id| ResponseData::ScanStarted { scan_id }),
        Request::CancelScan { scan_id } => state
            .cancel_scan(&scan_id, &client.sid)
            .map(|()| ResponseData::ScanCancelled { scan_id }),
        Request::GetScan { scan_id } => state
            .scan_status(&scan_id, &client.sid)
            .map(ResponseData::ScanStatus),
        Request::Quarantine { finding } => state
            .quarantine_finding(client, &finding)
            .map(ResponseData::QuarantineChanged),
        Request::ListQuarantine { limit } => state
            .database
            .list_quarantines(&client.sid, limit)
            .map(ResponseData::Quarantines)
            .map_err(|error| ApiError {
                code: ErrorCode::Internal,
                message: format!("Read quarantine records: {error}"),
                retryable: true,
            }),
        Request::RestoreQuarantine {
            quarantine_id,
            destination,
        } => state
            .restore_quarantine(client, &quarantine_id, destination.as_deref())
            .map(ResponseData::QuarantineChanged),
        Request::GetContentStatus => state.content_status().map(ResponseData::ContentStatus),
        Request::InstallContentUpdate => state
            .install_content_update()
            .map(ResponseData::ContentStatus),
        Request::RollbackContentUpdate => state
            .rollback_content_update()
            .map(ResponseData::ContentStatus),
        Request::ListExclusions => state
            .database
            .list_exclusions(&client.sid)
            .map(ResponseData::Exclusions)
            .map_err(storage_api_error("Read exclusions")),
        Request::AddExclusion { path, recursive } => state
            .add_exclusion(client, &path, recursive)
            .map(|()| ResponseData::PolicyChanged),
        Request::RemoveExclusion { path } => state
            .remove_exclusion(client, &path)
            .map(|()| ResponseData::PolicyChanged),
        Request::ListAllowedHashes => state
            .database
            .list_allowed_hashes(&client.sid)
            .map(ResponseData::AllowedHashes)
            .map_err(storage_api_error("Read allowed hashes")),
        Request::AllowHash { sha256, label } => state
            .allow_hash(client, &sha256, &label)
            .map(|()| ResponseData::PolicyChanged),
        Request::RemoveAllowedHash { sha256 } => state
            .remove_allowed_hash(client, &sha256)
            .map(|()| ResponseData::PolicyChanged),
    };
    match result {
        Ok(data) => ResponseEnvelope::success(request_id, data),
        Err(error) => ResponseEnvelope::error(request_id, error),
    }
}

fn known_folder_path(folder: &GUID, token: Option<&ClientToken>) -> Result<PathBuf> {
    let path = unsafe { SHGetKnownFolderPath(folder, KF_FLAG_DEFAULT, token.map(|value| value.0)) }
        .map_err(|error| anyhow!("resolve Windows known folder: {error}"))?;
    let decoded = unsafe { path.to_string() }.context("decode Windows known folder path");
    unsafe { CoTaskMemFree(Some(path.0.cast())) };
    decoded.map(PathBuf::from)
}

fn scan_profile_roots(profile: ScanProfile, token: Option<&ClientToken>) -> Vec<PathBuf> {
    let known = |folder: &GUID| known_folder_path(folder, token).ok();
    let mut roots = match profile {
        ScanProfile::Quick => [
            known(&FOLDERID_Downloads),
            known(&FOLDERID_LocalAppData).map(|path| path.join("Temp")),
        ]
        .into_iter()
        .flatten()
        .collect(),
        ScanProfile::Downloads => known(&FOLDERID_Downloads).into_iter().collect(),
        ScanProfile::Startup => [known(&FOLDERID_Startup), known(&FOLDERID_CommonStartup)]
            .into_iter()
            .flatten()
            .collect(),
        ScanProfile::Full => vec![PathBuf::from(
            std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into()),
        )],
    };
    roots.retain(|path| !path.as_os_str().is_empty() && path.exists());
    roots.sort();
    roots.dedup();
    roots
}

fn resolve_scan_roots(
    client: &ClientContext,
    target: &str,
    profile: Option<ScanProfile>,
) -> Result<Vec<PathBuf>, ApiError> {
    let primary_token = if profile.is_some() {
        client
            .token
            .as_ref()
            .map(ClientToken::duplicate_primary)
            .transpose()
            .map_err(|error| ApiError {
                code: ErrorCode::Unauthorized,
                message: format!("Cannot resolve scan-profile folders for this user: {error}"),
                retryable: false,
            })?
    } else {
        None
    };
    let roots = profile.map_or_else(
        || vec![PathBuf::from(target)],
        |value| scan_profile_roots(value, primary_token.as_ref()),
    );
    if roots.is_empty() {
        return Err(ApiError {
            code: ErrorCode::NotFound,
            message: "The selected scan profile has no available target directories".into(),
            retryable: false,
        });
    }
    with_client_impersonation(client.token.as_ref(), || {
        for root in &roots {
            let metadata = root.metadata().map_err(|error| ApiError {
                code: ErrorCode::NotFound,
                message: format!("Cannot scan '{}': {error}", root.display()),
                retryable: false,
            })?;
            if !metadata.is_file() && !metadata.is_dir() {
                return Err(ApiError {
                    code: ErrorCode::InvalidRequest,
                    message: format!(
                        "Scan target '{}' is not a regular file or directory",
                        root.display()
                    ),
                    retryable: false,
                });
            }
        }
        Ok(())
    })
    .map_err(|error| ApiError {
        code: ErrorCode::Unauthorized,
        message: format!("Cannot impersonate the requesting user: {error}"),
        retryable: false,
    })??;
    Ok(roots)
}

fn collect_scan_targets(roots: &[PathBuf], cancelled: &AtomicBool) -> Result<Vec<PathBuf>, String> {
    const MAXIMUM_FILES: usize = 1_000_000;
    let mut files = Vec::new();
    let mut directories = Vec::new();
    for root in roots {
        let metadata = std::fs::symlink_metadata(root).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_file() {
            files.push(root.clone());
        } else if metadata.is_dir() {
            directories.push(root.clone());
        }
    }
    while let Some(directory) = directories.pop() {
        if cancelled.load(Ordering::Relaxed) {
            return Err("Scan cancelled".into());
        }
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            if cancelled.load(Ordering::Relaxed) {
                return Err("Scan cancelled".into());
            }
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                directories.push(path);
            } else if file_type.is_file() {
                files.push(path);
                if files.len() >= MAXIMUM_FILES {
                    return Err(format!(
                        "Scan target exceeds the {MAXIMUM_FILES} file safety limit"
                    ));
                }
            }
        }
    }
    files.sort();
    Ok(files)
}

fn finish_cancelled(status: &Arc<Mutex<ScanJobStatus>>) {
    let mut current = status
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    current.state = ScanJobState::Cancelled;
    current.current_path.clear();
}

fn run_scan_job(
    scanner: &FileScanner,
    database: &Database,
    roots: &[PathBuf],
    cancelled: &AtomicBool,
    status: &Arc<Mutex<ScanJobStatus>>,
    owner_sid: &str,
    client_token: Option<&ClientToken>,
) {
    ScanWorker {
        scanner,
        database,
        cancelled,
        status,
        owner_sid,
        client_token,
    }
    .run(roots);
}

struct ScanWorker<'a> {
    scanner: &'a FileScanner,
    database: &'a Database,
    cancelled: &'a AtomicBool,
    status: &'a Arc<Mutex<ScanJobStatus>>,
    owner_sid: &'a str,
    client_token: Option<&'a ClientToken>,
}

impl ScanWorker<'_> {
    fn run(&self, roots: &[PathBuf]) {
        let Some(targets) = self.collect_targets(roots) else {
            return;
        };
        let single_file = targets.len() == 1;
        for target in targets {
            if self.cancelled.load(Ordering::Relaxed) {
                finish_cancelled(self.status);
                return;
            }
            self.status().current_path = target.display().to_string();
            if !self.scan_target(&target, single_file) {
                return;
            }
        }
        let mut current = self.status();
        current.state = ScanJobState::Completed;
        current.current_path.clear();
    }

    fn collect_targets(&self, roots: &[PathBuf]) -> Option<Vec<PathBuf>> {
        let targets = with_client_impersonation(self.client_token, || {
            collect_scan_targets(roots, self.cancelled)
        });
        let targets = match targets {
            Ok(result) => result,
            Err(error) => {
                self.fail(format!("Impersonate scan owner: {error}"));
                return None;
            }
        };
        match targets {
            Ok(targets) if !targets.is_empty() => {
                self.status().total_files = u64::try_from(targets.len()).unwrap_or(u64::MAX);
                Some(targets)
            }
            Ok(_) => {
                self.fail("No regular files were found in the selected target".into());
                None
            }
            Err(error) => {
                let mut current = self.status();
                current.state = if self.cancelled.load(Ordering::Relaxed) {
                    ScanJobState::Cancelled
                } else {
                    ScanJobState::Failed
                };
                current.error = Some(error);
                None
            }
        }
    }

    fn scan_target(&self, target: &Path, single_file: bool) -> bool {
        match self
            .database
            .path_excluded(self.owner_sid, &normalized_path_key(target))
        {
            Ok(true) => {
                let size_bytes = with_client_impersonation(self.client_token, || {
                    target.metadata().map_or(0, |metadata| metadata.len())
                })
                .unwrap_or(0);
                return self.record_finding(
                    ScanFinding {
                        path: target.display().to_string(),
                        verdict: ScanVerdict::Skipped,
                        score: 0,
                        reasons: vec!["Path is excluded by the user".into()],
                        sha256: String::new(),
                        size_bytes,
                        signature: SignatureStatus::NotApplicable,
                        amsi_result: "not_scanned".into(),
                        yara_status: "not_scanned".into(),
                        yara_matches: Vec::new(),
                        scanned_at: unix_timestamp(),
                    },
                    single_file,
                );
            }
            Ok(false) => {}
            Err(error) => {
                self.fail(format!("Read exclusions: {error}"));
                return false;
            }
        }
        let scan_result = with_client_impersonation(self.client_token, || {
            self.scanner
                .scan_file(target, self.cancelled)
                .map(|mut finding| {
                    apply_windows_scan_signals(&mut finding);
                    finding
                })
        });
        let scan_result = match scan_result {
            Ok(result) => result,
            Err(error) => {
                self.fail(format!("Impersonate scan owner: {error}"));
                return false;
            }
        };
        match scan_result {
            Ok(finding) => self.record_finding(finding, single_file),
            Err(ScanError::Cancelled) => {
                finish_cancelled(self.status);
                false
            }
            Err(error) => {
                let mut current = self.status();
                current.files_scanned = current.files_scanned.saturating_add(1);
                current.error = Some(format!("Some files could not be scanned: {error}"));
                true
            }
        }
    }

    fn record_finding(&self, mut finding: ScanFinding, single_file: bool) -> bool {
        if !finding.sha256.is_empty() {
            match self.database.allowed_hash(self.owner_sid, &finding.sha256) {
                Ok(Some(label)) => {
                    let label = if label.is_empty() {
                        "reviewed hash"
                    } else {
                        label.as_str()
                    };
                    finding.verdict = ScanVerdict::Skipped;
                    finding.score = 0;
                    finding.reasons = vec![format!("SHA-256 is allowed by the user ({label})")];
                }
                Ok(None) => {}
                Err(error) => {
                    self.fail(format!("Read allowed hashes: {error}"));
                    return false;
                }
            }
        }
        if let Err(error) = self.database.record_scan(self.owner_sid, &finding) {
            self.fail(format!("Persist scan result: {error}"));
            return false;
        }
        if matches!(
            finding.verdict,
            ScanVerdict::LowRisk | ScanVerdict::Suspicious | ScanVerdict::Malicious
        ) {
            let event = SecurityEvent {
                id: None,
                event_type: "scan_finding".into(),
                severity: Severity::from_score(finding.score),
                title: format!("{} scan finding", finding.verdict),
                detail: finding.reasons.join("; "),
                process_id: None,
                path: finding.path.clone(),
                created_at: finding.scanned_at.clone(),
                resolved: false,
            };
            if let Err(error) = self.database.record_event(self.owner_sid, &event) {
                tracing::warn!(error = %error, path = %finding.path, "persist scan event failed");
            }
        }
        let mut current = self.status();
        current.files_scanned = current.files_scanned.saturating_add(1);
        if single_file {
            current.finding = Some(finding.clone());
        }
        if finding.verdict != openguard_domain::ScanVerdict::Clean && current.findings.len() < 512 {
            current.findings.push(finding);
        }
        true
    }

    fn fail(&self, message: String) {
        let mut current = self.status();
        current.state = ScanJobState::Failed;
        current.error = Some(message);
    }

    fn status(&self) -> std::sync::MutexGuard<'_, ScanJobStatus> {
        self.status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl ServiceState {
    fn add_exclusion(
        &self,
        client: &ClientContext,
        requested_path: &str,
        recursive: bool,
    ) -> Result<(), ApiError> {
        let resolved = with_client_impersonation(client.token.as_ref(), || {
            PathBuf::from(requested_path).canonicalize()
        })
        .and_then(|result| result.map_err(anyhow::Error::from))
        .map_err(|error| ApiError {
            code: ErrorCode::NotFound,
            message: format!("Resolve exclusion path as the requesting user: {error}"),
            retryable: false,
        })?;
        let record = ExclusionRecord {
            path: resolved.display().to_string(),
            recursive,
            created_at: unix_timestamp(),
        };
        self.database
            .add_exclusion(&client.sid, &normalized_path_key(&resolved), &record)
            .map_err(storage_api_error("Add exclusion"))
    }

    fn remove_exclusion(
        &self,
        client: &ClientContext,
        requested_path: &str,
    ) -> Result<(), ApiError> {
        let key = normalized_path_key(Path::new(requested_path));
        let removed = self
            .database
            .remove_exclusion(&client.sid, &key)
            .map_err(storage_api_error("Remove exclusion"))?;
        if !removed {
            return Err(ApiError {
                code: ErrorCode::NotFound,
                message: "The exclusion was not found".into(),
                retryable: false,
            });
        }
        Ok(())
    }

    fn allow_hash(
        &self,
        client: &ClientContext,
        sha256: &str,
        label: &str,
    ) -> Result<(), ApiError> {
        let sha256 = sha256.trim().to_ascii_lowercase();
        if sha256.len() != 64 || !sha256.bytes().all(|value| value.is_ascii_hexdigit()) {
            return Err(ApiError {
                code: ErrorCode::InvalidRequest,
                message: "Allowed hashes must be an exact 64-character SHA-256 digest".into(),
                retryable: false,
            });
        }
        let label = label.trim();
        if label.len() > 200 {
            return Err(ApiError {
                code: ErrorCode::InvalidRequest,
                message: "Allow-list labels cannot exceed 200 characters".into(),
                retryable: false,
            });
        }
        self.database
            .allow_hash(
                &client.sid,
                &AllowedHashRecord {
                    sha256,
                    label: label.into(),
                    created_at: unix_timestamp(),
                },
            )
            .map_err(storage_api_error("Allow hash"))
    }

    fn remove_allowed_hash(&self, client: &ClientContext, sha256: &str) -> Result<(), ApiError> {
        let removed = self
            .database
            .remove_allowed_hash(&client.sid, &sha256.trim().to_ascii_lowercase())
            .map_err(storage_api_error("Remove allowed hash"))?;
        if !removed {
            return Err(ApiError {
                code: ErrorCode::NotFound,
                message: "The allowed hash was not found".into(),
                retryable: false,
            });
        }
        Ok(())
    }

    fn collect_snapshot(
        &mut self,
        owner_sid: &str,
    ) -> Result<openguard_domain::SystemSnapshot, openguard_windows::WindowsError> {
        let mut snapshot = self.collector.snapshot()?;
        match self.apply_executable_baseline(owner_sid, &mut snapshot) {
            Ok(initialized_now) => snapshot.coverage.push(CoverageNote {
                source: "executable_baseline".into(),
                state: CoverageState::Active,
                detail: if initialized_now {
                    "Persistent per-user executable baseline initialized without alerting on existing processes"
                        .into()
                } else {
                    "Persistent per-user executable baseline is active".into()
                },
            }),
            Err(error) => {
                tracing::warn!(error = %error, "update executable baseline failed");
                snapshot.coverage.push(CoverageNote {
                    source: "executable_baseline".into(),
                    state: CoverageState::Limited,
                    detail: format!("Executable baseline persistence is unavailable: {error}"),
                });
            }
        }
        let correlated = apply_behavior_correlations(&mut snapshot);
        snapshot.coverage.push(CoverageNote {
            source: "behavior_correlation".into(),
            state: CoverageState::Active,
            detail: format!(
                "Explainable parent, identity, trust, baseline, and destination correlation is active; {correlated} processes currently have correlated evidence"
            ),
        });
        for process in snapshot.processes.iter().filter(|process| process.is_new) {
            let report_key = format!("{owner_sid}:{}", process.identity);
            if !self.reported_processes.insert(report_key) {
                continue;
            }
            let event = SecurityEvent {
                id: None,
                event_type: "new_executable".into(),
                severity: process.risk.severity,
                title: format!("New executable observed: {}", process.name),
                detail: if process.risk.reasons.is_empty() {
                    "This executable identity was not present in the saved baseline".into()
                } else {
                    process.risk.reasons.join("; ")
                },
                process_id: Some(process.pid),
                path: process.path.clone(),
                created_at: unix_timestamp(),
                resolved: false,
            };
            if let Err(error) = self.database.record_event(owner_sid, &event) {
                tracing::warn!(error = %error, pid = process.pid, "persist new-process event failed");
            }
        }
        for process in snapshot.processes.iter().filter(|process| {
            process.risk.severity >= Severity::Medium
                && process
                    .risk
                    .reasons
                    .iter()
                    .any(|reason| reason.starts_with("Behavior:"))
        }) {
            let correlated_reasons = process
                .risk
                .reasons
                .iter()
                .filter(|reason| reason.starts_with("Behavior:"))
                .cloned()
                .collect::<Vec<_>>();
            let report_key = format!(
                "behavior:{owner_sid}:{}:{}:{}",
                process.pid,
                process.identity,
                correlated_reasons.join("|")
            );
            if !self.reported_processes.insert(report_key) {
                continue;
            }
            let event = SecurityEvent {
                id: None,
                event_type: "behavior_correlation".into(),
                severity: process.risk.severity,
                title: format!("Correlated behavior needs review: {}", process.name),
                detail: correlated_reasons.join("; "),
                process_id: Some(process.pid),
                path: process.path.clone(),
                created_at: unix_timestamp(),
                resolved: false,
            };
            if let Err(error) = self.database.record_event(owner_sid, &event) {
                tracing::warn!(error = %error, pid = process.pid, "persist behavior event failed");
            }
        }
        Ok(snapshot)
    }

    fn apply_executable_baseline(
        &self,
        owner_sid: &str,
        snapshot: &mut openguard_domain::SystemSnapshot,
    ) -> Result<bool, openguard_storage::StorageError> {
        let baseline_key = format!("baseline_initialized:{owner_sid}");
        let initialized = self.database.get_metadata(&baseline_key)?.as_deref() == Some("1");
        let identities = snapshot
            .processes
            .iter()
            .map(|process| process.identity.clone())
            .collect::<Vec<_>>();
        let known = self
            .database
            .known_executable_identities(owner_sid, &identities)?;
        for process in &mut snapshot.processes {
            process.is_new =
                initialized && !process.identity.is_empty() && !known.contains(&process.identity);
        }
        let observed_at = unix_timestamp();
        let observations = snapshot
            .processes
            .iter()
            .filter(|process| !process.identity.is_empty())
            .map(|process| SeenExecutable {
                identity: process.identity.clone(),
                path: process.path.clone(),
                name: process.name.clone(),
                signature: process.signature.to_string(),
                risk_score: process.risk.score,
                observed_at: observed_at.clone(),
            })
            .collect::<Vec<_>>();
        self.database.record_executables(owner_sid, &observations)?;
        if !initialized {
            self.database.set_metadata(&baseline_key, "1")?;
        }
        Ok(!initialized)
    }

    fn start_scan(
        &mut self,
        client: &ClientContext,
        target: &str,
        profile: Option<ScanProfile>,
    ) -> Result<String, ApiError> {
        let roots = resolve_scan_roots(client, target, profile)?;
        let target_label =
            profile.map_or_else(|| target.to_owned(), |value| format!("{value:?} profile"));

        self.prune_finished_scans();
        if self.scan_jobs.len() >= 128 {
            return Err(ApiError {
                code: ErrorCode::Busy,
                message: "Too many scan jobs are retained; retry after completed jobs are pruned"
                    .into(),
                retryable: true,
            });
        }

        let scan_id = Uuid::new_v4().simple().to_string();
        let cancelled = Arc::new(AtomicBool::new(false));
        let status = Arc::new(Mutex::new(ScanJobStatus {
            scan_id: scan_id.clone(),
            target: target_label,
            state: ScanJobState::Running,
            finding: None,
            findings: Vec::new(),
            files_scanned: 0,
            total_files: 0,
            current_path: String::new(),
            error: None,
        }));
        self.scan_jobs.insert(
            scan_id.clone(),
            ScanJob {
                owner_sid: client.sid.clone(),
                cancelled: Arc::clone(&cancelled),
                status: Arc::clone(&status),
            },
        );
        let scanner = Arc::clone(&self.scanner);
        let database = self.database.clone();
        let owner_sid = client.sid.clone();
        let client_token = client.duplicate_token().map_err(|error| ApiError {
            code: ErrorCode::Unauthorized,
            message: format!("Cannot preserve the requesting user's identity: {error}"),
            retryable: false,
        })?;
        thread::Builder::new()
            .name(format!("openguard-scan-{}", &scan_id[..8]))
            .spawn(move || {
                run_scan_job(
                    &scanner,
                    &database,
                    &roots,
                    &cancelled,
                    &status,
                    &owner_sid,
                    client_token.as_ref(),
                );
            })
            .map_err(|error| ApiError {
                code: ErrorCode::Internal,
                message: format!("Start native scan worker: {error}"),
                retryable: true,
            })?;
        Ok(scan_id)
    }

    fn cancel_scan(&self, scan_id: &str, owner_sid: &str) -> Result<(), ApiError> {
        let job = self.scan_jobs.get(scan_id).ok_or_else(|| ApiError {
            code: ErrorCode::NotFound,
            message: format!("Scan job '{scan_id}' was not found"),
            retryable: false,
        })?;
        authorize_scan_owner(job, owner_sid)?;
        job.cancelled.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn scan_status(&self, scan_id: &str, owner_sid: &str) -> Result<ScanJobStatus, ApiError> {
        let job = self.scan_jobs.get(scan_id).ok_or_else(|| ApiError {
            code: ErrorCode::NotFound,
            message: format!("Scan job '{scan_id}' was not found"),
            retryable: false,
        })?;
        authorize_scan_owner(job, owner_sid)?;
        Ok(job
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone())
    }

    fn quarantine_finding(
        &self,
        client: &ClientContext,
        requested: &ScanFinding,
    ) -> Result<QuarantineRecord, ApiError> {
        let verified = verify_quarantine_candidate(&self.scanner, client, requested)?;
        std::fs::create_dir_all(&self.quarantine_root).map_err(|error| ApiError {
            code: ErrorCode::Internal,
            message: format!("Create quarantine directory: {error}"),
            retryable: true,
        })?;
        let quarantine_id = Uuid::new_v4().simple().to_string();
        let quarantine_path = self
            .quarantine_root
            .join(format!("{quarantine_id}.quarantine"));
        let copied_hash = write_quarantine_payload(
            client.token.as_ref(),
            Path::new(&verified.path),
            &quarantine_path,
        )
        .map_err(|error| ApiError {
            code: ErrorCode::Conflict,
            message: format!("Copy file into quarantine: {error}"),
            retryable: false,
        })?;
        if copied_hash != verified.sha256 {
            let _ = std::fs::remove_file(&quarantine_path);
            return Err(ApiError {
                code: ErrorCode::Conflict,
                message: "The file changed while it was being quarantined; scan it again".into(),
                retryable: false,
            });
        }

        let record = QuarantineRecord {
            id: quarantine_id,
            original_path: verified.path.clone(),
            sha256: verified.sha256,
            reason: verified.reasons.join("; "),
            created_at: unix_timestamp(),
            restored_at: None,
            restored_path: None,
        };
        self.database
            .record_quarantine(&client.sid, &record, &quarantine_path)
            .map_err(|error| {
                let _ = std::fs::remove_file(&quarantine_path);
                ApiError {
                    code: ErrorCode::Internal,
                    message: format!("Record quarantine operation: {error}"),
                    retryable: true,
                }
            })?;
        let remove_result = with_client_impersonation(client.token.as_ref(), || {
            std::fs::remove_file(&record.original_path)
        });
        if let Err(error) = remove_result.and_then(|result| result.map_err(anyhow::Error::from)) {
            let _ = self.database.delete_quarantine(&client.sid, &record.id);
            let _ = std::fs::remove_file(&quarantine_path);
            return Err(ApiError {
                code: ErrorCode::Conflict,
                message: format!("Remove original after verified quarantine copy: {error}"),
                retryable: false,
            });
        }
        Ok(record)
    }

    fn restore_quarantine(
        &self,
        client: &ClientContext,
        quarantine_id: &str,
        requested_destination: Option<&str>,
    ) -> Result<QuarantineRecord, ApiError> {
        let stored = self
            .database
            .quarantine(&client.sid, quarantine_id)
            .map_err(|error| ApiError {
                code: ErrorCode::Internal,
                message: format!("Read quarantine record: {error}"),
                retryable: true,
            })?
            .ok_or_else(|| ApiError {
                code: ErrorCode::NotFound,
                message: format!("Quarantine item '{quarantine_id}' was not found"),
                retryable: false,
            })?;
        if stored.record.restored_at.is_some() {
            return Err(ApiError {
                code: ErrorCode::Conflict,
                message: "This quarantine item has already been restored".into(),
                retryable: false,
            });
        }
        let destination = requested_destination.map_or_else(
            || PathBuf::from(&stored.record.original_path),
            PathBuf::from,
        );
        let restored_hash = restore_quarantine_payload(
            client.token.as_ref(),
            &stored.quarantine_path,
            &destination,
        )
        .map_err(|error| ApiError {
            code: ErrorCode::Conflict,
            message: format!("Restore quarantine item: {error}"),
            retryable: false,
        })?;
        if restored_hash != stored.record.sha256 {
            let _ = with_client_impersonation(client.token.as_ref(), || {
                std::fs::remove_file(&destination)
            });
            return Err(ApiError {
                code: ErrorCode::Conflict,
                message: "Quarantine payload failed its SHA-256 integrity check".into(),
                retryable: false,
            });
        }
        let restored_at = unix_timestamp();
        self.database
            .mark_quarantine_restored(&client.sid, quarantine_id, &restored_at, &destination)
            .map_err(|error| ApiError {
                code: ErrorCode::Internal,
                message: format!("Record quarantine restore: {error}"),
                retryable: true,
            })?;
        let _ = std::fs::remove_file(&stored.quarantine_path);
        let mut record = stored.record;
        record.restored_at = Some(restored_at);
        record.restored_path = Some(destination.display().to_string());
        Ok(record)
    }

    fn prune_finished_scans(&mut self) {
        if self.scan_jobs.len() < 128 {
            return;
        }
        let finished: Vec<String> = self
            .scan_jobs
            .iter()
            .filter_map(|(scan_id, job)| {
                let state = job
                    .status
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .state;
                (!matches!(state, ScanJobState::Queued | ScanJobState::Running))
                    .then(|| scan_id.clone())
            })
            .collect();
        for scan_id in finished {
            if self.scan_jobs.len() < 96 {
                break;
            }
            self.scan_jobs.remove(&scan_id);
        }
    }

    fn content_status(&self) -> Result<ContentStatus, ApiError> {
        let previous_version = self
            .database
            .get_metadata("previous_content_version")
            .map_err(|error| ApiError {
                code: ErrorCode::Internal,
                message: format!("Read content activation state: {error}"),
                retryable: true,
            })?
            .filter(|version| !version.is_empty());
        Ok(ContentStatus {
            active_version: self.content_version.clone(),
            previous_version,
            source: self.content_source.clone(),
            manifest_url: DEFAULT_MANIFEST_URL.into(),
        })
    }

    fn install_content_update(&mut self) -> Result<ContentStatus, ApiError> {
        let version = self.updater.install_official().map_err(|error| ApiError {
            code: ErrorCode::LimitedCoverage,
            message: format!("Install signed security content: {error}"),
            retryable: true,
        })?;
        if version == self.content_version {
            return self.content_status();
        }
        let scanner = self
            .updater
            .scanner_for_version(&version)
            .map_err(|error| ApiError {
                code: ErrorCode::Conflict,
                message: format!("Activate validated security content: {error}"),
                retryable: false,
            })?;
        let reputation = ReputationFeed::from_path(
            &self
                .updater
                .version_directory(&version)
                .join("reputation.json"),
        )
        .map_err(|error| ApiError {
            code: ErrorCode::Conflict,
            message: format!("Activate validated network reputation: {error}"),
            retryable: false,
        })?;
        let previous =
            (self.content_source == "signed_update").then_some(self.content_version.as_str());
        self.database
            .activate_content_version(&version, previous)
            .map_err(|error| ApiError {
                code: ErrorCode::Internal,
                message: format!("Commit security-content activation: {error}"),
                retryable: true,
            })?;
        self.scanner = Arc::new(scanner);
        self.collector.set_reputation_feed(reputation);
        self.content_version = version;
        self.content_source = "signed_update".into();
        self.content_status()
    }

    fn rollback_content_update(&mut self) -> Result<ContentStatus, ApiError> {
        let previous = self
            .database
            .get_metadata("previous_content_version")
            .map_err(|error| ApiError {
                code: ErrorCode::Internal,
                message: format!("Read content rollback state: {error}"),
                retryable: true,
            })?
            .filter(|version| !version.is_empty())
            .ok_or_else(|| ApiError {
                code: ErrorCode::NotFound,
                message: "No previous signed content version is available".into(),
                retryable: false,
            })?;
        let scanner = self
            .updater
            .scanner_for_version(&previous)
            .map_err(|error| ApiError {
                code: ErrorCode::Conflict,
                message: format!("Validate rollback security content: {error}"),
                retryable: false,
            })?;
        let reputation = ReputationFeed::from_path(
            &self
                .updater
                .version_directory(&previous)
                .join("reputation.json"),
        )
        .map_err(|error| ApiError {
            code: ErrorCode::Conflict,
            message: format!("Validate rollback network reputation: {error}"),
            retryable: false,
        })?;
        let current = self.content_version.clone();
        self.database
            .activate_content_version(&previous, Some(&current))
            .map_err(|error| ApiError {
                code: ErrorCode::Internal,
                message: format!("Commit security-content rollback: {error}"),
                retryable: true,
            })?;
        self.scanner = Arc::new(scanner);
        self.collector.set_reputation_feed(reputation);
        self.content_version = previous;
        self.content_source = "signed_update".into();
        self.content_status()
    }

    fn health(&self) -> ServiceHealth {
        let platform = platform_health();
        ServiceHealth {
            version: env!("CARGO_PKG_VERSION").into(),
            protocol: PROTOCOL_VERSION,
            service_state: self.mode.into(),
            database_state: "ready".into(),
            content_version: self.content_version.clone(),
            uptime_seconds: self.started_at.elapsed().as_secs(),
            coverage: vec![
                CoverageNote {
                    source: "windows".into(),
                    state: CoverageState::Active,
                    detail: "Native Windows collector is available".into(),
                },
                CoverageNote {
                    source: "privilege".into(),
                    state: if platform.elevated {
                        CoverageState::Active
                    } else {
                        CoverageState::Limited
                    },
                    detail: if platform.elevated {
                        "Elevated collection is active".into()
                    } else {
                        "Running unelevated; protected details and TCP byte counters may be limited"
                            .into()
                    },
                },
                self.etw_monitor.as_ref().map_or_else(
                    || CoverageNote {
                        source: "etw_process_events".into(),
                        state: CoverageState::Limited,
                        detail: "ETW helper is unavailable; bounded snapshot reconciliation remains active"
                            .into(),
                    },
                    EtwProcessMonitor::coverage,
                ),
            ],
        }
    }
}

fn verify_quarantine_candidate(
    scanner: &FileScanner,
    client: &ClientContext,
    requested: &ScanFinding,
) -> Result<ScanFinding, ApiError> {
    if !matches!(
        requested.verdict,
        ScanVerdict::Suspicious | ScanVerdict::Malicious
    ) || requested.sha256.is_empty()
    {
        return Err(ApiError {
            code: ErrorCode::InvalidRequest,
            message: "Only a suspicious or malicious hash-identified finding can be quarantined"
                .into(),
            retryable: false,
        });
    }
    let path = PathBuf::from(&requested.path);
    let verified = with_client_impersonation(client.token.as_ref(), || -> Result<ScanFinding> {
        let metadata = std::fs::symlink_metadata(&path).context("inspect quarantine candidate")?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(anyhow!(
                "only regular non-symbolic-link files can be quarantined"
            ));
        }
        let mut finding = scanner
            .scan_file(&path, &AtomicBool::new(false))
            .map_err(|error| anyhow!("rescan quarantine candidate: {error}"))?;
        apply_windows_scan_signals(&mut finding);
        Ok(finding)
    })
    .and_then(|result| result)
    .map_err(|error| ApiError {
        code: ErrorCode::Conflict,
        message: format!("Verify quarantine candidate: {error}"),
        retryable: false,
    })?;
    if verified.sha256 != requested.sha256
        || !matches!(
            verified.verdict,
            ScanVerdict::Suspicious | ScanVerdict::Malicious
        )
    {
        return Err(ApiError {
            code: ErrorCode::Conflict,
            message: "The file no longer matches the suspicious scan finding; scan it again".into(),
            retryable: false,
        });
    }
    Ok(verified)
}

fn write_quarantine_payload(
    client_token: Option<&ClientToken>,
    source_path: &Path,
    quarantine_path: &Path,
) -> Result<String> {
    let mut destination = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(quarantine_path)
        .context("create defanged quarantine payload")?;
    destination
        .write_all(QUARANTINE_MAGIC)
        .context("write quarantine header")?;
    let result = with_client_impersonation(client_token, || -> Result<String> {
        let mut source = File::open(source_path).context("open quarantine source as client")?;
        hash_copy(&mut source, &mut destination)
    })
    .and_then(|result| result);
    if result.is_err() {
        drop(destination);
        let _ = std::fs::remove_file(quarantine_path);
    }
    result
}

fn restore_quarantine_payload(
    client_token: Option<&ClientToken>,
    quarantine_path: &Path,
    destination_path: &Path,
) -> Result<String> {
    let mut source = File::open(quarantine_path).context("open quarantine payload")?;
    let mut header = vec![0_u8; QUARANTINE_MAGIC.len()];
    source
        .read_exact(&mut header)
        .context("read quarantine header")?;
    if header != QUARANTINE_MAGIC {
        return Err(anyhow!("invalid or unsupported quarantine payload header"));
    }
    with_client_impersonation(client_token, || -> Result<String> {
        if let Some(parent) = destination_path.parent() {
            std::fs::create_dir_all(parent).context("create restore destination directory")?;
        }
        let mut destination = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination_path)
            .context("create restore destination without overwriting")?;
        let digest = hash_copy(&mut source, &mut destination)?;
        destination.sync_all().context("flush restored file")?;
        Ok(digest)
    })
    .and_then(|result| result)
}

fn hash_copy(source: &mut impl Read, destination: &mut impl Write) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = source.read(&mut buffer).context("read file payload")?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        destination
            .write_all(&buffer[..read])
            .context("write file payload")?;
    }
    Ok(hex::encode(hasher.finalize()))
}

fn unix_timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("unix:{seconds}")
}

fn normalized_path_key(path: &Path) -> String {
    let display = path.display().to_string().replace('/', "\\");
    display
        .strip_prefix(r"\\?\")
        .unwrap_or(&display)
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

fn apply_behavior_correlations(snapshot: &mut SystemSnapshot) -> usize {
    let process_names = snapshot
        .processes
        .iter()
        .map(|process| (process.pid, process.name.clone()))
        .collect::<HashMap<_, _>>();
    let mut network_signals = HashMap::<u32, (bool, bool, bool)>::new();
    for endpoint in &snapshot.endpoints {
        if endpoint.remote_port == 0 || endpoint.remote_address == "*" {
            continue;
        }
        let signal = network_signals.entry(endpoint.pid).or_default();
        if endpoint.reputation != "local" {
            signal.0 = true;
        }
        if endpoint.reputation == "suspicious" {
            signal.1 = true;
        }
        if endpoint.reputation == "malicious" {
            signal.2 = true;
        }
    }

    let mut correlated = 0;
    for process in &mut snapshot.processes {
        let parent_name = process_names
            .get(&process.parent_pid)
            .map_or("", String::as_str);
        let signals = network_signals
            .get(&process.pid)
            .copied()
            .unwrap_or_default();
        let previous_reasons = process.risk.reasons.len();
        process.risk = correlate_behavior(
            &process.risk,
            &process.name,
            process.signature,
            process.is_new,
            BehaviorContext {
                parent_name,
                has_public_network: signals.0,
                suspicious_destination: signals.1,
                malicious_destination: signals.2,
            },
        );
        if process.risk.reasons.len() > previous_reasons {
            correlated += 1;
        }
    }
    correlated
}

fn storage_api_error(
    operation: &'static str,
) -> impl FnOnce(openguard_storage::StorageError) -> ApiError {
    move |error| ApiError {
        code: ErrorCode::Internal,
        message: format!("{operation}: {error}"),
        retryable: true,
    }
}

fn authorize_scan_owner(job: &ScanJob, owner_sid: &str) -> Result<(), ApiError> {
    if job.owner_sid == owner_sid {
        return Ok(());
    }
    Err(ApiError {
        code: ErrorCode::Forbidden,
        message: "This scan job belongs to a different signed-in user".into(),
        retryable: false,
    })
}

impl ClientContext {
    fn duplicate_token(&self) -> Result<Option<ClientToken>> {
        self.token.as_ref().map(ClientToken::duplicate).transpose()
    }

    #[cfg(test)]
    fn test_user(sid: &str) -> Self {
        Self {
            sid: sid.into(),
            process_id: std::process::id(),
            token: None,
        }
    }
}

impl ClientToken {
    fn duplicate(&self) -> Result<Self> {
        let mut duplicate = HANDLE::default();
        unsafe {
            DuplicateTokenEx(
                self.0,
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                None,
                SecurityImpersonation,
                TokenImpersonation,
                &raw mut duplicate,
            )
        }
        .map_err(|error| anyhow!("duplicate client impersonation token: {error}"))?;
        Ok(Self(duplicate))
    }

    fn duplicate_primary(&self) -> Result<Self> {
        let mut duplicate = HANDLE::default();
        unsafe {
            DuplicateTokenEx(
                self.0,
                TOKEN_QUERY,
                None,
                SecurityImpersonation,
                TokenPrimary,
                &raw mut duplicate,
            )
        }
        .map_err(|error| anyhow!("duplicate client primary token: {error}"))?;
        Ok(Self(duplicate))
    }
}

fn capture_client_context(pipe: HANDLE) -> Result<ClientContext> {
    let mut process_id = 0;
    unsafe { GetNamedPipeClientProcessId(pipe, &raw mut process_id) }
        .map_err(|error| anyhow!("identify named-pipe client process: {error}"))?;
    unsafe { ImpersonateNamedPipeClient(pipe) }
        .map_err(|error| anyhow!("impersonate named-pipe client: {error}"))?;
    let _guard = ImpersonationGuard;

    let mut token = HANDLE::default();
    unsafe {
        OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
            true,
            &raw mut token,
        )
    }
    .map_err(|error| anyhow!("open named-pipe client token: {error}"))?;
    let token = ClientToken(token);
    let sid = token_user_sid(token.0)?;
    Ok(ClientContext {
        sid,
        process_id,
        token: Some(token),
    })
}

fn token_user_sid(token: HANDLE) -> Result<String> {
    let mut bytes_needed = 0;
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &raw mut bytes_needed) };
    if bytes_needed == 0 {
        return Err(anyhow!(
            "GetTokenInformation did not return a token-user buffer size"
        ));
    }
    let word_count = usize::try_from(bytes_needed)
        .context("token-user buffer length overflow")?
        .div_ceil(size_of::<usize>());
    let mut buffer = vec![0usize; word_count];
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            bytes_needed,
            &raw mut bytes_needed,
        )
    }
    .map_err(|error| anyhow!("read named-pipe client SID: {error}"))?;
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid_text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(token_user.User.Sid, &raw mut sid_text) }
        .map_err(|error| anyhow!("format named-pipe client SID: {error}"))?;
    let sid = unsafe { sid_text.to_string() }.context("decode named-pipe client SID")?;
    if !sid_text.is_null() {
        unsafe {
            LocalFree(Some(HLOCAL(sid_text.0.cast())));
        }
    }
    Ok(sid)
}

fn with_client_impersonation<T>(
    token: Option<&ClientToken>,
    operation: impl FnOnce() -> T,
) -> Result<T> {
    let Some(token) = token else {
        return Ok(operation());
    };
    unsafe { ImpersonateLoggedOnUser(token.0) }
        .map_err(|error| anyhow!("impersonate authenticated client: {error}"))?;
    let _guard = ImpersonationGuard;
    Ok(operation())
}

struct PipeSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl PipeSecurityDescriptor {
    fn new() -> Result<Self> {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                w!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"),
                SDDL_REVISION_1,
                &raw mut descriptor,
                None,
            )
        }
        .map_err(|error| anyhow!("create named-pipe security descriptor: {error}"))?;
        Ok(Self(descriptor))
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: false.into(),
        }
    }
}

impl Drop for PipeSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                LocalFree(Some(HLOCAL(self.0.0)));
            }
        }
    }
}

fn default_database_path(console: bool) -> PathBuf {
    let variable = if console {
        "LOCALAPPDATA"
    } else {
        "PROGRAMDATA"
    };
    let fallback = if console { "." } else { r"C:\ProgramData" };
    PathBuf::from(std::env::var(variable).unwrap_or_else(|_| fallback.into()))
        .join("OpenGuard")
        .join("openguard-native.db")
}

#[cfg(test)]
mod tests {
    use super::*;
    use openguard_domain::{Request, Response};
    use tempfile::TempDir;

    fn state(directory: &TempDir) -> ServiceState {
        ServiceState {
            started_at: Instant::now(),
            mode: "test",
            database: Database::open(directory.path().join("state.db")).expect("database"),
            collector: WindowsCollector::new(),
            scanner: Arc::new(FileScanner::new().expect("scanner")),
            scan_jobs: HashMap::new(),
            quarantine_root: directory.path().join("Quarantine"),
            reported_processes: HashSet::new(),
            updater: SecurityContentUpdater::new(directory.path().join("SecurityContent"))
                .expect("updater"),
            content_version: "bundled-test".into(),
            content_source: "bundled".into(),
            etw_monitor: None,
        }
    }

    fn test_client() -> ClientContext {
        ClientContext::test_user("S-1-5-21-test-user")
    }

    fn scan_and_wait(
        state: &mut ServiceState,
        client: &ClientContext,
        target: &Path,
    ) -> ScanJobStatus {
        let response = handle_request(
            state,
            client,
            RequestEnvelope::new(
                "policy-scan",
                Request::StartScan {
                    target: target.display().to_string(),
                    profile: None,
                },
            ),
        );
        let Response::Success { data } = response.body else {
            panic!("expected scan started response")
        };
        let ResponseData::ScanStarted { scan_id } = *data else {
            panic!("expected scan started response")
        };
        for _ in 0..100 {
            let status = state
                .scan_status(&scan_id, &client.sid)
                .expect("scan status");
            if !matches!(status.state, ScanJobState::Queued | ScanJobState::Running) {
                return status;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("scan completed before timeout")
    }

    #[test]
    fn ping_and_health_keep_request_identity() {
        let directory = TempDir::new().expect("temporary directory");
        let mut state = state(&directory);
        let client = test_client();
        let ping = handle_request(
            &mut state,
            &client,
            RequestEnvelope::new("ping-1", Request::Ping),
        );
        assert_eq!(ping.request_id, "ping-1");
        assert!(matches!(ping.body, Response::Success { .. }));

        let health = handle_request(
            &mut state,
            &client,
            RequestEnvelope::new("health-1", Request::GetHealth),
        );
        assert_eq!(health.request_id, "health-1");
        assert!(matches!(health.body, Response::Success { .. }));
    }

    #[test]
    fn snapshot_request_returns_native_processes() {
        let directory = TempDir::new().expect("temporary directory");
        let mut state = state(&directory);
        let response = handle_request(
            &mut state,
            &test_client(),
            RequestEnvelope::new("snapshot-1", Request::GetSnapshot),
        );
        let Response::Success { data } = response.body else {
            panic!("expected snapshot response")
        };
        let ResponseData::Snapshot(snapshot) = *data else {
            panic!("expected snapshot response")
        };
        assert!(!snapshot.processes.is_empty());
    }

    #[test]
    fn scan_job_completes_and_returns_the_finding() {
        let directory = TempDir::new().expect("temporary directory");
        let target = directory.path().join("sample.txt");
        std::fs::write(&target, b"ordinary native scanner test").expect("sample");
        let mut state = state(&directory);
        let client = test_client();
        let response = handle_request(
            &mut state,
            &client,
            RequestEnvelope::new(
                "scan-1",
                Request::StartScan {
                    target: target.display().to_string(),
                    profile: None,
                },
            ),
        );
        let Response::Success { data } = response.body else {
            panic!("expected scan started response")
        };
        let ResponseData::ScanStarted { scan_id } = *data else {
            panic!("expected scan started response")
        };

        let mut completed = None;
        for _ in 0..100 {
            let status = state
                .scan_status(&scan_id, &client.sid)
                .expect("scan status");
            if !matches!(status.state, ScanJobState::Queued | ScanJobState::Running) {
                completed = Some(status);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let status = completed.expect("scan completed before timeout");
        assert_eq!(status.state, ScanJobState::Completed);
        assert_eq!(status.finding.expect("finding").score, 0);
    }

    #[test]
    fn excluded_path_is_recorded_as_skipped_without_a_detection_event() {
        let directory = TempDir::new().expect("temporary directory");
        let target = directory.path().join("excluded.txt");
        std::fs::write(&target, b"OPENGUARD_SIGNED_CONTENT_TEST_MARKER_2026")
            .expect("excluded marker");
        let mut state = state(&directory);
        let client = test_client();
        let response = handle_request(
            &mut state,
            &client,
            RequestEnvelope::new(
                "exclude",
                Request::AddExclusion {
                    path: target.display().to_string(),
                    recursive: false,
                },
            ),
        );
        assert!(matches!(response.body, Response::Success { .. }));

        let status = scan_and_wait(&mut state, &client, &target);
        let finding = status.finding.expect("skipped finding");
        assert_eq!(finding.verdict, ScanVerdict::Skipped);
        assert_eq!(finding.reasons, ["Path is excluded by the user"]);
        assert!(
            state
                .database
                .recent_events(&client.sid, 20)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn allowed_hash_overrides_a_detection_without_hiding_the_scan_record() {
        let directory = TempDir::new().expect("temporary directory");
        let target = directory.path().join("allowed-marker.txt");
        let content = b"OPENGUARD_SIGNED_CONTENT_TEST_MARKER_2026";
        std::fs::write(&target, content).expect("allowed marker");
        let digest = format!("{:x}", Sha256::digest(content));
        let mut state = state(&directory);
        let client = test_client();
        let response = handle_request(
            &mut state,
            &client,
            RequestEnvelope::new(
                "allow",
                Request::AllowHash {
                    sha256: digest,
                    label: "Reviewed test fixture".into(),
                },
            ),
        );
        assert!(matches!(response.body, Response::Success { .. }));

        let status = scan_and_wait(&mut state, &client, &target);
        let finding = status.finding.expect("allowed finding");
        assert_eq!(finding.verdict, ScanVerdict::Skipped);
        assert_eq!(finding.score, 0);
        assert!(finding.reasons[0].contains("Reviewed test fixture"));
        assert!(
            state
                .database
                .recent_events(&client.sid, 20)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn folder_scan_reports_progress_and_only_retains_detections() {
        let directory = TempDir::new().expect("temporary directory");
        let target = directory.path().join("samples");
        std::fs::create_dir(&target).expect("sample directory");
        std::fs::write(target.join("clean.txt"), b"ordinary content").expect("clean sample");
        std::fs::write(
            target.join("marker.txt"),
            b"OPENGUARD_SIGNED_CONTENT_TEST_MARKER_2026",
        )
        .expect("marker sample");
        let mut state = state(&directory);
        let client = test_client();
        let response = handle_request(
            &mut state,
            &client,
            RequestEnvelope::new(
                "folder-scan",
                Request::StartScan {
                    target: target.display().to_string(),
                    profile: None,
                },
            ),
        );
        let Response::Success { data } = response.body else {
            panic!("expected scan started response")
        };
        let ResponseData::ScanStarted { scan_id } = *data else {
            panic!("expected scan started response")
        };
        let mut completed = None;
        for _ in 0..100 {
            let status = state
                .scan_status(&scan_id, &client.sid)
                .expect("scan status");
            if !matches!(status.state, ScanJobState::Queued | ScanJobState::Running) {
                completed = Some(status);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let status = completed.expect("folder scan completed");
        assert_eq!(status.state, ScanJobState::Completed);
        assert_eq!(status.files_scanned, 2);
        assert_eq!(status.total_files, 2);
        assert_eq!(status.findings.len(), 1);
        assert_eq!(
            status.findings[0].verdict,
            openguard_domain::ScanVerdict::Malicious
        );
    }

    #[test]
    fn scan_jobs_are_private_to_the_requesting_user() {
        let directory = TempDir::new().expect("temporary directory");
        let target = directory.path().join("private.txt");
        std::fs::write(&target, b"owner isolation test").expect("sample");
        let mut state = state(&directory);
        let owner = ClientContext::test_user("S-1-5-21-owner");
        let other = ClientContext::test_user("S-1-5-21-other");
        let response = handle_request(
            &mut state,
            &owner,
            RequestEnvelope::new(
                "private-scan",
                Request::StartScan {
                    target: target.display().to_string(),
                    profile: None,
                },
            ),
        );
        let Response::Success { data } = response.body else {
            panic!("expected scan started response")
        };
        let ResponseData::ScanStarted { scan_id } = *data else {
            panic!("expected scan started response")
        };
        let denied = state
            .scan_status(&scan_id, &other.sid)
            .expect_err("other user must not read scan state");
        assert_eq!(denied.code, ErrorCode::Forbidden);
        assert!(state.scan_status(&scan_id, &owner.sid).is_ok());
    }

    #[test]
    fn executable_baseline_suppresses_first_inventory_and_marks_new_identity() {
        let directory = TempDir::new().expect("temporary directory");
        let state = state(&directory);
        let mut first = openguard_domain::SystemSnapshot {
            processes: vec![openguard_domain::ProcessRecord {
                identity: "existing|1".into(),
                name: "existing.exe".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(
            state
                .apply_executable_baseline("owner", &mut first)
                .expect("first baseline")
        );
        assert!(!first.processes[0].is_new);

        let mut second = openguard_domain::SystemSnapshot {
            processes: vec![
                first.processes[0].clone(),
                openguard_domain::ProcessRecord {
                    identity: "new|2".into(),
                    name: "new.exe".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert!(
            !state
                .apply_executable_baseline("owner", &mut second)
                .expect("existing baseline")
        );
        assert!(!second.processes[0].is_new);
        assert!(second.processes[1].is_new);
    }

    #[test]
    fn quarantine_round_trip_is_defanged_scoped_and_integrity_checked() {
        let directory = TempDir::new().expect("temporary directory");
        let target = directory.path().join("detected.txt");
        let content = b"OPENGUARD_SIGNED_CONTENT_TEST_MARKER_2026";
        std::fs::write(&target, content).expect("detection marker");
        let mut state = state(&directory);
        let owner = test_client();
        let mut finding = state
            .scanner
            .scan_file(&target, &AtomicBool::new(false))
            .expect("scan marker");
        apply_windows_scan_signals(&mut finding);
        assert_eq!(finding.verdict, ScanVerdict::Malicious);

        let response = handle_request(
            &mut state,
            &owner,
            RequestEnvelope::new("quarantine", Request::Quarantine { finding }),
        );
        let Response::Success { data } = response.body else {
            panic!("expected quarantine response")
        };
        let ResponseData::QuarantineChanged(record) = *data else {
            panic!("expected changed quarantine record")
        };
        assert!(!target.exists());
        let payload = state
            .quarantine_root
            .join(format!("{}.quarantine", record.id));
        assert!(payload.exists());
        assert!(
            std::fs::read(&payload)
                .unwrap()
                .starts_with(QUARANTINE_MAGIC)
        );
        assert!(
            state
                .database
                .list_quarantines("another-user", 20)
                .unwrap()
                .is_empty()
        );

        let response = handle_request(
            &mut state,
            &owner,
            RequestEnvelope::new(
                "restore",
                Request::RestoreQuarantine {
                    quarantine_id: record.id,
                    destination: None,
                },
            ),
        );
        assert!(matches!(response.body, Response::Success { .. }));
        assert_eq!(std::fs::read(&target).unwrap(), content);
        assert!(!payload.exists());
    }
}
