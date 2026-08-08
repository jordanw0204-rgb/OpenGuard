#![forbid(unsafe_code)]

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use openguard_domain::{
    PROTOCOL_VERSION, Request, RequestEnvelope, Response, ResponseData, ScanJobState,
    ScanJobStatus, ScanProfile as DomainScanProfile,
};
use openguard_ipc::{read_frame, validate_response, write_frame};
use openguard_windows::platform_health;
use serde_json::Value;
use std::{
    ffi::OsString,
    fs::OpenOptions,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;
use windows_service::{
    service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState,
        ServiceType,
    },
    service_manager::{ServiceManager, ServiceManagerAccess},
};

const PIPE_PATH: &str = r"\\.\pipe\OpenGuard.v1";
const SERVICE_NAME: &str = "OpenGuardNative";

#[derive(Debug, Parser)]
#[command(
    name = "OpenGuardCLI",
    version,
    about = "OpenGuard native diagnostics and automation"
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
    #[arg(long, global = true)]
    pretty: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Report native runtime, privilege and service health.
    Doctor,
    /// Query the running native service.
    Health,
    /// Collect the current process and network snapshot.
    Snapshot,
    /// Read recent security events.
    Events {
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// Scan one local file and wait for its explainable verdict.
    Scan {
        target: PathBuf,
        #[arg(long, default_value_t = 120)]
        timeout_seconds: u64,
    },
    /// Run a named native scan profile for the signed-in user.
    ScanProfile {
        #[arg(value_enum)]
        profile: ProfileArgument,
        #[arg(long, default_value_t = 900)]
        timeout_seconds: u64,
    },
    /// Query a previously started scan job.
    ScanStatus { scan_id: String },
    /// Request cancellation for a scan job.
    CancelScan { scan_id: String },
    /// Rescan and quarantine one suspicious or malicious file.
    Quarantine {
        target: PathBuf,
        #[arg(long, default_value_t = 120)]
        timeout_seconds: u64,
    },
    /// List quarantine records owned by the signed-in user.
    QuarantineList {
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// Restore one quarantine item without overwriting an existing file.
    QuarantineRestore {
        quarantine_id: String,
        #[arg(long)]
        destination: Option<PathBuf>,
    },
    /// Inspect, install or roll back signed security content.
    Update {
        #[command(subcommand)]
        action: UpdateCommand,
    },
    /// Manage per-user scan exclusions and exact SHA-256 allow-list entries.
    Policy {
        #[command(subcommand)]
        action: PolicyCommand,
    },
    /// Install or manage the native Windows background service.
    Service {
        #[command(subcommand)]
        action: ServiceCommand,
    },
    /// Emit a protocol-compatible ping request without connecting.
    ProtocolFixture,
}

#[derive(Debug, Subcommand)]
enum ServiceCommand {
    Status,
    Install {
        /// Absolute path to OpenGuardService.exe. Defaults to the CLI directory.
        #[arg(long)]
        binary: Option<PathBuf>,
    },
    Start,
    Stop,
    Uninstall,
}

#[derive(Debug, Subcommand)]
enum UpdateCommand {
    Status,
    Install,
    Rollback,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// List path exclusions.
    Exclusions,
    /// Add a path exclusion. Directories include descendants unless --exact is set.
    Exclude {
        path: PathBuf,
        #[arg(long)]
        exact: bool,
    },
    /// Remove a path exclusion.
    RemoveExclusion { path: PathBuf },
    /// List exact SHA-256 allow-list entries.
    AllowedHashes,
    /// Add or update an exact SHA-256 allow-list entry.
    AllowHash {
        sha256: String,
        #[arg(long, default_value = "")]
        label: String,
    },
    /// Remove an exact SHA-256 allow-list entry.
    RemoveAllowedHash { sha256: String },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProfileArgument {
    Quick,
    Downloads,
    Startup,
    Full,
}

impl From<ProfileArgument> for DomainScanProfile {
    fn from(value: ProfileArgument) -> Self {
        match value {
            ProfileArgument::Quick => Self::Quick,
            ProfileArgument::Downloads => Self::Downloads,
            ProfileArgument::Startup => Self::Startup,
            ProfileArgument::Full => Self::Full,
        }
    }
}

fn main() -> Result<()> {
    let arguments = Arguments::parse();
    let value = match arguments.command {
        Command::Doctor => doctor(),
        Command::Health => response_value(send(Request::GetHealth)?)?,
        Command::Snapshot => response_value(send(Request::GetSnapshot)?)?,
        Command::Events { limit } => response_value(send(Request::RecentEvents { limit })?)?,
        Command::Scan {
            target,
            timeout_seconds,
        } => scan_file(&target, Duration::from_secs(timeout_seconds))?,
        Command::ScanProfile {
            profile,
            timeout_seconds,
        } => serde_json::to_value(start_scan_and_wait(
            Request::StartScan {
                target: String::new(),
                profile: Some(profile.into()),
            },
            Duration::from_secs(timeout_seconds),
        )?)?,
        Command::ScanStatus { scan_id } => response_value(send(Request::GetScan { scan_id })?)?,
        Command::CancelScan { scan_id } => response_value(send(Request::CancelScan { scan_id })?)?,
        Command::Quarantine {
            target,
            timeout_seconds,
        } => quarantine_file(&target, Duration::from_secs(timeout_seconds))?,
        Command::QuarantineList { limit } => {
            response_value(send(Request::ListQuarantine { limit })?)?
        }
        Command::QuarantineRestore {
            quarantine_id,
            destination,
        } => response_value(send(Request::RestoreQuarantine {
            quarantine_id,
            destination: destination.map(|path| path.display().to_string()),
        })?)?,
        Command::Update { action } => match action {
            UpdateCommand::Status => response_value(send(Request::GetContentStatus)?)?,
            UpdateCommand::Install => response_value(send(Request::InstallContentUpdate)?)?,
            UpdateCommand::Rollback => response_value(send(Request::RollbackContentUpdate)?)?,
        },
        Command::Policy { action } => match action {
            PolicyCommand::Exclusions => response_value(send(Request::ListExclusions)?)?,
            PolicyCommand::Exclude { path, exact } => {
                let path = path
                    .canonicalize()
                    .with_context(|| format!("resolve exclusion path {}", path.display()))?;
                response_value(send(Request::AddExclusion {
                    path: path.display().to_string(),
                    recursive: !exact,
                })?)?
            }
            PolicyCommand::RemoveExclusion { path } => {
                let path = path
                    .canonicalize()
                    .with_context(|| format!("resolve exclusion path {}", path.display()))?;
                response_value(send(Request::RemoveExclusion {
                    path: path.display().to_string(),
                })?)?
            }
            PolicyCommand::AllowedHashes => response_value(send(Request::ListAllowedHashes)?)?,
            PolicyCommand::AllowHash { sha256, label } => {
                response_value(send(Request::AllowHash { sha256, label })?)?
            }
            PolicyCommand::RemoveAllowedHash { sha256 } => {
                response_value(send(Request::RemoveAllowedHash { sha256 })?)?
            }
        },
        Command::Service { action } => manage_service(action)?,
        Command::ProtocolFixture => serde_json::to_value(RequestEnvelope::new(
            Uuid::new_v4().simple().to_string(),
            Request::Ping,
        ))?,
    };
    if arguments.pretty {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("{}", serde_json::to_string(&value)?);
    }
    Ok(())
}

fn manage_service(action: ServiceCommand) -> Result<Value> {
    match action {
        ServiceCommand::Install { binary } => {
            let binary = binary
                .map_or_else(service_binary_next_to_cli, Ok)?
                .canonicalize()?;
            let manager = ServiceManager::local_computer(
                None::<&str>,
                ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
            )
            .context("open the Windows Service Control Manager; installation requires elevation")?;
            let service = manager
                .create_service(
                    &ServiceInfo {
                        name: OsString::from(SERVICE_NAME),
                        display_name: OsString::from("OpenGuard Native Security Service"),
                        service_type: ServiceType::OWN_PROCESS,
                        start_type: ServiceStartType::AutoStart,
                        error_control: ServiceErrorControl::Normal,
                        executable_path: binary.clone(),
                        launch_arguments: Vec::new(),
                        dependencies: Vec::new(),
                        account_name: None,
                        account_password: None,
                    },
                    ServiceAccess::QUERY_STATUS | ServiceAccess::START,
                )
                .context("create OpenGuardNative service; installation requires elevation")?;
            service
                .start::<&str>(&[])
                .context("start OpenGuardNative")?;
            Ok(serde_json::json!({
                "service": SERVICE_NAME,
                "state": "start_requested",
                "binary": binary,
            }))
        }
        ServiceCommand::Status => {
            let service = open_service(ServiceAccess::QUERY_STATUS)?;
            let status = service
                .query_status()
                .context("query OpenGuardNative status")?;
            Ok(serde_json::json!({
                "service": SERVICE_NAME,
                "state": format!("{:?}", status.current_state).to_ascii_lowercase(),
                "process_id": status.process_id,
            }))
        }
        ServiceCommand::Start => {
            let service = open_service(ServiceAccess::START | ServiceAccess::QUERY_STATUS)?;
            service
                .start::<&str>(&[])
                .context("start OpenGuardNative")?;
            Ok(serde_json::json!({"service": SERVICE_NAME, "state": "start_requested"}))
        }
        ServiceCommand::Stop => {
            let service = open_service(ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
            let status = service.stop().context("stop OpenGuardNative")?;
            Ok(serde_json::json!({
                "service": SERVICE_NAME,
                "state": format!("{:?}", status.current_state).to_ascii_lowercase(),
            }))
        }
        ServiceCommand::Uninstall => {
            let service = open_service(
                ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
            )?;
            if matches!(
                service.query_status().map(|status| status.current_state),
                Ok(ServiceState::Running | ServiceState::StartPending)
            ) {
                let _ = service.stop();
            }
            service.delete().context("delete OpenGuardNative service")?;
            Ok(serde_json::json!({"service": SERVICE_NAME, "state": "delete_requested"}))
        }
    }
}

fn service_binary_next_to_cli() -> Result<PathBuf> {
    Ok(std::env::current_exe()
        .context("locate OpenGuardCLI executable")?
        .with_file_name("OpenGuardService.exe"))
}

fn open_service(access: ServiceAccess) -> Result<windows_service::service::Service> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("open the Windows Service Control Manager")?;
    manager
        .open_service(SERVICE_NAME, access)
        .context("open OpenGuardNative service")
}

fn doctor() -> Value {
    let platform = platform_health();
    let service = send(Request::GetHealth)
        .and_then(response_value)
        .unwrap_or_else(
            |error| serde_json::json!({"state": "offline", "error": error.to_string()}),
        );
    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": PROTOCOL_VERSION,
        "runtime": "native-rust",
        "platform": platform.platform,
        "process_token_available": platform.process_token_available,
        "elevated": platform.elevated,
        "service": service,
    })
}

fn scan_file(target: &Path, timeout: Duration) -> Result<Value> {
    Ok(serde_json::to_value(scan_path_status(target, timeout)?)?)
}

fn scan_path_status(target: &Path, timeout: Duration) -> Result<ScanJobStatus> {
    let target = target
        .canonicalize()
        .with_context(|| format!("resolve scan target {}", target.display()))?;
    start_scan_and_wait(
        Request::StartScan {
            target: target.display().to_string(),
            profile: None,
        },
        timeout,
    )
}

fn start_scan_and_wait(request: Request, timeout: Duration) -> Result<ScanJobStatus> {
    let response = send(request)?;
    let Response::Success { data } = response else {
        return Err(anyhow!("native service rejected scan request"));
    };
    let ResponseData::ScanStarted { scan_id } = *data else {
        return Err(anyhow!("native service returned the wrong scan response"));
    };
    let started = Instant::now();
    loop {
        if started.elapsed() > timeout {
            return Err(anyhow!(
                "scan {scan_id} timed out after {}s",
                timeout.as_secs()
            ));
        }
        let response = send(Request::GetScan {
            scan_id: scan_id.clone(),
        })?;
        let Response::Success { data } = response else {
            return Err(anyhow!("native service rejected scan status request"));
        };
        let ResponseData::ScanStatus(status) = *data else {
            return Err(anyhow!(
                "native service returned the wrong scan status response"
            ));
        };
        if matches!(status.state, ScanJobState::Queued | ScanJobState::Running) {
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        return Ok(status);
    }
}

fn quarantine_file(target: &Path, timeout: Duration) -> Result<Value> {
    if !target.is_file() {
        return Err(anyhow!("quarantine accepts one regular file at a time"));
    }
    let status = scan_path_status(target, timeout)?;
    let finding = status
        .finding
        .or_else(|| status.findings.into_iter().next())
        .ok_or_else(|| anyhow!("the scan did not return a file finding"))?;
    response_value(send(Request::Quarantine { finding })?)
}

fn send(body: Request) -> Result<Response> {
    let request_id = Uuid::new_v4().simple().to_string();
    let request = RequestEnvelope::new(request_id.clone(), body);
    let mut pipe = connect_pipe()?;
    write_frame(&mut pipe, &request).context("write native service request")?;
    let response = read_frame(&mut pipe).context("read native service response")?;
    validate_response(&response).context("validate native service response")?;
    if response.request_id != request_id {
        return Err(anyhow!(
            "native service response request identifier mismatch"
        ));
    }
    if let Response::Error { error } = &response.body {
        return Err(anyhow!(
            "{}: {}",
            serde_json::to_value(error.code)?,
            error.message
        ));
    }
    Ok(response.body)
}

fn connect_pipe() -> Result<std::fs::File> {
    let started = Instant::now();
    loop {
        match OpenOptions::new().read(true).write(true).open(PIPE_PATH) {
            Ok(pipe) => return Ok(pipe),
            Err(error)
                if matches!(error.raw_os_error(), Some(2 | 231))
                    && started.elapsed() < Duration::from_secs(3) =>
            {
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => {
                return Err(error).context("connect to the OpenGuard native service pipe");
            }
        }
    }
}

fn response_value(response: Response) -> Result<Value> {
    match response {
        Response::Success { data } => Ok(serde_json::to_value(*data)?),
        Response::Error { error } => Err(anyhow!(error.message)),
    }
}
