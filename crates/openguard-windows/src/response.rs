use crate::{WindowsError, process_image_path};
use std::{net::IpAddr, path::Path, process::Command};
use windows::Win32::{
    Foundation::CloseHandle,
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
        },
        Threading::{
            OpenProcess, OpenThread, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
            ResumeThread, SuspendThread, THREAD_SUSPEND_RESUME, TerminateProcess,
        },
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessControlResult {
    pub affected_threads: Vec<u32>,
    pub detail: String,
}

/// Terminates, suspends, or resumes an exact PID only after its executable path is revalidated.
///
/// # Errors
///
/// Returns an error when identity changes, the target is protected, or an API call fails.
pub fn control_process(
    action: &str,
    pid: u32,
    expected_path: &Path,
) -> Result<ProcessControlResult, WindowsError> {
    if pid <= 4 || pid == std::process::id() || expected_path.as_os_str().is_empty() {
        return Err(WindowsError::Api(
            "protected or incomplete process target".into(),
        ));
    }
    let actual = process_image_path(pid)?;
    if !same_path(&actual, expected_path) {
        return Err(WindowsError::Api(format!(
            "process identity changed: expected {}, found {}",
            expected_path.display(),
            actual.display()
        )));
    }
    match action {
        "terminate" => terminate(pid),
        "suspend" => control_threads(pid, true),
        "resume" => control_threads(pid, false),
        _ => Err(WindowsError::Api(format!(
            "unsupported process action {action}"
        ))),
    }
}

fn terminate(pid: u32) -> Result<ProcessControlResult, WindowsError> {
    let handle = unsafe {
        OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            pid,
        )
    }
    .map_err(|error| WindowsError::Api(format!("open PID {pid} for termination: {error}")))?;
    let result = unsafe { TerminateProcess(handle, 0x4f47) }
        .map_err(|error| WindowsError::Api(format!("terminate PID {pid}: {error}")));
    let _ = unsafe { CloseHandle(handle) };
    result?;
    Ok(ProcessControlResult {
        affected_threads: Vec::new(),
        detail: format!("Terminated PID {pid}"),
    })
}

fn control_threads(pid: u32, suspend: bool) -> Result<ProcessControlResult, WindowsError> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }
        .map_err(|error| WindowsError::Api(format!("enumerate threads: {error}")))?;
    let mut entry = THREADENTRY32 {
        dwSize: u32::try_from(std::mem::size_of::<THREADENTRY32>()).unwrap_or(u32::MAX),
        ..Default::default()
    };
    let mut affected = Vec::new();
    let mut next = unsafe { Thread32First(snapshot, &raw mut entry) }.is_ok();
    while next {
        if entry.th32OwnerProcessID == pid
            && let Ok(thread) =
                unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID) }
        {
            let result = if suspend {
                unsafe { SuspendThread(thread) }
            } else {
                unsafe { ResumeThread(thread) }
            };
            if result != u32::MAX {
                affected.push(entry.th32ThreadID);
            }
            let _ = unsafe { CloseHandle(thread) };
        }
        next = unsafe { Thread32Next(snapshot, &raw mut entry) }.is_ok();
    }
    let _ = unsafe { CloseHandle(snapshot) };
    if affected.is_empty() {
        return Err(WindowsError::Api(format!(
            "no controllable threads found for PID {pid}"
        )));
    }
    Ok(ProcessControlResult {
        detail: format!(
            "{} {} threads in PID {pid}",
            if suspend { "Suspended" } else { "Resumed" },
            affected.len()
        ),
        affected_threads: affected,
    })
}

/// Adds a narrowly scoped outbound Windows Firewall rule through the trusted system netsh.
///
/// # Errors
///
/// Returns an error for invalid addresses/paths or a rejected firewall operation.
pub fn block_remote_address(
    rule_name: &str,
    address: &str,
    program: Option<&Path>,
) -> Result<(), WindowsError> {
    let _: IpAddr = address
        .split('%')
        .next()
        .unwrap_or(address)
        .parse()
        .map_err(|_| WindowsError::Api("remote address is not a valid IP address".into()))?;
    validate_rule_name(rule_name)?;
    let mut command = Command::new(system_tool("netsh.exe"));
    command.args([
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &format!("name={rule_name}"),
        "dir=out",
        "action=block",
        &format!("remoteip={address}"),
        "enable=yes",
        "profile=any",
    ]);
    if let Some(program) = program.filter(|path| path.is_absolute()) {
        command.arg(format!("program={}", program.display()));
    }
    run_tool(command, "add temporary firewall rule")
}

/// Removes an OpenGuard-created Windows Firewall rule by its exact validated name.
///
/// # Errors
///
/// Returns an error when the rule name is invalid or Windows rejects removal.
pub fn remove_firewall_rule(rule_name: &str) -> Result<(), WindowsError> {
    validate_rule_name(rule_name)?;
    let mut command = Command::new(system_tool("netsh.exe"));
    command.args([
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        &format!("name={rule_name}"),
    ]);
    run_tool(command, "remove temporary firewall rule")
}

/// Disables or restores a service or scheduled task using trusted Windows system tools.
/// Drivers, WMI consumers, and browser extensions are intentionally report-only.
///
/// # Errors
///
/// Returns an error for unsupported categories, invalid locations, or rejected changes.
pub fn set_persistence_enabled(
    category: &str,
    location: &str,
    enabled: bool,
    previous_state: Option<&str>,
) -> Result<(), WindowsError> {
    if location.is_empty() || location.len() > 1_024 || location.contains(['\0', '\r', '\n']) {
        return Err(WindowsError::Api("invalid persistence location".into()));
    }
    match category {
        "service" => {
            let name = location
                .rsplit('\\')
                .next()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| WindowsError::Api("service location has no key name".into()))?;
            let start = if enabled {
                match previous_state.unwrap_or("manual") {
                    "automatic" => "auto",
                    "boot" => "boot",
                    "system" => "system",
                    _ => "demand",
                }
            } else {
                "disabled"
            };
            let mut command = Command::new(system_tool("sc.exe"));
            command.args(["config", name, "start=", start]);
            run_tool(
                command,
                if enabled {
                    "restore service startup"
                } else {
                    "disable service startup"
                },
            )
        }
        "scheduled_task" => {
            if !location.starts_with('\\') {
                return Err(WindowsError::Api(
                    "scheduled-task path must be absolute".into(),
                ));
            }
            let mut command = Command::new(system_tool("schtasks.exe"));
            command.args([
                "/Change",
                "/TN",
                location,
                if enabled { "/ENABLE" } else { "/DISABLE" },
            ]);
            run_tool(
                command,
                if enabled {
                    "restore scheduled task"
                } else {
                    "disable scheduled task"
                },
            )
        }
        _ => Err(WindowsError::Api(format!(
            "automatic response is not supported for {category} persistence"
        ))),
    }
}

fn validate_rule_name(value: &str) -> Result<(), WindowsError> {
    if value.starts_with("OpenGuard Temporary Block ")
        && value.len() <= 120
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b" -_".contains(&byte))
    {
        Ok(())
    } else {
        Err(WindowsError::Api(
            "invalid OpenGuard firewall rule name".into(),
        ))
    }
}

fn run_tool(mut command: Command, action: &str) -> Result<(), WindowsError> {
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    use std::os::windows::process::CommandExt;
    let output = command
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|error| WindowsError::Api(format!("{action}: {error}")))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        Err(WindowsError::Api(format!("{action}: {detail}")))
    }
}

fn system_tool(name: &str) -> std::path::PathBuf {
    std::env::var_os("SystemRoot")
        .map(std::path::PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"))
        .join("System32")
        .join(name)
}

fn same_path(left: &Path, right: &Path) -> bool {
    let normalize = |value: &Path| {
        std::fs::canonicalize(value)
            .unwrap_or_else(|_| value.to_path_buf())
            .to_string_lossy()
            .replace('/', "\\")
            .trim_start_matches(r"\\?\")
            .to_ascii_lowercase()
    };
    normalize(left) == normalize(right)
}
