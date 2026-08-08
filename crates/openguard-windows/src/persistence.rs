use openguard_domain::{
    CoverageNote, CoverageState, PersistenceInventory, PersistenceItem, Severity,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use winreg::{
    RegKey,
    enums::{HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY},
};

const MAX_PERSISTENCE_ITEMS: usize = 10_000;
const POWERSHELL_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone)]
pub struct PersistenceContext {
    pub owner_sid: String,
    pub user_profile: PathBuf,
    pub local_app_data: PathBuf,
    pub roaming_app_data: PathBuf,
}

/// Collects common user- and machine-level persistence mechanisms with per-source coverage.
#[must_use]
pub fn collect_persistence(context: &PersistenceContext) -> PersistenceInventory {
    let observed_at = timestamp();
    let mut items = Vec::new();
    let mut coverage = Vec::new();
    collect_services(&observed_at, &mut items, &mut coverage);
    collect_run_keys(context, &observed_at, &mut items, &mut coverage);
    collect_tasks_and_wmi(&observed_at, &mut items, &mut coverage);
    collect_browser_extensions(context, &observed_at, &mut items, &mut coverage);
    items.sort_by(|left, right| {
        right
            .risk
            .cmp(&left.risk)
            .then_with(|| left.category.cmp(&right.category))
            .then_with(|| {
                left.name
                    .to_ascii_lowercase()
                    .cmp(&right.name.to_ascii_lowercase())
            })
    });
    items.truncate(MAX_PERSISTENCE_ITEMS);
    PersistenceInventory {
        items,
        collected_at: observed_at,
        coverage,
    }
}

fn collect_services(
    observed_at: &str,
    items: &mut Vec<PersistenceItem>,
    coverage: &mut Vec<CoverageNote>,
) {
    let root = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(services) = root.open_subkey_with_flags(
        r"SYSTEM\CurrentControlSet\Services",
        KEY_READ | KEY_WOW64_64KEY,
    ) else {
        coverage.push(unavailable(
            "services_and_drivers",
            "The Services registry key was unavailable",
        ));
        return;
    };
    let mut count = 0_usize;
    for name in services.enum_keys().flatten() {
        let Ok(key) = services.open_subkey_with_flags(&name, KEY_READ) else {
            continue;
        };
        let kind = key.get_value::<u32, _>("Type").unwrap_or_default();
        if kind & 0x33 == 0 {
            continue;
        }
        let start = key.get_value::<u32, _>("Start").unwrap_or(3);
        if start == 4 {
            continue;
        }
        let command = key.get_value::<String, _>("ImagePath").unwrap_or_default();
        let display = key
            .get_value::<String, _>("DisplayName")
            .unwrap_or_else(|_| name.clone());
        let category = if kind & 0x03 != 0 {
            "driver"
        } else {
            "service"
        };
        let (risk, evidence) = command_risk(&command, category);
        items.push(PersistenceItem {
            id: stable_id(category, &name),
            category: category.into(),
            name: display,
            command,
            location: format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{name}"),
            state: start_state(start).into(),
            risk,
            evidence,
            detected_at: observed_at.into(),
            response_capability: if category == "service" {
                "disable_restore".into()
            } else {
                "none".into()
            },
        });
        count += 1;
        if count >= MAX_PERSISTENCE_ITEMS {
            break;
        }
    }
    coverage.push(CoverageNote {
        source: "services_and_drivers".into(),
        state: CoverageState::Active,
        detail: format!("Inventoried {count} enabled service and driver registrations"),
    });
}

fn collect_run_keys(
    context: &PersistenceContext,
    observed_at: &str,
    items: &mut Vec<PersistenceItem>,
    coverage: &mut Vec<CoverageNote>,
) {
    let paths = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ];
    let mut opened = 0_usize;
    let mut count = 0_usize;
    let users = RegKey::predef(HKEY_USERS);
    for path in paths {
        if let Ok(key) = users.open_subkey_with_flags(
            format!(r"{}\{path}", context.owner_sid),
            KEY_READ | KEY_WOW64_64KEY,
        ) {
            opened += 1;
            count += collect_run_values(
                &key,
                "run_key_user",
                &format!(r"HKU\{}\{path}", context.owner_sid),
                observed_at,
                items,
            );
        }
        for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
            if let Ok(key) =
                RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(path, KEY_READ | view)
            {
                opened += 1;
                count += collect_run_values(
                    &key,
                    "run_key_machine",
                    &format!(r"HKLM\{path}"),
                    observed_at,
                    items,
                );
            }
        }
    }
    coverage.push(CoverageNote {
        source: "run_and_runonce".into(),
        state: if opened == 0 {
            CoverageState::Limited
        } else {
            CoverageState::Active
        },
        detail: format!("Read {opened} visible Run/RunOnce keys and found {count} values"),
    });
}

fn collect_run_values(
    key: &RegKey,
    category: &str,
    location: &str,
    observed_at: &str,
    items: &mut Vec<PersistenceItem>,
) -> usize {
    let mut count = 0;
    for (name, _) in key.enum_values().flatten() {
        let Ok(command) = key.get_value::<String, _>(&name) else {
            continue;
        };
        let (risk, evidence) = command_risk(&command, category);
        items.push(PersistenceItem {
            id: stable_id(category, &format!("{location}|{name}")),
            category: category.into(),
            name,
            command,
            location: location.into(),
            state: "enabled".into(),
            risk,
            evidence,
            detected_at: observed_at.into(),
            response_capability: "none".into(),
        });
        count += 1;
    }
    count
}

fn collect_tasks_and_wmi(
    observed_at: &str,
    items: &mut Vec<PersistenceItem>,
    coverage: &mut Vec<CoverageNote>,
) {
    const SCRIPT: &str = r"
$ErrorActionPreference='SilentlyContinue'
$result=[ordered]@{items=@();tasks_error='';wmi_error=''}
try {
  $result.items += @(Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
    $cmd=(($_.Actions | ForEach-Object { (($_.Execute + ' ' + $_.Arguments).Trim()) }) -join ' | ')
    [ordered]@{category='scheduled_task';name=$_.TaskName;command=$cmd;location=($_.TaskPath+$_.TaskName);state=[string]$_.State;response_capability='disable_restore'}
  })
} catch { $result.tasks_error=$_.Exception.Message }
try {
  $result.items += @(Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction Stop | ForEach-Object {
    [ordered]@{category='wmi_consumer';name=$_.Name;command=(($_.ExecutablePath+' '+$_.CommandLineTemplate).Trim());location='root/subscription:CommandLineEventConsumer';state='enabled';response_capability='none'}
  })
  $result.items += @(Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
    [ordered]@{category='wmi_consumer';name=$_.Name;command=$_.ScriptText;location='root/subscription:ActiveScriptEventConsumer';state='enabled';response_capability='none'}
  })
} catch { $result.wmi_error=$_.Exception.Message }
$result | ConvertTo-Json -Compress -Depth 6
";
    match run_powershell_json(SCRIPT) {
        Ok(document) => {
            let task_count = document
                .items
                .iter()
                .filter(|item| item.category == "scheduled_task")
                .count();
            let wmi_count = document
                .items
                .iter()
                .filter(|item| item.category == "wmi_consumer")
                .count();
            for item in document.items {
                let (mut risk, mut evidence) = command_risk(&item.command, &item.category);
                if item.category == "wmi_consumer" {
                    risk = risk.max(Severity::Medium);
                    evidence.push(
                        "Permanent WMI consumers execute outside normal startup folders".into(),
                    );
                }
                items.push(PersistenceItem {
                    id: stable_id(&item.category, &item.location),
                    category: item.category,
                    name: item.name,
                    command: item.command,
                    location: item.location,
                    state: item.state,
                    risk,
                    evidence,
                    detected_at: observed_at.into(),
                    response_capability: item.response_capability,
                });
            }
            coverage.push(CoverageNote {
                source: "scheduled_tasks".into(),
                state: if document.tasks_error.is_empty() {
                    CoverageState::Active
                } else {
                    CoverageState::Limited
                },
                detail: if document.tasks_error.is_empty() {
                    format!(
                        "Inventoried {task_count} scheduled tasks through the Task Scheduler module"
                    )
                } else {
                    format!(
                        "Scheduled-task inventory was limited: {}",
                        document.tasks_error
                    )
                },
            });
            coverage.push(CoverageNote {
                source: "wmi_persistence".into(),
                state: if document.wmi_error.is_empty() {
                    CoverageState::Active
                } else {
                    CoverageState::Limited
                },
                detail: if document.wmi_error.is_empty() {
                    format!("Inventoried {wmi_count} permanent WMI command/script consumers")
                } else {
                    format!(
                        "WMI persistence inventory was limited: {}",
                        document.wmi_error
                    )
                },
            });
        }
        Err(error) => {
            coverage.push(unavailable("scheduled_tasks", &error));
            coverage.push(unavailable("wmi_persistence", &error));
        }
    }
}

#[allow(clippy::too_many_lines)]
fn collect_browser_extensions(
    context: &PersistenceContext,
    observed_at: &str,
    items: &mut Vec<PersistenceItem>,
    coverage: &mut Vec<CoverageNote>,
) {
    let roots = [
        (
            "edge_extension",
            context.local_app_data.join(r"Microsoft\Edge\User Data"),
        ),
        (
            "chrome_extension",
            context.local_app_data.join(r"Google\Chrome\User Data"),
        ),
    ];
    let mut manifests = 0_usize;
    for (category, root) in roots {
        let Ok(profiles) = fs::read_dir(&root) else {
            continue;
        };
        for profile in profiles.flatten() {
            let extensions = profile.path().join("Extensions");
            let Ok(extension_ids) = fs::read_dir(extensions) else {
                continue;
            };
            for extension_id in extension_ids.flatten() {
                let Ok(versions) = fs::read_dir(extension_id.path()) else {
                    continue;
                };
                for version in versions.flatten() {
                    let manifest = version.path().join("manifest.json");
                    let Ok(bytes) = fs::read(&manifest) else {
                        continue;
                    };
                    let value: serde_json::Value =
                        serde_json::from_slice(&bytes).unwrap_or_default();
                    let name = value
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("Browser extension");
                    let permissions = value
                        .get("permissions")
                        .and_then(serde_json::Value::as_array)
                        .map(|values| {
                            values
                                .iter()
                                .filter_map(serde_json::Value::as_str)
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    let broad = permissions.iter().any(|permission| {
                        matches!(
                            *permission,
                            "webRequest" | "cookies" | "nativeMessaging" | "debugger"
                        )
                    });
                    items.push(PersistenceItem {
                        id: stable_id(category, &extension_id.file_name().to_string_lossy()),
                        category: category.into(),
                        name: name.into(),
                        command: manifest.display().to_string(),
                        location: extension_id.path().display().to_string(),
                        state: "installed".into(),
                        risk: if broad {
                            Severity::Medium
                        } else {
                            Severity::Info
                        },
                        evidence: if broad {
                            vec![format!(
                                "Extension requests sensitive permissions: {}",
                                permissions.join(", ")
                            )]
                        } else {
                            vec!["Installed browser extension manifest".into()]
                        },
                        detected_at: observed_at.into(),
                        response_capability: "none".into(),
                    });
                    manifests += 1;
                    break;
                }
            }
        }
    }
    let firefox = context.roaming_app_data.join(r"Mozilla\Firefox\Profiles");
    if let Ok(profiles) = fs::read_dir(firefox) {
        for profile in profiles.flatten() {
            let path = profile.path().join("extensions.json");
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
            if let Some(addons) = document.get("addons").and_then(serde_json::Value::as_array) {
                for addon in addons.iter().filter(|value| {
                    value
                        .get("active")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false)
                }) {
                    let id = addon
                        .get("id")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown");
                    let name = addon
                        .get("defaultLocale")
                        .and_then(|value| value.get("name"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or(id);
                    items.push(PersistenceItem {
                        id: stable_id("firefox_extension", id),
                        category: "firefox_extension".into(),
                        name: name.into(),
                        command: path.display().to_string(),
                        location: format!("{} · {id}", profile.path().display()),
                        state: "installed".into(),
                        risk: Severity::Info,
                        evidence: vec!["Active Firefox add-on registration".into()],
                        detected_at: observed_at.into(),
                        response_capability: "none".into(),
                    });
                    manifests += 1;
                }
            }
        }
    }
    coverage.push(CoverageNote {
        source: "browser_extensions".into(),
        state: if context.local_app_data.as_os_str().is_empty() {
            CoverageState::Limited
        } else {
            CoverageState::Active
        },
        detail: format!(
            "Inventoried {manifests} Chrome, Edge, and Firefox extension registrations"
        ),
    });
}

#[derive(Debug, Deserialize)]
struct PowerShellInventory {
    #[serde(default)]
    items: Vec<PowerShellItem>,
    #[serde(default)]
    tasks_error: String,
    #[serde(default)]
    wmi_error: String,
}

#[derive(Debug, Deserialize)]
struct PowerShellItem {
    category: String,
    name: String,
    #[serde(default)]
    command: String,
    location: String,
    state: String,
    response_capability: String,
}

fn run_powershell_json(script: &str) -> Result<PowerShellInventory, String> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let output_path = std::env::temp_dir().join(format!(
        "openguard-persistence-{}-{}.json",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let output_file = File::create(&output_path).map_err(|error| error.to_string())?;
    let mut child = Command::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::from(output_file))
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("start persistence inventory: {error}"))?;
    let deadline = Instant::now() + POWERSHELL_TIMEOUT;
    let status = loop {
        match child.try_wait().map_err(|error| error.to_string())? {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = fs::remove_file(&output_path);
                return Err("persistence inventory timed out after 15 seconds".into());
            }
            None => thread::sleep(Duration::from_millis(25)),
        }
    };
    if !status.success() {
        let _ = fs::remove_file(&output_path);
        return Err(format!("persistence inventory exited with {status}"));
    }
    let mut bytes = Vec::new();
    File::open(&output_path)
        .and_then(|mut file| file.by_ref().take(4 * 1024 * 1024).read_to_end(&mut bytes))
        .map_err(|error| error.to_string())?;
    let _ = fs::remove_file(&output_path);
    serde_json::from_slice(&bytes).map_err(|error| format!("parse persistence inventory: {error}"))
}

fn command_risk(command: &str, category: &str) -> (Severity, Vec<String>) {
    let lowered = command.to_ascii_lowercase();
    let mut evidence = Vec::new();
    let mut risk = Severity::Info;
    if lowered.contains(r"\appdata\")
        || lowered.contains(r"\temp\")
        || lowered.contains(r"\downloads\")
    {
        risk = Severity::Medium;
        evidence.push("Startup command references a user-writable location".into());
    }
    if lowered.contains("-enc ")
        || lowered.contains("frombase64string")
        || lowered.contains("javascript:")
    {
        risk = Severity::High;
        evidence.push("Startup command contains encoded or script-based execution".into());
    }
    if category == "driver" && !lowered.is_empty() && !lowered.contains(r"\system32\") {
        risk = risk.max(Severity::Medium);
        evidence.push("Driver image is outside the normal System32 path".into());
    }
    if evidence.is_empty() {
        evidence.push("Registered startup mechanism; no high-confidence malicious signal".into());
    }
    (risk, evidence)
}

fn stable_id(category: &str, identity: &str) -> String {
    let digest = Sha256::digest(format!("{}\0{}", category, identity.to_ascii_lowercase()));
    format!("{category}-{}", hex::encode(&digest[..12]))
}

fn start_state(value: u32) -> &'static str {
    match value {
        0 => "boot",
        1 => "system",
        2 => "automatic",
        3 => "manual",
        4 => "disabled",
        _ => "unknown",
    }
}

fn unavailable(source: &str, detail: &str) -> CoverageNote {
    CoverageNote {
        source: source.into(),
        state: CoverageState::Unavailable,
        detail: detail.into(),
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
    fn command_risk_requires_explainable_signals() {
        assert_eq!(
            command_risk(r"C:\Windows\System32\svchost.exe", "service").0,
            Severity::Info
        );
        let encoded = command_risk(r"powershell.exe -enc AAAA", "scheduled_task");
        assert_eq!(encoded.0, Severity::High);
        assert!(!encoded.1.is_empty());
    }

    #[test]
    fn stable_ids_do_not_expose_commands_and_are_repeatable() {
        let first = stable_id("service", "Example");
        assert_eq!(first, stable_id("service", "example"));
        assert!(!first.contains("Example"));
    }
}
