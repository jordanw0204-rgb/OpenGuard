use crate::sysmon::{parse_event_xml, render_event_xml};
use openguard_domain::{CoverageNote, CoverageState, Severity};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    mpsc::{Receiver, SyncSender, TrySendError, sync_channel},
};
use windows::{
    Win32::System::EventLog::{
        EVT_HANDLE, EVT_SUBSCRIBE_NOTIFY_ACTION, EvtClose, EvtSubscribe, EvtSubscribeActionDeliver,
        EvtSubscribeActionError, EvtSubscribeToFutureEvents,
    },
    core::{HSTRING, PCWSTR},
};

const EVENT_QUEUE_CAPACITY: usize = 2_048;

const SOURCES: [(&str, &str); 2] = [
    ("Security", "*[System[(EventID=4688 or EventID=4689)]]"),
    (
        "Microsoft-Windows-Windows Defender/Operational",
        "*[System[(EventID=1116 or EventID=1117 or EventID=5007)]]",
    ),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsEvent {
    pub source: String,
    pub event_id: u32,
    pub occurred_at: String,
    fields: std::collections::BTreeMap<String, String>,
}

impl WindowsEvent {
    #[must_use]
    pub fn field(&self, name: &str) -> &str {
        self.fields.get(name).map_or("", String::as_str)
    }

    #[must_use]
    pub fn process_id(&self) -> Option<u32> {
        ["NewProcessId", "ProcessId", "ProcessID"]
            .into_iter()
            .find_map(|name| parse_u32(self.field(name)))
    }

    #[must_use]
    pub fn path(&self) -> &str {
        ["NewProcessName", "Path", "Process Name", "ProcessName"]
            .into_iter()
            .map(|name| self.field(name))
            .find(|value| !value.is_empty())
            .unwrap_or("")
    }

    #[must_use]
    pub const fn action(&self) -> &'static str {
        match self.event_id {
            4688 => "process_create_audit",
            4689 => "process_terminate_audit",
            1116 => "defender_threat_detected",
            1117 => "defender_threat_action",
            5007 => "defender_configuration_changed",
            _ => "windows_event",
        }
    }

    #[must_use]
    pub const fn severity(&self) -> Severity {
        match self.event_id {
            1116 => Severity::High,
            1117 | 5007 => Severity::Medium,
            _ => Severity::Info,
        }
    }

    #[must_use]
    pub fn title(&self) -> String {
        match self.event_id {
            4688 => "Windows audited process creation".into(),
            4689 => "Windows audited process termination".into(),
            1116 => "Microsoft Defender detected a threat".into(),
            1117 => "Microsoft Defender took threat action".into(),
            5007 => "Microsoft Defender configuration changed".into(),
            _ => format!("Windows event {}", self.event_id),
        }
    }

    #[must_use]
    pub fn detail(&self) -> String {
        let mut parts = Vec::with_capacity(8);
        for (label, field) in [
            ("process", "NewProcessName"),
            ("command", "CommandLine"),
            ("parent", "ParentProcessName"),
            ("threat", "Threat Name"),
            ("path", "Path"),
            ("action", "Action Name"),
            ("old", "Old Value"),
            ("new", "New Value"),
        ] {
            let value = self.field(field);
            if !value.is_empty() && value.len() <= 32 * 1024 {
                parts.push(format!("{label}={value}"));
            }
        }
        if parts.is_empty() {
            format!("{} event {}", self.source, self.event_id)
        } else {
            parts.join("; ")
        }
    }

    #[must_use]
    pub fn correlation_id(&self) -> String {
        format!(
            "windows-event-{}-{}-{}-{}",
            self.source.replace(['\\', '/', ' '], "-"),
            self.event_id,
            self.process_id().unwrap_or_default(),
            self.occurred_at
        )
    }
}

#[derive(Debug)]
struct CallbackContext {
    source: &'static str,
    sender: SyncSender<WindowsEvent>,
    received: AtomicU64,
    dropped: AtomicU64,
    parse_failures: AtomicU64,
    subscription_errors: AtomicU64,
}

#[derive(Debug)]
// Each callback receives a pointer to its heap allocation. Boxing keeps that address stable while
// the vector grows and until all subscription handles are closed in `Drop`.
#[allow(clippy::vec_box)]
pub struct NativeEventLogMonitor {
    subscriptions: Vec<EVT_HANDLE>,
    receiver: Receiver<WindowsEvent>,
    contexts: Vec<Box<CallbackContext>>,
    failures: Vec<String>,
}

impl Default for NativeEventLogMonitor {
    fn default() -> Self {
        Self::start()
    }
}

impl NativeEventLogMonitor {
    #[must_use]
    pub fn start() -> Self {
        let (sender, receiver) = sync_channel(EVENT_QUEUE_CAPACITY);
        let mut monitor = Self {
            subscriptions: Vec::new(),
            receiver,
            contexts: Vec::new(),
            failures: Vec::new(),
        };
        for (source, query) in SOURCES {
            let context = Box::new(CallbackContext {
                source,
                sender: sender.clone(),
                received: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
                parse_failures: AtomicU64::new(0),
                subscription_errors: AtomicU64::new(0),
            });
            let context_pointer = std::ptr::from_ref(context.as_ref()).cast::<core::ffi::c_void>();
            let source_text = HSTRING::from(source);
            let query_text = HSTRING::from(query);
            let subscription = unsafe {
                EvtSubscribe(
                    None,
                    None,
                    PCWSTR(source_text.as_ptr()),
                    PCWSTR(query_text.as_ptr()),
                    None,
                    Some(context_pointer),
                    Some(subscription_callback),
                    EvtSubscribeToFutureEvents.0,
                )
            };
            match subscription {
                Ok(handle) => monitor.subscriptions.push(handle),
                Err(error) => monitor.failures.push(format!("{source}: {error}")),
            }
            monitor.contexts.push(context);
        }
        monitor
    }

    #[must_use]
    pub fn drain(&self, limit: usize) -> Vec<WindowsEvent> {
        self.receiver
            .try_iter()
            .take(limit.clamp(1, EVENT_QUEUE_CAPACITY))
            .collect()
    }

    #[must_use]
    pub fn coverage(&self) -> CoverageNote {
        let received = self
            .contexts
            .iter()
            .map(|context| context.received.load(Ordering::Relaxed))
            .sum::<u64>();
        let dropped = self
            .contexts
            .iter()
            .map(|context| context.dropped.load(Ordering::Relaxed))
            .sum::<u64>();
        let parse_failures = self
            .contexts
            .iter()
            .map(|context| context.parse_failures.load(Ordering::Relaxed))
            .sum::<u64>();
        let subscription_errors = self
            .contexts
            .iter()
            .map(|context| context.subscription_errors.load(Ordering::Relaxed))
            .sum::<u64>();
        let state = if self.subscriptions.len() == SOURCES.len() {
            CoverageState::Active
        } else {
            CoverageState::Limited
        };
        let failure = if self.failures.is_empty() {
            "all requested channels subscribed".into()
        } else {
            format!("unavailable channels: {}", self.failures.join(" | "))
        };
        CoverageNote {
            source: "windows_event_log".into(),
            state,
            detail: format!(
                "Security process-audit and Microsoft Defender operational subscriptions: {}/{} active, {failure}; {received} received, {dropped} queue-dropped, {parse_failures} parse failures, {subscription_errors} subscription errors",
                self.subscriptions.len(),
                SOURCES.len()
            ),
        }
    }
}

impl Drop for NativeEventLogMonitor {
    fn drop(&mut self) {
        for subscription in self.subscriptions.drain(..) {
            let _ = unsafe { EvtClose(subscription) };
        }
    }
}

unsafe extern "system" fn subscription_callback(
    action: EVT_SUBSCRIBE_NOTIFY_ACTION,
    context: *const core::ffi::c_void,
    event: EVT_HANDLE,
) -> u32 {
    let Some(context) = (unsafe { context.cast::<CallbackContext>().as_ref() }) else {
        return 0;
    };
    if action == EvtSubscribeActionError {
        context.subscription_errors.fetch_add(1, Ordering::Relaxed);
        return 0;
    }
    if action != EvtSubscribeActionDeliver {
        return 0;
    }
    context.received.fetch_add(1, Ordering::Relaxed);
    let parsed = render_event_xml(event)
        .and_then(|xml| parse_event_xml(&xml))
        .map(|parsed| WindowsEvent {
            source: context.source.into(),
            event_id: parsed.event_id,
            occurred_at: parsed.occurred_at,
            fields: parsed.fields,
        });
    match parsed {
        Ok(event) => match context.sender.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                context.dropped.fetch_add(1, Ordering::Relaxed);
            }
        },
        Err(_) => {
            context.parse_failures.fetch_add(1, Ordering::Relaxed);
        }
    }
    0
}

fn parse_u32(value: &str) -> Option<u32> {
    let value = value.trim();
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(
            || value.parse().ok(),
            |hex| u32::from_str_radix(hex, 16).ok(),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROCESS_CREATE: &str = r#"<Event><System><EventID>4688</EventID><TimeCreated SystemTime="2026-08-08T12:00:00Z" /></System><EventData><Data Name="NewProcessId">0x4d2</Data><Data Name="NewProcessName">C:\Tools\sample.exe</Data><Data Name="CommandLine">sample.exe --run</Data><Data Name="ParentProcessName">C:\Windows\explorer.exe</Data></EventData></Event>"#;

    #[test]
    fn normalizes_security_process_creation() {
        let parsed = parse_event_xml(PROCESS_CREATE).expect("parse fixture");
        let event = WindowsEvent {
            source: "Security".into(),
            event_id: parsed.event_id,
            occurred_at: parsed.occurred_at,
            fields: parsed.fields,
        };
        assert_eq!(event.process_id(), Some(1_234));
        assert_eq!(event.path(), r"C:\Tools\sample.exe");
        assert_eq!(event.action(), "process_create_audit");
        assert!(event.detail().contains("sample.exe --run"));
    }

    #[test]
    fn assigns_defender_detection_high_severity() {
        let event = WindowsEvent {
            source: "Microsoft-Windows-Windows Defender/Operational".into(),
            event_id: 1116,
            occurred_at: "2026-08-08T12:00:00Z".into(),
            fields: std::collections::BTreeMap::from([(
                "Threat Name".into(),
                "Test threat".into(),
            )]),
        };
        assert_eq!(event.severity(), Severity::High);
        assert!(event.detail().contains("Test threat"));
    }
}
