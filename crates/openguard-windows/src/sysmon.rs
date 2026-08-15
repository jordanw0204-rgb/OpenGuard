use openguard_domain::{CoverageNote, CoverageState, Severity};
use quick_xml::{Reader, XmlVersion, events::Event};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{Receiver, SyncSender, TrySendError, sync_channel},
    },
};
use windows::{
    Win32::System::EventLog::{
        EVT_HANDLE, EVT_SUBSCRIBE_NOTIFY_ACTION, EvtClose, EvtRender, EvtRenderEventXml,
        EvtSubscribe, EvtSubscribeActionDeliver, EvtSubscribeActionError,
        EvtSubscribeToFutureEvents,
    },
    core::{HSTRING, PCWSTR},
};

const SYSMON_CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";
const SYSMON_QUEUE_CAPACITY: usize = 2_048;
const MAXIMUM_EVENT_XML_BYTES: usize = 512 * 1024;
const MAXIMUM_FIELDS: usize = 128;
const MAXIMUM_FIELD_NAME_BYTES: usize = 128;
const MAXIMUM_FIELD_VALUE_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysmonEvent {
    pub event_id: u32,
    pub occurred_at: String,
    pub fields: BTreeMap<String, String>,
}

impl SysmonEvent {
    #[must_use]
    pub fn field(&self, name: &str) -> &str {
        self.fields.get(name).map_or("", String::as_str)
    }

    #[must_use]
    pub fn process_id(&self) -> Option<u32> {
        ["ProcessId", "SourceProcessId", "TargetProcessId"]
            .into_iter()
            .find_map(|name| parse_u32(self.field(name)))
    }

    #[must_use]
    pub fn correlation_id(&self) -> String {
        ["ProcessGuid", "SourceProcessGuid", "TargetProcessGuid"]
            .into_iter()
            .map(|name| self.field(name))
            .find(|value| !value.is_empty())
            .map_or_else(
                || format!("sysmon-pid-{}", self.process_id().unwrap_or_default()),
                |value| format!("sysmon-{value}"),
            )
    }

    #[must_use]
    pub fn image(&self) -> &str {
        ["Image", "SourceImage", "TargetImage"]
            .into_iter()
            .map(|name| self.field(name))
            .find(|value| !value.is_empty())
            .unwrap_or("")
    }

    #[must_use]
    pub fn target_path(&self) -> &str {
        ["TargetFilename", "TargetObject", "TargetImage", "PipeName"]
            .into_iter()
            .map(|name| self.field(name))
            .find(|value| !value.is_empty())
            .unwrap_or("")
    }

    #[must_use]
    pub fn remote_address(&self) -> &str {
        let destination = self.field("DestinationIp");
        if destination.is_empty() {
            self.field("QueryName")
        } else {
            destination
        }
    }

    #[must_use]
    pub const fn action(&self) -> &'static str {
        match self.event_id {
            1 => "process_create",
            3 => "network_connect",
            5 => "process_terminate",
            6 => "driver_load",
            7 => "image_load",
            8 => "create_remote_thread",
            10 => "process_access",
            11 => "file_create",
            12 => "registry_create_delete",
            13 => "registry_value_set",
            14 => "registry_rename",
            15 => "file_stream_hash",
            16 => "configuration_change",
            17 => "pipe_created",
            18 => "pipe_connected",
            19 => "wmi_filter",
            20 => "wmi_consumer",
            21 => "wmi_binding",
            22 => "dns_query",
            23 | 26 => "file_delete",
            25 => "process_tampering",
            255 => "sysmon_error",
            _ => "sysmon_event",
        }
    }

    #[must_use]
    pub const fn severity(&self) -> Severity {
        match self.event_id {
            8 | 25 => Severity::High,
            10 | 19..=21 | 255 => Severity::Medium,
            6 | 12..=15 | 17 | 18 | 23 | 26 => Severity::Low,
            _ => Severity::Info,
        }
    }

    #[must_use]
    pub fn title(&self) -> String {
        format!("Sysmon {}", self.action().replace('_', " "))
    }

    #[must_use]
    pub fn detail(&self) -> String {
        let mut parts = Vec::with_capacity(8);
        append_detail(&mut parts, "image", self.image());
        append_detail(&mut parts, "command", self.field("CommandLine"));
        append_detail(&mut parts, "target", self.target_path());
        append_detail(&mut parts, "destination", self.field("DestinationIp"));
        append_detail(&mut parts, "port", self.field("DestinationPort"));
        append_detail(&mut parts, "dns", self.field("QueryName"));
        append_detail(&mut parts, "access", self.field("GrantedAccess"));
        append_detail(&mut parts, "pipe", self.field("PipeName"));
        if parts.is_empty() {
            format!("Sysmon event {}", self.event_id)
        } else {
            parts.join("; ")
        }
    }
}

fn append_detail(parts: &mut Vec<String>, label: &str, value: &str) {
    if !value.is_empty() && !parts.iter().any(|part| part.ends_with(value)) {
        parts.push(format!("{label}={value}"));
    }
}

#[derive(Debug)]
struct CallbackContext {
    sender: SyncSender<SysmonEvent>,
    received: AtomicU64,
    dropped: AtomicU64,
    parse_failures: AtomicU64,
    subscription_errors: AtomicU64,
}

#[derive(Debug)]
pub struct SysmonMonitor {
    subscription: Option<EVT_HANDLE>,
    receiver: Receiver<SysmonEvent>,
    context: Box<CallbackContext>,
    state: CoverageState,
    detail: String,
}

impl Default for SysmonMonitor {
    fn default() -> Self {
        Self::start()
    }
}

impl SysmonMonitor {
    #[must_use]
    pub fn start() -> Self {
        let (sender, receiver) = sync_channel(SYSMON_QUEUE_CAPACITY);
        let context = Box::new(CallbackContext {
            sender,
            received: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            parse_failures: AtomicU64::new(0),
            subscription_errors: AtomicU64::new(0),
        });
        let channel = HSTRING::from(SYSMON_CHANNEL);
        let query = HSTRING::from("*");
        let context_pointer = std::ptr::from_ref(context.as_ref()).cast::<core::ffi::c_void>();
        let subscription = unsafe {
            EvtSubscribe(
                None,
                None,
                PCWSTR(channel.as_ptr()),
                PCWSTR(query.as_ptr()),
                None,
                Some(context_pointer),
                Some(subscription_callback),
                EvtSubscribeToFutureEvents.0,
            )
        };
        match subscription {
            Ok(subscription) => Self {
                subscription: Some(subscription),
                receiver,
                context,
                state: CoverageState::Active,
                detail: "Optional Sysmon Event Log subscription is active; existing Sysmon configuration is unchanged".into(),
            },
            Err(error) => Self {
                subscription: None,
                receiver,
                context,
                state: CoverageState::Limited,
                detail: format!(
                    "Optional Sysmon channel is unavailable ({error}); native ETW, WFP, USN, and file monitoring remain active"
                ),
            },
        }
    }

    #[must_use]
    pub fn drain(&self, limit: usize) -> Vec<SysmonEvent> {
        self.receiver
            .try_iter()
            .take(limit.clamp(1, SYSMON_QUEUE_CAPACITY))
            .collect()
    }

    #[must_use]
    pub fn coverage(&self) -> CoverageNote {
        CoverageNote {
            source: "sysmon_events".into(),
            state: self.state.clone(),
            detail: format!(
                "{}; {} received, {} queue-dropped, {} parse failures, {} subscription errors",
                self.detail,
                self.context.received.load(Ordering::Relaxed),
                self.context.dropped.load(Ordering::Relaxed),
                self.context.parse_failures.load(Ordering::Relaxed),
                self.context.subscription_errors.load(Ordering::Relaxed),
            ),
        }
    }
}

impl Drop for SysmonMonitor {
    fn drop(&mut self) {
        if let Some(subscription) = self.subscription.take() {
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
    let parsed = render_event_xml(event).and_then(|xml| parse_event_xml(&xml));
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

pub(crate) fn render_event_xml(event: EVT_HANDLE) -> Result<String, String> {
    let mut used = 0_u32;
    let mut properties = 0_u32;
    let _ = unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            0,
            None,
            &raw mut used,
            &raw mut properties,
        )
    };
    let used_usize = usize::try_from(used).map_err(|_| "event XML size overflow")?;
    if !(2..=MAXIMUM_EVENT_XML_BYTES).contains(&used_usize) {
        return Err(format!("event XML size {used_usize} is outside bounds"));
    }
    let mut buffer = vec![0_u16; used_usize.div_ceil(2)];
    unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            used,
            Some(buffer.as_mut_ptr().cast()),
            &raw mut used,
            &raw mut properties,
        )
    }
    .map_err(|error| format!("render Sysmon event XML: {error}"))?;
    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16(&buffer[..length]).map_err(|error| format!("decode event XML: {error}"))
}

pub(crate) fn parse_event_xml(xml: &str) -> Result<SysmonEvent, String> {
    if xml.len() > MAXIMUM_EVENT_XML_BYTES {
        return Err("event XML exceeds the bounded parser limit".into());
    }
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut event_id = None;
    let mut occurred_at = String::new();
    let mut active_element = String::new();
    let mut active_data_name = String::new();
    let mut fields = BTreeMap::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) => {
                let name = String::from_utf8_lossy(start.local_name().as_ref()).into_owned();
                active_element.clone_from(&name);
                if name == "Data" {
                    active_data_name.clear();
                    for attribute in start.attributes().flatten() {
                        if attribute.key.local_name().as_ref() == b"Name" {
                            let value = attribute
                                .decoded_and_normalized_value(
                                    XmlVersion::Implicit1_0,
                                    reader.decoder(),
                                )
                                .map_err(|error| format!("decode field name: {error}"))?;
                            if value.len() <= MAXIMUM_FIELD_NAME_BYTES {
                                active_data_name = value.into_owned();
                            }
                        }
                    }
                } else if name == "TimeCreated" {
                    occurred_at = attribute_value(&start, &reader, b"SystemTime")?;
                }
            }
            Ok(Event::Empty(empty)) => {
                if empty.local_name().as_ref() == b"TimeCreated" {
                    occurred_at = attribute_value(&empty, &reader, b"SystemTime")?;
                }
            }
            Ok(Event::Text(text)) => {
                let value = text
                    .xml_content(XmlVersion::Implicit1_0)
                    .map_err(|error| format!("decode event text: {error}"))?
                    .into_owned();
                if active_element == "EventID" {
                    event_id = value.trim().parse::<u32>().ok();
                } else if active_element == "Data"
                    && !active_data_name.is_empty()
                    && fields.len() < MAXIMUM_FIELDS
                    && value.len() <= MAXIMUM_FIELD_VALUE_BYTES
                {
                    fields.insert(active_data_name.clone(), value);
                }
            }
            Ok(Event::End(end)) => {
                if end.local_name().as_ref() == b"Data" {
                    active_data_name.clear();
                }
                active_element.clear();
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(format!("parse event XML: {error}")),
        }
    }

    Ok(SysmonEvent {
        event_id: event_id.ok_or("Sysmon event has no numeric EventID")?,
        occurred_at: if occurred_at.is_empty() {
            timestamp()
        } else {
            occurred_at
        },
        fields,
    })
}

fn attribute_value(
    element: &quick_xml::events::BytesStart<'_>,
    reader: &Reader<&[u8]>,
    wanted: &[u8],
) -> Result<String, String> {
    for attribute in element.attributes().flatten() {
        if attribute.key.local_name().as_ref() == wanted {
            return attribute
                .decoded_and_normalized_value(XmlVersion::Implicit1_0, reader.decoder())
                .map(std::borrow::Cow::into_owned)
                .map_err(|error| format!("decode XML attribute: {error}"));
        }
    }
    Ok(String::new())
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

fn timestamp() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    format!("unix:{seconds}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROCESS_ACCESS: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>10</EventID><TimeCreated SystemTime="2026-08-08T23:40:00.0000000Z"/></System><EventData><Data Name="SourceProcessGuid">{11111111-1111-1111-1111-111111111111}</Data><Data Name="SourceProcessId">0x4d2</Data><Data Name="SourceImage">C:\Users\Jordan\AppData\Local\Temp\sample.exe</Data><Data Name="TargetImage">C:\Windows\System32\lsass.exe</Data><Data Name="GrantedAccess">0x1010</Data></EventData></Event>"#;

    #[test]
    fn parses_bounded_process_access_event() {
        let event = parse_event_xml(PROCESS_ACCESS).expect("parse fixture");
        assert_eq!(event.event_id, 10);
        assert_eq!(event.process_id(), Some(1_234));
        assert_eq!(
            event.image(),
            r"C:\Users\Jordan\AppData\Local\Temp\sample.exe"
        );
        assert!(event.target_path().ends_with("lsass.exe"));
        assert_eq!(event.severity(), Severity::Medium);
        assert!(event.detail().contains("access=0x1010"));
    }

    #[test]
    fn malformed_and_oversized_events_fail_closed() {
        assert!(parse_event_xml("<Event><EventID>nope</EventID>").is_err());
        assert!(parse_event_xml(&"x".repeat(MAXIMUM_EVENT_XML_BYTES + 1)).is_err());
    }

    #[test]
    fn unknown_event_stays_informational() {
        let event = SysmonEvent {
            event_id: 999,
            occurred_at: "unix:0".into(),
            fields: BTreeMap::new(),
        };
        assert_eq!(event.action(), "sysmon_event");
        assert_eq!(event.severity(), Severity::Info);
    }
}
