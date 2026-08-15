use openguard_domain::Severity;
use openguard_windows::SysmonEvent;
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};

const CHAIN_WINDOW: Duration = Duration::from_mins(10);
const ALERT_COOLDOWN: Duration = Duration::from_hours(1);
const MAXIMUM_CHAINS: usize = 4_096;
const MAXIMUM_SIGNALS_PER_CHAIN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BehaviorAlert {
    pub event_type: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub detail: String,
    pub process_id: Option<u32>,
    pub path: String,
    pub remote_address: String,
    pub correlation_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Rule {
    CredentialExfiltration,
    InjectionBeacon,
    DropPersistenceBeacon,
}

impl Rule {
    const fn event_type(self) -> &'static str {
        match self {
            Self::CredentialExfiltration => "credential_access_network_chain",
            Self::InjectionBeacon => "injection_network_chain",
            Self::DropPersistenceBeacon => "drop_persistence_network_chain",
        }
    }

    const fn severity(self) -> Severity {
        match self {
            Self::CredentialExfiltration | Self::InjectionBeacon => Severity::Critical,
            Self::DropPersistenceBeacon => Severity::High,
        }
    }

    const fn title(self) -> &'static str {
        match self {
            Self::CredentialExfiltration => "Credential access followed by outbound activity",
            Self::InjectionBeacon => "Process injection followed by outbound activity",
            Self::DropPersistenceBeacon => "File drop, persistence, and outbound activity",
        }
    }

    const fn mitre(self) -> &'static str {
        match self {
            Self::CredentialExfiltration => "T1003.001 + T1041",
            Self::InjectionBeacon => "T1055 + T1071",
            Self::DropPersistenceBeacon => "T1105 + T1547/T1546 + T1071",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignalKind {
    CredentialAccess,
    Injection,
    FileDrop,
    Persistence,
    Network,
}

#[derive(Debug, Clone)]
struct Signal {
    kind: SignalKind,
    observed_at: Instant,
    detail: String,
    remote_address: String,
}

#[derive(Debug)]
struct Chain {
    process_id: Option<u32>,
    path: String,
    last_seen: Instant,
    signals: VecDeque<Signal>,
}

#[derive(Debug, Default)]
pub struct BehaviorChainEngine {
    chains: HashMap<String, Chain>,
    reported: HashMap<(String, Rule), Instant>,
}

impl BehaviorChainEngine {
    #[must_use]
    pub fn ingest(&mut self, events: &[SysmonEvent]) -> Vec<BehaviorAlert> {
        self.ingest_at(events, Instant::now())
    }

    fn ingest_at(&mut self, events: &[SysmonEvent], now: Instant) -> Vec<BehaviorAlert> {
        self.prune(now);
        let mut alerts = Vec::new();
        for event in events {
            let Some(kind) = classify(event) else {
                continue;
            };
            let Some(correlation_id) = stable_correlation_id(event) else {
                continue;
            };
            let chain = self
                .chains
                .entry(correlation_id.clone())
                .or_insert_with(|| Chain {
                    process_id: event.process_id(),
                    path: event.image().to_owned(),
                    last_seen: now,
                    signals: VecDeque::new(),
                });
            chain.last_seen = now;
            chain.process_id = event.process_id().or(chain.process_id);
            if !event.image().is_empty() {
                event.image().clone_into(&mut chain.path);
            }
            chain.signals.push_back(Signal {
                kind,
                observed_at: now,
                detail: event.detail(),
                remote_address: event.remote_address().to_owned(),
            });
            while chain.signals.len() > MAXIMUM_SIGNALS_PER_CHAIN {
                chain.signals.pop_front();
            }

            for rule in matching_rules(chain) {
                let report_key = (correlation_id.clone(), rule);
                if self
                    .reported
                    .get(&report_key)
                    .is_some_and(|last| now.saturating_duration_since(*last) < ALERT_COOLDOWN)
                {
                    continue;
                }
                self.reported.insert(report_key, now);
                alerts.push(build_alert(rule, &correlation_id, chain));
            }
        }
        self.enforce_capacity();
        alerts
    }

    fn prune(&mut self, now: Instant) {
        self.chains.retain(|_, chain| {
            chain
                .signals
                .retain(|signal| now.saturating_duration_since(signal.observed_at) <= CHAIN_WINDOW);
            !chain.signals.is_empty()
        });
        self.reported
            .retain(|_, observed_at| now.saturating_duration_since(*observed_at) <= ALERT_COOLDOWN);
    }

    fn enforce_capacity(&mut self) {
        while self.chains.len() > MAXIMUM_CHAINS {
            let Some(oldest) = self
                .chains
                .iter()
                .min_by_key(|(_, chain)| chain.last_seen)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.chains.remove(&oldest);
            self.reported.retain(|(key, _), _| key != &oldest);
        }
    }
}

fn classify(event: &SysmonEvent) -> Option<SignalKind> {
    match event.event_id {
        10 if is_lsass(event.target_path())
            && has_memory_read_access(event.field("GrantedAccess")) =>
        {
            Some(SignalKind::CredentialAccess)
        }
        8 | 25 => Some(SignalKind::Injection),
        11 if is_executable_drop(event.target_path()) => Some(SignalKind::FileDrop),
        12..=14 if is_persistence_target(event.target_path()) => Some(SignalKind::Persistence),
        19..=21 => Some(SignalKind::Persistence),
        3 if is_external_address(event.field("DestinationIp")) => Some(SignalKind::Network),
        22 if is_external_dns_query(event.field("QueryName")) => Some(SignalKind::Network),
        _ => None,
    }
}

fn stable_correlation_id(event: &SysmonEvent) -> Option<String> {
    ["ProcessGuid", "SourceProcessGuid"]
        .into_iter()
        .map(|field| event.field(field))
        .find(|value| !value.is_empty())
        .map(|value| format!("sysmon-{value}"))
        .or_else(|| {
            event
                .process_id()
                .filter(|pid| *pid != 0)
                .map(|pid| format!("sysmon-pid-{pid}"))
        })
}

fn matching_rules(chain: &Chain) -> Vec<Rule> {
    let has = |kind| chain.signals.iter().any(|signal| signal.kind == kind);
    let mut rules = Vec::with_capacity(3);
    if has(SignalKind::CredentialAccess) && has(SignalKind::Network) {
        rules.push(Rule::CredentialExfiltration);
    }
    if has(SignalKind::Injection) && has(SignalKind::Network) {
        rules.push(Rule::InjectionBeacon);
    }
    if has(SignalKind::FileDrop) && has(SignalKind::Persistence) && has(SignalKind::Network) {
        rules.push(Rule::DropPersistenceBeacon);
    }
    rules
}

fn build_alert(rule: Rule, correlation_id: &str, chain: &Chain) -> BehaviorAlert {
    let evidence = chain
        .signals
        .iter()
        .map(|signal| signal.detail.as_str())
        .collect::<Vec<_>>()
        .join(" -> ");
    let remote_address = chain
        .signals
        .iter()
        .rev()
        .find(|signal| signal.kind == SignalKind::Network)
        .map_or("", |signal| signal.remote_address.as_str())
        .to_owned();
    BehaviorAlert {
        event_type: rule.event_type(),
        severity: rule.severity(),
        title: rule.title(),
        detail: format!(
            "Correlated within a 10-minute window; MITRE {}; evidence: {evidence}",
            rule.mitre()
        ),
        process_id: chain.process_id,
        path: chain.path.clone(),
        remote_address,
        correlation_id: correlation_id.to_owned(),
    }
}

fn is_lsass(path: &str) -> bool {
    path.rsplit(['\\', '/'])
        .next()
        .is_some_and(|name| name.eq_ignore_ascii_case("lsass.exe"))
}

fn has_memory_read_access(value: &str) -> bool {
    let trimmed = value.trim();
    let parsed = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        .or_else(|| trimmed.parse::<u32>().ok());
    parsed.is_some_and(|mask| mask & (0x0010 | 0x0020 | 0x0008) != 0)
}

fn is_executable_drop(path: &str) -> bool {
    let normalized = path.replace('/', "\\").to_ascii_lowercase();
    let user_writable = [
        "\\users\\",
        "\\programdata\\",
        "\\windows\\temp\\",
        "\\recycle.bin\\",
    ]
    .iter()
    .any(|segment| normalized.contains(segment));
    let executable = [
        ".exe", ".dll", ".scr", ".com", ".msi", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta",
    ]
    .iter()
    .any(|extension| normalized.ends_with(extension));
    user_writable && executable
}

fn is_persistence_target(target: &str) -> bool {
    let normalized = target.replace('/', "\\").to_ascii_lowercase();
    [
        "\\software\\microsoft\\windows\\currentversion\\run",
        "\\software\\microsoft\\windows nt\\currentversion\\winlogon",
        "\\system\\currentcontrolset\\services\\",
        "\\image file execution options\\",
    ]
    .iter()
    .any(|segment| normalized.contains(segment))
}

fn is_external_dns_query(query: &str) -> bool {
    let normalized = query.trim_end_matches('.').to_ascii_lowercase();
    let suffix = normalized.rsplit_once('.').map(|(_, suffix)| suffix);
    !normalized.is_empty() && normalized != "localhost" && !matches!(suffix, Some("local" | "lan"))
}

fn is_external_address(address: &str) -> bool {
    match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(value)) => !is_non_public_v4(value),
        Ok(IpAddr::V6(value)) => {
            !(value.is_loopback()
                || value.is_unspecified()
                || value.is_unique_local()
                || value.is_unicast_link_local())
        }
        Err(_) => false,
    }
}

fn is_non_public_v4(value: Ipv4Addr) -> bool {
    value.is_private()
        || value.is_loopback()
        || value.is_link_local()
        || value.is_unspecified()
        || value.is_broadcast()
        || value.octets()[0] == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn event(id: u32, fields: &[(&str, &str)]) -> SysmonEvent {
        SysmonEvent {
            event_id: id,
            occurred_at: "2026-08-08T12:00:00Z".into(),
            fields: fields
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    #[test]
    fn correlates_lsass_access_and_external_network() {
        let mut engine = BehaviorChainEngine::default();
        let now = Instant::now();
        assert!(
            engine
                .ingest_at(
                    &[event(
                        10,
                        &[
                            ("SourceProcessGuid", "{A}"),
                            ("SourceProcessId", "1234"),
                            ("SourceImage", r"C:\Users\Jordan\tool.exe"),
                            ("TargetImage", r"C:\Windows\System32\lsass.exe"),
                            ("GrantedAccess", "0x1010"),
                        ],
                    )],
                    now,
                )
                .is_empty()
        );
        let alerts = engine.ingest_at(
            &[event(
                3,
                &[
                    ("ProcessGuid", "{A}"),
                    ("ProcessId", "1234"),
                    ("Image", r"C:\Users\Jordan\tool.exe"),
                    ("DestinationIp", "203.0.113.8"),
                    ("DestinationPort", "443"),
                ],
            )],
            now + Duration::from_secs(2),
        );
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].event_type, "credential_access_network_chain");
        assert_eq!(alerts[0].severity, Severity::Critical);
    }

    #[test]
    fn correlates_drop_persistence_and_dns() {
        let mut engine = BehaviorChainEngine::default();
        let now = Instant::now();
        let alerts = engine.ingest_at(
            &[
                event(
                    11,
                    &[
                        ("ProcessGuid", "{B}"),
                        ("Image", r"C:\Users\Jordan\dropper.exe"),
                        (
                            "TargetFilename",
                            r"C:\Users\Jordan\AppData\Roaming\update.exe",
                        ),
                    ],
                ),
                event(
                    13,
                    &[
                        ("ProcessGuid", "{B}"),
                        ("Image", r"C:\Users\Jordan\dropper.exe"),
                        (
                            "TargetObject",
                            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Update",
                        ),
                    ],
                ),
                event(
                    22,
                    &[
                        ("ProcessGuid", "{B}"),
                        ("Image", r"C:\Users\Jordan\dropper.exe"),
                        ("QueryName", "control.example"),
                    ],
                ),
            ],
            now,
        );
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].event_type, "drop_persistence_network_chain");
    }

    #[test]
    fn ignores_single_signals_private_destinations_and_expired_chains() {
        let mut engine = BehaviorChainEngine::default();
        let now = Instant::now();
        assert!(
            engine
                .ingest_at(
                    &[event(
                        8,
                        &[("SourceProcessGuid", "{C}"), ("SourceProcessId", "9")],
                    )],
                    now,
                )
                .is_empty()
        );
        assert!(
            engine
                .ingest_at(
                    &[event(
                        3,
                        &[
                            ("ProcessGuid", "{C}"),
                            ("ProcessId", "9"),
                            ("DestinationIp", "192.168.1.2"),
                        ],
                    )],
                    now + Duration::from_secs(1),
                )
                .is_empty()
        );
        assert!(
            engine
                .ingest_at(
                    &[event(
                        3,
                        &[
                            ("ProcessGuid", "{C}"),
                            ("ProcessId", "9"),
                            ("DestinationIp", "8.8.8.8"),
                        ],
                    )],
                    now + CHAIN_WINDOW + Duration::from_secs(1),
                )
                .is_empty()
        );
    }

    #[test]
    fn suppresses_duplicate_chain_alerts_during_cooldown() {
        let mut engine = BehaviorChainEngine::default();
        let now = Instant::now();
        let first = [
            event(25, &[("ProcessGuid", "{D}"), ("ProcessId", "7")]),
            event(
                3,
                &[
                    ("ProcessGuid", "{D}"),
                    ("ProcessId", "7"),
                    ("DestinationIp", "8.8.4.4"),
                ],
            ),
        ];
        assert_eq!(engine.ingest_at(&first, now).len(), 1);
        assert!(
            engine
                .ingest_at(&first, now + Duration::from_secs(10))
                .is_empty()
        );
    }
}
