use openguard_domain::{RiskAssessment, Severity, SignatureStatus};
use std::collections::BTreeSet;

const DUAL_USE_NAMES: &[&str] = &[
    "certutil.exe",
    "cmd.exe",
    "cscript.exe",
    "mshta.exe",
    "powershell.exe",
    "pwsh.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "wscript.exe",
];

const OFFICE_PARENT_NAMES: &[&str] = &[
    "excel.exe",
    "msaccess.exe",
    "onenote.exe",
    "outlook.exe",
    "powerpnt.exe",
    "winword.exe",
];

const BROWSER_PARENT_NAMES: &[&str] = &["brave.exe", "chrome.exe", "firefox.exe", "msedge.exe"];

#[derive(Debug, Clone)]
pub struct RiskEnvironment {
    pub user_profile: String,
    pub temp_roots: Vec<String>,
    pub trusted_roots: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BehaviorContext<'a> {
    pub parent_name: &'a str,
    pub has_public_network: bool,
    pub suspicious_destination: bool,
    pub malicious_destination: bool,
}

impl RiskEnvironment {
    #[must_use]
    pub fn from_process_environment() -> Self {
        let variable =
            |key: &str, fallback: &str| std::env::var(key).unwrap_or_else(|_| fallback.to_owned());
        let temp_roots = BTreeSet::from([variable("TEMP", ""), variable("TMP", "")]);
        Self {
            user_profile: normalize(&variable("USERPROFILE", "")),
            temp_roots: temp_roots
                .into_iter()
                .map(|value| normalize(&value))
                .filter(|value| !value.is_empty())
                .collect(),
            trusted_roots: [
                variable("WINDIR", r"C:\Windows"),
                variable("ProgramFiles", r"C:\Program Files"),
                variable("ProgramFiles(x86)", r"C:\Program Files (x86)"),
            ]
            .into_iter()
            .map(|value| normalize(&value))
            .filter(|value| !value.is_empty())
            .collect(),
        }
    }
}

#[must_use]
pub fn assess_process(
    name: &str,
    path: &str,
    signature: SignatureStatus,
    accessible: bool,
    environment: &RiskEnvironment,
) -> RiskAssessment {
    if !accessible || path.is_empty() {
        return RiskAssessment {
            score: 5,
            severity: Severity::Info,
            reasons: vec!["Windows limited access to executable details".into()],
        };
    }

    let mut score = 0_u8;
    let mut reasons = Vec::new();
    let lowered_name = name.to_ascii_lowercase();
    let lowered_path = normalize(path);
    let in_temp = environment
        .temp_roots
        .iter()
        .any(|root| is_beneath(&lowered_path, root));
    let downloads = format!(r"{}\downloads", environment.user_profile);
    let in_downloads =
        !environment.user_profile.is_empty() && is_beneath(&lowered_path, &downloads);
    let in_trusted_root = environment
        .trusted_roots
        .iter()
        .any(|root| is_beneath(&lowered_path, root));

    if in_temp {
        add(&mut score, 35);
        reasons.push("Executable is running from a temporary directory".into());
    } else if in_downloads {
        add(&mut score, 18);
        reasons.push("Executable is running directly from Downloads".into());
    } else if !environment.user_profile.is_empty()
        && is_beneath(&lowered_path, &environment.user_profile)
    {
        add(&mut score, 8);
        reasons.push("Executable is running from a user-writable profile directory".into());
    }

    match signature {
        SignatureStatus::Untrusted => {
            add(&mut score, 25);
            reasons.push(
                "Authenticode trust verification failed or no trusted signature was found".into(),
            );
        }
        SignatureStatus::Unknown => {
            add(&mut score, 5);
            reasons.push("Authenticode trust could not be determined".into());
        }
        SignatureStatus::Trusted | SignatureStatus::NotApplicable => {}
    }

    if DUAL_USE_NAMES.contains(&lowered_name.as_str()) {
        add(&mut score, 7);
        reasons.push("Process is a legitimate dual-use execution tool".into());
        if in_temp || in_downloads {
            add(&mut score, 13);
            reasons.push("Dual-use tool was launched from a higher-risk location".into());
        }
    }

    let actual_name = lowered_path.rsplit('\\').next().unwrap_or_default();
    if !actual_name.is_empty() && !lowered_name.is_empty() && actual_name != lowered_name {
        add(&mut score, 25);
        reasons.push("Reported process name does not match the executable filename".into());
    }

    if !in_trusted_root && signature == SignatureStatus::Untrusted {
        add(&mut score, 10);
        reasons.push("Unsigned executable is outside Windows and Program Files".into());
    }

    RiskAssessment {
        score,
        severity: Severity::from_score(score),
        reasons,
    }
}

/// Adds explainable cross-signal evidence to a process risk assessment.
///
/// The rules deliberately require multiple independent signals for common
/// applications so normal browsing and trusted software do not become alerts.
#[must_use]
pub fn correlate_behavior(
    base: &RiskAssessment,
    name: &str,
    signature: SignatureStatus,
    is_new: bool,
    context: BehaviorContext<'_>,
) -> RiskAssessment {
    let mut result = base.clone();
    let lowered_name = name.to_ascii_lowercase();
    let lowered_parent = context.parent_name.to_ascii_lowercase();
    let is_dual_use = DUAL_USE_NAMES.contains(&lowered_name.as_str());

    if context.malicious_destination {
        add(&mut result.score, 50);
        result.reasons.push(
            "Behavior: process communicates with a locally classified malicious destination".into(),
        );
    } else if context.suspicious_destination && (is_new || signature != SignatureStatus::Trusted) {
        add(&mut result.score, 25);
        result.reasons.push(
            "Behavior: new or untrusted process communicates with a suspicious destination".into(),
        );
    }

    if is_new && context.has_public_network {
        add(&mut result.score, 15);
        result
            .reasons
            .push("Behavior: newly observed executable opened a public network connection".into());
    }

    if signature == SignatureStatus::Untrusted && context.has_public_network {
        add(&mut result.score, 12);
        result
            .reasons
            .push("Behavior: untrusted executable has active public network access".into());
    }

    if is_dual_use && OFFICE_PARENT_NAMES.contains(&lowered_parent.as_str()) {
        add(&mut result.score, 45);
        result.reasons.push(format!(
            "Behavior: Office application {} launched dual-use tool {name}",
            context.parent_name
        ));
    } else if is_dual_use
        && BROWSER_PARENT_NAMES.contains(&lowered_parent.as_str())
        && (is_new || signature != SignatureStatus::Trusted)
    {
        add(&mut result.score, 25);
        result.reasons.push(format!(
            "Behavior: browser {} launched a new or untrusted dual-use tool {name}",
            context.parent_name
        ));
    }

    result.severity = Severity::from_score(result.score);
    result.reasons.sort();
    result.reasons.dedup();
    result
}

fn add(score: &mut u8, amount: u8) {
    *score = score.saturating_add(amount).min(100);
}

fn normalize(value: &str) -> String {
    value
        .replace('/', "\\")
        .trim_end_matches(['\\', '/'])
        .to_lowercase()
}

fn is_beneath(candidate: &str, root: &str) -> bool {
    !root.is_empty() && (candidate == root || candidate.starts_with(&format!(r"{root}\")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment() -> RiskEnvironment {
        RiskEnvironment {
            user_profile: r"c:\users\test".into(),
            temp_roots: vec![r"c:\users\test\temp".into()],
            trusted_roots: vec![r"c:\windows".into(), r"c:\program files".into()],
        }
    }

    #[test]
    fn trusted_windows_binary_has_no_risk_signal() {
        let result = assess_process(
            "tool.exe",
            r"C:\Windows\System32\tool.exe",
            SignatureStatus::Trusted,
            true,
            &environment(),
        );
        assert_eq!(result.score, 0);
        assert!(result.reasons.is_empty());
    }

    #[test]
    fn unsigned_temp_executable_is_high_and_explained() {
        let result = assess_process(
            "payload.exe",
            r"C:\Users\Test\Temp\payload.exe",
            SignatureStatus::Untrusted,
            true,
            &environment(),
        );
        assert!(result.score >= 65);
        assert_eq!(result.severity, Severity::High);
        assert!(
            result
                .reasons
                .iter()
                .any(|reason| reason.contains("temporary"))
        );
        assert!(
            result
                .reasons
                .iter()
                .any(|reason| reason.contains("Authenticode"))
        );
    }

    #[test]
    fn inaccessible_process_is_not_claimed_malicious() {
        let result = assess_process(
            "System",
            "",
            SignatureStatus::Unknown,
            false,
            &environment(),
        );
        assert!(result.score < 15);
        assert!(result.reasons[0].contains("limited access"));
    }

    #[test]
    fn trusted_browser_network_activity_is_not_penalized() {
        let base = RiskAssessment::default();
        let result = correlate_behavior(
            &base,
            "chrome.exe",
            SignatureStatus::Trusted,
            false,
            BehaviorContext {
                parent_name: "explorer.exe",
                has_public_network: true,
                ..BehaviorContext::default()
            },
        );
        assert_eq!(result, base);
    }

    #[test]
    fn established_trusted_process_with_suspicious_destination_needs_more_evidence() {
        let base = RiskAssessment::default();
        let result = correlate_behavior(
            &base,
            "signed-client.exe",
            SignatureStatus::Trusted,
            false,
            BehaviorContext {
                parent_name: "explorer.exe",
                has_public_network: true,
                suspicious_destination: true,
                malicious_destination: false,
            },
        );
        assert_eq!(result, base);
    }

    #[test]
    fn trusted_established_browser_child_does_not_trigger_browser_rule() {
        let base = RiskAssessment::default();
        let result = correlate_behavior(
            &base,
            "powershell.exe",
            SignatureStatus::Trusted,
            false,
            BehaviorContext {
                parent_name: "msedge.exe",
                ..BehaviorContext::default()
            },
        );
        assert_eq!(result, base);
    }

    #[test]
    fn new_untrusted_process_with_malicious_destination_is_high_risk() {
        let result = correlate_behavior(
            &RiskAssessment::default(),
            "payload.exe",
            SignatureStatus::Untrusted,
            true,
            BehaviorContext {
                parent_name: "explorer.exe",
                has_public_network: true,
                malicious_destination: true,
                suspicious_destination: false,
            },
        );
        assert!(result.score >= 65);
        assert!(result.severity >= Severity::High);
        assert!(
            result
                .reasons
                .iter()
                .any(|reason| reason.contains("malicious destination"))
        );
    }

    #[test]
    fn office_spawning_dual_use_tool_is_explainable() {
        let result = correlate_behavior(
            &RiskAssessment::default(),
            "powershell.exe",
            SignatureStatus::Trusted,
            false,
            BehaviorContext {
                parent_name: "WINWORD.EXE",
                ..BehaviorContext::default()
            },
        );
        assert!(result.score >= 45);
        assert!(
            result
                .reasons
                .iter()
                .any(|reason| reason.contains("Office application"))
        );
    }
}
