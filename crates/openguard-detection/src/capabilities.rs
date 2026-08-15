use goblin::pe::PE;
use openguard_domain::ThreatCapability;
use std::collections::HashSet;

const STRING_SAMPLE_BYTES: usize = 4 * 1024 * 1024;

/// Bounded static capability assessment used as evidence by higher-level
/// runtime correlation. The score is deliberately capped below malicious.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilityAssessment {
    pub score: u16,
    pub capabilities: Vec<ThreatCapability>,
}

/// Extracts PE imports and a bounded text sample, then requires combinations
/// of independent primitives before reporting sensitive capabilities.
#[must_use]
pub fn inspect_capabilities(content: &[u8]) -> CapabilityAssessment {
    let strings = String::from_utf8_lossy(&content[..content.len().min(STRING_SAMPLE_BYTES)])
        .to_ascii_lowercase();
    let imports = pe_imports(content);
    assess(&imports, &strings)
}

fn pe_imports(content: &[u8]) -> HashSet<String> {
    let Ok(pe) = PE::parse(content) else {
        return HashSet::new();
    };
    pe.imports
        .iter()
        .map(|import| import.name.to_ascii_lowercase())
        .collect()
}

#[allow(clippy::too_many_lines)]
fn assess(imports: &HashSet<String>, strings: &str) -> CapabilityAssessment {
    let mut assessment = CapabilityAssessment::default();

    let keyboard = primitive_count(
        imports,
        strings,
        &[
            "setwindowshookexa",
            "setwindowshookexw",
            "getasynckeystate",
            "getkeystate",
            "getkeyboardstate",
            "registerrawinputdevices",
        ],
    );
    if keyboard >= 2 {
        push(
            &mut assessment,
            12,
            "keyboard_input_capture",
            "T1056.001",
            62,
            evidence(
                imports,
                &[
                    "setwindowshookexa",
                    "setwindowshookexw",
                    "getasynckeystate",
                    "getkeystate",
                    "getkeyboardstate",
                    "registerrawinputdevices",
                ],
            ),
        );
    }

    let capture = primitive_count(
        imports,
        strings,
        &[
            "bitblt",
            "getdc",
            "getwindowdc",
            "printwindow",
            "acquirenextframe",
        ],
    );
    if capture >= 2 {
        push(
            &mut assessment,
            10,
            "screen_capture",
            "T1113",
            58,
            evidence(
                imports,
                &[
                    "bitblt",
                    "getdc",
                    "getwindowdc",
                    "printwindow",
                    "acquirenextframe",
                ],
            ),
        );
    }

    let cross_process_write = has_primitive(
        imports,
        strings,
        &["writeprocessmemory", "ntwritevirtualmemory"],
    );
    let remote_allocate = has_primitive(
        imports,
        strings,
        &["virtualallocex", "ntallocatevirtualmemory"],
    );
    let remote_execute = has_primitive(
        imports,
        strings,
        &[
            "createremotethread",
            "ntcreatethreadex",
            "queueuserapc",
            "setthreadcontext",
        ],
    );
    if cross_process_write && remote_allocate && remote_execute {
        push(
            &mut assessment,
            48,
            "process_injection",
            "T1055",
            94,
            evidence(
                imports,
                &[
                    "writeprocessmemory",
                    "ntwritevirtualmemory",
                    "virtualallocex",
                    "ntallocatevirtualmemory",
                    "createremotethread",
                    "ntcreatethreadex",
                    "queueuserapc",
                    "setthreadcontext",
                ],
            ),
        );
    }

    let browser_artifact = contains_any(
        strings,
        &[
            "\\google\\chrome\\user data",
            "\\microsoft\\edge\\user data",
            "\\mozilla\\firefox\\profiles",
            "login data",
            "network\\cookies",
            "cookies.sqlite",
        ],
    );
    let decrypts_dpapi = has_any(imports, &["cryptunprotectdata", "ncryptdecrypt"])
        || contains_any(strings, &["cryptunprotectdata", "os_crypt.encrypted_key"]);
    let database_access = contains_any(
        strings,
        &["sqlite3_open", "sqlite3_prepare", "cookies.sqlite"],
    ) || has_any(imports, &["copyfilea", "copyfilew"]);
    if browser_artifact && decrypts_dpapi && database_access {
        push(
            &mut assessment,
            34,
            "browser_credential_access",
            "T1555.003",
            88,
            vec![
                "browser profile artifact references".into(),
                "credential decryption primitive".into(),
                "database or file-copy primitive".into(),
            ],
        );
    }

    let lsass_target = strings.contains("lsass");
    let process_dump = has_primitive(imports, strings, &["minidumpwritedump"])
        || contains_any(strings, &["comsvcs.dll", "procdump", "sekurlsa"]);
    if lsass_target && process_dump {
        push(
            &mut assessment,
            45,
            "os_credential_dumping",
            "T1003.001",
            92,
            vec![
                "LSASS target reference".into(),
                "process dump or credential extraction primitive".into(),
            ],
        );
    }

    let input_control = keyboard > 0
        || has_primitive(
            imports,
            strings,
            &["sendinput", "mouse_event", "keybd_event"],
        );
    let network = has_primitive(
        imports,
        strings,
        &[
            "connect",
            "wsaconnect",
            "internetconnecta",
            "internetconnectw",
            "winhttpconnect",
        ],
    );
    if capture >= 2 && input_control && network {
        push(
            &mut assessment,
            24,
            "remote_control_stack",
            "T1219.002",
            76,
            vec![
                "screen-capture primitives".into(),
                "input-monitoring or control primitives".into(),
                "outbound network primitive".into(),
            ],
        );
    }

    // Static capability evidence alone never produces a malicious verdict.
    assessment.score = assessment.score.min(70);
    assessment
}

fn push(
    assessment: &mut CapabilityAssessment,
    score: u16,
    category: &str,
    technique: &str,
    confidence: u8,
    evidence: Vec<String>,
) {
    assessment.score = assessment.score.saturating_add(score);
    assessment.capabilities.push(ThreatCapability {
        category: category.into(),
        mitre_technique: technique.into(),
        confidence,
        evidence,
    });
}

fn primitive_count(imports: &HashSet<String>, strings: &str, names: &[&str]) -> usize {
    names
        .iter()
        .filter(|name| imports.contains(**name) || strings.contains(**name))
        .count()
}

fn has_primitive(imports: &HashSet<String>, strings: &str, names: &[&str]) -> bool {
    names
        .iter()
        .any(|name| imports.contains(*name) || strings.contains(*name))
}

fn has_any(imports: &HashSet<String>, names: &[&str]) -> bool {
    names.iter().any(|name| imports.contains(*name))
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

fn evidence(imports: &HashSet<String>, names: &[&str]) -> Vec<String> {
    names
        .iter()
        .filter(|name| imports.contains(**name))
        .map(|name| format!("imports {name}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn imports(names: &[&str]) -> HashSet<String> {
        names.iter().map(|name| (*name).into()).collect()
    }

    #[test]
    fn a_single_dual_use_api_does_not_create_a_capability() {
        let assessment = assess(&imports(&["getasynckeystate"]), "");
        assert!(assessment.capabilities.is_empty());
        assert_eq!(assessment.score, 0);
    }

    #[test]
    fn correlated_keyboard_apis_create_low_weight_evidence() {
        let assessment = assess(&imports(&["setwindowshookexw", "getasynckeystate"]), "");
        assert_eq!(
            assessment.capabilities[0].category,
            "keyboard_input_capture"
        );
        assert!(assessment.score < 15);
    }

    #[test]
    fn injection_requires_write_allocate_and_execute() {
        let incomplete = assess(&imports(&["writeprocessmemory", "virtualallocex"]), "");
        assert!(incomplete.capabilities.is_empty());

        let complete = assess(
            &imports(&["writeprocessmemory", "virtualallocex", "createremotethread"]),
            "",
        );
        assert_eq!(complete.capabilities[0].category, "process_injection");
        assert_eq!(complete.capabilities[0].confidence, 94);
    }

    #[test]
    fn browser_credential_access_requires_three_signal_groups() {
        let imports = imports(&["cryptunprotectdata", "copyfilew"]);
        let absent_profile = assess(&imports, "ordinary database utility");
        assert!(absent_profile.capabilities.is_empty());

        let correlated = assess(
            &imports,
            r"c:\users\x\appdata\local\google\chrome\user data\default\login data",
        );
        assert_eq!(
            correlated.capabilities[0].category,
            "browser_credential_access"
        );
    }

    #[test]
    fn legitimate_screen_capture_alone_stays_low_risk() {
        let assessment = assess(&imports(&["getdc", "bitblt"]), "");
        assert_eq!(assessment.score, 10);
        assert_eq!(assessment.capabilities.len(), 1);
    }

    #[test]
    fn script_credential_dumping_requires_target_and_dump_primitive() {
        let harmless = assess(&HashSet::new(), "diagnose lsass service health");
        assert!(harmless.capabilities.is_empty());

        let correlated = assess(
            &HashSet::new(),
            "rundll32 comsvcs.dll minidump lsass process",
        );
        assert_eq!(correlated.capabilities[0].category, "os_credential_dumping");
    }
}
