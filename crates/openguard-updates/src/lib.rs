#![forbid(unsafe_code)]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use openguard_detection::FileScanner;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    path::{Component, Path, PathBuf},
    time::Duration,
};
use thiserror::Error;
use ureq::ResponseExt;
use url::Url;
use uuid::Uuid;

pub const DEFAULT_MANIFEST_URL: &str = "https://raw.githubusercontent.com/jordanw0204-rgb/OpenGuard/main/security-content/manifest.json";
const MANIFEST_LIMIT: usize = 1024 * 1024;
const FILE_LIMIT: u64 = 64 * 1024 * 1024;
const PUBLIC_KEY_TEXT: &str = include_str!("../../../security-content/update_public_key.txt");

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("security-content manifest is invalid: {0}")]
    Manifest(String),
    #[error("security-content signature is invalid")]
    InvalidSignature,
    #[error("security-content download failed: {0}")]
    Network(String),
    #[error("security-content file failed validation: {0}")]
    Content(String),
    #[error("security-content I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("security-content JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentFile {
    pub path: String,
    pub url: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentManifest {
    pub schema: u32,
    pub version: String,
    pub published_at: String,
    pub files: Vec<ContentFile>,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct SecurityContentUpdater {
    root: PathBuf,
    public_key: VerifyingKey,
    agent: ureq::Agent,
}

impl SecurityContentUpdater {
    /// Creates an updater pinned to `OpenGuard`'s offline release public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the compiled public key is corrupt.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, UpdateError> {
        Self::with_public_key(root, decode_public_key(PUBLIC_KEY_TEXT)?)
    }

    /// Creates an updater with an explicit key for deterministic verification tests.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not a valid Ed25519 verification key.
    pub fn with_public_key(
        root: impl AsRef<Path>,
        public_key: [u8; 32],
    ) -> Result<Self, UpdateError> {
        let public_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|error| UpdateError::Manifest(format!("public key: {error}")))?;
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .max_redirects(5)
            .build();
        Ok(Self {
            root: root.as_ref().to_path_buf(),
            public_key,
            agent: config.into(),
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Downloads, authenticates, validates and atomically stages the official feed.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, signature, hash, schema, rule compilation or
    /// atomic activation-preparation failures.
    pub fn install_official(&self) -> Result<String, UpdateError> {
        self.install_from_url(DEFAULT_MANIFEST_URL)
    }

    /// Downloads and installs a signed manifest from an HTTPS location.
    ///
    /// # Errors
    ///
    /// Returns an error if HTTPS, signature, bounds or content validation fails.
    pub fn install_from_url(&self, manifest_url: &str) -> Result<String, UpdateError> {
        let manifest_bytes = self.download(manifest_url, MANIFEST_LIMIT)?;
        self.install_with_fetcher(&manifest_bytes, |url, limit| self.download(url, limit))
    }

    /// Verifies and stages a manifest using a caller-supplied bounded fetcher.
    ///
    /// This is public so package/integration tests can stay fully offline.
    ///
    /// # Errors
    ///
    /// Returns an error if any authenticated file or scanner rule is invalid.
    pub fn install_with_fetcher(
        &self,
        manifest_bytes: &[u8],
        mut fetch: impl FnMut(&str, usize) -> Result<Vec<u8>, UpdateError>,
    ) -> Result<String, UpdateError> {
        let manifest = self.verify_manifest(manifest_bytes)?;
        let versions_root = self.root.join("versions");
        fs::create_dir_all(&versions_root)?;
        let destination = versions_root.join(&manifest.version);
        if destination.exists() {
            validate_installed(&destination, &manifest)?;
            return Ok(manifest.version);
        }
        let staging = versions_root.join(format!(
            ".staging-{}-{}",
            manifest.version,
            Uuid::new_v4().simple()
        ));
        fs::create_dir(&staging)?;
        let result = (|| {
            for item in &manifest.files {
                let limit = usize::try_from(item.size.saturating_add(1024).min(FILE_LIMIT + 1))
                    .map_err(|_| UpdateError::Content("file size overflow".into()))?;
                let data = fetch(&item.url, limit)?;
                validate_content_bytes(item, &data)?;
                let target = staging.join(content_path(&item.path)?);
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(target, data)?;
            }
            validate_content_directory(&staging)?;
            fs::write(staging.join("manifest.json"), manifest_bytes)?;
            fs::rename(&staging, &destination)?;
            Ok(manifest.version.clone())
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        result
    }

    /// Strictly verifies a manifest and all path/URL/size declarations.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON, an invalid strict Ed25519 signature,
    /// unsupported schema, unsafe path, insecure URL, duplicate or invalid digest.
    pub fn verify_manifest(&self, manifest_bytes: &[u8]) -> Result<ContentManifest, UpdateError> {
        if manifest_bytes.len() > MANIFEST_LIMIT {
            return Err(UpdateError::Manifest("manifest exceeds 1 MiB".into()));
        }
        let mut raw: Value = serde_json::from_slice(manifest_bytes)?;
        let signature_text = raw
            .as_object_mut()
            .and_then(|object| object.remove("signature"))
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| UpdateError::Manifest("missing signature".into()))?;
        let signature_bytes = STANDARD
            .decode(signature_text.as_bytes())
            .map_err(|_| UpdateError::InvalidSignature)?;
        let signature_array: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| UpdateError::InvalidSignature)?;
        let signature = Signature::from_bytes(&signature_array);
        let canonical = canonical_manifest_bytes(&raw)?;
        self.public_key
            .verify_strict(&canonical, &signature)
            .map_err(|_| UpdateError::InvalidSignature)?;

        let mut complete = raw;
        if let Some(object) = complete.as_object_mut() {
            object.insert("signature".into(), Value::String(signature_text));
        }
        let manifest: ContentManifest = serde_json::from_value(complete)?;
        validate_manifest_fields(&manifest)?;
        Ok(manifest)
    }

    /// Compiles every YARA rule in one installed immutable content version.
    ///
    /// # Errors
    ///
    /// Returns an error when the version/path is invalid, files are missing, or
    /// YARA-X rejects the installed sources.
    pub fn scanner_for_version(&self, version: &str) -> Result<FileScanner, UpdateError> {
        validate_version(version)?;
        scanner_from_directory(&self.root.join("versions").join(version))
    }

    #[must_use]
    pub fn version_directory(&self, version: &str) -> PathBuf {
        self.root.join("versions").join(version)
    }

    fn download(&self, url: &str, limit: usize) -> Result<Vec<u8>, UpdateError> {
        validate_https_url(url)?;
        let mut response = self
            .agent
            .get(url)
            .call()
            .map_err(|error| UpdateError::Network(error.to_string()))?;
        if response.get_uri().scheme_str() != Some("https") {
            return Err(UpdateError::Network(
                "redirected to a non-HTTPS content endpoint".into(),
            ));
        }
        response
            .body_mut()
            .with_config()
            .limit(u64::try_from(limit).unwrap_or(u64::MAX))
            .read_to_vec()
            .map_err(|error| UpdateError::Network(error.to_string()))
    }
}

fn decode_public_key(value: &str) -> Result<[u8; 32], UpdateError> {
    STANDARD
        .decode(value.trim().as_bytes())
        .map_err(|error| UpdateError::Manifest(format!("public key encoding: {error}")))?
        .try_into()
        .map_err(|_| UpdateError::Manifest("public key must contain 32 bytes".into()))
}

fn validate_manifest_fields(manifest: &ContentManifest) -> Result<(), UpdateError> {
    if manifest.schema != 1 {
        return Err(UpdateError::Manifest("unsupported schema".into()));
    }
    validate_version(&manifest.version)?;
    if manifest.files.is_empty() {
        return Err(UpdateError::Manifest("manifest contains no files".into()));
    }
    let mut paths = HashSet::new();
    for item in &manifest.files {
        content_path(&item.path)?;
        validate_https_url(&item.url)?;
        if item.size > FILE_LIMIT {
            return Err(UpdateError::Manifest(format!(
                "{} exceeds the 64 MiB file limit",
                item.path
            )));
        }
        if item.sha256.len() != 64 || !item.sha256.bytes().all(|value| value.is_ascii_hexdigit()) {
            return Err(UpdateError::Manifest(format!(
                "{} has an invalid SHA-256",
                item.path
            )));
        }
        if !paths.insert(item.path.to_ascii_lowercase()) {
            return Err(UpdateError::Manifest(format!(
                "duplicate content path {}",
                item.path
            )));
        }
    }
    Ok(())
}

fn validate_version(version: &str) -> Result<(), UpdateError> {
    if version.is_empty()
        || version.len() > 64
        || !version
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'.' | b'_' | b'-'))
    {
        return Err(UpdateError::Manifest("invalid content version".into()));
    }
    Ok(())
}

fn content_path(value: &str) -> Result<PathBuf, UpdateError> {
    let normalized = value.replace('\\', "/");
    let path = Path::new(&normalized);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(UpdateError::Manifest("unsafe content path".into()));
    }
    let allowed = normalized == "reputation.json"
        || (normalized.starts_with("rules/")
            && Path::new(&normalized)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("yar")));
    if !allowed {
        return Err(UpdateError::Manifest(format!(
            "unsupported content path {value}"
        )));
    }
    Ok(PathBuf::from(normalized))
}

fn validate_https_url(value: &str) -> Result<(), UpdateError> {
    let url = Url::parse(value)
        .map_err(|error| UpdateError::Manifest(format!("invalid content URL: {error}")))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(UpdateError::Manifest(
            "content URL must be credential-free HTTPS".into(),
        ));
    }
    Ok(())
}

/// Serializes a manifest value using the stable, recursive, alphabetic-key
/// representation covered by `OpenGuard` Ed25519 signatures.
///
/// # Errors
///
/// Returns an error when a scalar JSON value cannot be serialized.
pub fn canonical_manifest_bytes(value: &Value) -> Result<Vec<u8>, UpdateError> {
    fn write(value: &Value, output: &mut Vec<u8>) -> Result<(), serde_json::Error> {
        match value {
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                serde_json::to_writer(output, value)?;
            }
            Value::Array(items) => {
                output.push(b'[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    write(item, output)?;
                }
                output.push(b']');
            }
            Value::Object(object) => {
                output.push(b'{');
                let mut keys = object.keys().collect::<Vec<_>>();
                keys.sort_unstable();
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    serde_json::to_writer(&mut *output, key)?;
                    output.push(b':');
                    write(&object[key], output)?;
                }
                output.push(b'}');
            }
        }
        Ok(())
    }

    let mut output = Vec::new();
    write(value, &mut output)?;
    Ok(output)
}

fn validate_content_bytes(item: &ContentFile, data: &[u8]) -> Result<(), UpdateError> {
    if u64::try_from(data.len()).unwrap_or(u64::MAX) != item.size {
        return Err(UpdateError::Content(format!("{} size mismatch", item.path)));
    }
    let digest = hex::encode(Sha256::digest(data));
    if !digest.eq_ignore_ascii_case(&item.sha256) {
        return Err(UpdateError::Content(format!(
            "{} SHA-256 mismatch",
            item.path
        )));
    }
    Ok(())
}

fn validate_installed(root: &Path, manifest: &ContentManifest) -> Result<(), UpdateError> {
    for item in &manifest.files {
        let data = fs::read(root.join(content_path(&item.path)?))?;
        validate_content_bytes(item, &data)?;
    }
    validate_content_directory(root)
}

fn validate_content_directory(root: &Path) -> Result<(), UpdateError> {
    scanner_from_directory(root)?;
    let reputation = root.join("reputation.json");
    if reputation.exists() {
        let value: Value = serde_json::from_slice(&fs::read(reputation)?)?;
        if value.get("schema").and_then(Value::as_u64) != Some(1)
            || !value.get("entries").is_some_and(Value::is_array)
        {
            return Err(UpdateError::Content(
                "reputation.json has an invalid schema".into(),
            ));
        }
    }
    Ok(())
}

fn scanner_from_directory(root: &Path) -> Result<FileScanner, UpdateError> {
    let rules_root = root.join("rules");
    let mut paths = fs::read_dir(&rules_root)
        .map_err(|error| UpdateError::Content(format!("read rules directory: {error}")))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "yar"))
        .collect::<Vec<_>>();
    paths.sort();
    if paths.is_empty() {
        return Err(UpdateError::Content(
            "content contains no YARA rules".into(),
        ));
    }
    let sources = paths
        .iter()
        .map(fs::read_to_string)
        .collect::<Result<Vec<_>, _>>()?;
    let references = sources.iter().map(String::as_str).collect::<Vec<_>>();
    FileScanner::with_rule_sources(&references)
        .map_err(|error| UpdateError::Content(format!("compile YARA-X rules: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn repository_manifest_passes_strict_signature_and_content_validation() {
        let directory = TempDir::new().expect("temporary directory");
        let updater = SecurityContentUpdater::new(directory.path()).expect("updater");
        let manifest_bytes = include_bytes!("../../../security-content/manifest.json");
        let rules = include_bytes!("../../../security-content/rules/community.yar");
        let reputation = include_bytes!("../../../security-content/reputation.json");
        let version = updater
            .install_with_fetcher(manifest_bytes, |url, _| {
                if url.ends_with("community.yar") {
                    Ok(rules.to_vec())
                } else if url.ends_with("reputation.json") {
                    Ok(reputation.to_vec())
                } else {
                    Err(UpdateError::Network("unexpected test URL".into()))
                }
            })
            .expect("signed content install");
        assert_eq!(version, "2026.08.06.1");
        updater.scanner_for_version(&version).expect("active rules");
    }

    #[test]
    fn tampered_manifest_is_rejected_before_fetching() {
        let directory = TempDir::new().expect("temporary directory");
        let updater = SecurityContentUpdater::new(directory.path()).expect("updater");
        let mut manifest = include_bytes!("../../../security-content/manifest.json").to_vec();
        let position = manifest
            .windows("2026.08.06.1".len())
            .position(|value| value == b"2026.08.06.1")
            .expect("version");
        manifest[position] = b'9';
        let error = updater
            .install_with_fetcher(&manifest, |_, _| panic!("fetch must not run"))
            .expect_err("tampering must fail");
        assert!(matches!(error, UpdateError::InvalidSignature));
    }
}
