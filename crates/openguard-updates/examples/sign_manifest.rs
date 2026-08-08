use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use openguard_updates::canonical_manifest_bytes;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{env, error::Error, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let version = option(&arguments, "--version")?;
    let base_url = option(&arguments, "--base-url")?;
    let published_at = option(&arguments, "--published-at")?;
    let content_root = optional(&arguments, "--content-root")
        .map_or_else(|| PathBuf::from("security-content"), PathBuf::from);
    let output = optional(&arguments, "--output")
        .map_or_else(|| content_root.join("manifest.json"), PathBuf::from);
    let key_text = env::var("OPENGUARD_UPDATE_PRIVATE_KEY")
        .map_err(|_| "OPENGUARD_UPDATE_PRIVATE_KEY is required")?;
    let key_bytes = STANDARD.decode(key_text.trim())?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "the Ed25519 private key must contain exactly 32 bytes")?;
    let signing_key = SigningKey::from_bytes(&key_array);

    let relative_paths = [
        PathBuf::from("rules/community.yar"),
        PathBuf::from("reputation.json"),
    ];
    let mut files = Vec::with_capacity(relative_paths.len());
    for relative in relative_paths {
        let data = fs::read(content_root.join(&relative))?;
        files.push(json!({
            "path": relative.to_string_lossy().replace('\\', "/"),
            "url": format!(
                "{}/{}",
                base_url.trim_end_matches('/'),
                relative.to_string_lossy().replace('\\', "/")
            ),
            "sha256": hex::encode(Sha256::digest(&data)),
            "size": data.len(),
        }));
    }
    let mut manifest = json!({
        "schema": 1,
        "version": version,
        "published_at": published_at,
        "files": files,
    });
    let signature = signing_key.sign(&canonical_manifest_bytes(&manifest)?);
    manifest
        .as_object_mut()
        .ok_or("manifest must be an object")?
        .insert(
            "signature".into(),
            Value::String(STANDARD.encode(signature.to_bytes())),
        );
    let mut pretty = serde_json::to_string_pretty(&manifest)?;
    pretty.push('\n');
    fs::write(output, pretty)?;
    Ok(())
}

fn option(arguments: &[String], name: &str) -> Result<String, Box<dyn Error>> {
    optional(arguments, name).ok_or_else(|| format!("{name} is required").into())
}

fn optional(arguments: &[String], name: &str) -> Option<String> {
    arguments
        .iter()
        .position(|value| value == name)
        .and_then(|index| arguments.get(index + 1))
        .cloned()
}
