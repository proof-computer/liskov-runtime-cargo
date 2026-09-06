//! Customer-secret hydration over the existing job-bound Lockbox v2 wire.
//! No request is made without the server's optional customer-secret hint, so
//! old bootstrap responses and the independent logging path keep their behavior.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::Value;

use crate::bridge::Bridge;
use crate::http::{HttpClient, UreqHttpClient};
use crate::log_config_secret::{
    LogConfigSecretError, discover_lockbox_bootstrap_with, load_job_secret_payload_with,
};
use crate::protocol::RuntimeBootstrapResponse;

const SECRETS_URL: &str = "https://secrets.liskov.proof.computer";
const LOG_SECRET: &str = "blackbox-log-config";

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Metadata {
    secret_id: String,
    version_id: String,
    target: String,
    name: String,
    required: bool,
    bundle_id: String,
}

fn metadata(value: &Value) -> Result<Metadata, LogConfigSecretError> {
    let metadata: Metadata =
        serde_json::from_value(value.clone()).map_err(|_| LogConfigSecretError::InvalidResponse)?;
    if metadata.secret_id.is_empty()
        || metadata.secret_id.len() > 256
        || metadata.version_id.is_empty()
        || metadata.version_id.len() > 1024
        || metadata.name.is_empty()
        || metadata.name.len() > 4096
        || metadata.name.contains('\0')
        || !matches!(metadata.target.as_str(), "env" | "file")
    {
        return Err(LogConfigSecretError::InvalidResponse);
    }
    if metadata.target == "env"
        && (metadata.name.contains('=')
            || !metadata.name.bytes().enumerate().all(|(index, c)| {
                c == b'_' || c.is_ascii_alphabetic() || (index > 0 && c.is_ascii_digit())
            }))
    {
        return Err(LogConfigSecretError::InvalidResponse);
    }
    Ok(metadata)
}

pub(crate) fn validate_versions(
    versions: &Value,
    requested: &[String],
) -> Result<(), LogConfigSecretError> {
    let versions = versions
        .as_array()
        .ok_or(LogConfigSecretError::InvalidResponse)?;
    let mut ids = BTreeSet::new();
    let mut destinations = BTreeSet::new();
    for version in versions {
        let meta = metadata(version)?;
        if !ids.insert(meta.secret_id) || !destinations.insert((meta.target, meta.name)) {
            return Err(LogConfigSecretError::ResponseBinding);
        }
    }
    if requested.is_empty()
        || requested.len() > 256
        || ids.len() != requested.len()
        || ids != requested.iter().cloned().collect()
    {
        return Err(LogConfigSecretError::ResponseBinding);
    }
    Ok(())
}

pub(crate) fn validate_deliveries(
    secrets: &Value,
    versions: &Value,
) -> Result<(), LogConfigSecretError> {
    let secrets = secrets
        .as_array()
        .ok_or(LogConfigSecretError::InvalidPlaintext)?;
    let versions = versions
        .as_array()
        .ok_or(LogConfigSecretError::InvalidResponse)?;
    if secrets.len() != versions.len() {
        return Err(LogConfigSecretError::ResponseBinding);
    }
    let mut seen = BTreeSet::new();
    for secret in secrets {
        let meta = metadata(secret)?;
        if !seen.insert(meta.secret_id.clone())
            || !versions
                .iter()
                .any(|version| metadata(version).ok().as_ref() == Some(&meta))
            || secret["value"].as_str().is_none()
        {
            return Err(LogConfigSecretError::ResponseBinding);
        }
        if meta.target == "env" && secret["value"].as_str().is_some_and(|s| s.contains('\0')) {
            return Err(LogConfigSecretError::InvalidPlaintext);
        }
    }
    Ok(())
}

/// Values are kept out of Debug and error messages. They reach only the
/// workload environment or the declared private files.
#[derive(Default)]
pub struct CustomerSecretDelivery {
    pub environment: BTreeMap<String, String>,
    pub files: BTreeMap<String, String>,
}

/// Deterministic transport seam used by the runtime and offline wire fixtures.
pub fn load_customer_secrets_with(
    bootstrap: &RuntimeBootstrapResponse,
    bridge: &dyn Bridge,
    http: &dyn HttpClient,
    secrets_url: &str,
    now_ms: u64,
    discovery_nonce: [u8; 16],
    request_nonce: [u8; 16],
) -> Result<CustomerSecretDelivery, LogConfigSecretError> {
    if bootstrap
        .secrets
        .as_ref()
        .and_then(|s| s.customer_required)
        .is_none()
    {
        return Ok(CustomerSecretDelivery::default());
    }
    let raw = discover_lockbox_bootstrap_with(
        bootstrap,
        bridge,
        http,
        secrets_url,
        now_ms,
        discovery_nonce,
    )?
    .ok_or(LogConfigSecretError::InvalidBootstrap)?;
    let mut config: Value =
        serde_json::from_str(&raw).map_err(|_| LogConfigSecretError::InvalidBootstrap)?;
    let ids = config["s"]
        .as_array_mut()
        .ok_or(LogConfigSecretError::InvalidBootstrap)?;
    ids.retain(|id| id.as_str() != Some(LOG_SECRET));
    if ids.is_empty() {
        if bootstrap.secrets.as_ref().and_then(|s| s.customer_required) == Some(true) {
            return Err(LogConfigSecretError::ResponseBinding);
        }
        return Ok(CustomerSecretDelivery::default());
    }
    let payload = load_job_secret_payload_with(
        bootstrap,
        bridge,
        http,
        &config.to_string(),
        now_ms,
        request_nonce,
    )?;
    let mut delivery = CustomerSecretDelivery::default();
    for secret in payload["secrets"]
        .as_array()
        .ok_or(LogConfigSecretError::InvalidPlaintext)?
    {
        let meta = metadata(secret)?;
        let value = secret["value"]
            .as_str()
            .ok_or(LogConfigSecretError::InvalidPlaintext)?;
        let target = if meta.target == "file" {
            &mut delivery.files
        } else {
            &mut delivery.environment
        };
        if target.insert(meta.name, value.to_owned()).is_some() {
            return Err(LogConfigSecretError::ResponseBinding);
        }
    }
    Ok(delivery)
}

/// Prepare the complete customer delivery before changing the environment.
/// Logging is hydrated separately and never joins this required-secret gate.
pub fn hydrate_customer_secrets(
    bootstrap: &RuntimeBootstrapResponse,
    bridge: &dyn Bridge,
    environment: &mut BTreeMap<String, String>,
) -> Result<(), LogConfigSecretError> {
    let Some(required) = bootstrap.secrets.as_ref().and_then(|s| s.customer_required) else {
        return Ok(());
    };
    let load = || {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| LogConfigSecretError::Clock)?
            .as_millis();
        let now = u64::try_from(now).map_err(|_| LogConfigSecretError::Clock)?;
        let mut discovery = [0; 16];
        let mut request = [0; 16];
        getrandom::fill(&mut discovery).map_err(|_| LogConfigSecretError::Randomness)?;
        getrandom::fill(&mut request).map_err(|_| LogConfigSecretError::Randomness)?;
        let delivery = load_customer_secrets_with(
            bootstrap,
            bridge,
            &UreqHttpClient::default(),
            SECRETS_URL,
            now,
            discovery,
            request,
        )?;
        crate::file_secrets::install_secret_files(&delivery.files)
            .map_err(|_| LogConfigSecretError::FileInstallation)?;
        Ok(delivery)
    };
    match load() {
        Ok(delivery) => environment.extend(delivery.environment),
        Err(error) if required => return Err(error),
        Err(error) => eprintln!(
            "liskov-runtime-contact: optional customer-secret delivery unavailable ({})",
            error.code()
        ),
    }
    Ok(())
}

#[cfg(test)]
#[path = "job_secrets_tests.rs"]
mod tests;
