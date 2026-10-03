//! Narrow Lockbox reader for the server-owned Blackbox log configuration.
//!
//! The Cargo supervisor must own Runtime SSH logging before the provider
//! sidecar starts. `BLACKBOX_LOG_CONFIG` is nevertheless delivered as a
//! job-bound Lockbox secret, so the supervisor resolves only that exact secret
//! through the Acurast bridge. The customer-secret module reuses this wire
//! verifier and decoder without coupling customer delivery to logging.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::bridge::{Bridge, BridgeError};
use crate::diagnostics::canonical_json_bytes;
use crate::env_names::{LOCKBOX_BOOTSTRAP_ENV_NAMES, first_present};
use crate::http::{HttpClient, HttpError, UreqHttpClient};
use crate::protocol::RuntimeBootstrapResponse;

pub const BLACKBOX_LOG_CONFIG_ENV: &str = "BLACKBOX_LOG_CONFIG";
const BLACKBOX_LOG_CONFIG_SECRET_ID: &str = "blackbox-log-config";
const BLACKBOX_LOG_CONFIG_BUNDLE_ID: &str = "blackbox-log-config";
const DEFAULT_SECRETS_URL: &str = "https://secrets.liskov.proof.computer";
const SECRET_BOOTSTRAP_REQUEST_DOMAIN_V2: &str = "proof.liskov.secret-bootstrap-request.v2";
const SECRET_BOOTSTRAP_RESPONSE_DOMAIN_V2: &str = "proof.liskov.secret-bootstrap-response.v2";
const REQUEST_DOMAIN_V2: &str = "proof.lockbox.job-secret-request.v2";
const RESPONSE_DOMAIN_V2: &str = "proof.lockbox.job-secret-response.v2";
const ENCRYPTED_PAYLOAD_DOMAIN_V2: &str = "proof.lockbox.job-secret-response.encrypted-payload.v2";
const RESPONSE_AAD_DOMAIN_V2: &str = "proof.lockbox.job-secret-response.aad.v2";
/// The secp256k1 generator point. Encrypting to it once is how the JavaScript
/// SDK materialises a lazily created secp256k1 encryption key (`3i2d`); the
/// result is discarded.
const SECP256K1_PRIMING_PUBLIC_KEY: &str =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const REQUEST_TTL_MS: u64 = 60_000;
const MAX_CONFIG_BYTES: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum LogConfigSecretError {
    #[error("runtime secret file installation failed")]
    FileInstallation,
    #[error("runtime log-config bootstrap was invalid")]
    InvalidBootstrap,
    #[error("runtime log-config clock was unavailable")]
    Clock,
    #[error("runtime log-config timestamp overflowed")]
    TimestampOverflow,
    #[error("runtime log-config randomness was unavailable")]
    Randomness,
    #[error("runtime log-config encryption key lookup failed")]
    EncryptionKey(#[source] BridgeError),
    #[error("runtime log-config encryption key was invalid")]
    InvalidEncryptionKey,
    #[error("runtime log-config signing failed")]
    Signing(#[source] BridgeError),
    #[error("runtime log-config signature was invalid")]
    InvalidSignature,
    #[error("runtime log-config request serialization failed")]
    Serialization(#[source] serde_json::Error),
    #[error("runtime log-config transport failed")]
    Transport,
    #[error("runtime log-config request was rejected")]
    Rejected,
    #[error("runtime log-config response was invalid")]
    InvalidResponse,
    #[error("runtime log-config response binding was invalid")]
    ResponseBinding,
    #[error("runtime log-config decryption failed")]
    Decryption(#[source] BridgeError),
    #[error("runtime log-config plaintext was invalid")]
    InvalidPlaintext,
}

impl LogConfigSecretError {
    /// Bounded code for the `slipway.logging.attach` diagnostic's
    /// `hydrateErrorCode` attr — secret-free, one token per variant.
    pub fn code(&self) -> &'static str {
        match self {
            Self::FileInstallation => "file_installation",
            Self::InvalidBootstrap => "invalid_bootstrap",
            Self::Clock => "clock",
            Self::TimestampOverflow => "timestamp_overflow",
            Self::Randomness => "randomness",
            Self::EncryptionKey(_) => "encryption_key",
            Self::InvalidEncryptionKey => "invalid_encryption_key",
            Self::Signing(_) => "signing",
            Self::InvalidSignature => "invalid_signature",
            Self::Serialization(_) => "serialization",
            Self::Transport => "transport",
            Self::Rejected => "rejected",
            Self::InvalidResponse => "invalid_response",
            Self::ResponseBinding => "response_binding",
            Self::Decryption(_) => "decryption",
            Self::InvalidPlaintext => "invalid_plaintext",
        }
    }
}

/// The processor encryption key tier the response is encrypted to. The issuer
/// infers it from the acknowledgement, so it travels beside the signed request,
/// never inside it (ADR-0172).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseCurve {
    P256,
    Secp256k1,
}

impl ResponseCurve {
    fn bridge_curve(self) -> &'static str {
        match self {
            Self::P256 => "p256",
            Self::Secp256k1 => "secp256k1",
        }
    }

    /// The only `(version, curveName)` envelope accepted for a request that
    /// sent a key of this curve.
    fn envelope(self) -> (&'static str, &'static str) {
        match self {
            Self::P256 => ("acurast-p256-hkdf-aes-256-gcm-v2", "secp256r1"),
            Self::Secp256k1 => ("acurast-secp256k1-hkdf-aes-256-gcm-v1", "secp256k1"),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct CompactBootstrap {
    v: u8,
    u: String,
    uid: String,
    a: String,
    g: String,
    p: String,
    d: String,
    s: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedRequest {
    domain: &'static str,
    application_uid: String,
    application_id: String,
    grant_id: String,
    policy_digest: String,
    job_id: String,
    deployment_id: String,
    processor_id: String,
    requested_secret_ids: Vec<String>,
    nonce: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
    response_encryption_key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedRequest<'a> {
    #[serde(flatten)]
    unsigned: &'a UnsignedRequest,
    signature: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedSecretBootstrapRequest {
    domain: &'static str,
    job_id: String,
    processor_id: String,
    response_encryption_key: String,
    nonce: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedSecretBootstrapRequest<'a> {
    #[serde(flatten)]
    unsigned: &'a UnsignedSecretBootstrapRequest,
    signature: String,
}

/// Populate the signed runtime-environment map with the exact job-bound
/// Blackbox config when logging is enabled and no authoritative config is
/// already present. Failure is deliberately returned to the caller so tests
/// and future diagnostics can classify it, but the supervisor treats it as
/// non-fatal to workload execution and Runtime SSH state.
pub fn hydrate_blackbox_log_config(
    bootstrap: &RuntimeBootstrapResponse,
    bridge: &dyn Bridge,
    runtime_environment: &mut BTreeMap<String, String>,
) -> Result<(), LogConfigSecretError> {
    if !bootstrap.logging_enabled() || runtime_environment.contains_key(BLACKBOX_LOG_CONFIG_ENV) {
        return Ok(());
    }
    let ambient_bootstrap =
        ambient_lockbox_bootstrap(runtime_environment, |name| std::env::var(name).ok());
    let mut bootstrap_nonce = [0_u8; 16];
    getrandom::fill(&mut bootstrap_nonce).map_err(|_| LogConfigSecretError::Randomness)?;
    let mut request_nonce = [0_u8; 16];
    getrandom::fill(&mut request_nonce).map_err(|_| LogConfigSecretError::Randomness)?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LogConfigSecretError::Clock)?
        .as_millis();
    let now_ms = u64::try_from(now_ms).map_err(|_| LogConfigSecretError::Clock)?;
    let http = UreqHttpClient::default();
    let raw_bootstrap = match ambient_bootstrap {
        Some(raw_bootstrap) => raw_bootstrap,
        None => {
            let Some(raw_bootstrap) = discover_lockbox_bootstrap_with(
                bootstrap,
                bridge,
                &http,
                DEFAULT_SECRETS_URL,
                now_ms,
                bootstrap_nonce,
            )?
            else {
                return Ok(());
            };
            raw_bootstrap
        }
    };
    if let Some(config) = load_blackbox_log_config_with(
        bootstrap,
        bridge,
        &http,
        &raw_bootstrap,
        now_ms,
        request_nonce,
    )? {
        runtime_environment.insert(BLACKBOX_LOG_CONFIG_ENV.to_owned(), config);
    }
    Ok(())
}

/// The job-bound Lockbox bootstrap metadata, if any is already ambient.
///
/// Channel order is unchanged and load-bearing: a signed runtime-environment
/// value outranks an inherited process value, as the README documents. Within
/// each channel the `LISKOV_*` name is preferred and the legacy
/// `PROOF_LOCKBOX_BOOTSTRAP` is the migration bridge (`BKLG-20260829-m8kd`).
fn ambient_lockbox_bootstrap<F>(
    runtime_environment: &BTreeMap<String, String>,
    process_env: F,
) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    first_present(LOCKBOX_BOOTSTRAP_ENV_NAMES, |name| {
        runtime_environment.get(name).cloned()
    })
    .or_else(|| first_present(LOCKBOX_BOOTSTRAP_ENV_NAMES, process_env))
}

pub(crate) fn discover_lockbox_bootstrap_with(
    bootstrap: &RuntimeBootstrapResponse,
    bridge: &dyn Bridge,
    http: &dyn HttpClient,
    secrets_url: &str,
    now_ms: u64,
    nonce: [u8; 16],
) -> Result<Option<String>, LogConfigSecretError> {
    let endpoint = secure_join(secrets_url, "/api/jobs/secret-bootstrap")?;
    let (response_encryption_key, _) = encryption_public_key(bridge)?;
    let unsigned = UnsignedSecretBootstrapRequest {
        domain: SECRET_BOOTSTRAP_REQUEST_DOMAIN_V2,
        job_id: bootstrap.job_id.clone(),
        processor_id: bootstrap.processor_id.clone(),
        response_encryption_key,
        nonce: hex::encode(nonce),
        issued_at_ms: now_ms,
        expires_at_ms: now_ms
            .checked_add(REQUEST_TTL_MS)
            .ok_or(LogConfigSecretError::TimestampOverflow)?,
    };
    let message = canonical_json_bytes(
        &serde_json::to_value(&unsigned).map_err(LogConfigSecretError::Serialization)?,
    );
    let signature = sign(bridge, &message)?;
    let body = serde_json::to_vec(&SignedSecretBootstrapRequest {
        unsigned: &unsigned,
        signature,
    })
    .map_err(LogConfigSecretError::Serialization)?;
    let response = http
        .post(endpoint.as_str(), &body)
        .map_err(|error| match error {
            HttpError::Transport => LogConfigSecretError::Transport,
            HttpError::ResponseTooLarge => LogConfigSecretError::InvalidResponse,
        })?;
    if !(200..300).contains(&response.status) {
        return Err(LogConfigSecretError::Rejected);
    }
    let response: Value = serde_json::from_slice(&response.body)
        .map_err(|_| LogConfigSecretError::InvalidResponse)?;
    let policy_digest = normalize_policy_digest(&bootstrap.policy_digest)
        .ok_or(LogConfigSecretError::ResponseBinding)?;
    let grant_id = required_bounded_string(response.get("grantId"))?;
    let lockbox_url = required_bounded_string(response.get("lockboxUrl"))?;
    secure_join(lockbox_url, "/api/jobs/secret-requests")?;
    let requested_secret_ids = response["requestedSecretIds"]
        .as_array()
        .filter(|items| {
            items.len() <= 256
                && items.iter().all(|item| {
                    item.as_str()
                        .is_some_and(|value| !value.is_empty() && value.len() <= 256)
                })
                && items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == items.len()
        })
        .ok_or(LogConfigSecretError::InvalidResponse)?;
    if response["ok"].as_bool() != Some(true)
        || response["domain"].as_str() != Some(SECRET_BOOTSTRAP_RESPONSE_DOMAIN_V2)
        || response["applicationUid"].as_str() != Some(bootstrap.application_uid.as_str())
        || response["applicationId"].as_str() != Some(bootstrap.application_id.as_str())
        || normalize_policy_digest(response["policyDigest"].as_str().unwrap_or_default()).as_deref()
            != Some(policy_digest.as_str())
        || response["deploymentId"].as_str() != Some(bootstrap.deployment_id.as_str())
        || response["jobId"].as_str() != Some(unsigned.job_id.as_str())
        || response["processorId"].as_str() != Some(unsigned.processor_id.as_str())
    {
        return Err(LogConfigSecretError::ResponseBinding);
    }
    let requested_secret_ids = requested_secret_ids
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let compact = json!({
        "v": 2,
        "u": lockbox_url,
        "uid": bootstrap.application_uid,
        "a": bootstrap.application_id,
        "g": grant_id,
        "p": policy_digest,
        "d": bootstrap.deployment_id,
        "s": requested_secret_ids,
    });
    serde_json::to_string(&compact)
        .map(Some)
        .map_err(LogConfigSecretError::Serialization)
}

fn load_blackbox_log_config_with(
    bootstrap: &RuntimeBootstrapResponse,
    bridge: &dyn Bridge,
    http: &dyn HttpClient,
    raw_bootstrap: &str,
    now_ms: u64,
    nonce: [u8; 16],
) -> Result<Option<String>, LogConfigSecretError> {
    let mut config: CompactBootstrap =
        serde_json::from_str(raw_bootstrap).map_err(|_| LogConfigSecretError::InvalidBootstrap)?;
    if !config
        .s
        .iter()
        .any(|id| id == BLACKBOX_LOG_CONFIG_SECRET_ID)
    {
        return Ok(None);
    }
    config.s = vec![BLACKBOX_LOG_CONFIG_SECRET_ID.to_owned()];
    let raw = serde_json::to_string(&config).map_err(LogConfigSecretError::Serialization)?;
    let payload = load_job_secret_payload_with(bootstrap, bridge, http, &raw, now_ms, nonce)?;
    validate_secret_versions(&payload["secrets"])?;
    extract_blackbox_config(&payload).map(Some)
}

pub(crate) fn load_job_secret_payload_with(
    bootstrap: &RuntimeBootstrapResponse,
    bridge: &dyn Bridge,
    http: &dyn HttpClient,
    raw_bootstrap: &str,
    now_ms: u64,
    nonce: [u8; 16],
) -> Result<Value, LogConfigSecretError> {
    let config: CompactBootstrap =
        serde_json::from_str(raw_bootstrap).map_err(|_| LogConfigSecretError::InvalidBootstrap)?;
    let policy_digest = normalize_policy_digest(&bootstrap.policy_digest)
        .ok_or(LogConfigSecretError::InvalidBootstrap)?;
    if config.v != 2
        || config.uid.trim() != bootstrap.application_uid
        || config.a.trim() != bootstrap.application_id
        || normalize_policy_digest(&config.p).as_deref() != Some(policy_digest.as_str())
        || config.d.trim() != bootstrap.deployment_id
        || config.g.trim().is_empty()
    {
        return Err(LogConfigSecretError::InvalidBootstrap);
    }
    let endpoint = secure_endpoint(&config.u)?;
    let (response_encryption_key, response_curve) = encryption_public_key(bridge)?;
    let unsigned = UnsignedRequest {
        domain: REQUEST_DOMAIN_V2,
        application_uid: bootstrap.application_uid.clone(),
        application_id: bootstrap.application_id.clone(),
        grant_id: config.g,
        policy_digest,
        job_id: bootstrap.job_id.clone(),
        deployment_id: bootstrap.deployment_id.clone(),
        processor_id: bootstrap.processor_id.clone(),
        requested_secret_ids: config.s,
        nonce: hex::encode(nonce),
        issued_at_ms: now_ms,
        expires_at_ms: now_ms
            .checked_add(REQUEST_TTL_MS)
            .ok_or(LogConfigSecretError::TimestampOverflow)?,
        response_encryption_key,
    };
    let message = canonical_json_bytes(
        &serde_json::to_value(&unsigned).map_err(LogConfigSecretError::Serialization)?,
    );
    let signature = sign(bridge, &message)?;
    let body = serde_json::to_vec(&SignedRequest {
        unsigned: &unsigned,
        signature,
    })
    .map_err(LogConfigSecretError::Serialization)?;
    let response = http
        .post(endpoint.as_str(), &body)
        .map_err(|error| match error {
            HttpError::Transport => LogConfigSecretError::Transport,
            HttpError::ResponseTooLarge => LogConfigSecretError::InvalidResponse,
        })?;
    if !(200..300).contains(&response.status) {
        return Err(LogConfigSecretError::Rejected);
    }
    decrypt_job_secret_payload(&unsigned, response_curve, bridge, &response.body)
}

fn secure_endpoint(raw: &str) -> Result<url::Url, LogConfigSecretError> {
    secure_join(raw, "/api/jobs/secret-requests")
}

fn secure_join(raw: &str, path: &str) -> Result<url::Url, LogConfigSecretError> {
    let base = url::Url::parse(raw).map_err(|_| LogConfigSecretError::InvalidBootstrap)?;
    if base.scheme() != "https"
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return Err(LogConfigSecretError::InvalidBootstrap);
    }
    base.join(path)
        .map_err(|_| LogConfigSecretError::InvalidBootstrap)
}

/// The response key and its curve, in the SDK's tier order: any p256 key
/// first, secp256k1 only when no p256 key is exposed. The issuer binds the
/// request key to the acknowledgement's selected key, so preferring secp256k1
/// while a p256 key exists would be answered `response_key_mismatch`.
fn encryption_public_key(
    bridge: &dyn Bridge,
) -> Result<(String, ResponseCurve), LogConfigSecretError> {
    if let Some(selected) = select_encryption_key(&deployment_encryption_keys(bridge)?)? {
        return Ok(selected);
    }
    // A secp256k1 key may be materialised only by its first use; prime it the
    // way the JavaScript SDK does, best-effort, and read once more.
    let _ = bridge.call(
        "signer_encrypt",
        json!([{
            "curve": "secp256k1",
            "publicKey": SECP256K1_PRIMING_PUBLIC_KEY,
            "salt": "00",
            "bytes": "00",
        }]),
    );
    select_encryption_key(&deployment_encryption_keys(bridge)?)?
        .ok_or(LogConfigSecretError::InvalidEncryptionKey)
}

fn deployment_encryption_keys(bridge: &dyn Bridge) -> Result<Value, LogConfigSecretError> {
    bridge
        .call("deployment_encryptionKeys", json!([]))
        .map_err(LogConfigSecretError::EncryptionKey)
}

/// `None` only when neither key is exposed. An exposed key that is not a
/// public key is an error, never a reason to fall through to the next tier.
fn select_encryption_key(
    result: &Value,
) -> Result<Option<(String, ResponseCurve)>, LogConfigSecretError> {
    let keys = result.get("encryptionKeys");
    for curve in [ResponseCurve::P256, ResponseCurve::Secp256k1] {
        match keys.and_then(|keys| keys.get(curve.bridge_curve())) {
            None | Some(Value::Null) => continue,
            Some(value) => {
                return value
                    .as_str()
                    .and_then(normalize_public_key)
                    .map(|key| Some((key, curve)))
                    .ok_or(LogConfigSecretError::InvalidEncryptionKey);
            }
        }
    }
    Ok(None)
}

fn sign(bridge: &dyn Bridge, message: &[u8]) -> Result<String, LogConfigSecretError> {
    let result = bridge
        .call(
            "signer_sign",
            json!([{
                "curve": "ed25519",
                "bytes": hex::encode(message),
            }]),
        )
        .map_err(LogConfigSecretError::Signing)?;
    let signature = result
        .get("bytes")
        .and_then(Value::as_str)
        .and_then(|value| normalize_hex_exact(value, 64))
        .ok_or(LogConfigSecretError::InvalidSignature)?;
    Ok(format!("0x{signature}"))
}

fn decrypt_job_secret_payload(
    request: &UnsignedRequest,
    curve: ResponseCurve,
    bridge: &dyn Bridge,
    body: &[u8],
) -> Result<Value, LogConfigSecretError> {
    let response: Value =
        serde_json::from_slice(body).map_err(|_| LogConfigSecretError::InvalidResponse)?;
    if response["ok"].as_bool() != Some(true)
        || response["domain"].as_str() != Some(RESPONSE_DOMAIN_V2)
        || response["applicationUid"].as_str() != Some(request.application_uid.as_str())
        || response["applicationId"].as_str() != Some(request.application_id.as_str())
        || response["grantId"].as_str() != Some(request.grant_id.as_str())
        || normalize_policy_digest(response["policyDigest"].as_str().unwrap_or_default()).as_deref()
            != Some(request.policy_digest.as_str())
        || response["jobId"].as_str() != Some(request.job_id.as_str())
        || response["deploymentId"].as_str() != Some(request.deployment_id.as_str())
        || response["processorId"].as_str() != Some(request.processor_id.as_str())
        || response["requestedSecretIds"] != json!(request.requested_secret_ids)
        || response["requestId"]
            .as_str()
            .is_none_or(|request_id| request_id.is_empty())
    {
        return Err(LogConfigSecretError::ResponseBinding);
    }
    crate::job_secrets::validate_versions(
        &response["secretVersions"],
        &request.requested_secret_ids,
    )?;

    let encrypted = response["encryptedPayload"]
        .as_object()
        .ok_or(LogConfigSecretError::InvalidResponse)?;
    let (version, curve_name) = curve.envelope();
    if encrypted.get("domain").and_then(Value::as_str) != Some(ENCRYPTED_PAYLOAD_DOMAIN_V2)
        || encrypted.get("version").and_then(Value::as_str) != Some(version)
        || encrypted.get("curveName").and_then(Value::as_str) != Some(curve_name)
    {
        return Err(LogConfigSecretError::InvalidResponse);
    }
    let sender_public_key = required_bounded_string(encrypted.get("senderPublicKey"))?;
    let salt_hex = required_bounded_string(encrypted.get("saltHex"))?;
    let ciphertext_hex = required_bounded_string(encrypted.get("ciphertextHex"))?;
    let plaintext_digest = required_sha256(encrypted.get("plaintextDigest"))?;
    let aad_digest = required_sha256(encrypted.get("aadDigest"))?;
    let encrypted_payload_digest = required_sha256(encrypted.get("encryptedPayloadDigest"))?;

    let mut digest_value = Value::Object(encrypted.clone());
    digest_value
        .as_object_mut()
        .expect("encrypted payload is an object")
        .remove("encryptedPayloadDigest");
    if sha256_prefixed(&canonical_json_bytes(&digest_value)) != encrypted_payload_digest {
        return Err(LogConfigSecretError::InvalidResponse);
    }
    let aad = json!({
        "domain": RESPONSE_AAD_DOMAIN_V2,
        "requestId": response["requestId"],
        "applicationUid": request.application_uid,
        "applicationId": request.application_id,
        "grantId": request.grant_id,
        "policyDigest": request.policy_digest,
        "jobId": request.job_id,
        "deploymentId": request.deployment_id,
        "processorId": request.processor_id,
    });
    if sha256_prefixed(&canonical_json_bytes(&aad)) != aad_digest {
        return Err(LogConfigSecretError::ResponseBinding);
    }

    let decrypted = bridge
        .call(
            "signer_decrypt",
            json!([{
                "curve": curve.bridge_curve(),
                "publicKey": sender_public_key,
                "salt": salt_hex,
                "bytes": ciphertext_hex,
            }]),
        )
        .map_err(LogConfigSecretError::Decryption)?;
    let plaintext_hex = decrypted
        .get("bytes")
        .and_then(Value::as_str)
        .ok_or(LogConfigSecretError::InvalidPlaintext)?;
    if plaintext_hex.len() > MAX_CONFIG_BYTES.saturating_mul(2) {
        return Err(LogConfigSecretError::InvalidPlaintext);
    }
    let plaintext = Zeroizing::new(
        hex::decode(plaintext_hex).map_err(|_| LogConfigSecretError::InvalidPlaintext)?,
    );
    if sha256_prefixed(plaintext.as_slice()) != plaintext_digest {
        return Err(LogConfigSecretError::InvalidPlaintext);
    }
    let payload: Value =
        serde_json::from_slice(&plaintext).map_err(|_| LogConfigSecretError::InvalidPlaintext)?;
    validate_plaintext_binding(request, &response, &payload)?;
    crate::job_secrets::validate_deliveries(&payload["secrets"], &response["secretVersions"])?;
    Ok(payload)
}

fn validate_secret_versions(value: &Value) -> Result<(), LogConfigSecretError> {
    let [secret] = value
        .as_array()
        .ok_or(LogConfigSecretError::InvalidResponse)?
        .as_slice()
    else {
        return Err(LogConfigSecretError::InvalidResponse);
    };
    if secret["secretId"].as_str() != Some(BLACKBOX_LOG_CONFIG_SECRET_ID)
        || secret["target"].as_str() != Some("env")
        || secret["name"].as_str() != Some(BLACKBOX_LOG_CONFIG_ENV)
        || secret["required"].as_bool() != Some(true)
        || secret["bundleId"].as_str() != Some(BLACKBOX_LOG_CONFIG_BUNDLE_ID)
        || secret["versionId"]
            .as_str()
            .is_none_or(|version_id| version_id.is_empty())
    {
        return Err(LogConfigSecretError::ResponseBinding);
    }
    Ok(())
}

fn validate_plaintext_binding(
    request: &UnsignedRequest,
    response: &Value,
    payload: &Value,
) -> Result<(), LogConfigSecretError> {
    if payload["domain"].as_str() != Some(RESPONSE_DOMAIN_V2)
        || payload["requestId"] != response["requestId"]
        || payload["applicationUid"].as_str() != Some(request.application_uid.as_str())
        || payload["applicationId"].as_str() != Some(request.application_id.as_str())
        || payload["grantId"].as_str() != Some(request.grant_id.as_str())
        || normalize_policy_digest(payload["policyDigest"].as_str().unwrap_or_default()).as_deref()
            != Some(request.policy_digest.as_str())
        || payload["jobId"].as_str() != Some(request.job_id.as_str())
        || payload["deploymentId"].as_str() != Some(request.deployment_id.as_str())
        || payload["processorId"].as_str() != Some(request.processor_id.as_str())
    {
        return Err(LogConfigSecretError::ResponseBinding);
    }
    Ok(())
}

fn extract_blackbox_config(payload: &Value) -> Result<String, LogConfigSecretError> {
    let [secret] = payload["secrets"]
        .as_array()
        .ok_or(LogConfigSecretError::InvalidPlaintext)?
        .as_slice()
    else {
        return Err(LogConfigSecretError::InvalidPlaintext);
    };
    let value = secret["value"]
        .as_str()
        .filter(|value| !value.is_empty() && value.len() <= MAX_CONFIG_BYTES);
    if secret["secretId"].as_str() != Some(BLACKBOX_LOG_CONFIG_SECRET_ID)
        || secret["target"].as_str() != Some("env")
        || secret["name"].as_str() != Some(BLACKBOX_LOG_CONFIG_ENV)
        || secret["required"].as_bool() != Some(true)
        || secret["bundleId"].as_str() != Some(BLACKBOX_LOG_CONFIG_BUNDLE_ID)
        || secret["versionId"]
            .as_str()
            .is_none_or(|version_id| version_id.is_empty())
        || value.is_none()
    {
        return Err(LogConfigSecretError::InvalidPlaintext);
    }
    Ok(value.expect("validated config value").to_owned())
}

fn normalize_policy_digest(value: &str) -> Option<String> {
    let value = value
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(value.trim())
        .to_ascii_lowercase();
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(value)
}

/// A compressed or uncompressed SEC1 public key, on either curve.
fn normalize_public_key(value: &str) -> Option<String> {
    let value = value
        .trim()
        .strip_prefix("0x")
        .or_else(|| value.trim().strip_prefix("0X"))
        .unwrap_or(value.trim())
        .to_ascii_lowercase();
    matches!(value.len(), 66 | 130)
        .then_some(())
        .filter(|_| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(|_| value)
}

fn normalize_hex_exact(value: &str, byte_len: usize) -> Option<String> {
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value)
        .to_ascii_lowercase();
    (value.len() == byte_len.saturating_mul(2)
        && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
    .then_some(value)
}

fn required_bounded_string(value: Option<&Value>) -> Result<&str, LogConfigSecretError> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= MAX_CONFIG_BYTES.saturating_mul(2))
        .ok_or(LogConfigSecretError::InvalidResponse)
}

fn required_sha256(value: Option<&Value>) -> Result<String, LogConfigSecretError> {
    let value = value
        .and_then(Value::as_str)
        .ok_or(LogConfigSecretError::InvalidResponse)?;
    let digest = value
        .strip_prefix("sha256:")
        .ok_or(LogConfigSecretError::InvalidResponse)?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(LogConfigSecretError::InvalidResponse);
    }
    Ok(format!("sha256:{}", digest.to_ascii_lowercase()))
}

fn sha256_prefixed(value: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Mutex;

    use super::*;
    use crate::env_names::{LEGACY_LOCKBOX_BOOTSTRAP_ENV, LOCKBOX_BOOTSTRAP_ENV};
    use crate::http::HttpResponse;

    const APP_UID: &str = "app-0123456789abcdef0123456789abcdef";
    const POLICY_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const P256_KEY: &str = "02abababababababababababababababababababababababababababababababab";
    // liskov-rs `crates/slipway-crypto/vectors/grant_k1.json` at bad80efb195c,
    // copied so the k1 values reaching `signer_decrypt` are realistic.
    const K1_RECIPIENT_KEY: &str =
        "023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1";
    const K1_SENDER_KEY: &str =
        "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991";
    const K1_SALT: &str = "00000000000000000000000000000000";
    const K1_CIPHERTEXT: &str = "000102030405060708090a0bf45b672a768eef124229082e7704ab0be7b669d3f0f1ad7511f0dbb0783bb9cf05cb72dfe50688739c7cf6";
    const P256_ENVELOPE: Envelope = Envelope {
        domain: ENCRYPTED_PAYLOAD_DOMAIN_V2,
        version: "acurast-p256-hkdf-aes-256-gcm-v2",
        curve_name: "secp256r1",
        sender_public_key: P256_KEY,
        salt_hex: "2222222222222222222222222222222222222222222222222222222222222222",
        ciphertext_hex: "3333333333333333333333333333333333333333333333333333333333333333",
    };
    const K1_ENVELOPE: Envelope = Envelope {
        domain: ENCRYPTED_PAYLOAD_DOMAIN_V2,
        version: "acurast-secp256k1-hkdf-aes-256-gcm-v1",
        curve_name: "secp256k1",
        sender_public_key: K1_SENDER_KEY,
        salt_hex: K1_SALT,
        ciphertext_hex: K1_CIPHERTEXT,
    };

    struct Envelope {
        domain: &'static str,
        version: &'static str,
        curve_name: &'static str,
        sender_public_key: &'static str,
        salt_hex: &'static str,
        ciphertext_hex: &'static str,
    }

    struct FakeBridge {
        replies: Mutex<VecDeque<Result<Value, BridgeError>>>,
        calls: Mutex<Vec<(String, Value)>>,
    }

    impl FakeBridge {
        fn new(plaintext: &[u8]) -> Self {
            Self::with_keys(json!({"p256": P256_KEY}), plaintext)
        }

        fn with_keys(keys: Value, plaintext: &[u8]) -> Self {
            Self::replying([
                Ok(json!({"encryptionKeys": keys})),
                Ok(json!({"bytes": "11".repeat(64)})),
                Ok(json!({"bytes": hex::encode(plaintext)})),
            ])
        }

        fn for_discovery(plaintext: &[u8]) -> Self {
            Self::discovering(json!({"p256": P256_KEY}), plaintext)
        }

        fn discovering(keys: Value, plaintext: &[u8]) -> Self {
            Self::replying([
                Ok(json!({"encryptionKeys": keys.clone()})),
                Ok(json!({"bytes": "11".repeat(64)})),
                Ok(json!({"encryptionKeys": keys})),
                Ok(json!({"bytes": "22".repeat(64)})),
                Ok(json!({"bytes": hex::encode(plaintext)})),
            ])
        }

        fn replying<const N: usize>(replies: [Result<Value, BridgeError>; N]) -> Self {
            Self {
                replies: Mutex::new(replies.into()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn methods(&self) -> Vec<String> {
            let calls = self.calls.lock().unwrap();
            calls.iter().map(|(method, _)| method.clone()).collect()
        }
    }

    impl Bridge for FakeBridge {
        fn call(&self, method: &str, params: Value) -> Result<Value, BridgeError> {
            self.calls.lock().unwrap().push((method.to_owned(), params));
            self.replies.lock().unwrap().pop_front().unwrap()
        }
    }

    struct FakeHttp {
        responses: Mutex<VecDeque<HttpResponse>>,
        calls: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl FakeHttp {
        fn single(response: HttpResponse) -> Self {
            Self {
                responses: Mutex::new([response].into()),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl HttpClient for FakeHttp {
        fn post(&self, url: &str, body: &[u8]) -> Result<HttpResponse, HttpError> {
            self.calls
                .lock()
                .unwrap()
                .push((url.to_owned(), body.to_vec()));
            Ok(self.responses.lock().unwrap().pop_front().unwrap())
        }
    }

    fn bootstrap(logging: bool) -> RuntimeBootstrapResponse {
        serde_json::from_value(json!({
            "ok": true,
            "domain": "proof.liskov.runtime-bootstrap-response.v2",
            "applicationUid": APP_UID,
            "applicationId": "app-1",
            "policyDigest": POLICY_DIGEST,
            "jobId": "job-1",
            "deploymentId": "dep-1",
            "processorId": "processor-1",
            "runtimeInstanceId": "11".repeat(16),
            "slipwayUrl": "https://liskov.example",
            "runtimeEnv": {"enabled": true, "url": "https://liskov.example"},
            "secrets": {"required": true},
            "logging": {"enabled": logging},
            "serverTimeMs": 1_000,
            "scheduleEndMs": 61_000,
        }))
        .unwrap()
    }

    fn compact_bootstrap() -> String {
        json!({
            "v": 2,
            "u": "https://lockbox.example",
            "uid": APP_UID,
            "a": "app-1",
            "g": "grant-1",
            "p": POLICY_DIGEST,
            "d": "dep-1",
            "s": [BLACKBOX_LOG_CONFIG_SECRET_ID],
        })
        .to_string()
    }

    fn plaintext(config: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "domain": RESPONSE_DOMAIN_V2,
            "requestId": "request-1",
            "grantId": "grant-1",
            "applicationUid": APP_UID,
            "applicationId": "app-1",
            "repository": "owner/repo",
            "policyDigest": POLICY_DIGEST,
            "jobId": "job-1",
            "deploymentId": "dep-1",
            "processorId": "processor-1",
            "issuedAtMs": 1_000,
            "secrets": [{
                "secretId": BLACKBOX_LOG_CONFIG_SECRET_ID,
                "versionId": "version-1",
                "target": "env",
                "name": BLACKBOX_LOG_CONFIG_ENV,
                "required": true,
                "bundleId": BLACKBOX_LOG_CONFIG_BUNDLE_ID,
                "value": config,
            }],
        }))
        .unwrap()
    }

    fn response_body(plaintext: &[u8]) -> Vec<u8> {
        response_body_with(plaintext, &P256_ENVELOPE)
    }

    fn response_body_with(plaintext: &[u8], envelope: &Envelope) -> Vec<u8> {
        let aad = json!({
            "domain": RESPONSE_AAD_DOMAIN_V2,
            "requestId": "request-1",
            "applicationUid": APP_UID,
            "applicationId": "app-1",
            "grantId": "grant-1",
            "policyDigest": POLICY_DIGEST,
            "jobId": "job-1",
            "deploymentId": "dep-1",
            "processorId": "processor-1",
        });
        let mut encrypted = json!({
            "domain": envelope.domain,
            "version": envelope.version,
            "curveName": envelope.curve_name,
            "senderPublicKey": envelope.sender_public_key,
            "saltHex": envelope.salt_hex,
            "ciphertextHex": envelope.ciphertext_hex,
            "plaintextDigest": sha256_prefixed(plaintext),
            "aadDigest": sha256_prefixed(&canonical_json_bytes(&aad)),
        });
        let digest = sha256_prefixed(&canonical_json_bytes(&encrypted));
        encrypted["encryptedPayloadDigest"] = json!(digest);
        serde_json::to_vec(&json!({
            "ok": true,
            "domain": RESPONSE_DOMAIN_V2,
            "requestId": "request-1",
            "grantId": "grant-1",
            "applicationUid": APP_UID,
            "applicationId": "app-1",
            "repository": "owner/repo",
            "policyDigest": POLICY_DIGEST,
            "jobId": "job-1",
            "deploymentId": "dep-1",
            "processorId": "processor-1",
            "requestedSecretIds": [BLACKBOX_LOG_CONFIG_SECRET_ID],
            "responseKeyDigest": "sha256:ignored-by-client",
            "secretVersions": [{
                "secretId": BLACKBOX_LOG_CONFIG_SECRET_ID,
                "versionId": "version-1",
                "target": "env",
                "name": BLACKBOX_LOG_CONFIG_ENV,
                "required": true,
                "bundleId": BLACKBOX_LOG_CONFIG_BUNDLE_ID,
            }],
            "encryptedPayload": encrypted,
        }))
        .unwrap()
    }

    #[test]
    fn fetches_only_bound_blackbox_config_through_cargo_bridge() {
        let config = json!({
            "sinkId": "sink-1",
            "jobId": "job-1",
            "writeUrl": "https://logging.example/v1/sinks/sink-1/events",
            "dek": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        })
        .to_string();
        let plaintext = plaintext(&config);
        let bridge = FakeBridge::new(&plaintext);
        let http = FakeHttp::single(HttpResponse {
            status: 200,
            body: response_body(&plaintext),
        });

        let loaded = load_blackbox_log_config_with(
            &bootstrap(true),
            &bridge,
            &http,
            &compact_bootstrap(),
            1_000,
            [7; 16],
        )
        .unwrap();

        assert_eq!(loaded.as_deref(), Some(config.as_str()));
        let calls = bridge.calls.lock().unwrap();
        assert_eq!(calls[0].0, "deployment_encryptionKeys");
        assert_eq!(calls[1].0, "signer_sign");
        assert_eq!(calls[2].0, "signer_decrypt");
        assert_eq!(calls[2].1[0]["curve"], "p256");
        let http_calls = http.calls.lock().unwrap();
        assert_eq!(
            http_calls[0].0,
            "https://lockbox.example/api/jobs/secret-requests"
        );
        let request: Value = serde_json::from_slice(&http_calls[0].1).unwrap();
        assert_eq!(
            request["requestedSecretIds"],
            json!([BLACKBOX_LOG_CONFIG_SECRET_ID])
        );
        assert_eq!(request["responseEncryptionKey"], P256_KEY);
        assert!(request["signature"].as_str().unwrap().starts_with("0x"));
    }

    #[test]
    fn discovers_signed_job_grant_without_set_environment() {
        let config = "signed-secret-bootstrap-config";
        let plaintext = plaintext(config);
        let bridge = FakeBridge::for_discovery(&plaintext);
        let secret_bootstrap = serde_json::to_vec(&json!({
            "ok": true,
            "domain": SECRET_BOOTSTRAP_RESPONSE_DOMAIN_V2,
            "lockboxUrl": "https://lockbox.example",
            "applicationUid": APP_UID,
            "applicationId": "app-1",
            "grantId": "grant-1",
            "policyDigest": POLICY_DIGEST,
            "deploymentId": "dep-1",
            "jobId": "job-1",
            "processorId": "processor-1",
            "requestedSecretIds": [BLACKBOX_LOG_CONFIG_SECRET_ID],
        }))
        .unwrap();
        let http = FakeHttp {
            responses: Mutex::new(
                [
                    HttpResponse {
                        status: 200,
                        body: secret_bootstrap,
                    },
                    HttpResponse {
                        status: 200,
                        body: response_body(&plaintext),
                    },
                ]
                .into(),
            ),
            calls: Mutex::new(Vec::new()),
        };

        let raw_bootstrap = discover_lockbox_bootstrap_with(
            &bootstrap(true),
            &bridge,
            &http,
            DEFAULT_SECRETS_URL,
            1_000,
            [6; 16],
        )
        .unwrap()
        .unwrap();
        let loaded = load_blackbox_log_config_with(
            &bootstrap(true),
            &bridge,
            &http,
            &raw_bootstrap,
            1_000,
            [7; 16],
        )
        .unwrap();

        assert_eq!(loaded.as_deref(), Some(config));
        let http_calls = http.calls.lock().unwrap();
        assert_eq!(
            http_calls[0].0,
            "https://secrets.liskov.proof.computer/api/jobs/secret-bootstrap"
        );
        let bootstrap_request: Value = serde_json::from_slice(&http_calls[0].1).unwrap();
        assert_eq!(
            bootstrap_request["domain"],
            SECRET_BOOTSTRAP_REQUEST_DOMAIN_V2
        );
        assert_eq!(bootstrap_request["jobId"], "job-1");
        assert_eq!(bootstrap_request["processorId"], "processor-1");
        assert_eq!(bootstrap_request["responseEncryptionKey"], P256_KEY);
        assert!(
            bootstrap_request["signature"]
                .as_str()
                .unwrap()
                .starts_with("0x")
        );
        assert_eq!(
            http_calls[1].0,
            "https://lockbox.example/api/jobs/secret-requests"
        );
        let bridge_calls = bridge.calls.lock().unwrap();
        assert_eq!(bridge_calls[0].0, "deployment_encryptionKeys");
        assert_eq!(bridge_calls[1].0, "signer_sign");
        assert_eq!(bridge_calls[2].0, "deployment_encryptionKeys");
        assert_eq!(bridge_calls[3].0, "signer_sign");
        assert_eq!(bridge_calls[4].0, "signer_decrypt");
    }

    fn load_with(
        bridge: &FakeBridge,
        http: &FakeHttp,
    ) -> Result<Option<String>, LogConfigSecretError> {
        load_blackbox_log_config_with(
            &bootstrap(true),
            bridge,
            http,
            &compact_bootstrap(),
            1_000,
            [7; 16],
        )
    }

    fn sent_response_key(http: &FakeHttp, index: usize) -> Value {
        let http_calls = http.calls.lock().unwrap();
        let request: Value = serde_json::from_slice(&http_calls[index].1).unwrap();
        request["responseEncryptionKey"].clone()
    }

    #[test]
    fn a_secp256k1_only_processor_requests_and_decrypts_on_secp256k1() {
        let config = "k1-blackbox-config";
        let plaintext = plaintext(config);
        let bridge = FakeBridge::with_keys(json!({"secp256k1": K1_RECIPIENT_KEY}), &plaintext);
        let http = FakeHttp::single(HttpResponse {
            status: 200,
            body: response_body_with(&plaintext, &K1_ENVELOPE),
        });

        let loaded = load_with(&bridge, &http).unwrap();

        assert_eq!(loaded.as_deref(), Some(config));
        assert_eq!(sent_response_key(&http, 0), K1_RECIPIENT_KEY);
        assert_eq!(
            bridge.methods(),
            ["deployment_encryptionKeys", "signer_sign", "signer_decrypt"]
        );
        let calls = bridge.calls.lock().unwrap();
        assert_eq!(
            calls[2].1,
            json!([{
                "curve": "secp256k1",
                "publicKey": K1_SENDER_KEY,
                "salt": K1_SALT,
                "bytes": K1_CIPHERTEXT,
            }])
        );
    }

    #[test]
    fn a_secp256k1_only_processor_discovers_its_grant_with_the_secp256k1_key() {
        let plaintext = plaintext("config");
        let bridge = FakeBridge::discovering(json!({"secp256k1": K1_RECIPIENT_KEY}), &plaintext);
        let http = FakeHttp::single(HttpResponse {
            status: 200,
            body: serde_json::to_vec(&json!({
                "ok": true,
                "domain": SECRET_BOOTSTRAP_RESPONSE_DOMAIN_V2,
                "lockboxUrl": "https://lockbox.example",
                "applicationUid": APP_UID,
                "applicationId": "app-1",
                "grantId": "grant-1",
                "policyDigest": POLICY_DIGEST,
                "deploymentId": "dep-1",
                "jobId": "job-1",
                "processorId": "processor-1",
                "requestedSecretIds": [BLACKBOX_LOG_CONFIG_SECRET_ID],
            }))
            .unwrap(),
        });

        discover_lockbox_bootstrap_with(
            &bootstrap(true),
            &bridge,
            &http,
            DEFAULT_SECRETS_URL,
            1_000,
            [6; 16],
        )
        .unwrap()
        .unwrap();

        assert_eq!(sent_response_key(&http, 0), K1_RECIPIENT_KEY);
        assert_eq!(
            bridge.methods(),
            ["deployment_encryptionKeys", "signer_sign"]
        );
    }

    #[test]
    fn a_processor_exposing_both_keys_is_served_on_p256() {
        let plaintext = plaintext("config");
        let bridge = FakeBridge::with_keys(
            json!({"p256": P256_KEY, "secp256k1": K1_RECIPIENT_KEY}),
            &plaintext,
        );
        let http = FakeHttp::single(HttpResponse {
            status: 200,
            body: response_body(&plaintext),
        });

        assert_eq!(
            load_with(&bridge, &http).unwrap().as_deref(),
            Some("config")
        );
        assert_eq!(sent_response_key(&http, 0), P256_KEY);
        assert_eq!(
            bridge.methods(),
            ["deployment_encryptionKeys", "signer_sign", "signer_decrypt"]
        );
        assert_eq!(bridge.calls.lock().unwrap()[2].1[0]["curve"], "p256");
    }

    fn priming_call() -> Value {
        json!([{
            "curve": "secp256k1",
            "publicKey": SECP256K1_PRIMING_PUBLIC_KEY,
            "salt": "00",
            "bytes": "00",
        }])
    }

    #[test]
    fn a_processor_exposing_neither_key_is_primed_once_then_refused_before_http() {
        let bridge = FakeBridge::replying([
            Ok(json!({"encryptionKeys": {}})),
            Ok(json!({"bytes": "00"})),
            Ok(json!({"encryptionKeys": {}})),
        ]);
        let http = FakeHttp {
            responses: Mutex::new(VecDeque::new()),
            calls: Mutex::new(Vec::new()),
        };

        assert!(matches!(
            load_with(&bridge, &http),
            Err(LogConfigSecretError::InvalidEncryptionKey)
        ));
        assert_eq!(
            bridge.methods(),
            [
                "deployment_encryptionKeys",
                "signer_encrypt",
                "deployment_encryptionKeys"
            ]
        );
        assert_eq!(bridge.calls.lock().unwrap()[1].1, priming_call());
        assert!(http.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn a_secp256k1_key_materialised_by_priming_is_used_even_when_priming_errors() {
        let plaintext = plaintext("config");
        let bridge = FakeBridge::replying([
            Ok(json!({"encryptionKeys": {}})),
            Err(BridgeError::InvalidSocketName),
            Ok(json!({"encryptionKeys": {"secp256k1": K1_RECIPIENT_KEY}})),
            Ok(json!({"bytes": "11".repeat(64)})),
            Ok(json!({"bytes": hex::encode(&plaintext)})),
        ]);
        let http = FakeHttp::single(HttpResponse {
            status: 200,
            body: response_body_with(&plaintext, &K1_ENVELOPE),
        });

        assert_eq!(
            load_with(&bridge, &http).unwrap().as_deref(),
            Some("config")
        );
        assert_eq!(sent_response_key(&http, 0), K1_RECIPIENT_KEY);
        assert_eq!(
            bridge.methods(),
            [
                "deployment_encryptionKeys",
                "signer_encrypt",
                "deployment_encryptionKeys",
                "signer_sign",
                "signer_decrypt"
            ]
        );
        let calls = bridge.calls.lock().unwrap();
        assert_eq!(calls[1].1, priming_call());
        assert_eq!(calls[4].1[0]["curve"], "secp256k1");
    }

    #[test]
    fn an_envelope_that_does_not_match_the_sent_key_is_an_invalid_response() {
        let k1_on_v1_domain = Envelope {
            domain: "proof.lockbox.job-secret-response.encrypted-payload.v1",
            ..K1_ENVELOPE
        };
        let k1_id_on_secp256r1 = Envelope {
            curve_name: "secp256r1",
            ..K1_ENVELOPE
        };
        let p256_id_on_secp256k1 = Envelope {
            curve_name: "secp256k1",
            ..P256_ENVELOPE
        };
        let p256_keys = json!({"p256": P256_KEY});
        let k1_keys = json!({"secp256k1": K1_RECIPIENT_KEY});
        for (name, keys, envelope) in [
            ("p256 request, k1 envelope", &p256_keys, &K1_ENVELOPE),
            (
                "p256 request, p256 id on secp256k1",
                &p256_keys,
                &p256_id_on_secp256k1,
            ),
            ("k1 request, p256-v2 envelope", &k1_keys, &P256_ENVELOPE),
            (
                "k1 request, k1 id on secp256r1",
                &k1_keys,
                &k1_id_on_secp256r1,
            ),
            (
                "k1 request, k1 envelope on v1 domain",
                &k1_keys,
                &k1_on_v1_domain,
            ),
        ] {
            let plaintext = plaintext("config");
            let bridge = FakeBridge::with_keys(keys.clone(), &plaintext);
            let http = FakeHttp::single(HttpResponse {
                status: 200,
                body: response_body_with(&plaintext, envelope),
            });

            assert!(
                matches!(
                    load_with(&bridge, &http),
                    Err(LogConfigSecretError::InvalidResponse)
                ),
                "{name}"
            );
            assert_eq!(
                bridge.methods(),
                ["deployment_encryptionKeys", "signer_sign"],
                "{name}"
            );
        }
    }

    #[test]
    fn skips_lockbox_when_logging_is_disabled_or_config_is_already_signed() {
        let plaintext = plaintext("config");
        let bridge = FakeBridge::new(&plaintext);
        let mut environment =
            BTreeMap::from([(LEGACY_LOCKBOX_BOOTSTRAP_ENV.to_owned(), compact_bootstrap())]);
        hydrate_blackbox_log_config(&bootstrap(false), &bridge, &mut environment).unwrap();
        assert!(bridge.calls.lock().unwrap().is_empty());

        environment.insert(BLACKBOX_LOG_CONFIG_ENV.to_owned(), "signed".to_owned());
        hydrate_blackbox_log_config(&bootstrap(true), &bridge, &mut environment).unwrap();
        assert!(bridge.calls.lock().unwrap().is_empty());
        assert_eq!(environment[BLACKBOX_LOG_CONFIG_ENV], "signed");
    }

    #[test]
    fn rejects_cross_job_plaintext_without_exposing_secret_value() {
        let config = "credential-shaped-sensitive-value";
        let mut plaintext_value: Value = serde_json::from_slice(&plaintext(config)).unwrap();
        plaintext_value["jobId"] = json!("other-job");
        let plaintext = serde_json::to_vec(&plaintext_value).unwrap();
        let bridge = FakeBridge::new(&plaintext);
        let http = FakeHttp::single(HttpResponse {
            status: 200,
            body: response_body(&plaintext),
        });

        let error = load_blackbox_log_config_with(
            &bootstrap(true),
            &bridge,
            &http,
            &compact_bootstrap(),
            1_000,
            [7; 16],
        )
        .unwrap_err();

        assert!(matches!(error, LogConfigSecretError::ResponseBinding));
        assert!(!error.to_string().contains(config));
    }

    #[test]
    fn rejects_non_https_lockbox_and_unrequested_logging_secret() {
        let mut insecure: Value = serde_json::from_str(&compact_bootstrap()).unwrap();
        insecure["u"] = json!("http://lockbox.example");
        let plaintext = plaintext("config");
        let bridge = FakeBridge::new(&plaintext);
        let http = FakeHttp::single(HttpResponse {
            status: 200,
            body: response_body(&plaintext),
        });
        assert!(matches!(
            load_blackbox_log_config_with(
                &bootstrap(true),
                &bridge,
                &http,
                &insecure.to_string(),
                1_000,
                [7; 16]
            ),
            Err(LogConfigSecretError::InvalidBootstrap)
        ));

        let mut absent: Value = serde_json::from_str(&compact_bootstrap()).unwrap();
        absent["s"] = json!(["customer-secret"]);
        assert_eq!(
            load_blackbox_log_config_with(
                &bootstrap(true),
                &bridge,
                &http,
                &absent.to_string(),
                1_000,
                [7; 16]
            )
            .unwrap(),
            None
        );
        assert!(bridge.calls.lock().unwrap().is_empty());
        assert!(http.calls.lock().unwrap().is_empty());
    }

    fn process_env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        }
    }

    #[test]
    fn the_signed_runtime_environment_outranks_the_inherited_process_value() {
        let environment = BTreeMap::from([(
            LEGACY_LOCKBOX_BOOTSTRAP_ENV.to_owned(),
            "signed-legacy".to_owned(),
        )]);
        assert_eq!(
            ambient_lockbox_bootstrap(
                &environment,
                process_env(&[(LOCKBOX_BOOTSTRAP_ENV, "process-new")])
            ),
            Some("signed-legacy".to_owned())
        );
    }

    #[test]
    fn the_liskov_lockbox_name_is_preferred_within_each_channel() {
        let environment = BTreeMap::from([
            (LOCKBOX_BOOTSTRAP_ENV.to_owned(), "signed-new".to_owned()),
            (
                LEGACY_LOCKBOX_BOOTSTRAP_ENV.to_owned(),
                "signed-legacy".to_owned(),
            ),
        ]);
        assert_eq!(
            ambient_lockbox_bootstrap(&environment, process_env(&[])),
            Some("signed-new".to_owned())
        );
        assert_eq!(
            ambient_lockbox_bootstrap(
                &BTreeMap::new(),
                process_env(&[
                    (LOCKBOX_BOOTSTRAP_ENV, "process-new"),
                    (LEGACY_LOCKBOX_BOOTSTRAP_ENV, "process-legacy"),
                ])
            ),
            Some("process-new".to_owned())
        );
    }

    #[test]
    fn the_legacy_lockbox_name_still_resolves_on_its_own() {
        assert_eq!(
            ambient_lockbox_bootstrap(
                &BTreeMap::new(),
                process_env(&[(LEGACY_LOCKBOX_BOOTSTRAP_ENV, "process-legacy")])
            ),
            Some("process-legacy".to_owned())
        );
        assert_eq!(
            ambient_lockbox_bootstrap(&BTreeMap::new(), process_env(&[])),
            None
        );
    }
}
