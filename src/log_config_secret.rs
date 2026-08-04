//! Narrow Lockbox reader for the server-owned Blackbox log configuration.
//!
//! The Cargo supervisor must own Runtime SSH logging before the provider
//! sidecar starts. `BLACKBOX_LOG_CONFIG` is nevertheless delivered as a
//! job-bound Lockbox secret, so the supervisor resolves only that exact secret
//! through the Acurast bridge. Customer secrets remain owned by the workload's
//! runtime SDK.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::bridge::{Bridge, BridgeError};
use crate::diagnostics::canonical_json_bytes;
use crate::http::{HttpClient, HttpError, UreqHttpClient};
use crate::protocol::RuntimeBootstrapResponse;

pub const BLACKBOX_LOG_CONFIG_ENV: &str = "BLACKBOX_LOG_CONFIG";
const LOCKBOX_BOOTSTRAP_ENV: &str = "PROOF_LOCKBOX_BOOTSTRAP";
const BLACKBOX_LOG_CONFIG_SECRET_ID: &str = "blackbox-log-config";
const BLACKBOX_LOG_CONFIG_BUNDLE_ID: &str = "blackbox-log-config";
const REQUEST_DOMAIN_V2: &str = "proof.lockbox.job-secret-request.v2";
const RESPONSE_DOMAIN_V2: &str = "proof.lockbox.job-secret-response.v2";
const ENCRYPTED_PAYLOAD_DOMAIN_V2: &str = "proof.lockbox.job-secret-response.encrypted-payload.v2";
const RESPONSE_AAD_DOMAIN_V2: &str = "proof.lockbox.job-secret-response.aad.v2";
const REQUEST_TTL_MS: u64 = 60_000;
const MAX_CONFIG_BYTES: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum LogConfigSecretError {
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

#[derive(Debug, Deserialize)]
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
    let raw_bootstrap = runtime_environment
        .get(LOCKBOX_BOOTSTRAP_ENV)
        .cloned()
        .or_else(|| std::env::var(LOCKBOX_BOOTSTRAP_ENV).ok());
    let Some(raw_bootstrap) = raw_bootstrap else {
        return Ok(());
    };
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| LogConfigSecretError::Randomness)?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LogConfigSecretError::Clock)?
        .as_millis();
    let now_ms = u64::try_from(now_ms).map_err(|_| LogConfigSecretError::Clock)?;
    let http = UreqHttpClient::default();
    if let Some(config) =
        load_blackbox_log_config_with(bootstrap, bridge, &http, &raw_bootstrap, now_ms, nonce)?
    {
        runtime_environment.insert(BLACKBOX_LOG_CONFIG_ENV.to_owned(), config);
    }
    Ok(())
}

fn load_blackbox_log_config_with(
    bootstrap: &RuntimeBootstrapResponse,
    bridge: &dyn Bridge,
    http: &dyn HttpClient,
    raw_bootstrap: &str,
    now_ms: u64,
    nonce: [u8; 16],
) -> Result<Option<String>, LogConfigSecretError> {
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
    if !config
        .s
        .iter()
        .any(|secret_id| secret_id == BLACKBOX_LOG_CONFIG_SECRET_ID)
    {
        return Ok(None);
    }
    let endpoint = secure_endpoint(&config.u)?;
    let response_encryption_key = encryption_public_key(bridge)?;
    let unsigned = UnsignedRequest {
        domain: REQUEST_DOMAIN_V2,
        application_uid: bootstrap.application_uid.clone(),
        application_id: bootstrap.application_id.clone(),
        grant_id: config.g,
        policy_digest,
        job_id: bootstrap.job_id.clone(),
        deployment_id: bootstrap.deployment_id.clone(),
        processor_id: bootstrap.processor_id.clone(),
        requested_secret_ids: vec![BLACKBOX_LOG_CONFIG_SECRET_ID.to_owned()],
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
    validate_and_decrypt_response(&unsigned, bridge, &response.body).map(Some)
}

fn secure_endpoint(raw: &str) -> Result<url::Url, LogConfigSecretError> {
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
    base.join("/api/jobs/secret-requests")
        .map_err(|_| LogConfigSecretError::InvalidBootstrap)
}

fn encryption_public_key(bridge: &dyn Bridge) -> Result<String, LogConfigSecretError> {
    let result = bridge
        .call("deployment_encryptionKeys", json!([]))
        .map_err(LogConfigSecretError::EncryptionKey)?;
    result
        .get("encryptionKeys")
        .and_then(|keys| keys.get("p256"))
        .and_then(Value::as_str)
        .and_then(normalize_p256_key)
        .ok_or(LogConfigSecretError::InvalidEncryptionKey)
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

fn validate_and_decrypt_response(
    request: &UnsignedRequest,
    bridge: &dyn Bridge,
    body: &[u8],
) -> Result<String, LogConfigSecretError> {
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
        || response["requestedSecretIds"] != json!([BLACKBOX_LOG_CONFIG_SECRET_ID])
        || response["requestId"]
            .as_str()
            .is_none_or(|request_id| request_id.is_empty())
    {
        return Err(LogConfigSecretError::ResponseBinding);
    }
    validate_secret_versions(&response["secretVersions"])?;

    let encrypted = response["encryptedPayload"]
        .as_object()
        .ok_or(LogConfigSecretError::InvalidResponse)?;
    if encrypted.get("domain").and_then(Value::as_str) != Some(ENCRYPTED_PAYLOAD_DOMAIN_V2)
        || encrypted.get("version").and_then(Value::as_str)
            != Some("acurast-p256-hkdf-aes-256-gcm-v2")
        || encrypted.get("curveName").and_then(Value::as_str) != Some("secp256r1")
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
                "curve": "p256",
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
    extract_blackbox_config(&payload)
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

fn normalize_p256_key(value: &str) -> Option<String> {
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
    use crate::http::HttpResponse;

    const APP_UID: &str = "app-0123456789abcdef0123456789abcdef";
    const POLICY_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const P256_KEY: &str = "02abababababababababababababababababababababababababababababababab";

    struct FakeBridge {
        replies: Mutex<VecDeque<Value>>,
        calls: Mutex<Vec<(String, Value)>>,
    }

    impl FakeBridge {
        fn new(plaintext: &[u8]) -> Self {
            Self {
                replies: Mutex::new(
                    [
                        json!({"encryptionKeys": {"p256": P256_KEY}}),
                        json!({"bytes": "11".repeat(64)}),
                        json!({"bytes": hex::encode(plaintext)}),
                    ]
                    .into(),
                ),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl Bridge for FakeBridge {
        fn call(&self, method: &str, params: Value) -> Result<Value, BridgeError> {
            self.calls.lock().unwrap().push((method.to_owned(), params));
            Ok(self.replies.lock().unwrap().pop_front().unwrap())
        }
    }

    struct FakeHttp {
        response: HttpResponse,
        calls: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl HttpClient for FakeHttp {
        fn post(&self, url: &str, body: &[u8]) -> Result<HttpResponse, HttpError> {
            self.calls
                .lock()
                .unwrap()
                .push((url.to_owned(), body.to_vec()));
            Ok(self.response.clone())
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
        let request = UnsignedRequest {
            domain: REQUEST_DOMAIN_V2,
            application_uid: APP_UID.to_owned(),
            application_id: "app-1".to_owned(),
            grant_id: "grant-1".to_owned(),
            policy_digest: POLICY_DIGEST.to_owned(),
            job_id: "job-1".to_owned(),
            deployment_id: "dep-1".to_owned(),
            processor_id: "processor-1".to_owned(),
            requested_secret_ids: vec![BLACKBOX_LOG_CONFIG_SECRET_ID.to_owned()],
            nonce: "07".repeat(16),
            issued_at_ms: 1_000,
            expires_at_ms: 61_000,
            response_encryption_key: P256_KEY.to_owned(),
        };
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
            "domain": ENCRYPTED_PAYLOAD_DOMAIN_V2,
            "version": "acurast-p256-hkdf-aes-256-gcm-v2",
            "curveName": "secp256r1",
            "senderPublicKey": P256_KEY,
            "saltHex": "22".repeat(32),
            "ciphertextHex": "33".repeat(32),
            "plaintextDigest": sha256_prefixed(plaintext),
            "aadDigest": sha256_prefixed(&canonical_json_bytes(&aad)),
        });
        let digest = sha256_prefixed(&canonical_json_bytes(&encrypted));
        encrypted["encryptedPayloadDigest"] = json!(digest);
        let _ = request;
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
        let http = FakeHttp {
            response: HttpResponse {
                status: 200,
                body: response_body(&plaintext),
            },
            calls: Mutex::new(Vec::new()),
        };

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
    fn skips_lockbox_when_logging_is_disabled_or_config_is_already_signed() {
        let plaintext = plaintext("config");
        let bridge = FakeBridge::new(&plaintext);
        let mut environment =
            BTreeMap::from([(LOCKBOX_BOOTSTRAP_ENV.to_owned(), compact_bootstrap())]);
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
        let http = FakeHttp {
            response: HttpResponse {
                status: 200,
                body: response_body(&plaintext),
            },
            calls: Mutex::new(Vec::new()),
        };

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
        let http = FakeHttp {
            response: HttpResponse {
                status: 200,
                body: response_body(&plaintext),
            },
            calls: Mutex::new(Vec::new()),
        };
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
}
