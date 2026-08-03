use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::bridge::{Bridge, BridgeError};

pub const RUNTIME_BOOTSTRAP_REQUEST_DOMAIN_V2: &str = "proof.liskov.runtime-bootstrap-request.v2";
pub const RUNTIME_BOOTSTRAP_RESPONSE_DOMAIN_V2: &str = "proof.liskov.runtime-bootstrap-response.v2";
pub const RUNTIME_BOOTSTRAP_TTL_MS: u64 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeIdentity {
    pub job_id: String,
    pub processor_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedRuntimeBootstrapRequest {
    pub domain: &'static str,
    pub job_id: String,
    pub processor_id: String,
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedRuntimeBootstrapRequest {
    pub domain: &'static str,
    pub job_id: String,
    pub processor_id: String,
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeBootstrapResponse {
    pub ok: bool,
    pub domain: String,
    pub application_uid: String,
    pub application_id: String,
    pub policy_digest: String,
    pub deployment_id: String,
    pub job_id: String,
    pub processor_id: String,
    pub runtime_instance_id: String,
    pub slipway_url: String,
    #[serde(default)]
    pub runtime_env: Option<RuntimeEnvBootstrap>,
    #[serde(default)]
    pub supervision: Option<Value>,
    #[serde(default)]
    pub logging: Option<Value>,
    #[serde(default)]
    pub logging_outage_canary: bool,
    #[serde(default)]
    pub diagnostics: Option<RuntimeDiagnosticsBootstrap>,
    #[serde(default)]
    pub access: Option<RuntimeAccessBootstrap>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderLogMode {
    Disabled,
    Sanitized,
    RawTailscaledStderr,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderLogsBootstrap {
    pub mode: ProviderLogMode,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeDiagnosticsBootstrap {
    #[serde(default)]
    pub provider_logs: Option<ProviderLogsBootstrap>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeEnvBootstrap {
    pub enabled: bool,
    pub url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAccessProviderKind {
    Tailscale,
    Liskov,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeAccessProvider {
    pub kind: RuntimeAccessProviderKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeAccessArtifact {
    pub descriptor_id: String,
    pub version: String,
    pub url: String,
    pub sha256: String,
    pub byte_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAccessLaunchProfile {
    TailscaleStandardV1,
    TailscaleAcurastProotV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TailscaleRuntimeAccessBootstrap {
    pub provider: RuntimeAccessProvider,
    pub attachment_id: String,
    pub expected_tailnet: String,
    pub setup_deadline_ms: u64,
    pub fence: u64,
    #[serde(default)]
    pub launch_profile: Option<RuntimeAccessLaunchProfile>,
    pub artifact: RuntimeAccessArtifact,
}

impl TailscaleRuntimeAccessBootstrap {
    fn valid(&self) -> bool {
        let url_valid = url::Url::parse(&self.artifact.url).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
        });
        !self.attachment_id.is_empty()
            && self.attachment_id.len() <= 256
            && !self.expected_tailnet.is_empty()
            && self.expected_tailnet != "-"
            && self.expected_tailnet.len() <= 253
            && !self.expected_tailnet.contains('/')
            && self.fence > 0
            && !self.artifact.descriptor_id.is_empty()
            && !self.artifact.version.is_empty()
            && self.artifact.sha256.len() == 64
            && self
                .artifact
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            && (1..=134_217_728).contains(&self.artifact.byte_size)
            && url_valid
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedRuntimeAccessProtocol {
    LiskovAccessV0,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedRuntimeAccessBootstrap {
    pub provider: RuntimeAccessProvider,
    pub attachment_id: String,
    pub fence: u64,
    pub gateway_url: String,
    pub tunnel_id: String,
    pub protocol: ManagedRuntimeAccessProtocol,
    pub setup_deadline_ms: u64,
}

impl ManagedRuntimeAccessBootstrap {
    fn valid(&self) -> bool {
        let gateway_valid = url::Url::parse(&self.gateway_url).is_ok_and(|url| {
            url.scheme() == "wss"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && matches!(url.path(), "" | "/")
        });
        self.provider.kind == RuntimeAccessProviderKind::Liskov
            && !self.attachment_id.is_empty()
            && self.attachment_id.len() <= 256
            && self.fence > 0
            && !self.tunnel_id.is_empty()
            && self.tunnel_id.len() <= 256
            && self
                .tunnel_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            && gateway_valid
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum RuntimeAccessBootstrap {
    Tailscale(TailscaleRuntimeAccessBootstrap),
    Managed(ManagedRuntimeAccessBootstrap),
}

impl RuntimeAccessBootstrap {
    pub fn valid(&self) -> bool {
        match self {
            Self::Tailscale(access) => {
                access.provider.kind == RuntimeAccessProviderKind::Tailscale && access.valid()
            }
            Self::Managed(access) => access.valid(),
        }
    }

    pub fn provider_kind(&self) -> RuntimeAccessProviderKind {
        match self {
            Self::Tailscale(access) => access.provider.kind,
            Self::Managed(access) => access.provider.kind,
        }
    }

    pub fn attachment_id(&self) -> &str {
        match self {
            Self::Tailscale(access) => &access.attachment_id,
            Self::Managed(access) => &access.attachment_id,
        }
    }

    pub fn fence(&self) -> u64 {
        match self {
            Self::Tailscale(access) => access.fence,
            Self::Managed(access) => access.fence,
        }
    }

    pub fn binding_attrs(&self) -> Value {
        json!({
            "attachmentId": self.attachment_id(),
            "fence": self.fence(),
            "providerKind": match self.provider_kind() {
                RuntimeAccessProviderKind::Tailscale => "tailscale",
                RuntimeAccessProviderKind::Liskov => "liskov",
            },
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartLimit {
    Attempts { max_restarts: u8 },
    ScheduleEnd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisionMode {
    Never,
    OnFailure { restart_limit: RestartLimit },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisionPolicy {
    pub mode: SupervisionMode,
    pub server_time_ms: u64,
    pub schedule_end_ms: u64,
}

impl RuntimeBootstrapResponse {
    /// Logging is opt-in twice: the signed policy decision must explicitly
    /// enable it and the separate Blackbox environment must validate. Unknown
    /// bootstrap fields never broaden capture authority.
    pub fn logging_enabled(&self) -> bool {
        let Some(object) = self.logging.as_ref().and_then(Value::as_object) else {
            return false;
        };
        object.len() == 1 && object.get("enabled").and_then(Value::as_bool) == Some(true)
    }

    /// The outage injector is a server-owned release-canary control. It can
    /// affect only an otherwise-valid, explicitly enabled logging transport.
    pub fn logging_outage_canary_enabled(&self) -> bool {
        self.logging_enabled() && self.logging_outage_canary
    }

    /// Returns the server-authored provider-log mode only when the complete
    /// closed diagnostics shape is valid. Raw capture additionally requires a
    /// future expiry; stale or malformed controls fail closed to disabled.
    pub fn provider_log_mode(&self, now_ms: u64) -> ProviderLogMode {
        if !self.logging_enabled() || self.access.is_none() {
            return ProviderLogMode::Disabled;
        }
        let Some(provider_logs) = self
            .diagnostics
            .as_ref()
            .and_then(|diagnostics| diagnostics.provider_logs.as_ref())
        else {
            return ProviderLogMode::Disabled;
        };
        match provider_logs.mode {
            ProviderLogMode::Disabled => ProviderLogMode::Disabled,
            ProviderLogMode::Sanitized => {
                if provider_logs.expires_at_ms.is_none() {
                    ProviderLogMode::Sanitized
                } else {
                    ProviderLogMode::Disabled
                }
            }
            ProviderLogMode::RawTailscaledStderr => {
                if provider_logs.expires_at_ms.is_some_and(|expires_at_ms| {
                    expires_at_ms > now_ms
                        && now_ms
                            .checked_add(60 * 60 * 1000)
                            .is_some_and(|ceiling| expires_at_ms <= ceiling)
                }) {
                    ProviderLogMode::RawTailscaledStderr
                } else {
                    ProviderLogMode::Disabled
                }
            }
        }
    }

    pub fn provider_log_expiry_ms(&self) -> Option<u64> {
        let provider_logs = self.diagnostics.as_ref()?.provider_logs.as_ref()?;
        (provider_logs.mode == ProviderLogMode::RawTailscaledStderr)
            .then_some(provider_logs.expires_at_ms?)
    }

    /// Parse the optional server-owned supervision decision. Any missing,
    /// malformed, unknown, expired, or authority-broadening value fails closed
    /// to the compatibility `never` mode.
    pub fn supervision_policy(&self) -> Option<SupervisionPolicy> {
        let value = self.supervision.as_ref()?;
        let object = value.as_object()?;
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "mode" | "restartLimit" | "serverTimeMs" | "scheduleEndMs"
            )
        }) {
            return None;
        }
        let mode = match object.get("mode").and_then(Value::as_str)? {
            "never" => {
                if object
                    .get("restartLimit")
                    .is_some_and(|value| !value.is_null())
                {
                    return None;
                }
                SupervisionMode::Never
            }
            "on_failure" => {
                let limit = object.get("restartLimit")?.as_object()?;
                if limit
                    .keys()
                    .any(|key| !matches!(key.as_str(), "kind" | "maxRestarts"))
                {
                    return None;
                }
                let restart_limit = match limit.get("kind").and_then(Value::as_str)? {
                    "attempts" => {
                        let max_restarts = limit.get("maxRestarts")?.as_u64()?;
                        RestartLimit::Attempts {
                            max_restarts: u8::try_from(max_restarts).ok().filter(|n| *n <= 10)?,
                        }
                    }
                    "schedule_end" => {
                        if limit
                            .get("maxRestarts")
                            .is_some_and(|value| !value.is_null())
                        {
                            return None;
                        }
                        RestartLimit::ScheduleEnd
                    }
                    _ => return None,
                };
                SupervisionMode::OnFailure { restart_limit }
            }
            _ => return None,
        };
        let server_time_ms = object.get("serverTimeMs")?.as_u64()?;
        let schedule_end_ms = object.get("scheduleEndMs")?.as_u64()?;
        (schedule_end_ms > server_time_ms).then_some(SupervisionPolicy {
            mode,
            server_time_ms,
            schedule_end_ms,
        })
    }
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("bridge setup failed")]
    BridgeSetup(#[source] BridgeError),
    #[error("deployment identity bridge call failed")]
    DeploymentIdentityBridge(#[source] BridgeError),
    #[error("deployment identity was missing or invalid")]
    InvalidDeploymentIdentity,
    #[error("deployment public-key bridge call failed")]
    PublicKeyBridge(#[source] BridgeError),
    #[error("deployment Ed25519 public key was missing or invalid")]
    InvalidPublicKey,
    #[error("assigned-processors bridge call failed")]
    AssignedProcessorsBridge(#[source] BridgeError),
    #[error("deployment identity did not match exactly one assigned processor")]
    ProcessorMatchCount,
    #[error("deployment signing bridge call failed")]
    SignerBridge(#[source] BridgeError),
    #[error("Ed25519 signature was missing or invalid")]
    InvalidSignature,
    #[error("request timestamp overflowed")]
    TimestampOverflow,
    #[error("request serialization failed")]
    Serialization(#[from] serde_json::Error),
    #[error("runtime bootstrap response was invalid")]
    InvalidResponse,
    #[error("runtime bootstrap response binding did not match the request")]
    ResponseBinding,
}

pub fn discover_runtime_identity(bridge: &dyn Bridge) -> Result<RuntimeIdentity, ProtocolError> {
    let deployment = bridge
        .call("deployment_id", json!([]))
        .map_err(ProtocolError::DeploymentIdentityBridge)?;
    deployment
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or(ProtocolError::InvalidDeploymentIdentity)?;
    deployment
        .get("origin")
        .filter(|origin| origin.is_object())
        .ok_or(ProtocolError::InvalidDeploymentIdentity)?;
    let job_id = serde_json::to_string(&sort_json(deployment.clone()))?;

    let public_keys = bridge
        .call("deployment_publicKeys", json!([]))
        .map_err(ProtocolError::PublicKeyBridge)?;
    let current_key = public_keys
        .get("publicKeys")
        .and_then(|keys| keys.get("ed25519"))
        .and_then(Value::as_str)
        .and_then(|key| normalize_hex_exact(key, 32))
        .ok_or(ProtocolError::InvalidPublicKey)?;

    let assigned = bridge
        .call("deployment_assignedProcessors", json!([]))
        .map_err(ProtocolError::AssignedProcessorsBridge)?;
    let processors = assigned
        .get("processors")
        .and_then(Value::as_object)
        .ok_or(ProtocolError::ProcessorMatchCount)?;
    let matches: Vec<&str> = processors
        .iter()
        .filter_map(|(address, keys)| {
            keys.get("ed25519")
                .and_then(Value::as_str)
                .and_then(|key| normalize_hex_exact(key, 32))
                .filter(|key| key == &current_key)
                .map(|_| address.as_str())
        })
        .collect();
    let [processor_id] = matches.as_slice() else {
        return Err(ProtocolError::ProcessorMatchCount);
    };
    if processor_id.is_empty() {
        return Err(ProtocolError::ProcessorMatchCount);
    }

    Ok(RuntimeIdentity {
        job_id,
        processor_id: (*processor_id).to_owned(),
    })
}

pub fn build_unsigned_request(
    identity: RuntimeIdentity,
    nonce: String,
    issued_at_ms: u64,
) -> Result<UnsignedRuntimeBootstrapRequest, ProtocolError> {
    let expires_at_ms = issued_at_ms
        .checked_add(RUNTIME_BOOTSTRAP_TTL_MS)
        .ok_or(ProtocolError::TimestampOverflow)?;
    Ok(UnsignedRuntimeBootstrapRequest {
        domain: RUNTIME_BOOTSTRAP_REQUEST_DOMAIN_V2,
        job_id: identity.job_id,
        processor_id: identity.processor_id,
        nonce,
        issued_at_ms,
        expires_at_ms,
    })
}

pub fn canonical_unsigned_request_bytes(
    request: &UnsignedRuntimeBootstrapRequest,
) -> Result<Vec<u8>, ProtocolError> {
    let value = serde_json::to_value(request)?;
    Ok(serde_json::to_vec(&sort_json(value))?)
}

pub fn sign_request(
    bridge: &dyn Bridge,
    unsigned: UnsignedRuntimeBootstrapRequest,
) -> Result<SignedRuntimeBootstrapRequest, ProtocolError> {
    let message = canonical_unsigned_request_bytes(&unsigned)?;
    let result = bridge
        .call(
            "signer_sign",
            json!([{
                "curve": "ed25519",
                "bytes": hex::encode(message),
            }]),
        )
        .map_err(ProtocolError::SignerBridge)?;
    let signature = result
        .get("bytes")
        .and_then(Value::as_str)
        .and_then(|value| normalize_hex_exact(value, 64))
        .ok_or(ProtocolError::InvalidSignature)?;
    Ok(SignedRuntimeBootstrapRequest {
        domain: unsigned.domain,
        job_id: unsigned.job_id,
        processor_id: unsigned.processor_id,
        nonce: unsigned.nonce,
        issued_at_ms: unsigned.issued_at_ms,
        expires_at_ms: unsigned.expires_at_ms,
        signature: format!("0x{signature}"),
    })
}

pub fn validate_response(
    request: &SignedRuntimeBootstrapRequest,
    body: &[u8],
) -> Result<RuntimeBootstrapResponse, ProtocolError> {
    let response: RuntimeBootstrapResponse =
        serde_json::from_slice(body).map_err(|_| ProtocolError::InvalidResponse)?;
    if !response.ok
        || response.domain != RUNTIME_BOOTSTRAP_RESPONSE_DOMAIN_V2
        || response.application_uid.is_empty()
        || response.application_id.is_empty()
        || response.policy_digest.is_empty()
        || response.deployment_id.is_empty()
        || response.slipway_url.is_empty()
        || response
            .runtime_env
            .as_ref()
            .is_some_and(|runtime_env| runtime_env.enabled && runtime_env.url.is_empty())
        || response
            .access
            .as_ref()
            .is_some_and(|access| !access.valid())
    {
        return Err(ProtocolError::InvalidResponse);
    }
    if response.job_id != request.job_id
        || response.processor_id != request.processor_id
        || response.runtime_instance_id != request.nonce
    {
        return Err(ProtocolError::ResponseBinding);
    }
    Ok(response)
}

fn normalize_hex_exact(value: &str, bytes: usize) -> Option<String> {
    let value = value
        .strip_prefix("0x")
        .unwrap_or(value)
        .to_ascii_lowercase();
    (value.len() == bytes * 2 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(value)
}

fn sort_json(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(sort_json).collect()),
        Value::Object(items) => {
            let sorted: BTreeMap<String, Value> = items
                .into_iter()
                .map(|(key, value)| (key, sort_json(value)))
                .collect();
            Value::Object(Map::from_iter(sorted))
        }
        value => value,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;

    struct FakeBridge {
        replies: Mutex<VecDeque<Value>>,
        calls: Mutex<Vec<(String, Value)>>,
    }

    impl FakeBridge {
        fn new(replies: Vec<Value>) -> Self {
            Self {
                replies: Mutex::new(replies.into()),
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

    fn identity_replies(processors: Value) -> Vec<Value> {
        vec![
            json!({
                "id": "7",
                "origin": {"source": "abcd", "kind": "Acurast"}
            }),
            json!({"publicKeys": {"ed25519": format!("0x{}", "ab".repeat(32))}}),
            json!({"processors": processors}),
        ]
    }

    fn signed_request() -> SignedRuntimeBootstrapRequest {
        SignedRuntimeBootstrapRequest {
            domain: RUNTIME_BOOTSTRAP_REQUEST_DOMAIN_V2,
            job_id: "job-1".to_owned(),
            processor_id: "processor-1".to_owned(),
            nonce: "07".repeat(16),
            issued_at_ms: 1_000,
            expires_at_ms: 61_000,
            signature: format!("0x{}", "11".repeat(64)),
        }
    }

    #[test]
    fn canonical_request_bytes_match_the_existing_contract() {
        let request = build_unsigned_request(
            RuntimeIdentity {
                job_id: "job-1".to_owned(),
                processor_id: "processor-1".to_owned(),
            },
            "runtime-nonce".to_owned(),
            1_000,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(canonical_unsigned_request_bytes(&request).unwrap()).unwrap(),
            "{\"domain\":\"proof.liskov.runtime-bootstrap-request.v2\",\"expiresAtMs\":61000,\"issuedAtMs\":1000,\"jobId\":\"job-1\",\"nonce\":\"runtime-nonce\",\"processorId\":\"processor-1\"}"
        );
    }

    #[test]
    fn discovers_the_single_processor_matching_the_current_key() {
        let bridge = FakeBridge::new(identity_replies(json!({
            "processor-other": {"ed25519": "cd".repeat(32)},
            "processor-match": {"ed25519": "AB".repeat(32)}
        })));
        let identity = discover_runtime_identity(&bridge).unwrap();
        assert_eq!(
            identity.job_id,
            r#"{"id":"7","origin":{"kind":"Acurast","source":"abcd"}}"#
        );
        assert_eq!(identity.processor_id, "processor-match");
    }

    #[test]
    fn rejects_zero_and_ambiguous_processor_matches() {
        let zero = FakeBridge::new(identity_replies(json!({
            "processor-other": {"ed25519": "cd".repeat(32)}
        })));
        assert!(matches!(
            discover_runtime_identity(&zero),
            Err(ProtocolError::ProcessorMatchCount)
        ));

        let ambiguous = FakeBridge::new(identity_replies(json!({
            "processor-a": {"ed25519": "ab".repeat(32)},
            "processor-b": {"ed25519": format!("0x{}", "AB".repeat(32))}
        })));
        assert!(matches!(
            discover_runtime_identity(&ambiguous),
            Err(ProtocolError::ProcessorMatchCount)
        ));
    }

    #[test]
    fn signs_the_canonical_bytes_and_normalizes_the_signature() {
        let bridge = FakeBridge::new(vec![json!({"bytes": "AA".repeat(64)})]);
        let unsigned = build_unsigned_request(
            RuntimeIdentity {
                job_id: "job-1".to_owned(),
                processor_id: "processor-1".to_owned(),
            },
            "runtime-nonce".to_owned(),
            1_000,
        )
        .unwrap();
        let expected_message = canonical_unsigned_request_bytes(&unsigned).unwrap();
        let signed = sign_request(&bridge, unsigned).unwrap();
        assert_eq!(signed.signature, format!("0x{}", "aa".repeat(64)));

        let calls = bridge.calls.lock().unwrap();
        assert_eq!(calls[0].0, "signer_sign");
        assert_eq!(calls[0].1[0]["curve"], "ed25519");
        assert_eq!(calls[0].1[0]["bytes"], hex::encode(expected_message));
    }

    #[test]
    fn rejects_domain_and_all_identity_binding_mismatches() {
        let request = signed_request();
        let valid = json!({
            "ok": true,
            "domain": RUNTIME_BOOTSTRAP_RESPONSE_DOMAIN_V2,
            "applicationUid": "app-uid-1",
            "applicationId": "app-1",
            "policyDigest": "ab",
            "deploymentId": "dep-1",
            "jobId": request.job_id,
            "processorId": request.processor_id,
            "runtimeInstanceId": request.nonce,
            "slipwayUrl": "https://liskov.example"
        });
        assert!(validate_response(&request, &serde_json::to_vec(&valid).unwrap()).is_ok());

        for (field, value) in [
            (
                "domain",
                json!("proof.liskov.runtime-bootstrap-response.v1"),
            ),
            ("jobId", json!("wrong-job")),
            ("processorId", json!("wrong-processor")),
            ("runtimeInstanceId", json!("wrong-instance")),
        ] {
            let mut mutated = valid.clone();
            mutated[field] = value;
            assert!(validate_response(&request, &serde_json::to_vec(&mutated).unwrap()).is_err());
        }
    }

    #[test]
    fn rejects_empty_application_policy_deployment_and_slipway_fields() {
        let request = signed_request();
        let valid = json!({
            "ok": true,
            "domain": RUNTIME_BOOTSTRAP_RESPONSE_DOMAIN_V2,
            "applicationUid": "app-uid-1",
            "applicationId": "app-1",
            "policyDigest": "ab",
            "deploymentId": "dep-1",
            "jobId": request.job_id,
            "processorId": request.processor_id,
            "runtimeInstanceId": request.nonce,
            "slipwayUrl": "https://liskov.example"
        });
        for field in [
            "applicationUid",
            "applicationId",
            "policyDigest",
            "deploymentId",
            "slipwayUrl",
        ] {
            let mut mutated = valid.clone();
            mutated[field] = json!("");
            assert!(matches!(
                validate_response(&request, &serde_json::to_vec(&mutated).unwrap()),
                Err(ProtocolError::InvalidResponse)
            ));
        }
    }

    #[test]
    fn runtime_environment_bootstrap_is_typed_and_fail_closed() {
        let request = signed_request();
        let base = json!({
            "ok": true,
            "domain": RUNTIME_BOOTSTRAP_RESPONSE_DOMAIN_V2,
            "applicationUid": "app-uid-1",
            "applicationId": "app-1",
            "policyDigest": "ab",
            "deploymentId": "dep-1",
            "jobId": request.job_id,
            "processorId": request.processor_id,
            "runtimeInstanceId": request.nonce,
            "slipwayUrl": "https://liskov.example",
            "runtimeEnv": {
                "enabled": true,
                "url": "https://liskov.example"
            }
        });
        let parsed = validate_response(&request, &serde_json::to_vec(&base).unwrap()).unwrap();
        assert_eq!(
            parsed.runtime_env,
            Some(RuntimeEnvBootstrap {
                enabled: true,
                url: "https://liskov.example".into(),
            })
        );

        for runtime_env in [
            json!({"enabled": true, "url": ""}),
            json!({"enabled": true, "url": "https://liskov.example", "future": true}),
        ] {
            let mut invalid = base.clone();
            invalid["runtimeEnv"] = runtime_env;
            assert!(matches!(
                validate_response(&request, &serde_json::to_vec(&invalid).unwrap()),
                Err(ProtocolError::InvalidResponse)
            ));
        }
    }

    #[test]
    fn runtime_access_bootstrap_is_typed_pinned_and_closed() {
        let request = signed_request();
        let mut response = json!({
            "ok": true,
            "domain": RUNTIME_BOOTSTRAP_RESPONSE_DOMAIN_V2,
            "applicationUid": "app-uid-1",
            "applicationId": "app-1",
            "policyDigest": "sha256:policy",
            "deploymentId": "dep-1",
            "jobId": request.job_id,
            "processorId": request.processor_id,
            "runtimeInstanceId": request.nonce,
            "slipwayUrl": "https://liskov.example",
            "access": {
                "provider": {"kind": "tailscale"},
                "attachmentId": "att-1",
                "expectedTailnet": "example.com",
                "setupDeadlineMs": 60_000,
                "fence": 1,
                "artifact": {
                    "descriptorId": "descriptor-1",
                    "version": "1.80.3",
                    "url": "https://pkgs.tailscale.com/stable/client.tgz",
                    "sha256": "1".repeat(64),
                    "byteSize": 123,
                }
            }
        });
        let parsed = validate_response(&request, &serde_json::to_vec(&response).unwrap()).unwrap();
        assert_eq!(
            parsed.access.as_ref().unwrap().provider_kind(),
            RuntimeAccessProviderKind::Tailscale
        );
        assert_eq!(
            match parsed.access.unwrap() {
                RuntimeAccessBootstrap::Tailscale(access) => access.launch_profile,
                RuntimeAccessBootstrap::Managed(_) => panic!("expected Tailscale bootstrap"),
            },
            None
        );

        response["access"]["launchProfile"] = json!("tailscale_acurast_proot_v1");
        let parsed = validate_response(&request, &serde_json::to_vec(&response).unwrap()).unwrap();
        assert_eq!(
            match parsed.access.unwrap() {
                RuntimeAccessBootstrap::Tailscale(access) => access.launch_profile,
                RuntimeAccessBootstrap::Managed(_) => panic!("expected Tailscale bootstrap"),
            },
            Some(RuntimeAccessLaunchProfile::TailscaleAcurastProotV1)
        );

        for invalid in [
            json!("cloudflare"),
            json!("../tailnet"),
            json!("http://pkgs.example/client.tgz"),
            json!("ABCDEF"),
        ] {
            let mut rejected = response.clone();
            match invalid.as_str().unwrap() {
                "cloudflare" => rejected["access"]["provider"]["kind"] = invalid,
                "../tailnet" => rejected["access"]["expectedTailnet"] = invalid,
                value if value.starts_with("http:") => {
                    rejected["access"]["artifact"]["url"] = invalid
                }
                _ => rejected["access"]["artifact"]["sha256"] = invalid,
            }
            assert!(matches!(
                validate_response(&request, &serde_json::to_vec(&rejected).unwrap()),
                Err(ProtocolError::InvalidResponse)
            ));
        }
        response["access"]["futureProviderConfig"] = json!(true);
        assert!(matches!(
            validate_response(&request, &serde_json::to_vec(&response).unwrap()),
            Err(ProtocolError::InvalidResponse)
        ));

        response["access"]
            .as_object_mut()
            .unwrap()
            .remove("futureProviderConfig");
        response["access"]["launchProfile"] = json!("future_profile");
        assert!(matches!(
            validate_response(&request, &serde_json::to_vec(&response).unwrap()),
            Err(ProtocolError::InvalidResponse)
        ));

        response["access"] = json!({
            "provider": {"kind": "liskov"},
            "attachmentId": "att-managed-1",
            "fence": 1,
            "gatewayUrl": "wss://access.example",
            "tunnelId": "tunnel_managed_1",
            "protocol": "liskov_access_v0",
            "setupDeadlineMs": 60_000,
        });
        let parsed = validate_response(&request, &serde_json::to_vec(&response).unwrap()).unwrap();
        assert_eq!(
            parsed.access.as_ref().unwrap().provider_kind(),
            RuntimeAccessProviderKind::Liskov
        );
        assert_eq!(parsed.access.unwrap().attachment_id(), "att-managed-1");
        response["access"]["gatewayUrl"] = json!("wss://access.example?token=secret");
        assert!(matches!(
            validate_response(&request, &serde_json::to_vec(&response).unwrap()),
            Err(ProtocolError::InvalidResponse)
        ));
    }

    #[test]
    fn supervision_union_is_closed_and_defaults_to_never() {
        let request = signed_request();
        let base = json!({
            "ok": true,
            "domain": RUNTIME_BOOTSTRAP_RESPONSE_DOMAIN_V2,
            "applicationUid": "app-uid-1",
            "applicationId": "app-1",
            "policyDigest": "ab",
            "deploymentId": "dep-1",
            "jobId": request.job_id,
            "processorId": request.processor_id,
            "runtimeInstanceId": request.nonce,
            "slipwayUrl": "https://liskov.example"
        });
        let absent = validate_response(&request, &serde_json::to_vec(&base).unwrap()).unwrap();
        assert_eq!(absent.supervision_policy(), None);

        for (value, expected) in [
            (
                json!({
                    "mode": "on_failure",
                    "restartLimit": {"kind": "attempts", "maxRestarts": 0},
                    "serverTimeMs": 1_000,
                    "scheduleEndMs": 2_000,
                }),
                SupervisionMode::OnFailure {
                    restart_limit: RestartLimit::Attempts { max_restarts: 0 },
                },
            ),
            (
                json!({
                    "mode": "on_failure",
                    "restartLimit": {"kind": "schedule_end"},
                    "serverTimeMs": 1_000,
                    "scheduleEndMs": 2_000,
                }),
                SupervisionMode::OnFailure {
                    restart_limit: RestartLimit::ScheduleEnd,
                },
            ),
        ] {
            let mut response = base.clone();
            response["supervision"] = value;
            let parsed =
                validate_response(&request, &serde_json::to_vec(&response).unwrap()).unwrap();
            assert_eq!(
                parsed.supervision_policy().map(|policy| policy.mode),
                Some(expected)
            );
        }

        for invalid in [
            json!({"mode": "optional", "serverTimeMs": 1, "scheduleEndMs": 2}),
            json!({
                "mode": "on_failure",
                "restartLimit": {"kind": "attempts", "maxRestarts": 11},
                "serverTimeMs": 1,
                "scheduleEndMs": 2,
            }),
            json!({
                "mode": "on_failure",
                "restartLimit": {"kind": "future"},
                "serverTimeMs": 1,
                "scheduleEndMs": 2,
            }),
            json!({
                "mode": "on_failure",
                "restartLimit": {"kind": "schedule_end"},
                "serverTimeMs": 2,
                "scheduleEndMs": 2,
            }),
            json!({
                "mode": "on_failure",
                "restartLimit": {"kind": "schedule_end"},
                "serverTimeMs": 1,
                "scheduleEndMs": 2,
                "command": "replace",
            }),
        ] {
            let mut response = base.clone();
            response["supervision"] = invalid;
            let parsed =
                validate_response(&request, &serde_json::to_vec(&response).unwrap()).unwrap();
            assert_eq!(parsed.supervision_policy(), None);
        }
    }

    #[test]
    fn logging_decision_is_an_exact_closed_opt_in() {
        let request = signed_request();
        let base = json!({
            "ok": true,
            "domain": RUNTIME_BOOTSTRAP_RESPONSE_DOMAIN_V2,
            "applicationUid": "app-uid-1",
            "applicationId": "app-1",
            "policyDigest": "ab",
            "deploymentId": "dep-1",
            "jobId": request.job_id,
            "processorId": request.processor_id,
            "runtimeInstanceId": request.nonce,
            "slipwayUrl": "https://liskov.example"
        });
        for (logging, enabled) in [
            (None, false),
            (Some(json!({"enabled": false})), false),
            (Some(json!({"enabled": true})), true),
            (Some(json!({"enabled": true, "sink": "customer"})), false),
            (Some(json!(true)), false),
        ] {
            let mut response = base.clone();
            if let Some(logging) = logging {
                response["logging"] = logging;
            }
            let parsed =
                validate_response(&request, &serde_json::to_vec(&response).unwrap()).unwrap();
            assert_eq!(parsed.logging_enabled(), enabled);
        }
    }

    #[test]
    fn logging_outage_canary_never_enables_logging() {
        let request = signed_request();
        let mut response = json!({
            "ok": true,
            "domain": RUNTIME_BOOTSTRAP_RESPONSE_DOMAIN_V2,
            "applicationUid": "app-uid-1",
            "applicationId": "app-1",
            "policyDigest": "ab",
            "deploymentId": "dep-1",
            "jobId": request.job_id,
            "processorId": request.processor_id,
            "runtimeInstanceId": request.nonce,
            "slipwayUrl": "https://liskov.example",
            "loggingOutageCanary": true,
        });
        let parsed = validate_response(&request, &serde_json::to_vec(&response).unwrap()).unwrap();
        assert!(!parsed.logging_outage_canary_enabled());

        response["logging"] = json!({"enabled": true});
        let parsed = validate_response(&request, &serde_json::to_vec(&response).unwrap()).unwrap();
        assert!(parsed.logging_outage_canary_enabled());
    }

    #[test]
    fn provider_log_diagnostics_are_closed_and_expire_fail_closed() {
        let request = signed_request();
        let mut response = json!({
            "ok": true,
            "domain": RUNTIME_BOOTSTRAP_RESPONSE_DOMAIN_V2,
            "applicationUid": "app-uid-1",
            "applicationId": "app-1",
            "policyDigest": "sha256:policy",
            "deploymentId": "dep-1",
            "jobId": request.job_id,
            "processorId": request.processor_id,
            "runtimeInstanceId": request.nonce,
            "slipwayUrl": "https://liskov.example",
            "logging": {"enabled": true},
            "access": {
                "provider": {"kind": "tailscale"},
                "attachmentId": "att-1",
                "expectedTailnet": "example.com",
                "setupDeadlineMs": 60_000,
                "fence": 1,
                "artifact": {
                    "descriptorId": "descriptor-1",
                    "version": "1.98.10-liskov.1",
                    "url": "https://liskov.example/api/runtime-ssh/provider-clients/sha.tgz",
                    "sha256": "1".repeat(64),
                    "byteSize": 123,
                }
            },
            "diagnostics": {
                "providerLogs": {
                    "mode": "raw_tailscaled_stderr",
                    "expiresAtMs": 1_500_000,
                }
            }
        });
        let parsed = validate_response(&request, &serde_json::to_vec(&response).unwrap()).unwrap();
        assert_eq!(
            parsed.provider_log_mode(1_000_000),
            ProviderLogMode::RawTailscaledStderr
        );
        assert_eq!(
            parsed.provider_log_mode(1_500_000),
            ProviderLogMode::Disabled
        );

        response["diagnostics"]["providerLogs"]["expiresAtMs"] = json!(5_000_001);
        let parsed = validate_response(&request, &serde_json::to_vec(&response).unwrap()).unwrap();
        assert_eq!(
            parsed.provider_log_mode(1_000_000),
            ProviderLogMode::Disabled
        );

        response["diagnostics"]["providerLogs"] = json!({"mode": "sanitized"});
        let parsed = validate_response(&request, &serde_json::to_vec(&response).unwrap()).unwrap();
        assert_eq!(
            parsed.provider_log_mode(1_000_000),
            ProviderLogMode::Sanitized
        );

        response["diagnostics"]["providerLogs"] = json!({"mode": "future"});
        assert!(matches!(
            validate_response(&request, &serde_json::to_vec(&response).unwrap()),
            Err(ProtocolError::InvalidResponse)
        ));
    }
}
