//! Required, signed runtime-environment retrieval before customer startup.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use crate::bridge::{Bridge, BridgeError};
use crate::diagnostics::canonical_json_bytes;
use crate::http::{HttpClient, HttpError, UreqHttpClient};
use crate::protocol::RuntimeBootstrapResponse;

pub const RUNTIME_ENV_REQUEST_DOMAIN_V2: &str = "proof.liskov.runtime-env-request.v2";
pub const RUNTIME_ENV_RESPONSE_DOMAIN_V2: &str = "proof.liskov.runtime-env-response.v2";
pub const RUNTIME_ENV_REQUEST_TTL_MS: u64 = 60_000;

const MAX_RUNTIME_ENV_VALUES: usize = 128;
const PROTECTED_ENV_NAMES: &[&str] = &[
    "PROOF_SLIPWAY_BOOTSTRAP",
    "LISKOV_CARGO_SUPERVISION_CANARY_JSON",
    "LISKOV_RUNTIME_SSH_CREDENTIAL_V1",
];

#[derive(Debug, Error)]
pub enum RuntimeEnvError {
    #[error("runtime environment endpoint was invalid")]
    InvalidEndpoint,
    #[error("runtime environment randomness was unavailable")]
    Randomness,
    #[error("runtime environment clock was unavailable")]
    Clock,
    #[error("runtime environment timestamp overflowed")]
    TimestampOverflow,
    #[error("runtime environment signing failed")]
    Signing(#[source] BridgeError),
    #[error("runtime environment signature was invalid")]
    InvalidSignature,
    #[error("runtime environment request serialization failed")]
    Serialization(#[source] serde_json::Error),
    #[error("runtime environment transport failed")]
    Transport,
    #[error("runtime environment request was rejected")]
    Rejected,
    #[error("runtime environment response was invalid")]
    InvalidResponse,
    #[error("runtime environment response binding did not match the signed request")]
    ResponseBinding,
}

impl RuntimeEnvError {
    pub fn exit_status(&self) -> u8 {
        match self {
            Self::Transport => 75,
            _ => 70,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedRuntimeEnvRequest {
    domain: &'static str,
    application_uid: String,
    application_id: String,
    policy_digest: String,
    job_id: String,
    deployment_id: String,
    processor_id: String,
    nonce: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedRuntimeEnvRequest {
    domain: &'static str,
    application_uid: String,
    application_id: String,
    policy_digest: String,
    job_id: String,
    deployment_id: String,
    processor_id: String,
    nonce: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeEnvResponse {
    ok: bool,
    domain: String,
    request_id: String,
    application_uid: String,
    application_id: String,
    policy_digest: String,
    job_id: String,
    deployment_id: String,
    processor_id: String,
    revision: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
    refresh_after_ms: u64,
    values: BTreeMap<String, String>,
}

pub fn load_runtime_environment(
    bootstrap: &RuntimeBootstrapResponse,
    bridge: &dyn Bridge,
) -> Result<BTreeMap<String, String>, RuntimeEnvError> {
    if bootstrap
        .runtime_env
        .as_ref()
        .is_none_or(|config| !config.enabled)
    {
        return Ok(BTreeMap::new());
    }
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| RuntimeEnvError::Randomness)?;
    let issued_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuntimeEnvError::Clock)?
        .as_millis();
    let issued_at_ms = u64::try_from(issued_at_ms).map_err(|_| RuntimeEnvError::Clock)?;
    let http = UreqHttpClient::default();
    load_runtime_environment_with(bootstrap, bridge, &http, issued_at_ms, nonce)
}

fn load_runtime_environment_with(
    bootstrap: &RuntimeBootstrapResponse,
    bridge: &dyn Bridge,
    http: &dyn HttpClient,
    issued_at_ms: u64,
    nonce: [u8; 16],
) -> Result<BTreeMap<String, String>, RuntimeEnvError> {
    let Some(config) = bootstrap.runtime_env.as_ref() else {
        return Ok(BTreeMap::new());
    };
    if !config.enabled {
        return Ok(BTreeMap::new());
    }
    if config.url != bootstrap.slipway_url {
        return Err(RuntimeEnvError::ResponseBinding);
    }
    let endpoint = secure_endpoint(&config.url)?;
    let unsigned = UnsignedRuntimeEnvRequest {
        domain: RUNTIME_ENV_REQUEST_DOMAIN_V2,
        application_uid: bootstrap.application_uid.trim().to_owned(),
        application_id: bootstrap.application_id.trim().to_owned(),
        policy_digest: bootstrap.policy_digest.trim().to_ascii_lowercase(),
        job_id: bootstrap.job_id.trim().to_owned(),
        deployment_id: bootstrap.deployment_id.trim().to_owned(),
        processor_id: bootstrap.processor_id.trim().to_owned(),
        nonce: hex::encode(nonce),
        issued_at_ms,
        expires_at_ms: issued_at_ms
            .checked_add(RUNTIME_ENV_REQUEST_TTL_MS)
            .ok_or(RuntimeEnvError::TimestampOverflow)?,
    };
    if [
        unsigned.application_uid.as_str(),
        unsigned.application_id.as_str(),
        unsigned.policy_digest.as_str(),
        unsigned.job_id.as_str(),
        unsigned.deployment_id.as_str(),
        unsigned.processor_id.as_str(),
    ]
    .contains(&"")
    {
        return Err(RuntimeEnvError::ResponseBinding);
    }
    let message = canonical_json_bytes(
        &serde_json::to_value(&unsigned).map_err(RuntimeEnvError::Serialization)?,
    );
    let signature = sign(bridge, &message)?;
    let signed = SignedRuntimeEnvRequest {
        domain: unsigned.domain,
        application_uid: unsigned.application_uid.clone(),
        application_id: unsigned.application_id.clone(),
        policy_digest: unsigned.policy_digest.clone(),
        job_id: unsigned.job_id.clone(),
        deployment_id: unsigned.deployment_id.clone(),
        processor_id: unsigned.processor_id.clone(),
        nonce: unsigned.nonce.clone(),
        issued_at_ms: unsigned.issued_at_ms,
        expires_at_ms: unsigned.expires_at_ms,
        signature,
    };
    let body = serde_json::to_vec(&signed).map_err(RuntimeEnvError::Serialization)?;
    let response = http
        .post(endpoint.as_str(), &body)
        .map_err(|error| match error {
            HttpError::Transport => RuntimeEnvError::Transport,
            HttpError::ResponseTooLarge => RuntimeEnvError::InvalidResponse,
        })?;
    if !(200..300).contains(&response.status) {
        return Err(RuntimeEnvError::Rejected);
    }
    validate_response(&unsigned, &response.body)
}

fn secure_endpoint(raw: &str) -> Result<url::Url, RuntimeEnvError> {
    let base = url::Url::parse(raw).map_err(|_| RuntimeEnvError::InvalidEndpoint)?;
    if base.scheme() != "https"
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return Err(RuntimeEnvError::InvalidEndpoint);
    }
    base.join("/api/jobs/runtime-env")
        .map_err(|_| RuntimeEnvError::InvalidEndpoint)
}

fn sign(bridge: &dyn Bridge, message: &[u8]) -> Result<String, RuntimeEnvError> {
    let result = bridge
        .call(
            "signer_sign",
            json!([{
                "curve": "ed25519",
                "bytes": hex::encode(message),
            }]),
        )
        .map_err(RuntimeEnvError::Signing)?;
    let signature = result
        .get("bytes")
        .and_then(Value::as_str)
        .and_then(normalize_signature)
        .ok_or(RuntimeEnvError::InvalidSignature)?;
    Ok(format!("0x{signature}"))
}

fn normalize_signature(value: &str) -> Option<String> {
    let value = value
        .strip_prefix("0x")
        .unwrap_or(value)
        .to_ascii_lowercase();
    (value.len() == 128 && value.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(value)
}

fn validate_response(
    request: &UnsignedRuntimeEnvRequest,
    body: &[u8],
) -> Result<BTreeMap<String, String>, RuntimeEnvError> {
    let response: RuntimeEnvResponse =
        serde_json::from_slice(body).map_err(|_| RuntimeEnvError::InvalidResponse)?;
    if !response.ok
        || response.domain != RUNTIME_ENV_RESPONSE_DOMAIN_V2
        || response.request_id.is_empty()
        || response.revision.is_empty()
        || response.expires_at_ms <= response.issued_at_ms
        || response.refresh_after_ms < response.issued_at_ms
        || response.refresh_after_ms > response.expires_at_ms
    {
        return Err(RuntimeEnvError::InvalidResponse);
    }
    if response.application_uid != request.application_uid
        || response.application_id != request.application_id
        || response.policy_digest != request.policy_digest
        || response.job_id != request.job_id
        || response.deployment_id != request.deployment_id
        || response.processor_id != request.processor_id
    {
        return Err(RuntimeEnvError::ResponseBinding);
    }
    if response.values.len() > MAX_RUNTIME_ENV_VALUES
        || response.values.iter().any(|(name, value)| {
            !valid_env_name(name)
                || PROTECTED_ENV_NAMES.contains(&name.as_str())
                || value.as_bytes().contains(&0)
        })
    {
        return Err(RuntimeEnvError::InvalidResponse);
    }
    Ok(response.values)
}

fn valid_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::http::{HttpError, HttpResponse};
    use crate::protocol::{RuntimeBootstrapResponse, RuntimeEnvBootstrap};

    #[derive(Default)]
    struct FakeBridge {
        calls: Mutex<Vec<(String, Value)>>,
    }

    impl Bridge for FakeBridge {
        fn call(&self, method: &str, params: Value) -> Result<Value, BridgeError> {
            self.calls.lock().unwrap().push((method.into(), params));
            Ok(json!({"bytes": "ab".repeat(64)}))
        }
    }

    struct FakeHttp {
        response: Mutex<Option<HttpResponse>>,
        calls: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl FakeHttp {
        fn new(response: HttpResponse) -> Self {
            Self {
                response: Mutex::new(Some(response)),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl HttpClient for FakeHttp {
        fn post(&self, url: &str, body: &[u8]) -> Result<HttpResponse, HttpError> {
            self.calls.lock().unwrap().push((url.into(), body.to_vec()));
            Ok(self.response.lock().unwrap().take().unwrap())
        }
    }

    fn bootstrap(enabled: bool) -> RuntimeBootstrapResponse {
        RuntimeBootstrapResponse {
            ok: true,
            domain: "proof.liskov.runtime-bootstrap-response.v2".into(),
            application_uid: "app-uid".into(),
            application_id: "app".into(),
            policy_digest: "AA".into(),
            deployment_id: "deployment".into(),
            job_id: "job".into(),
            processor_id: "processor".into(),
            runtime_instance_id: "instance".into(),
            slipway_url: "https://liskov.example".into(),
            runtime_env: Some(RuntimeEnvBootstrap {
                enabled,
                url: "https://liskov.example".into(),
            }),
            supervision: None,
            logging: None,
            logging_outage_canary: false,
            diagnostics: None,
            access: None,
        }
    }

    fn response(values: Value) -> HttpResponse {
        HttpResponse {
            status: 200,
            body: serde_json::to_vec(&json!({
                "ok": true,
                "domain": RUNTIME_ENV_RESPONSE_DOMAIN_V2,
                "requestId": "request",
                "applicationUid": "app-uid",
                "applicationId": "app",
                "policyDigest": "aa",
                "jobId": "job",
                "deploymentId": "deployment",
                "processorId": "processor",
                "revision": "revision",
                "issuedAtMs": 1_001,
                "expiresAtMs": 61_001,
                "refreshAfterMs": 31_001,
                "values": values,
            }))
            .unwrap(),
        }
    }

    #[test]
    fn disabled_runtime_environment_performs_no_bridge_or_http_work() {
        let bridge = FakeBridge::default();
        let http = FakeHttp::new(response(json!({})));
        let values =
            load_runtime_environment_with(&bootstrap(false), &bridge, &http, 1_000, [7; 16])
                .unwrap();
        assert!(values.is_empty());
        assert!(bridge.calls.lock().unwrap().is_empty());
        assert!(http.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn signs_v2_request_and_returns_only_bound_valid_values() {
        let bridge = FakeBridge::default();
        let http = FakeHttp::new(response(json!({
            "LISKOV_HELLO_CANARY_FAIL_ONCE_FILE": "/tmp/once",
            "MODE": "safe"
        })));
        let values =
            load_runtime_environment_with(&bootstrap(true), &bridge, &http, 1_000, [7; 16])
                .unwrap();
        assert_eq!(values["MODE"], "safe");
        assert_eq!(values["LISKOV_HELLO_CANARY_FAIL_ONCE_FILE"], "/tmp/once");

        let calls = http.calls.lock().unwrap();
        assert_eq!(calls[0].0, "https://liskov.example/api/jobs/runtime-env");
        let request: Value = serde_json::from_slice(&calls[0].1).unwrap();
        assert_eq!(request["domain"], RUNTIME_ENV_REQUEST_DOMAIN_V2);
        assert_eq!(request["applicationUid"], "app-uid");
        assert_eq!(request["policyDigest"], "aa");
        assert_eq!(request["nonce"], "07".repeat(16));
        assert_eq!(request["signature"], format!("0x{}", "ab".repeat(64)));

        let signed_message = &bridge.calls.lock().unwrap()[0].1[0]["bytes"];
        assert_eq!(
            signed_message,
            &json!(hex::encode(
                "{\"applicationId\":\"app\",\"applicationUid\":\"app-uid\",\"deploymentId\":\"deployment\",\"domain\":\"proof.liskov.runtime-env-request.v2\",\"expiresAtMs\":61000,\"issuedAtMs\":1000,\"jobId\":\"job\",\"nonce\":\"07070707070707070707070707070707\",\"policyDigest\":\"aa\",\"processorId\":\"processor\"}"
            ))
        );
    }

    #[test]
    fn rejects_cross_binding_protected_names_and_endpoint_substitution() {
        let bridge = FakeBridge::default();
        let mut cross: Value = serde_json::from_slice(&response(json!({})).body).unwrap();
        cross["deploymentId"] = json!("other");
        let cross_binding = FakeHttp::new(HttpResponse {
            status: 200,
            body: serde_json::to_vec(&cross).unwrap(),
        });
        assert!(matches!(
            load_runtime_environment_with(
                &bootstrap(true),
                &bridge,
                &cross_binding,
                1_000,
                [7; 16]
            ),
            Err(RuntimeEnvError::ResponseBinding)
        ));

        let protected = FakeHttp::new(response(json!({
            "LISKOV_RUNTIME_SSH_CREDENTIAL_V1": "secret"
        })));
        assert!(matches!(
            load_runtime_environment_with(&bootstrap(true), &bridge, &protected, 1_000, [7; 16]),
            Err(RuntimeEnvError::InvalidResponse)
        ));

        let mut substituted = bootstrap(true);
        substituted.runtime_env.as_mut().unwrap().url = "https://other.example".into();
        assert!(matches!(
            load_runtime_environment_with(
                &substituted,
                &bridge,
                &FakeHttp::new(response(json!({}))),
                1_000,
                [7; 16]
            ),
            Err(RuntimeEnvError::ResponseBinding)
        ));
    }
}
