use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use url::Url;

use crate::bridge::BridgeError;
use crate::contact::ContactError;
use crate::http::{HttpClient, HttpError};
use crate::protocol::ProtocolError;

pub const PRECONTACT_DIAGNOSTIC_DOMAIN: &str = "proof.liskov.runtime-precontact-diagnostic.v1";
pub const PRECONTACT_HTTP_TIMEOUT: Duration = Duration::from_secs(2);
pub const MAX_PRECONTACT_RESPONSE_BYTES: usize = 8 * 1024;
const MAX_BOOTSTRAP_BYTES: usize = 64 * 1024;
const MAX_TOKEN_BYTES: usize = 48;
const MAX_BINDING_BYTES: usize = 1_024;
const MAX_VALIDITY_MS: i64 = 45 * 60_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactBootstrap {
    v: u8,
    u: String,
    uid: String,
    a: String,
    p: String,
    d: String,
    x: CompactExtensions,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactExtensions {
    #[serde(default)]
    t: Option<String>,
    #[serde(default)]
    h: Option<Value>,
    pc: CompactPrecontact,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactPrecontact {
    t: String,
    j: String,
    d: String,
    c: String,
    iat: i64,
    exp: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PrecontactReport<'a> {
    domain: &'static str,
    token: &'a str,
    application_uid: &'a str,
    application_id: &'a str,
    policy_digest: &'a str,
    job_id: &'a str,
    deployment_id: &'a str,
    child_session_id: &'a str,
    issued_at_ms: i64,
    expires_at_ms: i64,
    stage: &'static str,
    status: &'static str,
    sequence: u8,
    method: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_code: Option<&'static str>,
    attempt_count: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    rpc_code: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrecontactResponse {
    ok: bool,
    domain: String,
    accepted: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PrecontactError {
    #[error("runtime pre-contact bootstrap was unavailable")]
    Missing,
    #[error("runtime pre-contact bootstrap was too large")]
    TooLarge,
    #[error("runtime pre-contact bootstrap was invalid")]
    Invalid,
    #[error("runtime pre-contact bootstrap was outside its validity window")]
    OutsideWindow,
    #[error("runtime pre-contact transport failed")]
    Transport,
    #[error("runtime pre-contact response binding failed")]
    ResponseBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagnosticFailure {
    pub stage: &'static str,
    pub method: &'static str,
    pub code: &'static str,
    pub rpc_code: Option<i32>,
}

impl DiagnosticFailure {
    pub fn bridge(stage: &'static str, method: &'static str, error: &BridgeError) -> Self {
        Self {
            stage,
            method,
            code: error.failure_code(),
            rpc_code: error.rpc_code(),
        }
    }

    pub fn result_shape(stage: &'static str, method: &'static str) -> Self {
        Self {
            stage,
            method,
            code: "bridge_result_shape",
            rpc_code: None,
        }
    }

    pub fn from_contact(error: &ContactError) -> Self {
        match error {
            ContactError::Protocol(ProtocolError::BridgeSetup(error)) => {
                Self::bridge("bridge.discovery", "bridge_discovery", error)
            }
            ContactError::Protocol(ProtocolError::DeploymentIdentityBridge(error)) => {
                Self::bridge("bridge.identity", "deployment_id", error)
            }
            ContactError::Protocol(ProtocolError::InvalidDeploymentIdentity) => {
                Self::result_shape("bridge.identity", "deployment_id")
            }
            ContactError::Protocol(ProtocolError::PublicKeyBridge(error)) => {
                Self::bridge("bridge.identity", "deployment_publicKeys", error)
            }
            ContactError::Protocol(ProtocolError::InvalidPublicKey) => {
                Self::result_shape("bridge.identity", "deployment_publicKeys")
            }
            ContactError::Protocol(ProtocolError::AssignedProcessorsBridge(error)) => {
                Self::bridge("bridge.identity", "deployment_assignedProcessors", error)
            }
            ContactError::Protocol(ProtocolError::ProcessorMatchCount) => Self {
                stage: "bridge.identity",
                method: "deployment_assignedProcessors",
                code: "bridge_identity_mismatch",
                rpc_code: None,
            },
            ContactError::Protocol(ProtocolError::SignerBridge(error)) => {
                Self::bridge("bridge.signing", "signer_sign", error)
            }
            ContactError::Protocol(ProtocolError::InvalidSignature) => Self {
                stage: "bridge.signing",
                method: "signer_sign",
                code: "bridge_signing",
                rpc_code: None,
            },
            ContactError::Protocol(
                ProtocolError::TimestampOverflow | ProtocolError::Serialization(_),
            ) => Self {
                stage: "runtime-bootstrap.http",
                method: "runtime_bootstrap",
                code: "runtime_request",
                rpc_code: None,
            },
            ContactError::Randomness => Self {
                stage: "runtime-bootstrap.http",
                method: "runtime_bootstrap",
                code: "runtime_randomness",
                rpc_code: None,
            },
            ContactError::Clock => Self {
                stage: "runtime-bootstrap.http",
                method: "runtime_bootstrap",
                code: "runtime_clock",
                rpc_code: None,
            },
            ContactError::RetryExhausted => Self {
                stage: "runtime-bootstrap.http",
                method: "runtime_bootstrap",
                code: "http_transport",
                rpc_code: None,
            },
            ContactError::Configuration(_)
            | ContactError::PermanentServerRejection
            | ContactError::Protocol(
                ProtocolError::InvalidResponse | ProtocolError::ResponseBinding,
            ) => Self {
                stage: "runtime-bootstrap.http",
                method: "runtime_bootstrap",
                code: "http_response_binding",
                rpc_code: None,
            },
        }
    }
}

#[derive(Debug)]
pub struct PrecontactReporter {
    endpoint: String,
    token: String,
    application_uid: String,
    application_id: String,
    policy_digest: String,
    job_id: String,
    deployment_id: String,
    child_session_id: String,
    issued_at_ms: i64,
    expires_at_ms: i64,
    started: AtomicBool,
    terminal: AtomicBool,
}

impl PrecontactReporter {
    pub fn parse(raw: &str, now_ms: i64) -> Result<Self, PrecontactError> {
        if raw.is_empty() {
            return Err(PrecontactError::Missing);
        }
        if raw.len() > MAX_BOOTSTRAP_BYTES {
            return Err(PrecontactError::TooLarge);
        }
        let bootstrap: CompactBootstrap =
            serde_json::from_str(raw).map_err(|_| PrecontactError::Invalid)?;
        let _compatibility_fields = (&bootstrap.x.t, &bootstrap.x.h);
        let pc = bootstrap.x.pc;
        let bindings = [
            bootstrap.u.as_str(),
            bootstrap.uid.as_str(),
            bootstrap.a.as_str(),
            bootstrap.p.as_str(),
            bootstrap.d.as_str(),
            pc.j.as_str(),
            pc.d.as_str(),
            pc.c.as_str(),
        ];
        if bootstrap.v != 2
            || bindings
                .iter()
                .any(|value| value.is_empty() || value.len() > MAX_BINDING_BYTES)
            || bootstrap.p != bootstrap.p.to_ascii_lowercase()
            || bootstrap.d != pc.d
            || pc.t.len() != MAX_TOKEN_BYTES
            || pc.iat <= 0
            || pc.exp <= pc.iat
            || pc.exp - pc.iat > MAX_VALIDITY_MS
        {
            return Err(PrecontactError::Invalid);
        }
        let encoded_tag = pc.t.strip_prefix("lrp1_").ok_or(PrecontactError::Invalid)?;
        let tag = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded_tag)
            .map_err(|_| PrecontactError::Invalid)?;
        if tag.len() != 32
            || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&tag) != encoded_tag
        {
            return Err(PrecontactError::Invalid);
        }
        if now_ms < pc.iat || now_ms > pc.exp {
            return Err(PrecontactError::OutsideWindow);
        }
        let origin = Url::parse(&bootstrap.u).map_err(|_| PrecontactError::Invalid)?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
        {
            return Err(PrecontactError::Invalid);
        }
        let endpoint = origin
            .join("/api/jobs/runtime-diagnostics")
            .map_err(|_| PrecontactError::Invalid)?
            .to_string();
        Ok(Self {
            endpoint,
            token: pc.t,
            application_uid: bootstrap.uid,
            application_id: bootstrap.a,
            policy_digest: bootstrap.p,
            job_id: pc.j,
            deployment_id: pc.d,
            child_session_id: pc.c,
            issued_at_ms: pc.iat,
            expires_at_ms: pc.exp,
            started: AtomicBool::new(false),
            terminal: AtomicBool::new(false),
        })
    }

    pub fn report_started(&self, http: &dyn HttpClient) -> Result<(), PrecontactError> {
        if self.started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.send(
            http,
            "bridge.discovery",
            "started",
            0,
            "bridge_discovery",
            None,
            None,
        )
    }

    pub fn report_failed(
        &self,
        http: &dyn HttpClient,
        failure: DiagnosticFailure,
    ) -> Result<(), PrecontactError> {
        if self.terminal.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.send(
            http,
            failure.stage,
            "failed",
            1,
            failure.method,
            Some(failure.code),
            failure.rpc_code,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn send(
        &self,
        http: &dyn HttpClient,
        stage: &'static str,
        status: &'static str,
        sequence: u8,
        method: &'static str,
        failure_code: Option<&'static str>,
        rpc_code: Option<i32>,
    ) -> Result<(), PrecontactError> {
        let report = PrecontactReport {
            domain: PRECONTACT_DIAGNOSTIC_DOMAIN,
            token: &self.token,
            application_uid: &self.application_uid,
            application_id: &self.application_id,
            policy_digest: &self.policy_digest,
            job_id: &self.job_id,
            deployment_id: &self.deployment_id,
            child_session_id: &self.child_session_id,
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self.expires_at_ms,
            stage,
            status,
            sequence,
            method,
            failure_code,
            attempt_count: 1,
            rpc_code,
        };
        let body = serde_json::to_vec(&report).map_err(|_| PrecontactError::Invalid)?;
        let response = http
            .post(&self.endpoint, &body)
            .map_err(|error| match error {
                HttpError::Transport | HttpError::ResponseTooLarge => PrecontactError::Transport,
            })?;
        if !(200..300).contains(&response.status) {
            return Err(PrecontactError::ResponseBinding);
        }
        let response: PrecontactResponse =
            serde_json::from_slice(&response.body).map_err(|_| PrecontactError::ResponseBinding)?;
        if !response.ok || !response.accepted || response.domain != PRECONTACT_DIAGNOSTIC_DOMAIN {
            return Err(PrecontactError::ResponseBinding);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use serde_json::json;

    use super::*;
    use crate::http::HttpResponse;

    struct RecordingHttp {
        calls: Mutex<Vec<Value>>,
        response: Result<HttpResponse, HttpError>,
    }

    impl RecordingHttp {
        fn accepting() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                response: Ok(HttpResponse {
                    status: 200,
                    body: serde_json::to_vec(&json!({
                        "ok": true,
                        "domain": PRECONTACT_DIAGNOSTIC_DOMAIN,
                        "accepted": true,
                    }))
                    .unwrap(),
                }),
            }
        }
    }

    impl HttpClient for RecordingHttp {
        fn post(&self, _: &str, body: &[u8]) -> Result<HttpResponse, HttpError> {
            self.calls
                .lock()
                .unwrap()
                .push(serde_json::from_slice(body).unwrap());
            match &self.response {
                Ok(response) => Ok(response.clone()),
                Err(HttpError::Transport) => Err(HttpError::Transport),
                Err(HttpError::ResponseTooLarge) => Err(HttpError::ResponseTooLarge),
            }
        }
    }

    fn bootstrap() -> String {
        let token = format!(
            "lrp1_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32])
        );
        json!({
            "v": 2,
            "u": "https://liskov.example",
            "uid": "app-uid-1",
            "a": "app-1",
            "p": "sha256:ab",
            "d": "deployment-1",
            "x": {
                "pc": {
                    "t": token,
                    "j": "job-1",
                    "d": "deployment-1",
                    "c": "child-1",
                    "iat": 1_000,
                    "exp": 61_000
                }
            }
        })
        .to_string()
    }

    #[test]
    fn parses_only_the_bounded_compact_v2_binding() {
        let reporter = PrecontactReporter::parse(&bootstrap(), 2_000).unwrap();
        assert_eq!(
            reporter.endpoint,
            "https://liskov.example/api/jobs/runtime-diagnostics"
        );
        for now_ms in [999, 61_001] {
            assert_eq!(
                PrecontactReporter::parse(&bootstrap(), now_ms).unwrap_err(),
                PrecontactError::OutsideWindow
            );
        }
        let mut unknown: Value = serde_json::from_str(&bootstrap()).unwrap();
        unknown["message"] = json!("arbitrary");
        assert_eq!(
            PrecontactReporter::parse(&unknown.to_string(), 2_000).unwrap_err(),
            PrecontactError::Invalid
        );
        assert_eq!(
            PrecontactReporter::parse("", 2_000).unwrap_err(),
            PrecontactError::Missing
        );
        let mut mismatched: Value = serde_json::from_str(&bootstrap()).unwrap();
        mismatched["d"] = json!("wrong-deployment");
        assert_eq!(
            PrecontactReporter::parse(&mismatched.to_string(), 2_000).unwrap_err(),
            PrecontactError::Invalid
        );
        for invalid_token in [
            "lrp1_not-base64!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
            "lrp1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "lrp1_AAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAA",
        ] {
            let mut malformed: Value = serde_json::from_str(&bootstrap()).unwrap();
            malformed["x"]["pc"]["t"] = json!(invalid_token);
            assert_eq!(
                PrecontactReporter::parse(&malformed.to_string(), 2_000).unwrap_err(),
                PrecontactError::Invalid
            );
        }
    }

    #[test]
    fn sends_one_started_and_at_most_one_bounded_terminal_report() {
        let reporter = PrecontactReporter::parse(&bootstrap(), 2_000).unwrap();
        let http = RecordingHttp::accepting();
        reporter.report_started(&http).unwrap();
        reporter.report_started(&http).unwrap();
        reporter
            .report_failed(
                &http,
                DiagnosticFailure {
                    stage: "bridge.identity",
                    method: "deployment_id",
                    code: "bridge_rpc_error",
                    rpc_code: Some(-32_000),
                },
            )
            .unwrap();
        reporter
            .report_failed(
                &http,
                DiagnosticFailure::result_shape("bridge.identity", "deployment_id"),
            )
            .unwrap();
        let calls = http.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0]["status"], "started");
        assert_eq!(calls[0]["sequence"], 0);
        assert!(calls[0].get("failureCode").is_none());
        assert_eq!(calls[1]["status"], "failed");
        assert_eq!(calls[1]["sequence"], 1);
        assert_eq!(calls[1]["failureCode"], "bridge_rpc_error");
        assert_eq!(calls[1]["rpcCode"], -32_000);
        assert!(calls.iter().all(|call| call.get("message").is_none()));
    }

    #[test]
    fn reporter_never_retries_a_failed_http_send() {
        let reporter = PrecontactReporter::parse(&bootstrap(), 2_000).unwrap();
        let http = RecordingHttp {
            calls: Mutex::new(Vec::new()),
            response: Err(HttpError::Transport),
        };
        assert_eq!(
            reporter.report_started(&http).unwrap_err(),
            PrecontactError::Transport
        );
        reporter.report_started(&http).unwrap();
        assert_eq!(http.calls.lock().unwrap().len(), 1);
    }
}
