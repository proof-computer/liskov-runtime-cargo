use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use thiserror::Error;
use url::Url;

use crate::bridge::{Bridge, UnixBridge};
use crate::http::{HttpClient, HttpError, HttpResponse, UreqHttpClient};
use crate::protocol::{
    ProtocolError, RuntimeBootstrapResponse, build_unsigned_request, discover_runtime_identity,
    sign_request, validate_response,
};

/// The fleet's control-plane endpoint.
///
/// `runtime.liskov.proof.computer` is a fleet-only name for the same
/// `liskov-api` application the console's `api.` name resolves to
/// (`BKLG-20260829-t4rp`). It is deliberately not the operator console
/// hostname: processors on residential broadband and browsers need different
/// rate limits, protection rules and failure domains, and a deployed helper is
/// the least reachable client there is.
pub const DEFAULT_CORE_URL: &str = "https://runtime.liskov.proof.computer";

/// Environment override for [`DEFAULT_CORE_URL`], delivered by the on-chain
/// `acurast.setEnvironments` handoff.
pub const CORE_URL_ENV: &str = "LISKOV_CORE_URL";

/// The Liskov core base URL, selected exactly as the CLI documents it:
/// `--core-url`, then `LISKOV_CORE_URL`, then [`DEFAULT_CORE_URL`].
///
/// `--core-url` outranks the environment on purpose: a runtime-image entrypoint
/// passes it explicitly, and a stale entrypoint must not be silently overridden
/// by a handoff push.
pub fn resolve_core_url<F>(cli_core_url: Option<String>, env_lookup: F) -> String
where
    F: Fn(&str) -> Option<String>,
{
    cli_core_url
        .or_else(|| env_lookup(CORE_URL_ENV))
        .unwrap_or_else(|| DEFAULT_CORE_URL.to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCategory {
    Configuration = 2,
    Protocol = 70,
    TemporaryFailure = 75,
}

#[derive(Debug, Error)]
pub enum ContactError {
    #[error("invalid configuration: {0}")]
    Configuration(&'static str),
    #[error("runtime contact protocol failed: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("runtime randomness was unavailable")]
    Randomness,
    #[error("runtime clock was unavailable")]
    Clock,
    #[error("runtime contact was permanently rejected")]
    PermanentServerRejection,
    #[error("runtime contact retry budget was exhausted")]
    RetryExhausted,
}

impl ContactError {
    pub fn exit_category(&self) -> ExitCategory {
        match self {
            Self::Configuration(_) => ExitCategory::Configuration,
            Self::RetryExhausted => ExitCategory::TemporaryFailure,
            Self::Protocol(_) | Self::Randomness | Self::Clock | Self::PermanentServerRejection => {
                ExitCategory::Protocol
            }
        }
    }

    /// Canary-only stage code used when stderr is unavailable in the Acurast
    /// Shell runtime. The public/default exit categories remain unchanged.
    pub fn diagnostic_exit_code(&self) -> u8 {
        match self {
            Self::Configuration(_) => 2,
            Self::Protocol(ProtocolError::BridgeSetup(_)) => 80,
            Self::Protocol(ProtocolError::DeploymentIdentityBridge(_)) => 81,
            Self::Protocol(ProtocolError::InvalidDeploymentIdentity) => 82,
            Self::Protocol(ProtocolError::PublicKeyBridge(_)) => 83,
            Self::Protocol(ProtocolError::InvalidPublicKey) => 84,
            Self::Protocol(ProtocolError::AssignedProcessorsBridge(_)) => 85,
            Self::Protocol(ProtocolError::ProcessorMatchCount) => 86,
            Self::Protocol(ProtocolError::SignerBridge(_)) => 87,
            Self::Protocol(ProtocolError::InvalidSignature) => 88,
            Self::Protocol(ProtocolError::TimestampOverflow | ProtocolError::Serialization(_)) => {
                89
            }
            Self::PermanentServerRejection => 90,
            Self::Protocol(ProtocolError::InvalidResponse) => 91,
            Self::Protocol(ProtocolError::ResponseBinding) => 92,
            Self::Randomness => 93,
            Self::Clock => 94,
            Self::RetryExhausted => 95,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    pub initial_delay: Duration,
    pub interval: Duration,
    pub max_elapsed: Duration,
    pub max_attempts: usize,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(250),
            interval: Duration::from_secs(2),
            max_elapsed: Duration::from_secs(60),
            max_attempts: 30,
        }
    }
}

pub trait ContactRuntime {
    fn unix_time_ms(&self) -> Result<u64, ContactError>;
    fn elapsed(&self) -> Duration;
    fn fill_random(&self, bytes: &mut [u8]) -> Result<(), ContactError>;
    fn sleep(&self, duration: Duration);
}

#[derive(Debug)]
pub struct SystemRuntime {
    started: Instant,
}

impl Default for SystemRuntime {
    fn default() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl ContactRuntime for SystemRuntime {
    fn unix_time_ms(&self) -> Result<u64, ContactError> {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ContactError::Clock)?
            .as_millis();
        u64::try_from(millis).map_err(|_| ContactError::Clock)
    }

    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    fn fill_random(&self, bytes: &mut [u8]) -> Result<(), ContactError> {
        getrandom::fill(bytes).map_err(|_| ContactError::Randomness)
    }

    fn sleep(&self, duration: Duration) {
        thread::sleep(duration);
    }
}

pub fn validate_core_url(raw: &str) -> Result<Url, ContactError> {
    let url = Url::parse(raw).map_err(|_| ContactError::Configuration("invalid core URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ContactError::Configuration(
            "core URL must be HTTPS without user information, query, or fragment",
        ));
    }
    Ok(url)
}

pub fn establish_runtime_contact(
    core_url: &str,
    bridge_socket: &str,
) -> Result<RuntimeBootstrapResponse, ContactError> {
    let bridge = UnixBridge::new(bridge_socket)
        .map_err(ProtocolError::BridgeSetup)
        .map_err(ContactError::from)?;
    let http = UreqHttpClient::default();
    let runtime = SystemRuntime::default();
    establish_runtime_contact_with(core_url, &bridge, &http, &runtime, RetryPolicy::default())
}

pub fn establish_runtime_contact_with(
    core_url: &str,
    bridge: &dyn Bridge,
    http: &dyn HttpClient,
    runtime: &dyn ContactRuntime,
    retry: RetryPolicy,
) -> Result<RuntimeBootstrapResponse, ContactError> {
    let endpoint = validate_core_url(core_url)?
        .join("/api/jobs/runtime-bootstrap")
        .map_err(|_| ContactError::Configuration("invalid core URL"))?;
    let identity = discover_runtime_identity_with_retry(bridge, runtime, retry)?;
    let mut nonce = [0_u8; 16];
    runtime.fill_random(&mut nonce)?;
    let unsigned = build_unsigned_request(identity, hex::encode(nonce), runtime.unix_time_ms()?)?;
    let signed = sign_request(bridge, unsigned)?;
    let body = serde_json::to_vec(&signed).map_err(ProtocolError::from)?;

    let mut attempt = 0_usize;
    let mut next_delay = retry.initial_delay;
    loop {
        attempt += 1;
        match attempt_contact(http, endpoint.as_str(), &body, &signed) {
            Ok(response) => return Ok(response),
            Err(AttemptError::Permanent) => {
                return Err(ContactError::PermanentServerRejection);
            }
            Err(AttemptError::Protocol(error)) => return Err(ContactError::Protocol(error)),
            Err(AttemptError::Retryable) => {
                if attempt >= retry.max_attempts
                    || runtime
                        .elapsed()
                        .checked_add(next_delay)
                        .is_none_or(|elapsed| elapsed > retry.max_elapsed)
                {
                    return Err(ContactError::RetryExhausted);
                }
                eprintln!(
                    "liskov-runtime-contact: runtime contact unavailable; retrying ({attempt}/{})",
                    retry.max_attempts
                );
                runtime.sleep(next_delay);
                next_delay = retry.interval;
            }
        }
    }
}

fn discover_runtime_identity_with_retry(
    bridge: &dyn Bridge,
    runtime: &dyn ContactRuntime,
    retry: RetryPolicy,
) -> Result<crate::protocol::RuntimeIdentity, ContactError> {
    let mut attempt = 0_usize;
    let mut next_delay = retry.initial_delay;
    loop {
        attempt += 1;
        match discover_runtime_identity(bridge) {
            Ok(identity) => return Ok(identity),
            Err(error) if identity_error_is_retryable(&error) => {
                if attempt >= retry.max_attempts
                    || runtime
                        .elapsed()
                        .checked_add(next_delay)
                        .is_none_or(|elapsed| elapsed > retry.max_elapsed)
                {
                    return Err(ContactError::Protocol(error));
                }
                eprintln!(
                    "liskov-runtime-contact: runtime identity unavailable; retrying ({attempt}/{})",
                    retry.max_attempts
                );
                runtime.sleep(next_delay);
                next_delay = retry.interval;
            }
            Err(error) => return Err(ContactError::Protocol(error)),
        }
    }
}

fn identity_error_is_retryable(error: &ProtocolError) -> bool {
    matches!(
        error,
        ProtocolError::DeploymentIdentityBridge(_)
            | ProtocolError::InvalidDeploymentIdentity
            | ProtocolError::PublicKeyBridge(_)
            | ProtocolError::InvalidPublicKey
            | ProtocolError::AssignedProcessorsBridge(_)
            | ProtocolError::ProcessorMatchCount
    )
}

enum AttemptError {
    Retryable,
    Permanent,
    Protocol(ProtocolError),
}

fn attempt_contact(
    http: &dyn HttpClient,
    endpoint: &str,
    body: &[u8],
    request: &crate::protocol::SignedRuntimeBootstrapRequest,
) -> Result<RuntimeBootstrapResponse, AttemptError> {
    let response = match http.post(endpoint, body) {
        Ok(response) => response,
        Err(HttpError::Transport) => return Err(AttemptError::Retryable),
        Err(HttpError::ResponseTooLarge) => {
            return Err(AttemptError::Protocol(ProtocolError::InvalidResponse));
        }
    };
    if (200..300).contains(&response.status) {
        return validate_response(request, &response.body).map_err(AttemptError::Protocol);
    }
    if response_is_retryable(&response) {
        Err(AttemptError::Retryable)
    } else {
        Err(AttemptError::Permanent)
    }
}

#[derive(Deserialize)]
struct ServerErrorEnvelope {
    #[serde(default, alias = "code")]
    error: Option<String>,
    #[serde(default)]
    retryable: Option<bool>,
}

fn response_is_retryable(response: &HttpResponse) -> bool {
    let envelope = serde_json::from_slice::<ServerErrorEnvelope>(&response.body).ok();
    if envelope.as_ref().and_then(|body| body.retryable) == Some(true) {
        return true;
    }
    if envelope.as_ref().and_then(|body| body.retryable) == Some(false) {
        return false;
    }
    if envelope
        .as_ref()
        .and_then(|body| body.error.as_deref())
        .is_some_and(|code| code.ends_with("_not_found"))
    {
        return true;
    }
    matches!(
        response.status,
        404 | 409 | 425 | 429 | 500 | 502 | 503 | 504
    )
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use serde_json::{Value, json};

    use super::*;
    use crate::bridge::BridgeError;

    #[test]
    fn the_compiled_in_default_is_the_fleet_hostname_not_the_console() {
        // BKLG-20260829-t4rp: the console hostname is an operator-facing name
        // that `84f5` moves to a different origin. A deployed helper cannot be
        // re-pointed cheaply, so its compiled-in default must name the
        // fleet-only hostname.
        let url = Url::parse(DEFAULT_CORE_URL).expect("the default must be a valid URL");
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("runtime.liskov.proof.computer"));
        assert_eq!(url.path(), "/");
        assert!(url.query().is_none() && url.fragment().is_none());
        assert_eq!(DEFAULT_CORE_URL, "https://runtime.liskov.proof.computer");
    }

    #[test]
    fn core_url_precedence_is_cli_then_environment_then_default() {
        let env =
            |name: &str| (name == CORE_URL_ENV).then(|| "https://from-env.example".to_owned());
        assert_eq!(
            resolve_core_url(Some("https://from-cli.example".to_owned()), env),
            "https://from-cli.example"
        );
        assert_eq!(resolve_core_url(None, env), "https://from-env.example");
        assert_eq!(resolve_core_url(None, |_| None), DEFAULT_CORE_URL);
    }

    #[test]
    fn no_environment_name_other_than_liskov_core_url_moves_the_core_url() {
        assert_eq!(
            resolve_core_url(None, |name| (name != CORE_URL_ENV)
                .then(|| "https://wrong.example".to_owned())),
            DEFAULT_CORE_URL
        );
    }

    struct FakeBridge {
        replies: Mutex<VecDeque<Value>>,
        calls: Mutex<Vec<(String, Value)>>,
    }

    impl FakeBridge {
        fn successful() -> Self {
            Self {
                replies: Mutex::new(
                    vec![
                        json!({
                            "id": "83124",
                            "origin": {"kind": "Acurast", "source": "abcd"}
                        }),
                        json!({"publicKeys": {"ed25519": "ab".repeat(32)}}),
                        json!({"processors": {"processor-1": {"ed25519": "ab".repeat(32)}}}),
                        json!({"bytes": "11".repeat(64)}),
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

    struct DelayedIdentityBridge {
        bridge: FakeBridge,
        remaining_failures: Mutex<usize>,
    }

    impl DelayedIdentityBridge {
        fn new(remaining_failures: usize) -> Self {
            Self {
                bridge: FakeBridge::successful(),
                remaining_failures: Mutex::new(remaining_failures),
            }
        }
    }

    impl Bridge for DelayedIdentityBridge {
        fn call(&self, method: &str, params: Value) -> Result<Value, BridgeError> {
            if method == "deployment_id" {
                let mut remaining = self.remaining_failures.lock().unwrap();
                if *remaining > 0 {
                    *remaining -= 1;
                    self.bridge
                        .calls
                        .lock()
                        .unwrap()
                        .push((method.to_owned(), params));
                    return Err(BridgeError::RpcError { code: None });
                }
            }
            self.bridge.call(method, params)
        }
    }

    enum FakeHttpReply {
        Response(u16, Value),
        Transport,
    }

    struct FakeHttp {
        replies: Mutex<VecDeque<FakeHttpReply>>,
        bodies: Mutex<Vec<Vec<u8>>>,
    }

    impl FakeHttp {
        fn new(replies: Vec<FakeHttpReply>) -> Self {
            Self {
                replies: Mutex::new(replies.into()),
                bodies: Mutex::new(Vec::new()),
            }
        }
    }

    impl HttpClient for FakeHttp {
        fn post(&self, _: &str, body: &[u8]) -> Result<HttpResponse, HttpError> {
            self.bodies.lock().unwrap().push(body.to_vec());
            match self.replies.lock().unwrap().pop_front().unwrap() {
                FakeHttpReply::Response(status, value) => Ok(HttpResponse {
                    status,
                    body: serde_json::to_vec(&value).unwrap(),
                }),
                FakeHttpReply::Transport => Err(HttpError::Transport),
            }
        }
    }

    struct FakeRuntime {
        elapsed: Mutex<Duration>,
        sleeps: Mutex<Vec<Duration>>,
    }

    impl FakeRuntime {
        fn new() -> Self {
            Self {
                elapsed: Mutex::new(Duration::ZERO),
                sleeps: Mutex::new(Vec::new()),
            }
        }
    }

    impl ContactRuntime for FakeRuntime {
        fn unix_time_ms(&self) -> Result<u64, ContactError> {
            Ok(1_000)
        }

        fn elapsed(&self) -> Duration {
            *self.elapsed.lock().unwrap()
        }

        fn fill_random(&self, bytes: &mut [u8]) -> Result<(), ContactError> {
            bytes.fill(7);
            Ok(())
        }

        fn sleep(&self, duration: Duration) {
            self.sleeps.lock().unwrap().push(duration);
            *self.elapsed.lock().unwrap() += duration;
        }
    }

    fn success_response() -> Value {
        json!({
            "ok": true,
            "domain": "proof.liskov.runtime-bootstrap-response.v2",
            "applicationUid": "app-uid-1",
            "applicationId": "app-1",
            "policyDigest": "ab",
            "deploymentId": "dep-1",
            "jobId": "{\"id\":\"83124\",\"origin\":{\"kind\":\"Acurast\",\"source\":\"abcd\"}}",
            "processorId": "processor-1",
            "runtimeInstanceId": "07".repeat(16),
            "slipwayUrl": "https://liskov.example"
        })
    }

    #[test]
    fn validates_https_core_urls() {
        assert!(validate_core_url("https://liskov.example/base").is_ok());
        for invalid in [
            "http://liskov.example",
            "https://user@liskov.example",
            "https://liskov.example?query=1",
            "https://liskov.example#fragment",
        ] {
            assert!(matches!(
                validate_core_url(invalid),
                Err(ContactError::Configuration(_))
            ));
        }
    }

    #[test]
    fn retries_transport_status_not_found_and_explicit_retryable_with_identical_body() {
        let bridge = FakeBridge::successful();
        let http = FakeHttp::new(vec![
            FakeHttpReply::Transport,
            FakeHttpReply::Response(404, json!({"error": "runtime_bootstrap_job_not_found"})),
            FakeHttpReply::Response(418, json!({"error": "warming", "retryable": true})),
            FakeHttpReply::Response(200, success_response()),
        ]);
        let runtime = FakeRuntime::new();
        let response = establish_runtime_contact_with(
            "https://liskov.example",
            &bridge,
            &http,
            &runtime,
            RetryPolicy {
                max_elapsed: Duration::from_secs(10),
                ..RetryPolicy::default()
            },
        )
        .unwrap();
        assert_eq!(response.application_uid, "app-uid-1");

        let bodies = http.bodies.lock().unwrap();
        assert_eq!(bodies.len(), 4);
        assert!(bodies.windows(2).all(|pair| pair[0] == pair[1]));
        let request: Value = serde_json::from_slice(&bodies[0]).unwrap();
        assert_eq!(request["nonce"], "07".repeat(16));
        assert_eq!(request["signature"], format!("0x{}", "11".repeat(64)));
        assert_eq!(request["issuedAtMs"], 1_000);
        assert_eq!(
            *runtime.sleeps.lock().unwrap(),
            vec![
                Duration::from_millis(250),
                Duration::from_secs(2),
                Duration::from_secs(2)
            ]
        );
        assert_eq!(
            bridge
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(method, _)| method == "signer_sign")
                .count(),
            1
        );
    }

    #[test]
    fn retries_identity_before_generating_one_signed_request() {
        let bridge = DelayedIdentityBridge::new(2);
        let http = FakeHttp::new(vec![FakeHttpReply::Response(200, success_response())]);
        let runtime = FakeRuntime::new();
        establish_runtime_contact_with(
            "https://liskov.example",
            &bridge,
            &http,
            &runtime,
            RetryPolicy {
                max_elapsed: Duration::from_secs(10),
                ..RetryPolicy::default()
            },
        )
        .unwrap();

        assert_eq!(
            *runtime.sleeps.lock().unwrap(),
            vec![Duration::from_millis(250), Duration::from_secs(2)]
        );
        let calls = bridge.bridge.calls.lock().unwrap();
        assert_eq!(
            calls
                .iter()
                .filter(|(method, _)| method == "deployment_id")
                .count(),
            3
        );
        assert_eq!(
            calls
                .iter()
                .filter(|(method, _)| method == "signer_sign")
                .count(),
            1
        );
        assert_eq!(http.bodies.lock().unwrap().len(), 1);
    }

    #[test]
    fn identity_retry_exhaustion_preserves_the_failing_stage() {
        let bridge = DelayedIdentityBridge::new(2);
        let http = FakeHttp::new(Vec::new());
        let runtime = FakeRuntime::new();
        let error = establish_runtime_contact_with(
            "https://liskov.example",
            &bridge,
            &http,
            &runtime,
            RetryPolicy {
                max_attempts: 2,
                max_elapsed: Duration::from_secs(10),
                ..RetryPolicy::default()
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ContactError::Protocol(ProtocolError::DeploymentIdentityBridge(
                BridgeError::RpcError { .. }
            ))
        ));
        assert_eq!(
            *runtime.sleeps.lock().unwrap(),
            vec![Duration::from_millis(250)]
        );
        assert!(http.bodies.lock().unwrap().is_empty());
    }

    #[test]
    fn explicit_non_retryable_verdict_wins_over_retryable_status() {
        let bridge = FakeBridge::successful();
        let http = FakeHttp::new(vec![FakeHttpReply::Response(
            503,
            json!({"error": "permanent", "retryable": false}),
        )]);
        let error = establish_runtime_contact_with(
            "https://liskov.example",
            &bridge,
            &http,
            &FakeRuntime::new(),
            RetryPolicy::default(),
        )
        .unwrap_err();
        assert!(matches!(error, ContactError::PermanentServerRejection));
        assert_eq!(error.exit_category(), ExitCategory::Protocol);
    }

    #[test]
    fn retry_classification_covers_the_established_status_and_error_contract() {
        for status in [404, 409, 425, 429, 500, 502, 503, 504] {
            assert!(response_is_retryable(&HttpResponse {
                status,
                body: b"{}".to_vec(),
            }));
        }
        assert!(response_is_retryable(&HttpResponse {
            status: 418,
            body: br#"{"error":"runtime_bootstrap_job_not_found"}"#.to_vec(),
        }));
        assert!(response_is_retryable(&HttpResponse {
            status: 418,
            body: br#"{"error":"warming","retryable":true}"#.to_vec(),
        }));
        assert!(!response_is_retryable(&HttpResponse {
            status: 401,
            body: br#"{"error":"runtime_bootstrap_bad_signature"}"#.to_vec(),
        }));
    }

    #[test]
    fn retry_exhaustion_is_temporary_failure() {
        let bridge = FakeBridge::successful();
        let http = FakeHttp::new(vec![FakeHttpReply::Transport, FakeHttpReply::Transport]);
        let error = establish_runtime_contact_with(
            "https://liskov.example",
            &bridge,
            &http,
            &FakeRuntime::new(),
            RetryPolicy {
                initial_delay: Duration::ZERO,
                interval: Duration::ZERO,
                max_elapsed: Duration::from_secs(1),
                max_attempts: 2,
            },
        )
        .unwrap_err();
        assert!(matches!(error, ContactError::RetryExhausted));
        assert_eq!(error.exit_category(), ExitCategory::TemporaryFailure);
    }

    #[test]
    fn canary_diagnostic_codes_distinguish_non_secret_contact_stages() {
        let cases = [
            (
                ContactError::Protocol(ProtocolError::DeploymentIdentityBridge(
                    BridgeError::RpcError { code: None },
                )),
                81,
            ),
            (
                ContactError::Protocol(ProtocolError::InvalidDeploymentIdentity),
                82,
            ),
            (
                ContactError::Protocol(ProtocolError::PublicKeyBridge(BridgeError::RpcError {
                    code: None,
                })),
                83,
            ),
            (ContactError::Protocol(ProtocolError::InvalidPublicKey), 84),
            (
                ContactError::Protocol(ProtocolError::AssignedProcessorsBridge(
                    BridgeError::RpcError { code: None },
                )),
                85,
            ),
            (
                ContactError::Protocol(ProtocolError::ProcessorMatchCount),
                86,
            ),
            (
                ContactError::Protocol(ProtocolError::SignerBridge(BridgeError::RpcError {
                    code: None,
                })),
                87,
            ),
            (ContactError::Protocol(ProtocolError::InvalidSignature), 88),
            (ContactError::PermanentServerRejection, 90),
            (ContactError::Protocol(ProtocolError::InvalidResponse), 91),
            (ContactError::Protocol(ProtocolError::ResponseBinding), 92),
            (ContactError::RetryExhausted, 95),
        ];
        for (error, expected) in cases {
            assert_eq!(error.diagnostic_exit_code(), expected);
            assert_eq!(
                error.exit_category(),
                if matches!(error, ContactError::RetryExhausted) {
                    ExitCategory::TemporaryFailure
                } else {
                    ExitCategory::Protocol
                }
            );
        }
    }
}
