//! Signed diagnostic-v4 observations emitted after successful first contact.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

use crate::bridge::Bridge;
use crate::http::HttpClient;
use crate::protocol::RuntimeBootstrapResponse;

pub const RUNTIME_DIAGNOSTIC_DOMAIN_V4: &str = "proof.liskov.runtime-diagnostic.v4";
pub const CARGO_SUPERVISOR_COMPONENT: &str = "runtime-cargo-supervisor";
pub const DIAGNOSTIC_HTTP_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_DIAGNOSTIC_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_DELIVERY_ATTEMPTS: usize = 2;
const DIAGNOSTIC_QUEUE_CAPACITY: usize = 32;
const DIAGNOSTIC_SHUTDOWN_GRACE: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticStatus {
    Started,
    Succeeded,
    Failed,
    Info,
}

impl DiagnosticStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Info => "info",
        }
    }
}

pub struct DiagnosticReporter {
    bridge: Arc<dyn Bridge>,
    http: Arc<dyn HttpClient>,
    endpoint: String,
    application_uid: String,
    job_id: String,
    processor_id: String,
    runtime_instance_id: String,
    sequence: u64,
}

impl DiagnosticReporter {
    pub fn new(
        bootstrap: &RuntimeBootstrapResponse,
        bridge: Arc<dyn Bridge>,
        http: Arc<dyn HttpClient>,
    ) -> Option<Self> {
        let endpoint = url::Url::parse(&bootstrap.slipway_url)
            .ok()
            .filter(|url| {
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
            })?
            .join("/api/jobs/runtime-diagnostics")
            .ok()?
            .to_string();
        Some(Self {
            bridge,
            http,
            endpoint,
            application_uid: bootstrap.application_uid.clone(),
            job_id: bootstrap.job_id.clone(),
            processor_id: bootstrap.processor_id.clone(),
            runtime_instance_id: bootstrap.runtime_instance_id.clone(),
            sequence: 0,
        })
    }

    /// Sign and deliver one closed observation. Delivery is deliberately
    /// best-effort after first contact: failure advances the local sequence but
    /// never changes process supervision or the customer result.
    pub fn report(
        &mut self,
        stage: &'static str,
        status: DiagnosticStatus,
        code: Option<&'static str>,
        attrs: Value,
    ) {
        let sequence = self.sequence;
        self.sequence = self.sequence.saturating_add(1);
        let Some(timestamp_ms) = unix_time_ms() else {
            return;
        };
        let mut unsigned = json!({
            "domain": RUNTIME_DIAGNOSTIC_DOMAIN_V4,
            "jobId": self.job_id,
            "processorId": self.processor_id,
            "runtimeInstanceId": self.runtime_instance_id,
            "applicationUid": self.application_uid,
            "stage": stage,
            "status": status.as_str(),
            "sequence": sequence,
            "timestampMs": timestamp_ms,
            "component": CARGO_SUPERVISOR_COMPONENT,
            "code": code,
            "message": null,
            "attrs": attrs,
        });
        let message = canonical_json_bytes(&unsigned);
        let Ok(result) = self.bridge.call(
            "signer_sign",
            json!([{
                "curve": "ed25519",
                "bytes": hex::encode(message),
            }]),
        ) else {
            return;
        };
        let Some(signature) = result
            .get("bytes")
            .and_then(Value::as_str)
            .and_then(normalize_signature)
        else {
            return;
        };
        unsigned["signature"] = json!(format!("0x{signature}"));
        let Ok(body) = serde_json::to_vec(&unsigned) else {
            return;
        };
        for _ in 0..MAX_DELIVERY_ATTEMPTS {
            if self
                .http
                .post(&self.endpoint, &body)
                .is_ok_and(|response| (200..300).contains(&response.status))
            {
                break;
            }
        }
    }

    pub fn next_sequence(&self) -> u64 {
        self.sequence
    }
}

#[derive(Debug)]
enum DiagnosticWork {
    Observation {
        stage: &'static str,
        status: DiagnosticStatus,
        code: Option<&'static str>,
        attrs: Value,
    },
    Shutdown(std::sync::mpsc::Sender<()>),
}

/// Bounded, non-blocking delivery boundary for post-contact observations.
/// Network and bridge outages may drop evidence, but cannot stall signal
/// forwarding, child reaping, restart timers, or the customer result.
pub struct AsyncDiagnosticReporter {
    sender: Option<SyncSender<DiagnosticWork>>,
}

impl AsyncDiagnosticReporter {
    pub fn spawn(
        bootstrap: &RuntimeBootstrapResponse,
        bridge: Arc<dyn Bridge>,
        http: Arc<dyn HttpClient>,
    ) -> Option<Self> {
        // Validate the endpoint before starting a thread. The worker owns all
        // signing and HTTP state and is the sole sequence authority.
        DiagnosticReporter::new(bootstrap, bridge.clone(), http.clone())?;
        let bootstrap = bootstrap.clone();
        let (sender, receiver) = sync_channel(DIAGNOSTIC_QUEUE_CAPACITY);
        thread::Builder::new()
            .name("liskov-cargo-diagnostics".into())
            .spawn(move || {
                let Some(mut reporter) = DiagnosticReporter::new(&bootstrap, bridge, http) else {
                    return;
                };
                while let Ok(work) = receiver.recv() {
                    match work {
                        DiagnosticWork::Observation {
                            stage,
                            status,
                            code,
                            attrs,
                        } => reporter.report(stage, status, code, attrs),
                        DiagnosticWork::Shutdown(acknowledge) => {
                            let _ = acknowledge.send(());
                            break;
                        }
                    }
                }
            })
            .ok()?;
        Some(Self {
            sender: Some(sender),
        })
    }

    pub fn report(
        &mut self,
        stage: &'static str,
        status: DiagnosticStatus,
        code: Option<&'static str>,
        attrs: Value,
    ) {
        let Some(sender) = &self.sender else {
            return;
        };
        match sender.try_send(DiagnosticWork::Observation {
            stage,
            status,
            code,
            attrs,
        }) {
            Ok(()) | Err(TrySendError::Full(_)) => {}
            Err(TrySendError::Disconnected(_)) => self.sender = None,
        }
    }
}

impl Drop for AsyncDiagnosticReporter {
    fn drop(&mut self) {
        let Some(sender) = self.sender.take() else {
            return;
        };
        let (acknowledge, acknowledged) = std::sync::mpsc::channel();
        if sender
            .try_send(DiagnosticWork::Shutdown(acknowledge))
            .is_ok()
        {
            let _ = acknowledged.recv_timeout(DIAGNOSTIC_SHUTDOWN_GRACE);
        }
        // Dropping the sender detaches any worker still inside a bounded
        // bridge/HTTP attempt. Process exit remains governed by the customer.
    }
}

fn unix_time_ms() -> Option<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis();
    u64::try_from(millis).ok()
}

fn normalize_signature(value: &str) -> Option<String> {
    let value = value
        .strip_prefix("0x")
        .unwrap_or(value)
        .to_ascii_lowercase();
    (value.len() == 128 && value.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(value)
}

pub fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(&sort_json(value.clone())).expect("JSON values always serialize")
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
    use std::sync::Mutex;

    use crate::bridge::{Bridge, BridgeError};
    use crate::http::{HttpError, HttpResponse};

    use super::*;

    #[derive(Default)]
    struct FakeBridge {
        calls: Mutex<Vec<(String, Value)>>,
    }

    impl Bridge for FakeBridge {
        fn call(&self, method: &str, params: Value) -> Result<Value, BridgeError> {
            self.calls
                .lock()
                .unwrap()
                .push((method.to_string(), params));
            Ok(json!({"bytes": "ab".repeat(64)}))
        }
    }

    #[derive(Default)]
    struct FakeHttp {
        bodies: Mutex<Vec<Vec<u8>>>,
    }

    impl HttpClient for FakeHttp {
        fn post(&self, _url: &str, body: &[u8]) -> Result<HttpResponse, HttpError> {
            self.bodies.lock().unwrap().push(body.to_vec());
            Ok(HttpResponse {
                status: 200,
                body: Vec::new(),
            })
        }
    }

    struct SlowHttp;

    impl HttpClient for SlowHttp {
        fn post(&self, _url: &str, _body: &[u8]) -> Result<HttpResponse, HttpError> {
            thread::sleep(Duration::from_millis(500));
            Err(HttpError::Transport)
        }
    }

    fn bootstrap() -> RuntimeBootstrapResponse {
        RuntimeBootstrapResponse {
            ok: true,
            domain: "proof.liskov.runtime-bootstrap-response.v2".into(),
            application_uid: "app-uid".into(),
            application_id: "app".into(),
            policy_digest: "digest".into(),
            deployment_id: "deployment".into(),
            job_id: "job".into(),
            processor_id: "processor".into(),
            runtime_instance_id: "instance".into(),
            slipway_url: "https://liskov.example".into(),
            runtime_env: None,
            supervision: None,
            logging: None,
            logging_outage_canary: false,
        }
    }

    #[test]
    fn signs_every_field_and_advances_sequence_after_delivery_failure() {
        let bridge = Arc::new(FakeBridge::default());
        let http = Arc::new(FakeHttp::default());
        let mut reporter =
            DiagnosticReporter::new(&bootstrap(), bridge.clone(), http.clone()).unwrap();
        reporter.report(
            "runtime.health",
            DiagnosticStatus::Info,
            None,
            json!({"processAttempt": 0, "restartCount": 0}),
        );
        assert_eq!(reporter.next_sequence(), 1);
        let calls = bridge.calls.lock().unwrap();
        let call = &calls[0];
        assert_eq!(call.0, "signer_sign");
        let signed: Value = serde_json::from_slice(&http.bodies.lock().unwrap()[0]).unwrap();
        assert_eq!(signed["sequence"], 0);
        assert_eq!(signed["component"], CARGO_SUPERVISOR_COMPONENT);
        assert_eq!(signed["signature"], format!("0x{}", "ab".repeat(64)));
        assert_eq!(
            call.1[0]["bytes"],
            hex::encode(canonical_json_bytes(&json!({
                "domain": RUNTIME_DIAGNOSTIC_DOMAIN_V4,
                "jobId": "job",
                "processorId": "processor",
                "runtimeInstanceId": "instance",
                "applicationUid": "app-uid",
                "stage": "runtime.health",
                "status": "info",
                "sequence": 0,
                "timestampMs": signed["timestampMs"],
                "component": CARGO_SUPERVISOR_COMPONENT,
                "code": null,
                "message": null,
                "attrs": {"processAttempt": 0, "restartCount": 0},
            })))
        );
    }

    #[test]
    fn post_contact_outage_does_not_block_supervision_thread() {
        let bridge: Arc<dyn Bridge> = Arc::new(FakeBridge::default());
        let http: Arc<dyn HttpClient> = Arc::new(SlowHttp);
        let mut reporter = AsyncDiagnosticReporter::spawn(&bootstrap(), bridge, http).unwrap();
        let started = std::time::Instant::now();
        for process_attempt in 0..128 {
            reporter.report(
                "runtime.health",
                DiagnosticStatus::Info,
                None,
                json!({"processAttempt": process_attempt, "restartCount": 0}),
            );
        }
        assert!(started.elapsed() < Duration::from_millis(100));
        drop(reporter);
    }
}
