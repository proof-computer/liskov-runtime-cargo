//! Dormant, server-authorized coverage-result producer for Cargo/PRoot.
//!
//! Consumes the raw optional `factAuthorization` bootstrap block — the
//! server-minted, pre-filled partial `proof.liskov.processor-coverage-result.v1`
//! envelope — completes it with locally observed probe outcomes, signs the
//! canonical bytes with the claim-bound runtime key, and submits it once to
//! the bootstrap origin. Deliberately distinct from `processor_facts` and its
//! `proof.liskov.processor-fact-authorization.v1` contract: this module owns
//! the frozen coverage envelope only.
//!
//! Absent, malformed, unknown, misbound, or out-of-contract content never
//! produces a run: the helper stays dormant and customer execution is
//! untouched. Failures emit one closed diagnostic outcome code — never
//! bodies, signatures, nonces, or identity.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::bridge::Bridge;
use crate::diagnostics::canonical_json_bytes;
use crate::hardware::{collect_hardware_source_readings, hardware_metric_digest};
use crate::processor_facts::{
    AndroidFactCollector, AndroidPropertyCollector, BridgeFactSigner, ExecutionFactCollector,
    FactClock, FactSigner, HttpsResultDelivery, LinuxExecutionCollector, ResultDelivery,
    SecurePropertyFileReader, SystemFactClock, bounded_identifier, valid_hex, valid_sha256,
};
use crate::protocol::RuntimeBootstrapResponse;

pub const LISKOV_PROCESSOR_COVERAGE_RESULT_DOMAIN_V1: &str =
    "proof.liskov.processor-coverage-result.v1";
pub const COVERAGE_RESULT_PATH: &str = "/api/jobs/coverage-result";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_IDENTITY_BYTES: usize = 256;
const MAX_AUTHORIZATION_LIFETIME_MS: u64 = 86_400_000;
const AUTHORIZATION_FUTURE_TOLERANCE_MS: u64 = 60 * 1000;
const MAX_SUBMISSION_BYTES: usize = 16 * 1024;
const BOOTSTRAP_PROBE_ID: &str = "runtime-bootstrap";
const HARDWARE_CAPTURE_PROBE_ID: &str = "hardware-capture";
const BOOTSTRAP_PROBE_REGION: &str = "processor-local";

/// The frozen coverage-result envelope, byte-compatible with the
/// `liskov-rs` and `liskov-runtime-js` implementations. The shared golden
/// vector pins canonical-byte parity across all three repositories.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoverageResultV1 {
    pub domain: String,
    pub application_id: String,
    pub policy_version_id: String,
    pub policy_digest: String,
    pub artifact_digest: String,
    pub cycle_id: String,
    pub target: CoverageTarget,
    pub deployment_id: String,
    pub job_id: String,
    pub processor_id: String,
    pub probe_version: String,
    pub profile_version: String,
    pub sequence: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub outcomes: Vec<CoverageOutcome>,
    pub normalized_metric_digest: String,
    pub challenge: String,
    pub replay_subject: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoverageTarget {
    pub target_id: String,
    pub provider: String,
    pub runtime: CoverageTargetRuntime,
    pub release: CoverageTargetRelease,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageTargetRuntime {
    Javascript,
    NativeImage,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageTargetRelease {
    Source,
    Pinned,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoverageOutcome {
    pub probe_id: String,
    pub status: CoverageOutcomeStatus,
    pub region: String,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub duration_ms: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub errors: Vec<CoverageProbeError>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageOutcomeStatus {
    Succeeded,
    Failed,
    TimedOut,
    Unsupported,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoverageProbeError {
    pub code: String,
    pub message: String,
}

/// The delivered `factAuthorization` block: the envelope's binding set plus
/// the fresh challenge, replay subject, and submit URL. Everything except
/// `outcomes`, `normalizedMetricDigest`, and `signature`.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CoverageFactAuthorization {
    domain: String,
    application_id: String,
    policy_version_id: String,
    policy_digest: String,
    artifact_digest: String,
    cycle_id: String,
    target: CoverageTarget,
    deployment_id: String,
    job_id: String,
    processor_id: String,
    probe_version: String,
    profile_version: String,
    sequence: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
    challenge: String,
    replay_subject: String,
    submit_url: String,
}

impl CoverageFactAuthorization {
    fn structurally_valid(&self) -> bool {
        self.domain == LISKOV_PROCESSOR_COVERAGE_RESULT_DOMAIN_V1
            && [
                self.application_id.as_str(),
                self.policy_version_id.as_str(),
                self.cycle_id.as_str(),
                self.deployment_id.as_str(),
                self.job_id.as_str(),
                self.processor_id.as_str(),
                self.probe_version.as_str(),
                self.profile_version.as_str(),
                self.replay_subject.as_str(),
                self.target.target_id.as_str(),
                self.target.provider.as_str(),
            ]
            .iter()
            .all(|value| bounded_identifier(value, MAX_IDENTITY_BYTES))
            && valid_sha256(&self.policy_digest)
            && valid_sha256(&self.artifact_digest)
            && self
                .challenge
                .strip_prefix("0x")
                .is_some_and(|hex| valid_hex(hex, 32))
            && self.sequence <= MAX_SAFE_INTEGER
            && self.issued_at_ms <= MAX_SAFE_INTEGER
            && self.expires_at_ms <= MAX_SAFE_INTEGER
            && self.expires_at_ms > self.issued_at_ms
            && self.expires_at_ms - self.issued_at_ms <= MAX_AUTHORIZATION_LIFETIME_MS
    }

    fn valid_at(&self, now_ms: u64) -> bool {
        self.expires_at_ms > now_ms
            && self.issued_at_ms <= now_ms.saturating_add(AUTHORIZATION_FUTURE_TOLERANCE_MS)
    }
}

/// A validated authorization bound to this exact bootstrap, with the
/// submission URL reconstructed from the bootstrap origin.
#[derive(Clone)]
pub struct CoverageAuthorization {
    authorization: CoverageFactAuthorization,
    submit_url: String,
}

impl CoverageAuthorization {
    /// The server assigns the workload target at mint from its exact
    /// internal configuration; a native-image target is the fixed hardware
    /// capture profile (ADR-0079 §2 — the payload cannot choose).
    fn is_native_image_target(&self) -> bool {
        matches!(
            self.authorization.target.runtime,
            CoverageTargetRuntime::NativeImage
        )
    }
}

/// Remove and validate the raw capability independently of bootstrap
/// validity. Any malformed, unknown, out-of-contract, or misbound content
/// simply returns `None`: the producer never runs, and the runtime never
/// signs an envelope whose binding is not its own authenticated identity.
pub fn take_coverage_authorization(
    bootstrap: &mut RuntimeBootstrapResponse,
) -> Option<CoverageAuthorization> {
    let raw = bootstrap.fact_authorization.take()?;
    let authorization: CoverageFactAuthorization = serde_json::from_value(raw).ok()?;
    if !authorization.structurally_valid() {
        return None;
    }
    // Sign only our own identity: every binding field the runtime knows
    // authoritatively must match the authenticated bootstrap exactly.
    if authorization.deployment_id != bootstrap.deployment_id
        || authorization.job_id != bootstrap.job_id
        || authorization.processor_id != bootstrap.processor_id
    {
        return None;
    }
    let submit_url = coverage_submit_url(&bootstrap.slipway_url, &authorization.submit_url)?;
    Some(CoverageAuthorization {
        authorization,
        submit_url,
    })
}

/// The signed submission goes to the bootstrap origin at the fixed coverage
/// route; the block's `submitUrl` may only confirm that destination, never
/// direct the submission elsewhere.
fn coverage_submit_url(slipway_url: &str, block_submit_url: &str) -> Option<String> {
    let mut base = url::Url::parse(slipway_url).ok()?;
    if base.scheme() != "https"
        || base.host_str().is_none()
        || base.username() != ""
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return None;
    }
    base.set_path(COVERAGE_RESULT_PATH);
    let block = url::Url::parse(block_submit_url).ok()?;
    (block.scheme() == "https"
        && block.host_str() == base.host_str()
        && block.port_or_known_default() == base.port_or_known_default()
        && block.path() == COVERAGE_RESULT_PATH
        && block.username() == ""
        && block.password().is_none()
        && block.query().is_none()
        && block.fragment().is_none())
    .then(|| base.to_string())
}

/// Wall-clock stamps of the authenticated bootstrap exchange, measured
/// around the actual contact call.
#[derive(Clone, Copy)]
pub struct CoverageContactObservation {
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
}

/// Everything the supervisor needs to start the detached producer.
pub struct CoverageProducerActivation {
    pub authorization: CoverageAuthorization,
    pub observation: CoverageContactObservation,
}

/// Wall-clock capture for the contact observation. `None` keeps the
/// producer dormant.
pub fn wall_clock_ms() -> Option<u64> {
    SystemFactClock.now_ms()
}

pub struct CoverageProducerDependencies<'a> {
    pub clock: &'a dyn FactClock,
    pub signer: &'a dyn FactSigner,
    pub delivery: &'a dyn ResultDelivery,
    pub android: &'a dyn AndroidFactCollector,
    pub execution: &'a dyn ExecutionFactCollector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoverageProducerOutcome {
    Submitted,
    ClockUnavailable,
    AuthorizationExpired,
    EnvelopeUnrepresentable,
    OversizeRefused,
    SigningFailed,
    DeliveryFailed,
}

impl CoverageProducerOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::ClockUnavailable => "clock_unavailable",
            Self::AuthorizationExpired => "authorization_expired",
            Self::EnvelopeUnrepresentable => "envelope_unrepresentable",
            Self::OversizeRefused => "oversize_refused",
            Self::SigningFailed => "signing_failed",
            Self::DeliveryFailed => "delivery_failed",
        }
    }
}

/// One closed, bounded diagnostic line per producer run: a static outcome
/// code only — never bodies, signatures, nonces, or identity.
fn coverage_producer_line(outcome: CoverageProducerOutcome) -> String {
    format!(
        "liskov-runtime-contact: coverage \
         {{\"domain\":\"proof.liskov.processor-coverage-producer.v1\",\
         \"outcome\":\"{}\"}}",
        outcome.as_str()
    )
}

pub(crate) fn detached_coverage_task(
    activation: CoverageProducerActivation,
    bridge: Arc<dyn Bridge>,
) -> Box<dyn FnOnce() + Send> {
    Box::new(move || {
        let clock = SystemFactClock;
        let signer = BridgeFactSigner { bridge };
        let delivery = HttpsResultDelivery;
        let android = AndroidPropertyCollector::<SecurePropertyFileReader>::default();
        let execution = LinuxExecutionCollector;
        let dependencies = CoverageProducerDependencies {
            clock: &clock,
            signer: &signer,
            delivery: &delivery,
            android: &android,
            execution: &execution,
        };
        let outcome = run_coverage_producer(
            &activation.authorization,
            activation.observation,
            &dependencies,
        );
        eprintln!("{}", coverage_producer_line(outcome));
    })
}

pub(crate) fn run_coverage_producer(
    coverage: &CoverageAuthorization,
    observation: CoverageContactObservation,
    dependencies: &CoverageProducerDependencies<'_>,
) -> CoverageProducerOutcome {
    let Some(now_ms) = dependencies.clock.now_ms() else {
        return CoverageProducerOutcome::ClockUnavailable;
    };
    let authorization = &coverage.authorization;
    if !authorization.valid_at(now_ms) {
        return CoverageProducerOutcome::AuthorizationExpired;
    }

    // A backwards clock step between the two wall stamps clamps to a
    // zero-duration observation rather than an unrepresentable one.
    let completed_at_ms = observation.completed_at_ms.min(MAX_SAFE_INTEGER);
    let started_at_ms = observation.started_at_ms.min(completed_at_ms);
    let mut outcomes = vec![CoverageOutcome {
        probe_id: BOOTSTRAP_PROBE_ID.to_owned(),
        status: CoverageOutcomeStatus::Succeeded,
        region: BOOTSTRAP_PROBE_REGION.to_owned(),
        started_at_ms,
        completed_at_ms,
        duration_ms: completed_at_ms - started_at_ms,
        // The contact seam does not expose exchange sizes in this producer
        // revision: zero is the recorded floor, not a missing value.
        bytes_sent: 0,
        bytes_received: 0,
        errors: Vec::new(),
    }];

    // For the server-assigned native-image target, the committed metric
    // payload is the proof.liskov.processor-hardware.v1 source readings:
    // collected availability-first, digested, and dropped — the payload is
    // never logged or transmitted in this slice, only its commitment.
    let mut hardware_digest = None;
    if coverage.is_native_image_target() {
        let Some(capture_started_ms) = dependencies.clock.now_ms() else {
            return CoverageProducerOutcome::ClockUnavailable;
        };
        let readings = collect_hardware_source_readings(
            capture_started_ms.min(MAX_SAFE_INTEGER),
            dependencies.android,
            dependencies.execution,
        );
        let Some(digest) = hardware_metric_digest(&readings) else {
            return CoverageProducerOutcome::EnvelopeUnrepresentable;
        };
        let Some(capture_completed_ms) = dependencies.clock.now_ms() else {
            return CoverageProducerOutcome::ClockUnavailable;
        };
        let capture_completed_ms = capture_completed_ms.min(MAX_SAFE_INTEGER);
        let capture_started_ms = capture_started_ms.min(capture_completed_ms);
        outcomes.push(CoverageOutcome {
            probe_id: HARDWARE_CAPTURE_PROBE_ID.to_owned(),
            status: CoverageOutcomeStatus::Succeeded,
            region: BOOTSTRAP_PROBE_REGION.to_owned(),
            started_at_ms: capture_started_ms,
            completed_at_ms: capture_completed_ms,
            duration_ms: capture_completed_ms - capture_started_ms,
            bytes_sent: 0,
            bytes_received: 0,
            errors: Vec::new(),
        });
        hardware_digest = Some(digest);
    }

    let normalized_metric_digest = match hardware_digest {
        Some(digest) => digest,
        None => {
            let Ok(outcomes_value) = serde_json::to_value(&outcomes) else {
                return CoverageProducerOutcome::EnvelopeUnrepresentable;
            };
            format!(
                "sha256:{}",
                hex::encode(Sha256::digest(canonical_json_bytes(&outcomes_value)))
            )
        }
    };

    let result = CoverageResultV1 {
        domain: LISKOV_PROCESSOR_COVERAGE_RESULT_DOMAIN_V1.to_owned(),
        application_id: authorization.application_id.clone(),
        policy_version_id: authorization.policy_version_id.clone(),
        policy_digest: authorization.policy_digest.clone(),
        artifact_digest: authorization.artifact_digest.clone(),
        cycle_id: authorization.cycle_id.clone(),
        target: authorization.target.clone(),
        deployment_id: authorization.deployment_id.clone(),
        job_id: authorization.job_id.clone(),
        processor_id: authorization.processor_id.clone(),
        probe_version: authorization.probe_version.clone(),
        profile_version: authorization.profile_version.clone(),
        sequence: authorization.sequence,
        issued_at_ms: authorization.issued_at_ms,
        expires_at_ms: authorization.expires_at_ms,
        outcomes,
        normalized_metric_digest,
        challenge: authorization.challenge.clone(),
        replay_subject: authorization.replay_subject.clone(),
    };
    let Ok(unsigned_value) = serde_json::to_value(&result) else {
        return CoverageProducerOutcome::EnvelopeUnrepresentable;
    };
    let message = canonical_json_bytes(&unsigned_value);
    let Some(signature) = dependencies.signer.sign_ed25519(&message) else {
        return CoverageProducerOutcome::SigningFailed;
    };
    let mut signed = unsigned_value;
    let Value::Object(ref mut object) = signed else {
        return CoverageProducerOutcome::EnvelopeUnrepresentable;
    };
    object.insert("signature".to_owned(), Value::String(signature));
    let body = canonical_json_bytes(&signed);
    if body.len() > MAX_SUBMISSION_BYTES {
        return CoverageProducerOutcome::OversizeRefused;
    }

    // One submission per authorization: the byte-identical body may be
    // retried once because the server admits exact replays idempotently.
    for _ in 0..2 {
        let Some(now) = dependencies.clock.now_ms() else {
            return CoverageProducerOutcome::ClockUnavailable;
        };
        if now >= authorization.expires_at_ms {
            return CoverageProducerOutcome::AuthorizationExpired;
        }
        if dependencies.delivery.deliver(&coverage.submit_url, &body) {
            return CoverageProducerOutcome::Submitted;
        }
    }
    CoverageProducerOutcome::DeliveryFailed
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;

    use super::*;
    use crate::hardware::HardwareSourceReadingsV1;
    use crate::hardware::tests::{fixture_android, fixture_execution};
    use crate::processor_facts::{AndroidCorroborationFact, ExecutionSurfaceFact};

    #[derive(Default)]
    struct FakeAndroid(AtomicUsize);

    impl AndroidFactCollector for FakeAndroid {
        fn collect(&self) -> AndroidCorroborationFact {
            self.0.fetch_add(1, Ordering::SeqCst);
            fixture_android()
        }
    }

    #[derive(Default)]
    struct FakeExecution(AtomicUsize);

    impl ExecutionFactCollector for FakeExecution {
        fn collect(&self) -> ExecutionSurfaceFact {
            self.0.fetch_add(1, Ordering::SeqCst);
            fixture_execution()
        }
    }

    const NOW: u64 = 1_800_000_000_000;

    fn bootstrap(fact_authorization: Option<Value>) -> RuntimeBootstrapResponse {
        RuntimeBootstrapResponse {
            ok: true,
            domain: "proof.liskov.runtime-bootstrap-response.v2".into(),
            application_uid: "app-uid".into(),
            application_id: "app-id".into(),
            policy_digest: "sha256:policy".into(),
            deployment_id: "deployment".into(),
            job_id: "job".into(),
            processor_id: "processor".into(),
            runtime_instance_id: "instance".into(),
            slipway_url: "https://liskov.example".into(),
            runtime_env: None,
            supervision: None,
            logging: None,
            logging_outage_canary: false,
            diagnostics: None,
            access: None,
            processor_facts: None,
            fact_authorization,
        }
    }

    fn minted_block() -> Value {
        json!({
            "domain": LISKOV_PROCESSOR_COVERAGE_RESULT_DOMAIN_V1,
            "applicationId": "app-id",
            "policyVersionId": "policy-version-5",
            "policyDigest": format!("sha256:{}", "a".repeat(64)),
            "artifactDigest": format!("sha256:{}", "b".repeat(64)),
            "cycleId": "cov-cycle-canary-1",
            "target": {
                "targetId": "acurast-native-pinned",
                "provider": "acurast",
                "runtime": "native_image",
                "release": "pinned",
            },
            "deploymentId": "deployment",
            "jobId": "job",
            "processorId": "processor",
            "probeVersion": "probe-1",
            "profileVersion": "profile-1",
            "sequence": NOW - 5_000,
            "issuedAtMs": NOW - 5_000,
            "expiresAtMs": NOW + 895_000,
            "challenge": format!("0x{}", "11".repeat(32)),
            "replaySubject": "pcrs_0123456789abcdef",
            "submitUrl": "https://liskov.example/api/jobs/coverage-result",
        })
    }

    fn javascript_block() -> Value {
        let mut block = minted_block();
        block["target"] = json!({
            "targetId": "acurast-js-source",
            "provider": "acurast",
            "runtime": "javascript",
            "release": "source",
        });
        block
    }

    fn taken(block: Value) -> Option<CoverageAuthorization> {
        take_coverage_authorization(&mut bootstrap(Some(block)))
    }

    struct FixedClock(u64);

    impl FactClock for FixedClock {
        fn now_ms(&self) -> Option<u64> {
            Some(self.0)
        }
    }

    struct SequenceClock {
        values: Mutex<VecDeque<u64>>,
        fallback: u64,
    }

    impl FactClock for SequenceClock {
        fn now_ms(&self) -> Option<u64> {
            Some(
                self.values
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(self.fallback),
            )
        }
    }

    struct RecordingSigner {
        messages: Mutex<Vec<Vec<u8>>>,
        signature: Option<&'static str>,
    }

    impl RecordingSigner {
        fn succeeding() -> Self {
            Self {
                messages: Mutex::new(Vec::new()),
                signature: Some(
                    "0x2222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222",
                ),
            }
        }

        fn failing() -> Self {
            Self {
                messages: Mutex::new(Vec::new()),
                signature: None,
            }
        }
    }

    impl FactSigner for RecordingSigner {
        fn sign_ed25519(&self, message: &[u8]) -> Option<String> {
            self.messages.lock().unwrap().push(message.to_vec());
            self.signature.map(str::to_owned)
        }
    }

    struct RecordingDelivery {
        attempts: Mutex<Vec<(String, Vec<u8>)>>,
        succeed: bool,
    }

    impl RecordingDelivery {
        fn new(succeed: bool) -> Self {
            Self {
                attempts: Mutex::new(Vec::new()),
                succeed,
            }
        }
    }

    impl ResultDelivery for RecordingDelivery {
        fn deliver(&self, url: &str, body: &[u8]) -> bool {
            self.attempts
                .lock()
                .unwrap()
                .push((url.to_owned(), body.to_vec()));
            self.succeed
        }
    }

    fn observation() -> CoverageContactObservation {
        CoverageContactObservation {
            started_at_ms: NOW - 9_000,
            completed_at_ms: NOW - 7_750,
        }
    }

    #[test]
    fn matches_the_shared_three_way_canonical_signing_vector() {
        let vector: Value =
            serde_json::from_str(include_str!("../vectors/processor-coverage-result-v1.json"))
                .expect("shared vector parses");
        let result: CoverageResultV1 =
            serde_json::from_value(vector["result"].clone()).expect("frozen envelope parses");
        let canonical = canonical_json_bytes(&serde_json::to_value(&result).unwrap());
        assert_eq!(
            std::str::from_utf8(&canonical).unwrap(),
            vector["canonicalSigningPayload"].as_str().unwrap(),
        );
    }

    #[test]
    fn absent_block_keeps_the_producer_dormant() {
        assert!(take_coverage_authorization(&mut bootstrap(None)).is_none());
    }

    #[test]
    fn take_consumes_the_raw_block_exactly_once() {
        let mut response = bootstrap(Some(minted_block()));
        assert!(take_coverage_authorization(&mut response).is_some());
        assert!(response.fact_authorization.is_none());
        assert!(take_coverage_authorization(&mut response).is_none());
    }

    #[test]
    fn valid_block_resolves_the_bootstrap_origin_submit_url() {
        let coverage = taken(minted_block()).expect("valid block");
        assert_eq!(
            coverage.submit_url,
            "https://liskov.example/api/jobs/coverage-result"
        );
    }

    #[test]
    fn malformed_and_out_of_contract_blocks_stay_dormant() {
        let mutations: [(&str, Value); 10] = [
            ("domain", json!("proof.liskov.processor-fact-result.v1")),
            ("policyDigest", json!("sha256:short")),
            (
                "artifactDigest",
                json!(format!("SHA256:{}", "b".repeat(64))),
            ),
            ("challenge", json!(format!("0x{}", "11".repeat(16)))),
            ("challenge", json!("11".repeat(32))),
            ("expiresAtMs", json!(NOW - 5_001)),
            (
                "expiresAtMs",
                json!(NOW - 5_000 + MAX_AUTHORIZATION_LIFETIME_MS + 1),
            ),
            ("sequence", json!(MAX_SAFE_INTEGER + 1)),
            ("cycleId", json!("")),
            ("applicationId", json!("a".repeat(MAX_IDENTITY_BYTES + 1))),
        ];
        for (field, value) in mutations {
            let mut block = minted_block();
            block[field] = value;
            assert!(taken(block).is_none(), "mutated {field} must stay dormant");
        }
        assert!(taken(json!("not-an-object")).is_none());
        let mut unknown = minted_block();
        unknown["unknownField"] = json!(true);
        assert!(taken(unknown).is_none());
        let mut missing = minted_block();
        missing.as_object_mut().unwrap().remove("replaySubject");
        assert!(taken(missing).is_none());
    }

    #[test]
    fn misbound_identity_never_signs() {
        for field in ["deploymentId", "jobId", "processorId"] {
            let mut block = minted_block();
            block[field] = json!("someone-else");
            assert!(taken(block).is_none(), "foreign {field} must stay dormant");
        }
    }

    #[test]
    fn submit_url_may_confirm_but_never_redirect() {
        let cases = [
            "https://attacker.example/api/jobs/coverage-result",
            "http://liskov.example/api/jobs/coverage-result",
            "https://liskov.example/api/jobs/other-route",
            "https://liskov.example/api/jobs/coverage-result?next=1",
            "https://liskov.example/api/jobs/coverage-result#frag",
            "https://user@liskov.example/api/jobs/coverage-result",
            "https://liskov.example:8443/api/jobs/coverage-result",
        ];
        for submit_url in cases {
            let mut block = minted_block();
            block["submitUrl"] = json!(submit_url);
            assert!(
                taken(block).is_none(),
                "submitUrl {submit_url} must stay dormant"
            );
        }
    }

    #[test]
    fn producer_signs_and_submits_the_completed_envelope() {
        let coverage = taken(minted_block()).expect("valid block");
        let clock = FixedClock(NOW);
        let signer = RecordingSigner::succeeding();
        let delivery = RecordingDelivery::new(true);
        let android = FakeAndroid::default();
        let execution = FakeExecution::default();
        let outcome = run_coverage_producer(
            &coverage,
            observation(),
            &CoverageProducerDependencies {
                clock: &clock,
                signer: &signer,
                delivery: &delivery,
                android: &android,
                execution: &execution,
            },
        );
        assert_eq!(outcome, CoverageProducerOutcome::Submitted);

        let attempts = delivery.attempts.lock().unwrap();
        assert_eq!(attempts.len(), 1);
        let (url, body) = &attempts[0];
        assert_eq!(url, "https://liskov.example/api/jobs/coverage-result");
        assert!(body.len() <= MAX_SUBMISSION_BYTES);

        let mut submitted: Value = serde_json::from_slice(body).unwrap();
        let signature = submitted
            .as_object_mut()
            .unwrap()
            .remove("signature")
            .unwrap();
        assert_eq!(signature, json!(signer.signature.unwrap()));

        // The signed bytes are exactly the canonical body minus signature.
        let messages = signer.messages.lock().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0], canonical_json_bytes(&submitted));

        // Binding fields travel unaltered from the delivered block.
        let block = minted_block();
        for field in [
            "domain",
            "applicationId",
            "policyVersionId",
            "policyDigest",
            "artifactDigest",
            "cycleId",
            "target",
            "deploymentId",
            "jobId",
            "processorId",
            "probeVersion",
            "profileVersion",
            "sequence",
            "issuedAtMs",
            "expiresAtMs",
            "challenge",
            "replaySubject",
        ] {
            assert_eq!(submitted[field], block[field], "field {field}");
        }
        assert!(submitted.get("submitUrl").is_none());

        // The native-image target records the bootstrap exchange plus the
        // hardware capture, and the metric digest commits to the canonical
        // proof.liskov.processor-hardware.v1 payload the collectors read —
        // which itself never travels.
        assert_eq!(
            submitted["outcomes"],
            json!([
                {
                    "probeId": BOOTSTRAP_PROBE_ID,
                    "status": "succeeded",
                    "region": BOOTSTRAP_PROBE_REGION,
                    "startedAtMs": NOW - 9_000,
                    "completedAtMs": NOW - 7_750,
                    "durationMs": 1_250,
                    "bytesSent": 0,
                    "bytesReceived": 0,
                    "errors": [],
                },
                {
                    "probeId": HARDWARE_CAPTURE_PROBE_ID,
                    "status": "succeeded",
                    "region": BOOTSTRAP_PROBE_REGION,
                    "startedAtMs": NOW,
                    "completedAtMs": NOW,
                    "durationMs": 0,
                    "bytesSent": 0,
                    "bytesReceived": 0,
                    "errors": [],
                },
            ])
        );
        assert_eq!(android.0.load(Ordering::SeqCst), 1);
        assert_eq!(execution.0.load(Ordering::SeqCst), 1);
        let expected_digest =
            crate::hardware::hardware_metric_digest(&HardwareSourceReadingsV1::new(
                env!("CARGO_PKG_VERSION").into(),
                NOW,
                fixture_android(),
                fixture_execution(),
            ))
            .unwrap();
        assert_eq!(submitted["normalizedMetricDigest"], json!(expected_digest));
        for forbidden in ["SM-S135DL", "samsung", "a03su", "mt6765"] {
            assert!(
                !String::from_utf8_lossy(body).contains(forbidden),
                "hardware readings must never travel in the envelope"
            );
        }
    }

    #[test]
    fn javascript_target_commits_to_the_canonical_outcomes_without_collection() {
        let coverage = taken(javascript_block()).expect("valid block");
        let clock = FixedClock(NOW);
        let signer = RecordingSigner::succeeding();
        let delivery = RecordingDelivery::new(true);
        let android = FakeAndroid::default();
        let execution = FakeExecution::default();
        let outcome = run_coverage_producer(
            &coverage,
            observation(),
            &CoverageProducerDependencies {
                clock: &clock,
                signer: &signer,
                delivery: &delivery,
                android: &android,
                execution: &execution,
            },
        );
        assert_eq!(outcome, CoverageProducerOutcome::Submitted);
        assert_eq!(android.0.load(Ordering::SeqCst), 0);
        assert_eq!(execution.0.load(Ordering::SeqCst), 0);
        let attempts = delivery.attempts.lock().unwrap();
        let submitted: Value = serde_json::from_slice(&attempts[0].1).unwrap();
        assert_eq!(submitted["outcomes"].as_array().unwrap().len(), 1);
        assert_eq!(
            submitted["outcomes"][0]["probeId"],
            json!(BOOTSTRAP_PROBE_ID)
        );
        let expected_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(canonical_json_bytes(&submitted["outcomes"])))
        );
        assert_eq!(submitted["normalizedMetricDigest"], json!(expected_digest));
    }

    #[test]
    fn backwards_wall_clock_clamps_to_a_zero_duration_observation() {
        let coverage = taken(minted_block()).expect("valid block");
        let clock = FixedClock(NOW);
        let signer = RecordingSigner::succeeding();
        let delivery = RecordingDelivery::new(true);
        let android = FakeAndroid::default();
        let execution = FakeExecution::default();
        let outcome = run_coverage_producer(
            &coverage,
            CoverageContactObservation {
                started_at_ms: NOW,
                completed_at_ms: NOW - 4_000,
            },
            &CoverageProducerDependencies {
                clock: &clock,
                signer: &signer,
                delivery: &delivery,
                android: &android,
                execution: &execution,
            },
        );
        assert_eq!(outcome, CoverageProducerOutcome::Submitted);
        let attempts = delivery.attempts.lock().unwrap();
        let submitted: Value = serde_json::from_slice(&attempts[0].1).unwrap();
        assert_eq!(submitted["outcomes"][0]["startedAtMs"], json!(NOW - 4_000));
        assert_eq!(
            submitted["outcomes"][0]["completedAtMs"],
            json!(NOW - 4_000)
        );
        assert_eq!(submitted["outcomes"][0]["durationMs"], json!(0));
    }

    #[test]
    fn expired_authorization_neither_signs_nor_submits() {
        let coverage = taken(minted_block()).expect("valid block");
        let clock = FixedClock(NOW + 895_001);
        let signer = RecordingSigner::succeeding();
        let delivery = RecordingDelivery::new(true);
        let android = FakeAndroid::default();
        let execution = FakeExecution::default();
        let outcome = run_coverage_producer(
            &coverage,
            observation(),
            &CoverageProducerDependencies {
                clock: &clock,
                signer: &signer,
                delivery: &delivery,
                android: &android,
                execution: &execution,
            },
        );
        assert_eq!(outcome, CoverageProducerOutcome::AuthorizationExpired);
        assert!(signer.messages.lock().unwrap().is_empty());
        assert!(delivery.attempts.lock().unwrap().is_empty());
    }

    #[test]
    fn far_future_authorization_neither_signs_nor_submits() {
        let mut block = minted_block();
        block["issuedAtMs"] = json!(NOW + AUTHORIZATION_FUTURE_TOLERANCE_MS + 1);
        block["expiresAtMs"] = json!(NOW + AUTHORIZATION_FUTURE_TOLERANCE_MS + 895_000);
        let coverage = taken(block).expect("structurally valid block");
        let clock = FixedClock(NOW);
        let signer = RecordingSigner::succeeding();
        let delivery = RecordingDelivery::new(true);
        let android = FakeAndroid::default();
        let execution = FakeExecution::default();
        let outcome = run_coverage_producer(
            &coverage,
            observation(),
            &CoverageProducerDependencies {
                clock: &clock,
                signer: &signer,
                delivery: &delivery,
                android: &android,
                execution: &execution,
            },
        );
        assert_eq!(outcome, CoverageProducerOutcome::AuthorizationExpired);
        assert!(signer.messages.lock().unwrap().is_empty());
        assert!(delivery.attempts.lock().unwrap().is_empty());
    }

    #[test]
    fn signer_failure_never_submits() {
        let coverage = taken(minted_block()).expect("valid block");
        let clock = FixedClock(NOW);
        let signer = RecordingSigner::failing();
        let delivery = RecordingDelivery::new(true);
        let android = FakeAndroid::default();
        let execution = FakeExecution::default();
        let outcome = run_coverage_producer(
            &coverage,
            observation(),
            &CoverageProducerDependencies {
                clock: &clock,
                signer: &signer,
                delivery: &delivery,
                android: &android,
                execution: &execution,
            },
        );
        assert_eq!(outcome, CoverageProducerOutcome::SigningFailed);
        assert!(delivery.attempts.lock().unwrap().is_empty());
    }

    #[test]
    fn failed_delivery_retries_once_with_identical_bytes() {
        let coverage = taken(minted_block()).expect("valid block");
        let clock = FixedClock(NOW);
        let signer = RecordingSigner::succeeding();
        let delivery = RecordingDelivery::new(false);
        let android = FakeAndroid::default();
        let execution = FakeExecution::default();
        let outcome = run_coverage_producer(
            &coverage,
            observation(),
            &CoverageProducerDependencies {
                clock: &clock,
                signer: &signer,
                delivery: &delivery,
                android: &android,
                execution: &execution,
            },
        );
        assert_eq!(outcome, CoverageProducerOutcome::DeliveryFailed);
        let attempts = delivery.attempts.lock().unwrap();
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0], attempts[1]);
        assert_eq!(signer.messages.lock().unwrap().len(), 1);
    }

    #[test]
    fn expiry_between_attempts_stops_the_retry() {
        let coverage = taken(javascript_block()).expect("valid block");
        let clock = SequenceClock {
            values: Mutex::new(VecDeque::from([NOW, NOW, NOW + 895_001])),
            fallback: NOW + 895_001,
        };
        let signer = RecordingSigner::succeeding();
        let delivery = RecordingDelivery::new(false);
        let android = FakeAndroid::default();
        let execution = FakeExecution::default();
        let outcome = run_coverage_producer(
            &coverage,
            observation(),
            &CoverageProducerDependencies {
                clock: &clock,
                signer: &signer,
                delivery: &delivery,
                android: &android,
                execution: &execution,
            },
        );
        assert_eq!(outcome, CoverageProducerOutcome::AuthorizationExpired);
        assert_eq!(delivery.attempts.lock().unwrap().len(), 1);
    }

    #[test]
    fn diagnostic_lines_are_closed_and_redacted() {
        for outcome in [
            CoverageProducerOutcome::Submitted,
            CoverageProducerOutcome::ClockUnavailable,
            CoverageProducerOutcome::AuthorizationExpired,
            CoverageProducerOutcome::EnvelopeUnrepresentable,
            CoverageProducerOutcome::OversizeRefused,
            CoverageProducerOutcome::SigningFailed,
            CoverageProducerOutcome::DeliveryFailed,
        ] {
            let line = coverage_producer_line(outcome);
            assert!(line.starts_with(
                "liskov-runtime-contact: coverage \
                 {\"domain\":\"proof.liskov.processor-coverage-producer.v1\","
            ));
            for forbidden in ["0x", "challenge", "signature", "https://", "sha256"] {
                assert!(!line.contains(forbidden), "{line} must not leak");
            }
        }
    }
}
