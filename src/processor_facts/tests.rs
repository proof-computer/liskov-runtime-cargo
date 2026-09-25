use std::collections::VecDeque;
use std::os::unix::fs::symlink;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

const NOW: u64 = 1_800_000_000_000;
const HELPER_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn bootstrap(processor_facts: Option<Value>) -> RuntimeBootstrapResponse {
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
        secrets: None,
        runtime_env: None,
        supervision: None,
        logging: None,
        logging_outage_canary: false,
        diagnostics: None,
        access: None,
        processor_facts,
        fact_authorization: None,
    }
}

fn authorization_value(kinds: &[&str]) -> Value {
    json!({
        "domain": PROCESSOR_FACT_AUTHORIZATION_DOMAIN,
        "authorizationId": "authorization-1",
        "challenge": "11".repeat(32),
        "issuedAtMs": NOW - 1_000,
        "expiresAtMs": NOW + 299_000,
        "profile": CARGO_BASELINE_PROFILE,
        "catalogDigest": compiled_catalog_digest(),
        "helperContractEpoch": HELPER_CONTRACT_EPOCH,
        "expectedHelperVersion": env!("CARGO_PKG_VERSION"),
        "expectedHelperDigest": HELPER_DIGEST,
        "dueFactKinds": kinds,
    })
}

fn authorization(kinds: &[&str]) -> ProcessorFactAuthorization {
    serde_json::from_value(authorization_value(kinds)).unwrap()
}

fn binding() -> ProcessorFactBinding {
    ProcessorFactBinding::from_bootstrap(&bootstrap(None)).unwrap()
}

#[derive(Default)]
struct Counters {
    hash: AtomicUsize,
    android: AtomicUsize,
    execution: AtomicUsize,
    egress: AtomicUsize,
    coverage_hardware: AtomicUsize,
    signing: AtomicUsize,
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

impl SequenceClock {
    fn new(values: impl IntoIterator<Item = u64>, fallback: u64) -> Self {
        Self {
            values: Mutex::new(values.into_iter().collect()),
            fallback,
        }
    }
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

struct CountingHasher<'a> {
    counters: &'a Counters,
    digest: &'a str,
}

impl ExecutableHasher for CountingHasher<'_> {
    fn sha256(&self) -> Option<String> {
        self.counters.hash.fetch_add(1, Ordering::SeqCst);
        Some(self.digest.to_owned())
    }
}

struct CountingAndroid<'a>(&'a Counters);

impl AndroidFactCollector for CountingAndroid<'_> {
    fn collect(&self) -> AndroidCorroborationFact {
        self.0.android.fetch_add(1, Ordering::SeqCst);
        AndroidCorroborationFact::uniform(Availability::NotPresent)
    }
}

struct CountingExecution<'a>(&'a Counters);

impl ExecutionFactCollector for CountingExecution<'_> {
    fn collect(&self) -> ExecutionSurfaceFact {
        self.0.execution.fetch_add(1, Ordering::SeqCst);
        ExecutionSurfaceFact {
            architecture: Availability::Observed {
                value: "aarch64".into(),
            },
            word_size_bits: Availability::Observed { value: 64 },
            page_size_bytes: Availability::Observed { value: 4096 },
            kernel_abi: Availability::Observed {
                value: KernelAbi {
                    major: 4,
                    minor: 19,
                },
            },
            no_new_privs: Availability::Observed { value: true },
            seccomp: Availability::Observed {
                value: SeccompClass::Filter,
            },
            effective_capabilities: Availability::Observed {
                value: CapabilityClass::None,
            },
        }
    }
}

struct CountingEgress<'a>(&'a Counters);

impl EgressFactCollector for CountingEgress<'_> {
    fn collect(&self, endpoint: &str) -> ControlEgressFact {
        assert_eq!(
            endpoint,
            "https://liskov.example/api/jobs/processor-facts/egress"
        );
        self.0.egress.fetch_add(1, Ordering::SeqCst);
        ControlEgressFact {
            ipv4: closed_egress(EgressOutcome::Success, 1),
            ipv6: closed_egress(EgressOutcome::NoFamilyAddress, 1),
        }
    }
}

/// Every baseline test runs with this: a baseline grant that reached the raw
/// collector would panic the worker and fail the test.
struct UnreachableCoverageHardware;

impl CoverageHardwareCollector for UnreachableCoverageHardware {
    fn collect(&self) -> CoverageHardwareRawFact {
        panic!("a cargo-baseline-v1 grant read raw coverage hardware")
    }
}

struct RecordingSigner<'a> {
    counters: &'a Counters,
    inputs: Mutex<Vec<Vec<u8>>>,
}

impl FactSigner for RecordingSigner<'_> {
    fn sign_ed25519(&self, message: &[u8]) -> Option<String> {
        self.counters.signing.fetch_add(1, Ordering::SeqCst);
        self.inputs.lock().unwrap().push(message.to_vec());
        Some(format!("0x{}", "ab".repeat(64)))
    }
}

struct RecordingDelivery {
    responses: Mutex<VecDeque<bool>>,
    calls: Mutex<Vec<(String, Vec<u8>)>>,
}

impl RecordingDelivery {
    fn new(responses: impl IntoIterator<Item = bool>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
        }
    }
}

impl ResultDelivery for RecordingDelivery {
    fn deliver(&self, url: &str, body: &[u8]) -> bool {
        self.calls
            .lock()
            .unwrap()
            .push((url.to_owned(), body.to_vec()));
        self.responses.lock().unwrap().pop_front().unwrap_or(false)
    }
}

#[test]
fn missing_malformed_unknown_and_duplicate_authorization_are_dormant() {
    let mut absent = bootstrap(None);
    assert!(take_processor_fact_authorization(&mut absent).is_none());
    assert!(absent.processor_facts.is_none());

    for raw in [
        json!("not-an-object"),
        {
            let mut value = authorization_value(&["cargo_execution_surface.v1"]);
            value["unknown"] = json!(true);
            value
        },
        authorization_value(&["future_fact.v1"]),
        authorization_value(&["cargo_execution_surface.v1", "cargo_execution_surface.v1"]),
    ] {
        let mut response = bootstrap(Some(raw));
        assert!(take_processor_fact_authorization(&mut response).is_none());
        assert!(response.processor_facts.is_none());
    }
}

#[test]
fn absent_authorization_performs_no_hash_fact_signing_or_delivery_work() {
    let counters = Counters::default();
    let delivery = RecordingDelivery::new([true]);
    let mut response = bootstrap(None);

    if let Some(authorization) = take_processor_fact_authorization(&mut response) {
        let clock = FixedClock(NOW);
        let hasher = CountingHasher {
            counters: &counters,
            digest: HELPER_DIGEST,
        };
        let android = CountingAndroid(&counters);
        let execution = CountingExecution(&counters);
        let egress = CountingEgress(&counters);
        let signer = RecordingSigner {
            counters: &counters,
            inputs: Mutex::new(Vec::new()),
        };
        let dependencies = ProcessorFactWorkerDependencies {
            clock: &clock,
            executable_hasher: &hasher,
            android: &android,
            execution: &execution,
            egress: &egress,
            coverage_hardware: &UnreachableCoverageHardware,
            signer: &signer,
            delivery: &delivery,
        };
        run_processor_fact_worker(&authorization, &binding(), &dependencies).unwrap();
    }

    assert_eq!(counters.hash.load(Ordering::SeqCst), 0);
    assert_eq!(counters.android.load(Ordering::SeqCst), 0);
    assert_eq!(counters.execution.load(Ordering::SeqCst), 0);
    assert_eq!(counters.egress.load(Ordering::SeqCst), 0);
    assert_eq!(counters.signing.load(Ordering::SeqCst), 0);
    assert!(delivery.calls.lock().unwrap().is_empty());
}

#[test]
fn malformed_processor_facts_never_fail_the_authenticated_bootstrap() {
    let request = crate::protocol::SignedRuntimeBootstrapRequest {
        domain: crate::protocol::RUNTIME_BOOTSTRAP_REQUEST_DOMAIN_V2,
        job_id: "job".into(),
        processor_id: "processor".into(),
        nonce: "instance".into(),
        issued_at_ms: NOW,
        expires_at_ms: NOW + 60_000,
        signature: format!("0x{}", "ab".repeat(64)),
    };
    // RuntimeBootstrapResponse is deserialize-only, so build the wire value.
    let body = json!({
        "ok": true,
        "domain": "proof.liskov.runtime-bootstrap-response.v2",
        "applicationUid": "app-uid",
        "applicationId": "app-id",
        "policyDigest": "sha256:policy",
        "deploymentId": "deployment",
        "jobId": "job",
        "processorId": "processor",
        "runtimeInstanceId": "instance",
        "slipwayUrl": "https://liskov.example",
        "processorFacts": {"future": true},
    });
    let mut parsed =
        crate::protocol::validate_response(&request, &serde_json::to_vec(&body).unwrap()).unwrap();
    assert!(take_processor_fact_authorization(&mut parsed).is_none());
}

#[test]
fn expired_wrong_version_catalog_and_executable_digest_read_no_facts() {
    let counters = Counters::default();
    let clock = FixedClock(NOW);
    let hasher = CountingHasher {
        counters: &counters,
        digest: HELPER_DIGEST,
    };
    let android = CountingAndroid(&counters);
    let execution = CountingExecution(&counters);
    let egress = CountingEgress(&counters);
    let signer = RecordingSigner {
        counters: &counters,
        inputs: Mutex::new(Vec::new()),
    };
    let delivery = RecordingDelivery::new([]);
    let dependencies = ProcessorFactWorkerDependencies {
        clock: &clock,
        executable_hasher: &hasher,
        android: &android,
        execution: &execution,
        egress: &egress,
        coverage_hardware: &UnreachableCoverageHardware,
        signer: &signer,
        delivery: &delivery,
    };

    let mut expired = authorization(&["cargo_execution_surface.v1"]);
    expired.issued_at_ms = NOW - 300_000;
    expired.expires_at_ms = NOW;
    assert!(run_processor_fact_worker(&expired, &binding(), &dependencies).is_err());
    assert_eq!(counters.hash.load(Ordering::SeqCst), 0);

    let mut wrong_version = authorization(&["cargo_execution_surface.v1"]);
    wrong_version.expected_helper_version = "0.0.0".into();
    assert!(run_processor_fact_worker(&wrong_version, &binding(), &dependencies).is_err());
    assert_eq!(counters.hash.load(Ordering::SeqCst), 0);

    let mut wrong_catalog = authorization(&["cargo_execution_surface.v1"]);
    wrong_catalog.catalog_digest = format!("sha256:{}", "bb".repeat(32));
    assert!(run_processor_fact_worker(&wrong_catalog, &binding(), &dependencies).is_err());
    assert_eq!(counters.hash.load(Ordering::SeqCst), 0);

    let mut wrong_executable = authorization(&["cargo_execution_surface.v1"]);
    wrong_executable.expected_helper_digest = format!("sha256:{}", "cc".repeat(32));
    assert!(run_processor_fact_worker(&wrong_executable, &binding(), &dependencies).is_err());
    assert_eq!(counters.hash.load(Ordering::SeqCst), 1);
    assert_eq!(counters.execution.load(Ordering::SeqCst), 0);
    assert_eq!(counters.signing.load(Ordering::SeqCst), 0);
    assert!(delivery.calls.lock().unwrap().is_empty());
}

#[test]
fn only_due_dimensions_are_collected_and_ordered_by_catalog() {
    let counters = Counters::default();
    let clock = FixedClock(NOW);
    let hasher = CountingHasher {
        counters: &counters,
        digest: HELPER_DIGEST,
    };
    let android = CountingAndroid(&counters);
    let execution = CountingExecution(&counters);
    let egress = CountingEgress(&counters);
    let signer = RecordingSigner {
        counters: &counters,
        inputs: Mutex::new(Vec::new()),
    };
    let delivery = RecordingDelivery::new([true]);
    let dependencies = ProcessorFactWorkerDependencies {
        clock: &clock,
        executable_hasher: &hasher,
        android: &android,
        execution: &execution,
        egress: &egress,
        coverage_hardware: &UnreachableCoverageHardware,
        signer: &signer,
        delivery: &delivery,
    };
    let authorization =
        authorization(&["cargo_control_egress.v1", "cargo_android_corroboration.v1"]);
    run_processor_fact_worker(&authorization, &binding(), &dependencies).unwrap();
    assert_eq!(counters.android.load(Ordering::SeqCst), 1);
    assert_eq!(counters.execution.load(Ordering::SeqCst), 0);
    assert_eq!(counters.egress.load(Ordering::SeqCst), 1);
    let calls = delivery.calls.lock().unwrap();
    let body: Value = serde_json::from_slice(&calls[0].1).unwrap();
    assert_eq!(body["facts"][0]["kind"], "cargo_android_corroboration.v1");
    assert_eq!(body["facts"][1]["kind"], "cargo_control_egress.v1");
}

#[test]
fn result_signature_digest_bound_and_retry_bytes_are_canonical_and_identical() {
    let counters = Counters::default();
    let clock = FixedClock(NOW);
    let hasher = CountingHasher {
        counters: &counters,
        digest: HELPER_DIGEST,
    };
    let android = CountingAndroid(&counters);
    let execution = CountingExecution(&counters);
    let egress = CountingEgress(&counters);
    let signer = RecordingSigner {
        counters: &counters,
        inputs: Mutex::new(Vec::new()),
    };
    let delivery = RecordingDelivery::new([false, false]);
    let dependencies = ProcessorFactWorkerDependencies {
        clock: &clock,
        executable_hasher: &hasher,
        android: &android,
        execution: &execution,
        egress: &egress,
        coverage_hardware: &UnreachableCoverageHardware,
        signer: &signer,
        delivery: &delivery,
    };
    run_processor_fact_worker(
        &authorization(&["cargo_execution_surface.v1"]),
        &binding(),
        &dependencies,
    )
    .unwrap();

    let calls = delivery.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0], calls[1]);
    assert_eq!(
        calls[0].0,
        "https://liskov.example/api/jobs/processor-facts"
    );
    assert!(calls[0].1.len() <= MAX_RESULT_BYTES);
    let mut signed: Value = serde_json::from_slice(&calls[0].1).unwrap();
    assert!(signed.get("origin").is_none());
    assert!(signed.get("organizationId").is_none());
    assert!(signed.get("applicationId").is_none());
    let facts_digest = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(canonical_json_bytes(&signed["facts"])))
    );
    assert_eq!(signed["factsDigest"], facts_digest);
    signed.as_object_mut().unwrap().remove("signature");
    let signature_input = signer.inputs.lock().unwrap();
    assert_eq!(signature_input.as_slice(), &[canonical_json_bytes(&signed)]);
}

/// The three facts the shared vector carries, built from the closed
/// structs. Two Android fields are deliberately not `Observed`, so the
/// vector pins the value-less availability spelling as well.
fn shared_vector_facts() -> Vec<ProcessorFact> {
    let mut android = crate::hardware::tests::fixture_android();
    android.brand = Availability::NotPresent;
    android.product_name = Availability::SurfaceHidden;
    vec![
        ProcessorFact::Android(android),
        ProcessorFact::Execution(crate::hardware::tests::fixture_execution()),
        ProcessorFact::Egress(ControlEgressFact {
            ipv4: FamilyEgressObservation {
                outcome: EgressOutcome::Success,
                resolution_duration_ms: 11,
                request_duration_ms: Some(42),
                status_class: Some("2xx".into()),
            },
            ipv6: closed_egress(EgressOutcome::NoFamilyAddress, 11),
        }),
    ]
}

/// Cross-repo parity anchor: the unsigned body built from this crate's own
/// structs canonicalizes to exactly the bytes the `liskov-rs` admission
/// engine recomputes before it verifies a signature. The vector carries no
/// signature because the signature is excluded from its own input, and the
/// helper version is a literal so a release bump cannot move these bytes.
#[test]
fn matches_the_shared_processor_fact_result_vector() {
    let vector: Value =
        serde_json::from_str(include_str!("../../vectors/processor-fact-result-v1.json"))
            .expect("shared vector parses");
    let facts = shared_vector_facts();
    let facts_digest = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(canonical_json_bytes(
            &serde_json::to_value(&facts).unwrap()
        )))
    );
    let authorization_id = format!("pfa_{}", "a".repeat(64));
    let challenge = "b".repeat(64);
    let catalog_digest = format!("sha256:{}", "c".repeat(64));
    let helper_digest = format!("sha256:{}", "d".repeat(64));
    let unsigned = UnsignedProcessorFactResult {
        domain: PROCESSOR_FACT_RESULT_DOMAIN,
        authorization_id: &authorization_id,
        challenge: &challenge,
        deployment_id: "deployment-166327",
        job_id: r#"{"id":"166327","origin":{"kind":"Acurast"}}"#,
        processor_id: "5C81qALgzdeYUseGhtWPexwufYY83NcrnTazpFMcTizhuBb2",
        runtime_instance_id: "runtime-instance-9f2",
        profile: CARGO_BASELINE_PROFILE,
        catalog_digest: &catalog_digest,
        helper_contract_epoch: HELPER_CONTRACT_EPOCH,
        helper_version: "0.10.42",
        helper_digest: &helper_digest,
        capture_started_at_ms: 1_789_402_520_000,
        capture_completed_at_ms: 1_789_402_521_500,
        facts: &facts,
        facts_digest: &facts_digest,
    };
    let unsigned_value = serde_json::to_value(&unsigned).unwrap();
    assert_eq!(unsigned_value, vector["result"]);
    assert!(vector["result"].get("signature").is_none());
    assert_eq!(vector["result"]["factsDigest"], facts_digest);
    // The string, not the `Value`: equality on `Value` ignores key order,
    // and key order is exactly what a signature is sensitive to.
    let canonical = canonical_json_bytes(&unsigned_value);
    assert_eq!(
        std::str::from_utf8(&canonical).unwrap(),
        vector["canonicalSigningPayload"].as_str().unwrap(),
    );
    assert!(canonical.len() <= MAX_RESULT_BYTES);
}

/// SHA-256 of the checked-in `cargo-baseline-v1` catalog bytes. Every
/// authorization must name exactly this digest, so a byte change to the
/// catalog is a coordinated producer/consumer recut, not a test update.
const CARGO_BASELINE_CATALOG_DIGEST: &str =
    "sha256:3d66b4cba71a4ab57c197b80b523b2d172981bbf64ba62438ed9fdc0c5c5cb85";

/// Key sets a catalog field's value may carry: the availability envelope,
/// or one per-family egress observation. Anything else is a smuggled field.
const FIELD_ENVELOPES: [&[&str]; 2] = [
    &["status", "value"],
    &[
        "outcome",
        "requestDurationMs",
        "resolutionDurationMs",
        "statusClass",
    ],
];

fn baseline_catalog() -> Value {
    serde_json::from_str(include_str!("../../contracts/cargo-baseline-v1.json"))
        .expect("catalog parses")
}

/// `(kind, admitted fields)` in catalog order.
fn catalog_admissions(catalog: &Value) -> Vec<(&str, BTreeSet<&str>)> {
    catalog["facts"]
        .as_array()
        .expect("catalog facts")
        .iter()
        .map(|fact| {
            let fields = fact["fields"].as_array().expect("catalog fields");
            let admitted = fields
                .iter()
                .map(|field| field.as_str().expect("field name"))
                .collect::<BTreeSet<_>>();
            assert_eq!(admitted.len(), fields.len(), "duplicate catalog field");
            (fact["kind"].as_str().expect("catalog kind"), admitted)
        })
        .collect()
}

/// Every compiled `cargo-baseline-v1` kind. The match is exhaustive so a new
/// variant does not compile until it is placed here, where the catalog tests
/// meet it; the raw kind belongs to `coverage-hardware-v1` and its own catalog.
fn every_fact_kind() -> [ProcessorFactKind; 3] {
    [
        ProcessorFactKind::AndroidCorroboration,
        ProcessorFactKind::ExecutionSurface,
        ProcessorFactKind::ControlEgress,
    ]
    .map(|kind| match kind {
        ProcessorFactKind::AndroidCorroboration
        | ProcessorFactKind::ExecutionSurface
        | ProcessorFactKind::ControlEgress => {
            assert_eq!(kind.profile(), CARGO_BASELINE_PROFILE);
            kind
        }
        ProcessorFactKind::CoverageHardwareRaw => unreachable!("not a baseline kind"),
    })
}

/// Why `facts` is not exactly the catalog-admitted emission for `due`, or
/// `None` when it is: each due kind once, in catalog order, nothing else,
/// and each value carrying exactly the catalog's fields in a closed envelope.
fn catalog_violation(catalog: &Value, due: &BTreeSet<&str>, facts: &Value) -> Option<String> {
    let admissions = catalog_admissions(catalog);
    let expected = admissions
        .iter()
        .map(|(kind, _)| *kind)
        .filter(|kind| due.contains(kind))
        .collect::<Vec<_>>();
    if expected.len() != due.len() {
        return Some(format!("due kinds outside the catalog: {due:?}"));
    }
    let Some(facts) = facts.as_array() else {
        return Some("facts is not an array".into());
    };
    let emitted = facts
        .iter()
        .map(|fact| fact["kind"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    if emitted != expected {
        return Some(format!("emitted {emitted:?}, admitted {expected:?}"));
    }
    for (fact, (kind, admitted)) in facts
        .iter()
        .zip(admissions.iter().filter(|(kind, _)| due.contains(kind)))
    {
        let envelope = fact
            .as_object()
            .map(|object| object.keys().map(String::as_str).collect::<BTreeSet<_>>());
        if envelope != Some(BTreeSet::from(["kind", "value"])) {
            return Some(format!("{kind} envelope is {envelope:?}"));
        }
        let Some(value) = fact["value"].as_object() else {
            return Some(format!("{kind} value is not an object"));
        };
        let fields = value.keys().map(String::as_str).collect::<BTreeSet<_>>();
        if &fields != admitted {
            return Some(format!("{kind} carries {fields:?}, admitted {admitted:?}"));
        }
        for (field, observation) in value {
            let keys = observation
                .as_object()
                .map(|object| object.keys().map(String::as_str).collect::<BTreeSet<_>>());
            let closed = keys.as_ref().is_some_and(|keys| {
                FIELD_ENVELOPES
                    .iter()
                    .any(|envelope| keys.iter().all(|key| envelope.contains(key)))
            });
            if !closed {
                return Some(format!("{kind}.{field} carries {keys:?}"));
            }
        }
    }
    None
}

#[test]
fn catalog_names_exactly_the_compiled_profile_epoch_digest_and_fact_kinds() {
    let catalog = baseline_catalog();
    assert_eq!(
        catalog
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "domain",
            "facts",
            "forbidden",
            "helperContractEpoch",
            "profile"
        ]),
    );
    assert_eq!(catalog["domain"], "proof.liskov.processor-fact-catalog.v1");
    assert_eq!(catalog["profile"], CARGO_BASELINE_PROFILE);
    assert_eq!(catalog["helperContractEpoch"], HELPER_CONTRACT_EPOCH);
    assert_eq!(compiled_catalog_digest(), CARGO_BASELINE_CATALOG_DIGEST);

    for fact in catalog["facts"].as_array().unwrap() {
        assert_eq!(
            fact.as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["capture", "fields", "kind"]),
        );
        assert_eq!(fact["capture"], "authorized_due_only");
    }

    // Every catalog kind is a compiled kind, every compiled kind is in the
    // catalog, and catalog order is the kinds' own order.
    let kinds = catalog_admissions(&catalog)
        .into_iter()
        .map(|(kind, _)| {
            serde_json::from_value::<ProcessorFactKind>(json!(kind))
                .unwrap_or_else(|_| panic!("{kind} is not a compiled fact kind"))
        })
        .collect::<Vec<_>>();
    assert_eq!(kinds, every_fact_kind());
    assert!(kinds.is_sorted());
}

#[test]
fn worker_emits_exactly_the_catalog_admitted_set_for_every_due_subset() {
    let catalog = baseline_catalog();
    let kinds = catalog_admissions(&catalog)
        .into_iter()
        .map(|(kind, _)| kind)
        .collect::<Vec<_>>();
    for mask in 1..(1_usize << kinds.len()) {
        let due = kinds
            .iter()
            .enumerate()
            .filter(|(index, _)| mask & (1 << index) != 0)
            .map(|(_, kind)| *kind)
            .collect::<Vec<_>>();
        // Authorization array order must not reach the wire.
        let reversed = due.iter().rev().copied().collect::<Vec<_>>();
        for requested in [&due, &reversed] {
            let counters = Counters::default();
            let clock = FixedClock(NOW);
            let hasher = CountingHasher {
                counters: &counters,
                digest: HELPER_DIGEST,
            };
            let android = CountingAndroid(&counters);
            let execution = CountingExecution(&counters);
            let egress = CountingEgress(&counters);
            let signer = RecordingSigner {
                counters: &counters,
                inputs: Mutex::new(Vec::new()),
            };
            let delivery = RecordingDelivery::new([true]);
            let dependencies = ProcessorFactWorkerDependencies {
                clock: &clock,
                executable_hasher: &hasher,
                android: &android,
                execution: &execution,
                egress: &egress,
                coverage_hardware: &UnreachableCoverageHardware,
                signer: &signer,
                delivery: &delivery,
            };
            run_processor_fact_worker(&authorization(requested), &binding(), &dependencies)
                .unwrap();

            let calls = delivery.calls.lock().unwrap();
            let body: Value = serde_json::from_slice(&calls[0].1).unwrap();
            let due = due.iter().copied().collect::<BTreeSet<_>>();
            assert_eq!(
                catalog_violation(&catalog, &due, &body["facts"]),
                None,
                "{requested:?}"
            );
            assert_eq!(body["profile"], catalog["profile"]);
            assert_eq!(body["helperContractEpoch"], catalog["helperContractEpoch"]);
            assert_eq!(body["catalogDigest"], CARGO_BASELINE_CATALOG_DIGEST);
            for (kind, count) in [
                ("cargo_android_corroboration.v1", &counters.android),
                ("cargo_execution_surface.v1", &counters.execution),
                ("cargo_control_egress.v1", &counters.egress),
            ] {
                assert_eq!(
                    count.load(Ordering::SeqCst),
                    usize::from(due.contains(kind))
                );
            }
        }
    }
}

/// The vector's `catalogDigest` is a placeholder kept byte-identical with
/// `liskov-rs`; it pins canonical bytes, not this catalog, so it is checked
/// for shape only. The compiled digest is pinned above.
#[test]
fn shared_vector_carries_exactly_the_catalog_admitted_set_in_canonical_order() {
    let catalog = baseline_catalog();
    let vector: Value =
        serde_json::from_str(include_str!("../../vectors/processor-fact-result-v1.json"))
            .expect("shared vector parses");
    let result = &vector["result"];
    assert_eq!(result["domain"], PROCESSOR_FACT_RESULT_DOMAIN);
    assert_eq!(result["profile"], catalog["profile"]);
    assert_eq!(
        result["helperContractEpoch"],
        catalog["helperContractEpoch"]
    );
    assert!(valid_sha256(result["catalogDigest"].as_str().unwrap()));

    let every = catalog_admissions(&catalog)
        .into_iter()
        .map(|(kind, _)| kind)
        .collect::<BTreeSet<_>>();
    assert_eq!(catalog_violation(&catalog, &every, &result["facts"]), None);
    // Canonicalization sorts object keys, never the facts array.
    let canonical: Value =
        serde_json::from_str(vector["canonicalSigningPayload"].as_str().unwrap()).unwrap();
    assert_eq!(
        catalog_violation(&catalog, &every, &canonical["facts"]),
        None
    );
    assert_eq!(
        serde_json::to_value(shared_vector_facts()).unwrap(),
        result["facts"]
    );
}

#[test]
fn catalog_parity_rejects_unknown_forbidden_reordered_and_undue_facts() {
    let catalog = baseline_catalog();
    let vector: Value =
        serde_json::from_str(include_str!("../../vectors/processor-fact-result-v1.json")).unwrap();
    let facts = &vector["result"]["facts"];
    let every = catalog_admissions(&catalog)
        .into_iter()
        .map(|(kind, _)| kind)
        .collect::<BTreeSet<_>>();
    assert_eq!(catalog_violation(&catalog, &every, facts), None);

    let mutate = |change: &dyn Fn(&mut Vec<Value>)| {
        let mut changed = facts.as_array().unwrap().clone();
        change(&mut changed);
        Value::Array(changed)
    };
    for (case, candidate) in [
        (
            "unknown kind",
            mutate(&|facts| facts.push(json!({"kind": "future_fact.v1", "value": {}}))),
        ),
        (
            "forbidden field",
            mutate(&|facts| facts[0]["value"]["serial"] = json!({"status": "not_present"})),
        ),
        (
            "forbidden nested field",
            mutate(&|facts| facts[2]["value"]["ipv4"]["ipAddress"] = json!("192.0.2.1")),
        ),
        (
            "forbidden envelope field",
            mutate(&|facts| facts[1]["origin"] = json!("customer")),
        ),
        (
            "missing field",
            mutate(&|facts| {
                facts[0]["value"].as_object_mut().unwrap().remove("brand");
            }),
        ),
        ("reordered", mutate(&|facts| facts.swap(0, 1))),
        (
            "duplicate",
            mutate(&|facts| {
                let first = facts[0].clone();
                facts.insert(1, first);
            }),
        ),
        (
            "due kind absent",
            mutate(&|facts| {
                facts.remove(1);
            }),
        ),
    ] {
        assert!(
            catalog_violation(&catalog, &every, &candidate).is_some(),
            "{case} was accepted"
        );
    }

    let execution_only = BTreeSet::from(["cargo_execution_surface.v1"]);
    assert!(catalog_violation(&catalog, &execution_only, facts).is_some());
    let unknown_due = BTreeSet::from(["cargo_execution_surface.v1", "future_fact.v1"]);
    assert!(catalog_violation(&catalog, &unknown_due, facts).is_some());
}

#[derive(Default)]
struct NativeCounters {
    property_reads: AtomicUsize,
    linux_reads: AtomicUsize,
    dns: AtomicUsize,
    http: AtomicUsize,
}

struct CountingPropertyReader<'a> {
    counters: &'a NativeCounters,
    inner: FixturePropertyReader,
}

impl PropertyFileReader for CountingPropertyReader<'_> {
    fn read(
        &self,
        path: &str,
        budget: &mut PropertyReadBudget,
    ) -> Result<Vec<u8>, FileReadFailure> {
        self.counters.property_reads.fetch_add(1, Ordering::SeqCst);
        self.inner.read(path, budget)
    }
}

struct CountingLinux<'a>(&'a NativeCounters);

impl LinuxSystemReader for CountingLinux<'_> {
    fn page_size(&self) -> Result<u64, LinuxReadFailure> {
        self.0.linux_reads.fetch_add(1, Ordering::SeqCst);
        Ok(4096)
    }

    fn kernel_release(&self) -> Result<String, LinuxReadFailure> {
        self.0.linux_reads.fetch_add(1, Ordering::SeqCst);
        Ok("4.19.191".into())
    }

    fn proc_status(&self) -> Result<String, LinuxReadFailure> {
        self.0.linux_reads.fetch_add(1, Ordering::SeqCst);
        Err(LinuxReadFailure::SurfaceHidden)
    }
}

impl ExecutionFactCollector for CountingLinux<'_> {
    fn collect(&self) -> ExecutionSurfaceFact {
        collect_execution_surface(self)
    }
}

struct CountingNetwork<'a>(&'a NativeCounters);

impl EgressResolver for CountingNetwork<'_> {
    fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, EgressResolutionFailure> {
        self.0.dns.fetch_add(1, Ordering::SeqCst);
        Ok(vec!["192.0.2.1:443".parse().unwrap()])
    }
}

impl FamilyRequester for CountingNetwork<'_> {
    fn request(&self, _endpoint: &str, _address: SocketAddr) -> FamilyRequestResult {
        self.0.http.fetch_add(1, Ordering::SeqCst);
        family_result(EgressOutcome::Success)
    }
}

impl EgressFactCollector for CountingNetwork<'_> {
    fn collect(&self, endpoint: &str) -> ControlEgressFact {
        collect_control_egress(endpoint, self, self)
    }
}

/// The real collectors over counted native seams, so a zero count means
/// no property file, kernel surface, DNS lookup or egress request was
/// touched — and the positive control proves the counts can move.
#[test]
fn missing_or_refused_authorization_performs_no_native_read_dns_signature_or_http() {
    let expired = {
        let mut value = authorization_value(&["cargo_execution_surface.v1"]);
        value["issuedAtMs"] = json!(NOW - 300_000);
        value["expiresAtMs"] = json!(NOW);
        value
    };
    let wrong_catalog = {
        let mut value = authorization_value(&["cargo_execution_surface.v1"]);
        value["catalogDigest"] = json!(format!("sha256:{}", "bb".repeat(32)));
        value
    };
    let all_kinds = [
        "cargo_android_corroboration.v1",
        "cargo_execution_surface.v1",
        "cargo_control_egress.v1",
    ];
    let refused = [
        None,
        Some(authorization_value(&[])),
        Some(authorization_value(&["future_fact.v1"])),
        Some(authorization_value(&["cargo_serial.v1"])),
        Some(authorization_value(&["cargo_network_addresses.v1"])),
        Some(authorization_value(&["cargo_execution_surface.v2"])),
        Some(authorization_value(&["cargo_execution_surface"])),
        Some(authorization_value(&["CARGO_EXECUTION_SURFACE.V1"])),
        Some(authorization_value(&[
            "cargo_execution_surface.v1",
            "future_fact.v1",
        ])),
        Some(authorization_value(&[
            all_kinds[0],
            all_kinds[1],
            all_kinds[2],
            all_kinds[0],
        ])),
        Some(expired),
        Some(wrong_catalog),
    ];

    let run = |raw: Option<Value>| {
        let native = NativeCounters::default();
        let counters = Counters::default();
        let clock = FixedClock(NOW);
        let hasher = CountingHasher {
            counters: &counters,
            digest: HELPER_DIGEST,
        };
        let android = AndroidPropertyCollector {
            reader: CountingPropertyReader {
                counters: &native,
                inner: samsung_reader(true),
            },
        };
        let execution = CountingLinux(&native);
        let egress = CountingNetwork(&native);
        let signer = RecordingSigner {
            counters: &counters,
            inputs: Mutex::new(Vec::new()),
        };
        let delivery = RecordingDelivery::new([true]);
        let dependencies = ProcessorFactWorkerDependencies {
            clock: &clock,
            executable_hasher: &hasher,
            android: &android,
            execution: &execution,
            egress: &egress,
            coverage_hardware: &UnreachableCoverageHardware,
            signer: &signer,
            delivery: &delivery,
        };
        // The supervisor's own shape: only a parsed authorization runs.
        let mut response = bootstrap(raw);
        if let Some(authorization) = take_processor_fact_authorization(&mut response) {
            let _ = run_processor_fact_worker(&authorization, &binding(), &dependencies);
        }
        let delivered = delivery.calls.lock().unwrap().clone();
        (
            [
                native.property_reads.load(Ordering::SeqCst),
                native.linux_reads.load(Ordering::SeqCst),
                native.dns.load(Ordering::SeqCst),
                native.http.load(Ordering::SeqCst),
                counters.hash.load(Ordering::SeqCst),
                counters.signing.load(Ordering::SeqCst),
            ],
            delivered,
        )
    };

    for raw in refused {
        let shown = format!("{raw:?}");
        let (counts, delivered) = run(raw);
        assert_eq!(counts, [0; 6], "{shown}");
        assert!(delivered.is_empty(), "{shown}");
    }

    let (counts, delivered) = run(Some(authorization_value(&all_kinds)));
    let [property_reads, linux_reads, dns, http, hash, signing] = counts;
    assert!(property_reads > 0);
    assert_eq!(linux_reads, 3);
    assert_eq!((dns, http, hash, signing), (1, 1, 1, 1));
    assert_eq!(delivered.len(), 1);
    let body: Value = serde_json::from_slice(&delivered[0].1).unwrap();
    assert_eq!(
        catalog_violation(
            &baseline_catalog(),
            &BTreeSet::from(all_kinds),
            &body["facts"]
        ),
        None
    );
}

#[test]
fn failed_delivery_is_not_retried_after_authorization_expiry() {
    let counters = Counters::default();
    let authorization = authorization(&["cargo_execution_surface.v1"]);
    let clock = SequenceClock::new(
        [NOW, NOW, NOW, NOW, authorization.expires_at_ms],
        authorization.expires_at_ms,
    );
    let hasher = CountingHasher {
        counters: &counters,
        digest: HELPER_DIGEST,
    };
    let android = CountingAndroid(&counters);
    let execution = CountingExecution(&counters);
    let egress = CountingEgress(&counters);
    let signer = RecordingSigner {
        counters: &counters,
        inputs: Mutex::new(Vec::new()),
    };
    let delivery = RecordingDelivery::new([false, true]);
    let dependencies = ProcessorFactWorkerDependencies {
        clock: &clock,
        executable_hasher: &hasher,
        android: &android,
        execution: &execution,
        egress: &egress,
        coverage_hardware: &UnreachableCoverageHardware,
        signer: &signer,
        delivery: &delivery,
    };

    run_processor_fact_worker(&authorization, &binding(), &dependencies).unwrap();

    assert_eq!(delivery.calls.lock().unwrap().len(), 1);
}

fn samsung_reader(include_brand: bool) -> FixturePropertyReader {
    const CONTEXT: &str = "u:object_r:build_prop:s0";
    let names = ANDROID_PROPERTIES.map(|(name, _)| name);
    let mut values = vec![
        ("ro.build.version.release", "13"),
        ("ro.build.version.sdk", "33"),
        ("ro.build.version.security_patch", "2023-09-01"),
        ("ro.product.manufacturer", "samsung"),
        ("ro.product.model", "SM-S135DL"),
        ("ro.product.name", "a03sutfnssu"),
        ("ro.product.device", "a03su"),
        ("ro.board.platform", "mt6765"),
    ];
    if include_brand {
        values.push(("ro.product.brand", "samsung"));
    }
    FixturePropertyReader {
        files: BTreeMap::from([
            (
                PROPERTY_INFO_PATH.to_owned(),
                Ok(fixture_property_info(CONTEXT, &names)),
            ),
            (
                format!("{PROPERTY_DIRECTORY}/{CONTEXT}"),
                Ok(fixture_property_area(&values)),
            ),
        ]),
    }
}

#[test]
fn samsung_android_13_fixture_and_explicit_missing_field_are_exact() {
    let fact = collect_android_properties(&samsung_reader(false));
    assert!(matches!(fact.android_release, Availability::Observed { ref value } if value == "13"));
    assert!(matches!(fact.sdk_level, Availability::Observed { ref value } if value == "33"));
    assert!(
        matches!(fact.security_patch, Availability::Observed { ref value } if value == "2023-09-01")
    );
    assert!(matches!(fact.model, Availability::Observed { ref value } if value == "SM-S135DL"));
    assert!(matches!(fact.device, Availability::Observed { ref value } if value == "a03su"));
    assert!(
        matches!(fact.board_platform, Availability::Observed { ref value } if value == "mt6765")
    );
    assert!(matches!(fact.brand, Availability::NotPresent));
}

#[test]
fn property_info_and_area_corruption_fail_closed_by_class() {
    let mut truncated = samsung_reader(true);
    truncated
        .files
        .insert(PROPERTY_INFO_PATH.into(), Ok(vec![1, 0, 0]));
    assert!(matches!(
        collect_android_properties(&truncated).model,
        Availability::ParseError
    ));

    let mut unknown_info = samsung_reader(true);
    let info = unknown_info
        .files
        .get_mut(PROPERTY_INFO_PATH)
        .unwrap()
        .as_mut()
        .unwrap();
    patch_u32(info, 0, 2);
    assert!(matches!(
        collect_android_properties(&unknown_info).model,
        Availability::Unsupported
    ));

    let mut corrupt_offset = samsung_reader(true);
    let info = corrupt_offset
        .files
        .get_mut(PROPERTY_INFO_PATH)
        .unwrap()
        .as_mut()
        .unwrap();
    // Explicitly write the largest representable wire offset.
    info[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        collect_android_properties(&corrupt_offset).model,
        Availability::ParseError
    ));

    const CONTEXT: &str = "u:object_r:build_prop:s0";
    let mut unknown_area = samsung_reader(true);
    let area = unknown_area
        .files
        .get_mut(&format!("{PROPERTY_DIRECTORY}/{CONTEXT}"))
        .unwrap()
        .as_mut()
        .unwrap();
    patch_u32(area, 12, 0);
    assert!(matches!(
        collect_android_properties(&unknown_area).model,
        Availability::Unsupported
    ));

    let mut truncated_area = samsung_reader(true);
    truncated_area
        .files
        .get_mut(&format!("{PROPERTY_DIRECTORY}/{CONTEXT}"))
        .unwrap()
        .as_mut()
        .unwrap()
        .truncate(PROPERTY_AREA_HEADER_BYTES + 4);
    assert!(matches!(
        collect_android_properties(&truncated_area).model,
        Availability::ParseError
    ));
}

#[test]
fn unavailable_permission_unsafe_oversized_and_disappearing_files_are_explicit() {
    for (failure, expected) in [
        (FileReadFailure::NotFound, "surface_hidden"),
        (FileReadFailure::PermissionDenied, "permission_denied"),
        (FileReadFailure::UnsafeFile, "unsupported"),
        (FileReadFailure::TooLarge, "unsupported"),
        (FileReadFailure::Unavailable, "surface_hidden"),
    ] {
        let reader = FixturePropertyReader {
            files: BTreeMap::from([(PROPERTY_INFO_PATH.into(), Err(failure))]),
        };
        let value = serde_json::to_value(collect_android_properties(&reader)).unwrap();
        assert_eq!(value["model"]["status"], expected);
    }
}

#[test]
fn secure_reader_rejects_symlinks_without_following_them() {
    let unique = format!(
        "/tmp/liskov-property-symlink-{}-{}",
        std::process::id(),
        NOW
    );
    let _ = std::fs::remove_file(&unique);
    symlink("/etc/passwd", &unique).unwrap();
    let result = SecurePropertyFileReader.read(&unique, &mut PropertyReadBudget::new());
    std::fs::remove_file(&unique).unwrap();
    assert_eq!(result.unwrap_err(), FileReadFailure::UnsafeFile);
}

#[test]
fn property_info_absence_uses_only_compiled_contexts() {
    let area = fixture_property_area(&[("ro.product.model", "SM-S135DL")]);
    let reader = FixturePropertyReader {
        files: BTreeMap::from([(
            format!("{PROPERTY_DIRECTORY}/{}", FALLBACK_CONTEXTS[0]),
            Ok(area),
        )]),
    };
    let fact = collect_android_properties(&reader);
    assert!(matches!(fact.model, Availability::Observed { ref value } if value == "SM-S135DL"));
    assert!(matches!(fact.manufacturer, Availability::NotPresent));
}

#[test]
fn android_serializer_has_no_generic_or_forbidden_field_surface() {
    let serialized =
        serde_json::to_value(collect_android_properties(&samsung_reader(true))).unwrap();
    let object = serialized.as_object().unwrap();
    assert_eq!(object.len(), ANDROID_PROPERTIES.len());
    for forbidden in [
        "imei",
        "serial",
        "androidId",
        "advertisingId",
        "mac",
        "ssid",
        "ipAddress",
        "environment",
        "customer",
        "socName",
        "phoneName",
    ] {
        assert!(object.get(forbidden).is_none());
    }
}

struct FixtureLinux {
    page: Result<u64, LinuxReadFailure>,
    release: Result<String, LinuxReadFailure>,
    status: Result<String, LinuxReadFailure>,
}

impl LinuxSystemReader for FixtureLinux {
    fn page_size(&self) -> Result<u64, LinuxReadFailure> {
        self.page
    }

    fn kernel_release(&self) -> Result<String, LinuxReadFailure> {
        self.release.clone()
    }

    fn proc_status(&self) -> Result<String, LinuxReadFailure> {
        self.status.clone()
    }
}

#[test]
fn execution_surface_parses_page_kernel_status_and_capability_class() {
    for (capability, expected) in [
        ("0000000000000000", CapabilityClass::None),
        ("0000000000000001", CapabilityClass::Nonzero),
    ] {
        let fact = collect_execution_surface(&FixtureLinux {
            page: Ok(4096),
            release: Ok("4.19.157-perf+vendor-label".into()),
            status: Ok(format!(
                "Name:\ttest\nNoNewPrivs:\t1\nSeccomp:\t2\nCapEff:\t{capability}\n"
            )),
        });
        assert!(matches!(
            fact.page_size_bytes,
            Availability::Observed { value: 4096 }
        ));
        assert!(matches!(
            fact.kernel_abi,
            Availability::Observed {
                value: KernelAbi {
                    major: 4,
                    minor: 19
                }
            }
        ));
        assert!(matches!(
            fact.no_new_privs,
            Availability::Observed { value: true }
        ));
        assert!(matches!(
            fact.seccomp,
            Availability::Observed {
                value: SeccompClass::Filter
            }
        ));
        assert!(
            matches!(fact.effective_capabilities, Availability::Observed { ref value } if *value == expected)
        );
        let serialized = serde_json::to_string(&fact).unwrap();
        assert!(!serialized.contains("vendor-label"));
        assert!(!serialized.contains(capability));
    }
}

#[test]
fn execution_read_failures_and_malformed_values_are_explicit() {
    let fact = collect_execution_surface(&FixtureLinux {
        page: Err(LinuxReadFailure::Unsupported),
        release: Ok("raw-label".into()),
        status: Err(LinuxReadFailure::PermissionDenied),
    });
    assert!(matches!(fact.page_size_bytes, Availability::Unsupported));
    assert!(matches!(fact.kernel_abi, Availability::ParseError));
    assert!(matches!(fact.no_new_privs, Availability::PermissionDenied));
    assert!(matches!(fact.seccomp, Availability::PermissionDenied));
    assert!(matches!(
        fact.effective_capabilities,
        Availability::PermissionDenied
    ));
}

struct FixtureResolver(Result<Vec<SocketAddr>, EgressResolutionFailure>);

impl EgressResolver for FixtureResolver {
    fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, EgressResolutionFailure> {
        self.0.clone()
    }
}

struct FixtureRequester {
    ipv4: FamilyRequestResult,
    ipv6: FamilyRequestResult,
    calls: Mutex<Vec<SocketAddr>>,
}

impl FamilyRequester for FixtureRequester {
    fn request(&self, _endpoint: &str, address: SocketAddr) -> FamilyRequestResult {
        self.calls.lock().unwrap().push(address);
        if address.is_ipv4() {
            self.ipv4.clone()
        } else {
            self.ipv6.clone()
        }
    }
}

fn family_result(outcome: EgressOutcome) -> FamilyRequestResult {
    FamilyRequestResult {
        outcome,
        duration_ms: 7,
        status_class: (outcome == EgressOutcome::Success).then(|| "2xx".into()),
    }
}

#[test]
fn egress_handles_ipv4_ipv6_dual_stack_dns_failure_and_closed_outcomes() {
    let endpoint = "https://liskov.example/api/jobs/processor-facts/egress";
    let v4: SocketAddr = "192.0.2.1:443".parse().unwrap();
    let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    for (addresses, expected_v4, expected_v6, calls) in [
        (
            vec![v4],
            EgressOutcome::Success,
            EgressOutcome::NoFamilyAddress,
            1,
        ),
        (
            vec![v6],
            EgressOutcome::NoFamilyAddress,
            EgressOutcome::Success,
            1,
        ),
        (
            vec![v4, v6],
            EgressOutcome::Success,
            EgressOutcome::Success,
            2,
        ),
    ] {
        let requester = FixtureRequester {
            ipv4: family_result(EgressOutcome::Success),
            ipv6: family_result(EgressOutcome::Success),
            calls: Mutex::new(Vec::new()),
        };
        let fact = collect_control_egress(endpoint, &FixtureResolver(Ok(addresses)), &requester);
        assert_eq!(fact.ipv4.outcome, expected_v4);
        assert_eq!(fact.ipv6.outcome, expected_v6);
        assert_eq!(requester.calls.lock().unwrap().len(), calls);
        let serialized = serde_json::to_string(&fact).unwrap();
        assert!(!serialized.contains("192.0.2.1"));
        assert!(!serialized.contains("2001:db8"));
        assert!(!serialized.contains("liskov.example"));
    }

    let requester = FixtureRequester {
        ipv4: family_result(EgressOutcome::Success),
        ipv6: family_result(EgressOutcome::Success),
        calls: Mutex::new(Vec::new()),
    };
    let fact = collect_control_egress(
        endpoint,
        &FixtureResolver(Err(EgressResolutionFailure)),
        &requester,
    );
    assert_eq!(fact.ipv4.outcome, EgressOutcome::DnsFailed);
    assert_eq!(fact.ipv6.outcome, EgressOutcome::DnsFailed);
    assert!(requester.calls.lock().unwrap().is_empty());

    for outcome in [
        EgressOutcome::ConnectionFailed,
        EgressOutcome::Timeout,
        EgressOutcome::TransportOrTlsFailed,
        EgressOutcome::HttpUnexpectedStatus,
        EgressOutcome::ResponseTooLarge,
        EgressOutcome::InternalError,
    ] {
        let requester = FixtureRequester {
            ipv4: family_result(outcome),
            ipv6: family_result(EgressOutcome::Success),
            calls: Mutex::new(Vec::new()),
        };
        let fact = collect_control_egress(endpoint, &FixtureResolver(Ok(vec![v4])), &requester);
        assert_eq!(fact.ipv4.outcome, outcome);
    }
}

#[test]
fn future_clock_tolerance_and_five_minute_lifetime_are_strict() {
    let mut value = authorization_value(&["cargo_execution_surface.v1"]);
    value["issuedAtMs"] = json!(NOW + AUTHORIZATION_FUTURE_TOLERANCE_MS + 1);
    value["expiresAtMs"] = json!(NOW + AUTHORIZATION_FUTURE_TOLERANCE_MS + 2);
    let auth: ProcessorFactAuthorization = serde_json::from_value(value).unwrap();
    assert!(!auth.valid_at(NOW));

    let mut too_long = authorization_value(&["cargo_execution_surface.v1"]);
    too_long["issuedAtMs"] = json!(NOW);
    too_long["expiresAtMs"] = json!(NOW + MAX_AUTHORIZATION_LIFETIME_MS + 1);
    let mut response = bootstrap(Some(too_long));
    assert!(take_processor_fact_authorization(&mut response).is_none());
}

fn coverage_authorization_value() -> Value {
    let mut value = authorization_value(&["coverage_hardware_raw.v1"]);
    value["profile"] = json!(COVERAGE_HARDWARE_PROFILE);
    value["catalogDigest"] = json!(compiled_coverage_hardware_catalog_digest());
    value
}

fn coverage_authorization() -> ProcessorFactAuthorization {
    serde_json::from_value(coverage_authorization_value()).unwrap()
}

struct CountingCoverageHardware<'a> {
    counters: &'a Counters,
    reading: fn() -> CoverageHardwareRawFact,
}

impl CoverageHardwareCollector for CountingCoverageHardware<'_> {
    fn collect(&self) -> CoverageHardwareRawFact {
        self.counters
            .coverage_hardware
            .fetch_add(1, Ordering::SeqCst);
        (self.reading)()
    }
}

fn motorola_reading() -> CoverageHardwareRawFact {
    coverage_hardware::collect_coverage_hardware(&coverage_hardware::tests::motorola())
}

/// Run `authorization` with counting collectors whose raw reading is
/// `reading`, and return the delivery record.
fn run_with_counters(
    authorization: &ProcessorFactAuthorization,
    counters: &Counters,
    reading: fn() -> CoverageHardwareRawFact,
    responses: &[bool],
) -> (Result<(), ()>, RecordingDelivery, Vec<Vec<u8>>) {
    let clock = FixedClock(NOW);
    let hasher = CountingHasher {
        counters,
        digest: HELPER_DIGEST,
    };
    let android = CountingAndroid(counters);
    let execution = CountingExecution(counters);
    let egress = CountingEgress(counters);
    let coverage_hardware = CountingCoverageHardware { counters, reading };
    let signer = RecordingSigner {
        counters,
        inputs: Mutex::new(Vec::new()),
    };
    let delivery = RecordingDelivery::new(responses.iter().copied());
    let dependencies = ProcessorFactWorkerDependencies {
        clock: &clock,
        executable_hasher: &hasher,
        android: &android,
        execution: &execution,
        egress: &egress,
        coverage_hardware: &coverage_hardware,
        signer: &signer,
        delivery: &delivery,
    };
    let result = run_processor_fact_worker(authorization, &binding(), &dependencies);
    let inputs = signer.inputs.into_inner().unwrap();
    (result, delivery, inputs)
}

#[test]
fn a_coverage_hardware_grant_reads_only_the_raw_document_and_signs_it_once() {
    let mut response = bootstrap(Some(coverage_authorization_value()));
    let authorization = take_processor_fact_authorization(&mut response).unwrap();
    let counters = Counters::default();
    let (result, delivery, inputs) =
        run_with_counters(&authorization, &counters, motorola_reading, &[false, false]);
    result.unwrap();

    assert_eq!(counters.coverage_hardware.load(Ordering::SeqCst), 1);
    assert_eq!(counters.android.load(Ordering::SeqCst), 0);
    assert_eq!(counters.execution.load(Ordering::SeqCst), 0);
    assert_eq!(counters.egress.load(Ordering::SeqCst), 0);
    assert_eq!(counters.signing.load(Ordering::SeqCst), 1);

    // Two refused attempts carry byte-identical bodies under one signature.
    let calls = delivery.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0], calls[1]);
    assert_eq!(
        calls[0].0,
        "https://liskov.example/api/jobs/processor-facts"
    );
    assert!(calls[0].1.len() <= MAX_RESULT_BYTES);
    let mut signed: Value = serde_json::from_slice(&calls[0].1).unwrap();
    assert_eq!(signed["profile"], COVERAGE_HARDWARE_PROFILE);
    assert_eq!(
        signed["catalogDigest"],
        compiled_coverage_hardware_catalog_digest()
    );
    assert!(signed.get("origin").is_none());
    let payload: Value =
        serde_json::from_str(include_str!("../../vectors/processor-hardware-raw-v1.json")).unwrap();
    assert_eq!(
        signed["facts"],
        json!([{"kind": "coverage_hardware_raw.v1", "value": payload}])
    );
    signed.as_object_mut().unwrap().remove("signature");
    assert_eq!(inputs, [canonical_json_bytes(&signed)]);
}

#[test]
fn a_baseline_grant_never_reads_raw_hardware() {
    let counters = Counters::default();
    let (result, delivery, _) = run_with_counters(
        &authorization(&[
            "cargo_android_corroboration.v1",
            "cargo_execution_surface.v1",
            "cargo_control_egress.v1",
        ]),
        &counters,
        motorola_reading,
        &[true],
    );
    result.unwrap();
    assert_eq!(counters.coverage_hardware.load(Ordering::SeqCst), 0);
    assert_eq!(counters.android.load(Ordering::SeqCst), 1);
    let calls = delivery.calls.lock().unwrap();
    let body: Value = serde_json::from_slice(&calls[0].1).unwrap();
    assert_eq!(body["profile"], CARGO_BASELINE_PROFILE);
    assert!(
        body["facts"]
            .as_array()
            .unwrap()
            .iter()
            .all(|fact| fact["kind"] != "coverage_hardware_raw.v1")
    );
}

#[test]
fn mixed_profiles_and_kinds_are_no_grant_at_all() {
    let raw_in_baseline = authorization_value(&["coverage_hardware_raw.v1"]);
    let raw_beside_baseline =
        authorization_value(&["cargo_execution_surface.v1", "coverage_hardware_raw.v1"]);
    let mut baseline_in_raw = coverage_authorization_value();
    baseline_in_raw["dueFactKinds"] = json!(["cargo_execution_surface.v1"]);
    let mut raw_twice = coverage_authorization_value();
    raw_twice["dueFactKinds"] = json!(["coverage_hardware_raw.v1", "coverage_hardware_raw.v1"]);
    let mut raw_with_baseline = coverage_authorization_value();
    raw_with_baseline["dueFactKinds"] =
        json!(["coverage_hardware_raw.v1", "cargo_android_corroboration.v1"]);
    let mut raw_empty = coverage_authorization_value();
    raw_empty["dueFactKinds"] = json!([]);
    let mut unknown_profile = coverage_authorization_value();
    unknown_profile["profile"] = json!("coverage-hardware-v2");

    for raw in [
        raw_in_baseline,
        raw_beside_baseline,
        baseline_in_raw,
        raw_twice,
        raw_with_baseline,
        raw_empty,
        unknown_profile,
    ] {
        let mut response = bootstrap(Some(raw.clone()));
        assert!(
            take_processor_fact_authorization(&mut response).is_none(),
            "{raw}"
        );
        // Even handed straight to the worker, nothing is hashed or read.
        let Ok(parsed) = serde_json::from_value::<ProcessorFactAuthorization>(raw) else {
            continue;
        };
        let counters = Counters::default();
        let (result, delivery, _) =
            run_with_counters(&parsed, &counters, motorola_reading, &[true]);
        assert!(result.is_err());
        assert_eq!(counters.hash.load(Ordering::SeqCst), 0);
        assert_eq!(counters.coverage_hardware.load(Ordering::SeqCst), 0);
        assert_eq!(counters.execution.load(Ordering::SeqCst), 0);
        assert!(delivery.calls.lock().unwrap().is_empty());
    }
}

#[test]
fn wrong_catalog_helper_or_expired_raw_grants_read_nothing() {
    let wrong_catalog = {
        let mut grant = coverage_authorization();
        grant.catalog_digest = compiled_catalog_digest();
        grant
    };
    let baseline_with_raw_catalog = {
        let mut grant = authorization(&["cargo_execution_surface.v1"]);
        grant.catalog_digest = compiled_coverage_hardware_catalog_digest();
        grant
    };
    let wrong_version = {
        let mut grant = coverage_authorization();
        grant.expected_helper_version = "0.0.0".into();
        grant
    };
    let expired = {
        let mut grant = coverage_authorization();
        grant.issued_at_ms = NOW - 300_000;
        grant.expires_at_ms = NOW;
        grant
    };
    for grant in [
        wrong_catalog,
        baseline_with_raw_catalog,
        wrong_version,
        expired,
    ] {
        let counters = Counters::default();
        let (result, delivery, _) = run_with_counters(&grant, &counters, motorola_reading, &[true]);
        assert!(result.is_err());
        assert_eq!(counters.hash.load(Ordering::SeqCst), 0);
        assert_eq!(counters.coverage_hardware.load(Ordering::SeqCst), 0);
        assert_eq!(counters.execution.load(Ordering::SeqCst), 0);
        assert_eq!(counters.signing.load(Ordering::SeqCst), 0);
        assert!(delivery.calls.lock().unwrap().is_empty());
    }

    // A helper whose own digest is not the pinned one hashes itself once and
    // reads nothing.
    let mut wrong_helper = coverage_authorization();
    wrong_helper.expected_helper_digest = format!("sha256:{}", "cc".repeat(32));
    let counters = Counters::default();
    let (result, delivery, _) =
        run_with_counters(&wrong_helper, &counters, motorola_reading, &[true]);
    assert!(result.is_err());
    assert_eq!(counters.hash.load(Ordering::SeqCst), 1);
    assert_eq!(counters.coverage_hardware.load(Ordering::SeqCst), 0);
    assert_eq!(counters.signing.load(Ordering::SeqCst), 0);
    assert!(delivery.calls.lock().unwrap().is_empty());
}

#[test]
fn an_oversized_raw_reading_is_never_signed_or_sent() {
    let counters = Counters::default();
    let (result, delivery, inputs) = run_with_counters(
        &coverage_authorization(),
        &counters,
        coverage_hardware::tests::oversized_reading,
        &[true],
    );
    assert!(result.is_err());
    assert_eq!(counters.coverage_hardware.load(Ordering::SeqCst), 1);
    assert_eq!(counters.signing.load(Ordering::SeqCst), 0);
    assert!(inputs.is_empty());
    assert!(delivery.calls.lock().unwrap().is_empty());
}

#[test]
fn an_adr_0072_coverage_grant_alone_never_authorizes_raw_capture() {
    // The raw grant in the coverage slot is not a processor-fact grant.
    let mut response = bootstrap(None);
    response.fact_authorization = Some(coverage_authorization_value());
    assert!(take_processor_fact_authorization(&mut response).is_none());
    assert!(response.fact_authorization.is_some());

    // Beside a baseline grant it changes nothing about what that grant reads.
    let mut response = bootstrap(Some(authorization_value(&["cargo_execution_surface.v1"])));
    response.fact_authorization = Some(coverage_authorization_value());
    let authorization = take_processor_fact_authorization(&mut response).unwrap();
    let counters = Counters::default();
    let (result, _, _) = run_with_counters(&authorization, &counters, motorola_reading, &[true]);
    result.unwrap();
    assert_eq!(counters.execution.load(Ordering::SeqCst), 1);
    assert_eq!(counters.coverage_hardware.load(Ordering::SeqCst), 0);
}
