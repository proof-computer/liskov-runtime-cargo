use super::*;
use crate::bridge::BridgeError;
use crate::contact::ContactError;
use crate::protocol::RUNTIME_BOOTSTRAP_RESPONSE_DOMAIN_V2;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::io::{self, Cursor};
use std::sync::Mutex;

const ARCHIVE: &[u8] = include_bytes!("../../vectors/payload-archive-v1.tar.gz");
fn fixture() -> Value {
    serde_json::from_str(include_str!("../../vectors/payload-download-v1.json")).unwrap()
}
fn offer() -> AuthenticatedPayloadContext {
    let f: Value =
        serde_json::from_str(include_str!("../../vectors/payload-descriptor-v1.json")).unwrap();
    AuthenticatedPayloadContext {
        capability_version: 1,
        service_origin: "https://artifacts.example".into(),
        binding: serde_json::from_value(fixture()["expectedBinding"].clone()).unwrap(),
        descriptor_digest: f["descriptorDigest"].as_str().unwrap().into(),
        canonical_descriptor: f["canonicalUtf8"].as_str().unwrap().as_bytes().to_vec(),
    }
}
fn job() -> String {
    serde_json::to_string(&json!({"origin":{"kind":"Acurast","source":format!("0x{}", "11".repeat(32))}, "id": u128::MAX.to_string()})).unwrap()
}
fn bootstrap() -> RuntimeBootstrapResponse {
    serde_json::from_value(
        json!({"ok":true, "domain":RUNTIME_BOOTSTRAP_RESPONSE_DOMAIN_V2,
        "applicationUid":"app-0123456789abcdef0123456789abcdef", "applicationId":"app",
        "policyDigest":format!("sha256:{}", "22".repeat(32)), "deploymentId":"deployment",
        "jobId":job(), "processorId":"processor-fixture", "runtimeInstanceId":"incarnation-fixture",
        "slipwayUrl":"https://control.example"}),
    )
    .unwrap()
}
fn context() -> PayloadContext {
    PayloadContext::negotiate(&bootstrap(), offer(), 8 * 1024 * 1024, 1_700_000_000_000).unwrap()
}
fn policy() -> PayloadTransferPolicy {
    PayloadTransferPolicy {
        max_attempts: 3,
        max_elapsed: Duration::from_secs(10),
        retry_delay: Duration::from_millis(1),
    }
}
struct Runtime {
    time: Mutex<u64>,
    elapsed: Mutex<Duration>,
    nonce: Mutex<u8>,
    repeated: bool,
}
impl Default for Runtime {
    fn default() -> Self {
        Self {
            time: Mutex::new(1_700_000_000_000),
            elapsed: Mutex::new(Duration::ZERO),
            nonce: Mutex::new(0),
            repeated: false,
        }
    }
}
impl ContactRuntime for Runtime {
    fn unix_time_ms(&self) -> Result<u64, ContactError> {
        Ok(*self.time.lock().unwrap())
    }
    fn elapsed(&self) -> Duration {
        *self.elapsed.lock().unwrap()
    }
    fn fill_random(&self, bytes: &mut [u8]) -> Result<(), ContactError> {
        let mut n = self.nonce.lock().unwrap();
        if !self.repeated {
            *n += 1;
        }
        bytes.fill(*n);
        Ok(())
    }
    fn sleep(&self, d: Duration) {
        *self.elapsed.lock().unwrap() += d;
        *self.time.lock().unwrap() += d.as_millis() as u64;
    }
}
struct AdvancingClock {
    runtime: Runtime,
    calls: Mutex<usize>,
    advance_at: usize,
    advanced_time_ms: u64,
}
impl ContactRuntime for AdvancingClock {
    fn unix_time_ms(&self) -> Result<u64, ContactError> {
        let mut n = self.calls.lock().unwrap();
        *n += 1;
        Ok(if *n >= self.advance_at {
            self.advanced_time_ms
        } else {
            1_700_000_000_000
        })
    }
    fn elapsed(&self) -> Duration {
        self.runtime.elapsed()
    }
    fn fill_random(&self, b: &mut [u8]) -> Result<(), ContactError> {
        self.runtime.fill_random(b)
    }
    fn sleep(&self, d: Duration) {
        self.runtime.sleep(d)
    }
}
#[derive(Default)]
struct FakeBridge {
    calls: Mutex<Vec<(String, Value)>>,
    wrong_identity: bool,
    bad_signature: bool,
}
impl Bridge for FakeBridge {
    fn call(&self, method: &str, params: Value) -> Result<Value, BridgeError> {
        self.calls
            .lock()
            .unwrap()
            .push((method.into(), params.clone()));
        let seed = hex::decode(fixture()["testOnlySeedHex"].as_str().unwrap()).unwrap();
        let key = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let public = hex::encode(key.public_key().as_ref());
        Ok(match method {
            "deployment_id" => serde_json::from_str(&job()).unwrap(),
            "deployment_publicKeys" => json!({"publicKeys":{"ed25519":public}}),
            "deployment_assignedProcessors" => {
                let processor = if self.wrong_identity {
                    "wrong"
                } else {
                    "processor-fixture"
                };
                json!({"processors":{processor:{"ed25519":public}}})
            }
            "signer_sign" => {
                assert_eq!(params[0]["curve"], "ed25519");
                let bytes = hex::decode(params[0]["bytes"].as_str().unwrap()).unwrap();
                json!({"bytes":if self.bad_signature { "00".into() } else { format!("0x{}",hex::encode(key.sign(&bytes).as_ref())) }})
            }
            _ => panic!("unexpected bridge operation"),
        })
    }
}
#[derive(Clone, Copy)]
enum Behavior {
    Complete,
    Chunked,
    Interrupt,
    Empty,
    Transport,
    Replay,
    Redirect,
    WrongRange,
    WrongDescriptor,
    WrongLength,
    Corrupt,
    Extra,
    Encoded,
}
struct FakeHttp {
    behaviors: Mutex<Vec<Behavior>>,
    requests: Mutex<Vec<SignedPayloadDownloadRequestV1>>,
}
impl FakeHttp {
    fn new(b: Vec<Behavior>) -> Self {
        Self {
            behaviors: Mutex::new(b),
            requests: Mutex::new(vec![]),
        }
    }
}
struct Interrupted {
    bytes: Cursor<Vec<u8>>,
}
struct Chunked(Cursor<Vec<u8>>);
impl Read for Chunked {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let count = b.len().min(10);
        self.0.read(&mut b[..count])
    }
}
impl Read for Interrupted {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if self.bytes.position() == self.bytes.get_ref().len() as u64 {
            Err(io::Error::other("offline interruption"))
        } else {
            self.bytes.read(b)
        }
    }
}
impl PayloadHttpClient for FakeHttp {
    fn get(
        &self,
        url: &str,
        body: &[u8],
        range_header: Option<&str>,
    ) -> Result<PayloadHttpResponse, PayloadHttpError> {
        let envelope = SignedPayloadDownloadRequestV1::parse(body).unwrap();
        assert_eq!(
            url,
            format!(
                "https://artifacts.example{}",
                envelope.request.request_target
            )
        );
        envelope
            .request
            .validate_transport(
                "GET",
                &envelope.request.request_target,
                range_header,
                envelope.request.issued_at_ms,
            )
            .unwrap();
        let key = hex::decode(fixture()["publicKeyHex"].as_str().unwrap()).unwrap();
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
            .verify(
                &envelope.request.message().unwrap(),
                &hex::decode(&envelope.signature).unwrap(),
            )
            .unwrap();
        self.requests.lock().unwrap().push(envelope.clone());
        let behavior = self.behaviors.lock().unwrap().remove(0);
        if matches!(behavior, Behavior::Transport) {
            return Err(PayloadHttpError::Transport);
        }
        let selection = envelope.request.range.select(ARCHIVE.len() as u64).unwrap();
        let start = selection.offset as usize;
        let mut bytes = ARCHIVE[start..].to_vec();
        let mut response = PayloadHttpResponse {
            status: if start == 0 { 200 } else { 206 },
            content_length: Some(selection.length),
            content_range: if start == 0 {
                None
            } else {
                Some(format!(
                    "bytes {start}-{}/{}",
                    ARCHIVE.len() - 1,
                    ARCHIVE.len()
                ))
            },
            content_encoding: None,
            descriptor_digest: context().descriptor_digest,
            artifact_digest: context().binding.artifact_digest,
            body: Box::new(Cursor::new(vec![])),
        };
        match behavior {
            Behavior::Replay => response.status = 403,
            Behavior::Redirect => response.status = 302,
            Behavior::WrongRange => response.content_range = Some("bytes 0-0/1".into()),
            Behavior::WrongDescriptor => {
                response.descriptor_digest = format!("sha256:{}", "ff".repeat(32))
            }
            Behavior::WrongLength => response.content_length = Some(0),
            Behavior::Corrupt => bytes[0] ^= 1,
            Behavior::Extra => bytes.push(0),
            Behavior::Encoded => response.content_encoding = Some("gzip".into()),
            Behavior::Empty => bytes.clear(),
            _ => {}
        }
        response.body = if matches!(behavior, Behavior::Interrupt) {
            bytes.truncate(10);
            Box::new(Interrupted {
                bytes: Cursor::new(bytes),
            })
        } else if matches!(behavior, Behavior::Chunked) {
            Box::new(Chunked(Cursor::new(bytes)))
        } else {
            Box::new(Cursor::new(bytes))
        };
        Ok(response)
    }
}
#[test]
fn interruption_resumes_exact_offset_with_fresh_signatures_and_one_identity_discovery() {
    let http = FakeHttp::new(vec![
        Behavior::Interrupt,
        Behavior::Transport,
        Behavior::Complete,
    ]);
    let bridge = FakeBridge::default();
    let mut sink = vec![];
    let verified = download_payload(
        &context(),
        &bridge,
        &http,
        &Runtime::default(),
        &mut sink,
        policy(),
    )
    .unwrap();
    assert_eq!(sink, ARCHIVE);
    assert_eq!(verified.size_bytes, ARCHIVE.len() as u64);
    let requests = http.requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[1].request.range,
        PayloadDownloadRangeV1::Bytes {
            start: 10,
            end_inclusive: ARCHIVE.len() as u64 - 1
        }
    );
    assert_eq!(requests[1].request.range, requests[2].request.range);
    assert_ne!(requests[1].request.nonce, requests[2].request.nonce);
    assert_ne!(requests[1].signature, requests[2].signature);
    assert_eq!(
        bridge
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, _)| m == "deployment_id")
            .count(),
        1
    );
}
#[test]
fn responses_never_publish_incomplete_corrupt_unbound_redirected_or_replayed_bytes() {
    for (behavior, expected) in [
        (Behavior::Replay, PayloadError::Refused),
        (Behavior::Redirect, PayloadError::Response),
        (Behavior::WrongRange, PayloadError::Response),
        (Behavior::WrongDescriptor, PayloadError::Response),
        (Behavior::WrongLength, PayloadError::Response),
        (Behavior::Corrupt, PayloadError::Integrity),
        (Behavior::Extra, PayloadError::Response),
        (Behavior::Encoded, PayloadError::Response),
    ] {
        assert_eq!(
            download_payload(
                &context(),
                &FakeBridge::default(),
                &FakeHttp::new(vec![behavior]),
                &Runtime::default(),
                &mut vec![],
                policy()
            ),
            Err(expected)
        );
    }
    assert_eq!(
        download_payload(
            &context(),
            &FakeBridge::default(),
            &FakeHttp::new(vec![Behavior::Empty; 3]),
            &Runtime::default(),
            &mut vec![],
            policy()
        ),
        Err(PayloadError::Incomplete)
    );
}
#[test]
fn negotiation_refuses_unknown_modes_origins_descriptors_and_context_bindings() {
    for origin in [
        "http://artifacts.example",
        "https://u:p@artifacts.example",
        "https://artifacts.example/path",
        "https://artifacts.example/?q=1",
        "https://artifacts.example/#fragment",
    ] {
        let mut o = offer();
        o.service_origin = origin.into();
        assert!(matches!(
            PayloadContext::negotiate(&bootstrap(), o, 8 * 1024 * 1024, 1_700_000_000_000),
            Err(PayloadError::InvalidOrigin)
        ));
    }
    let mut o = offer();
    o.capability_version = 2;
    assert!(matches!(
        PayloadContext::negotiate(&bootstrap(), o, 8 * 1024 * 1024, 1_700_000_000_000),
        Err(PayloadError::UnsupportedCapability)
    ));
    for field in ["encryption", "format"] {
        let mut o = offer();
        let mut d: CargoPayloadDescriptorV1 =
            serde_json::from_slice(&o.canonical_descriptor).unwrap();
        if field == "encryption" {
            d.encryption = descriptor::PayloadEncryptionV1::Signer;
        } else {
            d.format = "unknown".into();
        }
        o.canonical_descriptor = serde_json::to_vec(&d).unwrap();
        o.descriptor_digest = digest(&o.canonical_descriptor);
        assert!(matches!(
            PayloadContext::negotiate(&bootstrap(), o, 8 * 1024 * 1024, 1_700_000_000_000),
            Err(PayloadError::Descriptor)
        ));
    }
    let mut o = offer();
    o.binding.runtime_instance_id = "another".into();
    assert!(matches!(
        PayloadContext::negotiate(&bootstrap(), o, 8 * 1024 * 1024, 1_700_000_000_000),
        Err(PayloadError::Binding)
    ));
    let mut o = offer();
    o.canonical_descriptor.push(b' ');
    assert!(matches!(
        PayloadContext::negotiate(&bootstrap(), o, 8 * 1024 * 1024, 1_700_000_000_000),
        Err(PayloadError::Descriptor)
    ));
    assert!(matches!(
        PayloadContext::negotiate(&bootstrap(), offer(), 1, 1_700_000_000_000),
        Err(PayloadError::Descriptor)
    ));
}
#[test]
fn expiry_identity_nonce_reuse_and_staging_failure_fail_closed() {
    let http = FakeHttp::new(vec![]);
    let runtime = Runtime::default();
    *runtime.time.lock().unwrap() = 1_700_000_060_000;
    assert_eq!(
        download_payload(
            &context(),
            &FakeBridge::default(),
            &http,
            &runtime,
            &mut vec![],
            policy()
        ),
        Err(PayloadDownloadRefusal::Expired.into())
    );
    assert!(http.requests.lock().unwrap().is_empty());
    let bridge = FakeBridge {
        wrong_identity: true,
        ..Default::default()
    };
    assert_eq!(
        download_payload(
            &context(),
            &bridge,
            &http,
            &Runtime::default(),
            &mut vec![],
            policy()
        ),
        Err(PayloadError::Binding)
    );
    let runtime = Runtime {
        repeated: true,
        ..Default::default()
    };
    let http = FakeHttp::new(vec![Behavior::Empty]);
    assert_eq!(
        download_payload(
            &context(),
            &FakeBridge::default(),
            &http,
            &runtime,
            &mut vec![],
            policy()
        ),
        Err(PayloadDownloadRefusal::NonceReplayed.into())
    );
    struct FailedWrite;
    impl Write for FailedWrite {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("offline failure"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(
        download_payload(
            &context(),
            &FakeBridge::default(),
            &FakeHttp::new(vec![Behavior::Complete]),
            &Runtime::default(),
            &mut FailedWrite,
            policy()
        ),
        Err(PayloadError::Write)
    );
}
#[test]
fn bridge_sequence_preserves_full_u128_and_rejects_conflicting_or_unsafe_values() {
    assert_eq!(
        bridge_job_ref(&job()).unwrap().sequence,
        u128::MAX.to_string()
    );
    let mut v: Value = serde_json::from_str(&job()).unwrap();
    v["sequence"] = json!("0");
    assert_eq!(bridge_job_ref(&v.to_string()), Err(PayloadError::Binding));
    v.as_object_mut().unwrap().remove("sequence");
    v["id"] = json!(9_007_199_254_740_992u64);
    assert_eq!(bridge_job_ref(&v.to_string()), Err(PayloadError::Binding));
}

#[test]
fn owner_production_origin_casing_refuses_until_the_owner_aligns_vectors() {
    let mut o = offer();
    o.binding.job.origin_kind = "Acurast".into();
    assert!(matches!(
        PayloadContext::negotiate(&bootstrap(), o, 8 * 1024 * 1024, 1_700_000_000_000),
        Err(PayloadError::Binding)
    ));
}

#[test]
fn transfer_budget_signature_and_clock_failures_never_return_verified_bytes() {
    for attempts in [0, MAX_PAYLOAD_TRANSFER_ATTEMPTS + 1] {
        let mut p = policy();
        p.max_attempts = attempts;
        assert_eq!(
            download_payload(
                &context(),
                &FakeBridge::default(),
                &FakeHttp::new(vec![]),
                &Runtime::default(),
                &mut vec![],
                p
            ),
            Err(PayloadError::Budget)
        );
    }
    let bridge = FakeBridge {
        bad_signature: true,
        ..Default::default()
    };
    assert_eq!(
        download_payload(
            &context(),
            &bridge,
            &FakeHttp::new(vec![]),
            &Runtime::default(),
            &mut vec![],
            policy()
        ),
        Err(PayloadDownloadRefusal::InvalidSignature.into())
    );
    // The owner's authorization, rather than an individual request, expires.
    for advance_at in [3, 4] {
        let clock = AdvancingClock {
            runtime: Runtime::default(),
            calls: Mutex::new(0),
            advance_at,
            advanced_time_ms: 1_700_000_060_000,
        };
        let mut sink = vec![];
        assert_eq!(
            download_payload(
                &context(),
                &FakeBridge::default(),
                &FakeHttp::new(vec![Behavior::Complete]),
                &clock,
                &mut sink,
                policy()
            ),
            Err(PayloadDownloadRefusal::Expired.into())
        );
    }
    struct FailedFlush;
    impl Write for FailedFlush {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("offline flush failure"))
        }
    }
    assert_eq!(
        download_payload(
            &context(),
            &FakeBridge::default(),
            &FakeHttp::new(vec![Behavior::Complete]),
            &Runtime::default(),
            &mut FailedFlush,
            policy()
        ),
        Err(PayloadError::Write)
    );
}

#[test]
fn slow_stream_request_expiry_resumes_exact_prefix_with_fresh_nonce() {
    // The request expires at 60 seconds, but authority lasts another hour.
    let mut c = context();
    c.binding.authorization_expires_at_ms += 3_600_000;
    for (advance_at, offset) in [(3, 0), (4, 10)] {
        let clock = AdvancingClock {
            runtime: Runtime::default(),
            calls: Mutex::new(0),
            advance_at,
            advanced_time_ms: 1_700_000_060_000,
        };
        let http = FakeHttp::new(vec![Behavior::Chunked, Behavior::Complete]);
        let mut sink = vec![];
        let verified = download_payload(
            &c,
            &FakeBridge::default(),
            &http,
            &clock,
            &mut sink,
            policy(),
        )
        .unwrap();
        assert_eq!(sink, ARCHIVE);
        assert_eq!(verified.size_bytes, ARCHIVE.len() as u64);
        let requests = http.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].request.range, PayloadDownloadRangeV1::Whole {});
        assert_eq!(
            requests[1].request.range,
            if offset == 0 {
                PayloadDownloadRangeV1::Whole {}
            } else {
                PayloadDownloadRangeV1::Bytes {
                    start: offset,
                    end_inclusive: ARCHIVE.len() as u64 - 1,
                }
            }
        );
        assert_ne!(requests[0].request.nonce, requests[1].request.nonce);
        assert_ne!(requests[0].signature, requests[1].signature);
        assert_eq!(
            requests[1].request.issued_at_ms,
            requests[0].request.expires_at_ms
        );
        assert!(requests[1].request.expires_at_ms > requests[0].request.expires_at_ms);
    }
}

#[test]
fn complete_entity_at_request_expiry_still_checks_integrity() {
    let mut c = context();
    c.binding.authorization_expires_at_ms += 3_600_000;
    for (behavior, expected) in [
        (Behavior::Complete, Ok(())),
        (Behavior::Corrupt, Err(PayloadError::Integrity)),
    ] {
        let clock = AdvancingClock {
            runtime: Runtime::default(),
            calls: Mutex::new(0),
            advance_at: 4,
            advanced_time_ms: 1_700_000_060_000,
        };
        let http = FakeHttp::new(vec![behavior]);
        let result = download_payload(
            &c,
            &FakeBridge::default(),
            &http,
            &clock,
            &mut vec![],
            policy(),
        );
        assert_eq!(result.map(|_| ()), expected);
        assert_eq!(http.requests.lock().unwrap().len(), 1);
    }
}

#[test]
fn expired_stream_attempt_consumes_the_invocation_budget() {
    let mut c = context();
    c.binding.authorization_expires_at_ms += 3_600_000;
    let clock = AdvancingClock {
        runtime: Runtime::default(),
        calls: Mutex::new(0),
        advance_at: 4,
        advanced_time_ms: 1_700_000_060_000,
    };
    let http = FakeHttp::new(vec![Behavior::Chunked]);
    let mut p = policy();
    p.max_attempts = 1;
    let mut sink = vec![];
    assert_eq!(
        download_payload(&c, &FakeBridge::default(), &http, &clock, &mut sink, p),
        Err(PayloadError::Incomplete)
    );
    assert_eq!(sink, ARCHIVE[..10]);
    assert_eq!(http.requests.lock().unwrap().len(), 1);
}

#[test]
fn payload_stream_reads_are_bounded_independently_of_artifact_size() {
    struct BoundedRead(Cursor<Vec<u8>>);
    impl Read for BoundedRead {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            assert!(b.len() <= STREAM_BUFFER_BYTES);
            self.0.read(b)
        }
    }
    struct LargeHttp {
        bytes: Vec<u8>,
        descriptor_digest: String,
    }
    impl PayloadHttpClient for LargeHttp {
        fn get(
            &self,
            _: &str,
            body: &[u8],
            _: Option<&str>,
        ) -> Result<PayloadHttpResponse, PayloadHttpError> {
            let e = SignedPayloadDownloadRequestV1::parse(body).unwrap();
            Ok(PayloadHttpResponse {
                status: 200,
                content_length: Some(self.bytes.len() as u64),
                content_range: None,
                content_encoding: None,
                descriptor_digest: self.descriptor_digest.clone(),
                artifact_digest: e.request.artifact_digest,
                body: Box::new(BoundedRead(Cursor::new(self.bytes.clone()))),
            })
        }
    }
    let bytes = vec![0x5a; STREAM_BUFFER_BYTES * 8 + 1];
    let mut c = context();
    c.binding.artifact_digest = digest(&bytes);
    c.descriptor.artifact_digest = c.binding.artifact_digest.clone();
    c.descriptor.artifact_size_bytes = bytes.len() as u64;
    c.descriptor_digest = digest(&serde_json::to_vec(&c.descriptor).unwrap());
    let http = LargeHttp {
        bytes: bytes.clone(),
        descriptor_digest: c.descriptor_digest.clone(),
    };
    let mut sink = vec![];
    assert_eq!(
        download_payload(
            &c,
            &FakeBridge::default(),
            &http,
            &Runtime::default(),
            &mut sink,
            policy()
        )
        .unwrap()
        .size_bytes,
        bytes.len() as u64
    );
    assert_eq!(sink, bytes);
}
