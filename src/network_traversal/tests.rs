use super::*;
use serde_json::{Value, json};
fn vectors() -> Value {
    serde_json::from_str(include_str!("../../vectors/network-traversal-v1.json")).unwrap()
}
fn descriptor(name: &str) -> TraversalDescriptorV1 {
    let v = vectors();
    serde_json::from_value(
        v["descriptors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["name"] == name)
            .unwrap()["descriptor"]
            .clone(),
    )
    .unwrap()
}
fn transcript(name: &str) -> TraversalTranscriptV1 {
    let v = vectors();
    serde_json::from_value(
        v["proofs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["name"] == name)
            .unwrap()["transcript"]
            .clone(),
    )
    .unwrap()
}
fn block(name: &str) -> NetworkTraversalV1 {
    let v = vectors();
    serde_json::from_value(
        v["results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["name"] == name)
            .unwrap()["networkTraversal"]
            .clone(),
    )
    .unwrap()
}
fn key() -> [u8; 32] {
    [7; 32]
}
#[test]
fn independent_golden_capabilities_bind_every_descriptor_byte() {
    let v = vectors();
    assert_eq!(v["testOnlyMacKeyHex"], hex::encode(key()));
    for vector in v["descriptors"].as_array().unwrap() {
        let d: TraversalDescriptorV1 =
            serde_json::from_value(vector["descriptor"].clone()).unwrap();
        let wire = vector["canonicalCapability"].as_str().unwrap().as_bytes();
        assert_eq!(
            d.canonical_bytes().unwrap(),
            vector["canonicalDescriptor"].as_str().unwrap().as_bytes()
        );
        assert_eq!(d.binding_digest().unwrap(), vector["descriptorDigest"]);
        assert_eq!(encode_traversal_capability(&key(), &d).unwrap(), wire);
        assert_eq!(
            decode_traversal_capability(&key(), wire, d.issued_at_ms + 1).unwrap(),
            d
        );
        // Mutations remain structurally valid but cannot keep the original MAC.
        for field in [
            "runId",
            "claimAuthorityDigest",
            "profileVersion",
            "catalogVersion",
            "artifactDigest",
            "helperVersion",
            "helperDigest",
            "endpointSetRevision",
            "deadlineMs",
            "budgets",
        ] {
            let mut c: Value = serde_json::from_slice(wire).unwrap();
            match field {
                "runId" => c["descriptor"][field] = json!("05".repeat(16)),
                "claimAuthorityDigest" => {
                    if d.mode == TraversalMode::Pair {
                        continue;
                    }
                    c["descriptor"][field] = json!(format!("sha256:{}", "f".repeat(64)));
                }
                "artifactDigest" | "helperDigest" => {
                    c["descriptor"][field] = json!(format!("sha256:{}", "f".repeat(64)))
                }
                "deadlineMs" => c["descriptor"][field] = json!(d.deadline_ms - 1),
                "budgets" => c["descriptor"][field]["outboundDatagrams"] = json!(63),
                _ => c["descriptor"][field] = json!("different-revision"),
            }
            assert_eq!(
                decode_traversal_capability(&key(), &canonical(&c).unwrap(), d.issued_at_ms + 1),
                Err(TraversalRefusal::InvalidMac),
                "{field}"
            );
        }
    }
}
#[test]
fn capabilities_refuse_domain_version_expiry_oversize_and_unknown_fields() {
    let d = descriptor("observe");
    let wire = encode_traversal_capability(&key(), &d).unwrap();
    assert_eq!(
        decode_traversal_capability(&[8; 32], &wire, d.issued_at_ms),
        Err(TraversalRefusal::InvalidMac)
    );
    assert_eq!(
        decode_traversal_capability(&key(), &wire, d.issued_at_ms - 1),
        Err(TraversalRefusal::NotYetValid)
    );
    assert_eq!(
        decode_traversal_capability(&key(), &wire, d.expires_at_ms),
        Err(TraversalRefusal::Expired)
    );
    assert_eq!(
        decode_traversal_capability(
            &key(),
            &vec![b' '; TRAVERSAL_BLOCK_MAX_BYTES + 1],
            d.issued_at_ms
        ),
        Err(TraversalRefusal::Oversize)
    );
    let mutate = |field: &str, value: Value, expected| {
        let mut c: Value = serde_json::from_slice(&wire).unwrap();
        if field == "domain" {
            c[field] = value;
        } else {
            c["descriptor"][field] = value;
        }
        assert_eq!(
            decode_traversal_capability(&key(), &canonical(&c).unwrap(), d.issued_at_ms),
            Err(expected)
        );
    };
    mutate(
        "domain",
        json!("proof.liskov.network-prober-challenge.v1"),
        TraversalRefusal::WrongDomain,
    );
    mutate("version", json!(2), TraversalRefusal::UnknownVersion);
    mutate("unknown", json!(true), TraversalRefusal::Malformed);
    mutate("mode", json!("auto_mapping"), TraversalRefusal::Malformed);
    mutate(
        "operations",
        json!(["scan_lan"]),
        TraversalRefusal::Malformed,
    );
    let mut whitespace = wire.clone();
    whitespace.push(b' ');
    assert_eq!(
        decode_traversal_capability(&key(), &whitespace, d.issued_at_ms),
        Err(TraversalRefusal::NonCanonical)
    );
    // Frozen coverage challenges are not traversal capabilities.
    let old = format!("0x{}", "11".repeat(32));
    assert!(decode_traversal_capability(&key(), old.as_bytes(), 100).is_err());
}
#[test]
fn consent_scope_finite_lease_and_pair_slots_are_closed() {
    let mapping = descriptor("mapping");
    let bad: [fn(&mut TraversalDescriptorV1); 12] = [
        |d| d.mapping = None,
        |d| d.mode = TraversalMode::Observe,
        |d| d.mapping.as_mut().unwrap().prior_uncertainty_resolved = false,
        |d| d.mapping.as_mut().unwrap().finite_expiry_verified = false,
        |d| d.mapping.as_mut().unwrap().requested_lease_sec = 0,
        |d| d.mapping.as_mut().unwrap().maximum_lease_sec = 121,
        |d| d.mapping.as_mut().unwrap().maximum_lease_sec = 59,
        |d| d.mapping.as_mut().unwrap().expires_at_ms = d.expires_at_ms - 1,
        |d| d.mapping.as_mut().unwrap().protocols = vec![TraversalRouterProtocol::NatPmp],
        |d| d.mapping.as_mut().unwrap().consent_reference.clear(),
        |d| d.budgets.cleanup_datagrams = 0,
        |d| d.budgets.cleanup_control_requests = 0,
    ];
    for mutate in bad {
        let mut d = mapping.clone();
        mutate(&mut d);
        assert!(d.validate().is_err());
    }
    let a = descriptor("pair_first");
    let b = descriptor("pair_second");
    validate_traversal_pair(&a, &b).unwrap();
    assert_eq!(
        validate_traversal_pair(&a, &a),
        Err(TraversalRefusal::InvalidPair)
    );
    let bad: [fn(&mut TraversalDescriptorV1); 7] = [
        |d| d.participant_role = None,
        |d| d.pair.as_mut().unwrap().participants.swap(0, 1),
        |d| {
            d.pair.as_mut().unwrap().participants[1].launch_instance_digest =
                d.pair.as_ref().unwrap().participants[0]
                    .launch_instance_digest
                    .clone()
        },
        |d| d.pair.as_mut().unwrap().participants[0].runtime_signer = "not-fixed".into(),
        |d| d.pair.as_mut().unwrap().expires_at_ms += 1,
        |d| d.participant_role = Some(TraversalParticipantRole::Second),
        |d| d.operations.push(TraversalOperation::MapPcp),
    ];
    for mutate in bad {
        let mut d = a.clone();
        mutate(&mut d);
        assert!(d.validate().is_err());
    }
    // Same pair id is insufficient: frozen scope/profile/topology and both signers must agree.
    for field in ["profileVersion", "endpointSetRevision", "helperVersion"] {
        let mut value = serde_json::to_value(&b).unwrap();
        value[field] = json!("other");
        let other = serde_json::from_value(value).unwrap();
        assert_eq!(
            validate_traversal_pair(&a, &other),
            Err(TraversalRefusal::InvalidPair)
        );
    }
    let mut other = b.clone();
    other.pair.as_mut().unwrap().participants[0].runtime_signer = format!("0x{}", "ff".repeat(32));
    assert_eq!(
        validate_traversal_pair(&a, &other),
        Err(TraversalRefusal::InvalidPair)
    );
    let wire = encode_traversal_capability(&key(), &a).unwrap();
    let mut c: Value = serde_json::from_slice(&wire).unwrap();
    c["descriptor"]["pair"]["participants"][1]["runtimeSigner"] =
        json!(format!("0x{}", "ff".repeat(32)));
    assert_eq!(
        decode_traversal_capability(&key(), &canonical(&c).unwrap(), a.issued_at_ms),
        Err(TraversalRefusal::InvalidMac)
    );
}
#[test]
fn hard_budgets_and_delivery_reserve_cannot_expand_or_extend_deadlines() {
    let d = descriptor("observe");
    let bad: [fn(&mut TraversalDescriptorV1); 10] = [
        |d| d.budgets.experiment_ms = 30001,
        |d| d.budgets.cleanup_reserve_ms = 5001,
        |d| d.budgets.outbound_datagrams = 65,
        |d| d.budgets.datagram_bytes = 513,
        |d| d.budgets.control_requests = 13,
        |d| d.budgets.external_dialbacks = 5,
        |d| d.budgets.concurrent_mapping_leases = 3,
        |d| d.budgets.relay_bytes_per_direction = 65537,
        |d| d.expires_at_ms = d.issued_at_ms + 120001,
        |d| d.deadline_ms = d.expires_at_ms + 1,
    ];
    for mutate in bad {
        let mut x = d.clone();
        mutate(&mut x);
        assert!(x.validate().is_err());
    }
    d.can_start(d.issued_at_ms + 1000, d.expires_at_ms, 5000)
        .unwrap();
    assert_eq!(
        d.can_start(d.deadline_ms - 29999, d.expires_at_ms, 5000),
        Err(TraversalRefusal::InsufficientTime)
    );
    assert_eq!(
        d.can_start(d.issued_at_ms, d.issued_at_ms + 34999, 5000),
        Err(TraversalRefusal::InsufficientTime)
    );
    assert_eq!(
        d.can_start(d.issued_at_ms, d.expires_at_ms, u64::MAX),
        Err(TraversalRefusal::InsufficientTime)
    );
    let mut zero = d.clone();
    zero.budgets.outbound_datagrams = 0;
    zero.budgets.datagram_bytes = 0;
    zero.budgets.external_dialbacks = 0;
    zero.validate().unwrap(); // Zero allowances are valid, not missing/defaulted.
    let mut reduced = d.clone();
    reduced.budgets.cleanup_reserve_ms = 4999;
    reduced.validate().unwrap();
    reduced
        .operations
        .push(TraversalOperation::RegisterEndpoint);
    assert_eq!(reduced.validate(), Err(TraversalRefusal::InvalidScope));
    reduced.operations.pop();
    reduced.operations.push(TraversalOperation::MapPcp);
    assert_eq!(reduced.validate(), Err(TraversalRefusal::InvalidScope));
}
#[test]
fn golden_transcripts_distinguish_external_router_and_two_peer_roles() {
    let v = vectors();
    for vector in v["proofs"].as_array().unwrap() {
        let d: TraversalDescriptorV1 =
            serde_json::from_value(vector["descriptor"].clone()).unwrap();
        let t: TraversalTranscriptV1 =
            serde_json::from_value(vector["transcript"].clone()).unwrap();
        assert_eq!(
            t.signing_message().unwrap(),
            vector["canonicalDeviceSigningPayload"]
                .as_str()
                .unwrap()
                .as_bytes()
        );
        t.validate_scope(&d, d.issued_at_ms + 1000).unwrap();
        let p: TraversalProofV1 = serde_json::from_value(vector["proof"].clone()).unwrap();
        p.validate().unwrap();
        assert_eq!(p.binding_digest().unwrap(), vector["proofDigest"]);
        if let TraversalProofV1::ProberReceipt { receipt } = p {
            assert_eq!(
                traversal_receipt_message(&receipt).unwrap(),
                vector["canonicalReceiptMacPayload"]
                    .as_str()
                    .unwrap()
                    .as_bytes()
            );
            verify_traversal_receipt(&key(), &receipt, &d, d.issued_at_ms + 1000).unwrap();
            let mut resigned = receipt.clone();
            resigned.mac.clear();
            sign_traversal_receipt(&key(), &mut resigned).unwrap();
            assert_eq!(resigned, receipt);
            let mut changed = receipt.clone();
            changed.device_signature = format!("0x{}", "ac".repeat(64));
            assert_eq!(
                verify_traversal_receipt(&key(), &changed, &d, d.issued_at_ms + 1000),
                Err(TraversalRefusal::InvalidMac)
            );
            changed = receipt.clone();
            changed.transcript.challenge = "08".repeat(32);
            assert_eq!(
                verify_traversal_receipt(&key(), &changed, &d, d.issued_at_ms + 1000),
                Err(TraversalRefusal::InvalidMac)
            );
            assert_eq!(
                verify_traversal_receipt(&key(), &receipt, &d, d.expires_at_ms),
                Err(TraversalRefusal::Expired)
            );
        }
    }
    let mut direct = transcript("first_direct");
    let relay = transcript("first_relay");
    assert_ne!(
        direct.signing_message().unwrap(),
        relay.signing_message().unwrap()
    );
    direct.domain = TRAVERSAL_RELAY_PEER_DOMAIN.into();
    assert_eq!(direct.validate(), Err(TraversalRefusal::WrongDomain));
    let mut router = transcript("device_router_create");
    router.domain = TRAVERSAL_EXTERNAL_PATH_DOMAIN.into();
    assert_eq!(router.validate(), Err(TraversalRefusal::WrongDomain));
    let mut fake = TraversalReceiptV1 {
        version: 1,
        transcript: transcript("first_direct"),
        device_signature: format!("0x{}", "ab".repeat(64)),
        mac: String::new(),
    };
    assert_eq!(
        sign_traversal_receipt(&key(), &mut fake),
        Err(TraversalRefusal::InvalidProof)
    );
    assert_eq!(
        transcript("second_direct").validate_scope(
            &descriptor("pair_first"),
            descriptor("pair_first").issued_at_ms
        ),
        Err(TraversalRefusal::InvalidBinding)
    );
    let mut cleanup = transcript("device_router_cleanup");
    cleanup.cleanup = None;
    assert_eq!(cleanup.validate(), Err(TraversalRefusal::InvalidProof));
    let mut lease = transcript("device_router_create");
    lease.granted_lease_sec = Some(121);
    assert_eq!(lease.validate(), Err(TraversalRefusal::InvalidProof));
    lease.outcome = TraversalOutcome::UnsupportedFiniteLease;
    lease.validate().unwrap();
}
#[test]
fn normalized_blocks_and_total_native_envelopes_are_bounded() {
    let v = vectors();
    for vector in v["results"].as_array().unwrap() {
        let d: TraversalDescriptorV1 =
            serde_json::from_value(vector["descriptor"].clone()).unwrap();
        let b: NetworkTraversalV1 =
            serde_json::from_value(vector["networkTraversal"].clone()).unwrap();
        b.validate_scope(&d, d.issued_at_ms + 2000).unwrap();
        assert!(serde_json::to_vec(&b).unwrap().len() <= TRAVERSAL_BLOCK_MAX_BYTES);
    }
    let result: crate::coverage::CoverageResultV1 =
        serde_json::from_value(v["coverageResult"].clone()).unwrap();
    assert_eq!(
        coverage_signing_message(&result).unwrap(),
        v["canonicalCoverageSigningPayload"]
            .as_str()
            .unwrap()
            .as_bytes()
    );
    assert!(result.network_sample.is_none()); // Traversal does not forge a bandwidth sample.
    let mut signed = SignedCoverageResultV1 {
        result,
        signature: format!("0x{}", "ab".repeat(64)),
    };
    let wire = encode_traversal_coverage_envelope(&signed).unwrap();
    assert!(decode_traversal_coverage_envelope(&wire).unwrap() == signed);
    let mut raw = wire.clone();
    raw.resize(TRAVERSAL_ENVELOPE_MAX_BYTES + 1, b' ');
    assert!(decode_traversal_coverage_envelope(&raw) == Err(TraversalRefusal::Oversize));
    signed.result.application_id = "x".repeat(TRAVERSAL_ENVELOPE_MAX_BYTES);
    assert!(coverage_signing_message(&signed.result).is_err());
    assert!(encode_traversal_coverage_envelope(&signed).is_err());
    let mut b = block("observe");
    b.phases[0].outcome = TraversalOutcome::Failed;
    assert_eq!(b.validate(), Err(TraversalRefusal::InvalidProof));
    b = block("observe");
    b.proofs.extend(vec![b.proofs[0].clone(); 16]);
    assert_eq!(b.validate(), Err(TraversalRefusal::Oversize));
    b = block("observe");
    b.version = 2;
    assert_eq!(b.validate(), Err(TraversalRefusal::UnknownVersion));
    b = block("observe");
    b.phases[0].proof_digest = None;
    assert_eq!(b.validate(), Err(TraversalRefusal::InvalidProof));
    let mut value = serde_json::to_value(block("observe")).unwrap();
    value["gatewayAddress"] = json!("192.0.2.1");
    assert!(serde_json::from_value::<NetworkTraversalV1>(value).is_err());
}
#[test]
fn absent_traversal_preserves_all_existing_coverage_signing_vectors() {
    for source in [
        include_str!("../../vectors/processor-coverage-result-v1.json"),
        include_str!("../../vectors/processor-coverage-network-v1.json"),
    ] {
        let v: Value = serde_json::from_str(source).unwrap();
        let result: crate::coverage::CoverageResultV1 =
            serde_json::from_value(v["result"].clone()).unwrap();
        assert!(result.network_traversal.is_none());
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("networkTraversal")
        );
        assert_eq!(
            crate::diagnostics::canonical_json_bytes(&serde_json::to_value(&result).unwrap()),
            v["canonicalSigningPayload"].as_str().unwrap().as_bytes()
        );
    }
}
fn keys(v: &Value) -> Vec<String> {
    let mut keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    keys
}
#[test]
fn closed_catalog_matches_codec_fields_and_hard_ceilings() {
    let c: Value = serde_json::from_str(include_str!(
        "../../vectors/network-traversal-contract-v1.json"
    ))
    .unwrap();
    let d = serde_json::to_value(descriptor("mapping")).unwrap();
    let b = serde_json::to_value(block("observe")).unwrap();
    let p = serde_json::to_value(descriptor("pair_first")).unwrap();
    let t = serde_json::to_value(transcript("external_baseline")).unwrap();
    for (field, value) in [
        ("fields", &b),
        ("descriptorFields", &d),
        ("budgetFields", &d["budgets"]),
        ("consentFields", &d["mapping"]),
        ("pairFields", &p["pair"]),
        ("participantFields", &p["pair"]["participants"][0]),
        ("phaseFields", &b["phases"][0]),
        ("transcriptFields", &t),
        ("receiptFields", &b["proofs"][0]["receipt"]),
    ] {
        let mut expected: Vec<_> = c[field]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        expected.sort();
        assert_eq!(keys(value), expected, "{field}");
    }
    assert_eq!(c["bounds"]["blockBytes"], TRAVERSAL_BLOCK_MAX_BYTES);
    assert_eq!(
        c["bounds"]["nativeEnvelopeBytes"],
        TRAVERSAL_ENVELOPE_MAX_BYTES
    );
    assert_eq!(c["bounds"]["capabilityMs"], TRAVERSAL_CAPABILITY_MAX_MS);
    assert_eq!(c["bounds"]["experimentMs"], TRAVERSAL_EXPERIMENT_MAX_MS);
    assert_eq!(
        c["bounds"]["cleanupReserveMs"],
        TRAVERSAL_CLEANUP_RESERVE_MS
    );
    assert_eq!(c["currentProfile"], false);
}

#[test]
fn pair_proof_requires_cross_matching_nonces_and_same_direct_or_relay_phase() {
    let a = descriptor("pair_first");
    let b = descriptor("pair_second");
    let first = transcript("first_direct");
    let second = transcript("second_direct");
    validate_pair_transcripts(&a, &b, &first, &second, a.issued_at_ms + 1000).unwrap();
    let mut wrong = second.clone();
    wrong.peer_challenge = Some("07".repeat(32));
    assert_eq!(
        validate_pair_transcripts(&a, &b, &first, &wrong, a.issued_at_ms + 1000),
        Err(TraversalRefusal::InvalidProof)
    );
    wrong = second.clone();
    wrong.stage = TraversalStage::RelayControl;
    wrong.transport = TraversalTransport::RelayControl;
    wrong.domain = TRAVERSAL_RELAY_PEER_DOMAIN.into();
    assert_eq!(
        validate_pair_transcripts(&a, &b, &first, &wrong, a.issued_at_ms + 1000),
        Err(TraversalRefusal::InvalidProof)
    );
    wrong = second.clone();
    wrong.outcome = TraversalOutcome::OneWayPeer;
    assert_eq!(
        validate_pair_transcripts(&a, &b, &first, &wrong, a.issued_at_ms + 1000),
        Err(TraversalRefusal::InvalidProof)
    );
    wrong = second;
    wrong.family = TraversalFamily::V6;
    assert_eq!(
        validate_pair_transcripts(&a, &b, &first, &wrong, a.issued_at_ms + 1000),
        Err(TraversalRefusal::InvalidProof)
    );
}
#[test]
fn unknown_cleanup_cannot_become_not_created_and_refusals_still_require_scope() {
    let mut t = transcript("device_router_cleanup");
    t.cleanup = Some(TraversalCleanup::CreationOutcomeUnknown);
    assert_eq!(t.validate(), Err(TraversalRefusal::InvalidProof));
    t.outcome = TraversalOutcome::CreationOutcomeUnknown;
    t.granted_lease_sec = None;
    t.validate().unwrap();
    t.cleanup = Some(TraversalCleanup::NotCreated);
    assert_eq!(t.validate(), Err(TraversalRefusal::InvalidProof));
    let mut d = descriptor("observe");
    d.operations = vec![TraversalOperation::BaselineTcp];
    let mut b = block("observe");
    b.descriptor_digest = d.binding_digest().unwrap();
    b.proofs.clear();
    b.phases.truncate(1);
    b.phases[0].outcome = TraversalOutcome::UnsupportedRuntimeApi;
    b.phases[0].proof_digest = None;
    b.validate_scope(&d, d.issued_at_ms + 2000).unwrap();
    b.phases[0].transport = TraversalTransport::Udp;
    assert_eq!(
        b.validate_scope(&d, d.issued_at_ms + 2000),
        Err(TraversalRefusal::InvalidScope)
    );
    b.phases[0].transport = TraversalTransport::Tcp;
    assert_eq!(
        b.validate_scope(&d, d.issued_at_ms + 1999),
        Err(TraversalRefusal::InvalidDeadline)
    );
}

struct QuietEffects;

impl TraversalEffects for QuietEffects {
    fn discover(&self) {}
    fn open_socket(&self) {}
    fn resolve_name(&self, _host: &str) {}
    fn sign(&self, _message: &[u8]) {}
    fn submit(&self, _body: &[u8]) {}
    fn cancelled(&self) -> bool {
        false
    }
}

#[test]
fn reservation_fits_both_deadlines_and_calls_no_effect() {
    let descriptor = descriptor("observe");
    let effects = QuietEffects;
    let now = descriptor.issued_at_ms + 1_000;
    let outcome = reserve_traversal(&ReserveInput {
        grant: None,
        now_ms: now,
        job_expires_at_ms: descriptor.expires_at_ms,
        artifact_digest: &descriptor.artifact_digest,
        helper: &DORMANT_HELPER,
        effects: &effects,
    });
    assert_eq!(outcome, ReserveOutcome::Absent);
    let capability = TraversalCapabilityV1 {
        domain: TRAVERSAL_CAPABILITY_DOMAIN.into(),
        descriptor: descriptor.clone(),
        mac: "ab".repeat(32),
    };
    let reserved = reserve_traversal(&ReserveInput {
        grant: Some(&capability),
        now_ms: now,
        job_expires_at_ms: descriptor.expires_at_ms,
        artifact_digest: &descriptor.artifact_digest,
        helper: &TraversalHelperIdentity {
            version: "cargo-helper-traversal-1",
            digest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        },
        effects: &effects,
    });
    let ReserveOutcome::Reserved(reservation) = reserved else {
        panic!("expected a reservation");
    };
    assert!(reservation_fits(&descriptor, reservation));
    assert_eq!(reservation.experiment_ms, 30_000);
    assert_eq!(reservation.cleanup_reserve_ms, 5_000);
    assert_eq!(
        reservation.delivery_reserve_ms,
        EXISTING_DELIVERY_RESERVE_MS
    );
    assert!(reservation.collector_end_ms <= descriptor.deadline_ms);
    assert!(reservation.delivery_end_ms <= descriptor.expires_at_ms.min(descriptor.expires_at_ms));
}

struct CancelledEffects;

impl TraversalEffects for CancelledEffects {
    fn discover(&self) {}
    fn open_socket(&self) {}
    fn resolve_name(&self, _host: &str) {}
    fn sign(&self, _message: &[u8]) {}
    fn submit(&self, _body: &[u8]) {}
    fn cancelled(&self) -> bool {
        true
    }
}

#[test]
fn cancellation_skips_a_fitting_grant_and_still_refuses_expiry() {
    let descriptor = descriptor("observe");
    let effects = CancelledEffects;
    let helper = TraversalHelperIdentity {
        version: "cargo-helper-traversal-1",
        digest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
    };
    let capability = TraversalCapabilityV1 {
        domain: TRAVERSAL_CAPABILITY_DOMAIN.into(),
        descriptor: descriptor.clone(),
        mac: "ab".repeat(32),
    };
    let now = descriptor.issued_at_ms + 1_000;
    let skipped = reserve_traversal(&ReserveInput {
        grant: Some(&capability),
        now_ms: now,
        job_expires_at_ms: descriptor.expires_at_ms,
        artifact_digest: &descriptor.artifact_digest,
        helper: &helper,
        effects: &effects,
    });
    assert_eq!(skipped, ReserveOutcome::SkippedBudget);
    let expired = reserve_traversal(&ReserveInput {
        grant: Some(&capability),
        now_ms: descriptor.expires_at_ms,
        job_expires_at_ms: descriptor.expires_at_ms,
        artifact_digest: &descriptor.artifact_digest,
        helper: &helper,
        effects: &effects,
    });
    assert_eq!(expired, ReserveOutcome::Refused(TraversalRefusal::Expired));
}
