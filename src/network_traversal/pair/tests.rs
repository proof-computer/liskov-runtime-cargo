use super::super::*;
use super::fixture::{Paired, Topology, corroborated, fixture_descriptor, paired};
use super::wire::{RELAY_DOMAIN, RelayDelivery};

fn outcomes(report: &NetworkTraversalV1) -> Vec<TraversalOutcome> {
    report.phases.iter().map(|phase| phase.outcome).collect()
}

fn stage_domains(result: &Paired) {
    for report in &result.reports {
        assert_eq!(report.proofs.len(), 2);
        assert_eq!(
            report.proofs[0].transcript().domain,
            TRAVERSAL_DIRECT_PEER_DOMAIN
        );
        assert_eq!(
            report.proofs[1].transcript().domain,
            TRAVERSAL_RELAY_PEER_DOMAIN
        );
        let direct = report.proofs[0].transcript();
        let relay = report.proofs[1].transcript();
        assert_ne!(direct.challenge, relay.challenge);
        assert_eq!(
            direct.authority,
            TraversalEvidenceAuthority::HelperObservedPeer
        );
    }
}

#[test]
fn independently_issued_peers_corroborate_on_their_registered_sockets() {
    let result = paired(Topology::Direct);
    assert_ne!(result.descriptors[0].run_id, result.descriptors[1].run_id);
    assert!(result.descriptors[0].issued_at_ms < result.descriptors[1].issued_at_ms);
    assert_eq!(
        result.descriptors[0].deadline_ms,
        result.descriptors[1].deadline_ms
    );
    assert!(corroborated(&result, TraversalStage::Direct));
    assert!(corroborated(&result, TraversalStage::RelayControl));
    stage_domains(&result);
}

#[test]
fn blocked_direct_traffic_has_separate_relay_success() {
    let result = paired(Topology::BlockDirect);
    for report in &result.reports {
        assert_eq!(
            outcomes(report),
            [
                TraversalOutcome::DirectNotEstablishedInTest,
                TraversalOutcome::Succeeded
            ]
        );
    }
    assert!(!corroborated(&result, TraversalStage::Direct));
    assert!(corroborated(&result, TraversalStage::RelayControl));
    stage_domains(&result);
    let [first, second] = &result.descriptors;
    let mut recast = result.reports[0].proofs[1].transcript().clone();
    recast.stage = TraversalStage::Direct;
    recast.transport = TraversalTransport::Udp;
    assert_eq!(recast.validate(), Err(TraversalRefusal::WrongDomain));
    assert!(
        validate_pair_transcripts(
            first,
            second,
            &recast,
            result.reports[1].proofs[1].transcript(),
            second.issued_at_ms + second.budgets.experiment_ms,
        )
        .is_err()
    );
}

#[test]
fn one_way_and_wrong_source_do_not_corroborate() {
    let oneway = paired(Topology::OneWay);
    assert_eq!(
        oneway.reports[0].phases[0].outcome,
        TraversalOutcome::DirectNotEstablishedInTest
    );
    assert_eq!(
        oneway.reports[1].phases[0].outcome,
        TraversalOutcome::OneWayPeer
    );
    assert!(!corroborated(&oneway, TraversalStage::Direct));

    let wrong = paired(Topology::WrongPeer);
    for report in &wrong.reports {
        assert_eq!(report.phases[0].outcome, TraversalOutcome::WrongPeer);
    }
    assert!(!corroborated(&wrong, TraversalStage::Direct));
}

#[test]
fn a_changed_return_cookie_stops_the_run_without_readmitting_either_role() {
    let result = paired(Topology::Rebind);
    for report in &result.reports {
        assert_eq!(outcomes(report), [TraversalOutcome::CandidateRebinding]);
    }
}

#[test]
fn independently_issued_grants_still_freeze_other_fields() {
    let first = fixture_descriptor(0, 3000);
    let mut second = fixture_descriptor(1, 3000);
    second.issued_at_ms += 700;
    second.deadline_ms = second.issued_at_ms + second.budgets.experiment_ms;
    assert_ne!(first.binding_digest(), second.binding_digest());
    validate_traversal_pair(&first, &second).unwrap();
    for mutate in [
        |descriptor: &mut TraversalDescriptorV1| descriptor.budgets.control_requests -= 1,
        |descriptor: &mut TraversalDescriptorV1| {
            descriptor.endpoint_set_revision.push_str("-other")
        },
        |descriptor: &mut TraversalDescriptorV1| descriptor.profile_version.push_str("-other"),
        |descriptor: &mut TraversalDescriptorV1| {
            descriptor.pair.as_mut().unwrap().participants[0].runtime_signer =
                format!("0x{}", "ff".repeat(32));
        },
    ] {
        let mut altered = second.clone();
        mutate(&mut altered);
        assert_eq!(
            validate_traversal_pair(&first, &altered),
            Err(TraversalRefusal::InvalidPair)
        );
    }
}

#[test]
fn relay_control_consumes_the_prober_wire_vector_without_rewriting_it() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../../../vectors/pair-coordinator-v1.json")).unwrap();
    let expected = vector["delivery"].clone();
    let parsed: RelayDelivery = serde_json::from_value(expected.clone()).unwrap();
    assert_eq!(parsed.domain, RELAY_DOMAIN);
    assert_eq!(parsed.sequence, parsed.frame.sequence());
    assert_eq!(serde_json::to_value(parsed).unwrap(), expected);
}
