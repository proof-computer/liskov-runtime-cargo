use super::*;

#[test]
fn a_missing_then_late_second_peer_does_not_renew_the_first_grant() {
    let first = fixture_descriptor(0, 350);
    let mut second = fixture_descriptor(1, 350);
    let oracle = Arc::new(Oracle::new(first.issued_at_ms + 1, Topology::Direct, None));

    let report = collect(oracle.clone(), 0, &first).unwrap();
    assert_eq!(report.phases[0].outcome, TraversalOutcome::PeerAbsent);
    let until = {
        let state = oracle.state.lock().unwrap();
        assert_eq!(state.bootstraps, [1, 0]);
        assert_eq!(state.sent_count, [2, 0]);
        assert_eq!(state.direct_sources, [None, None]);
        state.end.unwrap()
    };
    while oracle.now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    second.issued_at_ms = oracle.now() - 1;
    assert_eq!(second.deadline_ms, first.deadline_ms);
    let report = collect(oracle.clone(), 1, &second).unwrap();
    assert_eq!(report.phases[0].outcome, TraversalOutcome::LateJoin);
    let state = oracle.state.lock().unwrap();
    assert_eq!(state.bootstraps, [1, 1]);
    assert_eq!(state.end, Some(until));
    assert_eq!(state.post_count[1], 1);
    assert_eq!(state.sent_count[1], 0);
}

#[test]
fn insufficient_packet_budget_stops_before_an_unusable_enrollment() {
    let mut descriptor = fixture_descriptor(0, 350);
    descriptor.budgets.outbound_datagrams = 1;
    let oracle = Arc::new(Oracle::new(
        descriptor.issued_at_ms + 1,
        Topology::Direct,
        None,
    ));
    let report = collect(oracle.clone(), 0, &descriptor).unwrap();
    assert_eq!(report.phases[0].outcome, TraversalOutcome::BudgetExhausted);
    let state = oracle.state.lock().unwrap();
    assert_eq!(state.post_count, [0, 0]);
    assert_eq!(state.sent_count, [0, 0]);
}

#[test]
fn a_session_that_reaches_its_deadline_issues_no_io() {
    let descriptor = fixture_descriptor(0, 100);
    let oracle = Arc::new(Oracle::new(
        descriptor.issued_at_ms + 1,
        Topology::Direct,
        None,
    ));
    let (session, signer) = oracle.bootstrap(0, &descriptor);
    while oracle.now() < session.reservation.collector_end_ms {
        std::thread::sleep(Duration::from_millis(5));
    }
    let report = session
        .collect(
            &mut Network {
                oracle: oracle.clone(),
                role: 0,
                nonce: 0,
                revision: descriptor.endpoint_set_revision,
            },
            &signer,
        )
        .unwrap();
    assert_eq!(
        report.phases[0].outcome,
        TraversalOutcome::DirectNotEstablishedInTest
    );
    let state = oracle.state.lock().unwrap();
    assert_eq!(state.post_count, [0, 0]);
    assert_eq!(state.sent_count, [0, 0]);
}

#[test]
fn signature_must_belong_to_the_bootstrap_role() {
    let mut descriptor = fixture_descriptor(0, 350);
    descriptor.budgets.outbound_datagrams = 1;
    let oracle = Arc::new(Oracle::new(
        descriptor.issued_at_ms + 1,
        Topology::Direct,
        None,
    ));
    let (session, _) = oracle.bootstrap(0, &descriptor);
    let report = session.collect(
        &mut Network {
            oracle,
            role: 0,
            nonce: 0,
            revision: descriptor.endpoint_set_revision,
        },
        &Signature::new(1),
    );
    assert_eq!(report, Err(TraversalRefusal::InvalidProof));
}
