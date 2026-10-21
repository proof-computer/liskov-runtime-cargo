use super::*;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

const NOW: u64 = 1_775_000_001_000;
fn descriptor() -> TraversalDescriptorV1 {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../../../vectors/network-traversal-v1.json")).unwrap();
    serde_json::from_value(vector["descriptors"][0]["descriptor"].clone()).unwrap()
}
fn reservation(d: &TraversalDescriptorV1) -> Reservation {
    Reservation {
        experiment_ms: d.budgets.experiment_ms,
        cleanup_reserve_ms: d.budgets.cleanup_reserve_ms,
        delivery_reserve_ms: super::super::EXISTING_DELIVERY_RESERVE_MS,
        collector_end_ms: NOW + d.budgets.experiment_ms,
        delivery_end_ms: NOW + d.budgets.experiment_ms + super::super::EXISTING_DELIVERY_RESERVE_MS,
    }
}
fn endpoint(address: &str) -> BehaviourEndpoint {
    BehaviourEndpoint {
        address: address.parse().unwrap(),
        mapping_qualified: true,
        filtering_qualified: true,
    }
}
fn topology() -> BehaviourTopology {
    BehaviourTopology {
        revision: "a-p-a-q-b-p-1".into(),
        ap: endpoint("127.0.0.1:40000"),
        aq: Some(endpoint("127.0.0.1:40001")),
        bp: Some(endpoint("127.0.0.2:40000")),
    }
}
fn run(
    d: &TraversalDescriptorV1,
    t: &BehaviourTopology,
    network: &mut dyn BehaviourNetwork,
) -> UdpBehaviourReport {
    let session =
        BehaviourSession::from_authenticated_enrollment(&hex::encode([17; 16]), d).unwrap();
    collect_udp_behaviour(d, reservation(d), session, t, network)
}

#[derive(Clone, Copy)]
enum Mode {
    Independent,
    Address,
    Port,
}
#[derive(Default)]
struct Faults {
    blocked: bool,
    dropped_alternate_challenges: u8,
    noise: bool,
    flood: bool,
    rebind_mapping: bool,
    rebind_filtering: bool,
    repeat_tx: bool,
    cancelled: bool,
    late: bool,
    malformed: Option<usize>,
}
struct State {
    clock: u64,
    binds: usize,
    transactions: u8,
    mapping: Mode,
    filtering: Mode,
    faults: Faults,
    // Independent packet oracle: socket, destination, kind, requested source.
    sends: Vec<(usize, SocketAddr, u8, u8)>,
    first_pin: Option<usize>,
    previous: Option<(Vec<u8>, SocketAddr)>,
}
struct Network(Rc<RefCell<State>>);
impl Network {
    fn new(mapping: Mode, filtering: Mode) -> Self {
        Self(Rc::new(RefCell::new(State {
            clock: NOW,
            binds: 0,
            transactions: 0,
            mapping,
            filtering,
            faults: Faults::default(),
            sends: vec![],
            first_pin: None,
            previous: None,
        })))
    }
}
impl BehaviourNetwork for Network {
    fn now_ms(&self) -> u64 {
        self.0.borrow().clock
    }
    fn cancelled(&self) -> bool {
        self.0.borrow().faults.cancelled
    }
    fn transaction(&mut self) -> Result<[u8; 16], BehaviourFailure> {
        let mut state = self.0.borrow_mut();
        if !state.faults.repeat_tx {
            state.transactions += 1;
        }
        Ok([state.transactions.max(1); 16])
    }
    fn bind_fresh(&mut self) -> Result<Box<dyn BehaviourSocket>, BehaviourFailure> {
        self.0.borrow_mut().binds += 1;
        let id = self.0.borrow().binds;
        Ok(Box::new(Socket {
            state: self.0.clone(),
            id,
            frames: VecDeque::new(),
        }))
    }
}
struct Socket {
    state: Rc<RefCell<State>>,
    id: usize,
    frames: VecDeque<(Vec<u8>, SocketAddr)>,
}

// The fixture acts as a NAT table and packet-boundary oracle. Its policy is
// selected independently of the collector's expected classification.
impl BehaviourSocket for Socket {
    fn send_to(
        &mut self,
        packet: &[u8],
        destination: SocketAddr,
        _remaining_ms: u64,
    ) -> Result<(), BehaviourFailure> {
        let mut s = self.state.borrow_mut();
        s.sends.push((self.id, destination, packet[4], packet[5]));
        if s.faults.blocked {
            return Ok(());
        }
        let ingress = if destination.ip() == "127.0.0.2".parse::<IpAddr>().unwrap() {
            2
        } else if destination.port() == 40001 {
            1
        } else {
            0
        };
        let proof = packet[4] == 2;
        if !proof && packet[5] & s.faults.dropped_alternate_challenges != 0 {
            return Ok(());
        }
        if proof && ingress == 0 && s.first_pin.is_none() {
            s.first_pin = Some(self.id);
        }
        if proof && packet[5] != 0 {
            assert_eq!(
                s.first_pin,
                Some(self.id),
                "alternate proof must retain the first A:p socket"
            );
            let allowed = match s.filtering {
                Mode::Independent => true,
                Mode::Address => packet[5] == 1,
                Mode::Port => false,
            };
            if !allowed {
                return Ok(());
            }
        }
        let outgoing = if proof && packet[5] != 0 {
            packet[5]
        } else {
            ingress
        };
        let source = match outgoing {
            0 => "127.0.0.1:40000",
            1 => "127.0.0.1:40001",
            _ => "127.0.0.2:40000",
        }
        .parse()
        .unwrap();
        let mut response = packet.to_vec();
        response[4] = if proof { 3 } else { 1 };
        response[6] = ingress;
        response[7] = outgoing;
        if !proof {
            response[40..72].fill(0x71);
        }
        if proof {
            response.resize(128, 0);
            response[96] = 4;
            response[97..101].copy_from_slice(&[8, 8, 8, 8]);
            let offset = match s.mapping {
                Mode::Independent => 0,
                Mode::Address => {
                    if ingress == 2 {
                        2
                    } else {
                        0
                    }
                }
                Mode::Port => u16::from(ingress),
            };
            let mut port = 42000 + self.id as u16 * 10 + offset;
            let prior_ap_proofs = s
                .sends
                .iter()
                .filter(|(id, _, kind, selector)| *id == self.id && *kind == 2 && *selector == 0)
                .count();
            if (s.faults.rebind_filtering && self.id == 1 && prior_ap_proofs >= 2)
                || (s.faults.rebind_mapping && self.id == 2 && prior_ap_proofs >= 6)
            {
                port += 1;
            }
            response[113..115].copy_from_slice(&port.to_be_bytes());
        }
        if let Some(byte) = s.faults.malformed.filter(|_| proof) {
            response[byte] ^= 0xff;
        }
        if s.faults.noise || s.faults.flood {
            // Previous transaction/session/epoch, duplicate, false sender,
            // correct identity bytes with the wrong cookie, and malformed size.
            if let Some(old) = &s.previous {
                self.frames.push_back(old.clone());
            }
            let mut old_epoch = response.clone();
            old_epoch[8] ^= 1;
            let mut old_tx = response.clone();
            old_tx[24] ^= 1;
            let mut wrong_cookie = response.clone();
            wrong_cookie[40] ^= 1;
            self.frames.push_back((old_epoch, source));
            self.frames.push_back((old_tx, source));
            if proof {
                self.frames.push_back((wrong_cookie, source));
            }
            self.frames
                .push_back((response.clone(), "127.0.0.3:40000".parse().unwrap()));
            self.frames.push_back((vec![0; 513], source));
        }
        s.previous = Some((response.clone(), source));
        if s.faults.flood {
            for _ in 0..20 {
                self.frames.push_back((vec![0; 513], source));
            }
        } else {
            self.frames.push_back((response, source));
        }
        Ok(())
    }
    fn receive_from(
        &mut self,
        buffer: &mut [u8],
        remaining: u64,
    ) -> Result<(usize, SocketAddr), BehaviourFailure> {
        let mut state = self.state.borrow_mut();
        if state.faults.late {
            state.clock += 30000;
        }
        match self.frames.pop_front() {
            Some((packet, source)) => {
                buffer[..packet.len()].copy_from_slice(&packet);
                Ok((packet.len(), source))
            }
            None => {
                state.clock += remaining;
                Err(BehaviourFailure::Timeout)
            }
        }
    }
}

#[test]
fn independent_mapping_and_filtering_matrix_and_socket_packet_oracle() {
    let modes = [Mode::Independent, Mode::Address, Mode::Port];
    let outcomes = [
        TraversalOutcome::EndpointIndependent,
        TraversalOutcome::AddressDependent,
        TraversalOutcome::AddressAndPortDependent,
    ];
    for (m, expected_mapping) in modes.into_iter().zip(outcomes) {
        for (f, expected_filtering) in modes.into_iter().zip(outcomes) {
            let mut network = Network::new(m, f);
            let report = run(&descriptor(), &topology(), &mut network);
            assert_eq!(report.mapping.outcome, expected_mapping, "{report:?}");
            assert_eq!(report.filtering.outcome, expected_filtering, "{report:?}");
            let state = network.0.borrow();
            assert_eq!(state.binds, 2);
            assert!(
                state
                    .sends
                    .iter()
                    .filter(|(id, ..)| *id == 1)
                    .all(|(_, d, ..)| *d == topology().ap.address)
            );
            for e in [
                topology().ap.address,
                topology().aq.unwrap().address,
                topology().bp.unwrap().address,
            ] {
                assert!(state.sends.iter().any(|(id, d, ..)| *id == 2 && *d == e));
            }
            assert_eq!(report.sent_datagrams as usize, state.sends.len());
            assert!(report.sent_datagrams <= 20);
        }
    }
}

#[test]
fn duplicate_reordered_spoofed_epoch_transaction_and_cookie_frames_are_ignored() {
    let mut network = Network::new(Mode::Address, Mode::Port);
    network.0.borrow_mut().faults.noise = true;
    let report = run(&descriptor(), &topology(), &mut network);
    assert_eq!(report.mapping.outcome, TraversalOutcome::AddressDependent);
    assert_eq!(
        report.filtering.outcome,
        TraversalOutcome::AddressAndPortDependent
    );
}

#[test]
fn missing_ap_challenges_are_not_alternate_source_filtering_evidence() {
    // Lose B:p's challenge, both alternate challenges, or A:q's challenge when
    // B:p is actually filtered. None distinguishes the dependent classes.
    for (filtering, dropped) in [
        (Mode::Independent, 2),
        (Mode::Independent, 3),
        (Mode::Port, 1),
    ] {
        let mut network = Network::new(Mode::Independent, filtering);
        network.0.borrow_mut().faults.dropped_alternate_challenges = dropped;
        let report = run(&descriptor(), &topology(), &mut network);
        assert_eq!(
            report.filtering,
            BehaviourSummary::unknown(BehaviourFailure::ChallengeTimeout),
            "{report:?}"
        );
        assert_eq!(
            report.mapping.outcome,
            TraversalOutcome::EndpointIndependent
        );
        for (selector, result) in [(1, report.filtering_aq), (2, report.filtering_bp)] {
            if dropped & selector != 0 {
                assert_eq!(result, Err(BehaviourFailure::ChallengeTimeout));
                let state = network.0.borrow();
                assert!(
                    state
                        .sends
                        .contains(&(1, topology().ap.address, 0, selector))
                );
                assert!(
                    !state
                        .sends
                        .contains(&(1, topology().ap.address, 2, selector))
                );
            }
        }
    }
}

#[test]
fn blocked_udp_is_unknown_and_never_cgnat_or_relay_requirement() {
    let mut network = Network::new(Mode::Independent, Mode::Independent);
    network.0.borrow_mut().faults.blocked = true;
    let report = run(&descriptor(), &topology(), &mut network);
    assert_eq!(
        report.mapping,
        BehaviourSummary::unknown(BehaviourFailure::ChallengeTimeout)
    );
    assert_eq!(
        report.filtering,
        BehaviourSummary::unknown(BehaviourFailure::ChallengeTimeout)
    );
    assert_eq!(report.sent_datagrams, 2);
}

#[test]
fn qualification_is_per_primitive_and_partial_observations_survive_missing_b() {
    let mut t = topology();
    t.bp = None;
    let mut network = Network::new(Mode::Independent, Mode::Address);
    let report = run(&descriptor(), &t, &mut network);
    assert_eq!(
        report.mapping.outcome,
        TraversalOutcome::UnsupportedTopology
    );
    assert_eq!(
        report.filtering.outcome,
        TraversalOutcome::UnsupportedTopology
    );
    assert_eq!(report.mapping_aq, Ok(MappingComparison::Unchanged));
    assert_eq!(report.filtering_aq, Ok(()));
    let mut t = topology();
    t.bp.as_mut().unwrap().filtering_qualified = false; // echo is qualified only for mapping
    let report = run(
        &descriptor(),
        &t,
        &mut Network::new(Mode::Independent, Mode::Independent),
    );
    assert_eq!(
        report.mapping.outcome,
        TraversalOutcome::EndpointIndependent
    );
    assert_eq!(
        report.filtering.outcome,
        TraversalOutcome::UnsupportedTopology
    );
    assert_eq!(
        report.filtering_bp,
        Err(BehaviourFailure::UnsupportedTopology)
    );
    let mut t = topology();
    t.aq.as_mut().unwrap().filtering_qualified = false;
    let report = run(
        &descriptor(),
        &t,
        &mut Network::new(Mode::Independent, Mode::Independent),
    );
    assert_eq!(
        report.filtering.outcome,
        TraversalOutcome::EndpointIndependent
    );
    assert_eq!(
        report.filtering_aq,
        Err(BehaviourFailure::UnsupportedTopology)
    );
}

#[test]
fn wrong_revision_diversity_and_v6_cannot_enable_a_topology() {
    for alter in [0, 1, 2] {
        let mut t = topology();
        match alter {
            0 => t.revision = "another-revision".into(),
            1 => t.ap.address = "[2001:db8::1]:40000".parse().unwrap(),
            _ => t.bp.as_mut().unwrap().address = t.ap.address,
        }
        let mut network = Network::new(Mode::Independent, Mode::Independent);
        let report = run(&descriptor(), &t, &mut network);
        assert_eq!(
            report.mapping.outcome,
            TraversalOutcome::UnsupportedTopology
        );
        if alter != 2 {
            assert_eq!(network.0.borrow().binds, 0);
        }
        assert_eq!(
            report.filtering_bp,
            Err(BehaviourFailure::UnsupportedTopology)
        );
    }
}

#[test]
fn authorization_and_reservation_fail_closed_before_socket_effects() {
    for case in 0..5 {
        let mut d = descriptor();
        if case == 2 {
            d.operations
                .retain(|op| *op != TraversalOperation::ObserveMapping);
        }
        if case == 3 {
            d.budgets.datagram_bytes = 96;
        }
        let session =
            BehaviourSession::from_authenticated_enrollment(&hex::encode([17; 16]), &d).unwrap();
        let mut reserve = reservation(&d);
        let mut network = Network::new(Mode::Independent, Mode::Independent);
        match case {
            0 => network.0.borrow_mut().clock = d.expires_at_ms,
            1 => d.run_id = hex::encode([0x41; 16]),
            4 => reserve.collector_end_ms += 1,
            _ => {}
        }
        let report = collect_udp_behaviour(&d, reserve, session, &topology(), &mut network);
        assert_eq!(report.sent_datagrams, 0);
        assert_eq!(network.0.borrow().binds, 0);
        assert_eq!(
            report.mapping.reason,
            Some(if case == 3 {
                BehaviourFailure::BudgetExhausted
            } else {
                BehaviourFailure::NotAuthorized
            })
        );
    }
    let d = descriptor();
    for id in ["", "xyz", "00000000000000000000000000000000"] {
        assert!(BehaviourSession::from_authenticated_enrollment(id, &d).is_none());
    }
}

#[test]
fn mapping_and_filtering_rebinding_are_independent_unknowns() {
    for filtering in [false, true] {
        let mut network = Network::new(Mode::Independent, Mode::Independent);
        if filtering {
            network.0.borrow_mut().faults.rebind_filtering = true;
        } else {
            network.0.borrow_mut().faults.rebind_mapping = true;
        }
        let report = run(&descriptor(), &topology(), &mut network);
        let (changed, stable) = if filtering {
            (report.filtering, report.mapping)
        } else {
            (report.mapping, report.filtering)
        };
        assert_eq!(
            changed,
            BehaviourSummary::unknown(BehaviourFailure::Rebinding)
        );
        assert_eq!(stable.outcome, TraversalOutcome::EndpointIndependent);
    }
}

#[test]
fn deadlines_cancellation_and_budgets_are_spent_before_io() {
    let mut d = descriptor();
    d.budgets.outbound_datagrams = 1;
    let mut network = Network::new(Mode::Independent, Mode::Independent);
    let report = run(&d, &topology(), &mut network);
    assert_eq!(report.sent_datagrams, 1);
    assert_eq!(
        report.filtering.reason,
        Some(BehaviourFailure::BudgetExhausted)
    );
    assert_eq!(
        report.mapping.reason,
        Some(BehaviourFailure::BudgetExhausted)
    );
    for cancelled in [true, false] {
        let mut network = Network::new(Mode::Independent, Mode::Independent);
        network.0.borrow_mut().faults.cancelled = cancelled;
        network.0.borrow_mut().faults.late = !cancelled;
        let report = run(&descriptor(), &topology(), &mut network);
        assert!(report.sent_datagrams <= 1);
        assert_eq!(
            report.filtering.reason,
            Some(if cancelled {
                BehaviourFailure::Cancelled
            } else {
                BehaviourFailure::Deadline
            })
        );
    }
}

#[test]
fn invalid_padding_family_cookie_frames_and_receive_flood_never_classify() {
    for byte in [40, 72, 96, 101, 115] {
        let mut network = Network::new(Mode::Independent, Mode::Independent);
        network.0.borrow_mut().faults.malformed = Some(byte);
        let report = run(&descriptor(), &topology(), &mut network);
        assert_eq!(report.mapping.outcome, TraversalOutcome::Unknown);
        assert_eq!(report.filtering.outcome, TraversalOutcome::Unknown);
    }
    let mut network = Network::new(Mode::Independent, Mode::Independent);
    network.0.borrow_mut().faults.flood = true;
    let report = run(&descriptor(), &topology(), &mut network);
    assert_eq!(
        report.mapping.reason,
        Some(BehaviourFailure::InvalidResponse)
    );
    assert!(report.sent_datagrams <= 2);
    let mut network = Network::new(Mode::Independent, Mode::Independent);
    network.0.borrow_mut().faults.repeat_tx = true;
    let report = run(&descriptor(), &topology(), &mut network);
    assert_eq!(
        report.mapping.reason,
        Some(BehaviourFailure::InvalidResponse)
    );
}

#[test]
fn owner_transport_golden_vector_decodes_without_changing_wire_bytes() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../vectors/controlled-endpoints-v1.json"
    ))
    .unwrap();
    let response = hex::decode(v["observationHex"].as_str().unwrap()).unwrap();
    assert_eq!(
        decode_observed(&response).unwrap().to_string(),
        v["peer"].as_str().unwrap()
    );
    let mut network = Network::new(Mode::Independent, Mode::Independent);
    network.0.borrow_mut().transactions = 0x21;
    let mut experiment = Experiment {
        network: &mut network,
        session: [0x11; 16],
        end_ms: NOW + 1000,
        remaining: 2,
        sent: 0,
        transactions: BTreeSet::new(),
    };
    struct Golden {
        requests: VecDeque<Vec<u8>>,
        replies: VecDeque<(Vec<u8>, SocketAddr)>,
    }
    impl BehaviourSocket for Golden {
        fn send_to(
            &mut self,
            packet: &[u8],
            destination: SocketAddr,
            _: u64,
        ) -> Result<(), BehaviourFailure> {
            assert_eq!(packet, self.requests.pop_front().unwrap());
            assert_eq!(destination, "127.0.0.1:40000".parse().unwrap());
            Ok(())
        }
        fn receive_from(
            &mut self,
            buffer: &mut [u8],
            _: u64,
        ) -> Result<(usize, SocketAddr), BehaviourFailure> {
            let (packet, source) = self.replies.pop_front().unwrap();
            buffer[..packet.len()].copy_from_slice(&packet);
            Ok((packet.len(), source))
        }
    }
    let bytes = |key| hex::decode(v[key].as_str().unwrap()).unwrap();
    let mut socket = Golden {
        requests: VecDeque::from([bytes("requestHex"), bytes("proofHex")]),
        replies: VecDeque::from([
            (bytes("challengeHex"), "127.0.0.1:40000".parse().unwrap()),
            (response, "127.0.0.2:40000".parse().unwrap()),
        ]),
    };
    let observed = experiment
        .observe(
            &mut socket,
            "127.0.0.1:40000".parse().unwrap(),
            "127.0.0.2:40000".parse().unwrap(),
            0,
            2,
        )
        .unwrap();
    assert_eq!(observed.to_string(), v["peer"].as_str().unwrap());
    assert!(socket.requests.is_empty() && socket.replies.is_empty());
}

#[test]
fn actual_local_sockets_accept_alternate_sources_without_opening_them_in_filtering() {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };
    let ap = UdpSocket::bind("127.0.0.1:0").unwrap();
    let aq = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bp =
        UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), ap.local_addr().unwrap().port())).unwrap();
    let addresses = [
        ap.local_addr().unwrap(),
        aq.local_addr().unwrap(),
        bp.local_addr().unwrap(),
    ];
    let sockets = Arc::new([ap, aq, bp]);
    let stop = Arc::new(AtomicBool::new(false));
    let trace = Arc::new(Mutex::new(Vec::new()));
    let workers = (0..3)
        .map(|ingress| {
            let sockets = sockets.clone();
            let stop = stop.clone();
            let trace = trace.clone();
            std::thread::spawn(move || {
                sockets[ingress]
                    .set_read_timeout(Some(Duration::from_millis(50)))
                    .unwrap();
                while !stop.load(Ordering::Relaxed) {
                    let mut packet = [0; 513];
                    let (n, peer) = match sockets[ingress].recv_from(&mut packet) {
                        Ok(v) => v,
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            continue;
                        }
                        Err(e) => panic!("{e}"),
                    };
                    assert_eq!(n, 96);
                    trace.lock().unwrap().push((ingress, peer));
                    let proof = packet[4] == 2;
                    let outgoing = if proof && packet[5] != 0 {
                        usize::from(packet[5])
                    } else {
                        ingress
                    };
                    let mut reply = packet[..n].to_vec();
                    reply[4] = if proof { 3 } else { 1 };
                    reply[6] = ingress as u8;
                    reply[7] = outgoing as u8;
                    reply[40..72].fill(0x71);
                    if proof {
                        reply.resize(128, 0);
                        reply[96] = 4;
                        let IpAddr::V4(ip) = peer.ip() else {
                            unreachable!()
                        };
                        reply[97..101].copy_from_slice(&ip.octets());
                        reply[113..115].copy_from_slice(&peer.port().to_be_bytes());
                        // A byte-perfect response from the wrong actual sender is
                        // queued first; a connected client would then lose the real one.
                        if outgoing != ingress {
                            sockets[ingress].send_to(&reply, peer).unwrap();
                        }
                    }
                    sockets[outgoing].send_to(&reply, peer).unwrap();
                }
            })
        })
        .collect::<Vec<_>>();
    let qualified = |address| BehaviourEndpoint {
        address,
        mapping_qualified: true,
        filtering_qualified: true,
    };
    let topology = BehaviourTopology {
        revision: "a-p-a-q-b-p-1".into(),
        ap: qualified(addresses[0]),
        aq: Some(qualified(addresses[1])),
        bp: Some(qualified(addresses[2])),
    };
    let result = run(&descriptor(), &topology, &mut UdpBehaviourNetwork::new(NOW));
    stop.store(true, Ordering::Relaxed);
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(
        result.mapping.outcome,
        TraversalOutcome::EndpointIndependent,
        "{result:?}"
    );
    assert_eq!(
        result.filtering.outcome,
        TraversalOutcome::EndpointIndependent,
        "{result:?}"
    );
    let trace = trace.lock().unwrap();
    assert_eq!(trace.len(), 20);
    let filtering_socket = trace[0].1;
    assert!(
        trace[..8]
            .iter()
            .all(|(ingress, peer)| *ingress == 0 && *peer == filtering_socket)
    );
    let mapping_socket = trace[8].1;
    assert_ne!(filtering_socket, mapping_socket);
    assert!(trace[8..].iter().all(|(_, peer)| *peer == mapping_socket));
    assert!(
        [0, 1, 2]
            .iter()
            .all(|i| trace[8..].iter().any(|(ingress, _)| ingress == i))
    );
}
