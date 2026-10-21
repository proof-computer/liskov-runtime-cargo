use super::*;
use std::cell::Cell;
use std::rc::Rc;

fn descriptor() -> TraversalDescriptorV1 {
    {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../../vectors/network-traversal-v1.json"))
                .unwrap();
        serde_json::from_value(
            v["descriptors"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["name"] == "mapping")
                .unwrap()["descriptor"]
                .clone(),
        )
        .unwrap()
    }
}
fn session(d: &TraversalDescriptorV1) -> MappingSession {
    let c = d.mapping.as_ref().unwrap();
    MappingSession::from_authenticated_bootstrap(
        d.clone(),
        MappingBindings {
            claim_authority_digest: &d.claim_authority_digest,
            artifact_digest: &d.artifact_digest,
            helper: &TraversalHelperIdentity {
                version: "cargo-helper-traversal-1",
                digest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            },
            consent_reference: &c.consent_reference,
            processor_allowlist_digest: &c.processor_allowlist_digest,
            exclusive_reservation_digest: &c.exclusive_reservation_digest,
        },
        d.issued_at_ms,
        d.expires_at_ms,
    )
    .unwrap()
}
fn selected() -> SelectedGateway {
    let routes = parse_proc_net_route("Iface Destination Gateway Flags RefCnt Use Metric Mask\neth0 00000000 0100000A 0003 0 0 0 00000000\n").unwrap();
    match super::super::gateway::discover_loaded(&routes, &|| false) {
        GatewayDiscovery::Selected(g) => g,
        other => panic!("{other:?}"),
    }
}
fn plan(protocol: RouterProtocol) -> MappingMethodPlan {
    MappingMethodPlan {
        protocol,
        transport: MappedPortProtocol::Udp,
    }
}
fn authorize(d: &mut TraversalDescriptorV1, protocols: &[TraversalRouterProtocol]) {
    d.mapping.as_mut().unwrap().protocols = protocols.into();
    d.budgets.cleanup_datagrams = 2;
    d.budgets.cleanup_control_requests = 2;
    d.operations.retain(|op| {
        !matches!(
            op,
            TraversalOperation::MapPcp
                | TraversalOperation::MapNatPmp
                | TraversalOperation::MapUpnp
        )
    });
    d.operations.extend(protocols.iter().map(|p| match p {
        TraversalRouterProtocol::Pcp => TraversalOperation::MapPcp,
        TraversalRouterProtocol::NatPmp => TraversalOperation::MapNatPmp,
        TraversalRouterProtocol::UpnpIgd => TraversalOperation::MapUpnp,
    }));
    d.operations.sort();
}

struct Listener {
    port: u16,
    dropped: Rc<Cell<usize>>,
}
impl MappingListener for Listener {
    fn port(&self) -> u16 {
        self.port
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.dropped.set(self.dropped.get() + 1);
    }
}

struct Fixture {
    d: TraversalDescriptorV1,
    now: u64,
    stop: Option<MappingStop>,
    stop_on_verify: Option<MappingStop>,
    stop_after_create: Option<MappingStop>,
    fail_verify: bool,
    bad_binding: bool,
    substitute_phase: bool,
    exhaust_cleanup_time: bool,
    wrong_echo: bool,
    lost_create: bool,
    lost_delete: bool,
    reject_delete: bool,
    lease: u32,
    mismatch: bool,
    events: Vec<&'static str>,
    deadlines: Vec<u64>,
    ports: Vec<u16>,
    dropped: Rc<Cell<usize>>,
    consume_active_time: bool,
    crash: bool,
    created: bool,
    attestations: usize,
    real_sockets: bool,
    baseline_fails: bool,
    upnp_existing: bool,
}
impl Fixture {
    fn new(d: &TraversalDescriptorV1) -> Self {
        Self {
            d: d.clone(),
            now: d.issued_at_ms,
            stop: None,
            stop_on_verify: None,
            stop_after_create: None,
            fail_verify: false,
            bad_binding: false,
            substitute_phase: false,
            exhaust_cleanup_time: false,
            wrong_echo: false,
            lost_create: false,
            lost_delete: false,
            reject_delete: false,
            lease: 60,
            mismatch: false,
            events: vec![],
            deadlines: vec![],
            ports: vec![],
            dropped: Rc::new(Cell::new(0)),
            consume_active_time: false,
            crash: false,
            created: false,
            attestations: 0,
            real_sockets: false,
            baseline_fails: false,
            upnp_existing: false,
        }
    }
    fn run(&mut self, plans: &[MappingMethodPlan]) -> MappingRunReport {
        let g = selected();
        let reservation = ExclusiveReservation::new(g.gateway(), [0x55; 32]).unwrap();
        let d = self.d.clone();
        run_mapping_lifecycle(
            session(&d),
            plans,
            MappingGateway {
                gateway: &g,
                reservation: &reservation,
                local_address: Ipv4Addr::new(10, 0, 0, 2),
                external_address: Some(Ipv4Addr::new(93, 184, 216, 34)),
                igd: None,
                discovery_datagrams: 0,
                discovery_control_requests: 0,
            },
            self,
        )
    }
}
impl MappingRuntime for Fixture {
    fn now_ms(&self) -> u64 {
        self.now
    }
    fn observed_address(&self) -> Ipv4Addr {
        Ipv4Addr::new(93, 184, 216, 34)
    }
    fn stop(&self) -> Option<MappingStop> {
        self.stop
    }
    fn nonce(&mut self) -> Result<[u8; 12], MappingStop> {
        Ok([9; 12])
    }
    fn bind_fresh(
        &mut self,
        protocol: MappedPortProtocol,
    ) -> Result<Box<dyn MappingListener>, MappingStop> {
        self.events.push("bind");
        if self.real_sockets {
            let listener = NativeMappingListener::bind_fresh(protocol)?;
            self.ports.push(listener.port());
            return Ok(Box::new(listener));
        }
        let port = 40_000 + self.ports.len() as u16;
        self.ports.push(port);
        Ok(Box::new(Listener {
            port,
            dropped: self.dropped.clone(),
        }))
    }
    fn path_check(
        &mut self,
        listener: &mut dyn MappingListener,
        check: MappingPathCheck,
        end: u64,
    ) -> Result<MappingPathEvidence, MappingStop> {
        self.deadlines.push(end);
        self.events
            .push(if check.stage == TraversalStage::Baseline {
                "baseline"
            } else {
                "verify"
            });
        self.now += 1;
        if check.stage == TraversalStage::MappingVerify {
            if self.crash {
                panic!("fixture process death before deletion");
            }
            if let Some(stop) = self.stop_on_verify {
                self.stop = Some(stop);
                return Err(stop);
            }
            if self.consume_active_time {
                self.now = end + if self.exhaust_cleanup_time { 5_000 } else { 0 };
                return Err(MappingStop::Deadline);
            }
        }
        let baseline_failed = self.baseline_fails && check.stage == TraversalStage::Baseline;
        if self.real_sockets && !baseline_failed {
            use std::io::{Read, Write};
            use std::net::{IpAddr, TcpStream, UdpSocket};
            use std::time::Duration;
            let port = listener.port();
            let prober = std::thread::spawn(move || {
                let mut echoed = [0; 32];
                if check.transport == TraversalTransport::Tcp {
                    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    stream.write_all(&[7; 32]).unwrap();
                    stream.read_exact(&mut echoed).unwrap();
                } else {
                    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    socket
                        .send_to(&[7; 32], (Ipv4Addr::LOCALHOST, port))
                        .unwrap();
                    assert_eq!(socket.recv_from(&mut echoed).unwrap().0, 32);
                }
                assert_eq!(echoed, [7; 32]);
            });
            let answer = listener.answer_challenge(
                check.stage,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                Duration::from_secs(2),
            );
            prober.join().unwrap();
            assert_eq!(answer, Ok([7; 32]));
        }
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../../vectors/network-traversal-v1.json"))
                .unwrap();
        let mut t: TraversalTranscriptV1 =
            serde_json::from_value(v["proofs"][0]["transcript"].clone()).unwrap();
        t.descriptor_digest = self.d.binding_digest().unwrap();
        t.run_id = self.d.run_id.clone();
        t.expires_at_ms = self.d.expires_at_ms;
        t.stage = check.stage;
        t.method = check.method;
        t.family = check.family;
        t.transport = check.transport;
        t.challenge = hex::encode([7; 32]);
        if self.bad_binding {
            t.run_id = "08".repeat(16);
        }
        if self.substitute_phase {
            t.stage = TraversalStage::MappingVerify;
            t.method = TraversalMethod::Pcp;
        }
        if baseline_failed || (check.stage == TraversalStage::MappingVerify && self.fail_verify) {
            t.outcome = TraversalOutcome::Failed;
            t.error_class = Some(TraversalErrorClass::Timeout);
        }
        Ok(MappingPathEvidence {
            transcript: t,
            echoed_challenge: if baseline_failed {
                None
            } else {
                Some(if self.wrong_echo { [8; 32] } else { [7; 32] })
            },
        })
    }
    fn attest_path(&mut self, t: &TraversalTranscriptV1, end: u64) -> Result<(), MappingStop> {
        assert!(t.validate_scope(&self.d, self.now).is_ok());
        assert!(self.now < end);
        self.attestations += 1;
        Ok(())
    }
    fn router_exchange(
        &mut self,
        _destination: SocketAddr,
        request: &[u8],
        response: &mut [u8],
        end: u64,
    ) -> Result<usize, ControlRefusal> {
        self.deadlines.push(end);
        self.now += 1;
        if request.starts_with(b"POST ") {
            let xml = if request
                .windows(b"#AddPortMapping".len())
                .any(|w| w == b"#AddPortMapping")
            {
                self.events.push("create");
                self.created = true;
                include_str!("../../../vectors/upnp-igd-add-ok.xml").to_owned()
            } else if request
                .windows(b"#DeletePortMapping\"".len())
                .any(|w| w == b"#DeletePortMapping\"")
            {
                self.events.push("delete");
                self.created = false;
                include_str!("../../../vectors/upnp-igd-delete-ok.xml").to_owned()
            } else if self.upnp_existing {
                self.events.push("inspect");
                include_str!("../../../vectors/upnp-igd-existing-static.xml").to_owned()
            } else if !self.created {
                self.events.push("inspect");
                include_str!("../../../vectors/upnp-igd-absent-714.xml").to_owned()
            } else {
                self.events.push("confirm");
                include_str!("../../../vectors/upnp-igd-grant-finite.xml")
                    .replace("192.0.2.10", "10.0.0.2")
                    .replace(
                        "<NewProtocol>UDP</NewProtocol>",
                        if request
                            .windows(b"<NewProtocol>TCP</NewProtocol>".len())
                            .any(|w| w == b"<NewProtocol>TCP</NewProtocol>")
                        {
                            "<NewProtocol>TCP</NewProtocol>"
                        } else {
                            "<NewProtocol>UDP</NewProtocol>"
                        },
                    )
                    .replace(
                        "<NewLeaseDuration>60",
                        &format!("<NewLeaseDuration>{}", self.lease),
                    )
            };
            let status = if xml.contains("<s:Fault>") { 500 } else { 200 };
            let reply = format!(
                "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\n\r\n{xml}",
                xml.len()
            );
            response[..reply.len()].copy_from_slice(reply.as_bytes());
            return Ok(reply.len());
        }
        let pcp = request[0] == 2;
        let delete = if pcp {
            request[4..8] == [0; 4]
        } else {
            request[8..12] == [0; 4]
        };
        self.events.push(if delete { "delete" } else { "create" });
        if !delete {
            self.created = true;
            self.stop = self.stop_after_create;
        }
        if (!delete && self.lost_create) || (delete && self.lost_delete) {
            return Err(ControlRefusal::Bounded);
        }
        let lease = if delete { 0 } else { self.lease };
        let n = if pcp {
            response[..60].copy_from_slice(request);
            response[1] = 0x81;
            response[3] = if delete && self.reject_delete { 2 } else { 0 };
            response[4..8].copy_from_slice(&lease.to_be_bytes());
            response[8..12].copy_from_slice(&100u32.to_be_bytes());
            response[44..54].fill(0);
            response[54..56].fill(0xff);
            response[56..60].copy_from_slice(&if self.mismatch {
                [93, 184, 216, 35]
            } else {
                [93, 184, 216, 34]
            });
            60
        } else {
            response[..16].fill(0);
            response[1] = request[1] | 0x80;
            response[3] = if delete && self.reject_delete { 2 } else { 0 };
            response[4..8].copy_from_slice(&100u32.to_be_bytes());
            response[8..10].copy_from_slice(&request[4..6]);
            response[10..12].copy_from_slice(&request[4..6]);
            response[12..16].copy_from_slice(&lease.to_be_bytes());
            16
        };
        if delete && !self.reject_delete {
            self.created = false;
        }
        Ok(n)
    }
}

#[test]
fn scope_and_independent_consent_bindings_refuse_before_any_effect() {
    let original = descriptor();
    for field in 0..7 {
        let mut d = original.clone();
        match field {
            0 => d.mapping.as_mut().unwrap().consent_reference = "another-consent".into(),
            1 => {
                d.mapping.as_mut().unwrap().processor_allowlist_digest =
                    format!("sha256:{}", "77".repeat(32))
            }
            2 => {
                d.mapping.as_mut().unwrap().exclusive_reservation_digest =
                    format!("sha256:{}", "77".repeat(32))
            }
            3 => d.claim_authority_digest = format!("sha256:{}", "77".repeat(32)),
            4 => d.mapping.as_mut().unwrap().prior_uncertainty_resolved = false,
            5 => d.mapping.as_mut().unwrap().finite_expiry_verified = false,
            _ => d.operations.retain(|op| *op != TraversalOperation::MapPcp),
        }
        let c = original.mapping.as_ref().unwrap();
        assert!(
            MappingSession::from_authenticated_bootstrap(
                d,
                MappingBindings {
                    claim_authority_digest: &original.claim_authority_digest,
                    artifact_digest: &original.artifact_digest,
                    helper: &TraversalHelperIdentity {
                        version: "cargo-helper-traversal-1",
                        digest: "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                    },
                    consent_reference: &c.consent_reference,
                    processor_allowlist_digest: &c.processor_allowlist_digest,
                    exclusive_reservation_digest: &c.exclusive_reservation_digest
                },
                original.issued_at_ms,
                original.expires_at_ms
            )
            .is_err()
        );
    }
    let mut fixture = Fixture::new(&original);
    let result = fixture.run(&[plan(RouterProtocol::NatPmp)]);
    assert_eq!(result.stopped, Some(MappingStop::InvalidBinding));
    assert!(fixture.events.is_empty());
}

#[test]
fn baseline_accepted_lease_external_path_and_cleanup_are_separate_ordered_results() {
    let d = descriptor();
    let mut f = Fixture::new(&d);
    let report = f.run(&[plan(RouterProtocol::Pcp)]);
    assert_eq!(f.events, ["bind", "baseline", "create", "verify", "delete"]);
    let row = report.methods[0];
    assert_eq!(row.baseline.unwrap().stage, TraversalStage::Baseline);
    assert_eq!(row.create, Some(TraversalOutcome::Succeeded));
    assert_eq!(
        row.verification.unwrap().stage,
        TraversalStage::MappingVerify
    );
    assert_eq!(row.cleanup, TraversalCleanup::ConfirmedDeleted);
    assert_eq!(f.dropped.get(), 1);
    assert_eq!(report.external_dialbacks, 2);
    assert_eq!(report.control_requests, 6);
    assert_eq!(report.sent_datagrams, 4);
    assert!(
        f.deadlines[..3]
            .iter()
            .all(|end| *end == d.issued_at_ms + 25_000)
    );
    assert_eq!(*f.deadlines.last().unwrap(), d.issued_at_ms + 30_000);
}

#[test]
fn failure_cancel_expiry_and_shutdown_still_delete_owned_mapping() {
    for stop in [
        None,
        Some(MappingStop::Cancelled),
        Some(MappingStop::Expired),
        Some(MappingStop::GracefulShutdown),
        Some(MappingStop::Budget),
    ] {
        let mut f = Fixture::new(&descriptor());
        f.fail_verify = true;
        f.stop_on_verify = stop;
        let r = f.run(&[plan(RouterProtocol::Pcp)]);
        assert_eq!(
            r.methods[0].cleanup,
            TraversalCleanup::ConfirmedDeleted,
            "{stop:?}"
        );
        assert_eq!(f.events.last(), Some(&"delete"));
        assert!(!f.created);
        if stop.is_none() {
            assert_eq!(
                r.methods[0].verification.unwrap().outcome,
                TraversalOutcome::Failed
            );
        }
    }
}

#[test]
fn cleanup_time_and_packets_survive_ordinary_deadline_and_cancellation_after_create() {
    let mut f = Fixture::new(&descriptor());
    f.consume_active_time = true;
    assert_eq!(
        f.run(&[plan(RouterProtocol::Pcp)]).methods[0].cleanup,
        TraversalCleanup::ConfirmedDeleted
    );
    let mut f = Fixture::new(&descriptor());
    f.stop_after_create = Some(MappingStop::GracefulShutdown);
    let r = f.run(&[plan(RouterProtocol::Pcp)]);
    assert_eq!(f.events, ["bind", "baseline", "create", "delete"]);
    assert_eq!(r.methods[0].cleanup, TraversalCleanup::ConfirmedDeleted);
}

#[test]
fn invalid_or_unanswered_path_challenge_never_authorizes_create() {
    for wrong_echo in [false, true] {
        let mut f = Fixture::new(&descriptor());
        f.wrong_echo = wrong_echo;
        f.bad_binding = !wrong_echo;
        let r = f.run(&[plan(RouterProtocol::Pcp)]);
        assert_eq!(r.stopped, Some(MappingStop::InvalidBinding));
        assert_eq!(f.events, ["bind", "baseline"]);
        assert_eq!(f.attestations, 0);
    }
}

#[test]
fn router_address_mismatch_never_reaches_verifier_and_still_cleans_up() {
    let mut f = Fixture::new(&descriptor());
    f.mismatch = true;
    let r = f.run(&[plan(RouterProtocol::Pcp)]);
    assert_eq!(
        r.methods[0].verification.unwrap().outcome,
        TraversalOutcome::UnverifiableEndpoint
    );
    assert_eq!(r.methods[0].cleanup, TraversalCleanup::ConfirmedDeleted);
    assert_eq!(f.events, ["bind", "baseline", "create", "delete"]);
}

#[test]
fn sequential_methods_use_fresh_listeners_and_cleanup_before_next_baseline() {
    let mut d = descriptor();
    authorize(
        &mut d,
        &[
            TraversalRouterProtocol::Pcp,
            TraversalRouterProtocol::NatPmp,
        ],
    );
    let mut f = Fixture::new(&d);
    let r = f.run(&[plan(RouterProtocol::Pcp), plan(RouterProtocol::NatPmp)]);
    assert_eq!(r.methods.len(), 2);
    assert_eq!(
        f.events,
        [
            "bind", "baseline", "create", "verify", "delete", "bind", "baseline", "create",
            "verify", "delete"
        ]
    );
    assert_ne!(f.ports[0], f.ports[1]);
    assert_eq!(f.dropped.get(), 2);
    assert_eq!(r.control_requests, 12);
    assert_eq!(r.external_dialbacks, 4);
}

#[test]
fn unknown_creation_or_cleanup_suppresses_all_later_methods() {
    for fault in 0..3 {
        let mut d = descriptor();
        authorize(
            &mut d,
            &[
                TraversalRouterProtocol::Pcp,
                TraversalRouterProtocol::NatPmp,
            ],
        );
        let mut f = Fixture::new(&d);
        f.lost_create = fault == 0;
        f.lost_delete = fault == 1;
        f.reject_delete = fault == 2;
        let r = f.run(&[plan(RouterProtocol::Pcp), plan(RouterProtocol::NatPmp)]);
        assert_eq!(r.methods.len(), 1);
        assert!(f.created);
        assert_eq!(f.ports.len(), 1);
        if fault == 0 {
            assert_eq!(
                r.methods[0].create,
                Some(TraversalOutcome::CreationOutcomeUnknown)
            );
            assert!(r.methods[0].expiry_unknown);
            assert!(!f.events.contains(&"delete"));
        } else {
            assert!(f.events.contains(&"delete"));
            assert_ne!(r.methods[0].cleanup, TraversalCleanup::ConfirmedDeleted);
            assert_eq!(r.methods[0].expiry_unknown, fault == 1);
        }
    }
}

#[test]
fn overlong_owned_lease_inline_delete_uses_reserved_allowance_even_if_cancelled() {
    let mut f = Fixture::new(&descriptor());
    f.lease = 121;
    f.stop_after_create = Some(MappingStop::Cancelled);
    let r = f.run(&[plan(RouterProtocol::Pcp)]);
    assert_eq!(
        r.methods[0].create,
        Some(TraversalOutcome::UnsupportedFiniteLease)
    );
    assert_eq!(r.methods[0].cleanup, TraversalCleanup::ConfirmedDeleted);
    assert_eq!(f.events, ["bind", "baseline", "create", "delete"]);
    assert!(!f.created);
}

#[test]
fn combined_profile_that_exceeds_budgets_runs_only_one_method_and_records_deferral() {
    let mut d = descriptor();
    authorize(
        &mut d,
        &[
            TraversalRouterProtocol::Pcp,
            TraversalRouterProtocol::NatPmp,
            TraversalRouterProtocol::UpnpIgd,
        ],
    );
    let mut f = Fixture::new(&d);
    let r = f.run(&[
        plan(RouterProtocol::Pcp),
        plan(RouterProtocol::NatPmp),
        plan(RouterProtocol::UpnpIgd),
    ]);
    assert_eq!(r.methods.len(), 1);
    assert_eq!(r.deferred_methods, 2);
    assert_eq!(r.methods[0].cleanup, TraversalCleanup::ConfirmedDeleted);
    assert!(r.control_requests <= d.budgets.control_requests);
}

#[test]
fn report_delivery_retry_cannot_replay_a_consumed_session() {
    let mut f = Fixture::new(&descriptor());
    let report = f.run(&[plan(RouterProtocol::Pcp)]);
    let events = f.events.clone();
    let mut delivery = Vec::new();
    for _ in 0..2 {
        delivery.push(format!("{report:?}"));
    }
    assert_eq!(delivery[0], delivery[1]);
    assert_eq!(events, f.events);
    assert!(!delivery[0].contains("93.184.216.34"));
    assert!(!delivery[0].contains(&"07".repeat(32)));
}

#[test]
fn crash_fixture_never_claims_destructor_cleanup_or_verified_expiry() {
    let mut f = Fixture::new(&descriptor());
    f.crash = true;
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || f.run(&[plan(RouterProtocol::Pcp)])
        ))
        .is_err()
    );
    assert!(f.created);
    assert!(!f.events.contains(&"delete"));
    assert_eq!(f.dropped.get(), 1); // listener drop is not router deletion
}

#[test]
fn real_localhost_tcp_and_udp_challenges_cross_the_dedicated_socket_once() {
    use std::io::{Read, Write};
    use std::net::{IpAddr, TcpStream, UdpSocket};
    use std::time::Duration;
    for protocol in [MappedPortProtocol::Tcp, MappedPortProtocol::Udp] {
        let mut listener = NativeMappingListener::bind_fresh(protocol).unwrap();
        let port = listener.port();
        let prober = std::thread::spawn(move || {
            let nonce = [0x67; 32];
            let mut echo = [0; 32];
            match protocol {
                MappedPortProtocol::Tcp => {
                    let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
                    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                    s.write_all(&nonce).unwrap();
                    s.read_exact(&mut echo).unwrap();
                }
                MappedPortProtocol::Udp => {
                    let s = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
                    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                    s.send_to(&nonce, (Ipv4Addr::LOCALHOST, port)).unwrap();
                    let (n, source) = s.recv_from(&mut echo).unwrap();
                    assert_eq!(n, 32);
                    assert_eq!(source.port(), port);
                }
            }
            assert_eq!(nonce, echo);
        });
        assert_eq!(
            listener
                .answer_challenge(
                    TraversalStage::Baseline,
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    Duration::from_secs(2)
                )
                .unwrap(),
            [0x67; 32]
        );
        prober.join().unwrap();
        assert_eq!(
            listener.answer_challenge(
                TraversalStage::Baseline,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                Duration::from_secs(2)
            ),
            Err(MappingStop::Budget)
        );
        drop(listener);
        match protocol {
            MappedPortProtocol::Tcp => {
                /* TIME_WAIT is not an outstanding listener. */
                assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err());
            }
            MappedPortProtocol::Udp => {
                UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
            }
        }
    }
}

#[test]
fn truncated_and_wrong_source_udp_challenges_do_not_elicit_a_reply() {
    use std::net::{IpAddr, UdpSocket};
    use std::time::Duration;
    for wrong_source in [false, true] {
        let mut listener = NativeMappingListener::bind_fresh(MappedPortProtocol::Udp).unwrap();
        let s = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        s.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        s.send_to(
            if wrong_source { &[7; 32] } else { &[7; 31] },
            (Ipv4Addr::LOCALHOST, listener.port()),
        )
        .unwrap();
        let expected = if wrong_source {
            Ipv4Addr::new(127, 0, 0, 2)
        } else {
            Ipv4Addr::LOCALHOST
        };
        assert!(
            listener
                .answer_challenge(
                    TraversalStage::Baseline,
                    IpAddr::V4(expected),
                    Duration::from_millis(50)
                )
                .is_err()
        );
        assert!(s.recv_from(&mut [0; 33]).is_err());
    }
}

#[test]
fn ordinary_traffic_cannot_spend_cleanup_packets_or_requests() {
    let d = descriptor();
    let mut a = Accounting::new(&d.budgets);
    let ordinary_d = a.ordinary_datagrams;
    let ordinary_c = a.ordinary_control;
    a.charge(ordinary_d, ordinary_c, 0, false).unwrap();
    assert_eq!(a.charge(1, 0, 0, false), Err(MappingStop::Budget));
    assert_eq!(a.charge(0, 1, 0, false), Err(MappingStop::Budget));
    assert_eq!(a.cleanup_datagrams, d.budgets.cleanup_datagrams);
    assert_eq!(a.cleanup_control, d.budgets.cleanup_control_requests);
    a.charge(1, 1, 0, true).unwrap();
}

fn igd_descriptor(gateway: &SelectedGateway) -> IgdControlDescriptor {
    struct Search;
    impl IgdSearch for Search {
        fn search(
            &mut self,
            gateway: Ipv4Addr,
            _: SocketAddr,
            _: &[u8],
            _: &dyn Fn() -> bool,
            _: &dyn Fn() -> bool,
        ) -> Result<Vec<Vec<u8>>, IgdIoError> {
            Ok(vec![format!("HTTP/1.1 200 OK\r\nLOCATION: http://{gateway}:5000/root.xml\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n").into_bytes()])
        }
    }
    struct Docs;
    impl IgdDocuments for Docs {
        fn get(
            &mut self,
            _: &str,
            _: SocketAddr,
            _: &dyn Fn() -> bool,
            _: &dyn Fn() -> bool,
        ) -> Result<Vec<u8>, IgdIoError> {
            Ok(include_bytes!("../../../vectors/igd-wanip-device.xml").to_vec())
        }
    }
    match discover_igd(gateway, &mut Search, &mut Docs, &|| false, &|| false) {
        IgdDiscovery::Found(d) => d,
        result => panic!("{result:?}"),
    }
}

#[test]
fn per_method_request_counts_match_the_reserved_protocol_and_transport_costs() {
    for (protocol, authorized, controls, router_datagrams) in [
        (RouterProtocol::Pcp, TraversalRouterProtocol::Pcp, 6, 2),
        (
            RouterProtocol::NatPmp,
            TraversalRouterProtocol::NatPmp,
            6,
            2,
        ),
        (
            RouterProtocol::UpnpIgd,
            TraversalRouterProtocol::UpnpIgd,
            8,
            0,
        ),
    ] {
        for transport in [MappedPortProtocol::Tcp, MappedPortProtocol::Udp] {
            let mut d = descriptor();
            authorize(&mut d, &[authorized]);
            let mut f = Fixture::new(&d);
            let g = selected();
            let reservation = ExclusiveReservation::new(g.gateway(), [0x55; 32]).unwrap();
            let igd = igd_descriptor(&g);
            let r = run_mapping_lifecycle(
                session(&d),
                &[MappingMethodPlan {
                    protocol,
                    transport,
                }],
                MappingGateway {
                    gateway: &g,
                    reservation: &reservation,
                    local_address: Ipv4Addr::new(10, 0, 0, 2),
                    external_address: Some(f.observed_address()),
                    igd: Some(&igd),
                    discovery_datagrams: 0,
                    discovery_control_requests: 0,
                },
                &mut f,
            );
            assert_eq!(r.stopped, None, "{protocol:?} {transport:?}");
            assert_eq!(r.methods[0].cleanup, TraversalCleanup::ConfirmedDeleted);
            assert_eq!(r.control_requests, controls, "{protocol:?} {transport:?}");
            assert_eq!(
                r.sent_datagrams,
                router_datagrams
                    + if transport == MappedPortProtocol::Udp {
                        2
                    } else {
                        0
                    },
                "{protocol:?} {transport:?}"
            );
            assert_eq!(r.external_dialbacks, 2);
        }
    }
}

#[test]
fn upnp_lifecycle_uses_real_inspection_create_confirm_and_delete_codecs() {
    for existing in [false, true] {
        for lease in [60, 121] {
            let mut d = descriptor();
            authorize(&mut d, &[TraversalRouterProtocol::UpnpIgd]);
            let mut f = Fixture::new(&d);
            f.upnp_existing = existing;
            f.lease = lease;
            let g = selected();
            let reservation = ExclusiveReservation::new(g.gateway(), [0x55; 32]).unwrap();
            let igd = igd_descriptor(&g);
            let r = run_mapping_lifecycle(
                session(&d),
                &[plan(RouterProtocol::UpnpIgd)],
                MappingGateway {
                    gateway: &g,
                    reservation: &reservation,
                    local_address: Ipv4Addr::new(10, 0, 0, 2),
                    external_address: Some(f.observed_address()),
                    igd: Some(&igd),
                    discovery_datagrams: 1,
                    discovery_control_requests: 2,
                },
                &mut f,
            );
            assert_eq!(r.methods.len(), 1);
            if existing {
                assert_eq!(r.methods[0].cleanup, TraversalCleanup::NotCreated);
                assert_eq!(f.events, ["bind", "baseline", "inspect"]);
            } else {
                assert_eq!(
                    r.methods[0].cleanup,
                    TraversalCleanup::ConfirmedDeleted,
                    "{r:?} {:?}",
                    f.events
                );
                assert_eq!(f.events.last(), Some(&"delete"));
                assert!(!f.created);
                if lease > 120 {
                    assert_eq!(
                        r.methods[0].create,
                        Some(TraversalOutcome::UnsupportedFiniteLease)
                    );
                    assert!(!f.events.contains(&"verify"));
                } else {
                    assert_eq!(
                        r.methods[0].verification.unwrap().outcome,
                        TraversalOutcome::Succeeded
                    );
                }
            }
        }
    }
}

#[test]
fn full_lifecycle_keeps_one_real_listener_for_baseline_and_mapped_tcp_or_udp() {
    for transport in [MappedPortProtocol::Tcp, MappedPortProtocol::Udp] {
        let mut f = Fixture::new(&descriptor());
        f.real_sockets = true;
        let r = f.run(&[MappingMethodPlan {
            protocol: RouterProtocol::Pcp,
            transport,
        }]);
        assert_eq!(r.methods[0].cleanup, TraversalCleanup::ConfirmedDeleted);
        assert_eq!(
            r.methods[0].baseline.unwrap().outcome,
            TraversalOutcome::Succeeded
        );
        assert_eq!(
            r.methods[0].verification.unwrap().outcome,
            TraversalOutcome::Succeeded
        );
        assert_eq!(f.attestations, 2);
        assert_eq!(f.ports.len(), 1);
    }
}

#[test]
fn phase_substitution_is_refused_before_attestation_or_mutation() {
    let mut f = Fixture::new(&descriptor());
    f.substitute_phase = true;
    let r = f.run(&[plan(RouterProtocol::Pcp)]);
    assert_eq!(r.stopped, Some(MappingStop::InvalidBinding));
    assert_eq!(f.attestations, 0);
    assert_eq!(f.events, ["bind", "baseline"]);
}

#[test]
fn an_expired_cleanup_deadline_never_becomes_confirmed_deletion() {
    let mut f = Fixture::new(&descriptor());
    f.consume_active_time = true;
    f.exhaust_cleanup_time = true;
    let r = f.run(&[plan(RouterProtocol::Pcp)]);
    assert_eq!(r.methods[0].cleanup, TraversalCleanup::LeaseExpiryPending);
    assert!(!r.methods[0].expiry_unknown);
    assert!(f.created);
    assert!(!f.events.contains(&"delete"));
    assert_eq!(r.stopped, Some(MappingStop::Deadline));
}

#[test]
fn a_different_gateway_reservation_never_authorizes_baseline_or_mutation() {
    let d = descriptor();
    let g = selected();
    let wrong = ExclusiveReservation::new(g.gateway(), [0x66; 32]).unwrap();
    let mut f = Fixture::new(&d);
    let r = run_mapping_lifecycle(
        session(&d),
        &[plan(RouterProtocol::Pcp)],
        MappingGateway {
            gateway: &g,
            reservation: &wrong,
            local_address: Ipv4Addr::new(10, 0, 0, 2),
            external_address: None,
            igd: None,
            discovery_datagrams: 0,
            discovery_control_requests: 0,
        },
        &mut f,
    );
    assert_eq!(r.stopped, Some(MappingStop::InvalidBinding));
    assert!(f.events.is_empty());
}

#[test]
fn failed_baseline_with_no_challenge_can_be_followed_by_proven_mapped_reachability() {
    for transport in [MappedPortProtocol::Tcp, MappedPortProtocol::Udp] {
        let mut f = Fixture::new(&descriptor());
        f.real_sockets = true;
        f.baseline_fails = true;
        let report = f.run(&[MappingMethodPlan {
            protocol: RouterProtocol::Pcp,
            transport,
        }]);
        let row = report.methods[0];
        assert_eq!(row.baseline.unwrap().outcome, TraversalOutcome::Failed);
        assert_eq!(row.create, Some(TraversalOutcome::Succeeded));
        assert_eq!(
            row.verification.unwrap().outcome,
            TraversalOutcome::Succeeded
        );
        assert_eq!(row.cleanup, TraversalCleanup::ConfirmedDeleted);
        assert_eq!(f.attestations, 2);
        assert_eq!(f.ports.len(), 1);
    }
}
