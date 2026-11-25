//! ADR-0234 offline oracle. Control is in process and every UDP packet stays on
//! loopback. The fixture validates the actual source tuple before disclosing
//! candidates and can drop or change the source of direct traffic independently.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};

use super::super::*;
use super::wire::*;
use super::{PairBindings, PairIoError, PairNetwork, PairSession};
use crate::http::HttpResponse;
use crate::processor_facts::FactSigner;

const FIXTURE_KEY: [u8; 32] = [7; 32];
#[derive(Clone, Copy)]
pub(super) enum Topology {
    Direct,
    #[cfg(test)]
    BlockDirect,
    #[cfg(test)]
    OneWay,
    #[cfg(test)]
    WrongPeer,
    #[cfg(test)]
    Rebind,
}

struct Signature(Ed25519KeyPair);

impl Signature {
    fn new(role: usize) -> Self {
        Self(Ed25519KeyPair::from_seed_unchecked(&[1 + role as u8; 32]).unwrap())
    }

    fn public_key(&self) -> String {
        format!("0x{}", hex::encode(self.0.public_key().as_ref()))
    }
}

impl FactSigner for Signature {
    fn sign_ed25519(&self, message: &[u8]) -> Option<String> {
        let transcript: TraversalTranscriptV1 = serde_json::from_slice(message).ok()?;
        assert_eq!(transcript.signing_message().ok()?, message);
        Some(format!("0x{}", hex::encode(self.0.sign(message).as_ref())))
    }
}

pub(super) fn fixture_descriptor(role: usize, experiment_ms: u64) -> TraversalDescriptorV1 {
    let name = ["pair_first", "pair_second"][role];
    let mut descriptor = super::super::fixture_descriptor(name).unwrap();
    let pair = descriptor.pair.as_mut().unwrap();
    for (role, participant) in pair.participants.iter_mut().enumerate() {
        participant.runtime_signer = Signature::new(role).public_key();
    }
    descriptor.run_id = format!("{:032x}", role + 1);
    descriptor.budgets.experiment_ms = experiment_ms;
    descriptor.budgets.cleanup_reserve_ms = experiment_ms / 10;
    // Mirror the owner's mint rule with the native delivery floor and keep
    // the pair's grant deadline fixed as the roles bootstrap independently.
    descriptor.deadline_ms = descriptor.expires_at_ms - EXISTING_DELIVERY_RESERVE_MS;
    assert!(
        descriptor
            .operations
            .contains(&TraversalOperation::RegisterEndpoint)
    );
    descriptor
}

#[derive(Default)]
struct Member {
    descriptor: Option<TraversalDescriptorV1>,
    endpoint: Option<SocketAddr>,
    transaction: Option<String>,
    relay: bool,
    next_sequence: u16,
    challenge: Option<String>,
}

struct State {
    topology: Topology,
    members: [Member; 2],
    end: Option<u64>,
    first_waiting: Option<mpsc::Sender<()>>,
    bootstraps: [u16; 2],
    post_count: [u16; 2],
    sent_count: [u16; 2],
    direct_sources: [Option<SocketAddr>; 2],
}

struct Oracle {
    socket: UdpSocket,
    origin_ms: u64,
    started: Instant,
    state: Mutex<State>,
}

impl Oracle {
    fn now(&self) -> u64 {
        self.origin_ms + self.started.elapsed().as_millis() as u64
    }

    fn address(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    fn new(origin_ms: u64, topology: Topology, first_waiting: Option<mpsc::Sender<()>>) -> Self {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        Self {
            socket,
            origin_ms,
            started: Instant::now(),
            state: Mutex::new(State {
                topology,
                members: [Member::default(), Member::default()],
                end: None,
                first_waiting,
                bootstraps: [0; 2],
                post_count: [0; 2],
                sent_count: [0; 2],
                direct_sources: [None; 2],
            }),
        }
    }

    fn bootstrap(
        &self,
        role: usize,
        descriptor: &TraversalDescriptorV1,
    ) -> (PairSession, Signature) {
        self.state.lock().unwrap().bootstraps[role] += 1;
        assert!(self.now() > descriptor.issued_at_ms);
        let grant = encode_traversal_capability(&FIXTURE_KEY, descriptor).unwrap();
        let grant = serde_json::from_slice(&grant).unwrap();
        let signer = Signature::new(role);
        let session = PairSession::from_authenticated_bootstrap(
            grant,
            PairBindings {
                claim_authority_digest: &descriptor.claim_authority_digest,
                artifact_digest: &descriptor.artifact_digest,
                helper: &FIXTURE_HELPER,
                runtime_signer: &signer.public_key(),
            },
            self.now(),
            descriptor.expires_at_ms,
        )
        .unwrap();
        (session, signer)
    }

    fn enroll(&self, state: &mut State, role: usize, body: &[u8]) -> HttpResponse {
        let now = self.now();
        let descriptor = decode_traversal_capability(&FIXTURE_KEY, body, now).unwrap();
        assert_eq!(
            role == 0,
            descriptor.participant_role == Some(TraversalParticipantRole::First)
        );
        assert!(state.members[role].descriptor.is_none());
        if let Some(other) = &state.members[1 - role].descriptor {
            let (first, second) = if role == 0 {
                (&descriptor, other)
            } else {
                (other, &descriptor)
            };
            if validate_traversal_pair(first, second).is_err() {
                return response(409, json!({"status":"wrong_peer"}));
            }
        }
        if state.end.is_some_and(|until| now >= until) {
            return response(410, json!({"status":"expired"}));
        }
        let until = (now + descriptor.budgets.experiment_ms).min(descriptor.deadline_ms)
            - descriptor.budgets.cleanup_reserve_ms;
        let until = state.end.map_or(until, |previous| previous.min(until));
        state.end = Some(until);
        state.members[role].descriptor = Some(descriptor);
        response(
            200,
            Enrollment {
                session: handle(role),
                until_ms: until,
            },
        )
    }

    fn control(&self, state: &mut State, role: usize, body: &[u8]) -> HttpResponse {
        let request: Control<'_> = serde_json::from_slice(body).unwrap();
        assert_eq!(request.session, handle(role));
        let until = state.end.unwrap();
        if self.now() >= until {
            return response(410, json!({"status":"expired"}));
        }
        assert!(state.members[role].descriptor.is_some());
        let enrolled = state
            .members
            .iter()
            .all(|member| member.descriptor.is_some());
        let endpoints = state.members.iter().all(|member| member.endpoint.is_some());
        let mut progress = if endpoints {
            Progress::Ready
        } else if enrolled {
            Progress::AwaitingEndpoint
        } else {
            Progress::PeerAbsent
        };
        if role == 0 && progress == Progress::PeerAbsent {
            if let Some(notify) = state.first_waiting.take() {
                notify.send(()).unwrap();
            }
        }
        let candidate = match request.action {
            Action::Candidates if endpoints && !state.members.iter().any(|member| member.relay) => {
                state.members[1 - role].endpoint
            }
            Action::Relay if endpoints => {
                state.members[role].relay = true;
                if !state.members[1 - role].relay {
                    progress = Progress::AwaitingRelay;
                }
                None
            }
            _ => None,
        };
        let phase = if state.members.iter().all(|member| member.relay) {
            Phase::RelayControl
        } else {
            Phase::Direct
        };
        response(
            200,
            Status {
                phase,
                progress,
                candidate,
                until_ms: until,
            },
        )
    }

    fn datagram(&self, state: &mut State, packet: &[u8], role: usize, source: SocketAddr) {
        let mut buffer = [0; DATAGRAM_MAX + 1];
        let (length, observed) = self.socket.recv_from(&mut buffer).unwrap();
        assert_eq!(observed, source);
        assert_eq!(&buffer[..length], packet);
        let request: Value = serde_json::from_slice(packet).unwrap();
        assert_eq!(request["session"], handle(role));
        if self.now() >= state.end.unwrap() {
            return;
        }

        let transaction = request["transaction"].as_str().unwrap();
        let member = &state.members[role];
        let rebound = match state.topology {
            #[cfg(test)]
            Topology::Rebind => member.endpoint.is_some(),
            _ => false,
        };
        let cookie = sha256(format!("{observed}:{transaction}:{rebound}").as_bytes());
        let cookie = cookie.strip_prefix("sha256:").unwrap();
        match request["kind"].as_str().unwrap() {
            "cookie" => {
                assert_eq!(request["padding"], COOKIE_PADDING);
                self.send(
                    &Registration::Cookie {
                        session: handle(role),
                        transaction: transaction.into(),
                        cookie: cookie.into(),
                    },
                    observed,
                );
            }
            "register" => {
                assert_eq!(request["cookie"], cookie);
                assert!(member.endpoint.is_none());
                state.members[role].endpoint = Some(observed);
                state.members[role].transaction = Some(transaction.into());
                self.send(&Registration::Registered, observed);
            }
            "relay" => {
                assert_eq!(request["cookie"], cookie);
                self.forward(state, role, transaction, observed, &request);
            }
            _ => panic!("unexpected coordinator datagram"),
        }
    }

    fn forward(
        &self,
        state: &mut State,
        role: usize,
        transaction: &str,
        from: SocketAddr,
        request: &Value,
    ) {
        let (sender, peer) = if role == 0 {
            let [sender, peer] = &mut state.members;
            (sender, peer)
        } else {
            let [peer, sender] = &mut state.members;
            (sender, peer)
        };
        assert!(sender.relay && peer.relay);
        assert_eq!(sender.endpoint, Some(from));
        assert_eq!(sender.transaction.as_deref(), Some(transaction));
        let sequence = request["sequence"].as_u64().unwrap() as u16;
        assert_eq!(sequence, sender.next_sequence);
        let frame: Frame = serde_json::from_value(request["frame"].clone()).unwrap();
        assert_eq!(sequence, frame.sequence());
        match &frame {
            Frame::Challenge(nonce) => assert!(sender.challenge.replace(nonce.clone()).is_none()),
            Frame::Response(nonce) => assert_eq!(peer.challenge.take().as_ref(), Some(nonce)),
        }
        sender.next_sequence += 1;
        let descriptor = sender.descriptor.as_ref().unwrap();
        self.send(
            &RelayDelivery {
                domain: RELAY_DOMAIN.into(),
                pair_id: descriptor.pair.as_ref().unwrap().pair_id.clone(),
                sender: descriptor.binding_digest().unwrap(),
                recipient: peer.descriptor.as_ref().unwrap().binding_digest().unwrap(),
                sequence,
                frame,
                expires_at_ms: state.end.unwrap(),
                mac: "13".repeat(32),
            },
            peer.endpoint.unwrap(),
        );
    }

    fn send(&self, value: &impl serde::Serialize, to: SocketAddr) {
        let packet = serde_json::to_vec(value).unwrap();
        assert!(packet.len() <= DATAGRAM_MAX);
        assert_eq!(self.socket.send_to(&packet, to).unwrap(), packet.len());
    }
}

fn handle(role: usize) -> String {
    format!("{:032x}", 10 + role)
}

fn response(status: u16, value: impl serde::Serialize) -> HttpResponse {
    HttpResponse {
        status,
        body: serde_json::to_vec(&value).unwrap(),
    }
}

struct Network {
    oracle: Arc<Oracle>,
    role: usize,
    nonce: u8,
    revision: String,
}

impl PairNetwork for Network {
    fn now_ms(&self) -> u64 {
        self.oracle.now()
    }

    fn cancelled(&self) -> bool {
        false
    }

    fn random(&mut self) -> Result<[u8; 16], PairIoError> {
        self.nonce += 1;
        Ok([self.nonce; 16])
    }

    fn wait(&mut self, milliseconds: u64) {
        std::thread::sleep(Duration::from_millis(milliseconds));
    }

    fn open_socket(&mut self) -> Result<Box<dyn BehaviourSocket>, PairIoError> {
        Ok(Box::new(Socket {
            socket: UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            oracle: self.oracle.clone(),
            role: self.role,
        }))
    }

    fn coordinator(&self) -> SocketAddr {
        self.oracle.address()
    }

    fn endpoint_revision(&self) -> &str {
        &self.revision
    }

    fn candidate_allowed(&self, candidate: SocketAddr) -> bool {
        candidate.ip().is_loopback() && candidate != self.coordinator() && candidate.port() != 0
    }

    fn post(
        &mut self,
        path: &str,
        body: &[u8],
        remaining_ms: u64,
    ) -> Result<HttpResponse, PairIoError> {
        assert!(remaining_ms > 0);
        let mut state = self.oracle.state.lock().unwrap();
        state.post_count[self.role] += 1;
        Ok(match path {
            ENROLL_PATH => self.oracle.enroll(&mut state, self.role, body),
            CONTROL_PATH => self.oracle.control(&mut state, self.role, body),
            _ => panic!("unexpected control request"),
        })
    }
}

struct Socket {
    socket: UdpSocket,
    oracle: Arc<Oracle>,
    role: usize,
}

impl BehaviourSocket for Socket {
    fn send_to(
        &mut self,
        packet: &[u8],
        to: SocketAddr,
        remaining_ms: u64,
    ) -> Result<(), BehaviourFailure> {
        let mut state = self.oracle.state.lock().unwrap();
        assert!(remaining_ms > 0 && packet.len() <= DATAGRAM_MAX);
        state.sent_count[self.role] += 1;
        let address = self.socket.local_addr().unwrap();
        if to == self.oracle.address() {
            BehaviourSocket::send_to(&mut self.socket, packet, to, remaining_ms)?;
            self.oracle.datagram(&mut state, packet, self.role, address);
        } else {
            assert_eq!(Some(address), state.members[self.role].endpoint);
            assert_eq!(Some(to), state.members[1 - self.role].endpoint);
            assert!(!state.members.iter().all(|member| member.relay));
            state.direct_sources[self.role] = Some(address);
            match state.topology {
                Topology::Direct => {
                    BehaviourSocket::send_to(&mut self.socket, packet, to, remaining_ms)?
                }
                #[cfg(test)]
                Topology::OneWay if self.role == 0 => {
                    BehaviourSocket::send_to(&mut self.socket, packet, to, remaining_ms)?;
                }
                #[cfg(test)]
                Topology::WrongPeer => {
                    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                        .unwrap()
                        .send_to(packet, to)
                        .unwrap();
                }
                #[cfg(test)]
                _ => {}
            }
        }
        Ok(())
    }

    fn receive_from(
        &mut self,
        buffer: &mut [u8],
        remaining_ms: u64,
    ) -> Result<(usize, SocketAddr), BehaviourFailure> {
        BehaviourSocket::receive_from(&mut self.socket, buffer, remaining_ms)
    }
}

fn collect(
    oracle: Arc<Oracle>,
    role: usize,
    descriptor: &TraversalDescriptorV1,
) -> Result<NetworkTraversalV1, TraversalRefusal> {
    let (session, signer) = oracle.bootstrap(role, descriptor);
    session.collect(
        &mut Network {
            oracle,
            role,
            nonce: role as u8 * 32,
            revision: descriptor.endpoint_set_revision.clone(),
        },
        &signer,
    )
}

pub(super) struct Paired {
    pub descriptors: [TraversalDescriptorV1; 2],
    pub reports: [NetworkTraversalV1; 2],
}

pub(super) fn paired(topology: Topology) -> Paired {
    let first = fixture_descriptor(0, 3_000);
    let mut second = fixture_descriptor(1, 3_000);
    let (first_waiting, ready) = mpsc::channel();
    let oracle = Arc::new(Oracle::new(
        first.issued_at_ms + 1,
        topology,
        Some(first_waiting),
    ));
    let reports = std::thread::scope(|threads| {
        let first = threads.spawn(|| collect(oracle.clone(), 0, &first));
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        // The first helper already asked for candidates with its own grant.
        // Only now does the second bootstrap issue its role-local capability.
        let before = oracle.state.lock().unwrap();
        assert_eq!(before.bootstraps, [1, 0]);
        assert!(before.members[0].endpoint.is_some());
        assert!(before.members[1].descriptor.is_none());
        let until = before.end;
        drop(before);
        second.issued_at_ms = oracle.now();
        while oracle.now() <= second.issued_at_ms {
            std::thread::sleep(Duration::from_millis(1));
        }
        let second = collect(oracle.clone(), 1, &second);
        let reports = [first.join().unwrap().unwrap(), second.unwrap()];
        let after = oracle.state.lock().unwrap();
        assert_eq!(after.bootstraps, [1, 1]);
        assert_eq!(after.end, until);
        for (role, report) in reports.iter().enumerate() {
            let rebound = report.phases[0].outcome == TraversalOutcome::CandidateRebinding;
            if rebound {
                assert_eq!(after.sent_count[role], 3);
                assert_eq!(after.direct_sources[role], None);
                assert!(!after.members[role].relay);
            } else {
                assert!(after.direct_sources[role].is_some());
                assert_eq!(after.direct_sources[role], after.members[role].endpoint);
            }
            assert!(after.post_count[role] < 12);
            assert!(after.sent_count[role] <= 64);
            let serialized = serde_json::to_string(report).unwrap();
            assert!(!serialized.contains("127.0.0.1"));
        }
        reports
    });
    Paired {
        descriptors: [first, second],
        reports,
    }
}

pub(super) fn corroborated(result: &Paired, stage: TraversalStage) -> bool {
    let proofs = result.reports.each_ref().map(|report| {
        report
            .proofs
            .iter()
            .find(|proof| proof.transcript().stage == stage)
    });
    let [Some(first), Some(second)] = proofs else {
        return false;
    };
    let [a, b] = &result.descriptors;
    let now = a.issued_at_ms.max(b.issued_at_ms) + a.budgets.experiment_ms;
    validate_pair_transcripts(a, b, first.transcript(), second.transcript(), now).is_ok()
}

#[cfg(test)]
mod single;
