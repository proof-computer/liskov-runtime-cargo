use std::net::SocketAddr;

use serde::Serialize;

use super::super::*;
use super::wire::*;
use super::{PairIoError, PairNetwork, PairSession};

const CONTROL_WAIT_MS: u64 = 1_500;
const COOKIE_WAIT_MS: u64 = 700;
const UDP_WAIT_MS: u64 = 150;
const CHALLENGE_INTERVAL_MS: u64 = 300;
const DIRECT_SEND_LIMIT: u16 = 16;
const MAX_RECEIVES: usize = 128;
const RELAY_WINDOW_MS: u64 = 5_000;
const RELAY_CONTROL_POLLS: u16 = 3;

pub(super) struct Observation {
    pub phase: Phase,
    pub outcome: TraversalOutcome,
    pub error_class: Option<TraversalErrorClass>,
    pub stopped_at_ms: u64,
    pub challenge: String,
    pub peer_challenge: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    Budget,
    Cancelled,
    Deadline,
    Invalid,
    LateJoin,
    Missing,
    Rebinding,
    Timeout,
    Unavailable,
    WrongPeer,
}

impl Stop {
    fn evidence(self, phase: Phase) -> (TraversalOutcome, Option<TraversalErrorClass>) {
        use TraversalErrorClass as E;
        use TraversalOutcome as O;
        match self {
            Self::Budget => (O::BudgetExhausted, Some(E::BudgetExhausted)),
            Self::Cancelled => (O::Unknown, None),
            Self::Deadline | Self::Timeout if phase == Phase::Direct => {
                (O::DirectNotEstablishedInTest, Some(E::Timeout))
            }
            Self::Deadline | Self::Timeout => (O::Failed, Some(E::Timeout)),
            Self::Invalid => (O::Failed, Some(E::InvalidResponse)),
            Self::LateJoin => (O::LateJoin, Some(E::PeerUnavailable)),
            Self::Missing => (O::PeerAbsent, Some(E::PeerUnavailable)),
            Self::Rebinding => (O::CandidateRebinding, None),
            Self::Unavailable => (O::Failed, Some(E::ProberUnavailable)),
            Self::WrongPeer => (O::WrongPeer, None),
        }
    }
}

impl From<PairIoError> for Stop {
    fn from(error: PairIoError) -> Self {
        match error {
            PairIoError::Unavailable => Self::Unavailable,
            PairIoError::InvalidResponse => Self::Invalid,
        }
    }
}

fn encoded(value: &impl Serialize) -> Result<Vec<u8>, Stop> {
    serde_json::to_vec(value).map_err(|_| Stop::Invalid)
}

struct Exchange {
    nonce: String,
    peer_nonce: Option<String>,
    replied: bool,
    received_reply: bool,
    wrong_peer: bool,
}

impl Exchange {
    fn new(nonce: String) -> Self {
        Self {
            nonce,
            peer_nonce: None,
            replied: false,
            received_reply: false,
            wrong_peer: false,
        }
    }

    fn receive(&mut self, frame: Frame) -> Option<Frame> {
        if !valid_nonce(frame.nonce()) {
            return None;
        }
        match frame {
            Frame::Challenge(nonce)
                if nonce != self.nonce
                    && self.peer_nonce.as_ref().is_none_or(|seen| seen == &nonce) =>
            {
                self.peer_nonce = Some(nonce.clone());
                Some(Frame::Response(nonce))
            }
            Frame::Response(nonce) if nonce == self.nonce => {
                self.received_reply = true;
                None
            }
            _ => None,
        }
    }

    fn complete(&self) -> bool {
        self.replied && self.received_reply
    }

    fn close(self, phase: Phase, time: u64, stop: Option<Stop>) -> Observation {
        use TraversalOutcome as O;
        let (outcome, error_class) = match stop {
            Some(reason @ (Stop::Rebinding | Stop::Cancelled)) => reason.evidence(phase),
            _ if self.complete() => (O::Succeeded, None),
            None | Some(Stop::Deadline | Stop::Timeout) if self.replied || self.received_reply => {
                (O::OneWayPeer, None)
            }
            None | Some(Stop::Deadline | Stop::Timeout) if self.wrong_peer => {
                Stop::WrongPeer.evidence(phase)
            }
            _ => stop.unwrap_or(Stop::Timeout).evidence(phase),
        };
        Observation {
            phase,
            outcome,
            error_class,
            stopped_at_ms: time,
            challenge: self.nonce,
            peer_challenge: self.peer_nonce,
        }
    }
}

struct RegistrationContext {
    handle: String,
    transaction: String,
    cookie: String,
}

pub(super) struct Run<'a> {
    session: &'a PairSession,
    network: &'a mut dyn PairNetwork,
    udp: Option<Box<dyn BehaviourSocket>>,
    coordinator: SocketAddr,
    coordinator_end_ms: Option<u64>,
    end_ms: u64,
    controls: u16,
    datagrams: u16,
    datagram_bytes: usize,
    relay_outbound: usize,
    relay_inbound: usize,
    combined: bool,
}

impl Run<'_> {
    pub(super) fn collect(
        session: &PairSession,
        network: &mut dyn PairNetwork,
    ) -> Result<Vec<Observation>, TraversalRefusal> {
        use TraversalOperation::*;
        let descriptor = &session.capability.descriptor;
        let budgets = &descriptor.budgets;
        let direct = descriptor.operations.contains(&PairDirectUdp);
        let relay = descriptor.operations.contains(&PairRelayControl);
        let coordinator = network.coordinator();
        let mut run = Run {
            session,
            network,
            udp: None,
            coordinator,
            coordinator_end_ms: None,
            end_ms: session.reservation.collector_end_ms - budgets.cleanup_reserve_ms,
            // The coordinator holds the last control credit for cancellation.
            // Expiry closes the pair without one role cutting off a slower peer.
            controls: budgets.control_requests.saturating_sub(1),
            datagrams: budgets.outbound_datagrams,
            datagram_bytes: usize::from(budgets.datagram_bytes),
            relay_outbound: budgets.relay_bytes_per_direction as usize,
            relay_inbound: budgets.relay_bytes_per_direction as usize,
            combined: direct && relay,
        };

        let first_phase = if direct {
            Phase::Direct
        } else {
            Phase::RelayControl
        };
        let first_nonce = random_nonce(run.network)?;
        let mut first = Exchange::new(first_nonce);
        let registration = match run.register(&first.nonce) {
            Ok(registration) => registration,
            Err(stop) => {
                return Ok(vec![first.close(first_phase, run.now(), Some(stop))]);
            }
        };
        let mut observations = Vec::new();
        if direct {
            let candidate = run.candidate(&registration.handle);
            let stop = match candidate {
                Ok(candidate) => run.direct(candidate, &registration, &mut first).err(),
                Err(stop) => {
                    return Ok(vec![first.close(Phase::Direct, run.now(), Some(stop))]);
                }
            };
            observations.push(first.close(Phase::Direct, run.now(), stop));
            if !relay || matches!(stop, Some(Stop::Budget | Stop::Cancelled | Stop::Rebinding)) {
                return Ok(observations);
            }
            let nonce = random_nonce(run.network)?;
            if nonce == registration.transaction || observations[0].challenge == nonce {
                return Err(TraversalRefusal::InvalidProof);
            }
            first = Exchange::new(nonce);
        }
        let stop = run.relay(&registration, &mut first).err();
        observations.push(first.close(Phase::RelayControl, run.now(), stop));
        Ok(observations)
    }

    fn now(&self) -> u64 {
        self.network.now_ms()
    }

    fn remaining(&self, until: u64) -> Result<u64, Stop> {
        if self.network.cancelled() {
            return Err(Stop::Cancelled);
        }
        let remaining = self.end_ms.min(until).saturating_sub(self.now());
        if remaining == 0 {
            return Err(Stop::Deadline);
        }
        Ok(remaining)
    }

    fn apply_coordinator_end(&mut self, until: u64) -> Result<(), Stop> {
        if until > self.session.capability.descriptor.deadline_ms
            || self
                .coordinator_end_ms
                .is_some_and(|previous| until > previous)
        {
            return Err(Stop::Invalid);
        }
        self.end_ms = self.end_ms.min(until);
        self.coordinator_end_ms = Some(until);
        self.remaining(until).map(|_| ())
    }

    fn direct_end(&self) -> u64 {
        if !self.combined {
            return self.end_ms;
        }
        let reserved = (self.session.reservation.experiment_ms
            - self.session.reservation.cleanup_reserve_ms)
            / 3;
        self.end_ms.saturating_sub(reserved.min(RELAY_WINDOW_MS))
    }

    fn post(&mut self, path: &str, body: &[u8], until: u64) -> Result<Vec<u8>, Stop> {
        let timeout = self.remaining(until)?.min(CONTROL_WAIT_MS);
        self.controls = self.controls.checked_sub(1).ok_or(Stop::Budget)?;
        let reply = self.network.post(path, body, timeout)?;
        self.remaining(until)?;
        if reply.body.len() > CONTROL_RESPONSE_MAX {
            return Err(Stop::Invalid);
        }
        if reply.status == 200 {
            return Ok(reply.body);
        }
        let reason = serde_json::from_slice::<Refusal>(&reply.body).ok();
        Err(
            match (
                reply.status,
                reason.as_ref().map(|reply| reply.status.as_str()),
            ) {
                (429, _) => Stop::Budget,
                (409, Some("wrong_peer" | "duplicate_role")) => Stop::WrongPeer,
                (409, Some("rebinding")) => Stop::Rebinding,
                (410, Some("expired"))
                    if path == ENROLL_PATH
                        && self.session.role == TraversalParticipantRole::Second =>
                {
                    Stop::LateJoin
                }
                (410, Some("expired")) => Stop::Deadline,
                (503, _) => Stop::Unavailable,
                _ => Stop::Invalid,
            },
        )
    }

    fn control(&mut self, handle: &str, action: Action, until: u64) -> Result<Status, Stop> {
        let body = self.post(
            CONTROL_PATH,
            &encoded(&Control {
                session: handle,
                action,
            })?,
            until,
        )?;
        let status: Status = serde_json::from_slice(&body).map_err(|_| Stop::Invalid)?;
        self.apply_coordinator_end(status.until_ms)?;
        Ok(status)
    }

    fn send(
        &mut self,
        value: &impl Serialize,
        destination: SocketAddr,
        until: u64,
    ) -> Result<(), Stop> {
        let remaining = self.remaining(until)?;
        let packet = encoded(value)?;
        if packet.len() > self.datagram_bytes {
            return Err(Stop::Budget);
        }
        self.datagrams = self.datagrams.checked_sub(1).ok_or(Stop::Budget)?;
        self.udp
            .as_mut()
            .ok_or(Stop::Unavailable)?
            .send_to(&packet, destination, remaining)
            .map_err(|_| Stop::Unavailable)
    }

    fn receive(
        &mut self,
        buffer: &mut [u8; DATAGRAM_MAX + 1],
        until: u64,
    ) -> Result<Option<(usize, SocketAddr)>, Stop> {
        let wait = self.remaining(until)?.min(UDP_WAIT_MS);
        let reply = self
            .udp
            .as_mut()
            .ok_or(Stop::Unavailable)?
            .receive_from(buffer, wait);
        self.remaining(until)?;
        match reply {
            // A sentinel byte distinguishes an oversized truncated datagram.
            Ok((length, from)) if length <= self.datagram_bytes => Ok(Some((length, from))),
            Ok(_) | Err(BehaviourFailure::Timeout) => Ok(None),
            Err(_) => Err(Stop::Unavailable),
        }
    }

    fn wait_until(&mut self, until: u64) -> Result<(), Stop> {
        while self.now() < until {
            let wait = self
                .remaining(self.end_ms)?
                .min(until.saturating_sub(self.now()));
            if wait > 0 {
                self.network.wait(wait.min(UDP_WAIT_MS));
            }
        }
        Ok(())
    }

    fn register(&mut self, phase_nonce: &str) -> Result<RegistrationContext, Stop> {
        self.remaining(self.end_ms)?;
        if self.controls == 0 || self.datagrams < 2 {
            return Err(Stop::Budget);
        }
        let transaction = random_nonce(self.network).map_err(|_| Stop::Unavailable)?;
        if transaction == phase_nonce {
            return Err(Stop::Invalid);
        }
        let grant = canonical(&self.session.capability).map_err(|_| Stop::Invalid)?;
        let body = self.post(ENROLL_PATH, &grant, self.end_ms)?;
        let enrollment: Enrollment = serde_json::from_slice(&body).map_err(|_| Stop::Invalid)?;
        if !valid_nonce(&enrollment.session) {
            return Err(Stop::Invalid);
        }
        self.apply_coordinator_end(enrollment.until_ms)?;
        self.remaining(self.end_ms)?;
        self.udp = Some(self.network.open_socket()?);
        let cookie = self.cookie(&enrollment.session, &transaction, self.end_ms)?;
        self.send(
            &Request::Register {
                session: &enrollment.session,
                transaction: &transaction,
                cookie: &cookie,
            },
            self.coordinator,
            self.end_ms,
        )?;
        // The UDP acknowledgement contains no transaction. Authenticated
        // control proves both endpoints registered before releasing a candidate
        // or entering relay, so this reply is neither required nor evidence.
        Ok(RegistrationContext {
            handle: enrollment.session,
            transaction,
            cookie,
        })
    }

    fn cookie(&mut self, handle: &str, transaction: &str, until: u64) -> Result<String, Stop> {
        let until = until.min(self.now().saturating_add(COOKIE_WAIT_MS));
        self.send(
            &Request::Cookie {
                session: handle,
                transaction,
                padding: COOKIE_PADDING,
            },
            self.coordinator,
            until,
        )?;
        let mut buffer = [0; DATAGRAM_MAX + 1];
        for _ in 0..MAX_RECEIVES {
            let Some((length, from)) = self.receive(&mut buffer, until)? else {
                continue;
            };
            if from != self.coordinator {
                continue;
            }
            let Ok(Registration::Cookie {
                session,
                transaction: received,
                cookie,
            }) = serde_json::from_slice(&buffer[..length])
            else {
                continue;
            };
            if session == handle && received == transaction && lower_hex(&cookie, 32) {
                return Ok(cookie);
            }
        }
        Err(Stop::Timeout)
    }

    fn confirm_endpoint(
        &mut self,
        registration: &RegistrationContext,
        until: u64,
    ) -> Result<(), Stop> {
        // For the exact same transaction/epoch a changed return cookie means
        // the observed tuple changed. Drop the socket and leave expiry fenced.
        // Neither replaying registration nor changing the candidate is safe.
        let cookie = self.cookie(&registration.handle, &registration.transaction, until)?;
        if cookie != registration.cookie {
            return Err(Stop::Rebinding);
        }
        Ok(())
    }

    fn candidate(&mut self, handle: &str) -> Result<SocketAddr, Stop> {
        let mut polls = if self.combined {
            self.controls.saturating_sub(RELAY_CONTROL_POLLS).max(1)
        } else {
            self.controls
        };
        if polls == 0 {
            return Err(Stop::Budget);
        }

        while polls > 0 {
            let until = self.direct_end();
            let status = self.control(handle, Action::Candidates, until)?;
            let until = self.direct_end();
            polls -= 1;
            match (status.phase, status.progress, status.candidate) {
                (Phase::Direct, Progress::Ready, Some(candidate))
                    if self.network.candidate_allowed(candidate) =>
                {
                    let grace = (self.session.reservation.experiment_ms / 10).clamp(1, 1_000);
                    if self.now().saturating_add(grace) >= until {
                        return Err(Stop::LateJoin);
                    }
                    return Ok(candidate);
                }
                (Phase::Direct, Progress::PeerAbsent | Progress::AwaitingEndpoint, None) => {
                    if polls == 0 {
                        return Err(Stop::Missing);
                    }
                }
                _ => return Err(Stop::Invalid),
            }
            self.poll_wait(until, polls)?;
        }
        Err(Stop::Missing)
    }

    fn poll_wait(&mut self, until: u64, polls: u16) -> Result<(), Stop> {
        let next = self
            .now()
            .saturating_add(self.remaining(until)? / (1 + u64::from(polls)));
        self.wait_until(next)
    }

    fn direct(
        &mut self,
        candidate: SocketAddr,
        registration: &RegistrationContext,
        exchange: &mut Exchange,
    ) -> Result<(), Stop> {
        let end = self.direct_end();
        self.confirm_endpoint(registration, end)?;
        let mut buffer = [0; DATAGRAM_MAX + 1];
        let mut next_challenge = self.now();
        let mut next_reply = 0;
        let mut sent = 0;
        for _ in 0..MAX_RECEIVES {
            if self.now() >= next_challenge && !exchange.received_reply && sent < DIRECT_SEND_LIMIT
            {
                let frame = Frame::Challenge(exchange.nonce.clone());
                self.send_direct(candidate, frame, end)?;
                sent += 1;
                next_challenge = self.now().saturating_add(CHALLENGE_INTERVAL_MS);
            }
            let Some((length, from)) = self.receive(&mut buffer, end)? else {
                continue;
            };
            let Ok(packet) = serde_json::from_slice::<DirectFrame<'_>>(&buffer[..length]) else {
                continue;
            };
            if packet.domain != DIRECT_DOMAIN {
                continue;
            }
            if from != candidate {
                exchange.wrong_peer |= packet.pair_binding == self.session.pair_binding;
                continue;
            }
            if packet.pair_binding != self.session.pair_binding || packet.role == self.session.role
            {
                exchange.wrong_peer = true;
                continue;
            }
            if let Some(response) = exchange
                .receive(packet.frame)
                .filter(|_| self.now() >= next_reply && sent < DIRECT_SEND_LIMIT)
            {
                self.send_direct(candidate, response, end)?;
                sent += 1;
                exchange.replied = true;
                next_reply = self.now().saturating_add(CHALLENGE_INTERVAL_MS / 2);
            }
        }
        self.wait_until(end)?;
        Ok(())
    }

    fn send_direct(&mut self, candidate: SocketAddr, frame: Frame, until: u64) -> Result<(), Stop> {
        self.send(
            &DirectFrame {
                domain: DIRECT_DOMAIN,
                pair_binding: &self.session.pair_binding,
                role: self.session.role,
                frame,
            },
            candidate,
            until,
        )
    }

    fn relay(
        &mut self,
        registration: &RegistrationContext,
        exchange: &mut Exchange,
    ) -> Result<(), Stop> {
        self.confirm_endpoint(registration, self.end_ms)?;
        self.wait_for_relay(registration)?;
        self.send_relay(registration, Frame::Challenge(exchange.nonce.clone()))?;
        let mut buffer = [0; DATAGRAM_MAX + 1];
        let mut peer = None;
        for _ in 0..MAX_RECEIVES {
            let Some((length, from)) = self.receive(&mut buffer, self.end_ms)? else {
                continue;
            };
            if from != self.coordinator {
                continue;
            }
            let Ok(delivery) = serde_json::from_slice::<RelayDelivery>(&buffer[..length]) else {
                continue;
            };
            if !self.valid_delivery(&delivery)
                || peer.as_ref().is_some_and(|seen| seen != &delivery.sender)
            {
                exchange.wrong_peer = true;
                continue;
            }
            self.relay_inbound = self.relay_inbound.checked_sub(length).ok_or(Stop::Budget)?;
            peer = Some(delivery.sender);
            if let Some(response) = exchange
                .receive(delivery.frame)
                .filter(|_| !exchange.replied)
            {
                self.send_relay(registration, response)?;
                exchange.replied = true;
            }
            if exchange.complete() {
                return Ok(());
            }
        }
        Ok(())
    }

    fn wait_for_relay(&mut self, registration: &RegistrationContext) -> Result<(), Stop> {
        let mut polls = self.controls;
        if polls == 0 {
            return Err(Stop::Budget);
        }
        while polls > 0 {
            let status = self.control(&registration.handle, Action::Relay, self.end_ms)?;
            match (status.phase, status.progress, status.candidate) {
                (Phase::RelayControl, Progress::Ready, None) => return Ok(()),
                (
                    Phase::Direct,
                    Progress::PeerAbsent | Progress::AwaitingEndpoint | Progress::AwaitingRelay,
                    None,
                ) => {}
                _ => return Err(Stop::Invalid),
            }
            polls -= 1;
            if polls > 0 {
                self.poll_wait(self.end_ms, polls)?;
            }
        }
        Err(Stop::Missing)
    }

    fn send_relay(&mut self, registration: &RegistrationContext, frame: Frame) -> Result<(), Stop> {
        // The coordinator charges the size of the forwarded envelope. Digests,
        // MAC, sequence and nonce have fixed widths. The sender placeholder
        // takes exactly as many bytes as the peer grant's unknown digest.
        let delivery = RelayDelivery {
            domain: RELAY_DOMAIN.into(),
            pair_id: self.session.pair_id.clone(),
            sender: self.session.descriptor_digest.clone(),
            recipient: self.session.descriptor_digest.clone(),
            sequence: frame.sequence(),
            frame: frame.clone(),
            expires_at_ms: self.coordinator_end_ms.ok_or(Stop::Invalid)?,
            mac: "0".repeat(64),
        };
        let bytes = encoded(&delivery)?.len();
        if bytes > self.datagram_bytes {
            return Err(Stop::Budget);
        }
        self.relay_outbound = self.relay_outbound.checked_sub(bytes).ok_or(Stop::Budget)?;
        self.send(
            &Request::Relay {
                session: &registration.handle,
                transaction: &registration.transaction,
                cookie: &registration.cookie,
                sequence: delivery.sequence,
                frame,
            },
            self.coordinator,
            self.end_ms,
        )
    }

    fn valid_delivery(&self, delivery: &RelayDelivery) -> bool {
        // The MAC belongs to the prober/admission owner; helpers never have
        // that key. Match the observed source and exact recipient and pair,
        // then require round-trip fresh nonces and a second signed transcript.
        delivery.domain == RELAY_DOMAIN
            && delivery.pair_id == self.session.pair_id
            && delivery.recipient == self.session.descriptor_digest
            && delivery.sender != delivery.recipient
            && digest(&delivery.sender)
            && delivery.sequence == delivery.frame.sequence()
            && valid_nonce(delivery.frame.nonce())
            && self.coordinator_end_ms == Some(delivery.expires_at_ms)
            && self.now() < delivery.expires_at_ms
            && lower_hex(&delivery.mac, 32)
    }
}

fn random_nonce(network: &mut dyn PairNetwork) -> Result<String, TraversalRefusal> {
    let bytes = network
        .random()
        .map_err(|_| TraversalRefusal::InvalidProof)?;
    if bytes == [0; 16] {
        return Err(TraversalRefusal::InvalidProof);
    }
    Ok(hex::encode(bytes))
}
