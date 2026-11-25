//! An in-process prober and a single-lease PCP router on real loopback sockets.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use super::*;

const ROUTER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
// Addresses in the fixture's path observations are synthetic. Socket I/O uses loopback.
const OBSERVED: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 20);
const NONCE: [u8; 12] = [9; 12];

#[derive(Debug, PartialEq)]
enum Event {
    Baseline,
    Create,
    Verify,
    Delete,
}

struct Fixture<'a> {
    descriptor: &'a TraversalDescriptorV1,
    started: Instant,
    listener: Option<u16>,
    router: UdpSocket,
    router_client: UdpSocket,
    prober: UdpSocket,
    lease: Option<[u8; 20]>,
    trace: Vec<Event>,
    attestations: u8,
}

impl Fixture<'_> {
    fn pcp_reply(&mut self, request: &[u8]) -> Option<[u8; PCP_MAP_PACKET_BYTES]> {
        let port = self.listener?.to_be_bytes();
        if request.len() != PCP_MAP_PACKET_BYTES
            || request[..2] != [2, 1]
            || request[20..24] != CLIENT.octets()
            || request[24..36] != NONCE
            || request[36] != 17
            || request[40..42] != port
            || request[42..44] != port
        {
            return None;
        }
        let key = request[24..44].try_into().ok()?;
        let seconds = u32::from_be_bytes(request[4..8].try_into().ok()?);
        match (seconds, self.trace.as_slice(), self.lease) {
            (60, [Event::Baseline], None) => {
                self.lease = Some(key);
                self.trace.push(Event::Create);
            }
            (0, [Event::Baseline, Event::Create, Event::Verify], Some(owned)) if key == owned => {
                self.lease = None;
                self.trace.push(Event::Delete);
            }
            _ => return None,
        }
        let mut reply = [0; PCP_MAP_PACKET_BYTES];
        reply[..2].copy_from_slice(&[2, 0x81]);
        reply[4..8].copy_from_slice(&seconds.to_be_bytes());
        reply[8..12].copy_from_slice(&100u32.to_be_bytes());
        reply[24..44].copy_from_slice(&key);
        reply[54..56].fill(0xff);
        reply[56..60].copy_from_slice(&OBSERVED.octets());
        Some(reply)
    }
}

impl MappingRuntime for Fixture<'_> {
    fn now_ms(&self) -> u64 {
        self.descriptor.issued_at_ms + self.started.elapsed().as_millis() as u64
    }

    fn observed_address(&self) -> Ipv4Addr {
        OBSERVED
    }

    fn stop(&self) -> Option<MappingStop> {
        None
    }

    fn nonce(&mut self) -> Result<[u8; 12], MappingStop> {
        Ok(NONCE)
    }

    fn bind_fresh(
        &mut self,
        transport: MappedPortProtocol,
    ) -> Result<Box<dyn MappingListener>, MappingStop> {
        let listener = NativeMappingListener::bind_loopback(transport)?;
        self.listener = Some(listener.port());
        Ok(Box::new(listener))
    }

    fn path_check(
        &mut self,
        listener: &mut dyn MappingListener,
        check: MappingPathCheck,
        deadline_ms: u64,
    ) -> Result<MappingPathEvidence, MappingStop> {
        if Some(check.port) != self.listener || check.port != listener.port() {
            return Err(MappingStop::InvalidBinding);
        }
        let (event, nonce) = match (check.stage, self.lease) {
            (TraversalStage::Baseline, None) => (Event::Baseline, [7; 32]),
            (TraversalStage::MappingVerify, Some(_)) => (Event::Verify, [8; 32]),
            _ => return Err(MappingStop::InvalidBinding),
        };
        let remaining = deadline_ms.saturating_sub(self.now_ms()).min(500);
        let destination = (Ipv4Addr::LOCALHOST, check.port).into();
        let source = self
            .prober
            .local_addr()
            .map_err(|_| MappingStop::Unsupported)?;
        BehaviourSocket::send_to(&mut self.prober, &nonce, destination, remaining)
            .map_err(|_| MappingStop::Unsupported)?;
        let answer = listener.answer_challenge(
            check.stage,
            source.ip(),
            Duration::from_millis(deadline_ms.saturating_sub(self.now_ms()).min(500)),
        )?;
        let mut echo = [0; 33];
        let remaining = deadline_ms.saturating_sub(self.now_ms());
        let (length, sender) = self
            .prober
            .receive_from(&mut echo, remaining)
            .map_err(|_| MappingStop::Unsupported)?;
        if length != nonce.len() || echo[..length] != nonce || sender != destination {
            return Err(MappingStop::InvalidBinding);
        }
        self.trace.push(event);
        let transcript = TraversalTranscriptV1 {
            version: 1,
            domain: TRAVERSAL_EXTERNAL_PATH_DOMAIN.into(),
            descriptor_digest: self
                .descriptor
                .binding_digest()
                .map_err(|_| MappingStop::InvalidBinding)?,
            run_id: self.descriptor.run_id.clone(),
            pair_id: None,
            participant_role: None,
            authority: TraversalEvidenceAuthority::ExternalPath,
            stage: check.stage,
            method: check.method,
            transport: check.transport,
            family: check.family,
            challenge: hex::encode(nonce),
            peer_challenge: None,
            expires_at_ms: self.descriptor.expires_at_ms,
            outcome: TraversalOutcome::Succeeded,
            elapsed_ms: 0,
            granted_lease_sec: None,
            cleanup: None,
            protocol_error: None,
            error_class: None,
        };
        Ok(MappingPathEvidence {
            transcript,
            echoed_challenge: Some(answer),
        })
    }

    fn attest_path(
        &mut self,
        transcript: &TraversalTranscriptV1,
        deadline_ms: u64,
    ) -> Result<(), MappingStop> {
        if self.now_ms() >= deadline_ms {
            return Err(MappingStop::Deadline);
        }
        transcript
            .validate_scope(self.descriptor, self.now_ms())
            .map_err(|_| MappingStop::InvalidBinding)?;
        self.attestations += 1;
        Ok(())
    }

    fn router_exchange(
        &mut self,
        destination: SocketAddr,
        request: &[u8],
        response: &mut [u8],
        deadline_ms: u64,
    ) -> Result<usize, ControlRefusal> {
        if destination != (ROUTER, ROUTER_CONTROL_PORT).into() {
            return Err(ControlRefusal::Bounded);
        }
        let router = self
            .router
            .local_addr()
            .map_err(|_| ControlRefusal::Bounded)?;
        let client = self
            .router_client
            .local_addr()
            .map_err(|_| ControlRefusal::Bounded)?;
        let remaining = deadline_ms.saturating_sub(self.now_ms());
        BehaviourSocket::send_to(&mut self.router_client, request, router, remaining)
            .map_err(|_| ControlRefusal::Bounded)?;
        let mut packet = [0; PCP_MAP_PACKET_BYTES + 1];
        let remaining = deadline_ms.saturating_sub(self.now_ms());
        let (length, sender) = self
            .router
            .receive_from(&mut packet, remaining)
            .map_err(|_| ControlRefusal::Bounded)?;
        if sender != client {
            return Err(ControlRefusal::Bounded);
        }
        let reply = self
            .pcp_reply(&packet[..length])
            .ok_or(ControlRefusal::Bounded)?;
        let remaining = deadline_ms.saturating_sub(self.now_ms());
        BehaviourSocket::send_to(&mut self.router, &reply, client, remaining)
            .map_err(|_| ControlRefusal::Bounded)?;
        let remaining = deadline_ms.saturating_sub(self.now_ms());
        let (length, sender) = self
            .router_client
            .receive_from(response, remaining)
            .map_err(|_| ControlRefusal::Bounded)?;
        if sender != router {
            return Err(ControlRefusal::Bounded);
        }
        Ok(length)
    }
}

pub(in crate::network_traversal) fn run() -> Option<MappingRunReport> {
    let descriptor = super::super::fixture_descriptor("mapping")?;
    let consent = descriptor.mapping.as_ref()?;
    let route = RouteRecord::new(Ipv4Addr::UNSPECIFIED, 0, ROUTER, true, 0);
    let GatewayDiscovery::Selected(gateway) =
        super::super::gateway::discover_loaded(&[route], &|| false)
    else {
        return None;
    };
    let reservation = ExclusiveReservation::new(ROUTER, [0x55; 32])?;
    let session = MappingSession::from_authenticated_bootstrap(
        descriptor.clone(),
        MappingBindings {
            claim_authority_digest: &descriptor.claim_authority_digest,
            artifact_digest: &descriptor.artifact_digest,
            helper: &FIXTURE_HELPER,
            consent_reference: &consent.consent_reference,
            processor_allowlist_digest: &consent.processor_allowlist_digest,
            exclusive_reservation_digest: &consent.exclusive_reservation_digest,
        },
        descriptor.issued_at_ms,
        descriptor.expires_at_ms,
    )
    .ok()?;
    let loopback = || UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).ok();
    let mut fixture = Fixture {
        descriptor: &descriptor,
        started: Instant::now(),
        listener: None,
        router: loopback()?,
        router_client: loopback()?,
        prober: loopback()?,
        lease: None,
        trace: Vec::new(),
        attestations: 0,
    };
    let report = run_mapping_lifecycle(
        session,
        &[MappingMethodPlan {
            protocol: RouterProtocol::Pcp,
            transport: MappedPortProtocol::Udp,
        }],
        MappingGateway {
            gateway: &gateway,
            reservation: &reservation,
            local_address: CLIENT,
            external_address: None,
            igd: None,
            discovery_datagrams: 0,
            discovery_control_requests: 0,
        },
        &mut fixture,
    );
    // Check the router's packet-derived state and rebind the released listener.
    (fixture.trace == [Event::Baseline, Event::Create, Event::Verify, Event::Delete]
        && fixture.attestations == 2
        && fixture.lease.is_none()
        && UdpSocket::bind((Ipv4Addr::LOCALHOST, fixture.listener?)).is_ok())
    .then_some(report)
}
