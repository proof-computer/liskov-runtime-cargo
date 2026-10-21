//! Dormant, bounded UDP behaviour experiments (BKLG-20261014-8cze; ADR-0234).
//!
//! RFC 5780's socket isolation and comparison principles, using the existing
//! prober-owned LNT1 transport, not a public STUN service. Source protocol:
//! liskov-network-prober 220d3f88d332e0b82b7e49ad32781296ea6a1114.
//! `vectors/controlled-endpoints-v1.json` is copied byte-for-byte from that
//! owner (SHA-256 342012d3e464b8f3d62324a97f7fb30b140afeae7e58d9c6f7f25a18fe1c3616).
//! Comparisons describe only this finite A:p/A:q/B:p profile at this instant;
//! no classification predicts a different peer, port, or later network state.
//! Endpoint qualification is an input from the approved endpoint revision;
//! ordinary echo reachability never qualifies alternate-source primitives.
//! No caller in the released helper invokes this collector. There is no control
//! fetch, activation switch, signing, persistence, or result-admission claim here.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use super::{Reservation, TraversalDescriptorV1, TraversalOperation, TraversalOutcome};

const REQUEST_BYTES: usize = 96;
const RESPONSE_BYTES: usize = 128;
const WAIT_MS: u64 = 500;
const MAX_RECEIVES: usize = 16;

/// An exact operator-pinned tuple. Each primitive needs its own evidence.
/// Addresses remain in memory and this type deliberately has no Debug/serde.
pub struct BehaviourEndpoint {
    pub address: SocketAddr,
    pub mapping_qualified: bool,
    pub filtering_qualified: bool,
}

pub struct BehaviourTopology {
    pub revision: String,
    pub ap: BehaviourEndpoint,
    pub aq: Option<BehaviourEndpoint>,
    pub bp: Option<BehaviourEndpoint>,
}

/// A session returned by authenticated enrollment of this exact descriptor.
/// The prober fences its random session and cookies by process epoch/revision.
/// The client has no prober MAC key and never purports to verify that MAC.
/// Consumed by one collection; do not re-enroll to replenish a spent allowance.
pub struct BehaviourSession {
    id: [u8; 16],
    descriptor_digest: String,
}

impl BehaviourSession {
    pub fn from_authenticated_enrollment(
        session_hex: &str,
        descriptor: &TraversalDescriptorV1,
    ) -> Option<Self> {
        descriptor.validate().ok()?;
        let mut id = [0; 16];
        if !super::lower_hex(session_hex, 16)
            || hex::decode_to_slice(session_hex, &mut id).is_err()
            || id == [0; 16]
        {
            return None;
        }
        Some(Self {
            id,
            descriptor_digest: descriptor.binding_digest().ok()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BehaviourFailure {
    UnsupportedTopology,
    NotStarted,
    NotAuthorized,
    /// No challenge arrived from the contacted endpoint; not filtering evidence.
    ChallengeTimeout,
    /// The observation receive timed out after sending the challenge proof.
    Timeout,
    InvalidResponse,
    Rebinding,
    BudgetExhausted,
    Deadline,
    Cancelled,
    RuntimeUnavailable,
}

/// These are transient local summaries, not signed prober receipts. In
/// particular they must not be inserted into NetworkTraversalV1 as proofs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BehaviourSummary {
    pub outcome: TraversalOutcome,
    pub reason: Option<BehaviourFailure>,
}

impl BehaviourSummary {
    fn unknown(reason: BehaviourFailure) -> Self {
        Self {
            outcome: if reason == BehaviourFailure::UnsupportedTopology {
                TraversalOutcome::UnsupportedTopology
            } else {
                TraversalOutcome::Unknown
            },
            reason: Some(reason),
        }
    }

    fn classified(outcome: TraversalOutcome) -> Self {
        Self {
            outcome,
            reason: None,
        }
    }
}

/// A validated comparison without retaining either address/port tuple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingComparison {
    Unchanged,
    Changed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpBehaviourReport {
    pub mapping: BehaviourSummary,
    pub filtering: BehaviourSummary,
    /// Independently valid observations survive another unsupported primitive.
    pub mapping_aq: Result<MappingComparison, BehaviourFailure>,
    pub mapping_bp: Result<MappingComparison, BehaviourFailure>,
    pub filtering_aq: Result<(), BehaviourFailure>,
    pub filtering_bp: Result<(), BehaviourFailure>,
    pub sent_datagrams: u16,
}

/// Only send_to/recv_from are provided. A connected socket must not mask the
/// alternate-source filtering experiment. Each bind returns a new socket.
pub trait BehaviourSocket {
    fn send_to(
        &mut self,
        packet: &[u8],
        destination: SocketAddr,
        remaining_ms: u64,
    ) -> Result<(), BehaviourFailure>;
    fn receive_from(
        &mut self,
        buffer: &mut [u8],
        remaining_ms: u64,
    ) -> Result<(usize, SocketAddr), BehaviourFailure>;
}

/// Offline seams cover sockets, monotonic time, randomness, and cancellation.
pub trait BehaviourNetwork {
    fn now_ms(&self) -> u64;
    fn cancelled(&self) -> bool;
    fn transaction(&mut self) -> Result<[u8; 16], BehaviourFailure>;
    fn bind_fresh(&mut self) -> Result<Box<dyn BehaviourSocket>, BehaviourFailure>;
}

/// Explicitly invoked host adapter. Construction opens no sockets. The caller
/// supplies the same time origin used to reserve its grant; elapsed time is
/// monotonic even if the system clock moves backwards during collection.
pub struct UdpBehaviourNetwork {
    origin_ms: u64,
    started: Instant,
}

impl UdpBehaviourNetwork {
    pub fn new(now_ms: u64) -> Self {
        Self {
            origin_ms: now_ms,
            started: Instant::now(),
        }
    }
}

impl BehaviourNetwork for UdpBehaviourNetwork {
    fn now_ms(&self) -> u64 {
        self.origin_ms
            .saturating_add(self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64)
    }
    fn cancelled(&self) -> bool {
        false
    }
    fn transaction(&mut self) -> Result<[u8; 16], BehaviourFailure> {
        let mut tx = [0; 16];
        getrandom::fill(&mut tx).map_err(|_| BehaviourFailure::RuntimeUnavailable)?;
        Ok(tx)
    }
    fn bind_fresh(&mut self) -> Result<Box<dyn BehaviourSocket>, BehaviourFailure> {
        UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .map(|s| Box::new(s) as Box<dyn BehaviourSocket>)
            .map_err(|_| BehaviourFailure::RuntimeUnavailable)
    }
}

impl BehaviourSocket for UdpSocket {
    fn send_to(
        &mut self,
        packet: &[u8],
        destination: SocketAddr,
        remaining_ms: u64,
    ) -> Result<(), BehaviourFailure> {
        if remaining_ms == 0 {
            return Err(BehaviourFailure::Deadline);
        }
        self.set_write_timeout(Some(Duration::from_millis(remaining_ms.min(WAIT_MS))))
            .map_err(|_| BehaviourFailure::RuntimeUnavailable)?;
        match UdpSocket::send_to(self, packet, destination) {
            Ok(n) if n == packet.len() => Ok(()),
            _ => Err(BehaviourFailure::RuntimeUnavailable),
        }
    }
    fn receive_from(
        &mut self,
        buffer: &mut [u8],
        remaining_ms: u64,
    ) -> Result<(usize, SocketAddr), BehaviourFailure> {
        if remaining_ms == 0 {
            return Err(BehaviourFailure::Deadline);
        }
        self.set_read_timeout(Some(Duration::from_millis(remaining_ms.min(WAIT_MS))))
            .map_err(|_| BehaviourFailure::RuntimeUnavailable)?;
        self.recv_from(buffer).map_err(|error| match error.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                BehaviourFailure::Timeout
            }
            _ => BehaviourFailure::RuntimeUnavailable,
        })
    }
}

struct Experiment<'a> {
    network: &'a mut dyn BehaviourNetwork,
    session: [u8; 16],
    end_ms: u64,
    remaining: u16,
    sent: u16,
    transactions: BTreeSet<[u8; 16]>,
}

impl Experiment<'_> {
    fn check(&self) -> Result<(), BehaviourFailure> {
        if self.network.cancelled() {
            return Err(BehaviourFailure::Cancelled);
        }
        if self.network.now_ms() >= self.end_ms {
            return Err(BehaviourFailure::Deadline);
        }
        Ok(())
    }

    fn send(
        &mut self,
        socket: &mut dyn BehaviourSocket,
        packet: &[u8],
        destination: SocketAddr,
    ) -> Result<(), BehaviourFailure> {
        self.check()?;
        if self.remaining == 0 {
            return Err(BehaviourFailure::BudgetExhausted);
        }
        // No refund, including a failed kernel send.
        self.remaining -= 1;
        self.sent += 1;
        socket.send_to(
            packet,
            destination,
            self.end_ms.saturating_sub(self.network.now_ms()),
        )?;
        self.check()
    }

    fn receive(
        &mut self,
        socket: &mut dyn BehaviourSocket,
        request: &[u8; REQUEST_BYTES],
        source: SocketAddr,
        ingress: u8,
        outgoing: u8,
        kind: u8,
    ) -> Result<Vec<u8>, BehaviourFailure> {
        let until = self
            .network
            .now_ms()
            .saturating_add(WAIT_MS)
            .min(self.end_ms);
        let size = if kind == 1 {
            REQUEST_BYTES
        } else {
            RESPONSE_BYTES
        };
        let mut packet = [0; 513];
        for _ in 0..MAX_RECEIVES {
            self.check()?;
            let remaining = until.saturating_sub(self.network.now_ms());
            if remaining == 0 {
                return Err(BehaviourFailure::Timeout);
            }
            let received = socket.receive_from(&mut packet, remaining);
            self.check()?;
            let (n, actual) = received?;
            if n == size
                && actual == source
                && packet[..4] == *b"LNT1"
                && packet[4..8] == [kind, request[5], ingress, outgoing]
                && packet[8..40] == request[8..40]
                && packet[72..96] == [0; 24]
                && (kind == 1 || (packet[40..72] == request[40..72] && packet[115..128] == [0; 13]))
                && packet[40..72] != [0; 32]
            {
                return Ok(packet[..n].to_vec());
            }
        }
        Err(BehaviourFailure::InvalidResponse)
    }

    fn observe(
        &mut self,
        socket: &mut dyn BehaviourSocket,
        destination: SocketAddr,
        source: SocketAddr,
        ingress: u8,
        selector: u8,
    ) -> Result<SocketAddr, BehaviourFailure> {
        self.check()?;
        let tx = self.network.transaction()?;
        if tx == [0; 16] || !self.transactions.insert(tx) {
            return Err(BehaviourFailure::InvalidResponse);
        }
        let mut request = [0; REQUEST_BYTES];
        request[..4].copy_from_slice(b"LNT1");
        request[5] = selector;
        request[8..24].copy_from_slice(&self.session);
        request[24..40].copy_from_slice(&tx);
        self.send(socket, &request, destination)?;
        let challenge = self
            .receive(socket, &request, destination, ingress, ingress, 1)
            .map_err(|error| match error {
                BehaviourFailure::Timeout => BehaviourFailure::ChallengeTimeout,
                other => other,
            })?;
        request[4] = 2;
        request[40..72].copy_from_slice(&challenge[40..72]);
        self.send(socket, &request, destination)?;
        let outgoing = if selector == 0 { ingress } else { selector };
        let response = self.receive(socket, &request, source, ingress, outgoing, 3)?;
        decode_observed(&response)
    }
}

fn decode_observed(response: &[u8]) -> Result<SocketAddr, BehaviourFailure> {
    // IPv6 has no qualified topology in this collector. Do not reinterpret it.
    if response[96] != 4 || response[101..113] != [0; 12] {
        return Err(BehaviourFailure::InvalidResponse);
    }
    let ip = Ipv4Addr::new(response[97], response[98], response[99], response[100]);
    let port = u16::from_be_bytes([response[113], response[114]]);
    if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() || port == 0 {
        return Err(BehaviourFailure::InvalidResponse);
    }
    Ok(SocketAddr::new(IpAddr::V4(ip), port))
}

fn endpoint_v4(endpoint: &BehaviourEndpoint) -> bool {
    endpoint.address.is_ipv4()
        && endpoint.address.port() != 0
        && !endpoint.address.ip().is_unspecified()
        && !endpoint.address.ip().is_multicast()
}

fn alternate(
    topology: &BehaviourTopology,
    ip_change: bool,
    filtering: bool,
) -> Option<&BehaviourEndpoint> {
    let other = if ip_change {
        topology.bp.as_ref()?
    } else {
        topology.aq.as_ref()?
    };
    let ap = topology.ap.address;
    (endpoint_v4(other)
        && if filtering {
            other.filtering_qualified
        } else {
            other.mapping_qualified
        }
        && if ip_change {
            other.address.ip() != ap.ip() && other.address.port() == ap.port()
        } else {
            other.address.ip() == ap.ip() && other.address.port() != ap.port()
        })
    .then_some(other)
}

fn unavailable(reason: BehaviourFailure) -> UdpBehaviourReport {
    UdpBehaviourReport {
        mapping: BehaviourSummary::unknown(reason),
        filtering: BehaviourSummary::unknown(reason),
        mapping_aq: Err(reason),
        mapping_bp: Err(reason),
        filtering_aq: Err(reason),
        filtering_bp: Err(reason),
        sent_datagrams: 0,
    }
}

/// Collect once, with one local allowance and one absolute deadline. Filtering
/// runs FIRST on an A:p-only fresh socket: the prober pins its first A:p proof.
/// Keep that socket alive while a second socket collects all mapping samples,
/// so a local ephemeral port cannot be immediately reused between mechanisms.
pub fn collect_udp_behaviour(
    descriptor: &TraversalDescriptorV1,
    reservation: Reservation,
    session: BehaviourSession,
    topology: &BehaviourTopology,
    network: &mut dyn BehaviourNetwork,
) -> UdpBehaviourReport {
    if descriptor.validate_at(network.now_ms()).is_err()
        || descriptor.binding_digest().as_ref() != Ok(&session.descriptor_digest)
        || !super::reservation_fits(descriptor, reservation)
        || reservation.experiment_ms != descriptor.budgets.experiment_ms
        || reservation.cleanup_reserve_ms != descriptor.budgets.cleanup_reserve_ms
        || reservation.collector_end_ms
            > network
                .now_ms()
                .saturating_add(descriptor.budgets.experiment_ms)
    {
        return unavailable(BehaviourFailure::NotAuthorized);
    }
    if topology.revision != descriptor.endpoint_set_revision
        || !endpoint_v4(&topology.ap)
        || !topology.ap.mapping_qualified
    {
        return unavailable(BehaviourFailure::UnsupportedTopology);
    }
    if !descriptor
        .operations
        .contains(&TraversalOperation::ObserveMapping)
    {
        // LNT1 selector 0 baseline also needs mapping scope; never silently
        // spend that allowance under an observe_filtering-only capability.
        return unavailable(BehaviourFailure::NotAuthorized);
    }
    if descriptor.budgets.datagram_bytes < RESPONSE_BYTES as u16 {
        return unavailable(BehaviourFailure::BudgetExhausted);
    }
    let mut experiment = Experiment {
        network,
        session: session.id,
        end_ms: reservation
            .collector_end_ms
            .saturating_sub(reservation.cleanup_reserve_ms),
        remaining: descriptor
            .budgets
            .outbound_datagrams
            .saturating_sub(descriptor.budgets.cleanup_datagrams),
        sent: 0,
        transactions: BTreeSet::new(),
    };
    if let Err(error) = experiment.check() {
        return unavailable(error);
    }
    let mut report = unavailable(BehaviourFailure::NotStarted);
    if alternate(topology, false, false).is_none() {
        report.mapping_aq = Err(BehaviourFailure::UnsupportedTopology);
    }
    if alternate(topology, true, false).is_none() {
        report.mapping_bp = Err(BehaviourFailure::UnsupportedTopology);
    }
    if alternate(topology, false, true).is_none() {
        report.filtering_aq = Err(BehaviourFailure::UnsupportedTopology);
    }
    if alternate(topology, true, true).is_none() {
        report.filtering_bp = Err(BehaviourFailure::UnsupportedTopology);
    }
    // Keep ownership here until mapping finishes, even when filtering fails.
    let mut filter_socket = None;
    if !topology.ap.filtering_qualified {
        report.filtering = BehaviourSummary::unknown(BehaviourFailure::UnsupportedTopology);
    } else if descriptor
        .operations
        .contains(&TraversalOperation::ObserveFiltering)
    {
        match experiment.network.bind_fresh() {
            Ok(mut socket) => {
                report.filtering = filtering(
                    &mut experiment,
                    socket.as_mut(),
                    topology,
                    &mut report.filtering_aq,
                    &mut report.filtering_bp,
                );
                filter_socket = Some(socket);
            }
            Err(error) => report.filtering = BehaviourSummary::unknown(error),
        }
    } else {
        report.filtering = BehaviourSummary::unknown(BehaviourFailure::NotAuthorized);
    }
    match experiment
        .check()
        .and_then(|()| experiment.network.bind_fresh())
    {
        Ok(mut socket) => {
            report.mapping = mapping(
                &mut experiment,
                socket.as_mut(),
                topology,
                &mut report.mapping_aq,
                &mut report.mapping_bp,
            )
        }
        Err(error) => report.mapping = BehaviourSummary::unknown(error),
    }
    report.sent_datagrams = experiment.sent;
    drop(filter_socket);
    report
}

fn filtering(
    experiment: &mut Experiment<'_>,
    socket: &mut dyn BehaviourSocket,
    topology: &BehaviourTopology,
    aq: &mut Result<(), BehaviourFailure>,
    bp: &mut Result<(), BehaviourFailure>,
) -> BehaviourSummary {
    let ap = topology.ap.address;
    let initial = match experiment.observe(socket, ap, ap, 0, 0) {
        Ok(tuple) => tuple,
        Err(error) => return BehaviourSummary::unknown(error),
    };
    let mut test = |ip_change, slot: &mut Result<(), BehaviourFailure>| {
        if let Some(other) = alternate(topology, ip_change, true) {
            *slot = experiment
                .observe(socket, ap, other.address, 0, if ip_change { 2 } else { 1 })
                .and_then(|observed| {
                    if observed == initial {
                        Ok(())
                    } else {
                        Err(BehaviourFailure::Rebinding)
                    }
                });
        }
    };
    test(true, bp);
    test(false, aq);
    let final_tuple = match experiment.observe(socket, ap, ap, 0, 0) {
        Ok(tuple) => tuple,
        Err(error) => return BehaviourSummary::unknown(error),
    };
    if final_tuple != initial
        || *aq == Err(BehaviourFailure::Rebinding)
        || *bp == Err(BehaviourFailure::Rebinding)
    {
        return BehaviourSummary::unknown(BehaviourFailure::Rebinding);
    }
    // Only a missing observation after sending its proof can indicate filtering.
    // The challenge comes from the already-contacted A:p, so its loss cannot.
    // Each observation has one bounded attempt: loss or a silent proof refusal
    // can still resemble filtering. These finite results do not establish its
    // cause; no retransmission/loss-discounting guarantee is made.
    match (*bp, *aq) {
        (Ok(()), _) => BehaviourSummary::classified(TraversalOutcome::EndpointIndependent),
        (Err(BehaviourFailure::Timeout), Ok(())) => {
            BehaviourSummary::classified(TraversalOutcome::AddressDependent)
        }
        (Err(BehaviourFailure::Timeout), Err(BehaviourFailure::Timeout)) => {
            BehaviourSummary::classified(TraversalOutcome::AddressAndPortDependent)
        }
        (Err(BehaviourFailure::Timeout), Err(error)) | (Err(error), _) => {
            BehaviourSummary::unknown(error)
        }
    }
}

fn mapping(
    experiment: &mut Experiment<'_>,
    socket: &mut dyn BehaviourSocket,
    topology: &BehaviourTopology,
    aq: &mut Result<MappingComparison, BehaviourFailure>,
    bp: &mut Result<MappingComparison, BehaviourFailure>,
) -> BehaviourSummary {
    let ap = topology.ap.address;
    let initial = match experiment.observe(socket, ap, ap, 0, 0) {
        Ok(tuple) => tuple,
        Err(error) => return BehaviourSummary::unknown(error),
    };
    let mut sample = |ip_change, slot: &mut Result<MappingComparison, BehaviourFailure>| {
        let other = alternate(topology, ip_change, false)?;
        let identity = if ip_change { 2 } else { 1 };
        let pair = experiment
            .observe(socket, other.address, other.address, identity, 0)
            .and_then(|first| {
                experiment
                    .observe(socket, other.address, other.address, identity, 0)
                    .and_then(|second| {
                        if first == second {
                            Ok(first)
                        } else {
                            Err(BehaviourFailure::Rebinding)
                        }
                    })
            });
        *slot = pair.map(|observed| {
            if observed == initial {
                MappingComparison::Unchanged
            } else {
                MappingComparison::Changed
            }
        });
        Some(pair)
    };
    let at_aq = sample(false, aq);
    let at_bp = sample(true, bp);
    let final_tuple = match experiment.observe(socket, ap, ap, 0, 0) {
        Ok(tuple) => tuple,
        Err(error) => return BehaviourSummary::unknown(error),
    };
    if final_tuple != initial
        || *aq == Err(BehaviourFailure::Rebinding)
        || *bp == Err(BehaviourFailure::Rebinding)
    {
        return BehaviourSummary::unknown(BehaviourFailure::Rebinding);
    }
    match (at_aq, at_bp) {
        (Some(Ok(q)), _) if q != initial => {
            BehaviourSummary::classified(TraversalOutcome::AddressAndPortDependent)
        }
        (Some(Ok(_)), Some(Ok(b))) if b != initial => {
            BehaviourSummary::classified(TraversalOutcome::AddressDependent)
        }
        (Some(Ok(_)), Some(Ok(_))) => {
            BehaviourSummary::classified(TraversalOutcome::EndpointIndependent)
        }
        (Some(Err(error)), _) | (_, Some(Err(error))) => BehaviourSummary::unknown(error),
        _ => BehaviourSummary::unknown(BehaviourFailure::UnsupportedTopology),
    }
}

#[cfg(test)]
mod tests;
