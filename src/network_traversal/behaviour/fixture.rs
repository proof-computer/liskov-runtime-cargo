//! Prober-side LNT1 reflectors on three pinned loopback tuples.

use std::cell::RefCell;
use std::rc::Rc;

use super::*;

struct Reflectors {
    sockets: [UdpSocket; 3],
    addresses: [SocketAddr; 3],
    trace: Vec<(usize, SocketAddr)>,
}

impl Reflectors {
    fn new() -> Option<Self> {
        let ap = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).ok()?;
        let aq = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).ok()?;
        let bp =
            UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), ap.local_addr().ok()?.port())).ok()?;
        Some(Self {
            addresses: [
                ap.local_addr().ok()?,
                aq.local_addr().ok()?,
                bp.local_addr().ok()?,
            ],
            sockets: [ap, aq, bp],
            trace: Vec::new(),
        })
    }

    fn reflect(
        &mut self,
        ingress: usize,
        peer: SocketAddr,
        remaining_ms: u64,
    ) -> Result<(), BehaviourFailure> {
        let mut request = [0; REQUEST_BYTES + 1];
        let (length, source) = self.sockets[ingress].receive_from(&mut request, remaining_ms)?;
        if length != REQUEST_BYTES || source != peer || &request[..4] != b"LNT1" || request[5] > 2 {
            return Err(BehaviourFailure::InvalidResponse);
        }
        self.trace.push((ingress, source));
        let proof = request[4] == 2;
        let outgoing = if proof && request[5] != 0 {
            usize::from(request[5])
        } else {
            ingress
        };
        let mut reply = [0; RESPONSE_BYTES];
        reply[..length].copy_from_slice(&request[..length]);
        reply[4] = if proof { 3 } else { 1 };
        reply[6] = ingress as u8;
        reply[7] = outgoing as u8;
        reply[40..72].fill(0x71);
        let length = if proof {
            let IpAddr::V4(ip) = source.ip() else {
                return Err(BehaviourFailure::InvalidResponse);
            };
            reply[96] = 4;
            reply[97..101].copy_from_slice(&ip.octets());
            reply[113..115].copy_from_slice(&source.port().to_be_bytes());
            // The collector must reject a valid-looking observation from the wrong source.
            if outgoing != ingress {
                BehaviourSocket::send_to(&mut self.sockets[ingress], &reply, source, remaining_ms)?;
            }
            RESPONSE_BYTES
        } else {
            REQUEST_BYTES
        };
        BehaviourSocket::send_to(
            &mut self.sockets[outgoing],
            &reply[..length],
            source,
            remaining_ms,
        )
    }

    fn confirms_isolation(&self, report: &UdpBehaviourReport) -> bool {
        let trace = &self.trace;
        let (Some((0, first)), Some((0, second))) = (trace.first(), trace.get(8)) else {
            return false;
        };
        trace.len() == 20
            && trace.len() == usize::from(report.sent_datagrams)
            && first != second
            && trace[..8]
                .iter()
                .all(|(ingress, peer)| *ingress == 0 && peer == first)
            && trace[8..].iter().all(|(_, peer)| peer == second)
            && (0..3).all(|i| trace[8..].iter().any(|(ingress, _)| *ingress == i))
    }
}

struct Network {
    reflectors: Rc<RefCell<Reflectors>>,
    clock: UdpBehaviourNetwork,
}

impl BehaviourNetwork for Network {
    fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    fn cancelled(&self) -> bool {
        false
    }

    fn transaction(&mut self) -> Result<[u8; 16], BehaviourFailure> {
        self.clock.transaction()
    }

    fn bind_fresh(&mut self) -> Result<Box<dyn BehaviourSocket>, BehaviourFailure> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|_| BehaviourFailure::RuntimeUnavailable)?;
        let address = socket
            .local_addr()
            .map_err(|_| BehaviourFailure::RuntimeUnavailable)?;
        Ok(Box::new(Client {
            socket,
            address,
            reflectors: self.reflectors.clone(),
        }))
    }
}

struct Client {
    socket: UdpSocket,
    address: SocketAddr,
    reflectors: Rc<RefCell<Reflectors>>,
}

impl BehaviourSocket for Client {
    fn send_to(
        &mut self,
        packet: &[u8],
        destination: SocketAddr,
        remaining_ms: u64,
    ) -> Result<(), BehaviourFailure> {
        let ingress = self
            .reflectors
            .borrow()
            .addresses
            .iter()
            .position(|addr| *addr == destination)
            .ok_or(BehaviourFailure::UnsupportedTopology)?;
        BehaviourSocket::send_to(&mut self.socket, packet, destination, remaining_ms)?;
        self.reflectors
            .borrow_mut()
            .reflect(ingress, self.address, remaining_ms)
    }

    fn receive_from(
        &mut self,
        buffer: &mut [u8],
        remaining_ms: u64,
    ) -> Result<(usize, SocketAddr), BehaviourFailure> {
        self.socket.receive_from(buffer, remaining_ms)
    }
}

pub(in crate::network_traversal) fn run() -> Option<UdpBehaviourReport> {
    let descriptor = super::super::fixture_descriptor("observe")?;
    let now = descriptor.issued_at_ms + 1;
    let session = BehaviourSession::from_authenticated_enrollment(&"11".repeat(16), &descriptor)?;
    let collector_end_ms = now + descriptor.budgets.experiment_ms;
    let reserve = super::super::EXISTING_DELIVERY_RESERVE_MS;
    let reservation = Reservation {
        experiment_ms: descriptor.budgets.experiment_ms,
        cleanup_reserve_ms: descriptor.budgets.cleanup_reserve_ms,
        delivery_reserve_ms: reserve,
        collector_end_ms,
        delivery_end_ms: collector_end_ms + reserve,
    };
    let reflectors = Rc::new(RefCell::new(Reflectors::new()?));
    let endpoint = |address| BehaviourEndpoint {
        address,
        mapping_qualified: true,
        filtering_qualified: true,
    };
    let [ap, aq, bp] = reflectors.borrow().addresses;
    let topology = BehaviourTopology {
        revision: descriptor.endpoint_set_revision.clone(),
        ap: endpoint(ap),
        aq: Some(endpoint(aq)),
        bp: Some(endpoint(bp)),
    };
    let report = collect_udp_behaviour(
        &descriptor,
        reservation,
        session,
        &topology,
        &mut Network {
            reflectors: reflectors.clone(),
            clock: UdpBehaviourNetwork::new(now),
        },
    );
    let isolated = reflectors.borrow().confirms_isolation(&report);
    (isolated
        && report.mapping.outcome == TraversalOutcome::EndpointIndependent
        && report.filtering.outcome == TraversalOutcome::EndpointIndependent)
        .then_some(report)
}
