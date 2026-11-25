use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::http::HttpResponse;

use super::super::{
    BehaviourFailure, BehaviourNetwork, BehaviourSocket, PairIoError, PairNetwork, pair::wire,
};
use super::Clock;
use super::channel::{Channel, POLL_MS, cancelled};
use super::socket::{Ledger, Seam, loopback};

pub(super) struct UdpAdapter<'a> {
    pub clock: Clock,
    pub ledger: Ledger,
    pub endpoint: SocketAddr,
    pub ingress: Option<SocketAddr>,
    pub revision: &'a str,
    pub control: &'a mut Channel,
}

impl BehaviourNetwork for UdpAdapter<'_> {
    fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    fn cancelled(&self) -> bool {
        cancelled()
    }

    fn transaction(&mut self) -> Result<[u8; 16], BehaviourFailure> {
        super::random().map_err(|_| BehaviourFailure::RuntimeUnavailable)
    }

    fn bind_fresh(&mut self) -> Result<Box<dyn BehaviourSocket>, BehaviourFailure> {
        self.ledger
            .bind(self.endpoint, self.ingress, Seam::Behaviour)
            .map(|socket| Box::new(socket) as Box<dyn BehaviourSocket>)
            .map_err(|_| BehaviourFailure::RuntimeUnavailable)
    }
}

impl PairNetwork for UdpAdapter<'_> {
    fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    fn cancelled(&self) -> bool {
        cancelled()
    }

    fn random(&mut self) -> Result<[u8; 16], PairIoError> {
        super::random().map_err(|_| PairIoError::Unavailable)
    }

    fn wait(&mut self, milliseconds: u64) {
        let end = Instant::now() + Duration::from_millis(milliseconds);
        while !cancelled() {
            let delay = end
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(POLL_MS));
            if delay.is_zero() {
                break;
            }
            std::thread::sleep(delay);
        }
    }

    fn open_socket(&mut self) -> Result<Box<dyn BehaviourSocket>, PairIoError> {
        self.ledger
            .bind(self.endpoint, self.ingress, Seam::Pair)
            .map(|socket| Box::new(socket) as Box<dyn BehaviourSocket>)
            .map_err(|_| PairIoError::Unavailable)
    }

    fn coordinator(&self) -> SocketAddr {
        self.endpoint
    }

    fn endpoint_revision(&self) -> &str {
        self.revision
    }

    fn candidate_allowed(&self, candidate: SocketAddr) -> bool {
        loopback(candidate)
            && candidate.is_ipv4() == self.endpoint.is_ipv4()
            && candidate != self.endpoint
            && Some(candidate) != self.ingress
    }

    fn post(
        &mut self,
        path: &str,
        body: &[u8],
        remaining_ms: u64,
    ) -> Result<HttpResponse, PairIoError> {
        if !matches!(path, wire::ENROLL_PATH | wire::CONTROL_PATH) {
            return Err(PairIoError::InvalidResponse);
        }
        let until = Instant::now() + Duration::from_millis(remaining_ms);
        self.control
            .start(path, body, until)
            .map_err(|_| PairIoError::Unavailable)?;
        self.control
            .response(wire::CONTROL_RESPONSE_MAX, until)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::InvalidData {
                    PairIoError::InvalidResponse
                } else {
                    PairIoError::Unavailable
                }
            })
    }
}
