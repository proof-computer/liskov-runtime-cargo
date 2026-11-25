use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use super::super::{BehaviourSocket, TraversalRefusal};
use super::wire::CONTROL_RESPONSE_MAX;
use crate::http::{HttpClient, HttpError, HttpResponse, UreqHttpClient};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PairIoError {
    Unavailable,
    InvalidResponse,
}

/// Bounded operations for a single pair run. Instances are used with exactly
/// one socket. The clock uses the bootstrap time origin and monotonic elapsed
/// time, and every wait is bounded by the caller's remaining allowance.
pub trait PairNetwork {
    fn now_ms(&self) -> u64;
    fn cancelled(&self) -> bool;
    fn random(&mut self) -> Result<[u8; 16], PairIoError>;
    fn wait(&mut self, milliseconds: u64);
    fn open_socket(&mut self) -> Result<Box<dyn BehaviourSocket>, PairIoError>;
    fn coordinator(&self) -> SocketAddr;
    fn endpoint_revision(&self) -> &str;
    fn candidate_allowed(&self, candidate: SocketAddr) -> bool;
    fn post(
        &mut self,
        path: &str,
        body: &[u8],
        remaining_ms: u64,
    ) -> Result<HttpResponse, PairIoError>;
}

/// The authorized caller supplies the pinned control origin, UDP tuple and
/// revision together. Construction performs no I/O and the released helper
/// does not create this adapter. No candidate is used as a control destination.
pub struct HttpsPairNetwork<'a> {
    origin: url::Url,
    datagram: SocketAddr,
    revision: &'a str,
    started: Instant,
    origin_ms: u64,
    cancelled: &'a dyn Fn() -> bool,
}

impl<'a> HttpsPairNetwork<'a> {
    pub fn new(
        origin: &str,
        datagram: SocketAddr,
        revision: &'a str,
        now_ms: u64,
        cancelled: &'a dyn Fn() -> bool,
    ) -> Result<Self, TraversalRefusal> {
        let origin = url::Url::parse(origin).map_err(|_| TraversalRefusal::InvalidBinding)?;
        if origin.scheme() != "https"
            || origin.host().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !public_endpoint(datagram)
            || !super::super::text(revision)
        {
            return Err(TraversalRefusal::InvalidBinding);
        }
        Ok(Self {
            origin,
            datagram,
            revision,
            origin_ms: now_ms,
            started: Instant::now(),
            cancelled,
        })
    }
}

impl PairNetwork for HttpsPairNetwork<'_> {
    fn now_ms(&self) -> u64 {
        self.origin_ms.saturating_add(
            self.started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        )
    }
    fn cancelled(&self) -> bool {
        (self.cancelled)()
    }
    fn random(&mut self) -> Result<[u8; 16], PairIoError> {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(|_| PairIoError::Unavailable)?;
        Ok(nonce)
    }
    fn wait(&mut self, milliseconds: u64) {
        std::thread::sleep(Duration::from_millis(milliseconds));
    }
    fn open_socket(&mut self) -> Result<Box<dyn BehaviourSocket>, PairIoError> {
        bind_udp(self.datagram)
            .map(|socket| Box::new(socket) as Box<dyn BehaviourSocket>)
            .map_err(|_| PairIoError::Unavailable)
    }
    fn coordinator(&self) -> SocketAddr {
        self.datagram
    }
    fn endpoint_revision(&self) -> &str {
        self.revision
    }
    fn candidate_allowed(&self, candidate: SocketAddr) -> bool {
        candidate.is_ipv4() == self.datagram.is_ipv4()
            && candidate != self.datagram
            && public_endpoint(candidate)
    }
    fn post(
        &mut self,
        path: &str,
        body: &[u8],
        remaining_ms: u64,
    ) -> Result<HttpResponse, PairIoError> {
        let mut url = self.origin.clone();
        url.set_path(path);
        let client =
            UreqHttpClient::with_limits(Duration::from_millis(remaining_ms), CONTROL_RESPONSE_MAX);
        client
            .post(url.as_str(), body)
            .map_err(|error| match error {
                HttpError::Transport => PairIoError::Unavailable,
                HttpError::ResponseTooLarge => PairIoError::InvalidResponse,
            })
    }
}

pub(super) fn bind_udp(family: SocketAddr) -> std::io::Result<UdpSocket> {
    let address = if family.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    UdpSocket::bind((address, 0))
}

fn public_endpoint(address: SocketAddr) -> bool {
    address.port() != 0
        && match address.ip() {
            IpAddr::V4(ip) => {
                let [a, b, c, _] = ip.octets();
                a != 0
                    && a < 224
                    && !ip.is_private()
                    && !ip.is_loopback()
                    && !ip.is_link_local()
                    && !ip.is_documentation()
                    && !(a == 100 && (64..128).contains(&b))
                    && !(a == 192 && b == 0 && c == 0)
                    && !(a == 192 && b == 88 && c == 99)
                    && !(a == 198 && (b == 18 || b == 19))
            }
            IpAddr::V6(ip) => {
                let segments = ip.segments();
                matches!(address, SocketAddr::V6(v6) if v6.scope_id() == 0 && v6.flowinfo() == 0)
                    && (segments[0] & 0xe000 == 0x2000)
                    && !(segments[0] == 0x2001 && (segments[1] < 0x200 || segments[1] == 0xdb8))
                    && !matches!(segments[0], 0x2002 | 0x3fff)
            }
        }
}
