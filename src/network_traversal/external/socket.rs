use std::cell::RefCell;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::rc::Rc;
use std::time::{Duration, Instant};

use serde::Serialize;

use super::super::{BehaviourFailure, BehaviourSocket, pair::wire::DATAGRAM_MAX};
use super::channel::{POLL_MS, cancelled};

const FRAME_V4: u8 = 1;
const FRAME_V6: u8 = 2;

pub(super) fn loopback(addr: SocketAddr) -> bool {
    addr.port() != 0
        && addr.ip().is_loopback()
        && !matches!(addr, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.flowinfo() != 0)
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Seam {
    Behaviour,
    Pair,
    MappingListener,
    RouterClient,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SocketUse {
    index: usize,
    seam: Seam,
    local: SocketAddr,
    sent_datagrams: u64,
    sent_bytes: u64,
    received_datagrams: u64,
    received_bytes: u64,
}

#[derive(Clone, Default)]
pub(super) struct Ledger(Rc<RefCell<Vec<SocketUse>>>);

impl Ledger {
    pub(super) fn report(self) -> Vec<SocketUse> {
        self.0.take()
    }

    pub(super) fn bind(
        &self,
        endpoint: SocketAddr,
        ingress: Option<SocketAddr>,
        seam: Seam,
    ) -> io::Result<Socket> {
        let address = if endpoint.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        };
        self.track(UdpSocket::bind((address, 0))?, ingress, seam)
    }

    pub(super) fn track(
        &self,
        socket: UdpSocket,
        ingress: Option<SocketAddr>,
        seam: Seam,
    ) -> io::Result<Socket> {
        let local = socket.local_addr()?;
        let mut rows = self.0.borrow_mut();
        let index = rows.len();
        rows.push(SocketUse {
            index,
            seam,
            local,
            sent_datagrams: 0,
            sent_bytes: 0,
            received_datagrams: 0,
            received_bytes: 0,
        });
        Ok(Socket {
            socket,
            ingress,
            ledger: self.clone(),
            index,
        })
    }
}

pub(super) struct Socket {
    socket: UdpSocket,
    ingress: Option<SocketAddr>,
    ledger: Ledger,
    index: usize,
}

fn frame(out: &mut Vec<u8>, destination: SocketAddr, body: &[u8]) {
    match destination.ip() {
        IpAddr::V4(ip) => {
            out.push(FRAME_V4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(FRAME_V6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&destination.port().to_be_bytes());
    out.extend_from_slice(body);
}

fn unframe(frame: &[u8], v4: bool) -> Option<(SocketAddr, &[u8])> {
    let (ip, tail) = match frame {
        [FRAME_V4, a, b, c, d, tail @ ..] if v4 => {
            (IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)), tail)
        }
        [FRAME_V6, tail @ ..] if !v4 => {
            let (ip, tail) = tail.split_at_checked(16)?;
            (
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(ip).ok()?)),
                tail,
            )
        }
        _ => return None,
    };
    let [hi, lo, body @ ..] = tail else {
        return None;
    };
    let address = SocketAddr::new(ip, u16::from_be_bytes([*hi, *lo]));
    (loopback(address) && body.len() <= DATAGRAM_MAX).then_some((address, body))
}

fn wait_slice(until: Instant, stop: &dyn Fn() -> bool) -> Result<Duration, BehaviourFailure> {
    if stop() {
        return Err(BehaviourFailure::Cancelled);
    }
    let remaining = until.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(BehaviourFailure::Timeout);
    }
    Ok(remaining.min(Duration::from_millis(POLL_MS)))
}

fn retry(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

impl Socket {
    pub(super) fn send(
        &self,
        body: &[u8],
        to: SocketAddr,
        until: Instant,
        stop: &dyn Fn() -> bool,
    ) -> Result<(), BehaviourFailure> {
        if !loopback(to) || body.len() > DATAGRAM_MAX {
            return Err(BehaviourFailure::InvalidResponse);
        }
        let mut framed = Vec::new();
        let (wire, to) = match self.ingress {
            Some(ingress) if ingress.is_ipv4() == to.is_ipv4() => {
                frame(&mut framed, to, body);
                (framed.as_slice(), ingress)
            }
            Some(_) => return Err(BehaviourFailure::InvalidResponse),
            None => (body, to),
        };
        loop {
            self.socket
                .set_write_timeout(Some(wait_slice(until, stop)?))
                .map_err(|_| BehaviourFailure::RuntimeUnavailable)?;
            match self.socket.send_to(wire, to) {
                Ok(n) if n == wire.len() => {
                    let row = &mut self.ledger.0.borrow_mut()[self.index];
                    row.sent_bytes += n as u64;
                    row.sent_datagrams += 1;
                    return Ok(());
                }
                Err(e) if retry(&e) => {}
                _ => return Err(BehaviourFailure::RuntimeUnavailable),
            }
        }
    }

    pub(super) fn receive(
        &self,
        buffer: &mut [u8],
        until: Instant,
        stop: &dyn Fn() -> bool,
    ) -> Result<(usize, SocketAddr), BehaviourFailure> {
        // Large enough to count the actual wire size even for a refused UDP datagram.
        let mut wire = [0; 65_536];
        loop {
            self.socket
                .set_read_timeout(Some(wait_slice(until, stop)?))
                .map_err(|_| BehaviourFailure::RuntimeUnavailable)?;
            let (count, peer) = match self.socket.recv_from(&mut wire) {
                Ok(received) => received,
                Err(e) if retry(&e) => continue,
                Err(_) => return Err(BehaviourFailure::RuntimeUnavailable),
            };
            {
                let row = &mut self.ledger.0.borrow_mut()[self.index];
                row.received_bytes += count as u64;
                row.received_datagrams += 1;
            }
            let wire = &wire[..count];
            let (remote, body) = match self.ingress {
                Some(ingress) if ingress == peer => match unframe(wire, ingress.is_ipv4()) {
                    Some(value) => value,
                    None => continue,
                },
                Some(_) => continue,
                None if loopback(peer) => (peer, wire),
                None => continue,
            };
            if body.len() > DATAGRAM_MAX || body.len() > buffer.len() {
                continue;
            }
            buffer[..body.len()].copy_from_slice(body);
            return Ok((body.len(), remote));
        }
    }
}

impl BehaviourSocket for Socket {
    fn send_to(
        &mut self,
        packet: &[u8],
        destination: SocketAddr,
        remaining_ms: u64,
    ) -> Result<(), BehaviourFailure> {
        self.send(
            packet,
            destination,
            Instant::now() + Duration::from_millis(remaining_ms),
            &cancelled,
        )
    }

    fn receive_from(
        &mut self,
        buffer: &mut [u8],
        remaining_ms: u64,
    ) -> Result<(usize, SocketAddr), BehaviourFailure> {
        self.receive(
            buffer,
            Instant::now() + Duration::from_millis(remaining_ms),
            &cancelled,
        )
    }
}
