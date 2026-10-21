//! Explicitly constructed listener; never opened by grant reservation.
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use super::{
    INBOUND_PORT_MAX, INBOUND_PORT_MIN, MappedPortProtocol, MappingListener, MappingStop,
    TraversalStage,
};

enum Socket {
    Tcp(TcpListener),
    Udp(UdpSocket),
}
/// A dedicated IPv4 high-port listener. No Debug/serde: its tuple stays local.
pub struct NativeMappingListener {
    socket: Socket,
    port: u16,
    baseline_started: bool,
    verification_started: bool,
}
impl NativeMappingListener {
    pub fn bind_fresh(protocol: MappedPortProtocol) -> Result<Self, MappingStop> {
        for _ in 0..16 {
            let mut seed = [0; 2];
            getrandom::fill(&mut seed).map_err(|_| MappingStop::Unsupported)?;
            let port = INBOUND_PORT_MIN
                + u16::from_be_bytes(seed) % (INBOUND_PORT_MAX - INBOUND_PORT_MIN + 1);
            let socket = match protocol {
                MappedPortProtocol::Tcp => {
                    TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).map(Socket::Tcp)
                }
                MappedPortProtocol::Udp => {
                    UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).map(Socket::Udp)
                }
            };
            if let Ok(socket) = socket {
                return Ok(Self {
                    socket,
                    port,
                    baseline_started: false,
                    verification_started: false,
                });
            }
        }
        Err(MappingStop::Unsupported)
    }
}
fn remaining(end: Instant) -> Result<Duration, MappingStop> {
    let remaining = end.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(MappingStop::Deadline)
    } else {
        Ok(remaining)
    }
}
fn tcp_answer(mut stream: TcpStream, end: Instant) -> Result<[u8; 32], MappingStop> {
    let mut nonce = [0; 32];
    let mut received = 0;
    while received < nonce.len() {
        stream
            .set_read_timeout(Some(remaining(end)?))
            .map_err(|_| MappingStop::Unsupported)?;
        let n = stream
            .read(&mut nonce[received..])
            .map_err(|_| MappingStop::InvalidBinding)?;
        if n == 0 {
            return Err(MappingStop::InvalidBinding);
        }
        received += n;
    }
    let mut sent = 0;
    while sent < nonce.len() {
        stream
            .set_write_timeout(Some(remaining(end)?))
            .map_err(|_| MappingStop::Unsupported)?;
        let n = stream
            .write(&nonce[sent..])
            .map_err(|_| MappingStop::InvalidBinding)?;
        if n == 0 {
            return Err(MappingStop::InvalidBinding);
        }
        sent += n;
    }
    remaining(end)?;
    Ok(nonce)
}
impl MappingListener for NativeMappingListener {
    fn port(&self) -> u16 {
        self.port
    }
    fn answer_challenge(
        &mut self,
        stage: TraversalStage,
        source: IpAddr,
        budget: Duration,
    ) -> Result<[u8; 32], MappingStop> {
        match stage {
            TraversalStage::Baseline if !self.baseline_started && !self.verification_started => {
                self.baseline_started = true
            }
            // A failed baseline may have produced no local challenge at all.
            // The coordinator validates its authenticated failed observation
            // before create; local echo bookkeeping must not veto that path.
            TraversalStage::MappingVerify if !self.verification_started => {
                self.verification_started = true
            }
            _ => return Err(MappingStop::Budget),
        }
        let end = Instant::now()
            .checked_add(budget)
            .ok_or(MappingStop::Deadline)?;
        match &self.socket {
            Socket::Tcp(listener) => {
                listener
                    .set_nonblocking(true)
                    .map_err(|_| MappingStop::Unsupported)?;
                let mut refused = 0;
                loop {
                    remaining(end)?;
                    match listener.accept() {
                        Ok((stream, peer)) if peer.ip() == source => {
                            return tcp_answer(stream, end);
                        }
                        Ok(_) => {
                            refused += 1;
                            if refused == 16 {
                                return Err(MappingStop::InvalidBinding);
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(remaining(end)?.min(Duration::from_millis(5)))
                        }
                        Err(_) => return Err(MappingStop::Unsupported),
                    }
                }
            }
            Socket::Udp(socket) => {
                let mut packet = [0; 33];
                for _ in 0..16 {
                    socket
                        .set_read_timeout(Some(remaining(end)?))
                        .map_err(|_| MappingStop::Unsupported)?;
                    let (n, peer) = socket
                        .recv_from(&mut packet)
                        .map_err(|_| MappingStop::Deadline)?;
                    if peer.ip() != source {
                        continue;
                    }
                    if n != 32 {
                        return Err(MappingStop::InvalidBinding);
                    }
                    socket
                        .set_write_timeout(Some(remaining(end)?))
                        .map_err(|_| MappingStop::Unsupported)?;
                    if socket
                        .send_to(&packet[..32], peer)
                        .map_err(|_| MappingStop::Unsupported)?
                        != 32
                    {
                        return Err(MappingStop::InvalidBinding);
                    }
                    remaining(end)?;
                    return Ok(packet[..32].try_into().expect("fixed nonce length"));
                }
                Err(MappingStop::InvalidBinding)
            }
        }
    }
}
