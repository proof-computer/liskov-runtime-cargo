//! The device half of the inbound reachability check.
//!
//! The processor opens one high port, asks the prober to dial it once per
//! address family, and signs the nonce that arrives over each inbound
//! connection. A signature the device produces is worthless unless it travelled
//! the path being measured, which is why it is written back down the same
//! socket rather than posted.
//!
//! The listener is blocking and lives on its own threads: signing goes over the
//! Cargo bridge, which is synchronous, and must not stall the HTTP requests
//! waiting for the prober's verdicts.
use crate::inbound_reachability_contract::*;
use crate::processor_facts::FactSigner;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Sockets a device opened for one check. Closed when this is dropped: the
/// port never outlives the probe.
pub struct InboundListeners {
    pub port: u16,
    listeners: Vec<TcpListener>,
}

/// Bind one port in the admitted range across both families.
///
/// A Cargo workload cannot bind below 1024, so the range is high by necessity.
/// `[::]` is dual-stack on a default Linux, in which case the second bind is
/// refused and that one socket already serves IPv4. Where the OS keeps the two
/// separate, the second bind succeeds and both are served. Either way the
/// prober reaches the same port on either family, which is what lets one port
/// answer two questions.
pub fn bind_listeners(mut port_seed: impl FnMut() -> u16) -> std::io::Result<InboundListeners> {
    let mut last = std::io::Error::other("no port attempted");
    for _ in 0..32 {
        let port = port_seed();
        // Prefer the dual-stack socket: one port, both families, one answer.
        let mut listeners = match TcpListener::bind((Ipv6Addr::UNSPECIFIED, port)) {
            Ok(listener) => vec![listener],
            // No IPv6 stack at all. IPv4 alone still answers one family, and
            // the missing one simply goes unclaimed.
            Err(error) => match TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)) {
                Ok(listener) => {
                    listener.set_nonblocking(true)?;
                    return Ok(InboundListeners {
                        port,
                        listeners: vec![listener],
                    });
                }
                Err(_) => {
                    last = error;
                    continue;
                }
            },
        };
        // A refused IPv4 bind on the same port means the IPv6 socket is
        // already dual-stack and covers it; a successful one means this OS
        // keeps the families apart and both sockets are needed.
        if let Ok(v4) = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)) {
            listeners.push(v4);
        }
        for listener in &listeners {
            listener.set_nonblocking(true)?;
        }
        return Ok(InboundListeners { port, listeners });
    }
    Err(last)
}

impl InboundListeners {
    /// Answer inbound connections until `deadline`, or until `budget` of them
    /// have been served. Returns how many were answered.
    ///
    /// Runs on the calling thread and blocks; callers give it threads of its
    /// own so the prober's requests can be in flight at the same time.
    pub fn serve(&self, signer: &dyn FactSigner, deadline: Instant, budget: usize) -> usize {
        let stop = AtomicBool::new(false);
        let mut served = 0;
        std::thread::scope(|scope| {
            let mut handles = vec![];
            for listener in &self.listeners {
                let stop = &stop;
                handles.push(scope.spawn(move || {
                    let mut answered = 0;
                    while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                if answer(stream, signer, deadline) {
                                    answered += 1;
                                }
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(10));
                            }
                            Err(_) => break,
                        }
                    }
                    answered
                }));
            }
            // One thread per listener, and both stop at the same deadline; the
            // budget is shared, so a dual-stack socket serving both families
            // and two separate sockets serving one each behave alike.
            for handle in handles {
                served += handle.join().unwrap_or(0);
                if served >= budget {
                    stop.store(true, Ordering::Relaxed);
                }
            }
        });
        served
    }
}

/// Read the prober's nonce and write this processor's signature over it.
/// The peer's address is never read: only the prober knows which address it
/// dialled, and only the prober's signed verdict may say so.
fn answer(mut stream: TcpStream, signer: &dyn FactSigner, deadline: Instant) -> bool {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero()
        || stream.set_read_timeout(Some(remaining)).is_err()
        || stream.set_write_timeout(Some(remaining)).is_err()
        || stream.set_nodelay(true).is_err()
    {
        return false;
    }
    let mut nonce = [0u8; INBOUND_NONCE_BYTES];
    if stream.read_exact(&mut nonce).is_err() {
        return false;
    }
    let Some(signature) = signer.sign_ed25519(&nonce) else {
        return false;
    };
    let mut bytes = [0u8; INBOUND_SIGNATURE_BYTES];
    if hex::decode_to_slice(
        signature.strip_prefix("0x").unwrap_or(&signature),
        &mut bytes,
    )
    .is_err()
    {
        return false;
    }
    stream.write_all(&bytes).is_ok() && stream.flush().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct TestSigner {
        nonces: Mutex<Vec<Vec<u8>>>,
        signature: Option<String>,
    }
    impl TestSigner {
        fn signing() -> Self {
            Self {
                nonces: Mutex::new(vec![]),
                signature: Some(format!("0x{}", "2b".repeat(INBOUND_SIGNATURE_BYTES))),
            }
        }
        fn refusing() -> Self {
            Self {
                nonces: Mutex::new(vec![]),
                signature: None,
            }
        }
    }
    impl FactSigner for TestSigner {
        fn sign_ed25519(&self, message: &[u8]) -> Option<String> {
            self.nonces.lock().unwrap().push(message.to_vec());
            self.signature.clone()
        }
    }

    /// Stand in for the prober: dial the port the device opened, write a
    /// nonce, read back whatever the device says.
    fn dial(port: u16, nonce: &[u8]) -> Option<Vec<u8>> {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
        stream.write_all(nonce).ok()?;
        stream.flush().ok()?;
        let mut reply = vec![];
        stream.read_to_end(&mut reply).ok()?;
        Some(reply)
    }

    fn listeners() -> InboundListeners {
        let mut attempt = 0u16;
        bind_listeners(|| {
            attempt = attempt.wrapping_add(1);
            INBOUND_PORT_MIN + (attempt % 4096) * 7
        })
        .expect("a port in the admitted range")
    }

    #[test]
    fn the_port_is_in_the_admitted_range_and_closes_with_the_check() {
        let listeners = listeners();
        let port = listeners.port;
        assert!((INBOUND_PORT_MIN..=INBOUND_PORT_MAX).contains(&port));
        drop(listeners);
        // Nothing survives the probe: the next bind on that port succeeds.
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
    }

    #[test]
    fn the_nonce_that_arrived_inbound_is_the_nonce_that_is_signed() {
        let listeners = listeners();
        let port = listeners.port;
        let signer = TestSigner::signing();
        let nonce = vec![0x5au8; INBOUND_NONCE_BYTES];
        let probe = {
            let nonce = nonce.clone();
            std::thread::spawn(move || dial(port, &nonce))
        };
        let served = listeners.serve(&signer, Instant::now() + Duration::from_secs(3), 1);
        let reply = probe.join().unwrap().expect("the prober reached the port");

        assert_eq!(served, 1);
        assert_eq!(reply, vec![0x2bu8; INBOUND_SIGNATURE_BYTES]);
        // The signature covers exactly the bytes that crossed the connection.
        assert_eq!(signer.nonces.lock().unwrap().as_slice(), &[nonce]);
    }

    #[test]
    fn a_refusing_signer_answers_nothing_rather_than_answering_wrongly() {
        let listeners = listeners();
        let port = listeners.port;
        let probe = std::thread::spawn(move || dial(port, &[0x5au8; INBOUND_NONCE_BYTES]));
        let served = listeners.serve(
            &TestSigner::refusing(),
            Instant::now() + Duration::from_secs(2),
            1,
        );
        assert_eq!(served, 0);
        // The prober sees a connected socket that says nothing, which is
        // exactly the no_signature verdict and not a forged reachable one.
        assert_eq!(probe.join().unwrap(), Some(vec![]));
    }

    #[test]
    fn nobody_dialing_costs_only_the_deadline() {
        let started = Instant::now();
        let served = listeners().serve(
            &TestSigner::signing(),
            started + Duration::from_millis(300),
            2,
        );
        assert_eq!(served, 0);
        // A firewalled processor is the normal case: it must fail fast, and
        // never wait past the deadline it was given.
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_truncated_nonce_is_not_signed() {
        let listeners = listeners();
        let port = listeners.port;
        let signer = TestSigner::signing();
        let probe = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            stream.write_all(&[0u8; 8]).unwrap();
            stream.flush().unwrap();
            drop(stream);
        });
        let served = listeners.serve(&signer, Instant::now() + Duration::from_secs(1), 1);
        probe.join().unwrap();
        assert_eq!(served, 0);
        assert!(signer.nonces.lock().unwrap().is_empty());
    }
}
