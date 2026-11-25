//! Loopback-only, one-collector fact-probe protocol for ADR-0234 fixtures.

mod channel;
mod mapping;
mod request;
mod socket;
mod udp;

use std::time::{Duration, Instant};

use serde::Serialize;
use zeroize::Zeroizing;

use crate::processor_facts::FactSigner;
use crate::state_snapshot::{SeedSigner, StateSigner};

use super::*;
use channel::{Channel, Signal, cancelled};
use request::{Collector, Request};
use socket::{Ledger, SocketUse};
use udp::UdpAdapter;

#[derive(Clone, Copy)]
enum Refusal {
    InvalidRequest,
    InvalidGrant,
    InvalidEndpoint,
    Cancelled,
    ChannelUnavailable,
}

impl Refusal {
    fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidGrant => "invalid_grant",
            Self::InvalidEndpoint => "invalid_endpoint",
            Self::Cancelled => "cancelled",
            Self::ChannelUnavailable => "channel_unavailable",
        }
    }
}

#[derive(Clone, Copy)]
struct Clock {
    origin_ms: u64,
    started: Instant,
}

impl Clock {
    fn now_ms(self) -> u64 {
        self.origin_ms
            .saturating_add(self.started.elapsed().as_millis() as u64)
    }

    fn deadline(self, ms: u64) -> Instant {
        self.started + Duration::from_millis(ms.saturating_sub(self.origin_ms))
    }
}

struct FixtureSigner(SeedSigner);

impl FixtureSigner {
    fn from_hex(seed: String) -> Result<Self, Refusal> {
        let seed = Zeroizing::new(seed);
        let mut key = Zeroizing::new([0; 32]);
        if !lower_hex(&seed, 32) {
            return Err(Refusal::InvalidGrant);
        }
        hex::decode_to_slice(seed.as_bytes(), key.as_mut()).map_err(|_| Refusal::InvalidGrant)?;
        Ok(Self(SeedSigner::from_seed(&key)))
    }

    fn public_key(&self) -> String {
        format!("0x{}", hex::encode(self.0.public_key()))
    }
}

impl FactSigner for FixtureSigner {
    fn sign_ed25519(&self, message: &[u8]) -> Option<String> {
        self.0
            .sign_ed25519(message)
            .map(|signature| format!("0x{}", hex::encode(signature)))
    }
}

fn random<const N: usize>() -> Result<[u8; N], getrandom::Error> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}

#[derive(Serialize)]
#[serde(untagged)]
enum Outcome {
    Behaviour(UdpBehaviourReport),
    Mapping(MappingRunReport),
    Pair(NetworkTraversalV1),
}

#[derive(Serialize)]
struct Transcript {
    #[serde(rename = "type")]
    kind: &'static str,
    version: u8,
    collector: &'static str,
    result: Option<Outcome>,
    refusal: Option<TraversalRefusal>,
    sockets: Vec<SocketUse>,
}

/// Read and serve one version 2 request on the fact probe's stdio. Successful
/// acceptance produces one transcript even when the collector is cancelled.
pub fn run_external_traversal() -> Result<(), &'static str> {
    run().map_err(Refusal::code)
}

fn run() -> Result<(), Refusal> {
    let _signal = Signal::install().map_err(|_| Refusal::ChannelUnavailable)?;
    let mut channel = Channel::stdio().map_err(|_| Refusal::ChannelUnavailable)?;
    let line = Zeroizing::new(channel.request().map_err(|_| {
        if cancelled() {
            Refusal::Cancelled
        } else {
            Refusal::InvalidRequest
        }
    })?);
    let request = Request::parse(&line)?;
    let clock = Clock {
        origin_ms: request.origin_ms,
        started: Instant::now(),
    };
    let ledger = Ledger::default();
    let (collector, result, refusal) = match request.collector {
        Collector::Behaviour {
            descriptor,
            reservation,
            session,
            topology,
            ingress,
        } => {
            let mut network = UdpAdapter {
                clock,
                ledger: ledger.clone(),
                endpoint: topology.ap.address,
                ingress,
                revision: &topology.revision,
                control: &mut channel,
            };
            let result =
                collect_udp_behaviour(&descriptor, reservation, session, &topology, &mut network);
            ("udp-behaviour", Some(Outcome::Behaviour(result)), None)
        }
        Collector::Mapping {
            capability,
            session,
            signer,
            endpoints,
            plan,
            digest,
        } => {
            let adapter = mapping::Adapter::new(
                clock,
                ledger.clone(),
                &mut channel,
                &capability,
                &signer,
                endpoints,
            );
            match adapter.collect(session, plan, digest) {
                Some(result) => ("mapping", Some(Outcome::Mapping(result)), None),
                None => ("mapping", None, Some(TraversalRefusal::InvalidBinding)),
            }
        }
        Collector::Pair {
            session,
            signer,
            revision,
            coordinator,
            ingress,
        } => {
            let mut network = UdpAdapter {
                clock,
                ledger: ledger.clone(),
                endpoint: coordinator,
                ingress,
                revision: &revision,
                control: &mut channel,
            };
            match session.collect(&mut network, &signer) {
                Ok(result) => ("pair", Some(Outcome::Pair(result)), None),
                Err(refusal) => ("pair", None, Some(refusal)),
            }
        }
    };
    channel
        .transcript(&Transcript {
            kind: "transcript",
            version: 2,
            collector,
            result,
            refusal,
            sockets: ledger.report(),
        })
        .map_err(|_| Refusal::ChannelUnavailable)
}
