use std::net::{Ipv4Addr, SocketAddr};

use serde::Deserialize;

use super::super::*;
use super::{FixtureSigner, Refusal, socket::loopback};

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Scenario {
    ExternalLoopback,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Grant {
    capability: TraversalCapabilityV1,
    artifact_digest: String,
    claim_authority_digest: String,
    job_expires_at_ms: u64,
}

impl Grant {
    fn reserve(&self, origin_ms: u64) -> Result<Reservation, Refusal> {
        if self.claim_authority_digest != self.capability.descriptor.claim_authority_digest
            || bounded(&self.capability, TRAVERSAL_BLOCK_MAX_BYTES).is_err()
        {
            return Err(Refusal::InvalidGrant);
        }
        match reserve_traversal(&ReserveInput {
            grant: Some(&self.capability),
            now_ms: origin_ms,
            job_expires_at_ms: self.job_expires_at_ms,
            artifact_digest: &self.artifact_digest,
            helper: &FIXTURE_HELPER,
            effects: &NopTraversalEffects,
        }) {
            ReserveOutcome::Reserved(value) => Ok(value),
            _ => Err(Refusal::InvalidGrant),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Endpoint {
    address: SocketAddr,
    mapping_qualified: bool,
    filtering_qualified: bool,
}

impl From<Endpoint> for BehaviourEndpoint {
    fn from(value: Endpoint) -> Self {
        Self {
            address: value.address,
            mapping_qualified: value.mapping_qualified,
            filtering_qualified: value.filtering_qualified,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BehaviourEndpoints {
    revision: String,
    ap: Endpoint,
    aq: Option<Endpoint>,
    bp: Option<Endpoint>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairEndpoints {
    coordinator: SocketAddr,
    revision: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct MappingEndpoints {
    pub router: SocketAddr,
    pub path_source: Ipv4Addr,
    pub observed_address: Ipv4Addr,
    pub external_address: Option<Ipv4Addr>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Consent {
    consent_reference: String,
    processor_allowlist_digest: String,
    exclusive_reservation_digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Method {
    Pcp,
    NatPmp,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Transport {
    Udp,
}

#[derive(Deserialize)]
#[serde(
    tag = "collector",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum Wire {
    UdpBehaviour {
        version: u8,
        scenario: Scenario,
        origin_ms: u64,
        grant: Grant,
        session: String,
        endpoints: BehaviourEndpoints,
        nat_ingress: Option<SocketAddr>,
    },
    Pair {
        version: u8,
        scenario: Scenario,
        origin_ms: u64,
        grant: Grant,
        signer_seed: String,
        endpoints: PairEndpoints,
        nat_ingress: Option<SocketAddr>,
    },
    Mapping {
        version: u8,
        scenario: Scenario,
        origin_ms: u64,
        grant: Grant,
        signer_seed: String,
        endpoints: MappingEndpoints,
        consent: Consent,
        method: Method,
        transport: Transport,
    },
}

pub(super) struct Request {
    pub origin_ms: u64,
    pub collector: Collector,
}

pub(super) enum Collector {
    Behaviour {
        descriptor: TraversalDescriptorV1,
        reservation: Reservation,
        session: BehaviourSession,
        topology: BehaviourTopology,
        ingress: Option<SocketAddr>,
    },
    Pair {
        session: PairSession,
        signer: FixtureSigner,
        revision: String,
        coordinator: SocketAddr,
        ingress: Option<SocketAddr>,
    },
    Mapping {
        capability: String,
        session: MappingSession,
        signer: FixtureSigner,
        endpoints: MappingEndpoints,
        plan: MappingMethodPlan,
        digest: [u8; 32],
    },
}

fn framed(
    ingress: Option<SocketAddr>,
    base: SocketAddr,
    others: impl Iterator<Item = SocketAddr>,
) -> Result<(), Refusal> {
    if ingress.is_some_and(|addr| !loopback(addr) || addr.is_ipv4() != base.is_ipv4())
        || std::iter::once(base)
            .chain(others)
            .any(|addr| !loopback(addr) || addr.is_ipv4() != base.is_ipv4())
    {
        return Err(Refusal::InvalidEndpoint);
    }
    Ok(())
}

impl Request {
    pub(super) fn parse(line: &[u8]) -> Result<Self, Refusal> {
        if line.len() > super::channel::MAX_LINE {
            return Err(Refusal::InvalidRequest);
        }
        let wire: Wire = serde_json::from_slice(line).map_err(|_| Refusal::InvalidRequest)?;
        let (version, _scenario) = match &wire {
            Wire::UdpBehaviour {
                version, scenario, ..
            }
            | Wire::Pair {
                version, scenario, ..
            }
            | Wire::Mapping {
                version, scenario, ..
            } => (*version, scenario),
        };
        if version != 2 {
            return Err(Refusal::InvalidRequest);
        }
        let (origin_ms, collector) = match wire {
            Wire::UdpBehaviour {
                origin_ms,
                grant,
                session,
                endpoints,
                nat_ingress,
                ..
            } => {
                framed(
                    nat_ingress,
                    endpoints.ap.address,
                    endpoints.aq.iter().chain(&endpoints.bp).map(|e| e.address),
                )?;
                if endpoints.revision != grant.capability.descriptor.endpoint_set_revision
                    || grant.capability.descriptor.mode != TraversalMode::Observe
                {
                    return Err(Refusal::InvalidGrant);
                }
                let reservation = grant.reserve(origin_ms)?;
                let descriptor = grant.capability.descriptor;
                let session =
                    BehaviourSession::from_authenticated_enrollment(&session, &descriptor)
                        .ok_or(Refusal::InvalidGrant)?;
                let topology = BehaviourTopology {
                    revision: endpoints.revision,
                    ap: endpoints.ap.into(),
                    aq: endpoints.aq.map(Into::into),
                    bp: endpoints.bp.map(Into::into),
                };
                (
                    origin_ms,
                    Collector::Behaviour {
                        descriptor,
                        reservation,
                        session,
                        topology,
                        ingress: nat_ingress,
                    },
                )
            }
            Wire::Pair {
                origin_ms,
                grant,
                signer_seed,
                endpoints,
                nat_ingress,
                ..
            } => {
                framed(nat_ingress, endpoints.coordinator, std::iter::empty())?;
                if endpoints.revision != grant.capability.descriptor.endpoint_set_revision
                    || bounded(&grant.capability, TRAVERSAL_BLOCK_MAX_BYTES).is_err()
                {
                    return Err(Refusal::InvalidGrant);
                }
                let signer = FixtureSigner::from_hex(signer_seed)?;
                let session = PairSession::from_authenticated_bootstrap(
                    grant.capability,
                    PairBindings {
                        claim_authority_digest: &grant.claim_authority_digest,
                        artifact_digest: &grant.artifact_digest,
                        helper: &FIXTURE_HELPER,
                        runtime_signer: &signer.public_key(),
                    },
                    origin_ms,
                    grant.job_expires_at_ms,
                )
                .map_err(|_| Refusal::InvalidGrant)?;
                (
                    origin_ms,
                    Collector::Pair {
                        session,
                        signer,
                        revision: endpoints.revision,
                        coordinator: endpoints.coordinator,
                        ingress: nat_ingress,
                    },
                )
            }
            Wire::Mapping {
                origin_ms,
                grant,
                signer_seed,
                endpoints,
                consent,
                method,
                transport: Transport::Udp,
                ..
            } => {
                if !loopback(endpoints.router)
                    || !endpoints.path_source.is_loopback()
                    || !endpoints.observed_address.is_loopback()
                    || endpoints
                        .external_address
                        .is_some_and(|ip| !ip.is_loopback())
                {
                    return Err(Refusal::InvalidEndpoint);
                }
                grant.reserve(origin_ms)?;
                let signer = FixtureSigner::from_hex(signer_seed)?;
                let capability = String::from_utf8(
                    canonical(&grant.capability).map_err(|_| Refusal::InvalidGrant)?,
                )
                .map_err(|_| Refusal::InvalidGrant)?;
                let session = MappingSession::from_authenticated_bootstrap(
                    grant.capability.descriptor,
                    MappingBindings {
                        claim_authority_digest: &grant.claim_authority_digest,
                        artifact_digest: &grant.artifact_digest,
                        helper: &FIXTURE_HELPER,
                        consent_reference: &consent.consent_reference,
                        processor_allowlist_digest: &consent.processor_allowlist_digest,
                        exclusive_reservation_digest: &consent.exclusive_reservation_digest,
                    },
                    origin_ms,
                    grant.job_expires_at_ms,
                )
                .map_err(|_| Refusal::InvalidGrant)?;
                let mut digest = [0; 32];
                let hex = consent
                    .exclusive_reservation_digest
                    .strip_prefix("sha256:")
                    .ok_or(Refusal::InvalidGrant)?;
                hex::decode_to_slice(hex, &mut digest).map_err(|_| Refusal::InvalidGrant)?;
                if digest == [0; 32] {
                    return Err(Refusal::InvalidGrant);
                }
                let plan = MappingMethodPlan {
                    protocol: match method {
                        Method::Pcp => RouterProtocol::Pcp,
                        Method::NatPmp => RouterProtocol::NatPmp,
                    },
                    transport: MappedPortProtocol::Udp,
                };
                (
                    origin_ms,
                    Collector::Mapping {
                        capability,
                        session,
                        signer,
                        endpoints,
                        plan,
                        digest,
                    },
                )
            }
        };
        Ok(Self {
            origin_ms,
            collector,
        })
    }
}
