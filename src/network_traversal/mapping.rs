//! Finite PCP (RFC 6887), NAT-PMP (RFC 6886), and UPnP IGD MAP codecs.
//!
//! PCP and NAT-PMP speak through [`exchange_with_gateway`]. UPnP speaks SOAP
//! through [`exchange_upnp_soap`](super::gateway::exchange_upnp_soap) and does
//! not rediscover the gateway. There is no scheduler and no lease renewal. A
//! create always asks for 60 seconds. A granted lifetime of zero, or one past
//! the caller's ceiling (at most 120 seconds), is refused. Nothing retries
//! that refusal with lifetime zero or with a longer lease.
//!
//! NAT-PMP will refresh a mapping it did not create. No NAT-PMP packet is sent
//! unless the caller holds an [`ExclusiveReservation`] for this gateway.
//! A PCP nonce correlates a response; it does not by itself authorize deleting
//! a static or pre-existing mapping. Deletes of a grant this adapter did not
//! adopt as a finite lease require that reservation, and a nonce or tuple that
//! does not match the outstanding request is never deleted.

use std::net::Ipv4Addr;

use super::{
    ControlRefusal, ControlTransport, RouterProtocol, SelectedGateway, TraversalCleanup,
    TraversalErrorClass, TraversalOutcome, exchange_with_gateway,
};

mod upnp;

pub use upnp::{UpnpMap, map_upnp};

pub const MAPPING_REQUESTED_LEASE_SEC: u32 = 60;
pub const MAPPING_MAXIMUM_LEASE_SEC: u32 = 120;
/// Cargo cannot bind below 1024, so a listener under that is not an owned high port.
pub const MAPPING_HIGH_PORT_MIN: u16 = 1024;
pub const PCP_MAP_PACKET_BYTES: usize = 60;
pub const NATPMP_MAP_REQUEST_BYTES: usize = 12;
pub const NATPMP_MAP_RESPONSE_BYTES: usize = 16;

const PCP_VERSION: u8 = 2;
const PCP_MAP_OPCODE: u8 = 1;
const PCP_RESPONSE_BIT: u8 = 0x80;
const NATPMP_VERSION: u8 = 0;
const NATPMP_UDP: u8 = 1;
const NATPMP_TCP: u8 = 2;
const NATPMP_RESPONSE_BIT: u8 = 0x80;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappedPortProtocol {
    Tcp,
    Udp,
}

impl MappedPortProtocol {
    fn pcp(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }

    fn natpmp(self) -> u8 {
        match self {
            Self::Tcp => NATPMP_TCP,
            Self::Udp => NATPMP_UDP,
        }
    }

    fn from_natpmp(value: u8) -> Option<Self> {
        match value {
            NATPMP_TCP => Some(Self::Tcp),
            NATPMP_UDP => Some(Self::Udp),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingRefusal {
    LowPort,
    BadClientAddress,
    BadLifetimeCeiling,
    TrivialNonce,
    MissingReservation,
    ReservationGatewayMismatch,
    AmbiguousOwnership,
    Denied,
    ProtocolUnsupported,
    Conflict,
    Rebooted,
    Truncated,
    ReplayOrMismatch,
    OverlongOrZeroGrant,
    LostResponse,
    Cancelled,
    Malformed,
}

/// In-memory cleanup key. Addresses and the PCP nonce are not debug output.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OwnedMappingHandle {
    protocol: RouterProtocol,
    port_protocol: MappedPortProtocol,
    internal_port: u16,
    external_port: u16,
    /// PCP MAP deletes must repeat the client address. It stays off the debug output.
    client: Ipv4Addr,
    granted_lifetime_sec: u32,
    epoch: u32,
    nonce: Option<[u8; 12]>,
    reservation_digest: Option<[u8; 32]>,
    cleanup_authorized: bool,
    external_address: Option<Ipv4Addr>,
}

impl std::fmt::Debug for OwnedMappingHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnedMappingHandle")
            .field("protocol", &self.protocol)
            .field("port_protocol", &self.port_protocol)
            .field("internal_port", &self.internal_port)
            .field("external_port", &self.external_port)
            .field("client", &"<redacted>")
            .field("external_address", &"<redacted>")
            .field("granted_lifetime_sec", &self.granted_lifetime_sec)
            .field("epoch", &self.epoch)
            .field("cleanup_authorized", &self.cleanup_authorized)
            .field("nonce", &self.nonce.map(|_| "<redacted>"))
            .field(
                "reservation_digest",
                &self.reservation_digest.map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl OwnedMappingHandle {
    /// Transient router response, never a verifier destination or a log field.
    pub fn external_address(self) -> Option<Ipv4Addr> {
        self.external_address
    }
    pub fn protocol(self) -> RouterProtocol {
        self.protocol
    }

    pub fn port_protocol(self) -> MappedPortProtocol {
        self.port_protocol
    }

    pub fn internal_port(self) -> u16 {
        self.internal_port
    }

    pub fn external_port(self) -> u16 {
        self.external_port
    }

    pub fn granted_lifetime_sec(self) -> u32 {
        self.granted_lifetime_sec
    }

    pub fn epoch(self) -> u32 {
        self.epoch
    }

    pub fn cleanup_authorized(self) -> bool {
        self.cleanup_authorized
    }

    #[cfg(test)]
    fn nonce(self) -> Option<[u8; 12]> {
        self.nonce
    }
}

/// Proof that this gateway's external endpoint was reserved for this experiment.
/// A NAT-PMP mapping may already exist; without this proof the adapter sends nothing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExclusiveReservation {
    gateway: Ipv4Addr,
    digest: [u8; 32],
}

impl std::fmt::Debug for ExclusiveReservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExclusiveReservation")
            .field("gateway", &"<redacted>")
            .field("digest", &"<redacted>")
            .finish()
    }
}

impl ExclusiveReservation {
    pub(crate) fn matches_binding(self, gateway: &SelectedGateway, digest: &str) -> bool {
        self.authorizes(gateway) && digest == format!("sha256:{}", hex::encode(self.digest))
    }
    pub fn new(gateway: Ipv4Addr, digest: [u8; 32]) -> Option<Self> {
        if !usable_ipv4(gateway) || digest == [0; 32] {
            return None;
        }
        Some(Self { gateway, digest })
    }

    fn authorizes(self, gateway: &SelectedGateway) -> bool {
        self.gateway == gateway.gateway()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappingEffect {
    pub protocol: RouterProtocol,
    pub outcome: TraversalOutcome,
    pub cleanup: TraversalCleanup,
    pub error: Option<TraversalErrorClass>,
    pub refusal: Option<MappingRefusal>,
    pub handle: Option<OwnedMappingHandle>,
    pub granted_lifetime_sec: Option<u32>,
    pub epoch: Option<u32>,
    pub assigned_port: Option<u16>,
    pub port_changed: bool,
    pub lease_clamped: bool,
    pub gateway_rebooted: bool,
    pub requests_sent: u8,
}

pub struct PcpMap<'a> {
    pub local_address: Ipv4Addr,
    pub internal_port: u16,
    pub protocol: MappedPortProtocol,
    pub nonce: [u8; 12],
    pub maximum_lease_sec: u16,
    pub previous_epoch: Option<u32>,
    pub exclusive_reservation: Option<&'a ExclusiveReservation>,
}

pub struct NatPmpMap<'a> {
    pub internal_port: u16,
    pub protocol: MappedPortProtocol,
    pub maximum_lease_sec: u16,
    pub previous_epoch: Option<u32>,
    pub exclusive_reservation: Option<&'a ExclusiveReservation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DecodeFault {
    Truncated,
    Oversize,
    Malformed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServerClass {
    Success,
    Denied,
    Unsupported,
    Conflict,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Parsed {
    version_ok: bool,
    opcode_ok: bool,
    result: u16,
    lifetime: u32,
    epoch: u32,
    protocol: u8,
    internal_port: u16,
    assigned_port: u16,
    nonce: Option<[u8; 12]>,
    assigned_ip: Option<Ipv4Addr>,
}

pub fn map_pcp(
    gateway: &SelectedGateway,
    input: &PcpMap<'_>,
    transport: &mut dyn ControlTransport,
    cancelled: &dyn Fn() -> bool,
) -> MappingEffect {
    let Some(ceiling) = lease_ceiling(input.maximum_lease_sec) else {
        return local_refusal(RouterProtocol::Pcp, MappingRefusal::BadLifetimeCeiling);
    };
    if input.internal_port < MAPPING_HIGH_PORT_MIN {
        return local_refusal(RouterProtocol::Pcp, MappingRefusal::LowPort);
    }
    if !usable_ipv4(input.local_address) {
        return local_refusal(RouterProtocol::Pcp, MappingRefusal::BadClientAddress);
    }
    if input.nonce == [0; 12] {
        return local_refusal(RouterProtocol::Pcp, MappingRefusal::TrivialNonce);
    }
    let request = encode_pcp(
        input.local_address,
        input.protocol.pcp(),
        input.internal_port,
        input.internal_port,
        input.nonce,
        MAPPING_REQUESTED_LEASE_SEC,
    );
    let reservation_ok = input
        .exclusive_reservation
        .is_some_and(|reservation| reservation.authorizes(gateway));
    let digest = input
        .exclusive_reservation
        .filter(|reservation| reservation.authorizes(gateway))
        .map(|reservation| reservation.digest);
    exchange_create(
        MapParts {
            protocol: RouterProtocol::Pcp,
            port_protocol: input.protocol,
            internal_port: input.internal_port,
            client: input.local_address,
            previous_epoch: input.previous_epoch,
            ceiling,
            reservation_authorizes_delete: reservation_ok,
            nonce: Some(input.nonce),
            digest,
        },
        gateway,
        &request,
        transport,
        cancelled,
        |body| {
            decode_pcp(body).map(|parsed| {
                let matches = parsed.nonce == Some(input.nonce)
                    && parsed.protocol == input.protocol.pcp()
                    && parsed.internal_port == input.internal_port;
                (parsed, matches)
            })
        },
        |parsed| pcp_class(parsed.result),
    )
}

pub fn map_nat_pmp(
    gateway: &SelectedGateway,
    input: &NatPmpMap<'_>,
    transport: &mut dyn ControlTransport,
    cancelled: &dyn Fn() -> bool,
) -> MappingEffect {
    let Some(ceiling) = lease_ceiling(input.maximum_lease_sec) else {
        return local_refusal(RouterProtocol::NatPmp, MappingRefusal::BadLifetimeCeiling);
    };
    if input.internal_port < MAPPING_HIGH_PORT_MIN {
        return local_refusal(RouterProtocol::NatPmp, MappingRefusal::LowPort);
    }
    let Some(reservation) = input.exclusive_reservation else {
        return local_refusal(RouterProtocol::NatPmp, MappingRefusal::MissingReservation);
    };
    if !reservation.authorizes(gateway) {
        return local_refusal(
            RouterProtocol::NatPmp,
            MappingRefusal::ReservationGatewayMismatch,
        );
    }
    let request = encode_natpmp(
        input.protocol.natpmp(),
        input.internal_port,
        input.internal_port,
        MAPPING_REQUESTED_LEASE_SEC,
    );
    let opcode = input.protocol.natpmp();
    let digest = reservation.digest;
    exchange_create(
        MapParts {
            protocol: RouterProtocol::NatPmp,
            port_protocol: input.protocol,
            internal_port: input.internal_port,
            client: Ipv4Addr::UNSPECIFIED,
            previous_epoch: input.previous_epoch,
            ceiling,
            reservation_authorizes_delete: true,
            nonce: None,
            digest: Some(digest),
        },
        gateway,
        &request,
        transport,
        cancelled,
        |body| {
            decode_natpmp(body).map(|parsed| {
                let matches =
                    parsed.protocol == opcode && parsed.internal_port == input.internal_port;
                (parsed, matches)
            })
        },
        |parsed| natpmp_class(parsed.result),
    )
}

pub fn delete_owned_mapping(
    gateway: &SelectedGateway,
    handle: &OwnedMappingHandle,
    reservation: Option<&ExclusiveReservation>,
    previous_epoch: Option<u32>,
    transport: &mut dyn ControlTransport,
    cancelled: &dyn Fn() -> bool,
    control: Option<&super::IgdControlDescriptor>,
) -> MappingEffect {
    if !delete_allowed(handle, gateway, reservation) {
        let mut effect = blank(handle.protocol);
        effect.outcome = TraversalOutcome::UnsupportedSafeOwnership;
        effect.cleanup = TraversalCleanup::ExpiryUnknown;
        effect.refusal = Some(MappingRefusal::AmbiguousOwnership);
        effect.handle = Some(*handle);
        return effect;
    }
    if handle.protocol == RouterProtocol::UpnpIgd {
        return upnp::delete_owned(gateway, handle, control, transport, cancelled);
    }
    let request = delete_packet(handle);
    send_delete(
        handle,
        gateway,
        &request,
        previous_epoch,
        transport,
        cancelled,
        0,
    )
}

fn delete_allowed(
    handle: &OwnedMappingHandle,
    gateway: &SelectedGateway,
    reservation: Option<&ExclusiveReservation>,
) -> bool {
    if !handle.cleanup_authorized {
        return false;
    }
    match (handle.protocol, handle.reservation_digest) {
        (RouterProtocol::NatPmp, Some(digest))
        | (RouterProtocol::Pcp, Some(digest))
        | (RouterProtocol::UpnpIgd, Some(digest)) => reservation.is_some_and(|reservation| {
            reservation.authorizes(gateway) && reservation.digest == digest
        }),
        (RouterProtocol::Pcp, None) => true,
        _ => false,
    }
}

#[derive(Clone, Copy)]
struct MapParts {
    protocol: RouterProtocol,
    port_protocol: MappedPortProtocol,
    internal_port: u16,
    client: Ipv4Addr,
    previous_epoch: Option<u32>,
    ceiling: u32,
    reservation_authorizes_delete: bool,
    nonce: Option<[u8; 12]>,
    digest: Option<[u8; 32]>,
}

fn exchange_create<F, C>(
    parts: MapParts,
    gateway: &SelectedGateway,
    request: &[u8],
    transport: &mut dyn ControlTransport,
    cancelled: &dyn Fn() -> bool,
    decode: F,
    class: C,
) -> MappingEffect
where
    F: FnOnce(&[u8]) -> Result<(Parsed, bool), DecodeFault>,
    C: FnOnce(&Parsed) -> ServerClass,
{
    if cancelled() {
        return local_refusal(parts.protocol, MappingRefusal::Cancelled);
    }
    let body =
        match exchange_with_gateway(gateway, parts.protocol, None, request, transport, cancelled) {
            Ok(body) => body,
            Err(error) => {
                return lost(
                    parts.protocol,
                    1,
                    transport_refusal(error),
                    transport_error(error),
                );
            }
        };
    let (parsed, matches) = match decode(&body) {
        Ok(parsed) => parsed,
        Err(DecodeFault::Truncated) => {
            return lost(
                parts.protocol,
                1,
                MappingRefusal::Truncated,
                TraversalErrorClass::InvalidResponse,
            );
        }
        Err(DecodeFault::Oversize | DecodeFault::Malformed) => {
            return lost(
                parts.protocol,
                1,
                MappingRefusal::Malformed,
                TraversalErrorClass::InvalidResponse,
            );
        }
    };
    if !matches {
        return lost(
            parts.protocol,
            1,
            MappingRefusal::ReplayOrMismatch,
            TraversalErrorClass::InvalidResponse,
        );
    }
    let mut effect = blank(parts.protocol);
    effect.requests_sent = 1;
    effect.epoch = Some(parsed.epoch);
    effect.granted_lifetime_sec = Some(parsed.lifetime);
    effect.assigned_port = Some(parsed.assigned_port);
    // Classify the result before the epoch. An explicit error did not create a
    // mapping, even when the gateway epoch moved. A finite success after an
    // epoch drop is not adopted. An overlong grant still reaches adopt_or_refuse
    // so an exclusive reservation can delete it.
    let gateway_rebooted = rebooted(parts.previous_epoch, parsed.epoch);
    if !parsed.version_ok || !parsed.opcode_ok {
        effect.refusal = Some(MappingRefusal::ProtocolUnsupported);
        effect.error = Some(TraversalErrorClass::InvalidResponse);
        if parsed.result == 0 {
            effect.outcome = TraversalOutcome::CreationOutcomeUnknown;
            effect.cleanup = TraversalCleanup::ExpiryUnknown;
        } else {
            effect.outcome = TraversalOutcome::Failed;
            effect.cleanup = TraversalCleanup::NotCreated;
        }
        effect.gateway_rebooted = gateway_rebooted;
        return effect;
    }
    match class(&parsed) {
        ServerClass::Denied => {
            let mut effect = explicit(
                effect,
                MappingRefusal::Denied,
                TraversalErrorClass::TokenRefused,
            );
            effect.gateway_rebooted = gateway_rebooted;
            effect
        }
        ServerClass::Unsupported => {
            let mut effect = explicit(
                effect,
                MappingRefusal::ProtocolUnsupported,
                TraversalErrorClass::InvalidResponse,
            );
            effect.gateway_rebooted = gateway_rebooted;
            effect
        }
        ServerClass::Conflict => {
            let mut effect = explicit(
                effect,
                MappingRefusal::Conflict,
                TraversalErrorClass::MappingConflict,
            );
            effect.gateway_rebooted = gateway_rebooted;
            effect
        }
        ServerClass::Failed => {
            let mut effect = explicit(
                effect,
                MappingRefusal::Denied,
                TraversalErrorClass::InvalidResponse,
            );
            effect.gateway_rebooted = gateway_rebooted;
            effect
        }
        ServerClass::Success => {
            let finite = (1..=parts.ceiling).contains(&parsed.lifetime);
            if gateway_rebooted && finite && parsed.assigned_port != 0 {
                effect.gateway_rebooted = true;
                effect.outcome = TraversalOutcome::ExpiryUnknown;
                effect.cleanup = TraversalCleanup::ExpiryUnknown;
                effect.refusal = Some(MappingRefusal::Rebooted);
                effect.handle = Some(correlated_handle(
                    parts,
                    parsed.assigned_port,
                    parsed.lifetime,
                    parsed.epoch,
                    false,
                ));
                return effect;
            }
            let mut effect = adopt_or_refuse(effect, parts, parsed, gateway, transport, cancelled);
            // A delete of an overlong grant can observe a reboot the create
            // reply did not. Keep that observation.
            effect.gateway_rebooted |= gateway_rebooted;
            effect
        }
    }
}

fn adopt_or_refuse(
    mut effect: MappingEffect,
    parts: MapParts,
    parsed: Parsed,
    gateway: &SelectedGateway,
    transport: &mut dyn ControlTransport,
    cancelled: &dyn Fn() -> bool,
) -> MappingEffect {
    if parsed.assigned_ip.is_none() && parts.protocol == RouterProtocol::Pcp {
        effect.outcome = TraversalOutcome::CreationOutcomeUnknown;
        effect.cleanup = TraversalCleanup::ExpiryUnknown;
        effect.refusal = Some(MappingRefusal::Malformed);
        effect.error = Some(TraversalErrorClass::InvalidResponse);
        return effect;
    }
    let finite = (1..=parts.ceiling).contains(&parsed.lifetime);
    // A success code with a finite lifetime and external port 0 contradicts itself.
    if parsed.assigned_port == 0 && finite {
        effect.outcome = TraversalOutcome::CreationOutcomeUnknown;
        effect.cleanup = TraversalCleanup::ExpiryUnknown;
        effect.refusal = Some(MappingRefusal::Malformed);
        effect.error = Some(TraversalErrorClass::InvalidResponse);
        effect.handle = None;
        return effect;
    }
    if !finite {
        let authorized = parts.reservation_authorizes_delete;
        let handle = correlated_handle(
            parts,
            parsed.assigned_port,
            parsed.lifetime,
            parsed.epoch,
            authorized,
        );
        effect.handle = Some(handle);
        effect.refusal = Some(MappingRefusal::OverlongOrZeroGrant);
        effect.error = Some(TraversalErrorClass::LeaseRefused);
        effect.outcome = TraversalOutcome::UnsupportedFiniteLease;
        if !authorized {
            effect.outcome = TraversalOutcome::UnsupportedSafeOwnership;
            effect.cleanup = TraversalCleanup::ExpiryUnknown;
            effect.refusal = Some(MappingRefusal::AmbiguousOwnership);
            effect.error = Some(TraversalErrorClass::LeaseRefused);
            return effect;
        }
        let delete_request = delete_packet(&handle);
        return send_delete(
            &handle,
            gateway,
            &delete_request,
            Some(parsed.epoch),
            transport,
            cancelled,
            effect.requests_sent,
        );
    }
    let mut handle = correlated_handle(
        parts,
        parsed.assigned_port,
        parsed.lifetime,
        parsed.epoch,
        true,
    );
    handle.external_address = parsed.assigned_ip;
    effect.outcome = TraversalOutcome::Succeeded;
    effect.cleanup = TraversalCleanup::LeaseExpiryPending;
    effect.refusal = None;
    effect.error = None;
    effect.handle = Some(handle);
    effect.port_changed = parsed.assigned_port != parts.internal_port;
    effect.lease_clamped = parsed.lifetime < MAPPING_REQUESTED_LEASE_SEC;
    effect
}

fn send_delete(
    handle: &OwnedMappingHandle,
    gateway: &SelectedGateway,
    request: &[u8],
    previous_epoch: Option<u32>,
    transport: &mut dyn ControlTransport,
    cancelled: &dyn Fn() -> bool,
    already_sent: u8,
) -> MappingEffect {
    let mut effect = blank(handle.protocol);
    effect.handle = Some(*handle);
    effect.requests_sent = already_sent;
    effect.granted_lifetime_sec = Some(handle.granted_lifetime_sec);
    effect.assigned_port = Some(handle.external_port);
    effect.epoch = Some(handle.epoch);
    if handle.granted_lifetime_sec == 0 || handle.granted_lifetime_sec > MAPPING_MAXIMUM_LEASE_SEC {
        effect.outcome = TraversalOutcome::UnsupportedFiniteLease;
        effect.refusal = Some(MappingRefusal::OverlongOrZeroGrant);
        effect.error = Some(TraversalErrorClass::LeaseRefused);
    }
    if cancelled() {
        let finite_lease = (1..=MAPPING_MAXIMUM_LEASE_SEC).contains(&handle.granted_lifetime_sec);
        // No delete was sent. A known finite grant is still waiting to expire.
        if already_sent == 0 && finite_lease {
            effect.outcome = TraversalOutcome::Failed;
            effect.cleanup = TraversalCleanup::LeaseExpiryPending;
        } else {
            effect.outcome = TraversalOutcome::ExpiryUnknown;
            effect.cleanup = TraversalCleanup::ExpiryUnknown;
        }
        effect.refusal = Some(MappingRefusal::Cancelled);
        return effect;
    }
    let body = match exchange_with_gateway(
        gateway,
        handle.protocol,
        None,
        request,
        transport,
        cancelled,
    ) {
        Ok(body) => body,
        Err(error) => {
            effect.outcome = TraversalOutcome::ExpiryUnknown;
            effect.cleanup = TraversalCleanup::ExpiryUnknown;
            effect.refusal = Some(transport_refusal(error));
            effect.error = Some(TraversalErrorClass::CleanupFailed);
            effect.requests_sent = already_sent.saturating_add(1);
            return effect;
        }
    };
    effect.requests_sent = already_sent.saturating_add(1);
    let parsed = match handle.protocol {
        RouterProtocol::Pcp => decode_pcp(&body),
        RouterProtocol::NatPmp => decode_natpmp(&body),
        RouterProtocol::UpnpIgd => Err(DecodeFault::Malformed),
    };
    let Ok(parsed) = parsed else {
        effect.outcome = TraversalOutcome::ExpiryUnknown;
        effect.cleanup = TraversalCleanup::ExpiryUnknown;
        effect.refusal = Some(MappingRefusal::Truncated);
        effect.error = Some(TraversalErrorClass::CleanupFailed);
        return effect;
    };
    // Confirmed deletion requires a MAP response for this mapping. A wrong
    // version, a missing response bit, or another protocol is a mismatch:
    // the grant's expiry stays unknown.
    let matches = match handle.protocol {
        RouterProtocol::Pcp => {
            parsed.version_ok
                && parsed.opcode_ok
                && parsed.nonce == handle.nonce
                && parsed.internal_port == handle.internal_port
                && parsed.protocol == handle.port_protocol.pcp()
        }
        RouterProtocol::NatPmp => {
            parsed.version_ok
                && parsed.opcode_ok
                && parsed.internal_port == handle.internal_port
                && MappedPortProtocol::from_natpmp(parsed.protocol) == Some(handle.port_protocol)
        }
        RouterProtocol::UpnpIgd => false,
    };
    if !matches || rebooted(previous_epoch, parsed.epoch) {
        effect.gateway_rebooted = rebooted(previous_epoch, parsed.epoch);
        effect.outcome = TraversalOutcome::ExpiryUnknown;
        effect.cleanup = TraversalCleanup::ExpiryUnknown;
        effect.refusal = Some(if effect.gateway_rebooted {
            MappingRefusal::Rebooted
        } else {
            MappingRefusal::AmbiguousOwnership
        });
        effect.error = Some(TraversalErrorClass::CleanupFailed);
        effect.epoch = Some(parsed.epoch);
        return effect;
    }
    let class = match handle.protocol {
        RouterProtocol::Pcp => pcp_class(parsed.result),
        RouterProtocol::NatPmp => natpmp_class(parsed.result),
        RouterProtocol::UpnpIgd => ServerClass::Failed,
    };
    effect.epoch = Some(parsed.epoch);
    // Confirmed deletion is a success reply whose lifetime is zero. A success
    // that still carries a lifetime refreshed or ignored the delete.
    if class == ServerClass::Success && parsed.lifetime == 0 {
        effect.cleanup = TraversalCleanup::ConfirmedDeleted;
        if effect.refusal.is_none() {
            effect.outcome = TraversalOutcome::Succeeded;
        }
        effect.error = None;
        return effect;
    }
    effect.cleanup = TraversalCleanup::DeleteFailed;
    effect.refusal = Some(MappingRefusal::Denied);
    effect.error = Some(TraversalErrorClass::CleanupFailed);
    effect
}

fn delete_packet(handle: &OwnedMappingHandle) -> Vec<u8> {
    match handle.protocol {
        RouterProtocol::Pcp => encode_pcp(
            handle.client,
            handle.port_protocol.pcp(),
            handle.internal_port,
            handle.external_port,
            handle.nonce.unwrap_or([0; 12]),
            0,
        )
        .to_vec(),
        RouterProtocol::NatPmp => encode_natpmp(
            handle.port_protocol.natpmp(),
            handle.internal_port,
            // RFC 6886 §3.4: the suggested external port MUST be zero on delete.
            0,
            0,
        )
        .to_vec(),
        RouterProtocol::UpnpIgd => Vec::new(),
    }
}

fn correlated_handle(
    parts: MapParts,
    external_port: u16,
    lifetime: u32,
    epoch: u32,
    cleanup_authorized: bool,
) -> OwnedMappingHandle {
    OwnedMappingHandle {
        protocol: parts.protocol,
        port_protocol: parts.port_protocol,
        internal_port: parts.internal_port,
        external_port,
        client: parts.client,
        granted_lifetime_sec: lifetime,
        epoch,
        nonce: parts.nonce,
        reservation_digest: parts.digest,
        cleanup_authorized,
        external_address: None,
    }
}

fn encode_pcp(
    local: Ipv4Addr,
    protocol: u8,
    internal_port: u16,
    external_port: u16,
    nonce: [u8; 12],
    lifetime: u32,
) -> [u8; PCP_MAP_PACKET_BYTES] {
    let mut packet = [0u8; PCP_MAP_PACKET_BYTES];
    packet[0] = PCP_VERSION;
    packet[1] = PCP_MAP_OPCODE;
    packet[4..8].copy_from_slice(&lifetime.to_be_bytes());
    packet[8..24].copy_from_slice(&ipv4_mapped(local));
    packet[24..36].copy_from_slice(&nonce);
    packet[36] = protocol;
    packet[40..42].copy_from_slice(&internal_port.to_be_bytes());
    packet[42..44].copy_from_slice(&external_port.to_be_bytes());
    packet
}

fn encode_natpmp(
    opcode: u8,
    internal_port: u16,
    external_port: u16,
    lifetime: u32,
) -> [u8; NATPMP_MAP_REQUEST_BYTES] {
    let mut packet = [0u8; NATPMP_MAP_REQUEST_BYTES];
    packet[0] = NATPMP_VERSION;
    packet[1] = opcode;
    packet[4..6].copy_from_slice(&internal_port.to_be_bytes());
    packet[6..8].copy_from_slice(&external_port.to_be_bytes());
    packet[8..12].copy_from_slice(&lifetime.to_be_bytes());
    packet
}

fn decode_pcp(bytes: &[u8]) -> Result<Parsed, DecodeFault> {
    if bytes.len() < PCP_MAP_PACKET_BYTES {
        return Err(DecodeFault::Truncated);
    }
    if bytes.len() > PCP_MAP_PACKET_BYTES {
        return Err(DecodeFault::Oversize);
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bytes[24..36]);
    Ok(Parsed {
        version_ok: bytes[0] == PCP_VERSION,
        opcode_ok: bytes[1] == PCP_MAP_OPCODE | PCP_RESPONSE_BIT,
        // RFC 6887 §7.2 response header: version, R+opcode, reserved, result.
        result: u16::from(bytes[3]),
        lifetime: u32_at(bytes, 4),
        epoch: u32_at(bytes, 8),
        protocol: bytes[36],
        internal_port: u16_at(bytes, 40),
        assigned_port: u16_at(bytes, 42),
        nonce: Some(nonce),
        assigned_ip: mapped_ipv4(&bytes[44..60]),
    })
}

fn decode_natpmp(bytes: &[u8]) -> Result<Parsed, DecodeFault> {
    if bytes.len() < NATPMP_MAP_RESPONSE_BYTES {
        return Err(DecodeFault::Truncated);
    }
    if bytes.len() > NATPMP_MAP_RESPONSE_BYTES {
        return Err(DecodeFault::Oversize);
    }
    let opcode = bytes[1];
    Ok(Parsed {
        version_ok: bytes[0] == NATPMP_VERSION,
        opcode_ok: opcode & NATPMP_RESPONSE_BIT == NATPMP_RESPONSE_BIT
            && MappedPortProtocol::from_natpmp(opcode & !NATPMP_RESPONSE_BIT).is_some(),
        result: u16_at(bytes, 2),
        lifetime: u32_at(bytes, 12),
        epoch: u32_at(bytes, 4),
        protocol: opcode & !NATPMP_RESPONSE_BIT,
        internal_port: u16_at(bytes, 8),
        assigned_port: u16_at(bytes, 10),
        nonce: None,
        assigned_ip: None,
    })
}

fn pcp_class(code: u16) -> ServerClass {
    match code {
        0 => ServerClass::Success,
        2 => ServerClass::Denied,
        1 | 4 | 5 | 9 => ServerClass::Unsupported,
        11 => ServerClass::Conflict,
        _ => ServerClass::Failed,
    }
}

fn natpmp_class(code: u16) -> ServerClass {
    match code {
        0 => ServerClass::Success,
        2 => ServerClass::Denied,
        1 | 5 => ServerClass::Unsupported,
        // NAT-PMP has no conflict opcode. Out-of-resources is the refusal a
        // gateway returns when the requested mapping collides and cannot be made.
        4 => ServerClass::Conflict,
        _ => ServerClass::Failed,
    }
}

fn explicit(
    mut effect: MappingEffect,
    refusal: MappingRefusal,
    error: TraversalErrorClass,
) -> MappingEffect {
    effect.outcome = TraversalOutcome::Failed;
    effect.cleanup = TraversalCleanup::NotCreated;
    effect.refusal = Some(refusal);
    effect.error = Some(error);
    effect.handle = None;
    effect
}

fn lost(
    protocol: RouterProtocol,
    sent: u8,
    refusal: MappingRefusal,
    error: TraversalErrorClass,
) -> MappingEffect {
    let mut effect = blank(protocol);
    effect.outcome = TraversalOutcome::CreationOutcomeUnknown;
    effect.cleanup = TraversalCleanup::ExpiryUnknown;
    effect.refusal = Some(refusal);
    effect.error = Some(error);
    effect.requests_sent = sent;
    effect
}

fn local_refusal(protocol: RouterProtocol, refusal: MappingRefusal) -> MappingEffect {
    let mut effect = blank(protocol);
    effect.refusal = Some(refusal);
    effect.outcome = match refusal {
        MappingRefusal::MissingReservation
        | MappingRefusal::ReservationGatewayMismatch
        | MappingRefusal::AmbiguousOwnership
        | MappingRefusal::LowPort => TraversalOutcome::UnsupportedSafeOwnership,
        MappingRefusal::BadLifetimeCeiling => TraversalOutcome::UnsupportedFiniteLease,
        MappingRefusal::Cancelled => TraversalOutcome::Failed,
        _ => TraversalOutcome::Failed,
    };
    effect.cleanup = TraversalCleanup::NotCreated;
    effect
}

fn blank(protocol: RouterProtocol) -> MappingEffect {
    MappingEffect {
        protocol,
        outcome: TraversalOutcome::Failed,
        cleanup: TraversalCleanup::NotCreated,
        error: None,
        refusal: None,
        handle: None,
        granted_lifetime_sec: None,
        epoch: None,
        assigned_port: None,
        port_changed: false,
        lease_clamped: false,
        gateway_rebooted: false,
        requests_sent: 0,
    }
}

fn lease_ceiling(maximum_lease_sec: u16) -> Option<u32> {
    let maximum = u32::from(maximum_lease_sec);
    (MAPPING_REQUESTED_LEASE_SEC..=MAPPING_MAXIMUM_LEASE_SEC)
        .contains(&maximum)
        .then_some(maximum)
}

fn rebooted(previous: Option<u32>, epoch: u32) -> bool {
    previous.is_some_and(|previous| epoch < previous)
}

fn usable_ipv4(addr: Ipv4Addr) -> bool {
    !addr.is_unspecified() && !addr.is_broadcast() && !addr.is_multicast() && addr.octets()[0] < 240
}

fn ipv4_mapped(addr: Ipv4Addr) -> [u8; 16] {
    let octets = addr.octets();
    let mut mapped = [0u8; 16];
    mapped[10] = 0xff;
    mapped[11] = 0xff;
    mapped[12..].copy_from_slice(&octets);
    mapped
}

fn mapped_ipv4(bytes: &[u8]) -> Option<Ipv4Addr> {
    if bytes.len() != 16 || bytes[..10] != [0; 10] || bytes[10..12] != [0xff, 0xff] {
        return None;
    }
    let addr = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    usable_ipv4(addr).then_some(addr)
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn transport_refusal(error: ControlRefusal) -> MappingRefusal {
    match error {
        ControlRefusal::Cancelled => MappingRefusal::Cancelled,
        ControlRefusal::Oversize | ControlRefusal::Bounded => MappingRefusal::Malformed,
        ControlRefusal::Unsupported | ControlRefusal::WrongTarget => MappingRefusal::LostResponse,
    }
}

fn transport_error(error: ControlRefusal) -> TraversalErrorClass {
    match error {
        ControlRefusal::Cancelled | ControlRefusal::Bounded => TraversalErrorClass::Timeout,
        _ => TraversalErrorClass::InvalidResponse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_traversal::GatewayDiscovery;
    use crate::network_traversal::gateway::{RouteRecord, discover_loaded};
    use std::net::{IpAddr, SocketAddr};

    fn never() -> bool {
        false
    }

    fn gateway() -> SelectedGateway {
        match discover_loaded(
            &[RouteRecord::new(
                Ipv4Addr::UNSPECIFIED,
                0,
                Ipv4Addr::new(192, 0, 2, 1),
                true,
                1,
            )],
            &never,
        ) {
            GatewayDiscovery::Selected(gateway) => gateway,
            other => panic!("gateway fixture {other:?}"),
        }
    }

    fn reservation_for(gateway: &SelectedGateway) -> ExclusiveReservation {
        ExclusiveReservation::new(gateway.gateway(), [9; 32]).unwrap()
    }

    fn nonce() -> [u8; 12] {
        *b"nonce-bytes!"
    }

    fn pcp(reservation: Option<&ExclusiveReservation>, previous_epoch: Option<u32>) -> PcpMap<'_> {
        PcpMap {
            local_address: Ipv4Addr::new(192, 0, 2, 10),
            internal_port: 40_000,
            protocol: MappedPortProtocol::Udp,
            nonce: nonce(),
            maximum_lease_sec: 120,
            previous_epoch,
            exclusive_reservation: reservation,
        }
    }

    fn nat(
        reservation: Option<&ExclusiveReservation>,
        previous_epoch: Option<u32>,
    ) -> NatPmpMap<'_> {
        NatPmpMap {
            internal_port: 40_000,
            protocol: MappedPortProtocol::Udp,
            maximum_lease_sec: 120,
            previous_epoch,
            exclusive_reservation: reservation,
        }
    }

    struct Fake {
        sent: Vec<(SocketAddr, Vec<u8>)>,
        replies: Vec<Result<Vec<u8>, ControlRefusal>>,
    }

    impl ControlTransport for Fake {
        fn exchange(
            &mut self,
            destination: SocketAddr,
            request: &[u8],
            response: &mut [u8],
        ) -> Result<usize, ControlRefusal> {
            self.sent.push((destination, request.to_vec()));
            let reply = self
                .replies
                .pop()
                .unwrap_or(Err(ControlRefusal::Unsupported));
            let bytes = reply?;
            let length = bytes.len().min(response.len());
            response[..length].copy_from_slice(&bytes[..length]);
            Ok(length)
        }
    }

    impl Fake {
        fn new(replies: Vec<Result<Vec<u8>, ControlRefusal>>) -> Self {
            let mut replies = replies;
            replies.reverse();
            Self {
                sent: Vec::new(),
                replies,
            }
        }
    }

    fn pcp_response(
        result: u8,
        lifetime: u32,
        epoch: u32,
        internal: u16,
        assigned: u16,
        nonce: [u8; 12],
    ) -> Vec<u8> {
        let mut packet = vec![0u8; PCP_MAP_PACKET_BYTES];
        packet[0] = PCP_VERSION;
        packet[1] = PCP_MAP_OPCODE | PCP_RESPONSE_BIT;
        packet[3] = result;
        packet[4..8].copy_from_slice(&lifetime.to_be_bytes());
        packet[8..12].copy_from_slice(&epoch.to_be_bytes());
        packet[24..36].copy_from_slice(&nonce);
        packet[36] = 17;
        packet[40..42].copy_from_slice(&internal.to_be_bytes());
        packet[42..44].copy_from_slice(&assigned.to_be_bytes());
        packet[44..60].copy_from_slice(&ipv4_mapped(Ipv4Addr::new(198, 51, 100, 20)));
        packet
    }

    fn nat_response(
        result: u16,
        lifetime: u32,
        epoch: u32,
        internal: u16,
        assigned: u16,
        opcode: u8,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; NATPMP_MAP_RESPONSE_BYTES];
        packet[0] = NATPMP_VERSION;
        packet[1] = opcode | NATPMP_RESPONSE_BIT;
        packet[2..4].copy_from_slice(&result.to_be_bytes());
        packet[4..8].copy_from_slice(&epoch.to_be_bytes());
        packet[8..10].copy_from_slice(&internal.to_be_bytes());
        packet[10..12].copy_from_slice(&assigned.to_be_bytes());
        packet[12..16].copy_from_slice(&lifetime.to_be_bytes());
        packet
    }

    fn assert_delete_unconfirmed(deleted: &MappingEffect) {
        assert_eq!(deleted.cleanup, TraversalCleanup::ExpiryUnknown);
        assert_eq!(deleted.outcome, TraversalOutcome::ExpiryUnknown);
        assert_eq!(deleted.error, Some(TraversalErrorClass::CleanupFailed));
        assert_eq!(deleted.refusal, Some(MappingRefusal::AmbiguousOwnership));
        assert!(!deleted.gateway_rebooted);
        assert_ne!(deleted.cleanup, TraversalCleanup::ConfirmedDeleted);
    }

    fn assert_gateway_only(fake: &Fake, gateway: &SelectedGateway) {
        assert!(!fake.sent.is_empty());
        for (destination, _) in &fake.sent {
            assert_eq!(
                *destination,
                SocketAddr::new(IpAddr::V4(gateway.gateway()), 5351)
            );
        }
    }

    fn lifetime_of(protocol: RouterProtocol, packet: &[u8]) -> u32 {
        match protocol {
            RouterProtocol::Pcp => u32_at(packet, 4),
            RouterProtocol::NatPmp => u32_at(packet, 8),
            RouterProtocol::UpnpIgd => panic!("upnp is not a mapping codec"),
        }
    }

    #[test]
    fn request_bytes_pin_version_opcode_lifetime_and_tuple() {
        let pcp = encode_pcp(
            Ipv4Addr::new(192, 0, 2, 10),
            17,
            40_000,
            40_000,
            nonce(),
            MAPPING_REQUESTED_LEASE_SEC,
        );
        assert_eq!(pcp.len(), PCP_MAP_PACKET_BYTES);
        assert_eq!(&pcp[..8], &[2, 1, 0, 0, 0, 0, 0, 60]);
        assert_eq!(&pcp[8..24], &ipv4_mapped(Ipv4Addr::new(192, 0, 2, 10)));
        assert_eq!(&pcp[24..36], &nonce());
        assert_eq!(pcp[36], 17);
        assert_eq!(&pcp[40..44], &40_000u16.to_be_bytes().repeat(2));
        assert_eq!(&pcp[44..], &[0u8; 16]);

        let nat = encode_natpmp(NATPMP_UDP, 40_000, 40_000, MAPPING_REQUESTED_LEASE_SEC);
        assert_eq!(nat.len(), NATPMP_MAP_REQUEST_BYTES);
        assert_eq!(nat, [0, 1, 0, 0, 0x9c, 0x40, 0x9c, 0x40, 0, 0, 0, 60]);
    }

    #[test]
    fn literal_pcp_success_adopts_only_the_matching_nonce() {
        let gateway = gateway();
        let mut literal = [0u8; PCP_MAP_PACKET_BYTES];
        literal[0] = 2;
        literal[1] = 0x81;
        literal[4] = 0;
        literal[5] = 0;
        literal[6] = 0;
        literal[7] = 60;
        literal[8] = 0;
        literal[9] = 0;
        literal[10] = 0;
        literal[11] = 10;
        literal[24..36].copy_from_slice(&nonce());
        literal[36] = 17;
        literal[40] = 0x9c;
        literal[41] = 0x40;
        literal[42] = 0x9c;
        literal[43] = 0x40;
        literal[44..60].copy_from_slice(&ipv4_mapped(Ipv4Addr::new(198, 51, 100, 20)));
        let mut fake = Fake::new(vec![Ok(literal.to_vec())]);
        let effect = map_pcp(&gateway, &pcp(None, None), &mut fake, &never);
        assert_eq!(effect.outcome, TraversalOutcome::Succeeded);
        assert_eq!(effect.cleanup, TraversalCleanup::LeaseExpiryPending);
        let handle = effect.handle.unwrap();
        assert!(handle.cleanup_authorized());
        assert_eq!(handle.nonce(), Some(nonce()));
        assert_eq!(handle.external_port(), 40_000);
        assert_eq!(handle.protocol(), RouterProtocol::Pcp);
        assert_gateway_only(&fake, &gateway);
        assert_eq!(lifetime_of(RouterProtocol::Pcp, &fake.sent[0].1), 60);
    }

    #[test]
    fn low_port_bad_ceiling_and_missing_reservation_send_nothing() {
        let gateway = gateway();
        let mut fake = Fake::new(vec![]);
        let mut input = pcp(None, None);
        input.internal_port = 80;
        let effect = map_pcp(&gateway, &input, &mut fake, &never);
        assert_eq!(effect.refusal, Some(MappingRefusal::LowPort));
        assert_eq!(effect.outcome, TraversalOutcome::UnsupportedSafeOwnership);
        assert_eq!(effect.cleanup, TraversalCleanup::NotCreated);
        assert!(fake.sent.is_empty());

        input.internal_port = 40_000;
        input.maximum_lease_sec = 121;
        let effect = map_pcp(&gateway, &input, &mut fake, &never);
        assert_eq!(effect.refusal, Some(MappingRefusal::BadLifetimeCeiling));
        assert_eq!(effect.outcome, TraversalOutcome::UnsupportedFiniteLease);
        assert!(fake.sent.is_empty());

        let effect = map_nat_pmp(&gateway, &nat(None, None), &mut fake, &never);
        assert_eq!(effect.refusal, Some(MappingRefusal::MissingReservation));
        assert_eq!(effect.outcome, TraversalOutcome::UnsupportedSafeOwnership);
        assert_eq!(effect.requests_sent, 0);
        assert!(fake.sent.is_empty());

        let other = ExclusiveReservation::new(Ipv4Addr::new(198, 51, 100, 1), [9; 32]).unwrap();
        let effect = map_nat_pmp(&gateway, &nat(Some(&other), None), &mut fake, &never);
        assert_eq!(
            effect.refusal,
            Some(MappingRefusal::ReservationGatewayMismatch)
        );
        assert!(fake.sent.is_empty());
    }

    #[test]
    fn denial_unsupported_conflict_and_port_change_are_independent() {
        let gateway = gateway();
        let reservation = reservation_for(&gateway);

        let mut pcp_fake = Fake::new(vec![Ok(pcp_response(2, 0, 10, 40_000, 0, nonce()))]);
        let denied = map_pcp(&gateway, &pcp(None, None), &mut pcp_fake, &never);
        assert_eq!(denied.refusal, Some(MappingRefusal::Denied));
        assert_eq!(denied.cleanup, TraversalCleanup::NotCreated);
        assert_eq!(denied.outcome, TraversalOutcome::Failed);
        assert!(denied.handle.is_none());
        assert_eq!(pcp_fake.sent.len(), 1);

        let mut nat_fake = Fake::new(vec![Ok(nat_response(5, 0, 10, 40_000, 0, NATPMP_UDP))]);
        let unsupported = map_nat_pmp(
            &gateway,
            &nat(Some(&reservation), None),
            &mut nat_fake,
            &never,
        );
        assert_eq!(
            unsupported.refusal,
            Some(MappingRefusal::ProtocolUnsupported)
        );
        assert_eq!(unsupported.cleanup, TraversalCleanup::NotCreated);
        assert_eq!(unsupported.protocol, RouterProtocol::NatPmp);
        assert_ne!(denied.protocol, unsupported.protocol);

        let mut conflict = Fake::new(vec![Ok(pcp_response(11, 0, 10, 40_000, 0, nonce()))]);
        let effect = map_pcp(&gateway, &pcp(None, None), &mut conflict, &never);
        assert_eq!(effect.refusal, Some(MappingRefusal::Conflict));
        assert_eq!(effect.error, Some(TraversalErrorClass::MappingConflict));
        assert_eq!(effect.cleanup, TraversalCleanup::NotCreated);
        assert_eq!(conflict.sent.len(), 1);

        let mut nat_conflict = Fake::new(vec![Ok(nat_response(4, 0, 10, 40_000, 0, NATPMP_UDP))]);
        let effect = map_nat_pmp(
            &gateway,
            &nat(Some(&reservation), None),
            &mut nat_conflict,
            &never,
        );
        assert_eq!(effect.refusal, Some(MappingRefusal::Conflict));
        assert_eq!(effect.protocol, RouterProtocol::NatPmp);
        assert_eq!(nat_conflict.sent.len(), 1);

        let mut changed = Fake::new(vec![Ok(pcp_response(0, 60, 10, 40_000, 40_111, nonce()))]);
        let effect = map_pcp(&gateway, &pcp(None, None), &mut changed, &never);
        assert_eq!(effect.outcome, TraversalOutcome::Succeeded);
        assert!(effect.port_changed);
        assert_eq!(effect.handle.unwrap().external_port(), 40_111);
        assert!(!effect.lease_clamped);
    }

    #[test]
    fn lease_clamp_is_accepted_and_zero_or_overlong_never_falls_back_to_permanent() {
        let gateway = gateway();
        let reservation = reservation_for(&gateway);
        let mut clamped = Fake::new(vec![Ok(nat_response(
            0, 30, 10, 40_000, 40_000, NATPMP_UDP,
        ))]);
        let effect = map_nat_pmp(
            &gateway,
            &nat(Some(&reservation), None),
            &mut clamped,
            &never,
        );
        assert_eq!(effect.outcome, TraversalOutcome::Succeeded);
        assert!(effect.lease_clamped);
        assert_eq!(effect.granted_lifetime_sec, Some(30));
        assert_eq!(effect.handle.unwrap().granted_lifetime_sec(), 30);
        assert_eq!(clamped.sent.len(), 1);
        assert_eq!(lifetime_of(RouterProtocol::NatPmp, &clamped.sent[0].1), 60);

        let mut overlong = Fake::new(vec![
            Ok(pcp_response(0, u32::MAX, 10, 40_000, 40_000, nonce())),
            Ok(pcp_response(0, 0, 10, 40_000, 0, nonce())),
        ]);
        let effect = map_pcp(
            &gateway,
            &pcp(Some(&reservation), None),
            &mut overlong,
            &never,
        );
        assert_eq!(effect.outcome, TraversalOutcome::UnsupportedFiniteLease);
        assert_eq!(effect.cleanup, TraversalCleanup::ConfirmedDeleted);
        assert_eq!(effect.requests_sent, 2);
        assert_eq!(lifetime_of(RouterProtocol::Pcp, &overlong.sent[0].1), 60);
        assert_eq!(lifetime_of(RouterProtocol::Pcp, &overlong.sent[1].1), 0);
        assert!(effect.handle.unwrap().cleanup_authorized());

        let mut ambiguous = Fake::new(vec![Ok(pcp_response(0, 0, 10, 40_000, 40_000, nonce()))]);
        let effect = map_pcp(&gateway, &pcp(None, None), &mut ambiguous, &never);
        assert_eq!(effect.refusal, Some(MappingRefusal::AmbiguousOwnership));
        assert_eq!(effect.outcome, TraversalOutcome::UnsupportedSafeOwnership);
        assert_eq!(effect.cleanup, TraversalCleanup::ExpiryUnknown);
        assert_eq!(ambiguous.sent.len(), 1);
        assert!(!effect.handle.unwrap().cleanup_authorized());
        let handle = effect.handle.unwrap();
        let mut retry = Fake::new(vec![Ok(pcp_response(0, 0, 11, 40_000, 0, nonce()))]);
        let deleted =
            delete_owned_mapping(&gateway, &handle, None, Some(10), &mut retry, &never, None);
        assert!(retry.sent.is_empty());
        assert_eq!(deleted.refusal, Some(MappingRefusal::AmbiguousOwnership));
    }

    #[test]
    fn reboot_truncated_replay_and_lost_create_are_not_not_created() {
        let gateway = gateway();
        let reservation = reservation_for(&gateway);

        let mut rebooted = Fake::new(vec![Ok(pcp_response(0, 60, 3, 40_000, 40_000, nonce()))]);
        let effect = map_pcp(&gateway, &pcp(None, Some(50)), &mut rebooted, &never);
        assert!(effect.gateway_rebooted);
        assert_eq!(effect.outcome, TraversalOutcome::ExpiryUnknown);
        assert_eq!(effect.cleanup, TraversalCleanup::ExpiryUnknown);
        assert_ne!(effect.cleanup, TraversalCleanup::NotCreated);
        assert_eq!(rebooted.sent.len(), 1);
        assert!(!effect.handle.unwrap().cleanup_authorized());

        let mut truncated = Fake::new(vec![Ok(vec![0, 129, 0])]);
        let effect = map_nat_pmp(
            &gateway,
            &nat(Some(&reservation), None),
            &mut truncated,
            &never,
        );
        assert_eq!(effect.refusal, Some(MappingRefusal::Truncated));
        assert_eq!(effect.outcome, TraversalOutcome::CreationOutcomeUnknown);
        assert_eq!(effect.cleanup, TraversalCleanup::ExpiryUnknown);
        assert!(effect.handle.is_none());

        let mut replay = Fake::new(vec![Ok(pcp_response(0, 60, 10, 40_000, 40_000, [7; 12]))]);
        let effect = map_pcp(&gateway, &pcp(None, None), &mut replay, &never);
        assert_eq!(effect.refusal, Some(MappingRefusal::ReplayOrMismatch));
        assert_eq!(effect.outcome, TraversalOutcome::CreationOutcomeUnknown);
        assert_eq!(effect.cleanup, TraversalCleanup::ExpiryUnknown);
        assert_ne!(effect.cleanup, TraversalCleanup::NotCreated);
        assert_eq!(replay.sent.len(), 1);

        let mut foreign = Fake::new(vec![Ok(nat_response(
            0, 60, 10, 40_001, 40_000, NATPMP_UDP,
        ))]);
        let effect = map_nat_pmp(
            &gateway,
            &nat(Some(&reservation), None),
            &mut foreign,
            &never,
        );
        assert_eq!(effect.refusal, Some(MappingRefusal::ReplayOrMismatch));
        assert_eq!(effect.outcome, TraversalOutcome::CreationOutcomeUnknown);
        assert_eq!(foreign.sent.len(), 1);

        let mut lost = Fake::new(vec![Err(ControlRefusal::Bounded)]);
        let effect = map_pcp(&gateway, &pcp(None, None), &mut lost, &never);
        assert_eq!(effect.outcome, TraversalOutcome::CreationOutcomeUnknown);
        assert_eq!(effect.cleanup, TraversalCleanup::ExpiryUnknown);
        assert_ne!(effect.cleanup, TraversalCleanup::NotCreated);
        assert_ne!(effect.outcome, TraversalOutcome::Failed);
        assert!(effect.handle.is_none());
        assert_eq!(lost.sent.len(), 1);
    }

    #[test]
    fn delete_errors_keep_the_owned_handle_and_do_not_claim_deletion() {
        let gateway = gateway();
        let reservation = reservation_for(&gateway);
        let mut created = Fake::new(vec![Ok(nat_response(
            0, 60, 10, 40_000, 40_222, NATPMP_UDP,
        ))]);
        let effect = map_nat_pmp(
            &gateway,
            &nat(Some(&reservation), None),
            &mut created,
            &never,
        );
        let handle = effect.handle.unwrap();
        assert!(handle.cleanup_authorized());
        assert_eq!(handle.external_port(), 40_222);
        assert!(effect.port_changed);

        let mut failed = Fake::new(vec![Ok(nat_response(
            2, 60, 11, 40_000, 40_222, NATPMP_UDP,
        ))]);
        let deleted = delete_owned_mapping(
            &gateway,
            &handle,
            Some(&reservation),
            Some(10),
            &mut failed,
            &never,
            None,
        );
        assert_eq!(deleted.cleanup, TraversalCleanup::DeleteFailed);
        assert_eq!(deleted.error, Some(TraversalErrorClass::CleanupFailed));
        assert_eq!(
            deleted.handle.unwrap().external_port(),
            handle.external_port()
        );
        assert_eq!(lifetime_of(RouterProtocol::NatPmp, &failed.sent[0].1), 0);
        assert_eq!(&failed.sent[0].1[6..8], &[0, 0]);
        assert_gateway_only(&failed, &gateway);

        let mut pcp_created = Fake::new(vec![Ok(pcp_response(0, 60, 10, 40_000, 40_000, nonce()))]);
        let created = map_pcp(&gateway, &pcp(None, None), &mut pcp_created, &never);
        let handle = created.handle.unwrap();
        let mut pcp_failed = Fake::new(vec![Ok(pcp_response(7, 60, 11, 40_000, 40_000, nonce()))]);
        let deleted = delete_owned_mapping(
            &gateway,
            &handle,
            None,
            Some(10),
            &mut pcp_failed,
            &never,
            None,
        );
        assert_eq!(deleted.cleanup, TraversalCleanup::DeleteFailed);
        assert_eq!(deleted.handle.unwrap().nonce(), Some(nonce()));
        assert_eq!(pcp_failed.sent.len(), 1);
        assert_eq!(lifetime_of(RouterProtocol::Pcp, &pcp_failed.sent[0].1), 0);
    }

    #[test]
    fn a_long_existing_natpmp_mapping_is_deleted_instead_of_adopted() {
        let gateway = gateway();
        let reservation = reservation_for(&gateway);
        let mut fake = Fake::new(vec![
            Ok(nat_response(0, 86_400, 10, 40_000, 50_000, NATPMP_UDP)),
            Ok(nat_response(0, 0, 11, 40_000, 0, NATPMP_UDP)),
        ]);
        let effect = map_nat_pmp(&gateway, &nat(Some(&reservation), None), &mut fake, &never);
        assert_eq!(effect.outcome, TraversalOutcome::UnsupportedFiniteLease);
        assert_eq!(effect.cleanup, TraversalCleanup::ConfirmedDeleted);
        assert_ne!(effect.outcome, TraversalOutcome::Succeeded);
        assert_eq!(fake.sent.len(), 2);
        assert_eq!(lifetime_of(RouterProtocol::NatPmp, &fake.sent[0].1), 60);
        assert_eq!(lifetime_of(RouterProtocol::NatPmp, &fake.sent[1].1), 0);
        assert_eq!(effect.handle.unwrap().external_port(), 50_000);
    }

    #[test]
    fn rfc_pcp_not_authorized_is_not_a_grant() {
        let gateway = gateway();
        let mut packet = [0u8; PCP_MAP_PACKET_BYTES];
        packet[0] = 2;
        packet[1] = 0x81;
        packet[2] = 0;
        packet[3] = 2;
        packet[4..8].copy_from_slice(&30u32.to_be_bytes());
        packet[8..12].copy_from_slice(&10u32.to_be_bytes());
        packet[24..36].copy_from_slice(&nonce());
        packet[36] = 17;
        packet[40..42].copy_from_slice(&40_000u16.to_be_bytes());
        packet[42..44].copy_from_slice(&40_000u16.to_be_bytes());
        packet[44..60].copy_from_slice(&ipv4_mapped(Ipv4Addr::new(198, 51, 100, 20)));
        let mut fake = Fake::new(vec![Ok(packet.to_vec())]);
        let effect = map_pcp(&gateway, &pcp(None, None), &mut fake, &never);
        assert_eq!(effect.refusal, Some(MappingRefusal::Denied));
        assert_eq!(effect.outcome, TraversalOutcome::Failed);
        assert_eq!(effect.cleanup, TraversalCleanup::NotCreated);
        assert!(effect.handle.is_none());
        assert_eq!(fake.sent.len(), 1);
    }

    #[test]
    fn a_success_reply_that_keeps_a_lifetime_is_not_confirmed_deleted() {
        let gateway = gateway();
        let mut created = Fake::new(vec![Ok(pcp_response(0, 60, 10, 40_000, 40_000, nonce()))]);
        let created = map_pcp(&gateway, &pcp(None, None), &mut created, &never);
        let handle = created.handle.unwrap();
        let mut refreshed = Fake::new(vec![Ok(pcp_response(
            0,
            60,
            10,
            40_000,
            handle.external_port(),
            nonce(),
        ))]);
        let deleted = delete_owned_mapping(
            &gateway,
            &handle,
            None,
            Some(10),
            &mut refreshed,
            &never,
            None,
        );
        assert_eq!(deleted.cleanup, TraversalCleanup::DeleteFailed);
        assert_ne!(deleted.cleanup, TraversalCleanup::ConfirmedDeleted);
        assert_eq!(deleted.error, Some(TraversalErrorClass::CleanupFailed));
        assert_eq!(
            deleted.handle.unwrap().external_port(),
            handle.external_port()
        );
    }

    #[test]
    fn cancelling_an_explicit_delete_keeps_a_finite_grant() {
        let gateway = gateway();
        let mut created = Fake::new(vec![Ok(pcp_response(0, 60, 10, 40_000, 40_000, nonce()))]);
        let created = map_pcp(&gateway, &pcp(None, None), &mut created, &never);
        let handle = created.handle.unwrap();
        let mut fake = Fake::new(vec![]);
        let deleted =
            delete_owned_mapping(&gateway, &handle, None, Some(10), &mut fake, &|| true, None);
        assert!(fake.sent.is_empty());
        assert_eq!(deleted.cleanup, TraversalCleanup::LeaseExpiryPending);
        assert_eq!(deleted.refusal, Some(MappingRefusal::Cancelled));
        assert_eq!(deleted.handle.unwrap().external_port(), 40_000);
        assert_ne!(deleted.cleanup, TraversalCleanup::NotCreated);
    }

    #[test]
    fn a_rebooted_gateway_still_deletes_an_overlong_reserved_grant() {
        let gateway = gateway();
        let reservation = reservation_for(&gateway);
        let mut fake = Fake::new(vec![
            Ok(pcp_response(0, u32::MAX, 3, 40_000, 40_000, nonce())),
            Ok(pcp_response(0, 0, 4, 40_000, 0, nonce())),
        ]);
        let effect = map_pcp(
            &gateway,
            &pcp(Some(&reservation), Some(50)),
            &mut fake,
            &never,
        );
        assert!(effect.gateway_rebooted);
        assert_eq!(effect.outcome, TraversalOutcome::UnsupportedFiniteLease);
        assert_eq!(effect.cleanup, TraversalCleanup::ConfirmedDeleted);
        assert_eq!(fake.sent.len(), 2);
        assert_eq!(lifetime_of(RouterProtocol::Pcp, &fake.sent[1].1), 0);
    }

    #[test]
    fn a_delete_reply_that_is_not_a_map_response_is_not_confirmed() {
        let gateway = gateway();
        let reservation = reservation_for(&gateway);
        let mut created = Fake::new(vec![Ok(pcp_response(0, 60, 10, 40_000, 40_000, nonce()))]);
        let handle = map_pcp(&gateway, &pcp(None, None), &mut created, &never)
            .handle
            .unwrap();

        let mut wrong_version = pcp_response(0, 0, 11, 40_000, 0, nonce());
        wrong_version[0] = 1;
        let mut fake = Fake::new(vec![Ok(wrong_version)]);
        let deleted =
            delete_owned_mapping(&gateway, &handle, None, Some(10), &mut fake, &never, None);
        assert_delete_unconfirmed(&deleted);

        let mut missing_response = pcp_response(0, 0, 11, 40_000, 0, nonce());
        missing_response[1] = PCP_MAP_OPCODE;
        let mut fake = Fake::new(vec![Ok(missing_response)]);
        let deleted =
            delete_owned_mapping(&gateway, &handle, None, Some(10), &mut fake, &never, None);
        assert_delete_unconfirmed(&deleted);

        let mut wrong_protocol = pcp_response(0, 0, 11, 40_000, 0, nonce());
        wrong_protocol[36] = MappedPortProtocol::Tcp.pcp();
        let mut fake = Fake::new(vec![Ok(wrong_protocol)]);
        let deleted =
            delete_owned_mapping(&gateway, &handle, None, Some(10), &mut fake, &never, None);
        assert_delete_unconfirmed(&deleted);

        let mut nat_created = Fake::new(vec![Ok(nat_response(
            0, 60, 10, 40_000, 40_000, NATPMP_UDP,
        ))]);
        let nat_handle = map_nat_pmp(
            &gateway,
            &nat(Some(&reservation), None),
            &mut nat_created,
            &never,
        )
        .handle
        .unwrap();

        let mut nat_version = nat_response(0, 0, 11, 40_000, 0, NATPMP_UDP);
        nat_version[0] = 7;
        let mut fake = Fake::new(vec![Ok(nat_version)]);
        let deleted = delete_owned_mapping(
            &gateway,
            &nat_handle,
            Some(&reservation),
            Some(10),
            &mut fake,
            &never,
            None,
        );
        assert_delete_unconfirmed(&deleted);

        let mut nat_request = nat_response(0, 0, 11, 40_000, 0, NATPMP_UDP);
        nat_request[1] = NATPMP_UDP;
        let mut fake = Fake::new(vec![Ok(nat_request)]);
        let deleted = delete_owned_mapping(
            &gateway,
            &nat_handle,
            Some(&reservation),
            Some(10),
            &mut fake,
            &never,
            None,
        );
        assert_delete_unconfirmed(&deleted);
    }

    #[test]
    fn an_overlong_delete_that_shows_a_reboot_keeps_the_flag() {
        let gateway = gateway();
        let reservation = reservation_for(&gateway);
        let mut fake = Fake::new(vec![
            Ok(pcp_response(0, u32::MAX, 100, 40_000, 40_000, nonce())),
            Ok(pcp_response(0, 0, 5, 40_000, 0, nonce())),
        ]);
        let effect = map_pcp(
            &gateway,
            &pcp(Some(&reservation), Some(50)),
            &mut fake,
            &never,
        );
        assert!(effect.gateway_rebooted);
        assert_eq!(effect.refusal, Some(MappingRefusal::Rebooted));
        assert_eq!(effect.cleanup, TraversalCleanup::ExpiryUnknown);
        assert_eq!(effect.outcome, TraversalOutcome::ExpiryUnknown);
        assert_eq!(fake.sent.len(), 2);
    }

    #[test]
    fn a_rebooted_gateway_error_is_not_created() {
        let gateway = gateway();
        let mut fake = Fake::new(vec![Ok(pcp_response(2, 30, 3, 40_000, 40_000, nonce()))]);
        let effect = map_pcp(&gateway, &pcp(None, Some(50)), &mut fake, &never);
        assert!(effect.gateway_rebooted);
        assert_eq!(effect.refusal, Some(MappingRefusal::Denied));
        assert_eq!(effect.outcome, TraversalOutcome::Failed);
        assert_eq!(effect.cleanup, TraversalCleanup::NotCreated);
        assert!(effect.handle.is_none());
        assert_eq!(fake.sent.len(), 1);
    }

    #[test]
    fn a_finite_success_with_port_zero_is_untrustworthy() {
        let gateway = gateway();
        let mut fake = Fake::new(vec![Ok(pcp_response(0, 60, 10, 40_000, 0, nonce()))]);
        let effect = map_pcp(&gateway, &pcp(None, None), &mut fake, &never);
        assert_eq!(effect.outcome, TraversalOutcome::CreationOutcomeUnknown);
        assert_eq!(effect.cleanup, TraversalCleanup::ExpiryUnknown);
        assert_eq!(effect.refusal, Some(MappingRefusal::Malformed));
        assert!(effect.handle.is_none());
        assert_eq!(fake.sent.len(), 1);
    }

    #[test]
    fn protocols_do_not_decode_each_others_packets() {
        assert!(decode_pcp(&nat_response(0, 60, 1, 40_000, 40_000, NATPMP_UDP)).is_err());
        assert!(decode_natpmp(&pcp_response(0, 60, 1, 40_000, 40_000, nonce())).is_err());
        let mut long = pcp_response(0, 60, 1, 40_000, 40_000, nonce());
        long.push(0);
        assert_eq!(decode_pcp(&long), Err(DecodeFault::Oversize));
        assert_eq!(
            decode_natpmp(&[0, 129, 0, 0, 0, 0, 0, 1]),
            Err(DecodeFault::Truncated)
        );
    }
}
