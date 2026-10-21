//! UPnP IGD `AddPortMapping` / `DeletePortMapping` for one owned high port.
//!
//! Discovery stays in `igd`. This module only talks to the control URL on
//! [`IgdControlDescriptor`]. The selected gateway and that descriptor must
//! name the same address, and the caller must hold an [`ExclusiveReservation`]
//! for it. Either check failing sends nothing.
//!
//! A create reads `GetSpecificPortMappingEntry` for the exact external
//! port and protocol first. Any existing entry, including a static lease of
//! zero, blocks both create and delete. Absence is not enough on its own;
//! the reservation is the other half. A lost or unreadable probe also sends
//! no mutation.
//!
//! The create asks for 60 seconds. Error 725 (only permanent leases) is a
//! finished refusal: there is no second request with lease zero. A lost
//! create stays [`TraversalCleanup::CreationOutcomeUnknown`]. An overlong
//! grant is deleted only after the confirming read shows this client's tuple.
//! AddPortMapping success alone is not ownership.

use std::net::Ipv4Addr;

use sha2::{Digest, Sha256};

use super::super::gateway::{UPNP_SOAP_MAX_BYTES, UpnpSoapReply, exchange_upnp_soap};
use super::super::{
    ControlRefusal, ControlTransport, IGD_XML_MAX_DEPTH, IgdControlDescriptor, IgdServiceKind,
    SelectedGateway, TraversalCleanup, TraversalErrorClass, TraversalOutcome,
};
use super::{
    ExclusiveReservation, MAPPING_HIGH_PORT_MIN, MAPPING_MAXIMUM_LEASE_SEC,
    MAPPING_REQUESTED_LEASE_SEC, MappedPortProtocol, MappingEffect, MappingRefusal,
    OwnedMappingHandle, RouterProtocol,
};

const UPNP_ABSENT: u16 = 714;
const UPNP_CONFLICT: u16 = 718;
const UPNP_PERMANENT_ONLY: u16 = 725;
const SOAP_FIELD_MAX: usize = 64;
const SOAP_ATTRIBUTE_MAX: usize = 512;

/// One finite UPnP mapping attempt. `local_address` is the only internal
/// client this call will write.
pub struct UpnpMap<'a> {
    pub descriptor: &'a IgdControlDescriptor,
    pub local_address: Ipv4Addr,
    pub internal_port: u16,
    pub protocol: MappedPortProtocol,
    pub maximum_lease_sec: u16,
    pub exclusive_reservation: Option<&'a ExclusiveReservation>,
}

pub fn map_upnp(
    gateway: &SelectedGateway,
    input: &UpnpMap<'_>,
    transport: &mut dyn ControlTransport,
    cancelled: &dyn Fn() -> bool,
) -> MappingEffect {
    let Some(ceiling) = super::lease_ceiling(input.maximum_lease_sec) else {
        return super::local_refusal(RouterProtocol::UpnpIgd, MappingRefusal::BadLifetimeCeiling);
    };
    if input.internal_port < MAPPING_HIGH_PORT_MIN {
        return super::local_refusal(RouterProtocol::UpnpIgd, MappingRefusal::LowPort);
    }
    if !super::usable_ipv4(input.local_address) {
        return super::local_refusal(RouterProtocol::UpnpIgd, MappingRefusal::BadClientAddress);
    }
    let Some(reservation) = input.exclusive_reservation else {
        return super::local_refusal(RouterProtocol::UpnpIgd, MappingRefusal::MissingReservation);
    };
    if !reservation.authorizes(gateway) || input.descriptor.gateway() != gateway.gateway() {
        return super::local_refusal(
            RouterProtocol::UpnpIgd,
            MappingRefusal::ReservationGatewayMismatch,
        );
    }

    let tuple = tuple_fields(input.internal_port, input.protocol);
    match attempt(
        gateway,
        input.descriptor,
        "GetSpecificPortMappingEntry",
        &tuple,
        transport,
        cancelled,
    ) {
        Attempt::NotSent(refusal) => return super::local_refusal(RouterProtocol::UpnpIgd, refusal),
        Attempt::Sent(refusal, error) => {
            return unread_probe(refusal, error);
        }
        Attempt::Body(bytes) => match classify_probe(&bytes) {
            Probe::Absent => {}
            Probe::Present => return existing_entry(),
            Probe::Unreadable(refusal) => {
                return unread_probe(refusal, TraversalErrorClass::InvalidResponse);
            }
        },
    }

    if cancelled() {
        return stopped_before_create();
    }
    let add_body = add_fields(input.local_address, input.internal_port, input.protocol);
    match attempt(
        gateway,
        input.descriptor,
        "AddPortMapping",
        &add_body,
        transport,
        cancelled,
    ) {
        Attempt::NotSent(refusal) => return stopped_before_create_with(refusal),
        Attempt::Sent(refusal, error) => return lost_create(2, refusal, error),
        Attempt::Body(bytes) => match classify_add(&bytes) {
            AddReply::Accepted => {}
            AddReply::PermanentOnly => return permanent_only(),
            AddReply::Conflict => return add_conflict(),
            AddReply::Rejected => return add_rejected(),
            AddReply::Unreadable(refusal) => {
                return lost_create(2, refusal, TraversalErrorClass::InvalidResponse);
            }
        },
    }

    if cancelled() {
        return lost_create(2, MappingRefusal::Cancelled, TraversalErrorClass::Timeout);
    }
    match attempt(
        gateway,
        input.descriptor,
        "GetSpecificPortMappingEntry",
        &tuple,
        transport,
        cancelled,
    ) {
        Attempt::NotSent(refusal) | Attempt::Sent(refusal, _) => {
            lost_create(3, refusal, TraversalErrorClass::InvalidResponse)
        }
        Attempt::Body(bytes) => match classify_confirm(
            &bytes,
            input.local_address,
            input.internal_port,
            input.protocol,
            ceiling,
        ) {
            Confirm::Usable { lease } => adopt(input, reservation, lease),
            Confirm::OursButUnusable { lease } => {
                cleanup_unusable(gateway, input, reservation, lease, transport, cancelled)
            }
            Confirm::NotOurs | Confirm::Absent | Confirm::Unreadable => lost_create(
                3,
                MappingRefusal::AmbiguousOwnership,
                TraversalErrorClass::InvalidResponse,
            ),
        },
    }
}

pub(super) fn delete_owned(
    gateway: &SelectedGateway,
    handle: &OwnedMappingHandle,
    control: Option<&IgdControlDescriptor>,
    transport: &mut dyn ControlTransport,
    cancelled: &dyn Fn() -> bool,
) -> MappingEffect {
    let mut effect = super::blank(handle.protocol);
    effect.handle = Some(*handle);
    effect.granted_lifetime_sec = Some(handle.granted_lifetime_sec);
    effect.assigned_port = Some(handle.external_port);
    let Some(control) = control else {
        return keep_ambiguous(effect);
    };
    if handle.protocol != RouterProtocol::UpnpIgd || !control_matches(gateway, handle, control) {
        return keep_ambiguous(effect);
    }
    let finite = (1..=MAPPING_MAXIMUM_LEASE_SEC).contains(&handle.granted_lifetime_sec);
    if !finite {
        effect.outcome = TraversalOutcome::UnsupportedFiniteLease;
        effect.refusal = Some(MappingRefusal::OverlongOrZeroGrant);
        effect.error = Some(TraversalErrorClass::LeaseRefused);
    }
    if cancelled() {
        effect.refusal = Some(MappingRefusal::Cancelled);
        effect.requests_sent = 0;
        if finite {
            effect.outcome = TraversalOutcome::Failed;
            effect.cleanup = TraversalCleanup::LeaseExpiryPending;
        } else {
            effect.outcome = TraversalOutcome::ExpiryUnknown;
            effect.cleanup = TraversalCleanup::ExpiryUnknown;
        }
        return effect;
    }
    match transmit_delete(gateway, control, handle, transport, cancelled) {
        DeleteAttempt::NotSent(refusal) => {
            effect.outcome = TraversalOutcome::ExpiryUnknown;
            effect.cleanup = TraversalCleanup::ExpiryUnknown;
            effect.refusal = Some(refusal);
            effect.error = Some(TraversalErrorClass::CleanupFailed);
            effect.requests_sent = 0;
            effect
        }
        DeleteAttempt::Confirmed => {
            effect.cleanup = TraversalCleanup::ConfirmedDeleted;
            effect.requests_sent = 1;
            effect.error = None;
            if effect.refusal.is_none() {
                effect.outcome = TraversalOutcome::Succeeded;
            }
            effect
        }
        DeleteAttempt::Rejected => {
            effect.cleanup = TraversalCleanup::DeleteFailed;
            effect.refusal = Some(MappingRefusal::Denied);
            effect.error = Some(TraversalErrorClass::CleanupFailed);
            effect.requests_sent = 1;
            if finite {
                effect.outcome = TraversalOutcome::Failed;
            }
            effect
        }
        DeleteAttempt::Unknown { refusal, error } => {
            effect.outcome = TraversalOutcome::ExpiryUnknown;
            effect.cleanup = TraversalCleanup::ExpiryUnknown;
            effect.refusal = Some(refusal);
            effect.error = Some(error);
            effect.requests_sent = 1;
            effect
        }
    }
}

fn cleanup_unusable(
    gateway: &SelectedGateway,
    input: &UpnpMap<'_>,
    reservation: &ExclusiveReservation,
    lease: u32,
    transport: &mut dyn ControlTransport,
    cancelled: &dyn Fn() -> bool,
) -> MappingEffect {
    let handle = owned_handle(input, reservation, lease, true);
    let mut effect = super::delete_owned_mapping(
        gateway,
        &handle,
        Some(reservation),
        None,
        transport,
        cancelled,
        Some(input.descriptor),
    );
    effect.requests_sent = effect.requests_sent.saturating_add(3);
    let finite =
        (1..=input.maximum_lease_sec.into()).contains(&lease) && lease <= MAPPING_MAXIMUM_LEASE_SEC;
    if !finite {
        effect.outcome = TraversalOutcome::UnsupportedFiniteLease;
        if effect.cleanup == TraversalCleanup::ConfirmedDeleted {
            effect.refusal = Some(MappingRefusal::OverlongOrZeroGrant);
            effect.error = None;
        } else if effect.refusal != Some(MappingRefusal::Cancelled) {
            effect.refusal = Some(MappingRefusal::OverlongOrZeroGrant);
            effect.error = Some(TraversalErrorClass::CleanupFailed);
        }
        return effect;
    }
    effect.outcome = TraversalOutcome::Failed;
    if effect.cleanup == TraversalCleanup::ConfirmedDeleted {
        effect.refusal = Some(MappingRefusal::Denied);
        effect.error = None;
    } else if effect.refusal != Some(MappingRefusal::Cancelled) {
        effect.refusal = Some(MappingRefusal::Denied);
        effect.error = Some(TraversalErrorClass::CleanupFailed);
    }
    effect
}

fn adopt(input: &UpnpMap<'_>, reservation: &ExclusiveReservation, lease: u32) -> MappingEffect {
    let mut effect = super::blank(RouterProtocol::UpnpIgd);
    effect.outcome = TraversalOutcome::Succeeded;
    effect.cleanup = TraversalCleanup::LeaseExpiryPending;
    effect.requests_sent = 3;
    effect.granted_lifetime_sec = Some(lease);
    effect.assigned_port = Some(input.internal_port);
    effect.lease_clamped = lease < MAPPING_REQUESTED_LEASE_SEC;
    effect.handle = Some(owned_handle(input, reservation, lease, true));
    effect
}

fn owned_handle(
    input: &UpnpMap<'_>,
    reservation: &ExclusiveReservation,
    lease: u32,
    cleanup_authorized: bool,
) -> OwnedMappingHandle {
    OwnedMappingHandle {
        protocol: RouterProtocol::UpnpIgd,
        port_protocol: input.protocol,
        internal_port: input.internal_port,
        external_port: input.internal_port,
        client: input.local_address,
        granted_lifetime_sec: lease,
        epoch: 0,
        nonce: Some(control_fingerprint(input.descriptor)),
        reservation_digest: Some(reservation.digest),
        cleanup_authorized,
        external_address: None,
    }
}

fn existing_entry() -> MappingEffect {
    let mut effect = super::blank(RouterProtocol::UpnpIgd);
    effect.outcome = TraversalOutcome::Failed;
    effect.cleanup = TraversalCleanup::NotCreated;
    effect.refusal = Some(MappingRefusal::Conflict);
    effect.error = Some(TraversalErrorClass::MappingConflict);
    effect.requests_sent = 1;
    effect
}

fn unread_probe(refusal: MappingRefusal, error: TraversalErrorClass) -> MappingEffect {
    let mut effect = super::blank(RouterProtocol::UpnpIgd);
    effect.outcome = TraversalOutcome::UnsupportedSafeOwnership;
    effect.cleanup = TraversalCleanup::NotCreated;
    effect.refusal = Some(refusal);
    effect.error = Some(error);
    effect.requests_sent = 1;
    effect
}

fn stopped_before_create() -> MappingEffect {
    stopped_before_create_with(MappingRefusal::Cancelled)
}

fn stopped_before_create_with(refusal: MappingRefusal) -> MappingEffect {
    let mut effect = super::blank(RouterProtocol::UpnpIgd);
    effect.outcome = TraversalOutcome::Failed;
    effect.cleanup = TraversalCleanup::NotCreated;
    effect.refusal = Some(refusal);
    effect.requests_sent = 1;
    effect
}

fn permanent_only() -> MappingEffect {
    let mut effect = super::blank(RouterProtocol::UpnpIgd);
    effect.outcome = TraversalOutcome::UnsupportedFiniteLease;
    effect.cleanup = TraversalCleanup::NotCreated;
    effect.refusal = Some(MappingRefusal::OverlongOrZeroGrant);
    effect.error = Some(TraversalErrorClass::LeaseRefused);
    effect.requests_sent = 2;
    effect
}

fn add_conflict() -> MappingEffect {
    let mut effect = super::blank(RouterProtocol::UpnpIgd);
    effect.outcome = TraversalOutcome::Failed;
    effect.cleanup = TraversalCleanup::NotCreated;
    effect.refusal = Some(MappingRefusal::Conflict);
    effect.error = Some(TraversalErrorClass::MappingConflict);
    effect.requests_sent = 2;
    effect
}

fn add_rejected() -> MappingEffect {
    let mut effect = super::blank(RouterProtocol::UpnpIgd);
    effect.outcome = TraversalOutcome::Failed;
    effect.cleanup = TraversalCleanup::NotCreated;
    effect.refusal = Some(MappingRefusal::Denied);
    effect.error = Some(TraversalErrorClass::InvalidResponse);
    effect.requests_sent = 2;
    effect
}

fn lost_create(sent: u8, refusal: MappingRefusal, error: TraversalErrorClass) -> MappingEffect {
    let mut effect = super::blank(RouterProtocol::UpnpIgd);
    effect.outcome = TraversalOutcome::CreationOutcomeUnknown;
    effect.cleanup = TraversalCleanup::CreationOutcomeUnknown;
    effect.refusal = Some(refusal);
    effect.error = Some(error);
    effect.requests_sent = sent;
    effect
}

fn keep_ambiguous(mut effect: MappingEffect) -> MappingEffect {
    effect.outcome = TraversalOutcome::UnsupportedSafeOwnership;
    effect.cleanup = TraversalCleanup::ExpiryUnknown;
    effect.refusal = Some(MappingRefusal::AmbiguousOwnership);
    effect.requests_sent = 0;
    effect
}

enum Attempt {
    NotSent(MappingRefusal),
    Sent(MappingRefusal, TraversalErrorClass),
    Body(Vec<u8>),
}

fn attempt(
    gateway: &SelectedGateway,
    descriptor: &IgdControlDescriptor,
    action: &str,
    inner: &str,
    transport: &mut dyn ControlTransport,
    cancelled: &dyn Fn() -> bool,
) -> Attempt {
    if cancelled() {
        return Attempt::NotSent(MappingRefusal::Cancelled);
    }
    let request = match soap_request(descriptor, action, inner) {
        Ok(request) => request,
        Err(refusal) => return Attempt::NotSent(refusal),
    };
    // A refusal is local: the transport was not called. Once the request is
    // exchanged, every transport error is a lost reply. Unsupported, Oversize,
    // and WrongTarget from the transport are not proof that nothing was sent.
    match exchange_upnp_soap(
        gateway,
        &descriptor.control_target(),
        &request,
        transport,
        cancelled,
    ) {
        UpnpSoapReply::Exchanged(Ok(body)) => Attempt::Body(body),
        UpnpSoapReply::Refused(ControlRefusal::WrongTarget) => {
            Attempt::NotSent(MappingRefusal::ReservationGatewayMismatch)
        }
        UpnpSoapReply::Refused(ControlRefusal::Oversize | ControlRefusal::Unsupported) => {
            Attempt::NotSent(MappingRefusal::Malformed)
        }
        UpnpSoapReply::Refused(error) => Attempt::NotSent(super::transport_refusal(error)),
        UpnpSoapReply::Exchanged(Err(error)) => Attempt::Sent(
            super::transport_refusal(error),
            super::transport_error(error),
        ),
    }
}

enum DeleteAttempt {
    NotSent(MappingRefusal),
    Confirmed,
    Rejected,
    Unknown {
        refusal: MappingRefusal,
        error: TraversalErrorClass,
    },
}

fn transmit_delete(
    gateway: &SelectedGateway,
    descriptor: &IgdControlDescriptor,
    handle: &OwnedMappingHandle,
    transport: &mut dyn ControlTransport,
    cancelled: &dyn Fn() -> bool,
) -> DeleteAttempt {
    let inner = tuple_fields(handle.external_port, handle.port_protocol);
    match attempt(
        gateway,
        descriptor,
        "DeletePortMapping",
        &inner,
        transport,
        cancelled,
    ) {
        Attempt::NotSent(refusal) => DeleteAttempt::NotSent(refusal),
        Attempt::Sent(refusal, error) => DeleteAttempt::Unknown { refusal, error },
        Attempt::Body(bytes) => interpret_delete(&bytes),
    }
}

fn interpret_delete(bytes: &[u8]) -> DeleteAttempt {
    let view = match read_soap(bytes) {
        Ok(view) => view,
        Err(_) => {
            return DeleteAttempt::Unknown {
                refusal: MappingRefusal::Malformed,
                error: TraversalErrorClass::CleanupFailed,
            };
        }
    };
    if view.response == Some(ResponseKind::Delete) && view.error_code.is_none() {
        return DeleteAttempt::Confirmed;
    }
    if view.response == Some(ResponseKind::Fault) && view.error_code == Some(UPNP_ABSENT) {
        return DeleteAttempt::Confirmed;
    }
    if view.error_code.is_some() {
        return DeleteAttempt::Rejected;
    }
    DeleteAttempt::Unknown {
        refusal: MappingRefusal::AmbiguousOwnership,
        error: TraversalErrorClass::CleanupFailed,
    }
}

fn control_matches(
    gateway: &SelectedGateway,
    handle: &OwnedMappingHandle,
    control: &IgdControlDescriptor,
) -> bool {
    control.gateway() == gateway.gateway() && handle.nonce == Some(control_fingerprint(control))
}

fn control_fingerprint(descriptor: &IgdControlDescriptor) -> [u8; 12] {
    let material = format!(
        "{}|{}|{}",
        service_urn(descriptor.service()),
        descriptor.port(),
        descriptor.path_and_query()
    );
    let digest = Sha256::digest(material.as_bytes());
    let mut fingerprint = [0u8; 12];
    fingerprint.copy_from_slice(&digest[..12]);
    fingerprint
}

fn service_urn(kind: IgdServiceKind) -> &'static str {
    match kind {
        IgdServiceKind::WanIpConnection => "urn:schemas-upnp-org:service:WANIPConnection:1",
        IgdServiceKind::WanPppConnection => "urn:schemas-upnp-org:service:WANPPPConnection:1",
    }
}

fn protocol_name(protocol: MappedPortProtocol) -> &'static str {
    match protocol {
        MappedPortProtocol::Tcp => "TCP",
        MappedPortProtocol::Udp => "UDP",
    }
}

fn tuple_fields(port: u16, protocol: MappedPortProtocol) -> String {
    format!(
        "<NewRemoteHost></NewRemoteHost><NewExternalPort>{port}</NewExternalPort><NewProtocol>{}</NewProtocol>",
        protocol_name(protocol)
    )
}

fn add_fields(local: Ipv4Addr, port: u16, protocol: MappedPortProtocol) -> String {
    format!(
        "{}<NewInternalPort>{port}</NewInternalPort><NewInternalClient>{local}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>liskov</NewPortMappingDescription><NewLeaseDuration>{MAPPING_REQUESTED_LEASE_SEC}</NewLeaseDuration>",
        tuple_fields(port, protocol)
    )
}

fn soap_request(
    descriptor: &IgdControlDescriptor,
    action: &str,
    inner: &str,
) -> Result<Vec<u8>, MappingRefusal> {
    let path = descriptor.path_and_query();
    if !path.starts_with('/')
        || path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(MappingRefusal::Malformed);
    }
    let urn = service_urn(descriptor.service());
    let envelope = format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action} xmlns:u=\"{urn}\">{inner}</u:{action}></s:Body></s:Envelope>"
    );
    let host = format!("{}:{}", descriptor.gateway(), descriptor.port());
    if host
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(MappingRefusal::Malformed);
    }
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"{urn}#{action}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{envelope}",
        envelope.len()
    );
    if request.len() > UPNP_SOAP_MAX_BYTES {
        return Err(MappingRefusal::Malformed);
    }
    Ok(request.into_bytes())
}

enum Probe {
    Absent,
    Present,
    Unreadable(MappingRefusal),
}

fn classify_probe(bytes: &[u8]) -> Probe {
    let view = match read_soap(bytes) {
        Ok(view) => view,
        Err(_) => return Probe::Unreadable(MappingRefusal::Malformed),
    };
    match (view.response, view.error_code) {
        (Some(ResponseKind::Fault), Some(UPNP_ABSENT)) => Probe::Absent,
        (Some(ResponseKind::Get), None) => Probe::Present,
        (Some(ResponseKind::Fault), Some(_)) => {
            Probe::Unreadable(MappingRefusal::AmbiguousOwnership)
        }
        _ => Probe::Unreadable(MappingRefusal::Malformed),
    }
}

enum AddReply {
    Accepted,
    PermanentOnly,
    Conflict,
    Rejected,
    Unreadable(MappingRefusal),
}

fn classify_add(bytes: &[u8]) -> AddReply {
    let view = match read_soap(bytes) {
        Ok(view) => view,
        Err(_) => return AddReply::Unreadable(MappingRefusal::Malformed),
    };
    if view.response.is_some()
        && view.error_code.is_some()
        && view.response != Some(ResponseKind::Fault)
    {
        return AddReply::Unreadable(MappingRefusal::Malformed);
    }
    match view.error_code {
        Some(UPNP_PERMANENT_ONLY) => AddReply::PermanentOnly,
        Some(UPNP_CONFLICT) => AddReply::Conflict,
        Some(_) => AddReply::Rejected,
        None if view.response == Some(ResponseKind::Add) => AddReply::Accepted,
        None => AddReply::Unreadable(MappingRefusal::Malformed),
    }
}

enum Confirm {
    Usable { lease: u32 },
    OursButUnusable { lease: u32 },
    NotOurs,
    Absent,
    Unreadable,
}

fn classify_confirm(
    bytes: &[u8],
    local: Ipv4Addr,
    port: u16,
    protocol: MappedPortProtocol,
    ceiling: u32,
) -> Confirm {
    let view = match read_soap(bytes) {
        Ok(view) => view,
        Err(_) => return Confirm::Unreadable,
    };
    if view.response == Some(ResponseKind::Fault) && view.error_code == Some(UPNP_ABSENT) {
        return Confirm::Absent;
    }
    if view.response != Some(ResponseKind::Get) || view.error_code.is_some() {
        return Confirm::Unreadable;
    }
    let (Some(client), Some(seen_port), Some(lease), Some(enabled)) = (
        view.internal_client,
        view.internal_port,
        view.lease_sec,
        view.enabled,
    ) else {
        return Confirm::Unreadable;
    };
    if view.protocol.is_some_and(|seen| seen != protocol) || client != local || seen_port != port {
        return Confirm::NotOurs;
    }
    if enabled && (1..=ceiling).contains(&lease) {
        Confirm::Usable { lease }
    } else {
        Confirm::OursButUnusable { lease }
    }
}

enum ReadFault {
    Redirect,
    Malformed,
    Bounded,
}

struct SoapView {
    response: Option<ResponseKind>,
    error_code: Option<u16>,
    internal_client: Option<Ipv4Addr>,
    internal_port: Option<u16>,
    lease_sec: Option<u32>,
    enabled: Option<bool>,
    protocol: Option<MappedPortProtocol>,
}

impl SoapView {
    fn empty() -> Self {
        Self {
            response: None,
            error_code: None,
            internal_client: None,
            internal_port: None,
            lease_sec: None,
            enabled: None,
            protocol: None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResponseKind {
    Get,
    Add,
    Delete,
    Fault,
}

fn read_soap(bytes: &[u8]) -> Result<SoapView, ReadFault> {
    let body = parse_http(bytes)?;
    parse_xml(&body)
}

fn parse_http(bytes: &[u8]) -> Result<String, ReadFault> {
    if bytes.contains(&0) {
        return Err(ReadFault::Malformed);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ReadFault::Malformed)?;
    let Some((head, body)) = text.split_once("\r\n\r\n") else {
        return Err(ReadFault::Malformed);
    };
    let mut lines = head.split("\r\n");
    let status = lines.next().ok_or(ReadFault::Malformed)?;
    let mut parts = status.split_whitespace();
    let version = parts.next().ok_or(ReadFault::Malformed)?;
    let code = parts.next().ok_or(ReadFault::Malformed)?;
    if !version.starts_with("HTTP/1.") {
        return Err(ReadFault::Malformed);
    }
    let code: u16 = code.parse().map_err(|_| ReadFault::Malformed)?;
    if matches!(code, 301 | 302 | 303 | 307 | 308) {
        return Err(ReadFault::Redirect);
    }
    if code != 200 && code != 500 {
        return Err(ReadFault::Malformed);
    }
    let mut content_length = None;
    let mut headers = 0usize;
    for line in lines {
        headers = headers.saturating_add(1);
        if headers > 32 || line.starts_with(' ') || line.starts_with('\t') || line.is_empty() {
            return Err(ReadFault::Malformed);
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(ReadFault::Malformed);
        };
        if name.eq_ignore_ascii_case("Transfer-Encoding")
            && !value.trim().eq_ignore_ascii_case("identity")
        {
            return Err(ReadFault::Malformed);
        }
        if name.eq_ignore_ascii_case("Content-Length") {
            if content_length.is_some() {
                return Err(ReadFault::Malformed);
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| ReadFault::Malformed)?,
            );
        }
    }
    if content_length.is_some_and(|length| length > UPNP_SOAP_MAX_BYTES)
        || body.len() > UPNP_SOAP_MAX_BYTES
    {
        return Err(ReadFault::Bounded);
    }
    if let Some(length) = content_length {
        if body.len() != length {
            return Err(ReadFault::Malformed);
        }
    }
    Ok(body.to_owned())
}

fn parse_xml(input: &str) -> Result<SoapView, ReadFault> {
    let mut parser = XmlParser {
        input,
        index: 0,
        depth: 0,
        stack: Vec::new(),
        buffer: String::new(),
        capturing: None,
        view: SoapView::empty(),
    };
    parser.parse().map_err(|fault| match fault {
        ParseFault::Bounded => ReadFault::Bounded,
        ParseFault::Entity | ParseFault::Malformed => ReadFault::Malformed,
    })?;
    Ok(parser.view)
}

enum ParseFault {
    Malformed,
    Entity,
    Bounded,
}

struct XmlParser<'a> {
    input: &'a str,
    index: usize,
    depth: usize,
    stack: Vec<String>,
    buffer: String,
    capturing: Option<String>,
    view: SoapView,
}

impl XmlParser<'_> {
    fn parse(&mut self) -> Result<(), ParseFault> {
        if let Some(stripped) = self.input.strip_prefix('\u{feff}') {
            self.input = stripped;
        }
        self.skip_whitespace();
        if self.rest().starts_with("<?") {
            self.skip_declaration()?;
            self.skip_whitespace();
        }
        while self.index < self.input.len() {
            if self.rest().starts_with('<') {
                self.markup()?;
            } else {
                self.text()?;
            }
        }
        if !self.stack.is_empty() || self.capturing.is_some() {
            return Err(ParseFault::Malformed);
        }
        Ok(())
    }

    fn rest(&self) -> &str {
        &self.input[self.index..]
    }

    fn markup(&mut self) -> Result<(), ParseFault> {
        let rest = self.rest();
        if rest.starts_with("<!--") {
            self.skip_comment()
        } else if rest.starts_with("<![") {
            Err(ParseFault::Malformed)
        } else if rest.starts_with("<!") {
            Err(ParseFault::Entity)
        } else if rest.starts_with("<?") {
            Err(ParseFault::Malformed)
        } else if rest.starts_with("</") {
            self.end_tag()
        } else {
            self.start_tag()
        }
    }

    fn skip_comment(&mut self) -> Result<(), ParseFault> {
        let rest = self.rest();
        let Some(end) = rest.find("-->") else {
            return Err(ParseFault::Malformed);
        };
        if end < 4 || rest[4..end].contains("--") {
            return Err(ParseFault::Malformed);
        }
        self.index = self.index.saturating_add(end).saturating_add(3);
        Ok(())
    }

    fn skip_declaration(&mut self) -> Result<(), ParseFault> {
        let rest = self.rest();
        if !rest.starts_with("<?xml") {
            return Err(ParseFault::Malformed);
        }
        let Some(end) = rest.find("?>") else {
            return Err(ParseFault::Malformed);
        };
        if rest[2..end].contains('<') {
            return Err(ParseFault::Malformed);
        }
        self.index = self.index.saturating_add(end).saturating_add(2);
        Ok(())
    }

    fn start_tag(&mut self) -> Result<(), ParseFault> {
        self.index = self.index.saturating_add(1);
        let name = self.read_name()?;
        let self_closing = self.read_attributes()?;
        let local = local_name(&name).to_owned();
        self.note_element(&local)?;
        if self_closing {
            if self.capturing.as_deref() == Some(local.as_str()) {
                self.commit(&local)?;
            }
            return Ok(());
        }
        self.depth = self.depth.saturating_add(1);
        if self.depth > IGD_XML_MAX_DEPTH {
            return Err(ParseFault::Bounded);
        }
        self.stack.push(local);
        Ok(())
    }

    fn end_tag(&mut self) -> Result<(), ParseFault> {
        self.index = self.index.saturating_add(2);
        let name = self.read_name()?;
        self.skip_whitespace();
        if !self.rest().starts_with('>') {
            return Err(ParseFault::Malformed);
        }
        self.index = self.index.saturating_add(1);
        let frame = self.stack.pop().ok_or(ParseFault::Malformed)?;
        if frame != name && frame != local_name(&name) && local_name(&frame) != local_name(&name) {
            return Err(ParseFault::Malformed);
        }
        self.depth = self.depth.saturating_sub(1);
        let local = local_name(&name).to_owned();
        if self.capturing.as_deref() == Some(local.as_str()) {
            self.commit(&local)?;
        }
        Ok(())
    }

    fn note_element(&mut self, local: &str) -> Result<(), ParseFault> {
        let kind = match local {
            "GetSpecificPortMappingEntryResponse" => Some(ResponseKind::Get),
            "AddPortMappingResponse" => Some(ResponseKind::Add),
            "DeletePortMappingResponse" => Some(ResponseKind::Delete),
            "Fault" => Some(ResponseKind::Fault),
            _ => None,
        };
        if let Some(kind) = kind {
            if self.view.response.is_some() {
                return Err(ParseFault::Malformed);
            }
            self.view.response = Some(kind);
        }
        if matches!(
            local,
            "errorCode"
                | "NewInternalClient"
                | "NewInternalPort"
                | "NewLeaseDuration"
                | "NewEnabled"
                | "NewProtocol"
        ) {
            if self.capturing.is_some() {
                return Err(ParseFault::Malformed);
            }
            self.buffer.clear();
            self.capturing = Some(local.to_owned());
        }
        Ok(())
    }

    fn commit(&mut self, local: &str) -> Result<(), ParseFault> {
        let text = self.buffer.trim().to_owned();
        self.buffer.clear();
        self.capturing = None;
        if text.len() > SOAP_FIELD_MAX {
            return Err(ParseFault::Bounded);
        }
        match local {
            "errorCode" => {
                if self.view.error_code.is_some()
                    || text.is_empty()
                    || text.len() > 5
                    || !text.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(ParseFault::Malformed);
                }
                self.view.error_code = Some(text.parse().map_err(|_| ParseFault::Malformed)?);
            }
            "NewInternalClient" => {
                if self.view.internal_client.is_some() {
                    return Err(ParseFault::Malformed);
                }
                self.view.internal_client = Some(text.parse().map_err(|_| ParseFault::Malformed)?);
            }
            "NewInternalPort" => {
                if self.view.internal_port.is_some() {
                    return Err(ParseFault::Malformed);
                }
                self.view.internal_port = Some(text.parse().map_err(|_| ParseFault::Malformed)?);
            }
            "NewLeaseDuration" => {
                if self.view.lease_sec.is_some() {
                    return Err(ParseFault::Malformed);
                }
                self.view.lease_sec = Some(text.parse().map_err(|_| ParseFault::Malformed)?);
            }
            "NewEnabled" => {
                if self.view.enabled.is_some() {
                    return Err(ParseFault::Malformed);
                }
                self.view.enabled = Some(match text.as_str() {
                    "1" => true,
                    "0" => false,
                    _ => return Err(ParseFault::Malformed),
                });
            }
            "NewProtocol" => {
                if self.view.protocol.is_some() {
                    return Err(ParseFault::Malformed);
                }
                self.view.protocol = Some(match text.as_str() {
                    "TCP" => MappedPortProtocol::Tcp,
                    "UDP" => MappedPortProtocol::Udp,
                    _ => return Err(ParseFault::Malformed),
                });
            }
            _ => {}
        }
        Ok(())
    }

    fn read_attributes(&mut self) -> Result<bool, ParseFault> {
        let mut attributes = 0usize;
        loop {
            self.skip_whitespace();
            let rest = self.rest();
            if rest.starts_with("/>") {
                self.index = self.index.saturating_add(2);
                return Ok(true);
            }
            if rest.starts_with('>') {
                self.index = self.index.saturating_add(1);
                return Ok(false);
            }
            if rest.is_empty() {
                return Err(ParseFault::Malformed);
            }
            attributes = attributes.saturating_add(1);
            if attributes > 16 {
                return Err(ParseFault::Bounded);
            }
            let _name = self.read_name()?;
            self.skip_whitespace();
            if !self.rest().starts_with('=') {
                return Err(ParseFault::Malformed);
            }
            self.index = self.index.saturating_add(1);
            self.skip_whitespace();
            self.read_attribute_value()?;
        }
    }

    fn read_attribute_value(&mut self) -> Result<(), ParseFault> {
        let quote = self.rest().chars().next().ok_or(ParseFault::Malformed)?;
        if quote != '"' && quote != '\'' {
            return Err(ParseFault::Malformed);
        }
        self.index = self.index.saturating_add(quote.len_utf8());
        let start = self.index;
        while self.index < self.input.len() {
            let character = self.input[self.index..]
                .chars()
                .next()
                .ok_or(ParseFault::Malformed)?;
            if character == quote {
                let raw = &self.input[start..self.index];
                if raw.len() > SOAP_ATTRIBUTE_MAX {
                    return Err(ParseFault::Bounded);
                }
                decode_text(raw, &mut String::new(), true)?;
                self.index = self.index.saturating_add(character.len_utf8());
                return Ok(());
            }
            if character == '<' {
                return Err(ParseFault::Malformed);
            }
            self.index = self.index.saturating_add(character.len_utf8());
        }
        Err(ParseFault::Malformed)
    }

    fn text(&mut self) -> Result<(), ParseFault> {
        let start = self.index;
        while self.index < self.input.len() && !self.rest().starts_with('<') {
            let character = self.input[self.index..]
                .chars()
                .next()
                .ok_or(ParseFault::Malformed)?;
            self.index = self.index.saturating_add(character.len_utf8());
        }
        let raw = &self.input[start..self.index];
        if self.capturing.is_some() {
            decode_text(raw, &mut self.buffer, false)?;
            if self.buffer.len() > SOAP_FIELD_MAX {
                return Err(ParseFault::Bounded);
            }
        } else {
            decode_text(raw, &mut String::new(), true)?;
        }
        Ok(())
    }

    fn read_name(&mut self) -> Result<String, ParseFault> {
        let start = self.index;
        let Some(first) = self.rest().chars().next() else {
            return Err(ParseFault::Malformed);
        };
        if !first.is_ascii_alphabetic() && first != '_' {
            return Err(ParseFault::Malformed);
        }
        self.index = self.index.saturating_add(first.len_utf8());
        while let Some(character) = self.rest().chars().next() {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | ':') {
                self.index = self.index.saturating_add(character.len_utf8());
            } else {
                break;
            }
        }
        let name = &self.input[start..self.index];
        if name.is_empty() || name.len() > SOAP_FIELD_MAX {
            return Err(ParseFault::Malformed);
        }
        Ok(name.to_owned())
    }

    fn skip_whitespace(&mut self) {
        while let Some(character) = self.rest().chars().next() {
            if character.is_ascii_whitespace() {
                self.index = self.index.saturating_add(character.len_utf8());
            } else {
                break;
            }
        }
    }
}

fn local_name(name: &str) -> &str {
    name.rsplit_once(':')
        .map(|(_, local)| local)
        .unwrap_or(name)
}

fn decode_text(raw: &str, output: &mut String, discard: bool) -> Result<(), ParseFault> {
    let bytes = raw.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'&' {
            let character = raw[index..].chars().next().ok_or(ParseFault::Malformed)?;
            if !discard {
                output.push(character);
            }
            index = index.saturating_add(character.len_utf8());
            continue;
        }
        let rest = &raw[index..];
        let Some(end) = rest.find(';') else {
            return Err(ParseFault::Entity);
        };
        if end > 8 {
            return Err(ParseFault::Entity);
        }
        let token = &rest[..=end];
        let character = match token {
            "&amp;" => '&',
            "&lt;" => '<',
            "&gt;" => '>',
            "&quot;" => '"',
            "&apos;" => '\'',
            _ => return Err(ParseFault::Entity),
        };
        if !discard {
            output.push(character);
        }
        index = index.saturating_add(token.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::super::super::gateway::{RouteRecord, discover_loaded};
    use super::super::super::{
        GatewayDiscovery, IgdDiscovery, IgdDocuments, IgdIoError, IgdSearch, discover_igd,
    };
    use super::*;

    const DEVICE_XML: &str = include_str!("../../../vectors/igd-wanip-device.xml");
    const LIMITS: &str = include_str!("../../../vectors/upnp-igd-mapping-v1.json");
    const ABSENT: &str = include_str!("../../../vectors/upnp-igd-absent-714.xml");
    const EXISTING: &str = include_str!("../../../vectors/upnp-igd-existing-static.xml");
    const ADD_OK: &str = include_str!("../../../vectors/upnp-igd-add-ok.xml");
    const GRANT: &str = include_str!("../../../vectors/upnp-igd-grant-finite.xml");
    const OVERLONG: &str = include_str!("../../../vectors/upnp-igd-grant-overlong.xml");
    const CLAMPED: &str = include_str!("../../../vectors/upnp-igd-grant-clamped.xml");
    const ERROR_725: &str = include_str!("../../../vectors/upnp-igd-error-725.xml");
    const ERROR_718: &str = include_str!("../../../vectors/upnp-igd-error-718.xml");
    const DELETE_OK: &str = include_str!("../../../vectors/upnp-igd-delete-ok.xml");
    const DELETE_FAILED: &str = include_str!("../../../vectors/upnp-igd-delete-failed.xml");
    const ENTITY: &str = include_str!("../../../vectors/upnp-igd-entity.xml");

    fn never() -> bool {
        false
    }

    fn gateway_at(address: Ipv4Addr) -> SelectedGateway {
        match discover_loaded(
            &[RouteRecord::new(Ipv4Addr::UNSPECIFIED, 0, address, true, 1)],
            &never,
        ) {
            GatewayDiscovery::Selected(gateway) => gateway,
            other => panic!("gateway fixture {other:?}"),
        }
    }

    fn ssdp(location: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1\r\nLOCATION: {location}\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
        )
        .into_bytes()
    }

    struct ScriptedSearch {
        reply: Vec<u8>,
    }

    impl IgdSearch for ScriptedSearch {
        fn search(
            &mut self,
            _gateway: Ipv4Addr,
            _destination: SocketAddr,
            _request: &[u8],
            _cancelled: &dyn Fn() -> bool,
            _deadline_exceeded: &dyn Fn() -> bool,
        ) -> Result<Vec<Vec<u8>>, IgdIoError> {
            Ok(vec![self.reply.clone()])
        }
    }

    struct ScriptedDocs {
        body: Vec<u8>,
    }

    impl IgdDocuments for ScriptedDocs {
        fn get(
            &mut self,
            _url: &str,
            _socket: SocketAddr,
            _cancelled: &dyn Fn() -> bool,
            _deadline_exceeded: &dyn Fn() -> bool,
        ) -> Result<Vec<u8>, IgdIoError> {
            Ok(self.body.clone())
        }
    }

    fn descriptor_from(gateway: &SelectedGateway, device_xml: &str) -> IgdControlDescriptor {
        let mut search = ScriptedSearch {
            reply: ssdp(&format!("http://{}:5000/rootDesc.xml", gateway.gateway())),
        };
        let mut documents = ScriptedDocs {
            body: device_xml.as_bytes().to_vec(),
        };
        match discover_igd(gateway, &mut search, &mut documents, &never, &never) {
            IgdDiscovery::Found(descriptor) => descriptor,
            other => panic!("expected a descriptor, got {other:?}"),
        }
    }

    fn http(status: u16, body: &str) -> Vec<u8> {
        let reason = if status == 200 {
            "OK"
        } else {
            "Internal Server Error"
        };
        let body = body.trim_end_matches('\n');
        format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn ok_body(body: &str) -> Result<Vec<u8>, ControlRefusal> {
        Ok(http(200, body))
    }

    fn fault_body(body: &str) -> Result<Vec<u8>, ControlRefusal> {
        Ok(http(500, body))
    }

    struct Fake {
        sent: Vec<(SocketAddr, Vec<u8>)>,
        replies: Vec<Result<Vec<u8>, ControlRefusal>>,
        sends: Arc<AtomicUsize>,
    }

    impl ControlTransport for Fake {
        fn exchange(
            &mut self,
            destination: SocketAddr,
            request: &[u8],
            response: &mut [u8],
        ) -> Result<usize, ControlRefusal> {
            self.sends.fetch_add(1, Ordering::SeqCst);
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
                sends: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    struct Fixture {
        gateway: SelectedGateway,
        descriptor: IgdControlDescriptor,
        reservation: ExclusiveReservation,
    }

    fn fixture() -> Fixture {
        let gateway = gateway_at(Ipv4Addr::new(192, 0, 2, 1));
        let descriptor = descriptor_from(&gateway, DEVICE_XML);
        let reservation = ExclusiveReservation::new(gateway.gateway(), [9; 32]).unwrap();
        Fixture {
            gateway,
            descriptor,
            reservation,
        }
    }

    fn run(
        replies: Vec<Result<Vec<u8>, ControlRefusal>>,
        stop_after: Option<usize>,
    ) -> (MappingEffect, Fake, Fixture) {
        let fixture = fixture();
        let mut fake = Fake::new(replies);
        let sends = Arc::clone(&fake.sends);
        let input = UpnpMap {
            descriptor: &fixture.descriptor,
            local_address: Ipv4Addr::new(192, 0, 2, 10),
            internal_port: 40_000,
            protocol: MappedPortProtocol::Udp,
            maximum_lease_sec: 120,
            exclusive_reservation: Some(&fixture.reservation),
        };
        let effect = map_upnp(&fixture.gateway, &input, &mut fake, &|| {
            stop_after.is_some_and(|limit| sends.load(Ordering::SeqCst) >= limit)
        });
        assert_gateway_only(&fake, &fixture);
        assert_no_permanent_retry(&fake);
        (effect, fake, fixture)
    }

    fn assert_gateway_only(fake: &Fake, fixture: &Fixture) {
        for (destination, _) in &fake.sent {
            assert_eq!(*destination, fixture.descriptor.socket());
            assert_ne!(destination.port(), 5351);
        }
    }

    fn assert_no_permanent_retry(fake: &Fake) {
        for (_, bytes) in &fake.sent {
            let text = std::str::from_utf8(bytes).unwrap();
            assert!(!text.contains("<NewLeaseDuration>0</NewLeaseDuration>"));
            if text.contains("<u:AddPortMapping ") {
                assert!(text.contains("<NewLeaseDuration>60</NewLeaseDuration>"));
                assert!(text.contains("<NewInternalClient>192.0.2.10</NewInternalClient>"));
                assert!(!text.contains("<NewInternalClient>192.0.2.1</NewInternalClient>"));
            }
        }
    }

    fn actions(fake: &Fake) -> Vec<&'static str> {
        fake.sent
            .iter()
            .map(|(_, bytes)| {
                let text = std::str::from_utf8(bytes).unwrap();
                if text.contains("<u:DeletePortMapping ") {
                    "delete"
                } else if text.contains("<u:AddPortMapping ") {
                    "add"
                } else if text.contains("<u:GetSpecificPortMappingEntry ") {
                    "get"
                } else {
                    "other"
                }
            })
            .collect()
    }

    #[test]
    fn limits_match_the_mapping_vector() {
        let limits: serde_json::Value = serde_json::from_str(LIMITS).unwrap();
        assert_eq!(
            limits["soapMaxBytes"].as_u64(),
            Some(UPNP_SOAP_MAX_BYTES as u64)
        );
        assert_eq!(
            limits["xmlMaxDepth"].as_u64(),
            Some(IGD_XML_MAX_DEPTH as u64)
        );
        assert_eq!(
            limits["requestedLeaseSec"].as_u64(),
            Some(u64::from(MAPPING_REQUESTED_LEASE_SEC))
        );
        assert_eq!(
            limits["maximumLeaseSec"].as_u64(),
            Some(u64::from(MAPPING_MAXIMUM_LEASE_SEC))
        );
        assert_eq!(
            limits["highPortMin"].as_u64(),
            Some(u64::from(MAPPING_HIGH_PORT_MIN))
        );
        assert_eq!(limits["absentError"].as_u64(), Some(u64::from(UPNP_ABSENT)));
        assert_eq!(
            limits["conflictError"].as_u64(),
            Some(u64::from(UPNP_CONFLICT))
        );
        assert_eq!(
            limits["permanentOnlyError"].as_u64(),
            Some(u64::from(UPNP_PERMANENT_ONLY))
        );
        assert_eq!(
            limits["actions"].as_array().unwrap(),
            &[
                "GetSpecificPortMappingEntry",
                "AddPortMapping",
                "DeletePortMapping"
            ]
            .map(serde_json::Value::from)
        );
    }

    #[test]
    fn local_refusals_and_a_foreign_descriptor_send_nothing() {
        let fixture = fixture();
        let mut fake = Fake::new(vec![]);
        let mut input = UpnpMap {
            descriptor: &fixture.descriptor,
            local_address: Ipv4Addr::new(192, 0, 2, 10),
            internal_port: 80,
            protocol: MappedPortProtocol::Udp,
            maximum_lease_sec: 120,
            exclusive_reservation: Some(&fixture.reservation),
        };
        let effect = map_upnp(&fixture.gateway, &input, &mut fake, &never);
        assert_eq!(effect.refusal, Some(MappingRefusal::LowPort));
        assert_eq!(effect.outcome, TraversalOutcome::UnsupportedSafeOwnership);
        assert_eq!(effect.cleanup, TraversalCleanup::NotCreated);
        assert!(fake.sent.is_empty());

        input.internal_port = 40_000;
        input.maximum_lease_sec = 121;
        let effect = map_upnp(&fixture.gateway, &input, &mut fake, &never);
        assert_eq!(effect.refusal, Some(MappingRefusal::BadLifetimeCeiling));
        assert_eq!(effect.outcome, TraversalOutcome::UnsupportedFiniteLease);
        assert!(fake.sent.is_empty());

        input.maximum_lease_sec = 120;
        input.exclusive_reservation = None;
        let effect = map_upnp(&fixture.gateway, &input, &mut fake, &never);
        assert_eq!(effect.refusal, Some(MappingRefusal::MissingReservation));
        assert_eq!(effect.requests_sent, 0);
        assert!(fake.sent.is_empty());

        let other = ExclusiveReservation::new(Ipv4Addr::new(198, 51, 100, 1), [4; 32]).unwrap();
        input.exclusive_reservation = Some(&other);
        let effect = map_upnp(&fixture.gateway, &input, &mut fake, &never);
        assert_eq!(
            effect.refusal,
            Some(MappingRefusal::ReservationGatewayMismatch)
        );
        assert!(fake.sent.is_empty());

        input.exclusive_reservation = Some(&fixture.reservation);
        input.local_address = Ipv4Addr::UNSPECIFIED;
        let effect = map_upnp(&fixture.gateway, &input, &mut fake, &never);
        assert_eq!(effect.refusal, Some(MappingRefusal::BadClientAddress));
        assert!(fake.sent.is_empty());

        input.local_address = Ipv4Addr::new(192, 0, 2, 10);
        let foreign_gateway = gateway_at(Ipv4Addr::new(198, 51, 100, 8));
        let foreign = descriptor_from(&foreign_gateway, DEVICE_XML);
        input.descriptor = &foreign;
        let effect = map_upnp(&fixture.gateway, &input, &mut fake, &never);
        assert_eq!(
            effect.refusal,
            Some(MappingRefusal::ReservationGatewayMismatch)
        );
        assert!(fake.sent.is_empty());

        input.descriptor = &fixture.descriptor;
        let effect = map_upnp(&fixture.gateway, &input, &mut fake, &|| true);
        assert_eq!(effect.refusal, Some(MappingRefusal::Cancelled));
        assert_eq!(effect.cleanup, TraversalCleanup::NotCreated);
        assert!(fake.sent.is_empty());
    }

    #[test]
    fn an_existing_or_static_tuple_is_not_overwritten_or_deleted() {
        let (static_entry, static_fake, _) = run(vec![ok_body(EXISTING)], None);
        assert_eq!(static_entry.refusal, Some(MappingRefusal::Conflict));
        assert_eq!(static_entry.cleanup, TraversalCleanup::NotCreated);
        assert_eq!(static_entry.outcome, TraversalOutcome::Failed);
        assert!(static_entry.handle.is_none());
        assert_eq!(actions(&static_fake), ["get"]);

        let (ours, ours_fake, _) = run(vec![ok_body(GRANT)], None);
        assert_eq!(ours.refusal, Some(MappingRefusal::Conflict));
        assert_eq!(actions(&ours_fake), ["get"]);
        assert!(
            !std::str::from_utf8(&ours_fake.sent[0].1)
                .unwrap()
                .contains("DeletePortMapping")
        );
    }

    #[test]
    fn an_unreadable_probe_sends_no_mutation() {
        let (entity, entity_fake, _) = run(vec![fault_body(ENTITY)], None);
        assert_eq!(entity.outcome, TraversalOutcome::UnsupportedSafeOwnership);
        assert_eq!(entity.cleanup, TraversalCleanup::NotCreated);
        assert_eq!(actions(&entity_fake), ["get"]);

        let redirect =
            b"HTTP/1.1 302 Found\r\nLocation: http://198.51.100.9/ctl\r\nContent-Length: 0\r\n\r\n";
        let (redirected, redirect_fake, _) = run(vec![Ok(redirect.to_vec())], None);
        assert_eq!(redirected.cleanup, TraversalCleanup::NotCreated);
        assert_eq!(actions(&redirect_fake), ["get"]);

        let (lost, lost_fake, _) = run(vec![Err(ControlRefusal::Bounded)], None);
        assert_eq!(lost.outcome, TraversalOutcome::UnsupportedSafeOwnership);
        assert_ne!(lost.outcome, TraversalOutcome::CreationOutcomeUnknown);
        assert_eq!(lost_fake.sent.len(), 1);

        let commented = "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><!-- <errorCode>714</errorCode> --><s:Fault><detail><errorCode>501</errorCode></detail></s:Fault></s:Body></s:Envelope>";
        let (hidden, hidden_fake, _) = run(vec![fault_body(commented)], None);
        assert_eq!(hidden.cleanup, TraversalCleanup::NotCreated);
        assert_eq!(actions(&hidden_fake), ["get"]);

        let deep = format!("<r>{}</r>", "<a>".repeat(20) + &"</a>".repeat(20));
        let (nested, nested_fake, _) = run(vec![ok_body(&deep)], None);
        assert_eq!(nested.refusal, Some(MappingRefusal::Malformed));
        assert_eq!(actions(&nested_fake), ["get"]);
    }

    #[test]
    fn a_finite_grant_is_adopted_from_the_confirming_read() {
        let (effect, fake, adopted) = run(
            vec![fault_body(ABSENT), ok_body(ADD_OK), ok_body(GRANT)],
            None,
        );
        assert_eq!(effect.outcome, TraversalOutcome::Succeeded);
        assert_eq!(effect.cleanup, TraversalCleanup::LeaseExpiryPending);
        assert!(!effect.lease_clamped);
        assert!(!effect.port_changed);
        assert_eq!(effect.requests_sent, 3);
        assert_eq!(actions(&fake), ["get", "add", "get"]);
        let handle = effect.handle.unwrap();
        assert!(handle.cleanup_authorized());
        assert_eq!(handle.protocol(), RouterProtocol::UpnpIgd);
        assert_eq!(handle.internal_port(), 40_000);
        assert_eq!(handle.external_port(), 40_000);
        assert_eq!(handle.granted_lifetime_sec(), 60);
        let text = std::str::from_utf8(&fake.sent[1].1).unwrap();
        assert!(text.contains("POST /ctl/IPConn HTTP/1.1"));
        assert!(text.contains("Host: 192.0.2.1:5000"));
        assert!(text.contains(
            "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\""
        ));
        assert_eq!(fake.sent[0].0, adopted.descriptor.socket());

        let tcp_grant = GRANT.replace(
            "<NewProtocol>UDP</NewProtocol>",
            "<NewProtocol>TCP</NewProtocol>",
        );
        let fixture = fixture();
        let mut fake = Fake::new(vec![
            fault_body(ABSENT),
            ok_body(ADD_OK),
            ok_body(&tcp_grant),
        ]);
        let input = UpnpMap {
            descriptor: &fixture.descriptor,
            local_address: Ipv4Addr::new(192, 0, 2, 10),
            internal_port: 40_000,
            protocol: MappedPortProtocol::Tcp,
            maximum_lease_sec: 120,
            exclusive_reservation: Some(&fixture.reservation),
        };
        let effect = map_upnp(&fixture.gateway, &input, &mut fake, &never);
        assert_eq!(effect.outcome, TraversalOutcome::Succeeded);
        assert_eq!(
            effect.handle.unwrap().port_protocol(),
            MappedPortProtocol::Tcp
        );
        assert!(
            std::str::from_utf8(&fake.sent[1].1)
                .unwrap()
                .contains("<NewProtocol>TCP</NewProtocol>")
        );
    }

    #[test]
    fn a_clamped_lease_is_kept_and_725_does_not_retry_with_zero() {
        let (clamped, clamped_fake, _) = run(
            vec![fault_body(ABSENT), ok_body(ADD_OK), ok_body(CLAMPED)],
            None,
        );
        assert_eq!(clamped.outcome, TraversalOutcome::Succeeded);
        assert!(clamped.lease_clamped);
        assert_eq!(clamped.granted_lifetime_sec, Some(30));
        assert_eq!(clamped.handle.unwrap().granted_lifetime_sec(), 30);
        assert_eq!(actions(&clamped_fake), ["get", "add", "get"]);

        let (permanent, permanent_fake, _) =
            run(vec![fault_body(ABSENT), fault_body(ERROR_725)], None);
        assert_eq!(permanent.outcome, TraversalOutcome::UnsupportedFiniteLease);
        assert_eq!(permanent.cleanup, TraversalCleanup::NotCreated);
        assert_eq!(permanent.error, Some(TraversalErrorClass::LeaseRefused));
        assert!(permanent.handle.is_none());
        assert_eq!(permanent.requests_sent, 2);
        assert_eq!(actions(&permanent_fake), ["get", "add"]);

        let (conflict, conflict_fake, _) =
            run(vec![fault_body(ABSENT), fault_body(ERROR_718)], None);
        assert_eq!(conflict.refusal, Some(MappingRefusal::Conflict));
        assert_eq!(conflict.cleanup, TraversalCleanup::NotCreated);
        assert_eq!(actions(&conflict_fake), ["get", "add"]);
    }

    #[test]
    fn a_lost_create_is_not_not_created_and_is_not_deleted() {
        let (lost, lost_fake, _) =
            run(vec![fault_body(ABSENT), Err(ControlRefusal::Bounded)], None);
        assert_eq!(lost.outcome, TraversalOutcome::CreationOutcomeUnknown);
        assert_eq!(lost.cleanup, TraversalCleanup::CreationOutcomeUnknown);
        assert_ne!(lost.cleanup, TraversalCleanup::NotCreated);
        assert!(lost.handle.is_none());
        assert_eq!(actions(&lost_fake), ["get", "add"]);

        let (unconfirmed, unconfirmed_fake, _) = run(
            vec![
                fault_body(ABSENT),
                ok_body(ADD_OK),
                Err(ControlRefusal::Bounded),
            ],
            None,
        );
        assert_eq!(
            unconfirmed.outcome,
            TraversalOutcome::CreationOutcomeUnknown
        );
        assert_eq!(actions(&unconfirmed_fake), ["get", "add", "get"]);

        let other = GRANT.replace("192.0.2.10", "198.51.100.77");
        let (someone, someone_fake, _) = run(
            vec![fault_body(ABSENT), ok_body(ADD_OK), ok_body(&other)],
            None,
        );
        assert_eq!(someone.outcome, TraversalOutcome::CreationOutcomeUnknown);
        assert_eq!(someone.refusal, Some(MappingRefusal::AmbiguousOwnership));
        assert_eq!(actions(&someone_fake), ["get", "add", "get"]);
    }

    #[test]
    fn a_transport_error_after_add_is_a_lost_create() {
        for (error, refusal) in [
            (ControlRefusal::Unsupported, MappingRefusal::LostResponse),
            (ControlRefusal::WrongTarget, MappingRefusal::LostResponse),
            (ControlRefusal::Oversize, MappingRefusal::Malformed),
        ] {
            let (lost, lost_fake, _) = run(vec![fault_body(ABSENT), Err(error)], None);
            assert_eq!(lost.outcome, TraversalOutcome::CreationOutcomeUnknown);
            assert_eq!(lost.cleanup, TraversalCleanup::CreationOutcomeUnknown);
            assert_ne!(lost.cleanup, TraversalCleanup::NotCreated);
            assert_eq!(lost.refusal, Some(refusal));
            assert!(lost.handle.is_none());
            assert_eq!(lost.requests_sent, 2);
            assert_eq!(actions(&lost_fake), ["get", "add"]);
        }

        let (probe, probe_fake, _) = run(vec![Err(ControlRefusal::Unsupported)], None);
        assert_eq!(probe.outcome, TraversalOutcome::UnsupportedSafeOwnership);
        assert_eq!(probe.cleanup, TraversalCleanup::NotCreated);
        assert_eq!(probe.requests_sent, 1);
        assert_eq!(actions(&probe_fake), ["get"]);

        let (created, _, fixture) = run(
            vec![fault_body(ABSENT), ok_body(ADD_OK), ok_body(GRANT)],
            None,
        );
        let mut fake = Fake::new(vec![Err(ControlRefusal::Unsupported)]);
        let deleted = delete_owned(
            &fixture.gateway,
            &created.handle.unwrap(),
            Some(&fixture.descriptor),
            &mut fake,
            &never,
        );
        assert_eq!(deleted.outcome, TraversalOutcome::ExpiryUnknown);
        assert_eq!(deleted.cleanup, TraversalCleanup::ExpiryUnknown);
        assert_eq!(deleted.refusal, Some(MappingRefusal::LostResponse));
        assert_eq!(deleted.requests_sent, 1);
        assert_eq!(actions(&fake), ["delete"]);
    }

    #[test]
    fn an_overlong_grant_is_deleted_only_after_the_tuple_is_ours() {
        let (effect, fake, _) = run(
            vec![
                fault_body(ABSENT),
                ok_body(ADD_OK),
                ok_body(OVERLONG),
                ok_body(DELETE_OK),
            ],
            None,
        );
        assert_eq!(effect.outcome, TraversalOutcome::UnsupportedFiniteLease);
        assert_eq!(effect.cleanup, TraversalCleanup::ConfirmedDeleted);
        assert_eq!(effect.requests_sent, 4);
        assert_eq!(actions(&fake), ["get", "add", "get", "delete"]);
        assert!(effect.handle.unwrap().cleanup_authorized());
        let delete = std::str::from_utf8(&fake.sent[3].1).unwrap();
        assert!(delete.contains("<u:DeletePortMapping "));
        assert!(!delete.contains("NewLeaseDuration"));
        assert!(delete.contains("<NewExternalPort>40000</NewExternalPort>"));

        let (failed, failed_fake, fixture) = run(
            vec![
                fault_body(ABSENT),
                ok_body(ADD_OK),
                ok_body(OVERLONG),
                fault_body(DELETE_FAILED),
            ],
            None,
        );
        assert_eq!(failed.outcome, TraversalOutcome::UnsupportedFiniteLease);
        assert_eq!(failed.cleanup, TraversalCleanup::DeleteFailed);
        assert_eq!(failed.error, Some(TraversalErrorClass::CleanupFailed));
        let handle = failed.handle.unwrap();
        assert_eq!(handle.external_port(), 40_000);
        assert_eq!(actions(&failed_fake), ["get", "add", "get", "delete"]);

        let mut retry = Fake::new(vec![ok_body(DELETE_OK)]);
        let deleted = delete_owned(
            &fixture.gateway,
            &handle,
            Some(&fixture.descriptor),
            &mut retry,
            &never,
        );
        assert_eq!(deleted.cleanup, TraversalCleanup::ConfirmedDeleted);
        assert_eq!(deleted.outcome, TraversalOutcome::UnsupportedFiniteLease);
        assert_eq!(actions(&retry), ["delete"]);

        let (cancelled, cancelled_fake, _) = run(
            vec![fault_body(ABSENT), ok_body(ADD_OK), ok_body(OVERLONG)],
            Some(3),
        );
        assert_eq!(cancelled.outcome, TraversalOutcome::UnsupportedFiniteLease);
        assert_eq!(cancelled.cleanup, TraversalCleanup::ExpiryUnknown);
        assert_eq!(cancelled.refusal, Some(MappingRefusal::Cancelled));
        assert_eq!(actions(&cancelled_fake), ["get", "add", "get"]);
    }

    #[test]
    fn cancellation_and_explicit_delete_keep_independent_outcomes() {
        let (stopped, stopped_fake, _) = run(vec![fault_body(ABSENT)], Some(1));
        assert_eq!(stopped.cleanup, TraversalCleanup::NotCreated);
        assert_eq!(stopped.refusal, Some(MappingRefusal::Cancelled));
        assert_eq!(actions(&stopped_fake), ["get"]);

        let (created, _, fixture) = run(
            vec![fault_body(ABSENT), ok_body(ADD_OK), ok_body(GRANT)],
            None,
        );
        let handle = created.handle.unwrap();
        let mut fake = Fake::new(vec![]);
        let deleted = delete_owned(
            &fixture.gateway,
            &handle,
            Some(&fixture.descriptor),
            &mut fake,
            &|| true,
        );
        assert!(fake.sent.is_empty());
        assert_eq!(deleted.cleanup, TraversalCleanup::LeaseExpiryPending);
        assert_eq!(deleted.refusal, Some(MappingRefusal::Cancelled));
        assert_eq!(deleted.handle.unwrap().external_port(), 40_000);

        let mut fake = Fake::new(vec![fault_body(DELETE_FAILED)]);
        let deleted = super::super::delete_owned_mapping(
            &fixture.gateway,
            &handle,
            Some(&fixture.reservation),
            None,
            &mut fake,
            &never,
            Some(&fixture.descriptor),
        );
        assert_eq!(deleted.cleanup, TraversalCleanup::DeleteFailed);
        assert_eq!(deleted.error, Some(TraversalErrorClass::CleanupFailed));
        assert_eq!(deleted.handle.unwrap().granted_lifetime_sec(), 60);

        let mut fake = Fake::new(vec![ok_body(DELETE_OK)]);
        let deleted = delete_owned(
            &fixture.gateway,
            &handle,
            Some(&fixture.descriptor),
            &mut fake,
            &never,
        );
        assert_eq!(deleted.cleanup, TraversalCleanup::ConfirmedDeleted);
        assert_eq!(deleted.outcome, TraversalOutcome::Succeeded);
        assert!(
            std::str::from_utf8(&fake.sent[0].1)
                .unwrap()
                .contains("DeletePortMapping")
        );

        let mut fake = Fake::new(vec![ok_body(DELETE_OK)]);
        let mismatched = delete_owned(&fixture.gateway, &handle, None, &mut fake, &never);
        assert!(fake.sent.is_empty());
        assert_eq!(mismatched.refusal, Some(MappingRefusal::AmbiguousOwnership));
        assert_eq!(
            mismatched.outcome,
            TraversalOutcome::UnsupportedSafeOwnership
        );
    }

    #[test]
    fn a_ppp_descriptor_uses_its_own_control_target() {
        let gateway = gateway_at(Ipv4Addr::new(192, 0, 2, 1));
        let device = DEVICE_XML.replace(
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "urn:schemas-upnp-org:service:WANIPConnection:99",
        );
        let descriptor = descriptor_from(&gateway, &device);
        assert_eq!(descriptor.service(), IgdServiceKind::WanPppConnection);
        assert_eq!(descriptor.path_and_query(), "/ctl/PPP");
        let reservation = ExclusiveReservation::new(gateway.gateway(), [9; 32]).unwrap();
        let mut fake = Fake::new(vec![fault_body(ABSENT), fault_body(ERROR_725)]);
        let input = UpnpMap {
            descriptor: &descriptor,
            local_address: Ipv4Addr::new(192, 0, 2, 10),
            internal_port: 40_000,
            protocol: MappedPortProtocol::Udp,
            maximum_lease_sec: 120,
            exclusive_reservation: Some(&reservation),
        };
        let effect = map_upnp(&gateway, &input, &mut fake, &never);
        assert_eq!(effect.outcome, TraversalOutcome::UnsupportedFiniteLease);
        let text = std::str::from_utf8(&fake.sent[1].1).unwrap();
        assert!(text.contains("POST /ctl/PPP HTTP/1.1"));
        assert!(text.contains("WANPPPConnection:1#AddPortMapping"));
        assert_eq!(fake.sent[0].0.port(), 5000);
    }

    #[test]
    fn a_disabled_owned_tuple_is_removed_instead_of_adopted() {
        let disabled = GRANT.replace("<NewEnabled>1</NewEnabled>", "<NewEnabled>0</NewEnabled>");
        let (effect, fake, _) = run(
            vec![
                fault_body(ABSENT),
                ok_body(ADD_OK),
                ok_body(&disabled),
                ok_body(DELETE_OK),
            ],
            None,
        );
        assert_eq!(effect.outcome, TraversalOutcome::Failed);
        assert_eq!(effect.cleanup, TraversalCleanup::ConfirmedDeleted);
        assert_ne!(effect.outcome, TraversalOutcome::Succeeded);
        assert_eq!(actions(&fake), ["get", "add", "get", "delete"]);
    }
}
