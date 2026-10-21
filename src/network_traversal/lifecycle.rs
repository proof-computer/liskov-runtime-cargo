//! One-shot, dormant mapping lifecycle (BKLG-20261014-95bj; ADR-0234).
//!
//! Invoked only by an authenticated-bootstrap caller, never by the released
//! helper. The caller owns server-side one-shot consent consumption; this
//! non-Clone session is consumed once and delivery receives only its report.
//! No issuance, persistence, activation switch, renewals or delivery retries
//! live here. These are local summaries, not signed/admitted traversal proofs.
//!
//! Path control follows liskov-network-prober ecd9b478d4700d0cb55c761ec0dbf1adc068344f
//! (`path/check`, then `path/receipt`). Only that service's observed participant
//! address is a dial destination. Router addresses are comparison inputs only.

use std::net::{Ipv4Addr, SocketAddr};

use super::*;
use crate::inbound_reachability_contract::{INBOUND_PORT_MAX, INBOUND_PORT_MIN};

/// A conservative minimum window for a complete baseline/create/verify/delete
/// profile. Every actual I/O still receives the same absolute run deadline.
const METHOD_WINDOW_MS: u64 = 8_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingStop {
    Cancelled,
    Expired,
    GracefulShutdown,
    Deadline,
    Budget,
    InvalidBinding,
    Unsupported,
    CleanupUncertain,
}

/// Independent bindings from authenticated bootstrap and operator fixture
/// evidence, not fields copied from the grant being checked. No raw identity.
pub struct MappingBindings<'a> {
    pub claim_authority_digest: &'a str,
    pub artifact_digest: &'a str,
    pub helper: &'a TraversalHelperIdentity,
    pub consent_reference: &'a str,
    pub processor_allowlist_digest: &'a str,
    pub exclusive_reservation_digest: &'a str,
}

/// Consumed once. Construction performs no discovery, socket or router I/O.
/// The bootstrap caller authenticates the descriptor; native code holds no
/// capability/receipt MAC key and cannot replace that authentication.
pub struct MappingSession {
    descriptor: TraversalDescriptorV1,
    reservation: Reservation,
}

impl MappingSession {
    pub fn from_authenticated_bootstrap(
        descriptor: TraversalDescriptorV1,
        bindings: MappingBindings<'_>,
        now_ms: u64,
        job_expires_at_ms: u64,
    ) -> Result<Self, TraversalRefusal> {
        descriptor.can_start(now_ms, job_expires_at_ms, EXISTING_DELIVERY_RESERVE_MS)?;
        let consent = descriptor
            .mapping
            .as_ref()
            .ok_or(TraversalRefusal::InvalidConsent)?;
        if descriptor.mode != TraversalMode::Mapping
            || descriptor.claim_authority_digest != bindings.claim_authority_digest
            || descriptor.artifact_digest != bindings.artifact_digest
            || descriptor.helper_version != bindings.helper.version
            || descriptor.helper_digest != bindings.helper.digest
            || consent.consent_reference != bindings.consent_reference
            || consent.processor_allowlist_digest != bindings.processor_allowlist_digest
            || consent.exclusive_reservation_digest != bindings.exclusive_reservation_digest
        {
            return Err(TraversalRefusal::InvalidBinding);
        }
        let end = now_ms + descriptor.budgets.experiment_ms;
        let reservation = Reservation {
            experiment_ms: descriptor.budgets.experiment_ms,
            cleanup_reserve_ms: descriptor.budgets.cleanup_reserve_ms,
            delivery_reserve_ms: EXISTING_DELIVERY_RESERVE_MS,
            collector_end_ms: end,
            delivery_end_ms: end + EXISTING_DELIVERY_RESERVE_MS,
        };
        Ok(Self {
            descriptor,
            reservation,
        })
    }
}

/// Each entry gets a fresh dedicated listener and its own mapping state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappingMethodPlan {
    pub protocol: RouterProtocol,
    pub transport: MappedPortProtocol,
}

/// Selected gateway and independent, exclusive owned-fixture reservation.
/// External address is a bounded discovery result for NAT-PMP/UPnP, not a dial
/// destination. If unavailable, those methods cannot claim external reachability.
/// PCP uses its correlated MAP response instead. Never log this input.
pub struct MappingGateway<'a> {
    pub gateway: &'a SelectedGateway,
    pub reservation: &'a ExclusiveReservation,
    pub local_address: Ipv4Addr,
    pub external_address: Option<Ipv4Addr>,
    pub igd: Option<&'a IgdControlDescriptor>,
    /// Prior bounded discovery in this SAME run consumes the same allowance.
    /// Reading local routes costs no packets; SSDP/document requests do.
    pub discovery_datagrams: u16,
    pub discovery_control_requests: u16,
}

/// Runtime must bind a fresh high-port socket, retain it through cleanup, and
/// close it on drop. UDP has sent nothing before its unsolicited baseline.
pub trait MappingListener {
    fn port(&self) -> u16;
    /// Echo one bounded nonce per phase from the pinned prober IP. Called concurrently
    /// with authenticated path/check; the returned nonce must match its
    /// transcript. Unsupported runtimes must fail explicitly.
    fn answer_challenge(
        &mut self,
        _stage: TraversalStage,
        _source: std::net::IpAddr,
        _remaining: std::time::Duration,
    ) -> Result<[u8; 32], MappingStop> {
        Err(MappingStop::Unsupported)
    }
}

mod listener;
pub use listener::NativeMappingListener;

/// No destination address is accepted. The authenticated prober alone chooses
/// its same-participant observed destination. Stage/method are independently
/// checked against the returned transcript before any signing/admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappingPathCheck {
    pub stage: TraversalStage,
    pub method: TraversalMethod,
    pub transport: TraversalTransport,
    pub family: TraversalFamily,
    pub port: u16,
}

/// Authenticated path observation plus the locally echoed nonce. The runtime
/// echoes at most one 32-byte challenge from its pinned prober source on the
/// dedicated socket. It never signs a raw network packet. No Debug/serde.
pub struct MappingPathEvidence {
    pub transcript: TraversalTranscriptV1,
    pub echoed_challenge: Option<[u8; 32]>,
}

/// All effects are injected. Implementations MUST bound the whole operation by
/// deadline_ms (including partial reads), use only the pinned authenticated
/// prober, and send at most one control request per path_check/attest_path. The
/// listener may emit at most one UDP echo (<=512 bytes). No implicit retries.
/// Router exchange is exactly one request with bounded response storage.
/// `stop` is ordinary-work cancellation; cleanup deliberately ignores it.
pub trait MappingRuntime {
    fn now_ms(&self) -> u64;
    /// Same participant address observed by authenticated prober control, not
    /// a client/router supplied target. Valid only for this one-shot session.
    fn observed_address(&self) -> Ipv4Addr;
    fn stop(&self) -> Option<MappingStop>;
    fn nonce(&mut self) -> Result<[u8; 12], MappingStop>;
    fn bind_fresh(
        &mut self,
        transport: MappedPortProtocol,
    ) -> Result<Box<dyn MappingListener>, MappingStop>;
    fn path_check(
        &mut self,
        listener: &mut dyn MappingListener,
        check: MappingPathCheck,
        deadline_ms: u64,
    ) -> Result<MappingPathEvidence, MappingStop>;
    /// Invoked only after local scope/challenge validation. Sign the canonical
    /// transcript through the existing bridge signer, then fetch its receipt
    /// over authenticated control. Check that the receipt retains these exact
    /// transcript bytes and the returned signature. Device-signature admission
    /// remains with the API; native code never holds the prober MAC key.
    fn attest_path(
        &mut self,
        transcript: &TraversalTranscriptV1,
        deadline_ms: u64,
    ) -> Result<(), MappingStop>;
    fn router_exchange(
        &mut self,
        destination: SocketAddr,
        request: &[u8],
        response: &mut [u8],
        deadline_ms: u64,
    ) -> Result<usize, ControlRefusal>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappingPathSummary {
    pub stage: TraversalStage,
    pub outcome: TraversalOutcome,
    pub error: Option<TraversalErrorClass>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappingMethodReport {
    pub plan: MappingMethodPlan,
    pub baseline: Option<MappingPathSummary>,
    pub create: Option<TraversalOutcome>,
    pub granted_lease_sec: Option<u32>,
    pub verification: Option<MappingPathSummary>,
    pub cleanup: TraversalCleanup,
    /// Never turn a lost create into a known finite expiry or not_created.
    pub expiry_unknown: bool,
    pub stopped: Option<MappingStop>,
}

/// Tuple/token/nonce-free summaries only. Retrying delivery of this value has
/// no route back into the consumed MappingSession or any router operation.
#[derive(Debug, PartialEq, Eq)]
pub struct MappingRunReport {
    /// The selected gateway is already a bounded discovery output. This field
    /// is separate from create/lease/path/cleanup and asserts no router support.
    pub discovery: TraversalOutcome,
    pub methods: Vec<MappingMethodReport>,
    /// Combined profile exceeded time/dialback/packet limits: use separate
    /// profiles with fresh explicit consent, never automatically rearm this one.
    pub deferred_methods: usize,
    pub stopped: Option<MappingStop>,
    pub sent_datagrams: u16,
    pub control_requests: u16,
    pub external_dialbacks: u16,
}

struct Accounting {
    ordinary_datagrams: u16,
    ordinary_control: u16,
    cleanup_datagrams: u16,
    cleanup_control: u16,
    dialbacks: u16,
    sent_datagrams: u16,
    control_requests: u16,
    external_dialbacks: u16,
    datagram_bytes: u16,
}

impl Accounting {
    fn new(b: &TraversalBudgets) -> Self {
        // This subtraction happens before ANY discovery/baseline traffic.
        Self {
            ordinary_datagrams: b.outbound_datagrams - b.cleanup_datagrams,
            ordinary_control: b.control_requests - b.cleanup_control_requests,
            cleanup_datagrams: b.cleanup_datagrams,
            cleanup_control: b.cleanup_control_requests,
            dialbacks: b.external_dialbacks,
            sent_datagrams: 0,
            control_requests: 0,
            external_dialbacks: 0,
            datagram_bytes: b.datagram_bytes,
        }
    }
    fn charge(
        &mut self,
        datagrams: u16,
        controls: u16,
        dialbacks: u16,
        cleanup: bool,
    ) -> Result<(), MappingStop> {
        let (d, c) = if cleanup {
            (&mut self.cleanup_datagrams, &mut self.cleanup_control)
        } else {
            (&mut self.ordinary_datagrams, &mut self.ordinary_control)
        };
        if *d < datagrams || *c < controls || self.dialbacks < dialbacks {
            return Err(MappingStop::Budget);
        }
        *d -= datagrams;
        *c -= controls;
        self.dialbacks -= dialbacks;
        self.sent_datagrams += datagrams;
        self.control_requests += controls;
        self.external_dialbacks += dialbacks;
        Ok(()) // No refunds on lost replies, cancellation or failed sends.
    }
    fn fits(&self, plans: &[MappingMethodPlan], available_ms: u64) -> bool {
        let mut controls = 0;
        let mut datagrams = 0;
        let mut deletes_udp = 0;
        for plan in plans {
            let udp_router = plan.protocol != RouterProtocol::UpnpIgd;
            controls += 4 + if udp_router { 1 } else { 3 };
            datagrams +=
                u16::from(udp_router) + 2 * u16::from(plan.transport == MappedPortProtocol::Udp);
            deletes_udp += u16::from(udp_router);
        }
        controls <= self.ordinary_control
            && datagrams <= self.ordinary_datagrams
            && plans.len() <= usize::from(self.cleanup_control)
            && deletes_udp <= self.cleanup_datagrams
            && 2 * plans.len() <= usize::from(self.dialbacks)
            && (plans.len() as u64) * METHOD_WINDOW_MS <= available_ms
            && (datagrams + deletes_udp == 0 || self.datagram_bytes >= 60)
    }
}

fn method(protocol: RouterProtocol) -> TraversalMethod {
    match protocol {
        RouterProtocol::Pcp => TraversalMethod::Pcp,
        RouterProtocol::NatPmp => TraversalMethod::NatPmp,
        RouterProtocol::UpnpIgd => TraversalMethod::UpnpIgd,
    }
}
fn transport(protocol: MappedPortProtocol) -> TraversalTransport {
    match protocol {
        MappedPortProtocol::Tcp => TraversalTransport::Tcp,
        MappedPortProtocol::Udp => TraversalTransport::Udp,
    }
}
fn ordinary(runtime: &dyn MappingRuntime, end: u64) -> Result<(), MappingStop> {
    if let Some(stop) = runtime.stop() {
        return Err(stop);
    }
    if runtime.now_ms() >= end {
        return Err(MappingStop::Deadline);
    }
    Ok(())
}

/// Adapter calls include inline deletes for refused overlong leases. Recognize
/// only the adapters' exact delete encodings so they spend cleanup allowance
/// even when they occur inside create, never ordinary traffic's allowance.
fn delete_request(protocol: RouterProtocol, request: &[u8]) -> bool {
    match protocol {
        RouterProtocol::Pcp => request.len() == PCP_MAP_PACKET_BYTES && request[4..8] == [0; 4],
        RouterProtocol::NatPmp => {
            request.len() == NATPMP_MAP_REQUEST_BYTES && request[8..12] == [0; 4]
        }
        RouterProtocol::UpnpIgd => request
            .windows(b"#DeletePortMapping\"".len())
            .any(|w| w == b"#DeletePortMapping\""),
    }
}
struct BoundedControl<'a> {
    runtime: &'a mut dyn MappingRuntime,
    accounting: &'a mut Accounting,
    protocol: RouterProtocol,
    ordinary_end: u64,
    cleanup_end: u64,
    cleaning: bool,
}
impl ControlTransport for BoundedControl<'_> {
    fn exchange(
        &mut self,
        destination: SocketAddr,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, ControlRefusal> {
        let cleanup = self.cleaning || delete_request(self.protocol, request);
        let end = if cleanup {
            self.cleanup_end
        } else {
            self.ordinary_end
        };
        if self.runtime.now_ms() >= end || (!cleanup && self.runtime.stop().is_some()) {
            return Err(ControlRefusal::Bounded);
        }
        let datagrams = u16::from(self.protocol != RouterProtocol::UpnpIgd);
        if datagrams != 0 && request.len() > usize::from(self.accounting.datagram_bytes) {
            return Err(ControlRefusal::Oversize);
        }
        self.accounting
            .charge(datagrams, 1, 0, cleanup)
            .map_err(|_| ControlRefusal::Bounded)?;
        let count = self
            .runtime
            .router_exchange(destination, request, response, end)?;
        // Parse a correlated create reply even if ordinary time just expired:
        // discarding it would throw away the only safe owned cleanup handle.
        if count > response.len() || (cleanup && self.runtime.now_ms() >= end) {
            return Err(ControlRefusal::Bounded);
        }
        Ok(count)
    }
}

fn path(
    runtime: &mut dyn MappingRuntime,
    accounting: &mut Accounting,
    listener: &mut dyn MappingListener,
    descriptor: &TraversalDescriptorV1,
    check: MappingPathCheck,
    end: u64,
) -> Result<MappingPathSummary, MappingStop> {
    ordinary(runtime, end)?;
    accounting.charge(
        u16::from(check.transport == TraversalTransport::Udp),
        2,
        1,
        false,
    )?;
    let evidence = runtime.path_check(listener, check, end)?;
    ordinary(runtime, end)?;
    let t = &evidence.transcript;
    if t.validate_scope(descriptor, runtime.now_ms()).is_err()
        || t.authority != TraversalEvidenceAuthority::ExternalPath
        || t.stage != check.stage
        || t.method != check.method
        || t.transport != check.transport
        || t.family != check.family
        || !matches!(
            t.outcome,
            TraversalOutcome::Succeeded
                | TraversalOutcome::Failed
                | TraversalOutcome::UnverifiableEndpoint
                | TraversalOutcome::BudgetExhausted
                | TraversalOutcome::ProberNoEgress
        )
        || (t.outcome == TraversalOutcome::Succeeded
            && evidence
                .echoed_challenge
                .as_ref()
                .is_none_or(|c| hex::encode(c) != t.challenge))
    {
        return Err(MappingStop::InvalidBinding);
    }
    runtime.attest_path(t, end)?;
    ordinary(runtime, end)?;
    Ok(MappingPathSummary {
        stage: check.stage,
        outcome: t.outcome,
        error: t.error_class,
    })
}

/// Runs one bounded sequence; cancellation/unwind-free errors converge on the
/// same explicit cleanup block. Process death cannot run that block: the report
/// remains unknown unless the independently qualified gateway enforces expiry.
/// Do not wrap this in a delivery retry closure.
pub fn run_mapping_lifecycle(
    session: MappingSession,
    plans: &[MappingMethodPlan],
    gateway: MappingGateway<'_>,
    runtime: &mut dyn MappingRuntime,
) -> MappingRunReport {
    let d = &session.descriptor;
    let mut accounting = Accounting::new(&d.budgets);
    let mut report = MappingRunReport {
        discovery: TraversalOutcome::NotStarted,
        methods: vec![],
        deferred_methods: 0,
        stopped: None,
        sent_datagrams: 0,
        control_requests: 0,
        external_dialbacks: 0,
    };
    let consent = d.mapping.as_ref().expect("validated mapping session");
    let end = session.reservation.collector_end_ms;
    let active_end = end - session.reservation.cleanup_reserve_ms;
    let plan_ok = |p: &MappingMethodPlan| {
        let op = match p.protocol {
            RouterProtocol::Pcp => TraversalOperation::MapPcp,
            RouterProtocol::NatPmp => TraversalOperation::MapNatPmp,
            RouterProtocol::UpnpIgd => TraversalOperation::MapUpnp,
        };
        d.operations.contains(&op)
            && d.operations
                .contains(&if p.transport == MappedPortProtocol::Tcp {
                    TraversalOperation::BaselineTcp
                } else {
                    TraversalOperation::BaselineUdp
                })
    };
    if d.validate_at(runtime.now_ms()).is_err()
        || plans.is_empty()
        || plans.len() > 3
        || plans.iter().any(|p| !plan_ok(p))
        || plans
            .iter()
            .enumerate()
            .any(|(i, p)| plans[..i].contains(p))
        || !gateway
            .reservation
            .matches_binding(gateway.gateway, &consent.exclusive_reservation_digest)
    {
        report.stopped = Some(MappingStop::InvalidBinding);
        return report;
    }
    if accounting
        .charge(
            gateway.discovery_datagrams,
            gateway.discovery_control_requests,
            0,
            false,
        )
        .is_err()
    {
        report.stopped = Some(MappingStop::Budget);
        return report;
    }
    report.discovery = TraversalOutcome::Succeeded;
    report.sent_datagrams = accounting.sent_datagrams;
    report.control_requests = accounting.control_requests;
    let available = active_end.saturating_sub(runtime.now_ms());
    let selected = if accounting.fits(plans, available) {
        plans
    } else {
        report.deferred_methods = plans.len() - 1;
        &plans[..1]
    };
    if !accounting.fits(selected, available) {
        report.stopped = Some(MappingStop::Budget);
        return report;
    }
    for plan in selected {
        let mut row = MappingMethodReport {
            plan: *plan,
            baseline: None,
            create: None,
            granted_lease_sec: None,
            verification: None,
            cleanup: TraversalCleanup::NotCreated,
            expiry_unknown: false,
            stopped: None,
        };
        if let Err(stop) = ordinary(runtime, active_end) {
            report.stopped = Some(stop);
            break;
        }
        let mut listener = match runtime.bind_fresh(plan.transport) {
            Ok(l) => l,
            Err(stop) => {
                report.stopped = Some(stop);
                break;
            }
        };
        let port = listener.port();
        if !(INBOUND_PORT_MIN..=INBOUND_PORT_MAX).contains(&port) {
            report.stopped = Some(MappingStop::InvalidBinding);
            break;
        }
        let baseline = MappingPathCheck {
            stage: TraversalStage::Baseline,
            method: TraversalMethod::Unassisted,
            transport: transport(plan.transport),
            family: TraversalFamily::V4,
            port,
        };
        match path(
            runtime,
            &mut accounting,
            listener.as_mut(),
            d,
            baseline,
            active_end,
        ) {
            Ok(summary) => row.baseline = Some(summary),
            Err(stop) => {
                row.stopped = Some(stop);
                report.stopped = Some(stop);
                report.methods.push(row);
                break;
            }
        }
        // A valid failed dialback is still a measured baseline. Unsupported or
        // quota results are not a baseline and must not authorize mutation.
        if !matches!(
            row.baseline.unwrap().outcome,
            TraversalOutcome::Succeeded | TraversalOutcome::Failed
        ) {
            row.stopped = Some(MappingStop::Unsupported);
            report.methods.push(row);
            report.stopped = Some(MappingStop::Unsupported);
            break;
        }
        if let Err(stop) = ordinary(runtime, active_end) {
            row.stopped = Some(stop);
            report.methods.push(row);
            report.stopped = Some(stop);
            break;
        }
        // Recheck the complete remaining sequence BEFORE create. This reserves
        // deletion even when baseline consumed ordinary time or allowances.
        let cleanup_udp = u16::from(plan.protocol != RouterProtocol::UpnpIgd);
        if accounting.cleanup_control == 0
            || accounting.cleanup_datagrams < cleanup_udp
            || runtime.now_ms().saturating_add(1_000) >= active_end
        {
            row.stopped = Some(MappingStop::Budget);
            report.methods.push(row);
            report.stopped = Some(MappingStop::Budget);
            break;
        }
        let nonce = if plan.protocol == RouterProtocol::Pcp {
            match runtime.nonce() {
                Ok(n) if n != [0; 12] => n,
                _ => {
                    row.stopped = Some(MappingStop::Unsupported);
                    report.methods.push(row);
                    report.stopped = Some(MappingStop::Unsupported);
                    break;
                }
            }
        } else {
            [0; 12]
        };
        let mut control = BoundedControl {
            runtime,
            accounting: &mut accounting,
            protocol: plan.protocol,
            ordinary_end: active_end,
            cleanup_end: end,
            cleaning: false,
        };
        // The transport fences cancellation before every ordinary request. The
        // adapters' callback stays false so cancellation cannot suppress an
        // inline owned delete after an overlong response.
        let created = match plan.protocol {
            RouterProtocol::Pcp => map_pcp(
                gateway.gateway,
                &PcpMap {
                    local_address: gateway.local_address,
                    internal_port: port,
                    protocol: plan.transport,
                    nonce,
                    maximum_lease_sec: consent.maximum_lease_sec,
                    previous_epoch: None,
                    exclusive_reservation: Some(gateway.reservation),
                },
                &mut control,
                &|| false,
            ),
            RouterProtocol::NatPmp => map_nat_pmp(
                gateway.gateway,
                &NatPmpMap {
                    internal_port: port,
                    protocol: plan.transport,
                    maximum_lease_sec: consent.maximum_lease_sec,
                    previous_epoch: None,
                    exclusive_reservation: Some(gateway.reservation),
                },
                &mut control,
                &|| false,
            ),
            RouterProtocol::UpnpIgd => match gateway.igd {
                Some(igd) => map_upnp(
                    gateway.gateway,
                    &UpnpMap {
                        descriptor: igd,
                        local_address: gateway.local_address,
                        internal_port: port,
                        protocol: plan.transport,
                        maximum_lease_sec: consent.maximum_lease_sec,
                        exclusive_reservation: Some(gateway.reservation),
                    },
                    &mut control,
                    &|| false,
                ),
                None => {
                    row.stopped = Some(MappingStop::Unsupported);
                    report.methods.push(row);
                    report.stopped = Some(MappingStop::Unsupported);
                    break;
                }
            },
        };
        row.create = Some(created.outcome);
        row.granted_lease_sec = created.granted_lifetime_sec;
        row.cleanup = created.cleanup;
        if let Some(handle) = created
            .handle
            .filter(|_| created.cleanup == TraversalCleanup::LeaseExpiryPending)
        {
            if created.outcome == TraversalOutcome::Succeeded {
                let mapped_address = if plan.protocol == RouterProtocol::Pcp {
                    handle.external_address()
                } else {
                    gateway.external_address
                };
                // Missing address never substitutes the observed address or
                // invents router evidence. The runtime compares its discovery
                // address to its authenticated control-observed participant.
                if let Some(address) = mapped_address {
                    let check = MappingPathCheck {
                        stage: TraversalStage::MappingVerify,
                        method: method(plan.protocol),
                        port: handle.external_port(),
                        ..baseline
                    };
                    if !(INBOUND_PORT_MIN..=INBOUND_PORT_MAX).contains(&check.port) {
                        row.stopped = Some(MappingStop::InvalidBinding);
                    } else {
                        match address == runtime.observed_address() {
                            false => {
                                row.verification = Some(MappingPathSummary {
                                    stage: TraversalStage::MappingVerify,
                                    outcome: TraversalOutcome::UnverifiableEndpoint,
                                    error: None,
                                })
                            }
                            true => match path(
                                runtime,
                                &mut accounting,
                                listener.as_mut(),
                                d,
                                check,
                                active_end,
                            ) {
                                Ok(summary) => row.verification = Some(summary),
                                Err(stop) => row.stopped = Some(stop),
                            },
                        }
                    }
                } else {
                    row.verification = Some(MappingPathSummary {
                        stage: TraversalStage::MappingVerify,
                        outcome: TraversalOutcome::UnverifiableEndpoint,
                        error: None,
                    });
                }
            }
            // Always attempt explicit owned cleanup, even on cancellation,
            // job expiry or graceful shutdown. Never extend the absolute end.
            let cleanup_requests_before = accounting.control_requests;
            let mut control = BoundedControl {
                runtime,
                accounting: &mut accounting,
                protocol: plan.protocol,
                ordinary_end: active_end,
                cleanup_end: end,
                cleaning: true,
            };
            let deleted = delete_owned_mapping(
                gateway.gateway,
                &handle,
                Some(gateway.reservation),
                created.epoch,
                &mut control,
                &|| false,
                gateway.igd,
            );
            row.cleanup = match deleted.cleanup {
                TraversalCleanup::ConfirmedDeleted => TraversalCleanup::ConfirmedDeleted,
                _ if accounting.control_requests == cleanup_requests_before => {
                    TraversalCleanup::LeaseExpiryPending
                }
                _ => {
                    row.expiry_unknown = deleted.cleanup == TraversalCleanup::ExpiryUnknown;
                    TraversalCleanup::DeleteFailed
                }
            };
        }
        row.expiry_unknown |= matches!(
            row.cleanup,
            TraversalCleanup::CreationOutcomeUnknown | TraversalCleanup::ExpiryUnknown
        );
        let uncertain = !matches!(
            row.cleanup,
            TraversalCleanup::NotCreated | TraversalCleanup::ConfirmedDeleted
        );
        let stopped = row.stopped;
        report.methods.push(row);
        // Listener drops only after explicit cleanup. An uncertain mapping
        // suppresses every later method and requires operator resolution.
        if uncertain || stopped.is_some() {
            report.stopped = stopped.or(Some(MappingStop::CleanupUncertain));
            break;
        }
    }
    report.sent_datagrams = accounting.sent_datagrams;
    report.control_requests = accounting.control_requests;
    report.external_dialbacks = accounting.external_dialbacks;
    report
}

#[cfg(test)]
mod tests;
