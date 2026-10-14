//! Time reservation for the dormant traversal collector.
//!
//! Cleanup is already inside `experiment_ms` and is not added twice. The
//! delivery reserve is the helper's existing two-attempt budget, not a field
//! the grant can raise.

use super::{
    TRAVERSAL_CAPABILITY_DOMAIN, TraversalCapabilityV1, TraversalDescriptorV1, TraversalRefusal,
    lower_hex,
};

/// Two bounded coverage deliveries stay outside the collector. This is the
/// same 40 s floor `coverage` already leaves ahead of a bandwidth sample.
pub const EXISTING_DELIVERY_RESERVE_MS: u64 = 40_000;

/// Identity this build will accept on a traversal grant.
///
/// The digest is unpublished: this collector is dormant, and a grant that
/// names any other helper fails closed before discovery or submission.
pub struct TraversalHelperIdentity {
    pub version: &'static str,
    pub digest: &'static str,
}

pub const DORMANT_HELPER: TraversalHelperIdentity = TraversalHelperIdentity {
    version: env!("CARGO_PKG_VERSION"),
    digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
};

/// Injected seams. The dormant collector never calls the effect methods.
pub trait TraversalEffects {
    fn discover(&self);
    fn open_socket(&self);
    fn resolve_name(&self, host: &str);
    fn sign(&self, message: &[u8]);
    fn submit(&self, body: &[u8]);
    fn cancelled(&self) -> bool;
}

/// Production seams. Every method is a no-op so a mistake cannot touch the network.
pub struct NopTraversalEffects;

impl TraversalEffects for NopTraversalEffects {
    fn discover(&self) {}
    fn open_socket(&self) {}
    fn resolve_name(&self, _host: &str) {}
    fn sign(&self, _message: &[u8]) {}
    fn submit(&self, _body: &[u8]) {}
    fn cancelled(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reservation {
    pub experiment_ms: u64,
    pub cleanup_reserve_ms: u64,
    pub delivery_reserve_ms: u64,
    pub collector_end_ms: u64,
    pub delivery_end_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReserveOutcome {
    Absent,
    Refused(TraversalRefusal),
    Reserved(Reservation),
    SkippedBudget,
}

pub struct ReserveInput<'a> {
    pub grant: Option<&'a TraversalCapabilityV1>,
    pub now_ms: u64,
    pub job_expires_at_ms: u64,
    pub artifact_digest: &'a str,
    pub helper: &'a TraversalHelperIdentity,
    pub effects: &'a dyn TraversalEffects,
}

/// Structural admission used before the producer starts. Expiry is separate:
/// it needs the clock, which this function does not have.
pub fn grant_structure_ok(
    capability: &TraversalCapabilityV1,
    artifact_digest: &str,
    helper: &TraversalHelperIdentity,
) -> bool {
    capability.domain == TRAVERSAL_CAPABILITY_DOMAIN
        && lower_hex(&capability.mac, 32)
        && capability.descriptor.validate().is_ok()
        && capability.descriptor.helper_version == helper.version
        && capability.descriptor.helper_digest == helper.digest
        && capability.descriptor.artifact_digest == artifact_digest
}

/// Reserve the experiment, its included cleanup, and the existing delivery
/// attempts. Effect methods stay uncalled on every outcome. A refusal is
/// decided before cancellation, so an expired or unbound grant still fails
/// closed. Cancellation of a grant that fits only skips the collector.
pub fn reserve_traversal(input: &ReserveInput<'_>) -> ReserveOutcome {
    let Some(capability) = input.grant else {
        return ReserveOutcome::Absent;
    };
    if capability.domain != TRAVERSAL_CAPABILITY_DOMAIN {
        return ReserveOutcome::Refused(TraversalRefusal::WrongDomain);
    }
    if !lower_hex(&capability.mac, 32) {
        return ReserveOutcome::Refused(TraversalRefusal::InvalidMac);
    }
    if let Err(refusal) = capability.descriptor.validate() {
        return ReserveOutcome::Refused(refusal);
    }
    if capability.descriptor.helper_version != input.helper.version
        || capability.descriptor.helper_digest != input.helper.digest
        || capability.descriptor.artifact_digest != input.artifact_digest
    {
        return ReserveOutcome::Refused(TraversalRefusal::InvalidBinding);
    }
    match capability.descriptor.can_start(
        input.now_ms,
        input.job_expires_at_ms,
        EXISTING_DELIVERY_RESERVE_MS,
    ) {
        Ok(()) if input.effects.cancelled() => ReserveOutcome::SkippedBudget,
        Ok(()) => {
            let collector_end_ms = input
                .now_ms
                .saturating_add(capability.descriptor.budgets.experiment_ms);
            ReserveOutcome::Reserved(Reservation {
                experiment_ms: capability.descriptor.budgets.experiment_ms,
                cleanup_reserve_ms: capability.descriptor.budgets.cleanup_reserve_ms,
                delivery_reserve_ms: EXISTING_DELIVERY_RESERVE_MS,
                collector_end_ms,
                delivery_end_ms: collector_end_ms.saturating_add(EXISTING_DELIVERY_RESERVE_MS),
            })
        }
        Err(TraversalRefusal::InsufficientTime) => ReserveOutcome::SkippedBudget,
        Err(refusal) => ReserveOutcome::Refused(refusal),
    }
}

/// `can_start` succeeded only when both deadlines still hold the whole reserve.
pub fn reservation_fits(descriptor: &TraversalDescriptorV1, reservation: Reservation) -> bool {
    reservation.collector_end_ms <= descriptor.deadline_ms
        && reservation.delivery_end_ms <= descriptor.expires_at_ms
        && reservation.cleanup_reserve_ms <= reservation.experiment_ms
        && reservation.delivery_reserve_ms == EXISTING_DELIVERY_RESERVE_MS
}
