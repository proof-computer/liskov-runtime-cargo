//! The processor-fact grant: the raw `processorFacts` bootstrap block, parsed
//! closed and checked against the one profile it names.
//!
//! Two profiles share this envelope and never a grant (Q-20260923-z2uc):
//! `cargo-baseline-v1` admits a non-empty subset of its three kinds, and
//! `coverage-hardware-v1` admits exactly `coverage_hardware_raw.v1`, alone. A
//! grant that names a kind of the other profile is not either profile's grant,
//! so it parses to nothing and nothing is read.

use std::collections::BTreeSet;

use serde::Deserialize;

use super::{
    AUTHORIZATION_FUTURE_TOLERANCE_MS, CARGO_BASELINE_PROFILE, COVERAGE_HARDWARE_PROFILE,
    HELPER_CONTRACT_EPOCH, MAX_AUTHORIZATION_LIFETIME_MS, PROCESSOR_FACT_AUTHORIZATION_DOMAIN,
    bounded_identifier, valid_hex, valid_sha256,
};
use crate::protocol::RuntimeBootstrapResponse;

/// Every catalog-admitted fact dimension, each owned by exactly one profile, in
/// canonical catalog order within its profile. No generic fact name or value
/// map exists, so forbidden properties cannot become serializable by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub enum ProcessorFactKind {
    #[serde(rename = "cargo_android_corroboration.v1")]
    AndroidCorroboration,
    #[serde(rename = "cargo_execution_surface.v1")]
    ExecutionSurface,
    #[serde(rename = "cargo_control_egress.v1")]
    ControlEgress,
    #[serde(rename = "coverage_hardware_raw.v1")]
    CoverageHardwareRaw,
}

impl ProcessorFactKind {
    /// The one profile whose catalog admits this kind.
    pub const fn profile(self) -> &'static str {
        match self {
            Self::AndroidCorroboration | Self::ExecutionSurface | Self::ControlEgress => {
                CARGO_BASELINE_PROFILE
            }
            Self::CoverageHardwareRaw => COVERAGE_HARDWARE_PROFILE,
        }
    }
}

/// How many due kinds a grant of `profile` may name, or `None` for a profile
/// this helper does not know.
fn admitted_kind_count(profile: &str) -> Option<std::ops::RangeInclusive<usize>> {
    match profile {
        CARGO_BASELINE_PROFILE => Some(1..=3),
        COVERAGE_HARDWARE_PROFILE => Some(1..=1),
        _ => None,
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessorFactAuthorization {
    pub(super) domain: String,
    pub(super) authorization_id: String,
    pub(super) challenge: String,
    pub(super) issued_at_ms: u64,
    pub(super) expires_at_ms: u64,
    pub(super) profile: String,
    pub(super) catalog_digest: String,
    pub(super) helper_contract_epoch: u64,
    pub(super) expected_helper_version: String,
    pub(super) expected_helper_digest: String,
    pub(super) due_fact_kinds: Vec<ProcessorFactKind>,
}

impl std::fmt::Debug for ProcessorFactAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessorFactAuthorization")
            .field("domain", &self.domain)
            .field("profile", &self.profile)
            .field("helper_contract_epoch", &self.helper_contract_epoch)
            .field("due_fact_kinds", &self.due_fact_kinds)
            .finish_non_exhaustive()
    }
}

impl ProcessorFactAuthorization {
    pub(super) fn structurally_valid(&self) -> bool {
        self.domain == PROCESSOR_FACT_AUTHORIZATION_DOMAIN
            && bounded_identifier(&self.authorization_id, 128)
            && valid_hex(&self.challenge, 32)
            && self.expires_at_ms > self.issued_at_ms
            && self
                .expires_at_ms
                .checked_sub(self.issued_at_ms)
                .is_some_and(|lifetime| lifetime <= MAX_AUTHORIZATION_LIFETIME_MS)
            && admitted_kind_count(&self.profile)
                .is_some_and(|count| count.contains(&self.due_fact_kinds.len()))
            && self
                .due_fact_kinds
                .iter()
                .all(|kind| kind.profile() == self.profile)
            && valid_sha256(&self.catalog_digest)
            && self.helper_contract_epoch == HELPER_CONTRACT_EPOCH
            && !self.expected_helper_version.is_empty()
            && self.expected_helper_version.len() <= 64
            && self
                .expected_helper_version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
            && valid_sha256(&self.expected_helper_digest)
            && self.due_fact_kinds.iter().collect::<BTreeSet<_>>().len()
                == self.due_fact_kinds.len()
    }

    pub(super) fn valid_at(&self, now_ms: u64) -> bool {
        self.structurally_valid()
            && self.expires_at_ms > now_ms
            && self.issued_at_ms <= now_ms.saturating_add(AUTHORIZATION_FUTURE_TOLERANCE_MS)
    }
}

/// Remove and parse the raw capability independently of bootstrap validity.
/// Any malformed, unknown, or out-of-contract content simply returns `None`.
pub fn take_processor_fact_authorization(
    bootstrap: &mut RuntimeBootstrapResponse,
) -> Option<ProcessorFactAuthorization> {
    let raw = bootstrap.processor_facts.take()?;
    let authorization: ProcessorFactAuthorization = serde_json::from_value(raw).ok()?;
    authorization.structurally_valid().then_some(authorization)
}
