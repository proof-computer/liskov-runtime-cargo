//! The processor-fact grant: the raw `processorFacts` bootstrap block, parsed
//! closed and checked against the one profile it names.

use std::collections::BTreeSet;

use serde::Deserialize;

use super::{
    AUTHORIZATION_FUTURE_TOLERANCE_MS, CARGO_BASELINE_PROFILE, HELPER_CONTRACT_EPOCH,
    MAX_AUTHORIZATION_LIFETIME_MS, PROCESSOR_FACT_AUTHORIZATION_DOMAIN, bounded_identifier,
    valid_hex, valid_sha256,
};
use crate::protocol::RuntimeBootstrapResponse;

/// The three catalog-admitted fact dimensions. No generic fact name or value
/// map exists, so forbidden properties cannot become serializable by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub enum ProcessorFactKind {
    #[serde(rename = "cargo_android_corroboration.v1")]
    AndroidCorroboration,
    #[serde(rename = "cargo_execution_surface.v1")]
    ExecutionSurface,
    #[serde(rename = "cargo_control_egress.v1")]
    ControlEgress,
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
            && self.profile == CARGO_BASELINE_PROFILE
            && valid_sha256(&self.catalog_digest)
            && self.helper_contract_epoch == HELPER_CONTRACT_EPOCH
            && !self.expected_helper_version.is_empty()
            && self.expected_helper_version.len() <= 64
            && self
                .expected_helper_version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
            && valid_sha256(&self.expected_helper_digest)
            && (1..=3).contains(&self.due_fact_kinds.len())
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
