//! Dormant ADR-0234 traversal grant decoder, result codec, and gateway seam.
//!
//! Issuance stays with the API. Grant checks reserve collector time and do not
//! discover a gateway, open an experiment socket, resolve DNS, or attach a
//! traversal block to a live submission. Gateway selection and router-control
//! adapters live in `gateway` and run only when a caller invokes them.

mod auth;
mod descriptor;
mod gateway;
mod proof;
mod reserve;
mod result;

pub use auth::*;
pub use descriptor::*;
pub use gateway::*;
pub use proof::*;
pub use reserve::*;
pub use result::*;

use serde::{Deserialize, Serialize};

pub const TRAVERSAL_BLOCK_MAX_BYTES: usize = 8 * 1024;
pub const TRAVERSAL_ENVELOPE_MAX_BYTES: usize = 16 * 1024;
pub const TRAVERSAL_CAPABILITY_MAX_MS: u64 = 120_000;
pub const TRAVERSAL_EXPERIMENT_MAX_MS: u64 = 30_000;
pub const TRAVERSAL_CLEANUP_RESERVE_MS: u64 = 5_000;
const SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Closed codec refusals. Experiment outcomes have their own closed vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalRefusal {
    Malformed,
    UnknownVersion,
    WrongDomain,
    InvalidBinding,
    InvalidScope,
    InvalidBudget,
    InvalidDeadline,
    InvalidConsent,
    InvalidPair,
    InvalidProof,
    Oversize,
    NotYetValid,
    Expired,
    InsufficientTime,
    InvalidMac,
    NonCanonical,
}

impl std::fmt::Display for TraversalRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for TraversalRefusal {}

pub(crate) fn text(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_graphic())
}

pub(crate) fn lower_hex(s: &str, bytes: usize) -> bool {
    s.len() == bytes * 2
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn digest(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(|s| lower_hex(s, 32))
}

pub(crate) fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, TraversalRefusal> {
    let value = serde_json::to_value(value).map_err(|_| TraversalRefusal::Malformed)?;
    Ok(crate::diagnostics::canonical_json_bytes(&value))
}

pub(crate) fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

pub(crate) fn bounded<T: Serialize>(value: &T, limit: usize) -> Result<(), TraversalRefusal> {
    if serde_json::to_vec(value)
        .map_err(|_| TraversalRefusal::Malformed)?
        .len()
        > limit
    {
        return Err(TraversalRefusal::Oversize);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
