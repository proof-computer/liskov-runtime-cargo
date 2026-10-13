//! Dark request-proof protocol for Cargo payload delivery (ADR-0230/0232).
//!
//! Sign the UTF-8 compact JSON emitted by `message`, with Ed25519 and the
//! chain-verified job signing key. Field order is declaration order, including
//! nested bindings. Do not trim, case-fold, omit null, or normalize paths.
//! Numeric values fit JavaScript safe integers; job sequences are decimal
//! strings. No locale-dependent key ordering or caller property bag is used.
//!
//! These are pure encodings and refusal checks, not an entitlement issuer.
//! The existing runtime authority must verify the signature, resolve canonical
//! job/tenant/launch/workload/key facts, atomically consume the nonce and retain
//! the exact storage reference. An unavailable authority never permits a read.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub mod descriptor;

use descriptor::{
    CargoPayloadDescriptorV1, PAYLOAD_MAX_SAFE_INTEGER, PayloadDescriptorRefusal,
    is_payload_sha256_digest,
};

pub const PAYLOAD_DOWNLOAD_DOMAIN_V1: &str = "proof.liskov.payload-download.v1";
pub const MAX_PAYLOAD_DOWNLOAD_ENVELOPE_BYTES: usize = 8192;
pub const MAX_PAYLOAD_DOWNLOAD_VALIDITY_MS: i64 = 60_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadDownloadRefusal {
    MalformedEnvelope,
    EnvelopeTooLarge,
    UnsupportedDomain,
    InvalidDigest,
    InvalidIdentity,
    InvalidJobReference,
    MethodMismatch,
    TargetMismatch,
    InvalidRange,
    RangeMismatch,
    RangeUnsatisfiable,
    Overflow,
    InvalidTime,
    NotYetValid,
    Expired,
    InvalidNonce,
    InvalidSignature,
    UnknownKey,
    NonceReplayed,
    WrongApplication,
    WrongJob,
    WrongIncarnation,
    WrongArtifact,
    WrongLaunch,
    WrongWorkload,
    UnsupportedEncryption,
    EntitlementRevoked,
    AuthorityUnavailable,
    InvalidAuthorization,
}

/// A normalized reference from the existing Acurast job owner. Origin key is
/// its canonical key (not a caller-selected public key or another job id).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PayloadJobRefV1 {
    pub origin_kind: String,
    pub origin_key: String,
    pub sequence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PayloadLaunchBindingV1 {
    pub launch_id: String,
    pub policy_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PayloadWorkloadBindingV1 {
    pub authorization_id: String,
    pub revision_digest: String,
    pub policy_digest: String,
}

/// Whole object or ONE closed inclusive byte range. Open-ended, suffix,
/// multipart and normalized aliases are deliberately unsupported in v1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PayloadDownloadRangeV1 {
    Whole {},
    Bytes { start: u64, end_inclusive: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PayloadByteSelectionV1 {
    pub offset: u64,
    pub length: u64,
}

impl PayloadDownloadRangeV1 {
    pub fn from_header(header: Option<&str>) -> Result<Self, PayloadDownloadRefusal> {
        let Some(header) = header else {
            return Ok(Self::Whole {});
        };
        let (start, end) = header
            .strip_prefix("bytes=")
            .and_then(|s| s.split_once('-'))
            .ok_or(PayloadDownloadRefusal::InvalidRange)?;
        let start = canonical_u64(start).ok_or(PayloadDownloadRefusal::InvalidRange)?;
        let end_inclusive = canonical_u64(end).ok_or(PayloadDownloadRefusal::InvalidRange)?;
        let range = Self::Bytes {
            start,
            end_inclusive,
        };
        range.validate()?;
        Ok(range)
    }

    fn validate(&self) -> Result<(), PayloadDownloadRefusal> {
        if let Self::Bytes {
            start,
            end_inclusive,
        } = self
        {
            if start > end_inclusive {
                return Err(PayloadDownloadRefusal::InvalidRange);
            }
            end_inclusive
                .checked_sub(*start)
                .and_then(|n| n.checked_add(1))
                .ok_or(PayloadDownloadRefusal::Overflow)?;
            if *end_inclusive > PAYLOAD_MAX_SAFE_INTEGER {
                return Err(PayloadDownloadRefusal::InvalidRange);
            }
        }
        Ok(())
    }

    pub fn select(
        &self,
        object_size: u64,
    ) -> Result<PayloadByteSelectionV1, PayloadDownloadRefusal> {
        self.validate()?;
        if object_size == 0 || object_size > PAYLOAD_MAX_SAFE_INTEGER {
            return Err(PayloadDownloadRefusal::RangeUnsatisfiable);
        }
        match self {
            Self::Whole {} => Ok(PayloadByteSelectionV1 {
                offset: 0,
                length: object_size,
            }),
            Self::Bytes {
                start,
                end_inclusive,
            } if *end_inclusive < object_size => Ok(PayloadByteSelectionV1 {
                offset: *start,
                length: end_inclusive - start + 1,
            }),
            Self::Bytes { .. } => Err(PayloadDownloadRefusal::RangeUnsatisfiable),
        }
    }
}

fn canonical_u64(text: &str) -> Option<u64> {
    if text.is_empty()
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return None;
    }
    text.parse().ok()
}

fn token(text: &str, max: usize) -> bool {
    !text.is_empty()
        && text.len() <= max
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}

fn lower_hex(text: &str, bytes: usize) -> bool {
    text.len() == bytes * 2
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn compact<T: Serialize>(value: &T) -> Result<Vec<u8>, PayloadDownloadRefusal> {
    serde_json::to_vec(value).map_err(|_| PayloadDownloadRefusal::MalformedEnvelope)
}

/// Signed fields only. `workload` serializes as explicit null for original
/// launch entitlement, or the exact admitted revision binding for an update.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PayloadDownloadRequestV1 {
    pub domain: String,
    pub method: String,
    pub request_target: String,
    pub range: PayloadDownloadRangeV1,
    pub artifact_digest: String,
    pub organisation_id: String,
    pub application_uid: String,
    pub job: PayloadJobRefV1,
    pub processor_id: String,
    pub runtime_instance_id: String,
    pub launch: PayloadLaunchBindingV1,
    #[serde(deserialize_with = "required_workload")]
    pub workload: Option<PayloadWorkloadBindingV1>,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    /// 32 bytes, lowercase hex, new for every download attempt.
    pub nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedPayloadDownloadRequestV1 {
    pub request: PayloadDownloadRequestV1,
    /// 64-byte Ed25519 signature, lowercase hex, without a prefix.
    pub signature: String,
}

fn required_workload<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<PayloadWorkloadBindingV1>, D::Error> {
    Option::deserialize(deserializer)
}

impl PayloadDownloadRequestV1 {
    pub fn validate(&self) -> Result<(), PayloadDownloadRefusal> {
        use PayloadDownloadRefusal as R;
        if self.domain != PAYLOAD_DOWNLOAD_DOMAIN_V1 {
            return Err(R::UnsupportedDomain);
        }
        if !is_payload_sha256_digest(&self.artifact_digest)
            || !is_payload_sha256_digest(&self.launch.policy_digest)
        {
            return Err(R::InvalidDigest);
        }
        if self.method != "GET" {
            return Err(R::MethodMismatch);
        }
        if self.request_target != format!("/v1/payloads/{}", self.artifact_digest) {
            return Err(R::TargetMismatch);
        }
        self.range.validate()?;
        if !token(&self.organisation_id, 128)
            || !token(&self.application_uid, 128)
            || !token(&self.processor_id, 128)
            || !token(&self.runtime_instance_id, 128)
            || !token(&self.launch.launch_id, 128)
        {
            return Err(R::InvalidIdentity);
        }
        // The canonical job owner still resolves supported origin kinds/keys.
        if !token(&self.job.origin_kind, 32)
            || !token(&self.job.origin_key, 256)
            || self.job.sequence.is_empty()
            || !self.job.sequence.bytes().all(|b| b.is_ascii_digit())
            || (self.job.sequence.len() > 1 && self.job.sequence.starts_with('0'))
            || self.job.sequence.parse::<u128>().is_err()
        {
            return Err(R::InvalidJobReference);
        }
        if let Some(workload) = &self.workload {
            if !token(&workload.authorization_id, 128) {
                return Err(R::InvalidIdentity);
            }
            if !is_payload_sha256_digest(&workload.revision_digest)
                || !is_payload_sha256_digest(&workload.policy_digest)
            {
                return Err(R::InvalidDigest);
            }
        }
        let span = self
            .expires_at_ms
            .checked_sub(self.issued_at_ms)
            .ok_or(R::Overflow)?;
        if self.issued_at_ms < 0
            || self.expires_at_ms as i128 > PAYLOAD_MAX_SAFE_INTEGER as i128
            || !(1..=MAX_PAYLOAD_DOWNLOAD_VALIDITY_MS).contains(&span)
        {
            return Err(R::InvalidTime);
        }
        if !lower_hex(&self.nonce, 32) {
            return Err(R::InvalidNonce);
        }
        Ok(())
    }

    pub fn message(&self) -> Result<Vec<u8>, PayloadDownloadRefusal> {
        self.validate()?;
        let bytes = compact(self)?;
        if bytes.len() > MAX_PAYLOAD_DOWNLOAD_ENVELOPE_BYTES {
            return Err(PayloadDownloadRefusal::EnvelopeTooLarge);
        }
        Ok(bytes)
    }

    pub fn request_digest(&self) -> Result<String, PayloadDownloadRefusal> {
        Ok(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(self.message()?))
        ))
    }

    /// Exact transport and time binding. The authority additionally bounds
    /// expiry by canonical entitlement/job expiry; time has no skew allowance.
    pub fn validate_transport(
        &self,
        method: &str,
        target: &str,
        range_header: Option<&str>,
        now_ms: i64,
    ) -> Result<(), PayloadDownloadRefusal> {
        self.validate()?;
        if method != self.method {
            return Err(PayloadDownloadRefusal::MethodMismatch);
        }
        if target != self.request_target {
            return Err(PayloadDownloadRefusal::TargetMismatch);
        }
        if PayloadDownloadRangeV1::from_header(range_header)? != self.range {
            return Err(PayloadDownloadRefusal::RangeMismatch);
        }
        if now_ms < self.issued_at_ms {
            return Err(PayloadDownloadRefusal::NotYetValid);
        }
        if now_ms >= self.expires_at_ms {
            return Err(PayloadDownloadRefusal::Expired);
        }
        Ok(())
    }

    /// Compare with facts resolved by the canonical runtime authority. A match
    /// is not permission: signature, replay, revocation and reference retention
    /// are separate checks owned there.
    pub fn validate_binding(
        &self,
        expected: &PayloadDownloadBindingV1,
    ) -> Result<(), PayloadDownloadRefusal> {
        self.validate()?;
        use PayloadDownloadRefusal as R;
        if self.organisation_id != expected.organisation_id
            || self.application_uid != expected.application_uid
        {
            return Err(R::WrongApplication);
        }
        if self.job != expected.job || self.processor_id != expected.processor_id {
            return Err(R::WrongJob);
        }
        if self.runtime_instance_id != expected.runtime_instance_id {
            return Err(R::WrongIncarnation);
        }
        if self.artifact_digest != expected.artifact_digest {
            return Err(R::WrongArtifact);
        }
        if self.launch != expected.launch {
            return Err(R::WrongLaunch);
        }
        if self.workload != expected.workload {
            return Err(R::WrongWorkload);
        }
        if self.expires_at_ms > expected.authorization_expires_at_ms {
            return Err(R::Expired);
        }
        Ok(())
    }
}

impl SignedPayloadDownloadRequestV1 {
    /// Parse before origin access. Unknown/duplicate fields, unsafe numbers,
    /// malformed signatures and oversized wire envelopes refuse.
    pub fn parse(bytes: &[u8]) -> Result<Self, PayloadDownloadRefusal> {
        if bytes.len() > MAX_PAYLOAD_DOWNLOAD_ENVELOPE_BYTES {
            return Err(PayloadDownloadRefusal::EnvelopeTooLarge);
        }
        let envelope: Self =
            serde_json::from_slice(bytes).map_err(|_| PayloadDownloadRefusal::MalformedEnvelope)?;
        envelope.request.validate()?;
        if !lower_hex(&envelope.signature, 64) {
            return Err(PayloadDownloadRefusal::InvalidSignature);
        }
        Ok(envelope)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PayloadDownloadBindingV1 {
    pub organisation_id: String,
    pub application_uid: String,
    pub job: PayloadJobRefV1,
    pub processor_id: String,
    pub runtime_instance_id: String,
    pub artifact_digest: String,
    pub launch: PayloadLaunchBindingV1,
    pub workload: Option<PayloadWorkloadBindingV1>,
    pub authorization_expires_at_ms: i64,
}

/// Fixed schema/declaration-order encoding: no enclosing archive hash can
/// refer to these bytes from inside that archive. SHA-256 is computed by the
/// artifact owner over this output and stored alongside the archive digest.
pub fn canonical_payload_descriptor_bytes(
    descriptor: &CargoPayloadDescriptorV1,
    artifact_limit_bytes: u64,
) -> Result<Vec<u8>, PayloadDescriptorRefusal> {
    descriptor.validate(artifact_limit_bytes)?;
    serde_json::to_vec(descriptor).map_err(|_| PayloadDescriptorRefusal::InvalidInventory)
}

#[cfg(test)]
mod tests;
