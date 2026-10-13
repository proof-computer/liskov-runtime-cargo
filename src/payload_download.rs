//! Dormant authenticated payload client. Only a fully verified return value may
//! be used by the later staging owner to publish a revision. Partial sink bytes
//! are untrusted, including after an error; this module never executes them.
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::bridge::Bridge;
use crate::contact::ContactRuntime;
use crate::http::{PayloadHttpClient, PayloadHttpError, PayloadHttpResponse};
use crate::payload_protocol::descriptor::CargoPayloadDescriptorV1;
use crate::payload_protocol::*;
use crate::protocol::{RuntimeBootstrapResponse, discover_runtime_identity};

pub const MAX_PAYLOAD_DESCRIPTOR_BYTES: usize = 256 * 1024;
pub const MAX_PAYLOAD_TRANSFER_ATTEMPTS: usize = 64;
const STREAM_BUFFER_BYTES: usize = 16 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PayloadError {
    #[error("invalid payload transfer budget")]
    Budget,
    #[error("unsupported payload capability")]
    UnsupportedCapability,
    #[error("invalid payload service origin")]
    InvalidOrigin,
    #[error("payload context binding mismatch")]
    Binding,
    #[error("payload protocol refusal: {0:?}")]
    Protocol(PayloadDownloadRefusal),
    #[error("invalid payload descriptor")]
    Descriptor,
    #[error("payload bridge operation failed")]
    Bridge,
    #[error("payload clock or randomness unavailable")]
    Runtime,
    #[error("payload response binding mismatch")]
    Response,
    #[error("payload authorization refused")]
    Refused,
    #[error("payload transfer incomplete")]
    Incomplete,
    #[error("payload integrity mismatch")]
    Integrity,
    #[error("payload staging write failed")]
    Write,
}
impl From<PayloadDownloadRefusal> for PayloadError {
    fn from(value: PayloadDownloadRefusal) -> Self {
        Self::Protocol(value)
    }
}

/// Local input seam for the authenticated context/control owner, not a new
/// server wire schema. The caller must obtain these facts through its bound
/// HTTPS context response, never manifest URLs, environment overrides or a
/// public Application pointer. No current startup path constructs this type.
pub struct AuthenticatedPayloadContext {
    pub capability_version: u32,
    pub service_origin: String,
    pub binding: PayloadDownloadBindingV1,
    pub descriptor_digest: String,
    pub canonical_descriptor: Vec<u8>,
}

/// Validated immutable context. No private object locator or alternate origin.
pub struct PayloadContext {
    origin: String,
    binding: PayloadDownloadBindingV1,
    descriptor_digest: String,
    descriptor: CargoPayloadDescriptorV1,
}
impl PayloadContext {
    /// Negotiate v1 against already-validated first contact. The owner supplies
    /// the artifact ceiling; no fallback or implicit quota increase is made.
    pub fn negotiate(
        bootstrap: &RuntimeBootstrapResponse,
        context: AuthenticatedPayloadContext,
        artifact_limit_bytes: u64,
        now_ms: i64,
    ) -> Result<Self, PayloadError> {
        if context.capability_version != 1 {
            return Err(PayloadError::UnsupportedCapability);
        }
        let origin =
            Url::parse(&context.service_origin).map_err(|_| PayloadError::InvalidOrigin)?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
        {
            return Err(PayloadError::InvalidOrigin);
        }
        let binding = &context.binding;
        if !bootstrap.ok
            || bootstrap.domain != crate::protocol::RUNTIME_BOOTSTRAP_RESPONSE_DOMAIN_V2
            || bootstrap.application_uid != binding.application_uid
            || bootstrap.processor_id != binding.processor_id
            || bootstrap.runtime_instance_id != binding.runtime_instance_id
            || bootstrap.policy_digest != binding.launch.policy_digest
            || bridge_job_ref(&bootstrap.job_id)? != binding.job
        {
            return Err(PayloadError::Binding);
        }
        if now_ms < 0 || now_ms >= binding.authorization_expires_at_ms {
            return Err(PayloadDownloadRefusal::Expired.into());
        }
        if context.canonical_descriptor.len() > MAX_PAYLOAD_DESCRIPTOR_BYTES
            || digest(&context.canonical_descriptor) != context.descriptor_digest
        {
            return Err(PayloadError::Descriptor);
        }
        let descriptor: CargoPayloadDescriptorV1 =
            serde_json::from_slice(&context.canonical_descriptor)
                .map_err(|_| PayloadError::Descriptor)?;
        let canonical = canonical_payload_descriptor_bytes(&descriptor, artifact_limit_bytes)
            .map_err(|_| PayloadError::Descriptor)?;
        if canonical != context.canonical_descriptor
            || descriptor.artifact_digest != binding.artifact_digest
        {
            return Err(PayloadError::Descriptor);
        }
        let result = Self {
            origin: origin.origin().ascii_serialization(),
            binding: context.binding,
            descriptor_digest: context.descriptor_digest,
            descriptor,
        };
        result
            .request(PayloadDownloadRangeV1::Whole {}, now_ms, "00".repeat(32))?
            .validate()?;
        Ok(result)
    }

    pub fn descriptor(&self) -> &CargoPayloadDescriptorV1 {
        &self.descriptor
    }
    pub fn descriptor_digest(&self) -> &str {
        &self.descriptor_digest
    }

    fn request(
        &self,
        range: PayloadDownloadRangeV1,
        now_ms: i64,
        nonce: String,
    ) -> Result<PayloadDownloadRequestV1, PayloadError> {
        if now_ms < 0 || now_ms >= self.binding.authorization_expires_at_ms {
            return Err(PayloadDownloadRefusal::Expired.into());
        }
        let expires = now_ms
            .checked_add(MAX_PAYLOAD_DOWNLOAD_VALIDITY_MS)
            .ok_or(PayloadDownloadRefusal::Overflow)?
            .min(self.binding.authorization_expires_at_ms);
        let request = PayloadDownloadRequestV1 {
            domain: PAYLOAD_DOWNLOAD_DOMAIN_V1.into(),
            method: "GET".into(),
            request_target: format!("/v1/payloads/{}", self.binding.artifact_digest),
            range,
            artifact_digest: self.binding.artifact_digest.clone(),
            organisation_id: self.binding.organisation_id.clone(),
            application_uid: self.binding.application_uid.clone(),
            job: self.binding.job.clone(),
            processor_id: self.binding.processor_id.clone(),
            runtime_instance_id: self.binding.runtime_instance_id.clone(),
            launch: self.binding.launch.clone(),
            workload: self.binding.workload.clone(),
            issued_at_ms: now_ms,
            expires_at_ms: expires,
            nonce,
        };
        request.validate_binding(&self.binding)?;
        Ok(request)
    }
}

/// Payload-only bridge conversion. It does not alter older bootstrap or
/// credential matching. Refuse unsupported origins instead of inventing keys;
/// full u128 decimal strings remain exact, and numeric JSON must be safe.
fn bridge_job_ref(text: &str) -> Result<PayloadJobRefV1, PayloadError> {
    let value: Value = serde_json::from_str(text).map_err(|_| PayloadError::Binding)?;
    let (origin, raw_sequence, alternate) = match &value {
        Value::Array(v) if v.len() == 2 => (&v[0], &v[1], None),
        Value::Object(v) => (
            v.get("origin").ok_or(PayloadError::Binding)?,
            v.get("sequence")
                .or_else(|| v.get("id"))
                .ok_or(PayloadError::Binding)?,
            v.get("id"),
        ),
        _ => return Err(PayloadError::Binding),
    };
    fn sequence(value: &Value) -> Option<String> {
        match value {
            Value::String(v)
                if !v.is_empty()
                    && v.bytes().all(|b| b.is_ascii_digit())
                    && (v.len() == 1 || !v.starts_with('0')) =>
            {
                v.parse::<u128>().ok().map(|n| n.to_string())
            }
            Value::Number(v) => v
                .as_u64()
                .filter(|n| *n <= descriptor::PAYLOAD_MAX_SAFE_INTEGER)
                .map(|n| n.to_string()),
            _ => None,
        }
    }
    let parsed = sequence(raw_sequence).ok_or(PayloadError::Binding)?;
    if alternate.is_some_and(|v| sequence(v).as_ref() != Some(&parsed)) {
        return Err(PayloadError::Binding);
    }
    if origin.get("kind").and_then(Value::as_str) != Some("Acurast") {
        return Err(PayloadError::Binding);
    }
    let key = origin
        .get("source")
        .and_then(Value::as_str)
        .ok_or(PayloadError::Binding)?;
    let raw = key.strip_prefix("0x").unwrap_or(key);
    if raw.len() != 64 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PayloadError::Binding);
    }
    Ok(PayloadJobRefV1 {
        origin_kind: "acurast".into(),
        origin_key: format!("0x{}", raw.to_ascii_lowercase()),
        sequence: parsed,
    })
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn now(runtime: &dyn ContactRuntime) -> Result<i64, PayloadError> {
    i64::try_from(runtime.unix_time_ms().map_err(|_| PayloadError::Runtime)?)
        .map_err(|_| PayloadError::Runtime)
}

/// A bounded invocation budget. The client does not reset it on resume, and
/// every new HTTP attempt consumes it, including failures before any bytes.
#[derive(Clone, Copy)]
pub struct PayloadTransferPolicy {
    pub max_attempts: usize,
    pub max_elapsed: Duration,
    pub retry_delay: Duration,
}

/// Proof of the exact complete bytes written by this call. It confers no
/// extraction, execution or entitlement authority.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedPayload {
    pub artifact_digest: String,
    pub descriptor_digest: String,
    pub size_bytes: u64,
}

pub fn download_payload(
    context: &PayloadContext,
    bridge: &dyn Bridge,
    http: &dyn PayloadHttpClient,
    runtime: &dyn ContactRuntime,
    sink: &mut dyn Write,
    policy: PayloadTransferPolicy,
) -> Result<VerifiedPayload, PayloadError> {
    if !(1..=MAX_PAYLOAD_TRANSFER_ATTEMPTS).contains(&policy.max_attempts)
        || policy.max_elapsed.is_zero()
    {
        return Err(PayloadError::Budget);
    }
    let identity = discover_runtime_identity(bridge).map_err(|_| PayloadError::Bridge)?;
    if identity.processor_id != context.binding.processor_id
        || bridge_job_ref(&identity.job_id)? != context.binding.job
    {
        return Err(PayloadError::Binding);
    }
    let started = runtime.elapsed();
    let mut hasher = Sha256::new();
    let mut offset = 0u64;
    let mut nonces = BTreeSet::new();
    let size = context.descriptor.artifact_size_bytes;
    for _ in 0..policy.max_attempts {
        if runtime.elapsed().saturating_sub(started) >= policy.max_elapsed {
            break;
        }
        let range = if offset == 0 {
            PayloadDownloadRangeV1::Whole {}
        } else {
            PayloadDownloadRangeV1::Bytes {
                start: offset,
                end_inclusive: size - 1,
            }
        };
        let mut random = [0u8; 32];
        runtime
            .fill_random(&mut random)
            .map_err(|_| PayloadError::Runtime)?;
        let nonce = hex::encode(random);
        if !nonces.insert(nonce.clone()) {
            return Err(PayloadDownloadRefusal::NonceReplayed.into());
        }
        let request = context.request(range.clone(), now(runtime)?, nonce)?;
        let signed = bridge
            .call(
                "signer_sign",
                json!([{ "curve": "ed25519", "bytes": hex::encode(request.message()?) }]),
            )
            .map_err(|_| PayloadError::Bridge)?;
        let raw = signed
            .get("bytes")
            .and_then(Value::as_str)
            .ok_or(PayloadError::Bridge)?;
        let signature = raw.strip_prefix("0x").unwrap_or(raw).to_ascii_lowercase();
        let envelope = SignedPayloadDownloadRequestV1 { request, signature };
        let body = serde_json::to_vec(&envelope).map_err(|_| PayloadError::Bridge)?;
        SignedPayloadDownloadRequestV1::parse(&body)?;
        let range_header = match range {
            PayloadDownloadRangeV1::Whole {} => None,
            PayloadDownloadRangeV1::Bytes {
                start,
                end_inclusive,
            } => Some(format!("bytes={start}-{end_inclusive}")),
        };
        envelope.request.validate_transport(
            "GET",
            &envelope.request.request_target,
            range_header.as_deref(),
            now(runtime)?,
        )?;
        let url = format!("{}{}", context.origin, envelope.request.request_target);
        let response = http.get(&url, &body, range_header.as_deref());
        match response {
            Err(PayloadHttpError::Transport) => {}
            Err(PayloadHttpError::Rejected) => return Err(PayloadError::Refused),
            Ok(mut response) => {
                if matches!(response.status, 408 | 429 | 500..=599) {
                    // No error body is read, buffered or logged.
                } else {
                    validate_response(context, &envelope.request, &response)?;
                    let mut remaining = size - offset;
                    let mut buffer = [0u8; STREAM_BUFFER_BYTES];
                    while remaining > 0 {
                        envelope.request.validate_transport(
                            "GET",
                            &envelope.request.request_target,
                            range_header.as_deref(),
                            now(runtime)?,
                        )?;
                        if runtime.elapsed().saturating_sub(started) >= policy.max_elapsed {
                            return Err(PayloadError::Incomplete);
                        }
                        let count =
                            usize::try_from(remaining.min(STREAM_BUFFER_BYTES as u64)).unwrap();
                        match response.body.read(&mut buffer[..count]) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                sink.write_all(&buffer[..n])
                                    .map_err(|_| PayloadError::Write)?;
                                hasher.update(&buffer[..n]);
                                offset += n as u64;
                                remaining -= n as u64;
                            }
                        }
                    }
                    if remaining == 0 {
                        let mut extra = [0u8; 1];
                        match response.body.read(&mut extra) {
                            Ok(0) => {}
                            Ok(_) => return Err(PayloadError::Response),
                            Err(_) => return Err(PayloadError::Incomplete),
                        }
                        envelope.request.validate_transport(
                            "GET",
                            &envelope.request.request_target,
                            range_header.as_deref(),
                            now(runtime)?,
                        )?;
                        if format!("sha256:{}", hex::encode(hasher.finalize()))
                            != context.binding.artifact_digest
                        {
                            return Err(PayloadError::Integrity);
                        }
                        sink.flush().map_err(|_| PayloadError::Write)?;
                        return Ok(VerifiedPayload {
                            artifact_digest: context.binding.artifact_digest.clone(),
                            descriptor_digest: context.descriptor_digest.clone(),
                            size_bytes: offset,
                        });
                    }
                }
            }
        }
        runtime.sleep(
            policy.retry_delay.min(
                policy
                    .max_elapsed
                    .saturating_sub(runtime.elapsed().saturating_sub(started)),
            ),
        );
    }
    Err(PayloadError::Incomplete)
}

fn validate_response(
    context: &PayloadContext,
    request: &PayloadDownloadRequestV1,
    response: &PayloadHttpResponse,
) -> Result<(), PayloadError> {
    let size = context.descriptor.artifact_size_bytes;
    let selection = request.range.select(size)?;
    let content_range = match request.range {
        PayloadDownloadRangeV1::Whole {} => None,
        PayloadDownloadRangeV1::Bytes {
            start,
            end_inclusive,
        } => Some(format!("bytes {start}-{end_inclusive}/{size}")),
    };
    if response.status != if content_range.is_some() { 206 } else { 200 } {
        return Err(if response.status == 401 || response.status == 403 {
            PayloadError::Refused
        } else {
            PayloadError::Response
        });
    }
    if response.content_length != Some(selection.length)
        || response.content_range != content_range
        || response.descriptor_digest != context.descriptor_digest
        || response.artifact_digest != context.binding.artifact_digest
        || response
            .content_encoding
            .as_deref()
            .is_some_and(|v| v != "identity")
    {
        return Err(PayloadError::Response);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
