use super::*;

pub const TRAVERSAL_CAPABILITY_DOMAIN: &str = "proof.liskov.network-traversal-capability.v1";
const CAPABILITY_MAC_DOMAIN: &[u8] = b"proof.liskov.network-traversal-capability.v1\0";
const BEHAVIOUR_RECEIPT_MAC_DOMAIN: &[u8] =
    b"proof.liskov.network-traversal-behaviour-receipt.v1\0";
const PATH_RECEIPT_MAC_DOMAIN: &[u8] = b"proof.liskov.network-traversal-external-receipt.v1\0";
const REGISTRATION_RECEIPT_MAC_DOMAIN: &[u8] =
    b"proof.liskov.network-traversal-registration-receipt.v1\0";

/// A bounded canonical JSON capability, sent through authenticated control traffic.
/// API issuance policy is deliberately not implemented in this codec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraversalCapabilityV1 {
    pub domain: String,
    pub descriptor: TraversalDescriptorV1,
    pub mac: String,
}

fn mac_tag(key: &[u8; 32], domain: &[u8], message: &[u8]) -> ring::hmac::Tag {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    let mut payload = Vec::with_capacity(domain.len() + message.len());
    payload.extend_from_slice(domain);
    payload.extend_from_slice(message);
    ring::hmac::sign(&key, &payload)
}

fn verify_mac(
    key: &[u8; 32],
    domain: &[u8],
    message: &[u8],
    signature: &str,
) -> Result<(), TraversalRefusal> {
    if !lower_hex(signature, 32) {
        return Err(TraversalRefusal::InvalidMac);
    }
    let signature = hex::decode(signature).map_err(|_| TraversalRefusal::InvalidMac)?;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    let mut payload = Vec::with_capacity(domain.len() + message.len());
    payload.extend_from_slice(domain);
    payload.extend_from_slice(message);
    ring::hmac::verify(&key, &payload, &signature).map_err(|_| TraversalRefusal::InvalidMac)
}

/// Encode an already authorized immutable descriptor; does not grant authority or mint a run.
pub fn encode_traversal_capability(
    key: &[u8; 32],
    descriptor: &TraversalDescriptorV1,
) -> Result<Vec<u8>, TraversalRefusal> {
    let bytes = descriptor.canonical_bytes()?;
    let capability = TraversalCapabilityV1 {
        domain: TRAVERSAL_CAPABILITY_DOMAIN.into(),
        descriptor: descriptor.clone(),
        mac: hex::encode(mac_tag(key, CAPABILITY_MAC_DOMAIN, &bytes).as_ref()),
    };
    bounded(&capability, TRAVERSAL_BLOCK_MAX_BYTES)?;
    canonical(&capability)
}

pub fn decode_traversal_capability(
    key: &[u8; 32],
    bytes: &[u8],
    now_ms: u64,
) -> Result<TraversalDescriptorV1, TraversalRefusal> {
    if bytes.len() > TRAVERSAL_BLOCK_MAX_BYTES {
        return Err(TraversalRefusal::Oversize);
    }
    let capability: TraversalCapabilityV1 =
        serde_json::from_slice(bytes).map_err(|_| TraversalRefusal::Malformed)?;
    if capability.domain != TRAVERSAL_CAPABILITY_DOMAIN {
        return Err(TraversalRefusal::WrongDomain);
    }
    capability.descriptor.validate_at(now_ms)?;
    if canonical(&capability)? != bytes {
        return Err(TraversalRefusal::NonCanonical);
    }
    verify_mac(
        key,
        CAPABILITY_MAC_DOMAIN,
        &capability.descriptor.canonical_bytes()?,
        &capability.mac,
    )?;
    Ok(capability.descriptor)
}

fn receipt_domain(receipt: &TraversalReceiptV1) -> Result<&'static [u8], TraversalRefusal> {
    if receipt.version != 1 {
        return Err(TraversalRefusal::UnknownVersion);
    }
    receipt.transcript.validate()?;
    if receipt
        .device_signature
        .strip_prefix("0x")
        .is_none_or(|s| !lower_hex(s, 64))
    {
        return Err(TraversalRefusal::InvalidProof);
    }
    match receipt.transcript.authority {
        TraversalEvidenceAuthority::ExternalPath => Ok(PATH_RECEIPT_MAC_DOMAIN),
        TraversalEvidenceAuthority::ProberObservedBehaviour => Ok(BEHAVIOUR_RECEIPT_MAC_DOMAIN),
        TraversalEvidenceAuthority::ProberObservedRegistration => {
            Ok(REGISTRATION_RECEIPT_MAC_DOMAIN)
        }
        _ => Err(TraversalRefusal::InvalidProof),
    }
}

/// Canonical receipt MAC input: mac is the empty string, device signature is retained.
pub fn traversal_receipt_message(
    receipt: &TraversalReceiptV1,
) -> Result<Vec<u8>, TraversalRefusal> {
    receipt_domain(receipt)?;
    let mut unsigned = receipt.clone();
    unsigned.mac.clear();
    canonical(&unsigned)
}

pub fn sign_traversal_receipt(
    key: &[u8; 32],
    receipt: &mut TraversalReceiptV1,
) -> Result<(), TraversalRefusal> {
    let signature = mac_tag(
        key,
        receipt_domain(receipt)?,
        &traversal_receipt_message(receipt)?,
    );
    receipt.mac = hex::encode(signature.as_ref());
    bounded(receipt, TRAVERSAL_BLOCK_MAX_BYTES)
}

pub fn verify_traversal_receipt(
    key: &[u8; 32],
    receipt: &TraversalReceiptV1,
    descriptor: &TraversalDescriptorV1,
    now_ms: u64,
) -> Result<(), TraversalRefusal> {
    bounded(receipt, TRAVERSAL_BLOCK_MAX_BYTES)?;
    receipt.transcript.validate_scope(descriptor, now_ms)?;
    verify_mac(
        key,
        receipt_domain(receipt)?,
        &traversal_receipt_message(receipt)?,
        &receipt.mac,
    )
}
