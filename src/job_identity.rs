//! Shared strict identity semantics for credentials and direct discovery.
use serde_json::Value;

const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AcurastJobIdentity {
    origin: [u8; 32],
    sequence: u64,
}

/// Acurast exposes the same job through two JSON encodings: the control plane
/// persists `[origin, sequence]`, while the runtime bridge reports
/// `{origin: {kind: "Acurast", source: <hex>}, id: <sequence>}`. Preserve exact
/// matching for opaque IDs, but otherwise compare only a fully parsed Acurast
/// account and safe non-negative sequence. Unknown or malformed forms never
/// broaden credential authority.
pub(crate) fn runtime_job_ids_match(left: &str, right: &str) -> bool {
    left == right
        || match (acurast_job_identity(left), acurast_job_identity(right)) {
            (Some(left), Some(right)) => left == right,
            _ => false,
        }
}

fn acurast_job_identity(job_id: &str) -> Option<AcurastJobIdentity> {
    let value: Value = serde_json::from_str(job_id).ok()?;
    let (origin, raw_sequence) = match &value {
        Value::Array(items) if items.len() == 2 => (&items[0], &items[1]),
        Value::Object(object) => {
            let origin = object.get("origin")?;
            let sequence = match (object.get("sequence"), object.get("id")) {
                (Some(sequence), Some(id)) => (parse_safe_sequence(sequence)?
                    == parse_safe_sequence(id)?)
                .then_some(sequence)?,
                (Some(sequence), None) => sequence,
                (None, Some(id)) => id,
                (None, None) => return None,
            };
            (origin, sequence)
        }
        _ => return None,
    };
    Some(AcurastJobIdentity {
        origin: acurast_origin(origin)?,
        sequence: parse_safe_sequence(raw_sequence)?,
    })
}

fn parse_safe_sequence(value: &Value) -> Option<u64> {
    let sequence = match value {
        Value::Number(number) => number.as_u64()?,
        Value::String(string) if !string.trim().is_empty() => string.trim().parse().ok()?,
        _ => return None,
    };
    (sequence <= MAX_SAFE_JSON_INTEGER).then_some(sequence)
}

fn acurast_origin(value: &Value) -> Option<[u8; 32]> {
    let object = value.as_object()?;
    let marked_acurast = object.get("kind").and_then(Value::as_str) == Some("Acurast")
        || object.get("name").and_then(Value::as_str) == Some("Acurast")
        || object.contains_key("acurast");
    if !marked_acurast {
        return None;
    }
    if let Some(source) = object.get("source").and_then(Value::as_str) {
        return parse_origin_hex(source);
    }
    nested_origin_bytes(object.get("values")?)
}

fn parse_origin_hex(source: &str) -> Option<[u8; 32]> {
    let source = source.trim().strip_prefix("0x").unwrap_or(source.trim());
    if source.len() != 64 || !source.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let decoded = hex::decode(source).ok()?;
    decoded.try_into().ok()
}

fn nested_origin_bytes(value: &Value) -> Option<[u8; 32]> {
    let items = value.as_array()?;
    if items.len() == 32 {
        let bytes = items
            .iter()
            .map(|item| item.as_u64().and_then(|byte| u8::try_from(byte).ok()))
            .collect::<Option<Vec<_>>>()?;
        return bytes.try_into().ok();
    }
    items.iter().find_map(nested_origin_bytes)
}

/// A bounded directory key retains opaque equality and normalizes only the
/// same strict Acurast forms used for credential binding. JSON-shaped references
/// must parse completely; malformed structured IDs are never opaque fallbacks.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DirectoryJobKey<'a> {
    Acurast(AcurastJobIdentity),
    Opaque(&'a str),
}

pub(crate) fn directory_job_key(job_id: &str) -> Option<DirectoryJobKey<'_>> {
    if job_id.is_empty() || job_id.len() > 512 {
        return None;
    }
    match acurast_job_identity(job_id) {
        Some(identity) => Some(DirectoryJobKey::Acurast(identity)),
        None if job_id.trim_start().starts_with(['[', '{']) => None,
        None => Some(DirectoryJobKey::Opaque(job_id)),
    }
}
