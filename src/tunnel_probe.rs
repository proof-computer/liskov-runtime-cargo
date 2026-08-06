//! Evidence-gathering helpers for the Acurast Tunnel bridge surface.
//!
//! This module backs the feature-gated `liskov-tunnel-probe` binary. It never
//! participates in signed first contact or the supervised production path.
//!
//! The probe carries its own JSON-RPC client rather than reusing
//! [`crate::bridge::UnixBridge`]: the production client deliberately discards
//! the reply body of an RPC error (so a hostile reply cannot reach a log), but
//! the processor reports its one-active-tunnel limit only as an internal error
//! whose *message* is `tunnel already active`. Capturing that message is the
//! point of the probe, so the widened surface stays here instead of weakening
//! the production bridge.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

pub const TUNNEL_PROBE_DOMAIN: &str = "proof.liskov.tunnel-probe.v1";

pub const METHOD_START: &str = "tunnel_start";
pub const METHOD_STOP: &str = "tunnel_stop";
pub const METHOD_STATUS: &str = "tunnel_status";
pub const METHOD_CERT_PEM: &str = "tunnel_certPem";

/// Methods the probe will issue without an explicit mutation opt-in.
pub const READ_ONLY_METHODS: &[&str] = &[METHOD_STATUS, METHOD_CERT_PEM];
/// Methods that change processor state and require `--yes-mutate`.
pub const MUTATING_METHODS: &[&str] = &[METHOD_START, METHOD_STOP];

/// Read-only names walked by `discover`, most-likely-first.
///
/// The confirmed spelling comes from the 1.27.0-rc1/1.26.0 dispatch tables, but
/// the matrix is data so a processor rename shows up as evidence rather than as
/// a probe that needs rebuilding.
pub const READ_ONLY_NAME_CANDIDATES: &[&str] = &[
    METHOD_STATUS,
    METHOD_CERT_PEM,
    "tunnel_state",
    "tunnel_info",
];

/// Extra read-only context the discover pass collects alongside the matrix.
pub const CONTEXT_METHODS: &[&str] = &["processor_version", "deployment_id"];

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// Longer than [`DEFAULT_TIMEOUT`]: ACME issuance on a cold tunnel is slow.
pub const START_TIMEOUT: Duration = Duration::from_secs(120);

/// Any base64/hex-looking run at least this long is replaced by a digest.
const REDACT_MIN_OPAQUE_LEN: usize = 128;

// ---------------------------------------------------------------------------
// Wire client
// ---------------------------------------------------------------------------

/// A single JSON-RPC reply, preserving the error message the production bridge
/// intentionally drops.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawReply {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

impl RawReply {
    pub fn is_ok(&self) -> bool {
        self.result.is_some() && self.error_code.is_none()
    }
}

#[derive(Debug)]
pub enum ProbeError {
    InvalidSocketName,
    Io(std::io::Error),
    Timeout,
    Eof,
    ResponseTooLarge,
    InvalidJson(serde_json::Error),
    JsonRpcVersion,
    IdMismatch,
    MalformedReply,
}

impl ProbeError {
    pub fn failure_code(&self) -> &'static str {
        match self {
            Self::InvalidSocketName => "probe_socket_name",
            Self::Io(_) => "probe_io",
            Self::Timeout => "probe_timeout",
            Self::Eof => "probe_eof",
            Self::ResponseTooLarge => "probe_reply_oversized",
            Self::InvalidJson(_) => "probe_json",
            Self::JsonRpcVersion => "probe_jsonrpc_version",
            Self::IdMismatch => "probe_id_mismatch",
            Self::MalformedReply => "probe_malformed_reply",
        }
    }
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.failure_code())
    }
}

/// Minimal newline-delimited JSON-RPC 2.0 client over an abstract Unix socket.
///
/// One connection per call, matching how the processor keys pending requests.
#[derive(Debug)]
pub struct ProbeClient {
    socket_name: String,
    next_id: AtomicU64,
    max_response_bytes: usize,
}

impl ProbeClient {
    pub fn new(socket_name: impl Into<String>) -> Result<Self, ProbeError> {
        let socket_name = socket_name.into();
        if socket_name.is_empty() || socket_name.as_bytes().contains(&0) {
            return Err(ProbeError::InvalidSocketName);
        }
        Ok(Self {
            socket_name,
            next_id: AtomicU64::new(1),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        })
    }

    pub fn call(&self, method: &str, params: Value) -> Result<RawReply, ProbeError> {
        self.call_with_timeout(method, params, DEFAULT_TIMEOUT)
    }

    pub fn call_with_timeout(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<RawReply, ProbeError> {
        // Decimal-uint ids: Acurast Core keys pending connections by UInt.
        let id = self.next_id.fetch_add(1, Ordering::Relaxed).to_string();
        let request = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": id,
        });
        let mut request_bytes = serde_json::to_vec(&request).map_err(ProbeError::InvalidJson)?;
        request_bytes.push(b'\n');

        let address =
            SocketAddr::from_abstract_name(self.socket_name.as_bytes()).map_err(ProbeError::Io)?;
        let mut stream = UnixStream::connect_addr(&address).map_err(ProbeError::Io)?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(ProbeError::Io)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(ProbeError::Io)?;
        stream.write_all(&request_bytes).map_err(ProbeError::Io)?;
        stream.flush().map_err(ProbeError::Io)?;

        let mut response_bytes = Vec::new();
        let mut reader = BufReader::new(stream)
            .take(u64::try_from(self.max_response_bytes).unwrap_or(u64::MAX) + 1);
        match reader.read_until(b'\n', &mut response_bytes) {
            Ok(0) => return Err(ProbeError::Eof),
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(ProbeError::Timeout);
            }
            Err(error) => return Err(ProbeError::Io(error)),
        }
        if response_bytes.len() > self.max_response_bytes {
            return Err(ProbeError::ResponseTooLarge);
        }
        if response_bytes.last() != Some(&b'\n') {
            return Err(ProbeError::Eof);
        }
        response_bytes.pop();

        let response: Value =
            serde_json::from_slice(&response_bytes).map_err(ProbeError::InvalidJson)?;
        parse_reply(&response, &id)
    }
}

/// Validate the JSON-RPC envelope and split it into a [`RawReply`].
pub fn parse_reply(response: &Value, expected_id: &str) -> Result<RawReply, ProbeError> {
    if response["jsonrpc"] != json!("2.0") {
        return Err(ProbeError::JsonRpcVersion);
    }
    if response["id"] != json!(expected_id) {
        return Err(ProbeError::IdMismatch);
    }
    if let Some(error) = response.get("error") {
        let error_code = error
            .get("code")
            .and_then(Value::as_i64)
            .and_then(|code| i32::try_from(code).ok());
        let error_message = error
            .get("message")
            .and_then(Value::as_str)
            .map(redact_text);
        return Ok(RawReply {
            result: None,
            error_code,
            error_message,
        });
    }
    match response.get("result") {
        Some(result) => Ok(RawReply {
            result: Some(redact(result)),
            error_code: None,
            error_message: None,
        }),
        None => Err(ProbeError::MalformedReply),
    }
}

// ---------------------------------------------------------------------------
// Observations
// ---------------------------------------------------------------------------

/// What a reply says about the *method name*, independent of the payload.
///
/// `-32601` means the dispatcher never matched the name; `-32602` means it
/// matched and then rejected the params — the decisive discovery signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NameVerdict {
    Supported,
    NameRejected,
    NameAcceptedParamsRejected,
    NameAcceptedCallFailed,
    Indeterminate,
}

pub const JSON_RPC_METHOD_NOT_FOUND: i32 = -32601;
pub const JSON_RPC_INVALID_PARAMS: i32 = -32602;
pub const JSON_RPC_INTERNAL_ERROR: i32 = -32603;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelObservation {
    pub event: &'static str,
    pub method: String,
    pub params_shape: &'static str,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_message: Option<String>,
    pub name_verdict: NameVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
}

/// Describe a params value without echoing its contents.
pub fn params_shape(params: &Value) -> &'static str {
    match params {
        Value::Array(items) if items.is_empty() => "empty-array",
        Value::Array(items) if items.len() == 1 && items[0].is_object() => "single-object",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
        Value::Null => "null",
        _ => "scalar",
    }
}

pub fn classify(reply: &Result<RawReply, ProbeError>) -> (String, Option<i32>, NameVerdict) {
    match reply {
        Ok(reply) if reply.is_ok() => ("ok".to_string(), None, NameVerdict::Supported),
        Ok(reply) => {
            let code = reply.error_code;
            let verdict = match code {
                Some(JSON_RPC_METHOD_NOT_FOUND) => NameVerdict::NameRejected,
                Some(JSON_RPC_INVALID_PARAMS) => NameVerdict::NameAcceptedParamsRejected,
                Some(_) => NameVerdict::NameAcceptedCallFailed,
                None => NameVerdict::Indeterminate,
            };
            ("rpc_error".to_string(), code, verdict)
        }
        Err(error) => (
            error.failure_code().to_string(),
            None,
            NameVerdict::Indeterminate,
        ),
    }
}

pub fn observe(
    method: &str,
    params: &Value,
    reply: Result<RawReply, ProbeError>,
) -> TunnelObservation {
    let (outcome, rpc_code, name_verdict) = classify(&reply);
    let (result, rpc_message) = match &reply {
        Ok(reply) => (reply.result.clone(), reply.error_message.clone()),
        Err(_) => (None, None),
    };
    TunnelObservation {
        event: "observation",
        method: method.to_string(),
        params_shape: params_shape(params),
        outcome,
        rpc_code,
        rpc_message,
        name_verdict,
        result,
    }
}

// ---------------------------------------------------------------------------
// Tunnel result decoding
// ---------------------------------------------------------------------------

/// `TunnelStatus` ordinals, with `-1` meaning no tunnel has been started.
pub fn decode_tunnel_status(ordinal: i64) -> &'static str {
    match ordinal {
        -1 => "none",
        0 => "starting",
        1 => "running",
        2 => "stopped",
        3 => "failed",
        _ => "unknown",
    }
}

/// The four strings a successful `tunnel_start` returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelInfo {
    pub client_id: String,
    pub secondary_client_id: String,
    pub url: String,
    pub secondary_url: String,
}

/// Best-effort decode of a `tunnel_start` result.
///
/// The field ordering of the wire result is itself under test, so an object
/// reply is read by key and an array reply is reported positionally.
pub fn parse_tunnel_info(result: &Value) -> Option<TunnelInfo> {
    let string_at = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    match result {
        Value::Object(map) => Some(TunnelInfo {
            client_id: string_at(map.get("clientId")),
            secondary_client_id: string_at(map.get("secondaryClientId")),
            url: string_at(map.get("url")),
            secondary_url: string_at(map.get("secondaryUrl")),
        }),
        Value::Array(items) if items.len() >= 4 => Some(TunnelInfo {
            client_id: string_at(items.first()),
            secondary_client_id: string_at(items.get(1)),
            secondary_url: string_at(items.get(2)),
            url: string_at(items.get(3)),
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Spec validation
// ---------------------------------------------------------------------------

/// Required TunnelSpec keys, per the processor's `TunnelSpec.fromJson`.
pub const SPEC_REQUIRED_KEYS: &[&str] = &["serverAddrs", "domainSuffix", "localAddr", "primaryKey"];
pub const SPEC_REQUIRED_PRIMARY_KEY_KEYS: &[&str] = &["algorithm", "bytes"];

/// Check a spec locally so an obvious omission costs nothing on the device.
///
/// A missing required key raises `JSONException` inside the processor, which
/// surfaces as a generic internal error — much harder to read than this.
pub fn validate_spec(spec: &Value) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    let Some(map) = spec.as_object() else {
        return Err(vec!["spec must be a JSON object".to_string()]);
    };
    for key in SPEC_REQUIRED_KEYS {
        if !map.contains_key(*key) {
            problems.push(format!("missing required key: {key}"));
        }
    }
    match map.get("serverAddrs") {
        Some(Value::Array(items)) if !items.is_empty() => {}
        Some(_) => problems.push("serverAddrs must be a non-empty array".to_string()),
        None => {}
    }
    match map.get("primaryKey") {
        Some(Value::Object(primary)) => {
            for key in SPEC_REQUIRED_PRIMARY_KEY_KEYS {
                if !primary.contains_key(*key) {
                    problems.push(format!("missing required key: primaryKey.{key}"));
                }
            }
        }
        Some(_) => problems.push("primaryKey must be a JSON object".to_string()),
        None => {}
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// Summarize a spec for the transcript without echoing the private key bytes.
pub fn summarize_spec(spec: &Value) -> Value {
    let Some(map) = spec.as_object() else {
        return json!({"present": false});
    };
    let primary_key = map.get("primaryKey").and_then(Value::as_object);
    json!({
        "serverAddrs": map.get("serverAddrs").cloned().unwrap_or(Value::Null),
        "domainSuffix": map.get("domainSuffix").cloned().unwrap_or(Value::Null),
        "localAddr": map.get("localAddr").cloned().unwrap_or(Value::Null),
        "forceH2": map.get("forceH2").cloned().unwrap_or(Value::Null),
        "poolSize": map.get("poolSize").cloned().unwrap_or(Value::Null),
        "acmeStaging": map.get("acmeStaging").cloned().unwrap_or(Value::Null),
        "primaryKeyAlgorithm": primary_key
            .and_then(|key| key.get("algorithm"))
            .cloned()
            .unwrap_or(Value::Null),
        // The fingerprint is what makes an identity-reuse claim checkable.
        "primaryKeyFingerprint": primary_key
            .and_then(|key| key.get("bytes"))
            .and_then(Value::as_str)
            .map(sha256_hex)
            .map(Value::String)
            .unwrap_or(Value::Null),
        "certPemPresent": map.contains_key("certPem"),
    })
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// What a PEM blob is, without any of its bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PemSummary {
    pub present: bool,
    pub byte_length: usize,
    pub sha256: String,
    pub labels: Vec<String>,
    pub private_label_seen: bool,
}

/// Describe PEM text by digest and labels only.
///
/// The digest is the identity-reuse signal across a stop/start; the body never
/// leaves this function.
pub fn summarize_pem(text: &str) -> PemSummary {
    let mut labels = Vec::new();
    let mut private_label_seen = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            if let Some(label) = rest.strip_suffix("-----") {
                if label.contains("PRIVATE KEY") {
                    private_label_seen = true;
                }
                if !labels.iter().any(|seen| seen == label) {
                    labels.push(label.to_string());
                }
            }
        }
    }
    PemSummary {
        present: !text.is_empty(),
        byte_length: text.len(),
        sha256: sha256_hex(text),
        labels,
        private_label_seen,
    }
}

fn looks_like_pem(text: &str) -> bool {
    text.contains("-----BEGIN ")
}

fn is_opaque_blob(text: &str) -> bool {
    text.len() >= REDACT_MIN_OPAQUE_LEN
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'))
}

/// Replace anything secret-shaped in a string with a digest reference.
pub fn redact_text(text: &str) -> String {
    if looks_like_pem(text) {
        let summary = summarize_pem(text);
        return format!(
            "[pem redacted labels={:?} bytes={} sha256={}]",
            summary.labels, summary.byte_length, summary.sha256
        );
    }
    if text.starts_with("eyJ") && text.len() >= 32 {
        return format!("[jwt redacted sha256={}]", sha256_hex(text));
    }
    if is_opaque_blob(text) {
        return format!(
            "[opaque redacted bytes={} sha256={}]",
            text.len(),
            sha256_hex(text)
        );
    }
    text.to_string()
}

/// Apply [`redact_text`] to every string in a JSON value.
pub fn redact(value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(redact_text(text)),
        Value::Array(items) => Value::Array(items.iter().map(redact).collect()),
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, item) in map {
                out.insert(key.clone(), redact(item));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERT_PEM: &str =
        "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAK\n-----END CERTIFICATE-----\n";
    const PRIVATE_PEM: &str =
        "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBsecretbytes\n-----END EC PRIVATE KEY-----\n";

    #[test]
    fn summarize_pem_reports_labels_without_the_body() {
        let summary = summarize_pem(CERT_PEM);
        assert!(summary.present);
        assert_eq!(summary.labels, vec!["CERTIFICATE".to_string()]);
        assert!(!summary.private_label_seen);
        assert_eq!(summary.byte_length, CERT_PEM.len());

        let serialized = serde_json::to_string(&summary).unwrap();
        assert!(!serialized.contains("MIIBkTCB"));
    }

    #[test]
    fn summarize_pem_flags_private_keys_and_never_serializes_their_bytes() {
        let summary = summarize_pem(PRIVATE_PEM);
        assert!(summary.private_label_seen);
        assert_eq!(summary.labels, vec!["EC PRIVATE KEY".to_string()]);

        let serialized = serde_json::to_string(&summary).unwrap();
        assert!(!serialized.contains("secretbytes"));
        assert!(!serialized.contains("MHcCAQEEIB"));
    }

    #[test]
    fn summarize_pem_digest_is_stable_and_distinguishes_material() {
        assert_eq!(
            summarize_pem(CERT_PEM).sha256,
            summarize_pem(CERT_PEM).sha256
        );
        assert_ne!(
            summarize_pem(CERT_PEM).sha256,
            summarize_pem(PRIVATE_PEM).sha256
        );
    }

    #[test]
    fn redact_replaces_pem_jwt_and_long_opaque_strings() {
        let jwt = format!("eyJ{}", "a".repeat(64));
        let opaque = "A".repeat(REDACT_MIN_OPAQUE_LEN);
        let value = json!({
            "cert": CERT_PEM,
            "token": jwt,
            "blob": opaque,
            "url": "https://abc123.acu.run",
            "nested": [CERT_PEM],
        });

        let redacted = redact(&value);
        let text = serde_json::to_string(&redacted).unwrap();
        assert!(!text.contains("MIIBkTCB"));
        assert!(text.contains("[pem redacted"));
        assert!(text.contains("[jwt redacted"));
        assert!(text.contains("[opaque redacted"));
        // Short, non-secret values must survive: the public URL is the finding.
        assert_eq!(redacted["url"], json!("https://abc123.acu.run"));
        assert!(
            redacted["nested"][0]
                .as_str()
                .unwrap()
                .contains("[pem redacted")
        );
    }

    #[test]
    fn classify_maps_the_discovery_codes() {
        let method_not_found = Ok(RawReply {
            result: None,
            error_code: Some(JSON_RPC_METHOD_NOT_FOUND),
            error_message: None,
        });
        assert_eq!(classify(&method_not_found).2, NameVerdict::NameRejected);

        let invalid_params = Ok(RawReply {
            result: None,
            error_code: Some(JSON_RPC_INVALID_PARAMS),
            error_message: None,
        });
        assert_eq!(
            classify(&invalid_params).2,
            NameVerdict::NameAcceptedParamsRejected
        );

        let internal = Ok(RawReply {
            result: None,
            error_code: Some(JSON_RPC_INTERNAL_ERROR),
            error_message: Some("tunnel already active".to_string()),
        });
        assert_eq!(classify(&internal).2, NameVerdict::NameAcceptedCallFailed);

        let ok = Ok(RawReply {
            result: Some(json!(1)),
            error_code: None,
            error_message: None,
        });
        assert_eq!(classify(&ok).2, NameVerdict::Supported);

        let transport: Result<RawReply, ProbeError> = Err(ProbeError::Timeout);
        let (outcome, code, verdict) = classify(&transport);
        assert_eq!(outcome, "probe_timeout");
        assert_eq!(code, None);
        assert_eq!(verdict, NameVerdict::Indeterminate);
    }

    #[test]
    fn parse_reply_preserves_the_error_message_the_limit_is_reported_through() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": "7",
            "error": {"code": JSON_RPC_INTERNAL_ERROR, "message": "tunnel already active"},
        });
        let reply = parse_reply(&response, "7").unwrap();
        assert_eq!(reply.error_code, Some(JSON_RPC_INTERNAL_ERROR));
        assert_eq!(
            reply.error_message.as_deref(),
            Some("tunnel already active")
        );
        assert!(!reply.is_ok());
    }

    #[test]
    fn parse_reply_rejects_envelope_mismatches() {
        let wrong_version = json!({"jsonrpc": "1.0", "id": "1", "result": {}});
        assert!(matches!(
            parse_reply(&wrong_version, "1"),
            Err(ProbeError::JsonRpcVersion)
        ));

        let wrong_id = json!({"jsonrpc": "2.0", "id": "2", "result": {}});
        assert!(matches!(
            parse_reply(&wrong_id, "1"),
            Err(ProbeError::IdMismatch)
        ));

        let no_result = json!({"jsonrpc": "2.0", "id": "1"});
        assert!(matches!(
            parse_reply(&no_result, "1"),
            Err(ProbeError::MalformedReply)
        ));
    }

    #[test]
    fn parse_reply_redacts_results_before_they_can_be_printed() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": "1",
            "result": CERT_PEM,
        });
        let reply = parse_reply(&response, "1").unwrap();
        let text = serde_json::to_string(&reply).unwrap();
        assert!(!text.contains("MIIBkTCB"));
    }

    #[test]
    fn decode_tunnel_status_covers_every_ordinal_including_no_tunnel() {
        assert_eq!(decode_tunnel_status(-1), "none");
        assert_eq!(decode_tunnel_status(0), "starting");
        assert_eq!(decode_tunnel_status(1), "running");
        assert_eq!(decode_tunnel_status(2), "stopped");
        assert_eq!(decode_tunnel_status(3), "failed");
        assert_eq!(decode_tunnel_status(9), "unknown");
    }

    #[test]
    fn parse_tunnel_info_reads_objects_by_key_and_arrays_positionally() {
        let object = json!({
            "clientId": "abc",
            "secondaryClientId": "def",
            "url": "https://abc.acu.run",
            "secondaryUrl": "https://def.acu.run",
        });
        let info = parse_tunnel_info(&object).unwrap();
        assert_eq!(info.client_id, "abc");
        assert_eq!(info.url, "https://abc.acu.run");

        let array = json!(["abc", "def", "https://def.acu.run", "https://abc.acu.run"]);
        let info = parse_tunnel_info(&array).unwrap();
        assert_eq!(info.client_id, "abc");
        assert_eq!(info.url, "https://abc.acu.run");

        assert!(parse_tunnel_info(&json!("nope")).is_none());
    }

    #[test]
    fn validate_spec_names_every_missing_required_key() {
        let problems = validate_spec(&json!({})).unwrap_err();
        assert_eq!(problems.len(), SPEC_REQUIRED_KEYS.len());

        let problems = validate_spec(&json!({
            "serverAddrs": [],
            "domainSuffix": "acu.run",
            "localAddr": "127.0.0.1:18081",
            "primaryKey": {"algorithm": "Secp256r1"},
        }))
        .unwrap_err();
        assert!(problems.iter().any(|p| p.contains("serverAddrs must be")));
        assert!(problems.iter().any(|p| p.contains("primaryKey.bytes")));

        let good = json!({
            "serverAddrs": ["relay-1.mainnet.acurast.com:4433"],
            "domainSuffix": "acu.run",
            "localAddr": "127.0.0.1:18081",
            "primaryKey": {"algorithm": "Secp256r1", "bytes": "AAAA"},
        });
        assert!(validate_spec(&good).is_ok());
    }

    #[test]
    fn summarize_spec_fingerprints_the_key_without_revealing_it() {
        let spec = json!({
            "serverAddrs": ["relay-1.mainnet.acurast.com:4433"],
            "domainSuffix": "acu.run",
            "localAddr": "127.0.0.1:18081",
            "primaryKey": {"algorithm": "Secp256r1", "bytes": "c2VjcmV0LWtleS1ieXRlcw=="},
        });
        let summary = summarize_spec(&spec);
        let text = serde_json::to_string(&summary).unwrap();
        assert!(!text.contains("c2VjcmV0LWtleS1ieXRlcw"));
        assert_eq!(summary["primaryKeyAlgorithm"], json!("Secp256r1"));
        assert_eq!(
            summary["primaryKeyFingerprint"],
            json!(sha256_hex("c2VjcmV0LWtleS1ieXRlcw=="))
        );
    }

    #[test]
    fn params_shape_describes_without_echoing() {
        assert_eq!(params_shape(&json!([])), "empty-array");
        assert_eq!(params_shape(&json!([{"a": 1}])), "single-object");
        assert_eq!(params_shape(&json!([1, 2])), "array");
        assert_eq!(params_shape(&json!({"a": 1})), "object");
    }

    #[test]
    fn mutating_methods_are_disjoint_from_read_only_methods() {
        for method in MUTATING_METHODS {
            assert!(
                !READ_ONLY_METHODS.contains(method),
                "{method} must not be reachable without --yes-mutate"
            );
            assert!(
                !READ_ONLY_NAME_CANDIDATES.contains(method),
                "{method} must not be walked by the discover matrix"
            );
        }
    }
}
