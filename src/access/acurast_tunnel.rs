//! The one Acurast `tunnel_start` of a public HTTP attachment
//! (`BKLG-20261001-pn65`): the exact `TunnelSpec` built from a P-256 identity
//! and one local port, a single start over the bridge socket, the
//! `tunnel_status`/`tunnel_certPem` poll that follows it, and a typed code for
//! every outcome.
//!
//! Nothing calls it yet. The wiring packet named in `BKLG-20260803-88f6` wraps
//! it in the `slipway-runtime-ssh` store's `claim_public_ingress_attempt` CAS,
//! which owns the one attempt per attachment; the marker file here is only a
//! job-local guard beneath it. No outcome is retried.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "wired by the Acurast driver packet named in BKLG-20260803-88f6"
    )
)]

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::num::NonZeroU16;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::tunnel_probe::{
    self, JSON_RPC_INTERNAL_ERROR, JSON_RPC_INVALID_PARAMS, METHOD_CERT_PEM, METHOD_START,
    METHOD_STATUS, METHOD_STOP, PemSummary, ProbeClient, ProbeError, RawReply, START_TIMEOUT,
};

/// Platform-derived, never authored: the contract gives an Acurast attachment
/// no relay or suffix field.
pub(super) const ACURAST_MAINNET_RELAYS: &[&str] = &["relay-1.mainnet.acurast.com:4433"];
pub(super) const ACURAST_TUNNEL_SUFFIX: &str = "acu.run";
pub(super) const ATTEMPT_MARKER_FILE: &str = "acurast-tunnel.attempted";
const PRIMARY_KEY_ALGORITHM: &str = "Secp256r1";
pub(super) const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// From the first poll; a tunnel neither serving nor failed by then is
/// reported, not waited on.
pub(super) const SERVING_DEADLINE: Duration = Duration::from_secs(180);
/// `tunnel_status` and `tunnel_certPem` read local state and answer at once.
const POLL_CALL_TIMEOUT: Duration = Duration::from_secs(5);

// The processor reports both of these only as `-32603` with a message
// (`IllegalStateException` wrapped as InternalError): the provider's untyped
// errors, matched by substring because there is nothing else to match.
const ALREADY_ACTIVE_MESSAGE: &str = "tunnel already active";
const DESTROYED_MESSAGE: &str = "already been destroyed";

/// A P-256 tunnel identity as PKCS#8 DER. Where it is generated and how it
/// reaches the job belongs to the bootstrap packet, not to this module.
pub(super) struct TunnelIdentity {
    pkcs8: Zeroizing<Vec<u8>>,
    public_key: Vec<u8>,
}

impl TunnelIdentity {
    pub(super) fn from_pkcs8(pkcs8: Zeroizing<Vec<u8>>) -> Result<Self, AcurastTunnelFailure> {
        let key_pair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            &pkcs8,
            &SystemRandom::new(),
        )
        .map_err(|_| AcurastTunnelFailure::IdentityInvalid)?;
        let public_key = key_pair.public_key().as_ref().to_vec();
        Ok(Self { pkcs8, public_key })
    }

    /// SEC1 uncompressed public point. The relay's `clientId` derivation from
    /// it is not recorded yet; the live attempt pins it against this value.
    pub(super) fn public_key_hex(&self) -> String {
        hex::encode(&self.public_key)
    }
}

impl fmt::Debug for TunnelIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelIdentity")
            .field("algorithm", &PRIMARY_KEY_ALGORITHM)
            .finish_non_exhaustive()
    }
}

/// The `params[0]` of `tunnel_start`. It carries the private key in base64,
/// so its `Debug` is the probe's key-free summary.
pub(super) struct TunnelSpec(Value);

impl TunnelSpec {
    pub(super) fn as_value(&self) -> &Value {
        &self.0
    }
}

impl fmt::Debug for TunnelSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TunnelSpec")
            .field(&tunnel_probe::summarize_spec(&self.0))
            .finish()
    }
}

/// One HTTP service per attachment. How several services would share one
/// `<clientId>.acu.run` hostname is `Q-20261001-t9e6`, not decided here.
pub(super) fn build_spec(
    identity: &TunnelIdentity,
    local_ports: &[NonZeroU16],
    acme_staging: bool,
) -> Result<TunnelSpec, AcurastTunnelFailure> {
    let port = match local_ports {
        [] => return Err(AcurastTunnelFailure::ServiceMissing),
        [port] => *port,
        _ => return Err(AcurastTunnelFailure::MultipleServicesUnsupported),
    };
    // `secondaryLocalAddr` is omitted: the secondary connection is the TCP
    // slot of a later slice.
    let spec = json!({
        "serverAddrs": ACURAST_MAINNET_RELAYS,
        "primaryKey": {
            "algorithm": PRIMARY_KEY_ALGORITHM,
            "bytes": BASE64_STANDARD.encode(identity.pkcs8.as_slice()),
        },
        "domainSuffix": ACURAST_TUNNEL_SUFFIX,
        "localAddr": format!("127.0.0.1:{port}"),
        "acmeStaging": acme_staging,
    });
    if tunnel_probe::validate_spec(&spec).is_err() {
        return Err(AcurastTunnelFailure::SpecRejected);
    }
    Ok(TunnelSpec(spec))
}

/// The clock and sleep the poll runs on.
pub(super) trait PollClock {
    fn now(&self) -> Instant;
    fn sleep(&self, duration: Duration);
}

pub(super) struct SystemPollClock;

impl PollClock for SystemPollClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AcurastTunnelFailure {
    IdentityInvalid,
    ServiceMissing,
    MultipleServicesUnsupported,
    AttemptAlreadySpent,
    AttemptMarkerFailed,
    BridgeUnavailable,
    BridgeReplyMalformed,
    AlreadyActive,
    SpecRejected,
    StartFailed,
    UrlMissing,
    Wedged,
    StatusUnreadable,
    StoppedUnexpectedly,
    FailedBeforeCertificate,
    FailedAfterCertificate,
    StartTimeout,
    CertificateTimeout,
    StopFailed,
}

impl AcurastTunnelFailure {
    pub(super) fn code(self) -> &'static str {
        match self {
            Self::IdentityInvalid => "acurast_tunnel_identity_invalid",
            Self::ServiceMissing => "acurast_tunnel_service_missing",
            Self::MultipleServicesUnsupported => "acurast_tunnel_multiple_services_unsupported",
            Self::AttemptAlreadySpent => "acurast_tunnel_attempt_already_spent",
            Self::AttemptMarkerFailed => "acurast_tunnel_attempt_marker_failed",
            Self::BridgeUnavailable => "acurast_tunnel_bridge_unavailable",
            Self::BridgeReplyMalformed => "acurast_tunnel_bridge_reply_malformed",
            Self::AlreadyActive => "acurast_tunnel_already_active",
            Self::SpecRejected => "acurast_tunnel_spec_rejected",
            Self::StartFailed => "acurast_tunnel_start_failed",
            Self::UrlMissing => "acurast_tunnel_url_missing",
            Self::Wedged => "acurast_tunnel_wedged",
            Self::StatusUnreadable => "acurast_tunnel_status_unreadable",
            Self::StoppedUnexpectedly => "acurast_tunnel_stopped_unexpectedly",
            Self::FailedBeforeCertificate => "acurast_tunnel_failed_before_certificate",
            Self::FailedAfterCertificate => "acurast_tunnel_failed_after_certificate",
            Self::StartTimeout => "acurast_tunnel_start_timeout",
            Self::CertificateTimeout => "acurast_tunnel_certificate_timeout",
            Self::StopFailed => "acurast_tunnel_stop_failed",
        }
    }
}

impl fmt::Display for AcurastTunnelFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

pub(super) const SERVING_CODE: &str = "acurast_tunnel_serving";

/// A tunnel the relay is serving with a certificate. `url` is the publication
/// hostname as the processor issued it; `cert` describes the certificate
/// without carrying it.
#[derive(Debug)]
pub(super) struct AcurastTunnelServing {
    pub(super) url: String,
    pub(super) client_id: String,
    pub(super) cert: PemSummary,
    client: ProbeClient,
}

impl AcurastTunnelServing {
    pub(super) fn code(&self) -> &'static str {
        SERVING_CODE
    }

    /// Only a serving tunnel can be stopped; after a failure the processor's
    /// client object is already destroyed and a stop recovers nothing.
    pub(super) fn stop(self) -> Result<(), AcurastTunnelFailure> {
        match self.client.call(METHOD_STOP, json!([])) {
            Ok(reply) if reply.is_ok() => Ok(()),
            Ok(reply) => Err(classify_rpc_error(&reply, AcurastTunnelFailure::StopFailed)),
            Err(error) => Err(classify_transport_error(&error)),
        }
    }
}

/// Spend this job's one `tunnel_start` and follow it to an outcome.
///
/// The marker `<root>/acurast-tunnel.attempted` is created before the call;
/// if it already exists nothing is sent and no socket is opened.
pub(super) fn start_once(
    root: &Path,
    socket_name: &str,
    spec: &TunnelSpec,
    clock: &dyn PollClock,
) -> Result<AcurastTunnelServing, AcurastTunnelFailure> {
    // Name validation only; `ProbeClient` connects per call.
    let client =
        ProbeClient::new(socket_name).map_err(|_| AcurastTunnelFailure::BridgeUnavailable)?;
    spend_attempt(root)?;

    let reply = client
        .call_with_timeout(METHOD_START, json!([spec.as_value()]), START_TIMEOUT)
        .map_err(|error| classify_transport_error(&error))?;
    if !reply.is_ok() {
        return Err(match reply.error_code {
            Some(JSON_RPC_INVALID_PARAMS) => AcurastTunnelFailure::SpecRejected,
            _ => classify_rpc_error(&reply, AcurastTunnelFailure::StartFailed),
        });
    }
    let info = reply
        .result
        .as_ref()
        .and_then(tunnel_probe::parse_tunnel_info)
        .ok_or(AcurastTunnelFailure::BridgeReplyMalformed)?;
    if info.url.is_empty() {
        return Err(AcurastTunnelFailure::UrlMissing);
    }

    let deadline = clock.now() + SERVING_DEADLINE;
    loop {
        let status = poll(&client, METHOD_STATUS)?
            .result
            .as_ref()
            .and_then(Value::as_i64)
            .ok_or(AcurastTunnelFailure::StatusUnreadable)?;
        let running = match tunnel_probe::decode_tunnel_status(status) {
            "starting" => false,
            "running" => {
                let pem = read_certificate(&client)?;
                if !pem.is_empty() {
                    return Ok(AcurastTunnelServing {
                        url: info.url,
                        client_id: info.client_id,
                        cert: tunnel_probe::summarize_pem(&pem),
                        client,
                    });
                }
                true
            }
            // Whether ACME issued before the relay leg failed. A certificate
            // that cannot be read after the failure counts as none.
            "failed" => {
                return Err(match read_certificate(&client) {
                    Ok(pem) if !pem.is_empty() => AcurastTunnelFailure::FailedAfterCertificate,
                    _ => AcurastTunnelFailure::FailedBeforeCertificate,
                });
            }
            "none" | "stopped" => return Err(AcurastTunnelFailure::StoppedUnexpectedly),
            _ => return Err(AcurastTunnelFailure::StatusUnreadable),
        };
        if clock.now() >= deadline {
            return Err(if running {
                AcurastTunnelFailure::CertificateTimeout
            } else {
                AcurastTunnelFailure::StartTimeout
            });
        }
        clock.sleep(POLL_INTERVAL);
    }
}

/// The PEM text, or empty while none is issued.
fn read_certificate(client: &ProbeClient) -> Result<Zeroizing<String>, AcurastTunnelFailure> {
    poll(client, METHOD_CERT_PEM)?
        .result
        .and_then(|result| result.as_str().map(str::to_owned))
        .map(Zeroizing::new)
        .ok_or(AcurastTunnelFailure::StatusUnreadable)
}

fn spend_attempt(root: &Path) -> Result<(), AcurastTunnelFailure> {
    let marker = root.join(ATTEMPT_MARKER_FILE);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&marker)
        .map_err(|error| match error.kind() {
            ErrorKind::AlreadyExists => AcurastTunnelFailure::AttemptAlreadySpent,
            _ => AcurastTunnelFailure::AttemptMarkerFailed,
        })?;
    // The marker must outlive a crash during the call it guards.
    file.sync_all()
        .and_then(|()| File::open(root)?.sync_all())
        .map_err(|_| AcurastTunnelFailure::AttemptMarkerFailed)
}

fn poll(client: &ProbeClient, method: &str) -> Result<RawReply, AcurastTunnelFailure> {
    // Unredacted: the PEM is summarized before it can reach any log, and a
    // status ordinal has nothing to redact.
    let reply = client
        .call_unredacted_with_timeout(method, json!([]), POLL_CALL_TIMEOUT)
        .map_err(|error| classify_transport_error(&error))?;
    if reply.is_ok() {
        Ok(reply)
    } else {
        Err(classify_rpc_error(
            &reply,
            AcurastTunnelFailure::StatusUnreadable,
        ))
    }
}

fn classify_rpc_error(reply: &RawReply, otherwise: AcurastTunnelFailure) -> AcurastTunnelFailure {
    let message = reply.error_message.as_deref().unwrap_or_default();
    match reply.error_code {
        Some(JSON_RPC_INTERNAL_ERROR) if message.contains(DESTROYED_MESSAGE) => {
            AcurastTunnelFailure::Wedged
        }
        Some(JSON_RPC_INTERNAL_ERROR) if message.contains(ALREADY_ACTIVE_MESSAGE) => {
            AcurastTunnelFailure::AlreadyActive
        }
        _ => otherwise,
    }
}

fn classify_transport_error(error: &ProbeError) -> AcurastTunnelFailure {
    match error {
        ProbeError::InvalidSocketName
        | ProbeError::Io(_)
        | ProbeError::Timeout
        | ProbeError::Eof => AcurastTunnelFailure::BridgeUnavailable,
        ProbeError::ResponseTooLarge
        | ProbeError::InvalidJson(_)
        | ProbeError::JsonRpcVersion
        | ProbeError::IdMismatch
        | ProbeError::MalformedReply => AcurastTunnelFailure::BridgeReplyMalformed,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::{BufRead, BufReader, Write};
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{SocketAddr, UnixListener};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::thread;

    use super::*;
    use crate::diagnostics::canonical_json_bytes;

    static COUNTER: AtomicU64 = AtomicU64::new(1);

    const CERT_PEM: &str =
        "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKcertificatebody\n-----END CERTIFICATE-----\n";
    const URL: &str = "https://0123456789abcdef.acu.run";

    fn unique(prefix: &str) -> String {
        format!(
            "{prefix}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn scratch_root() -> PathBuf {
        let root = std::env::temp_dir().join(unique("liskov-acurast-tunnel"));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn test_pkcs8() -> Zeroizing<Vec<u8>> {
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .unwrap();
        Zeroizing::new(document.as_ref().to_vec())
    }

    fn port(value: u16) -> NonZeroU16 {
        NonZeroU16::new(value).unwrap()
    }

    fn test_spec() -> TunnelSpec {
        let identity = TunnelIdentity::from_pkcs8(test_pkcs8()).unwrap();
        build_spec(&identity, &[port(18081)], false).unwrap()
    }

    fn ok(result: Value) -> Value {
        json!({"result": result})
    }

    fn error(code: i32, message: &str) -> Value {
        json!({"error": {"code": code, "message": message}})
    }

    fn started() -> Value {
        ok(json!({
            "clientId": "0123456789abcdef",
            "secondaryClientId": "",
            "secondaryUrl": "",
            "url": URL,
        }))
    }

    #[derive(Debug)]
    struct Received {
        method: String,
        params: Value,
        marker_present: bool,
    }

    /// Answers each connection with the next scripted reply, then `-32601`
    /// once the script runs out, recording every request it receives.
    struct ScriptedBridge {
        socket_name: String,
        stop: Arc<AtomicBool>,
        handle: thread::JoinHandle<Vec<Received>>,
    }

    impl ScriptedBridge {
        fn serve(script: Vec<Value>, marker: PathBuf) -> Self {
            let socket_name = unique("liskov-acurast-tunnel-test");
            let address = SocketAddr::from_abstract_name(socket_name.as_bytes()).unwrap();
            let listener = UnixListener::bind_addr(&address).unwrap();
            listener.set_nonblocking(true).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let stopping = Arc::clone(&stop);
            let handle = thread::spawn(move || {
                let mut script = script.into_iter();
                let mut received = Vec::new();
                while !stopping.load(Ordering::Relaxed) {
                    let stream = match listener.accept() {
                        Ok((stream, _)) => stream,
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                            continue;
                        }
                        Err(error) => panic!("accept: {error}"),
                    };
                    stream.set_nonblocking(false).unwrap();
                    let marker_present = marker.exists();
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let request: Value = serde_json::from_str(line.trim_end()).unwrap();
                    let scripted = script
                        .next()
                        .unwrap_or_else(|| error(-32601, "Method not found"));
                    let mut response = json!({"jsonrpc": "2.0", "id": request["id"]});
                    if let Some(error) = scripted.get("error") {
                        response["error"] = error.clone();
                    } else {
                        response["result"] = scripted["result"].clone();
                    }
                    let mut bytes = serde_json::to_vec(&response).unwrap();
                    bytes.push(b'\n');
                    reader.get_mut().write_all(&bytes).unwrap();
                    received.push(Received {
                        method: request["method"].as_str().unwrap().to_string(),
                        params: request["params"].clone(),
                        marker_present,
                    });
                }
                received
            });
            Self {
                socket_name,
                stop,
                handle,
            }
        }

        fn finish(self) -> Vec<Received> {
            self.stop.store(true, Ordering::Relaxed);
            self.handle.join().unwrap()
        }
    }

    fn methods(received: &[Received]) -> Vec<&str> {
        received
            .iter()
            .map(|request| request.method.as_str())
            .collect()
    }

    struct FakeClock {
        now: Cell<Instant>,
        sleeps: Cell<u32>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                now: Cell::new(Instant::now()),
                sleeps: Cell::new(0),
            }
        }
    }

    impl PollClock for FakeClock {
        fn now(&self) -> Instant {
            self.now.get()
        }

        fn sleep(&self, duration: Duration) {
            assert_eq!(duration, POLL_INTERVAL);
            self.now.set(self.now.get() + duration);
            self.sleeps.set(self.sleeps.get() + 1);
        }
    }

    fn run(
        script: Vec<Value>,
    ) -> (
        Result<AcurastTunnelServing, AcurastTunnelFailure>,
        Vec<Received>,
    ) {
        let root = scratch_root();
        let bridge = ScriptedBridge::serve(script, root.join(ATTEMPT_MARKER_FILE));
        let outcome = start_once(&root, &bridge.socket_name, &test_spec(), &FakeClock::new());
        (outcome, bridge.finish())
    }

    #[test]
    fn builds_the_exact_spec_for_one_port() {
        let pkcs8 = test_pkcs8();
        let identity = TunnelIdentity::from_pkcs8(pkcs8.clone()).unwrap();
        let spec = build_spec(&identity, &[port(18081)], false).unwrap();
        let encoded = BASE64_STANDARD.encode(pkcs8.as_slice());
        let expected = json!({
            "serverAddrs": ["relay-1.mainnet.acurast.com:4433"],
            "primaryKey": {"algorithm": "Secp256r1", "bytes": encoded},
            "domainSuffix": "acu.run",
            "localAddr": "127.0.0.1:18081",
            "acmeStaging": false,
        });
        assert_eq!(
            canonical_json_bytes(spec.as_value()),
            canonical_json_bytes(&expected)
        );
        assert_eq!(tunnel_probe::validate_spec(spec.as_value()), Ok(()));
        let bytes = spec.as_value()["primaryKey"]["bytes"].as_str().unwrap();
        assert_eq!(BASE64_STANDARD.decode(bytes).unwrap(), pkcs8.as_slice());

        let staging = build_spec(&identity, &[port(18081)], true).unwrap();
        assert_eq!(staging.as_value()["acmeStaging"], json!(true));
    }

    #[test]
    fn exposes_the_uncompressed_public_point() {
        let pkcs8 = test_pkcs8();
        let expected = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            &pkcs8,
            &SystemRandom::new(),
        )
        .unwrap()
        .public_key()
        .as_ref()
        .to_vec();
        let identity = TunnelIdentity::from_pkcs8(pkcs8).unwrap();
        let public_key = identity.public_key_hex();
        assert_eq!(public_key.len(), 130);
        assert!(public_key.starts_with("04"));
        assert_eq!(public_key, hex::encode(expected));
    }

    #[test]
    fn refuses_a_key_that_is_not_p256_pkcs8() {
        let refused =
            TunnelIdentity::from_pkcs8(Zeroizing::new(vec![0x30, 0x03, 0x02, 0x01, 0x00]));
        assert_eq!(refused.unwrap_err(), AcurastTunnelFailure::IdentityInvalid);
    }

    #[test]
    fn refuses_more_than_one_service_before_building() {
        let identity = TunnelIdentity::from_pkcs8(test_pkcs8()).unwrap();
        let refused = build_spec(&identity, &[port(18081), port(18082)], false).unwrap_err();
        assert_eq!(
            refused.code(),
            "acurast_tunnel_multiple_services_unsupported"
        );
        let missing = build_spec(&identity, &[], false).unwrap_err();
        assert_eq!(missing.code(), "acurast_tunnel_service_missing");
    }

    #[test]
    fn serves_once_running_with_a_certificate() {
        let (outcome, received) = run(vec![
            started(),
            ok(json!(1)),
            ok(json!("")),
            ok(json!(1)),
            ok(json!(CERT_PEM)),
        ]);
        let serving = outcome.unwrap();
        assert_eq!(serving.code(), "acurast_tunnel_serving");
        assert_eq!(serving.url, URL);
        assert_eq!(serving.client_id, "0123456789abcdef");
        assert_eq!(serving.cert, tunnel_probe::summarize_pem(CERT_PEM));
        assert_eq!(
            methods(&received),
            [
                METHOD_START,
                METHOD_STATUS,
                METHOD_CERT_PEM,
                METHOD_STATUS,
                METHOD_CERT_PEM
            ]
        );
        assert!(
            received[1..]
                .iter()
                .all(|request| request.params == json!([]))
        );
    }

    #[test]
    fn sends_the_spec_as_the_only_start_param() {
        let root = scratch_root();
        let spec = test_spec();
        let bridge = ScriptedBridge::serve(
            vec![error(-32602, "Invalid params")],
            root.join(ATTEMPT_MARKER_FILE),
        );
        let _ = start_once(&root, &bridge.socket_name, &spec, &FakeClock::new());
        let received = bridge.finish();
        assert_eq!(received[0].params, json!([spec.as_value()]));
    }

    #[test]
    fn a_failure_with_no_certificate_is_before_the_certificate() {
        let (outcome, received) = run(vec![started(), ok(json!(1)), ok(json!("")), ok(json!(3))]);
        assert_eq!(
            outcome.unwrap_err().code(),
            "acurast_tunnel_failed_before_certificate"
        );
        // The certificate read after the failure is answered `-32601` here
        // and counts as no certificate.
        assert_eq!(
            methods(&received),
            [
                METHOD_START,
                METHOD_STATUS,
                METHOD_CERT_PEM,
                METHOD_STATUS,
                METHOD_CERT_PEM
            ]
        );
    }

    #[test]
    fn a_failure_with_a_certificate_is_after_the_certificate() {
        let (outcome, _) = run(vec![
            started(),
            ok(json!(0)),
            ok(json!(3)),
            ok(json!(CERT_PEM)),
        ]);
        assert_eq!(
            outcome.unwrap_err().code(),
            "acurast_tunnel_failed_after_certificate"
        );
    }

    #[test]
    fn classifies_start_errors_without_polling() {
        for (reply, code) in [
            (
                error(-32603, "Internal error: tunnel already active"),
                "acurast_tunnel_already_active",
            ),
            (
                error(
                    -32603,
                    "Internal error: TunnelClient object has already been destroyed",
                ),
                "acurast_tunnel_wedged",
            ),
            (
                error(-32602, "Invalid params"),
                "acurast_tunnel_spec_rejected",
            ),
            (
                error(-32603, "Internal error"),
                "acurast_tunnel_start_failed",
            ),
            (ok(json!({"clientId": "x"})), "acurast_tunnel_url_missing"),
            (
                ok(json!("unexpected")),
                "acurast_tunnel_bridge_reply_malformed",
            ),
        ] {
            let (outcome, received) = run(vec![reply]);
            assert_eq!(outcome.unwrap_err().code(), code);
            assert_eq!(methods(&received), [METHOD_START]);
        }
    }

    #[test]
    fn a_wedged_status_poll_is_reported() {
        let (outcome, _) = run(vec![
            started(),
            error(
                -32603,
                "Internal error: TunnelClient object has already been destroyed",
            ),
        ]);
        assert_eq!(outcome.unwrap_err().code(), "acurast_tunnel_wedged");
    }

    #[test]
    fn a_stopped_or_absent_tunnel_is_unexpected() {
        for status in [-1, 2] {
            let (outcome, _) = run(vec![started(), ok(json!(status))]);
            assert_eq!(
                outcome.unwrap_err().code(),
                "acurast_tunnel_stopped_unexpectedly"
            );
        }
        let (outcome, _) = run(vec![started(), ok(json!(9))]);
        assert_eq!(
            outcome.unwrap_err().code(),
            "acurast_tunnel_status_unreadable"
        );
    }

    #[test]
    fn running_without_a_certificate_times_out_at_the_deadline() {
        let polls = SERVING_DEADLINE.as_secs() / POLL_INTERVAL.as_secs() + 1;
        let mut script = vec![started()];
        for _ in 0..polls {
            script.extend([ok(json!(1)), ok(json!(""))]);
        }
        let root = scratch_root();
        let bridge = ScriptedBridge::serve(script, root.join(ATTEMPT_MARKER_FILE));
        let clock = FakeClock::new();
        let outcome = start_once(&root, &bridge.socket_name, &test_spec(), &clock);
        let received = bridge.finish();
        assert_eq!(
            outcome.unwrap_err().code(),
            "acurast_tunnel_certificate_timeout"
        );
        assert_eq!(u64::from(clock.sleeps.get()), polls - 1);
        assert_eq!(received.len() as u64, 1 + 2 * polls);
    }

    #[test]
    fn a_tunnel_still_starting_at_the_deadline_is_a_start_timeout() {
        let polls = SERVING_DEADLINE.as_secs() / POLL_INTERVAL.as_secs() + 1;
        let mut script = vec![started()];
        script.extend((0..polls).map(|_| ok(json!(0))));
        let (outcome, received) = run(script);
        assert_eq!(outcome.unwrap_err().code(), "acurast_tunnel_start_timeout");
        assert_eq!(received.len() as u64, 1 + polls);
    }

    #[test]
    fn writes_the_marker_before_the_first_request() {
        let root = scratch_root();
        let marker = root.join(ATTEMPT_MARKER_FILE);
        let bridge = ScriptedBridge::serve(vec![error(-32602, "Invalid params")], marker.clone());
        let _ = start_once(&root, &bridge.socket_name, &test_spec(), &FakeClock::new());
        let received = bridge.finish();
        assert_eq!(methods(&received), [METHOD_START]);
        assert!(received[0].marker_present);
        let mode = std::fs::metadata(&marker).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_second_start_in_the_same_root_opens_no_socket() {
        let root = scratch_root();
        let first = ScriptedBridge::serve(
            vec![error(-32603, "Internal error: tunnel already active")],
            root.join(ATTEMPT_MARKER_FILE),
        );
        let outcome = start_once(&root, &first.socket_name, &test_spec(), &FakeClock::new());
        assert_eq!(outcome.unwrap_err().code(), "acurast_tunnel_already_active");
        assert_eq!(first.finish().len(), 1);

        let second = ScriptedBridge::serve(vec![started()], root.join(ATTEMPT_MARKER_FILE));
        let outcome = start_once(&root, &second.socket_name, &test_spec(), &FakeClock::new());
        assert_eq!(
            outcome.unwrap_err().code(),
            "acurast_tunnel_attempt_already_spent"
        );
        assert_eq!(second.finish().len(), 0);
    }

    #[test]
    fn an_absent_bridge_is_unavailable_and_spends_the_attempt() {
        let root = scratch_root();
        let outcome = start_once(
            &root,
            &unique("liskov-acurast-tunnel-absent"),
            &test_spec(),
            &FakeClock::new(),
        );
        assert_eq!(
            outcome.unwrap_err().code(),
            "acurast_tunnel_bridge_unavailable"
        );
        assert!(root.join(ATTEMPT_MARKER_FILE).exists());
    }

    #[test]
    fn stop_is_issued_only_from_serving() {
        let root = scratch_root();
        let bridge = ScriptedBridge::serve(
            vec![
                started(),
                ok(json!(1)),
                ok(json!(CERT_PEM)),
                ok(Value::Null),
            ],
            root.join(ATTEMPT_MARKER_FILE),
        );
        let serving =
            start_once(&root, &bridge.socket_name, &test_spec(), &FakeClock::new()).unwrap();
        assert_eq!(serving.stop(), Ok(()));
        let received = bridge.finish();
        assert_eq!(received.last().unwrap().method, METHOD_STOP);
    }

    #[test]
    fn the_system_clock_moves_forward() {
        let clock = SystemPollClock;
        let before = clock.now();
        clock.sleep(Duration::from_millis(1));
        assert!(clock.now() > before);
    }

    #[test]
    fn debug_output_carries_no_pem_and_no_key_bytes() {
        let pkcs8 = test_pkcs8();
        let identity = TunnelIdentity::from_pkcs8(pkcs8.clone()).unwrap();
        let spec = build_spec(&identity, &[port(18081)], false).unwrap();
        let root = scratch_root();
        let bridge = ScriptedBridge::serve(
            vec![started(), ok(json!(1)), ok(json!(CERT_PEM))],
            root.join(ATTEMPT_MARKER_FILE),
        );
        let serving = start_once(&root, &bridge.socket_name, &spec, &FakeClock::new()).unwrap();
        bridge.finish();

        let rendered = [
            format!("{identity:?}"),
            format!("{spec:?}"),
            format!("{serving:?}"),
            format!("{:?}", AcurastTunnelFailure::FailedAfterCertificate),
        ]
        .join("\n");
        let encoded = BASE64_STANDARD.encode(pkcs8.as_slice());
        assert!(!rendered.contains(&encoded));
        assert!(!rendered.contains(&encoded[..32]));
        assert!(!rendered.contains(&hex::encode(pkcs8.as_slice())[..32]));
        assert!(!rendered.contains(&identity.public_key_hex()));
        assert!(!rendered.contains("BEGIN CERTIFICATE"));
        assert!(!rendered.contains("certificatebody"));
        assert!(rendered.contains(URL));
    }
}
