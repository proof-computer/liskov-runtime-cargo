//! Built-in blind managed-access connector and loopback-only Dropbear canary.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use futures_util::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{AUTHORIZATION, SEC_WEBSOCKET_PROTOCOL};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use zeroize::{Zeroize, Zeroizing};

use super::{
    AccessError, CREDENTIAL_SCHEMA, ManagedRuntimeSshCredentialProvider,
    ManagedRuntimeSshCredentialV1, private_root, runtime_job_ids_match, terminate_child,
    unix_time_ms,
};
use crate::protocol::{
    ManagedRuntimeAccessBootstrap, ManagedRuntimeAccessProtocol, RuntimeAccessProviderKind,
    RuntimeBootstrapResponse,
};

const SETUP_LIMIT: Duration = Duration::from_secs(180);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_COMMAND_OUTPUT: usize = 64 * 1024;
const MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_DIRECTION_BYTES: u64 = 1024 * 1024 * 1024;
const CONNECTOR_SUBPROTOCOL: &str = "liskov-access.v0";
const FIXED_SSH_TARGET: &str = "127.0.0.1:2222";

pub struct ManagedAccessSession {
    dropbear: Child,
    connector: ConnectorWorker,
    root: PathBuf,
    attachment_id: String,
    fence: u64,
    host_public_key: String,
    host_fingerprint: String,
    degraded_reported: bool,
    stopped: bool,
}

impl ManagedAccessSession {
    pub(super) fn binding_attrs(&self) -> serde_json::Value {
        serde_json::json!({
            "attachmentId": self.attachment_id,
            "fence": self.fence,
            "providerKind": "liskov",
        })
    }

    pub(super) fn ready_attrs(&self) -> serde_json::Value {
        serde_json::json!({
            "attachmentId": self.attachment_id,
            "fence": self.fence,
            "providerKind": "liskov",
            "hostPublicKey": self.host_public_key,
            "hostFingerprint": self.host_fingerprint,
            "clientVersion": env!("CARGO_PKG_VERSION"),
        })
    }

    pub(super) fn newly_crashed(&mut self) -> bool {
        if self.degraded_reported {
            return false;
        }
        let dropbear_crashed = self.dropbear.try_wait().ok().flatten().is_some();
        let connector_crashed = self.connector.is_finished();
        if dropbear_crashed || connector_crashed {
            self.degraded_reported = true;
            true
        } else {
            false
        }
    }

    pub(super) fn stop(&mut self) -> Result<(), AccessError> {
        if self.stopped {
            return Ok(());
        }
        self.stopped = true;
        let connector_result = self.connector.stop();
        let dropbear_result = terminate_child(&mut self.dropbear);
        let remove_result = std::fs::remove_dir_all(&self.root)
            .map_err(|_| AccessError::new("access_cleanup_failed"));
        connector_result.and(dropbear_result).and(remove_result)
    }
}

struct ConnectorWorker {
    cancel: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl ConnectorWorker {
    fn is_finished(&self) -> bool {
        self.handle
            .as_ref()
            .is_none_or(thread::JoinHandle::is_finished)
    }

    fn stop(&mut self) -> Result<(), AccessError> {
        self.cancel.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            handle
                .join()
                .map_err(|_| AccessError::new("access_cleanup_failed"))?;
        }
        Ok(())
    }
}

impl Drop for ConnectorWorker {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

pub(super) fn setup(
    bootstrap: &RuntimeBootstrapResponse,
    access: &ManagedRuntimeAccessBootstrap,
    credential: ManagedRuntimeSshCredentialV1,
) -> Result<ManagedAccessSession, AccessError> {
    let now_ms = unix_time_ms().ok_or_else(|| AccessError::new("access_setup_failed"))?;
    let setup_deadline = setup_deadline(access.setup_deadline_ms, now_ms)?;
    let validated = validate_binding(bootstrap, access, credential, now_ms)?;
    let root = private_root(&access.attachment_id)?;
    let result = setup_in_root(access, validated, &root, setup_deadline);
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&root);
    }
    result
}

struct ValidatedCredential {
    connector_token: Zeroizing<String>,
    operator_public_key: Zeroizing<String>,
    expires_at_ms: u64,
}

fn validate_binding(
    bootstrap: &RuntimeBootstrapResponse,
    access: &ManagedRuntimeAccessBootstrap,
    mut credential: ManagedRuntimeSshCredentialV1,
    now_ms: u64,
) -> Result<ValidatedCredential, AccessError> {
    if credential.schema != CREDENTIAL_SCHEMA
        || credential.organization_id.is_empty()
        || credential.attachment_id != access.attachment_id
        || credential.application_uid != bootstrap.application_uid
        || credential.deployment_id != bootstrap.deployment_id
        || !runtime_job_ids_match(&credential.job_id, &bootstrap.job_id)
        || credential.policy_digest != bootstrap.policy_digest
        || credential.fence != access.fence
        || credential.expires_at_ms < access.setup_deadline_ms
        || credential.expires_at_ms <= now_ms
        || access.setup_deadline_ms <= now_ms
        || access.provider.kind != RuntimeAccessProviderKind::Liskov
        || access.protocol != ManagedRuntimeAccessProtocol::LiskovAccessV0
    {
        return Err(AccessError::new("access_setup_failed"));
    }
    match &mut credential.provider {
        ManagedRuntimeSshCredentialProvider::Liskov {
            connector_token,
            operator_public_key,
        } if valid_connector_token(connector_token)
            && parse_ed25519_public_key(operator_public_key).is_some() =>
        {
            Ok(ValidatedCredential {
                connector_token: Zeroizing::new(std::mem::take(connector_token)),
                operator_public_key: Zeroizing::new(std::mem::take(operator_public_key)),
                expires_at_ms: credential.expires_at_ms,
            })
        }
        _ => Err(AccessError::new("access_setup_failed")),
    }
}

fn setup_deadline(setup_deadline_ms: u64, now_ms: u64) -> Result<Instant, AccessError> {
    let remaining_ms = setup_deadline_ms
        .checked_sub(now_ms)
        .ok_or_else(|| AccessError::new("access_setup_failed"))?;
    let remaining = Duration::from_millis(remaining_ms).min(SETUP_LIMIT);
    (!remaining.is_zero())
        .then(|| Instant::now() + remaining)
        .ok_or_else(|| AccessError::new("access_setup_failed"))
}

fn setup_in_root(
    access: &ManagedRuntimeAccessBootstrap,
    credential: ValidatedCredential,
    root: &Path,
    deadline: Instant,
) -> Result<ManagedAccessSession, AccessError> {
    install_dropbear(deadline)?;
    verify_dropbear_options(deadline)?;

    let host_key_path = root.join("dropbear-ed25519-host-key");
    run_checked(
        "dropbearkey",
        &[
            OsString::from("-t"),
            OsString::from("ed25519"),
            OsString::from("-f"),
            host_key_path.as_os_str().to_os_string(),
        ],
        deadline,
    )?;
    std::fs::set_permissions(&host_key_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| AccessError::new("access_setup_failed"))?;
    let public_output = run_capture(
        "dropbearkey",
        &[
            OsString::from("-y"),
            OsString::from("-f"),
            host_key_path.as_os_str().to_os_string(),
        ],
        deadline,
        true,
    )?;
    let (host_public_key, host_fingerprint) = host_public_evidence(&public_output)?;

    let authorization_dir = root.join("authorization");
    std::fs::create_dir(&authorization_dir).map_err(|_| AccessError::new("access_setup_failed"))?;
    std::fs::set_permissions(&authorization_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| AccessError::new("access_setup_failed"))?;
    write_private(
        &authorization_dir.join("authorized_keys"),
        format!("{}\n", credential.operator_public_key.as_str()).as_bytes(),
    )?;

    let pid_file = root.join("dropbear.pid");
    let endpoint = connector_endpoint(&access.gateway_url, &access.tunnel_id)?;
    let mut dropbear = spawn_dropbear(&host_key_path, &authorization_dir, &pid_file)?;
    let start_check = Instant::now() + Duration::from_millis(150);
    while Instant::now() < start_check {
        if dropbear
            .try_wait()
            .map_err(|_| AccessError::new("access_sidecar_failed"))?
            .is_some()
        {
            return Err(AccessError::new("access_sidecar_failed"));
        }
        thread::sleep(POLL_INTERVAL);
    }

    let (registered_sender, registered_receiver) = mpsc::sync_channel(1);
    let mut connector = match spawn_connector(
        endpoint,
        credential.connector_token,
        credential.expires_at_ms,
        registered_sender,
    ) {
        Ok(connector) => connector,
        Err(error) => {
            let _ = terminate_child(&mut dropbear);
            return Err(error);
        }
    };
    let registration_wait = deadline.saturating_duration_since(Instant::now());
    match registered_receiver.recv_timeout(registration_wait) {
        Ok(()) => {}
        Err(_) => {
            let _ = connector.stop();
            let _ = terminate_child(&mut dropbear);
            return Err(AccessError::new("access_connector_registration_failed"));
        }
    }

    Ok(ManagedAccessSession {
        dropbear,
        connector,
        root: root.to_path_buf(),
        attachment_id: access.attachment_id.clone(),
        fence: access.fence,
        host_public_key,
        host_fingerprint,
        degraded_reported: false,
        stopped: false,
    })
}

fn install_dropbear(deadline: Instant) -> Result<(), AccessError> {
    run_checked("apt-get", &[OsString::from("update")], deadline)?;
    let (program, arguments) = dropbear_install_argv();
    run_checked(
        program,
        &arguments.iter().map(OsString::from).collect::<Vec<_>>(),
        deadline,
    )
}

fn dropbear_install_argv() -> (&'static str, [&'static str; 3]) {
    ("apt-get", ["install", "-y", "dropbear"])
}

fn verify_dropbear_options(deadline: Instant) -> Result<(), AccessError> {
    let output = run_capture("dropbear", &[OsString::from("-h")], deadline, false)?;
    let text = String::from_utf8_lossy(&output);
    for required in ["-D", "-F", "-E", "-s", "-g", "-j", "-k", "-p", "-r", "-P"] {
        if !text.contains(required) {
            return Err(AccessError::new("access_dropbear_options_unsupported"));
        }
    }
    Ok(())
}

fn spawn_dropbear(
    host_key_path: &Path,
    authorization_dir: &Path,
    pid_file: &Path,
) -> Result<Child, AccessError> {
    let mut command = Command::new("dropbear");
    command
        .args(["-F", "-E", "-s", "-g", "-j", "-k", "-p", FIXED_SSH_TARGET])
        .arg("-r")
        .arg(host_key_path)
        .arg("-D")
        .arg(authorization_dir)
        .arg("-P")
        .arg(pid_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: this pre-exec hook performs only async-signal-safe setpgid.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    command
        .spawn()
        .map_err(|_| AccessError::new("access_sidecar_spawn_failed"))
}

fn run_checked(
    program: &str,
    arguments: &[OsString],
    deadline: Instant,
) -> Result<(), AccessError> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| AccessError::new("access_setup_failed"))?;
    wait_child(&mut child, deadline)?
        .success()
        .then_some(())
        .ok_or_else(|| AccessError::new("access_setup_failed"))
}

fn run_capture(
    program: &str,
    arguments: &[OsString],
    deadline: Instant,
    require_success: bool,
) -> Result<Vec<u8>, AccessError> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| AccessError::new("access_setup_failed"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| AccessError::new("access_setup_failed"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| AccessError::new("access_setup_failed"))?;
    let stdout_thread = thread::spawn(move || bounded_read(&mut stdout));
    let stderr_thread = thread::spawn(move || bounded_read(&mut stderr));
    let status = wait_child(&mut child, deadline)?;
    let mut output = stdout_thread
        .join()
        .map_err(|_| AccessError::new("access_setup_failed"))??;
    let stderr = stderr_thread
        .join()
        .map_err(|_| AccessError::new("access_setup_failed"))??;
    if output.len().saturating_add(stderr.len()) > MAX_COMMAND_OUTPUT {
        output.zeroize();
        return Err(AccessError::new("access_setup_failed"));
    }
    output.extend(stderr);
    if require_success && !status.success() {
        output.zeroize();
        return Err(AccessError::new("access_setup_failed"));
    }
    Ok(output)
}

fn bounded_read(reader: &mut impl Read) -> Result<Vec<u8>, AccessError> {
    let mut output = Vec::new();
    reader
        .take(u64::try_from(MAX_COMMAND_OUTPUT).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut output)
        .map_err(|_| AccessError::new("access_setup_failed"))?;
    (output.len() <= MAX_COMMAND_OUTPUT)
        .then_some(output)
        .ok_or_else(|| AccessError::new("access_setup_failed"))
}

fn wait_child(
    child: &mut Child,
    deadline: Instant,
) -> Result<std::process::ExitStatus, AccessError> {
    let command_deadline = deadline;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| AccessError::new("access_setup_failed"))?
        {
            return Ok(status);
        }
        if Instant::now() >= command_deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(AccessError::new("access_setup_failed"));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), AccessError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| AccessError::new("access_setup_failed"))?;
    file.write_all(bytes)
        .map_err(|_| AccessError::new("access_setup_failed"))?;
    file.sync_all()
        .map_err(|_| AccessError::new("access_setup_failed"))
}

fn host_public_evidence(output: &[u8]) -> Result<(String, String), AccessError> {
    let text = std::str::from_utf8(output).map_err(|_| AccessError::new("access_setup_failed"))?;
    let public_key = text
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("ssh-ed25519 "))
        .and_then(parse_ed25519_public_key)
        .ok_or_else(|| AccessError::new("access_setup_failed"))?;
    let encoded = public_key
        .split_ascii_whitespace()
        .nth(1)
        .ok_or_else(|| AccessError::new("access_setup_failed"))?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| AccessError::new("access_setup_failed"))?;
    let fingerprint = format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob)));
    Ok((public_key, fingerprint))
}

fn parse_ed25519_public_key(value: &str) -> Option<String> {
    if value.len() > 1024 || value.contains(['\r', '\n', '\0']) {
        return None;
    }
    let mut parts = value.split_ascii_whitespace();
    if parts.next()? != "ssh-ed25519" {
        return None;
    }
    let encoded = parts.next()?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    if blob.len() != 51
        || &blob[0..4] != 11_u32.to_be_bytes().as_slice()
        || &blob[4..15] != b"ssh-ed25519"
        || &blob[15..19] != 32_u32.to_be_bytes().as_slice()
    {
        return None;
    }
    Some(format!("ssh-ed25519 {encoded}"))
}

fn valid_connector_token(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn connector_endpoint(gateway_url: &str, tunnel_id: &str) -> Result<String, AccessError> {
    let url = format!(
        "{}/v0/connectors/{tunnel_id}",
        gateway_url.trim_end_matches('/')
    );
    let parsed = url::Url::parse(&url).map_err(|_| AccessError::new("access_setup_failed"))?;
    if parsed.scheme() != "wss"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(AccessError::new("access_setup_failed"));
    }
    Ok(url)
}

fn spawn_connector(
    endpoint: String,
    token: Zeroizing<String>,
    expires_at_ms: u64,
    registered: mpsc::SyncSender<()>,
) -> Result<ConnectorWorker, AccessError> {
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = cancel.clone();
    let handle = thread::Builder::new()
        .name("liskov-managed-access".into())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            if let Ok(runtime) = runtime {
                runtime.block_on(connector_loop(
                    endpoint,
                    token,
                    expires_at_ms,
                    worker_cancel,
                    registered,
                ));
            }
        })
        .map_err(|_| AccessError::new("access_connector_start_failed"))?;
    Ok(ConnectorWorker {
        cancel,
        handle: Some(handle),
    })
}

async fn connector_loop(
    endpoint: String,
    token: Zeroizing<String>,
    expires_at_ms: u64,
    cancel: Arc<AtomicBool>,
    registered: mpsc::SyncSender<()>,
) {
    let mut registered = Some(registered);
    let mut attempt = 0_u32;
    while !cancel.load(Ordering::Acquire)
        && unix_time_ms().is_some_and(|now_ms| now_ms < expires_at_ms)
    {
        match connect_once(&endpoint, &token, cancel.clone(), registered.as_ref()).await {
            Ok(()) => {
                registered = None;
                attempt = 0;
            }
            Err(()) => {
                attempt = attempt.saturating_add(1);
            }
        }
        let delay = reconnect_delay(attempt);
        if wait_cancelled(cancel.clone(), delay).await {
            break;
        }
    }
}

async fn connect_once(
    endpoint: &str,
    token: &str,
    cancel: Arc<AtomicBool>,
    registered: Option<&mpsc::SyncSender<()>>,
) -> Result<(), ()> {
    let mut request = endpoint.into_client_request().map_err(|_| ())?;
    let authorization = format!("Bearer {token}").parse().map_err(|_| ())?;
    request.headers_mut().insert(AUTHORIZATION, authorization);
    request.headers_mut().insert(
        SEC_WEBSOCKET_PROTOCOL,
        CONNECTOR_SUBPROTOCOL.parse().map_err(|_| ())?,
    );
    let mut config = WebSocketConfig::default();
    config.max_message_size = Some(MAX_FRAME_BYTES);
    config.max_frame_size = Some(MAX_FRAME_BYTES);
    let connecting = tokio_tungstenite::connect_async_with_config(request, Some(config), false);
    let (mut websocket, response) = tokio::select! {
        result = tokio::time::timeout(CONNECT_TIMEOUT, connecting) => result.map_err(|_| ())?.map_err(|_| ())?,
        _ = wait_until_cancelled(cancel.clone()) => return Err(()),
    };
    if response
        .headers()
        .get(SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        != Some(CONNECTOR_SUBPROTOCOL)
    {
        let _ = websocket.close(None).await;
        return Err(());
    }
    if let Some(registered) = registered {
        let _ = registered.try_send(());
    }
    wait_for_open_and_relay(&mut websocket, cancel).await
}

async fn wait_for_open_and_relay<S>(
    websocket: &mut tokio_tungstenite::WebSocketStream<S>,
    cancel: Arc<AtomicBool>,
) -> Result<(), ()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let message = tokio::select! {
            message = websocket.next() => message,
            _ = wait_until_cancelled(cancel.clone()) => {
                let _ = websocket.close(None).await;
                return Ok(());
            }
        };
        match message {
            Some(Ok(Message::Text(text))) if text == "open" => break,
            Some(Ok(Message::Ping(bytes))) => {
                websocket.send(Message::Pong(bytes)).await.map_err(|_| ())?
            }
            Some(Ok(Message::Pong(_))) => {}
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return Err(()),
            Some(Ok(_)) => return Err(()),
        }
    }

    let mut tcp = tokio::select! {
        result = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(FIXED_SSH_TARGET)) => result.map_err(|_| ())?.map_err(|_| ())?,
        _ = wait_until_cancelled(cancel.clone()) => return Ok(()),
    };
    let mut tcp_buffer = vec![0_u8; MAX_FRAME_BYTES];
    let mut websocket_to_tcp = 0_u64;
    let mut tcp_to_websocket = 0_u64;
    loop {
        tokio::select! {
            read = tcp.read(&mut tcp_buffer) => {
                let read = read.map_err(|_| ())?;
                if read == 0 {
                    let _ = websocket.close(None).await;
                    return Ok(());
                }
                tcp_to_websocket = tcp_to_websocket.saturating_add(u64::try_from(read).map_err(|_| ())?);
                if tcp_to_websocket > MAX_DIRECTION_BYTES {
                    return Err(());
                }
                websocket
                    .send(Message::Binary(tcp_buffer[..read].to_vec().into()))
                    .await
                    .map_err(|_| ())?;
            }
            message = websocket.next() => {
                match message {
                    Some(Ok(Message::Binary(bytes))) => {
                        if bytes.len() > MAX_FRAME_BYTES {
                            return Err(());
                        }
                        websocket_to_tcp = websocket_to_tcp.saturating_add(u64::try_from(bytes.len()).map_err(|_| ())?);
                        if websocket_to_tcp > MAX_DIRECTION_BYTES {
                            return Err(());
                        }
                        tcp.write_all(&bytes).await.map_err(|_| ())?;
                    }
                    Some(Ok(Message::Ping(bytes))) => websocket.send(Message::Pong(bytes)).await.map_err(|_| ())?,
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return Ok(()),
                    Some(Ok(Message::Text(_))) | Some(Ok(Message::Frame(_))) => return Err(()),
                }
            }
            _ = wait_until_cancelled(cancel.clone()) => {
                let _ = tcp.shutdown().await;
                let _ = websocket.close(None).await;
                return Ok(());
            }
        }
    }
}

fn reconnect_delay(attempt: u32) -> Duration {
    let exponent = attempt.min(5);
    let base_ms = 250_u64.saturating_mul(1_u64 << exponent).min(8_000);
    let mut jitter = [0_u8; 2];
    let jitter_ms = if getrandom::fill(&mut jitter).is_ok() {
        u64::from(u16::from_le_bytes(jitter)) % 251
    } else {
        0
    };
    Duration::from_millis(base_ms.saturating_add(jitter_ms))
}

async fn wait_until_cancelled(cancel: Arc<AtomicBool>) {
    while !cancel.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_cancelled(cancel: Arc<AtomicBool>, duration: Duration) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(duration) => false,
        _ = wait_until_cancelled(cancel) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn compatibility_install_uses_exact_argv_without_a_shell() {
        assert_eq!(
            dropbear_install_argv(),
            ("apt-get", ["install", "-y", "dropbear"])
        );
    }

    #[test]
    fn operator_key_and_host_evidence_are_strict_ed25519_openssh() {
        assert_eq!(
            parse_ed25519_public_key(PUBLIC_KEY).as_deref(),
            Some(PUBLIC_KEY)
        );
        assert!(parse_ed25519_public_key("ssh-rsa AAAA").is_none());
        assert!(parse_ed25519_public_key("ssh-ed25519 AAAA\nsecret").is_none());

        let output = format!("Public key portion is:\n{PUBLIC_KEY}\nFingerprint: ignored\n");
        let (public, fingerprint) = host_public_evidence(output.as_bytes()).unwrap();
        assert_eq!(public, PUBLIC_KEY);
        assert!(fingerprint.starts_with("SHA256:"));
        assert!(!fingerprint.contains('='));
    }

    #[test]
    fn connector_endpoint_and_target_are_fixed_and_credential_free() {
        assert_eq!(
            connector_endpoint("wss://access.example", "tunnel_123").unwrap(),
            "wss://access.example/v0/connectors/tunnel_123"
        );
        assert_eq!(FIXED_SSH_TARGET, "127.0.0.1:2222");
        assert!(connector_endpoint("ws://access.example", "tunnel_123").is_err());
    }

    #[test]
    fn reconnect_backoff_is_capped_far_below_connection_rate_limit() {
        for attempt in 0..100 {
            let delay = reconnect_delay(attempt);
            assert!(delay >= Duration::from_millis(250));
            assert!(delay <= Duration::from_millis(8_250));
        }
    }
}
