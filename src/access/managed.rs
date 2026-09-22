//! Built-in blind managed-access connector and loopback-only Dropbear canary.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream as StdTcpStream};
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
use tokio_tungstenite::tungstenite::Error as WebSocketError;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{AUTHORIZATION, SEC_WEBSOCKET_PROTOCOL};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use zeroize::{Zeroize, Zeroizing};

use super::{
    AccessError, CompactManagedRuntimeSshCredentialProviderV2, MANAGED_CREDENTIAL_SCHEMA_V2,
    ManagedRuntimeSshCredential, ManagedRuntimeSshCredentialProviderV2, SidecarEvent, private_root,
    runtime_job_ids_match, terminate_child, unix_time_ms,
};
use crate::logging::RuntimeSshLogEmitter;
use crate::protocol::{
    ManagedRuntimeAccessBootstrap, ManagedRuntimeAccessToolchain, RuntimeAccessProviderKind,
    RuntimeBootstrapResponse,
};

const SETUP_LIMIT: Duration = Duration::from_secs(180);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Once a credential has been admitted, a later `401` most likely means the
/// attachment was revoked, stopped or fence-superseded. The blind gateway cannot
/// say so, and a control-plane hiccup looks the same, so back off to this
/// ceiling rather than stop.
const REFUSED_AFTER_ADMISSION_CEILING: Duration = Duration::from_secs(300);
const MAX_COMMAND_OUTPUT: usize = 64 * 1024;
const MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_DIRECTION_BYTES: u64 = 1024 * 1024 * 1024;
const CONNECTOR_SUBPROTOCOL_V1: &str = "liskov-access.v1";
const FIXED_SSH_TARGET: &str = "127.0.0.1:2222";
const DROPBEAR_ARGV0_NO_REEXEC: &str = "/liskov-dropbear-no-reexec";
const DROPBEAR_FILENAME: &str = "liskov-dropbear";
const DROPBEARKEY_FILENAME: &str = "liskov-dropbearkey";
const MAX_TOOLCHAIN_BINARY_BYTES: u64 = 32 * 1024 * 1024;
const DROPBEAR_START_CHECK: Duration = Duration::from_millis(150);
/// A dead Dropbear is restarted at most this many times over the session's
/// life, the helper's usual budget (`PROVIDER_FETCH_ATTEMPTS`,
/// `BRING_UP_ATTEMPTS`). A death after that stays degraded.
pub(super) const MAX_SIDECAR_RESPAWNS: u32 = 3;
/// A respawn runs inline in the supervision loop, so its listener check is
/// bounded like the endpoint probes rather than by the setup deadline.
const RESPAWN_LISTENER_LIMIT: Duration = Duration::from_secs(2);

/// Starts Dropbear again with the session's host key, authorized keys and pid
/// file, and returns it only once it is listening.
type SidecarRespawn = Box<dyn FnMut() -> Result<Child, AccessError> + Send>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SidecarState {
    Running,
    /// Dropbear exited and was reported; the next respawn is due at `retry_at`.
    Down {
        retry_at: Instant,
    },
    /// Reported and never respawned: the connector finished or the respawn
    /// budget is spent.
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectorAttemptError {
    ConfigurationFailed,
    ConnectTimeout,
    HttpRefused(u16),
    TransportFailed,
    ProtocolFailed,
    RelayFailed,
    Cancelled,
}

impl ConnectorAttemptError {
    fn code(self) -> Option<&'static str> {
        match self {
            Self::ConfigurationFailed => Some("access_connector_configuration_failed"),
            Self::ConnectTimeout => Some("access_connector_connect_timeout"),
            Self::HttpRefused(_) => Some("access_connector_http_refused"),
            Self::TransportFailed => Some("access_connector_transport_failed"),
            Self::ProtocolFailed => Some("access_connector_protocol_failed"),
            Self::RelayFailed => Some("access_connector_relay_failed"),
            Self::Cancelled => None,
        }
    }

    fn http_status(self) -> Option<u16> {
        match self {
            Self::HttpRefused(status) => Some(status),
            _ => None,
        }
    }

    fn access_error(self) -> Option<AccessError> {
        self.code().map(AccessError::new)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectorRegistrationEvent {
    Registered,
    Failed(ConnectorAttemptError),
}

enum ConnectorConnectResult<T> {
    Completed(Result<T, WebSocketError>),
    TimedOut,
    Cancelled,
}

pub struct ManagedAccessSession {
    dropbear: Child,
    connector: ConnectorWorker,
    root: PathBuf,
    attachment_id: String,
    fence: u64,
    host_public_key: String,
    host_fingerprint: String,
    sidecar: SidecarState,
    respawn: SidecarRespawn,
    respawn_delay: fn(u32) -> Duration,
    respawns_used: u32,
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

    pub(super) fn sidecar_event(&mut self) -> SidecarEvent {
        self.sidecar_event_at(Instant::now())
    }

    /// Advance the sidecar state machine. Called on every supervision-loop
    /// pass, so it never sleeps for the backoff: a respawn is only attempted
    /// on the first pass after it falls due.
    fn sidecar_event_at(&mut self, now: Instant) -> SidecarEvent {
        if self.stopped {
            return SidecarEvent::Unchanged;
        }
        match self.sidecar {
            SidecarState::Terminal => SidecarEvent::Unchanged,
            SidecarState::Running => {
                // The connector reconnects on its own until the credential
                // expires, so its thread finishing is final.
                if self.connector.is_finished() {
                    self.sidecar = SidecarState::Terminal;
                    return SidecarEvent::Crashed;
                }
                if self.dropbear.try_wait().ok().flatten().is_none() {
                    return SidecarEvent::Unchanged;
                }
                self.sidecar = self.next_respawn(now);
                SidecarEvent::Crashed
            }
            SidecarState::Down { retry_at } => {
                if self.connector.is_finished() {
                    // Already reported degraded; nothing left to relay to.
                    self.sidecar = SidecarState::Terminal;
                    return SidecarEvent::Unchanged;
                }
                if now < retry_at {
                    return SidecarEvent::Unchanged;
                }
                self.respawns_used += 1;
                let started = Instant::now();
                let result = (self.respawn)();
                let elapsed = started.elapsed();
                let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
                match result {
                    Ok(dropbear) => {
                        self.dropbear = dropbear;
                        self.sidecar = SidecarState::Running;
                        SidecarEvent::Recovered { elapsed_ms }
                    }
                    Err(error) => {
                        self.sidecar = self.next_respawn(now + elapsed);
                        if self.sidecar == SidecarState::Terminal {
                            SidecarEvent::Exhausted {
                                elapsed_ms,
                                code: error.code,
                            }
                        } else {
                            SidecarEvent::RespawnFailed {
                                elapsed_ms,
                                code: error.code,
                            }
                        }
                    }
                }
            }
        }
    }

    fn next_respawn(&self, now: Instant) -> SidecarState {
        if self.respawns_used < MAX_SIDECAR_RESPAWNS {
            SidecarState::Down {
                retry_at: now + (self.respawn_delay)(self.respawns_used),
            }
        } else {
            SidecarState::Terminal
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

    /// A session whose sidecar is `program`, respawned as the same program.
    #[cfg(test)]
    pub(crate) fn for_test(program: &str, args: &[&str]) -> Result<Self, AccessError> {
        let root = private_root("o8c9-session-test")?;
        let mut dropbear = spawn_test_sidecar(program, args)?;
        let respawn_program = program.to_string();
        let respawn_args = args.iter().map(ToString::to_string).collect::<Vec<_>>();
        let respawn: SidecarRespawn = Box::new(move || {
            let args = respawn_args.iter().map(String::as_str).collect::<Vec<_>>();
            spawn_test_sidecar(&respawn_program, &args)
        });
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let handle = match thread::Builder::new()
            .name("liskov-managed-access-test".into())
            .spawn(move || {
                while !worker_cancel.load(Ordering::Acquire) {
                    thread::sleep(Duration::from_millis(10));
                }
            }) {
            Ok(handle) => handle,
            Err(_) => {
                let _ = terminate_child(&mut dropbear);
                let _ = std::fs::remove_dir_all(&root);
                return Err(AccessError::new("access_connector_start_failed"));
            }
        };
        Ok(Self {
            dropbear,
            connector: ConnectorWorker {
                cancel,
                handle: Some(handle),
            },
            root,
            attachment_id: "att-test".into(),
            fence: 1,
            host_public_key: String::new(),
            host_fingerprint: String::new(),
            sidecar: SidecarState::Running,
            respawn,
            respawn_delay: reconnect_delay,
            respawns_used: 0,
            stopped: false,
        })
    }

    /// Replace the respawn step, which in production re-verifies the toolchain
    /// and starts the real Dropbear on the fixed port.
    #[cfg(test)]
    pub(crate) fn with_respawn(
        mut self,
        respawn: impl FnMut() -> Result<Child, AccessError> + Send + 'static,
        respawn_delay: fn(u32) -> Duration,
    ) -> Self {
        self.respawn = Box::new(respawn);
        self.respawn_delay = respawn_delay;
        self
    }
}

#[cfg(test)]
pub(crate) fn spawn_test_sidecar(program: &str, args: &[&str]) -> Result<Child, AccessError> {
    let mut command = Command::new(program);
    command
        .args(args)
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
    credential: ManagedRuntimeSshCredential,
    provider_logger: Option<RuntimeSshLogEmitter>,
) -> Result<ManagedAccessSession, AccessError> {
    let now_ms = unix_time_ms().ok_or_else(|| AccessError::new("access_setup_failed"))?;
    let setup_deadline = setup_deadline(access.setup_deadline_ms, now_ms)?;
    let validated = validate_binding(bootstrap, access, credential, now_ms)?;
    let root = private_root(&access.attachment_id)?;
    let result = setup_in_root(access, validated, &root, setup_deadline, provider_logger);
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&root);
    }
    result
}

struct ValidatedCredential {
    connector_token: Zeroizing<String>,
    authorized_keys: Zeroizing<Vec<String>>,
    toolchain: ManagedRuntimeAccessToolchain,
    expires_at_ms: u64,
}

struct VerifiedToolchain {
    dropbear: PathBuf,
    dropbearkey: PathBuf,
}

fn validate_binding(
    bootstrap: &RuntimeBootstrapResponse,
    access: &ManagedRuntimeAccessBootstrap,
    credential: ManagedRuntimeSshCredential,
    now_ms: u64,
) -> Result<ValidatedCredential, AccessError> {
    if access.setup_deadline_ms <= now_ms
        || access.provider.kind != RuntimeAccessProviderKind::Liskov
    {
        return Err(AccessError::new("access_setup_failed"));
    }
    match credential {
        ManagedRuntimeSshCredential::V1Full(mut credential) => {
            let binding = validate_v1_bootstrap_binding(bootstrap, access)?;
            let Some(expected_toolchain) = access.toolchain.as_ref() else {
                return Err(AccessError::new("access_setup_failed"));
            };
            if credential.schema != MANAGED_CREDENTIAL_SCHEMA_V2
                || credential.organization_id != binding.organization_id
                || credential.attachment_id != access.attachment_id
                || credential.application_id != binding.application_id
                || credential.application_uid != binding.application_uid
                || credential.liskov_deployment_id != binding.liskov_deployment_id
                || credential.deployment_id != binding.deployment_id
                || credential.liskov_job_id != binding.liskov_job_id
                || credential.job_id != binding.job_id
                || credential.policy_digest != binding.policy_digest
                || credential.fence != access.fence
                || credential.expires_at_ms < access.setup_deadline_ms
                || credential.expires_at_ms <= now_ms
            {
                return Err(AccessError::new("access_setup_failed"));
            }
            match &mut credential.provider {
                ManagedRuntimeSshCredentialProviderV2::Liskov {
                    connector_token,
                    authorized_keys,
                    toolchain,
                } if valid_connector_token(connector_token)
                    && toolchain.runtime_contact_sha256
                        == expected_toolchain.runtime_contact_sha256
                    && toolchain.dropbear_sha256 == expected_toolchain.dropbear_sha256
                    && toolchain.dropbearkey_sha256 == expected_toolchain.dropbearkey_sha256 =>
                {
                    let keys = normalized_authorized_keys(authorized_keys)?;
                    let fingerprints = keys
                        .iter()
                        .map(|key| ssh_public_key_fingerprint(key))
                        .collect::<Result<Vec<_>, _>>()?;
                    if fingerprints != access.authorized_key_fingerprints
                        || (!access.authorized_keys.is_empty() && keys != access.authorized_keys)
                    {
                        return Err(AccessError::new("access_setup_failed"));
                    }
                    Ok(ValidatedCredential {
                        connector_token: Zeroizing::new(std::mem::take(connector_token)),
                        authorized_keys: Zeroizing::new(keys),
                        toolchain: expected_toolchain.clone(),
                        expires_at_ms: credential.expires_at_ms,
                    })
                }
                _ => Err(AccessError::new("access_setup_failed")),
            }
        }
        ManagedRuntimeSshCredential::V1Compact(mut credential) => {
            validate_v1_bootstrap_binding(bootstrap, access)?;
            let Some(expected_toolchain) = access.toolchain.as_ref() else {
                return Err(AccessError::new("access_setup_failed"));
            };
            if credential.schema != MANAGED_CREDENTIAL_SCHEMA_V2
                || credential.attachment_id != access.attachment_id
                || credential.fence != access.fence
                || credential.expires_at_ms < access.setup_deadline_ms
                || credential.expires_at_ms <= now_ms
            {
                return Err(AccessError::new("access_setup_failed"));
            }
            match &mut credential.provider {
                CompactManagedRuntimeSshCredentialProviderV2::Liskov { connector_token }
                    if valid_connector_token(connector_token) =>
                {
                    let keys = normalized_authorized_keys(&access.authorized_keys)?;
                    let fingerprints = keys
                        .iter()
                        .map(|key| ssh_public_key_fingerprint(key))
                        .collect::<Result<Vec<_>, _>>()?;
                    if fingerprints != access.authorized_key_fingerprints {
                        return Err(AccessError::new("access_setup_failed"));
                    }
                    Ok(ValidatedCredential {
                        connector_token: Zeroizing::new(std::mem::take(connector_token)),
                        authorized_keys: Zeroizing::new(keys),
                        toolchain: expected_toolchain.clone(),
                        expires_at_ms: credential.expires_at_ms,
                    })
                }
                _ => Err(AccessError::new("access_setup_failed")),
            }
        }
    }
}

fn validate_v1_bootstrap_binding<'a>(
    bootstrap: &RuntimeBootstrapResponse,
    access: &'a ManagedRuntimeAccessBootstrap,
) -> Result<&'a crate::protocol::ManagedRuntimeAccessBinding, AccessError> {
    let binding = access
        .binding
        .as_ref()
        .ok_or_else(|| AccessError::new("access_setup_failed"))?;
    if binding.organization_id.is_empty()
        || binding.application_id != bootstrap.application_id
        || binding.application_uid != bootstrap.application_uid
        || binding.liskov_deployment_id.is_empty()
        || binding.deployment_id != bootstrap.deployment_id
        || binding.liskov_job_id.is_empty()
        || !runtime_job_ids_match(&binding.job_id, &bootstrap.job_id)
        || binding.policy_digest != bootstrap.policy_digest
    {
        return Err(AccessError::new("access_setup_failed"));
    }
    Ok(binding)
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

fn normalized_authorized_keys(values: &[String]) -> Result<Vec<String>, AccessError> {
    if !(1..=8).contains(&values.len()) {
        return Err(AccessError::new("access_setup_failed"));
    }
    let keys = values
        .iter()
        .map(|value| parse_ed25519_public_key(value))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| AccessError::new("access_setup_failed"))?;
    let unique = keys.iter().collect::<std::collections::BTreeSet<_>>();
    (unique.len() == keys.len())
        .then_some(keys)
        .ok_or_else(|| AccessError::new("access_setup_failed"))
}

fn ssh_public_key_fingerprint(value: &str) -> Result<String, AccessError> {
    let encoded = value
        .split(' ')
        .nth(1)
        .ok_or_else(|| AccessError::new("access_setup_failed"))?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| AccessError::new("access_setup_failed"))?;
    Ok(format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(Sha256::digest(blob))
    ))
}

fn verify_fixed_toolchain(
    runtime_contact_sha256: &str,
    dropbear_sha256: &str,
    dropbearkey_sha256: &str,
) -> Result<VerifiedToolchain, AccessError> {
    let helper = std::env::current_exe().map_err(|_| AccessError::new("access_setup_failed"))?;
    let directory = helper
        .parent()
        .ok_or_else(|| AccessError::new("access_setup_failed"))?;
    let dropbear = directory.join(DROPBEAR_FILENAME);
    let dropbearkey = directory.join(DROPBEARKEY_FILENAME);
    verify_toolchain_binary(&helper, runtime_contact_sha256)?;
    verify_toolchain_binary(&dropbear, dropbear_sha256)?;
    verify_toolchain_binary(&dropbearkey, dropbearkey_sha256)?;
    Ok(VerifiedToolchain {
        dropbear,
        dropbearkey,
    })
}

fn verify_toolchain_binary(path: &Path, expected_sha256: &str) -> Result<(), AccessError> {
    if expected_sha256.len() != 64
        || !expected_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AccessError::new("access_toolchain_digest_invalid"));
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| AccessError::new("access_toolchain_missing"))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_TOOLCHAIN_BINARY_BYTES {
        return Err(AccessError::new("access_toolchain_invalid"));
    }
    let file =
        std::fs::File::open(path).map_err(|_| AccessError::new("access_toolchain_missing"))?;
    let mut bytes = Vec::new();
    file.take(MAX_TOOLCHAIN_BINARY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AccessError::new("access_toolchain_invalid"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_TOOLCHAIN_BINARY_BYTES
        || hex::encode(Sha256::digest(&bytes)) != expected_sha256
    {
        bytes.zeroize();
        return Err(AccessError::new("access_toolchain_digest_mismatch"));
    }
    bytes.zeroize();
    Ok(())
}

fn setup_in_root(
    access: &ManagedRuntimeAccessBootstrap,
    credential: ValidatedCredential,
    root: &Path,
    deadline: Instant,
    provider_logger: Option<RuntimeSshLogEmitter>,
) -> Result<ManagedAccessSession, AccessError> {
    let verified = verify_fixed_toolchain(
        &credential.toolchain.runtime_contact_sha256,
        &credential.toolchain.dropbear_sha256,
        &credential.toolchain.dropbearkey_sha256,
    )?;
    let dropbear = verified.dropbear.as_path();
    let dropbearkey = verified.dropbearkey.as_path();
    verify_dropbear_options(dropbear, deadline)?;

    let host_key_path = root.join("dropbear-ed25519-host-key");
    run_checked(
        dropbearkey,
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
        dropbearkey,
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
        format!("{}\n", credential.authorized_keys.join("\n")).as_bytes(),
    )?;

    let pid_file = root.join("dropbear.pid");
    let endpoint = connector_endpoint(&access.gateway_url, &access.tunnel_id)?;
    let mut dropbear = spawn_dropbear(dropbear, &host_key_path, &authorization_dir, &pid_file)?;
    check_dropbear_started(&mut dropbear)?;
    if let Err(error) = verify_dropbear_listener(deadline) {
        let _ = terminate_child(&mut dropbear);
        return Err(error);
    }

    // The connector may fail and then register before this thread is scheduled
    // again. Preserve both ordered events: dropping a full-channel registration
    // would turn a successful retry back into a false setup timeout.
    let (registered_sender, registered_receiver) = mpsc::channel();
    let respawn = dropbear_respawner(
        credential.toolchain,
        host_key_path,
        authorization_dir,
        pid_file,
    );
    let mut connector = match spawn_connector(
        endpoint,
        credential.connector_token,
        credential.expires_at_ms,
        CONNECTOR_SUBPROTOCOL_V1,
        registered_sender,
        provider_logger,
    ) {
        Ok(connector) => connector,
        Err(error) => {
            let _ = terminate_child(&mut dropbear);
            return Err(error);
        }
    };
    if let Err(error) = wait_for_connector_registration(&registered_receiver, deadline) {
        let _ = connector.stop();
        let _ = terminate_child(&mut dropbear);
        return Err(error);
    }

    Ok(ManagedAccessSession {
        dropbear,
        connector,
        root: root.to_path_buf(),
        attachment_id: access.attachment_id.clone(),
        fence: access.fence,
        host_public_key,
        host_fingerprint,
        sidecar: SidecarState::Running,
        respawn,
        respawn_delay: reconnect_delay,
        respawns_used: 0,
        stopped: false,
    })
}

/// The production respawn step: the same toolchain check, arguments and
/// start checks as setup, reusing the session's host key and authorized keys
/// so the host key pinned at `ready` still matches.
fn dropbear_respawner(
    toolchain: ManagedRuntimeAccessToolchain,
    host_key_path: PathBuf,
    authorization_dir: PathBuf,
    pid_file: PathBuf,
) -> SidecarRespawn {
    Box::new(move || {
        let verified = verify_fixed_toolchain(
            &toolchain.runtime_contact_sha256,
            &toolchain.dropbear_sha256,
            &toolchain.dropbearkey_sha256,
        )
        .map_err(|_| AccessError::new("access_sidecar_spawn_failed"))?;
        let mut dropbear = spawn_dropbear(
            &verified.dropbear,
            &host_key_path,
            &authorization_dir,
            &pid_file,
        )?;
        let started = check_dropbear_started(&mut dropbear)
            .and_then(|()| verify_dropbear_listener(Instant::now() + RESPAWN_LISTENER_LIMIT));
        if let Err(error) = started {
            let _ = terminate_child(&mut dropbear);
            return Err(error);
        }
        Ok(dropbear)
    })
}

/// Dropbear exits at once on a bad key, a bad argument or a taken port.
fn check_dropbear_started(dropbear: &mut Child) -> Result<(), AccessError> {
    let start_check = Instant::now() + DROPBEAR_START_CHECK;
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
    Ok(())
}

fn wait_for_connector_registration(
    receiver: &mpsc::Receiver<ConnectorRegistrationEvent>,
    deadline: Instant,
) -> Result<(), AccessError> {
    let mut latest_failure = None;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(latest_failure
                .and_then(ConnectorAttemptError::access_error)
                .unwrap_or_else(|| AccessError::new("access_connector_registration_failed")));
        }
        match receiver.recv_timeout(remaining) {
            Ok(ConnectorRegistrationEvent::Registered) => return Ok(()),
            Ok(ConnectorRegistrationEvent::Failed(error)) => latest_failure = Some(error),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err(latest_failure
                    .and_then(ConnectorAttemptError::access_error)
                    .unwrap_or_else(|| AccessError::new("access_connector_registration_failed")));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(latest_failure
                    .and_then(ConnectorAttemptError::access_error)
                    .unwrap_or_else(|| AccessError::new("access_connector_registration_failed")));
            }
        }
    }
}

fn verify_dropbear_options(dropbear: &Path, deadline: Instant) -> Result<(), AccessError> {
    let output = run_capture(dropbear, &[OsString::from("-h")], deadline, false)?;
    let text = String::from_utf8_lossy(&output);
    for required in ["-D", "-F", "-E", "-s", "-g", "-j", "-k", "-p", "-r", "-P"] {
        if !text.contains(required) {
            return Err(AccessError::new("access_dropbear_options_unsupported"));
        }
    }
    Ok(())
}

fn dropbear_arguments(host_key: &Path, authorization_dir: &Path, pid_file: &Path) -> Vec<OsString> {
    vec![
        OsString::from("-F"),
        OsString::from("-E"),
        OsString::from("-s"),
        OsString::from("-g"),
        OsString::from("-j"),
        OsString::from("-k"),
        OsString::from("-p"),
        OsString::from(FIXED_SSH_TARGET),
        OsString::from("-r"),
        host_key.as_os_str().to_os_string(),
        OsString::from("-D"),
        authorization_dir.as_os_str().to_os_string(),
        OsString::from("-P"),
        pid_file.as_os_str().to_os_string(),
    ]
}

fn spawn_dropbear(
    dropbear: &Path,
    host_key_path: &Path,
    authorization_dir: &Path,
    pid_file: &Path,
) -> Result<Child, AccessError> {
    let mut command = Command::new(dropbear);
    command
        // Live Acurast PRoot dogfood closed the accepted connection before an
        // SSH banner on Dropbear's normal fexecve(2) path. Use Dropbear's built-
        // in straight-fork fallback by giving it an unopenable argv[0].
        .arg0(DROPBEAR_ARGV0_NO_REEXEC)
        .args(dropbear_arguments(
            host_key_path,
            authorization_dir,
            pid_file,
        ))
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

fn verify_dropbear_listener(deadline: Instant) -> Result<(), AccessError> {
    let address: SocketAddr = FIXED_SSH_TARGET
        .parse()
        .map_err(|_| AccessError::new("access_sidecar_failed"))?;
    let probe_deadline = deadline.min(Instant::now() + CONNECT_TIMEOUT);
    loop {
        let remaining = probe_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(AccessError::new("access_sidecar_failed"));
        }
        let connect_timeout = remaining.min(Duration::from_secs(1));
        match StdTcpStream::connect_timeout(&address, connect_timeout) {
            Ok(mut stream) => {
                stream
                    .set_read_timeout(Some(remaining))
                    .map_err(|_| AccessError::new("access_sidecar_failed"))?;
                let banner = read_ssh_banner(&mut stream)?;
                return valid_dropbear_banner(&banner)
                    .then_some(())
                    .ok_or_else(|| AccessError::new("access_sidecar_failed"));
            }
            Err(_) => thread::sleep(POLL_INTERVAL.min(remaining)),
        }
    }
}

fn read_ssh_banner(stream: &mut impl Read) -> Result<Vec<u8>, AccessError> {
    let mut banner = Vec::with_capacity(64);
    let mut byte = [0_u8; 1];
    while banner.len() < 255 {
        stream
            .read_exact(&mut byte)
            .map_err(|_| AccessError::new("access_sidecar_failed"))?;
        banner.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(banner);
        }
    }
    Err(AccessError::new("access_sidecar_failed"))
}

fn valid_dropbear_banner(banner: &[u8]) -> bool {
    banner.starts_with(b"SSH-2.0-dropbear_") && banner.ends_with(b"\r\n")
}

fn run_checked(
    program: &Path,
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
    program: &Path,
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
    value.len() <= 4096
        && value.split('.').count() == 3
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn connector_endpoint(gateway_url: &str, tunnel_id: &str) -> Result<String, AccessError> {
    let url = format!(
        "{}/v1/connectors/{tunnel_id}",
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
    subprotocol: &'static str,
    registered: mpsc::Sender<ConnectorRegistrationEvent>,
    provider_logger: Option<RuntimeSshLogEmitter>,
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
                connector_driver(
                    unix_time_ms,
                    |registered| {
                        runtime.block_on(connect_once(
                            &endpoint,
                            &token,
                            subprotocol,
                            worker_cancel.clone(),
                            registered,
                        ))
                    },
                    |delay| runtime.block_on(wait_cancelled(worker_cancel.clone(), delay)),
                    |elapsed_ms, outcome, code, http_status| {
                        if let Some(logger) = provider_logger.as_ref() {
                            logger.connector_stage(elapsed_ms, outcome, code, http_status);
                        }
                    },
                    &worker_cancel,
                    expires_at_ms,
                    Some(registered),
                );
            }
        })
        .map_err(|_| AccessError::new("access_connector_start_failed"))?;
    Ok(ConnectorWorker {
        cancel,
        handle: Some(handle),
    })
}

fn connector_driver<Now, Connect, Wait, Report>(
    mut now_ms: Now,
    mut connect_once: Connect,
    mut wait: Wait,
    mut report: Report,
    cancel: &AtomicBool,
    expires_at_ms: u64,
    mut registered: Option<mpsc::Sender<ConnectorRegistrationEvent>>,
) where
    Now: FnMut() -> Option<u64>,
    Connect: FnMut(
        Option<&mpsc::Sender<ConnectorRegistrationEvent>>,
    ) -> Result<(), ConnectorAttemptError>,
    Wait: FnMut(Duration) -> bool,
    Report: FnMut(u64, &'static str, Option<&'static str>, Option<u16>),
{
    let mut attempt = 0_u32;
    // `Ok`, `RelayFailed` and `ProtocolFailed` each got past the WebSocket
    // upgrade, which the gateway grants only once the control plane admitted
    // the credential.
    let mut admitted_once = false;
    let mut refusal_streak = 0_u32;
    while !cancel.load(Ordering::Acquire) && now_ms().is_some_and(|now_ms| now_ms < expires_at_ms) {
        let started = Instant::now();
        let mut refused = false;
        match connect_once(registered.as_ref()) {
            Ok(()) => {
                let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                report(elapsed_ms, "ok", None, None);
                registered = None;
                attempt = 0;
                admitted_once = true;
            }
            Err(ConnectorAttemptError::Cancelled) => {
                let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                report(elapsed_ms, "cancelled", None, None);
                break;
            }
            Err(error) => {
                if let Some(registered) = registered.as_ref() {
                    let _ = registered.send(ConnectorRegistrationEvent::Failed(error));
                }
                if matches!(
                    error,
                    ConnectorAttemptError::RelayFailed | ConnectorAttemptError::ProtocolFailed
                ) {
                    admitted_once = true;
                }
                refused = error == ConnectorAttemptError::HttpRefused(401);
                attempt = attempt.saturating_add(1);
                let can_retry = !cancel.load(Ordering::Acquire)
                    && now_ms().is_some_and(|now_ms| now_ms < expires_at_ms);
                let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                report(
                    elapsed_ms,
                    if can_retry { "retry" } else { "failed" },
                    error.code(),
                    error.http_status(),
                );
                if !can_retry {
                    break;
                }
            }
        }
        refusal_streak = if refused {
            refusal_streak.saturating_add(1)
        } else {
            0
        };
        let delay = if admitted_once && refused {
            refused_after_admission_delay(refusal_streak)
        } else {
            reconnect_delay(attempt)
        };
        if wait(delay) {
            break;
        }
    }
}

async fn connect_once(
    endpoint: &str,
    token: &str,
    subprotocol: &'static str,
    cancel: Arc<AtomicBool>,
    registered: Option<&mpsc::Sender<ConnectorRegistrationEvent>>,
) -> Result<(), ConnectorAttemptError> {
    let mut request = endpoint
        .into_client_request()
        .map_err(|_| ConnectorAttemptError::ConfigurationFailed)?;
    let authorization = format!("Bearer {token}")
        .parse()
        .map_err(|_| ConnectorAttemptError::ConfigurationFailed)?;
    request.headers_mut().insert(AUTHORIZATION, authorization);
    request.headers_mut().insert(
        SEC_WEBSOCKET_PROTOCOL,
        subprotocol
            .parse()
            .map_err(|_| ConnectorAttemptError::ConfigurationFailed)?,
    );
    let mut config = WebSocketConfig::default();
    config.max_message_size = Some(MAX_FRAME_BYTES);
    config.max_frame_size = Some(MAX_FRAME_BYTES);
    let connecting = tokio_tungstenite::connect_async_with_config(request, Some(config), false);
    let connect_result = tokio::select! {
        result = tokio::time::timeout(CONNECT_TIMEOUT, connecting) => match result {
            Ok(result) => ConnectorConnectResult::Completed(result),
            Err(_) => ConnectorConnectResult::TimedOut,
        },
        _ = wait_until_cancelled(cancel.clone()) => ConnectorConnectResult::Cancelled,
    };
    let (mut websocket, response) = classify_connector_connect(connect_result)?;
    if response
        .headers()
        .get(SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        != Some(subprotocol)
    {
        let _ = websocket.close(None).await;
        return Err(ConnectorAttemptError::ProtocolFailed);
    }
    if let Some(registered) = registered {
        let _ = registered.send(ConnectorRegistrationEvent::Registered);
    }
    wait_for_open_and_relay(&mut websocket, cancel).await
}

fn classify_connector_connect<T>(
    result: ConnectorConnectResult<T>,
) -> Result<T, ConnectorAttemptError> {
    match result {
        ConnectorConnectResult::Completed(Ok(connection)) => Ok(connection),
        ConnectorConnectResult::Completed(Err(WebSocketError::Http(response))) => Err(
            ConnectorAttemptError::HttpRefused(response.status().as_u16()),
        ),
        ConnectorConnectResult::Completed(Err(_)) => Err(ConnectorAttemptError::TransportFailed),
        ConnectorConnectResult::TimedOut => Err(ConnectorAttemptError::ConnectTimeout),
        ConnectorConnectResult::Cancelled => Err(ConnectorAttemptError::Cancelled),
    }
}

async fn wait_for_open_and_relay<S>(
    websocket: &mut tokio_tungstenite::WebSocketStream<S>,
    cancel: Arc<AtomicBool>,
) -> Result<(), ConnectorAttemptError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let message = tokio::select! {
            message = websocket.next() => message,
            _ = wait_until_cancelled(cancel.clone()) => {
                let _ = websocket.close(None).await;
                return Err(ConnectorAttemptError::Cancelled);
            }
        };
        match message {
            Some(Ok(Message::Text(text))) if text == "open" => break,
            Some(Ok(Message::Ping(bytes))) => websocket
                .send(Message::Pong(bytes))
                .await
                .map_err(|_| ConnectorAttemptError::RelayFailed)?,
            Some(Ok(Message::Pong(_))) => {}
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => {
                return Err(ConnectorAttemptError::RelayFailed);
            }
            Some(Ok(_)) => return Err(ConnectorAttemptError::ProtocolFailed),
        }
    }

    let mut tcp = tokio::select! {
        result = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(FIXED_SSH_TARGET)) => result
            .map_err(|_| ConnectorAttemptError::RelayFailed)?
            .map_err(|_| ConnectorAttemptError::RelayFailed)?,
        _ = wait_until_cancelled(cancel.clone()) => return Err(ConnectorAttemptError::Cancelled),
    };
    let mut tcp_buffer = vec![0_u8; MAX_FRAME_BYTES];
    let mut websocket_to_tcp = 0_u64;
    let mut tcp_to_websocket = 0_u64;
    loop {
        tokio::select! {
            read = tcp.read(&mut tcp_buffer) => {
                let read = read.map_err(|_| ConnectorAttemptError::RelayFailed)?;
                if read == 0 {
                    let _ = websocket.close(None).await;
                    return Ok(());
                }
                tcp_to_websocket = tcp_to_websocket.saturating_add(
                    u64::try_from(read).map_err(|_| ConnectorAttemptError::RelayFailed)?
                );
                if tcp_to_websocket > MAX_DIRECTION_BYTES {
                    return Err(ConnectorAttemptError::RelayFailed);
                }
                websocket
                    .send(Message::Binary(tcp_buffer[..read].to_vec().into()))
                    .await
                    .map_err(|_| ConnectorAttemptError::RelayFailed)?;
            }
            message = websocket.next() => {
                match message {
                    Some(Ok(Message::Binary(bytes))) => {
                        if bytes.len() > MAX_FRAME_BYTES {
                            return Err(ConnectorAttemptError::RelayFailed);
                        }
                        websocket_to_tcp = websocket_to_tcp.saturating_add(
                            u64::try_from(bytes.len())
                                .map_err(|_| ConnectorAttemptError::RelayFailed)?
                        );
                        if websocket_to_tcp > MAX_DIRECTION_BYTES {
                            return Err(ConnectorAttemptError::RelayFailed);
                        }
                        tcp.write_all(&bytes)
                            .await
                            .map_err(|_| ConnectorAttemptError::RelayFailed)?;
                    }
                    Some(Ok(Message::Ping(bytes))) => websocket
                        .send(Message::Pong(bytes))
                        .await
                        .map_err(|_| ConnectorAttemptError::RelayFailed)?,
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return Ok(()),
                    Some(Ok(Message::Text(_))) | Some(Ok(Message::Frame(_))) => {
                        return Err(ConnectorAttemptError::ProtocolFailed);
                    }
                }
            }
            _ = wait_until_cancelled(cancel.clone()) => {
                let _ = tcp.shutdown().await;
                let _ = websocket.close(None).await;
                return Err(ConnectorAttemptError::Cancelled);
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

/// The wait after the `refusal_streak`-th consecutive `401` once the credential
/// has been admitted: 8 s doubling to [`REFUSED_AFTER_ADMISSION_CEILING`], plus
/// the same 0–250 ms jitter as [`reconnect_delay`].
fn refused_after_admission_delay(refusal_streak: u32) -> Duration {
    let exponent = refusal_streak.saturating_sub(1).min(6);
    let ceiling_ms = u64::try_from(REFUSED_AFTER_ADMISSION_CEILING.as_millis()).unwrap_or(u64::MAX);
    let base_ms = 8_000_u64.saturating_mul(1_u64 << exponent).min(ceiling_ms);
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
    use crate::access::{
        CompactManagedRuntimeSshCredentialProviderV2, CompactManagedRuntimeSshCredentialV2,
        ManagedCredentialToolchain, ManagedRuntimeSshCredentialV2,
    };
    use crate::protocol::{
        ManagedRuntimeAccessBinding, ManagedRuntimeAccessProtocol, ManagedRuntimeAccessToolchain,
        RuntimeAccessProvider,
    };

    const PUBLIC_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

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
            "wss://access.example/v1/connectors/tunnel_123"
        );
        assert_eq!(FIXED_SSH_TARGET, "127.0.0.1:2222");
        assert_eq!(DROPBEAR_ARGV0_NO_REEXEC, "/liskov-dropbear-no-reexec");
        assert!(connector_endpoint("ws://access.example", "tunnel_123").is_err());
    }

    #[test]
    fn listener_probe_requires_a_bounded_dropbear_ssh_banner() {
        let mut valid = std::io::Cursor::new(b"SSH-2.0-dropbear_2026.94\r\n".to_vec());
        assert!(valid_dropbear_banner(&read_ssh_banner(&mut valid).unwrap()));

        let mut substituted = std::io::Cursor::new(b"SSH-2.0-substituted\r\n".to_vec());
        assert!(!valid_dropbear_banner(
            &read_ssh_banner(&mut substituted).unwrap()
        ));

        let mut oversized = std::io::Cursor::new(vec![b'x'; 256]);
        assert_eq!(
            read_ssh_banner(&mut oversized).unwrap_err().code,
            "access_sidecar_failed"
        );
    }

    #[test]
    fn reconnect_backoff_is_capped_far_below_connection_rate_limit() {
        for attempt in 0..100 {
            let delay = reconnect_delay(attempt);
            assert!(delay >= Duration::from_millis(250));
            assert!(delay <= Duration::from_millis(8_250));
        }
    }

    #[test]
    fn fixed_toolchain_digest_verification_rejects_tampering() {
        let root = private_root("toolchain-test").unwrap();
        let binary = root.join("liskov-dropbear");
        std::fs::write(&binary, b"static-toolchain-fixture").unwrap();
        let digest = hex::encode(Sha256::digest(b"static-toolchain-fixture"));
        verify_toolchain_binary(&binary, &digest).unwrap();

        std::fs::write(&binary, b"tampered-toolchain-fixture").unwrap();
        assert_eq!(
            verify_toolchain_binary(&binary, &digest).unwrap_err().code,
            "access_toolchain_digest_mismatch"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn v2_credential_rejects_a_substituted_application_identity() {
        let now_ms = unix_time_ms().unwrap();
        let expires_at_ms = now_ms + 60_000;
        let bootstrap = RuntimeBootstrapResponse {
            ok: true,
            domain: "proof.liskov.runtime-bootstrap-response.v2".into(),
            application_uid: "app-uid".into(),
            application_id: "app-id".into(),
            policy_digest: "sha256:policy".into(),
            deployment_id: "provider-deployment".into(),
            job_id: "provider-job".into(),
            processor_id: "processor".into(),
            runtime_instance_id: "instance".into(),
            slipway_url: "https://liskov.example".into(),
            secrets: None,
            runtime_env: None,
            supervision: None,
            logging: None,
            logging_outage_canary: false,
            diagnostics: None,
            access: None,
            processor_facts: None,
            fact_authorization: None,
        };
        let access = ManagedRuntimeAccessBootstrap {
            provider: RuntimeAccessProvider {
                kind: RuntimeAccessProviderKind::Liskov,
            },
            attachment_id: "att-1".into(),
            fence: 1,
            gateway_url: "wss://gateway.example".into(),
            tunnel_id: "tun_1".into(),
            protocol: ManagedRuntimeAccessProtocol::LiskovAccessV1,
            setup_deadline_ms: now_ms + 30_000,
            binding: Some(ManagedRuntimeAccessBinding {
                organization_id: "org-1".into(),
                application_id: "app-id".into(),
                application_uid: "app-uid".into(),
                liskov_deployment_id: "canonical-deployment".into(),
                deployment_id: "provider-deployment".into(),
                liskov_job_id: "canonical-job".into(),
                job_id: "provider-job".into(),
                policy_digest: "sha256:policy".into(),
            }),
            authorized_keys: vec![PUBLIC_KEY.into()],
            authorized_key_fingerprints: vec!["SHA256:key".into()],
            toolchain: Some(ManagedRuntimeAccessToolchain {
                runtime_contact_sha256: "1".repeat(64),
                dropbear_sha256: "2".repeat(64),
                dropbearkey_sha256: "3".repeat(64),
            }),
            credential: None,
            credential_consumed: false,
        };
        let credential =
            ManagedRuntimeSshCredential::V1Full(Box::new(ManagedRuntimeSshCredentialV2 {
                schema: MANAGED_CREDENTIAL_SCHEMA_V2.into(),
                provider: ManagedRuntimeSshCredentialProviderV2::Liskov {
                    connector_token: "a.b.c".into(),
                    authorized_keys: vec![PUBLIC_KEY.into()],
                    toolchain: ManagedCredentialToolchain {
                        runtime_contact_sha256: "1".repeat(64),
                        dropbear_sha256: "2".repeat(64),
                        dropbearkey_sha256: "3".repeat(64),
                    },
                },
                organization_id: "org-1".into(),
                attachment_id: "att-1".into(),
                application_id: "substituted-app".into(),
                application_uid: "app-uid".into(),
                liskov_deployment_id: "canonical-deployment".into(),
                deployment_id: "provider-deployment".into(),
                liskov_job_id: "canonical-job".into(),
                job_id: "provider-job".into(),
                policy_digest: "sha256:policy".into(),
                fence: 1,
                expires_at_ms,
            }));
        assert_eq!(
            validate_binding(&bootstrap, &access, credential, now_ms)
                .err()
                .unwrap()
                .code,
            "access_setup_failed"
        );
    }

    #[test]
    fn compact_v2_credential_rejects_a_substituted_signed_bootstrap_binding() {
        let now_ms = unix_time_ms().unwrap();
        let expires_at_ms = now_ms + 60_000;
        let bootstrap = RuntimeBootstrapResponse {
            ok: true,
            domain: "proof.liskov.runtime-bootstrap-response.v2".into(),
            application_uid: "app-uid".into(),
            application_id: "substituted-app".into(),
            policy_digest: "sha256:policy".into(),
            deployment_id: "provider-deployment".into(),
            job_id: "provider-job".into(),
            processor_id: "processor".into(),
            runtime_instance_id: "instance".into(),
            slipway_url: "https://liskov.example".into(),
            secrets: None,
            runtime_env: None,
            supervision: None,
            logging: None,
            logging_outage_canary: false,
            diagnostics: None,
            access: None,
            processor_facts: None,
            fact_authorization: None,
        };
        let access = ManagedRuntimeAccessBootstrap {
            provider: RuntimeAccessProvider {
                kind: RuntimeAccessProviderKind::Liskov,
            },
            attachment_id: "att-1".into(),
            fence: 1,
            gateway_url: "wss://gateway.example".into(),
            tunnel_id: "tun_1".into(),
            protocol: ManagedRuntimeAccessProtocol::LiskovAccessV1,
            setup_deadline_ms: now_ms + 30_000,
            binding: Some(ManagedRuntimeAccessBinding {
                organization_id: "org-1".into(),
                application_id: "app-id".into(),
                application_uid: "app-uid".into(),
                liskov_deployment_id: "canonical-deployment".into(),
                deployment_id: "provider-deployment".into(),
                liskov_job_id: "canonical-job".into(),
                job_id: "provider-job".into(),
                policy_digest: "sha256:policy".into(),
            }),
            authorized_keys: vec![PUBLIC_KEY.into()],
            authorized_key_fingerprints: vec!["SHA256:key".into()],
            toolchain: Some(ManagedRuntimeAccessToolchain {
                runtime_contact_sha256: "1".repeat(64),
                dropbear_sha256: "2".repeat(64),
                dropbearkey_sha256: "3".repeat(64),
            }),
            credential: None,
            credential_consumed: false,
        };
        let credential =
            ManagedRuntimeSshCredential::V1Compact(CompactManagedRuntimeSshCredentialV2 {
                schema: MANAGED_CREDENTIAL_SCHEMA_V2.into(),
                provider: CompactManagedRuntimeSshCredentialProviderV2::Liskov {
                    connector_token: "a.b.c".into(),
                },
                attachment_id: "att-1".into(),
                fence: 1,
                expires_at_ms,
            });
        assert_eq!(
            validate_binding(&bootstrap, &access, credential, now_ms)
                .err()
                .unwrap()
                .code,
            "access_setup_failed"
        );
    }

    fn compact_binding_fixture(
        now_ms: u64,
        application_id: &str,
        fence: u64,
        expires_at_ms: u64,
        connector_token: &str,
    ) -> (
        RuntimeBootstrapResponse,
        ManagedRuntimeAccessBootstrap,
        CompactManagedRuntimeSshCredentialV2,
    ) {
        let fingerprint = ssh_public_key_fingerprint(PUBLIC_KEY).unwrap();
        let bootstrap = RuntimeBootstrapResponse {
            ok: true,
            domain: "proof.liskov.runtime-bootstrap-response.v2".into(),
            application_uid: "app-uid".into(),
            application_id: application_id.into(),
            policy_digest: "sha256:policy".into(),
            deployment_id: "provider-deployment".into(),
            job_id: "provider-job".into(),
            processor_id: "processor".into(),
            runtime_instance_id: "instance".into(),
            slipway_url: "https://liskov.example".into(),
            secrets: None,
            runtime_env: None,
            supervision: None,
            logging: None,
            logging_outage_canary: false,
            diagnostics: None,
            access: None,
            processor_facts: None,
            fact_authorization: None,
        };
        let access = ManagedRuntimeAccessBootstrap {
            provider: RuntimeAccessProvider {
                kind: RuntimeAccessProviderKind::Liskov,
            },
            attachment_id: "att-1".into(),
            fence: 1,
            gateway_url: "wss://gateway.example".into(),
            tunnel_id: "tun_1".into(),
            protocol: ManagedRuntimeAccessProtocol::LiskovAccessV1,
            setup_deadline_ms: now_ms + 30_000,
            binding: Some(ManagedRuntimeAccessBinding {
                organization_id: "org-1".into(),
                application_id: "app-id".into(),
                application_uid: "app-uid".into(),
                liskov_deployment_id: "canonical-deployment".into(),
                deployment_id: "provider-deployment".into(),
                liskov_job_id: "canonical-job".into(),
                job_id: "provider-job".into(),
                policy_digest: "sha256:policy".into(),
            }),
            authorized_keys: vec![PUBLIC_KEY.into()],
            authorized_key_fingerprints: vec![fingerprint],
            toolchain: Some(ManagedRuntimeAccessToolchain {
                runtime_contact_sha256: "1".repeat(64),
                dropbear_sha256: "2".repeat(64),
                dropbearkey_sha256: "3".repeat(64),
            }),
            credential: None,
            credential_consumed: false,
        };
        let credential = CompactManagedRuntimeSshCredentialV2 {
            schema: MANAGED_CREDENTIAL_SCHEMA_V2.into(),
            provider: CompactManagedRuntimeSshCredentialProviderV2::Liskov {
                connector_token: connector_token.into(),
            },
            attachment_id: "att-1".into(),
            fence,
            expires_at_ms,
        };
        (bootstrap, access, credential)
    }

    #[test]
    fn compact_v2_credential_accepts_the_exact_signed_bootstrap_binding() {
        let now_ms = unix_time_ms().unwrap();
        let expires_at_ms = now_ms + 60_000;
        let token = "header.payload.signature";
        let (bootstrap, access, credential) =
            compact_binding_fixture(now_ms, "app-id", 1, expires_at_ms, token);
        let validated = validate_binding(
            &bootstrap,
            &access,
            ManagedRuntimeSshCredential::V1Compact(credential),
            now_ms,
        )
        .expect("matching compact credential must verify offline");
        assert_eq!(validated.connector_token.as_str(), token);
        assert_eq!(validated.authorized_keys.as_slice(), [PUBLIC_KEY]);
        assert_eq!(validated.expires_at_ms, expires_at_ms);

        let (bootstrap, access, credential) =
            compact_binding_fixture(now_ms, "substituted-app", 1, expires_at_ms, token);
        assert_eq!(
            validate_binding(
                &bootstrap,
                &access,
                ManagedRuntimeSshCredential::V1Compact(credential),
                now_ms,
            )
            .err()
            .unwrap()
            .code,
            "access_setup_failed"
        );

        let (bootstrap, access, credential) =
            compact_binding_fixture(now_ms, "app-id", 2, expires_at_ms, token);
        assert_eq!(
            validate_binding(
                &bootstrap,
                &access,
                ManagedRuntimeSshCredential::V1Compact(credential),
                now_ms,
            )
            .err()
            .unwrap()
            .code,
            "access_setup_failed"
        );

        let (bootstrap, access, credential) =
            compact_binding_fixture(now_ms, "app-id", 1, now_ms, token);
        assert_eq!(
            validate_binding(
                &bootstrap,
                &access,
                ManagedRuntimeSshCredential::V1Compact(credential),
                now_ms,
            )
            .err()
            .unwrap()
            .code,
            "access_setup_failed"
        );

        let (bootstrap, access, credential) =
            compact_binding_fixture(now_ms, "app-id", 1, expires_at_ms, "header.payload");
        assert_eq!(
            validate_binding(
                &bootstrap,
                &access,
                ManagedRuntimeSshCredential::V1Compact(credential),
                now_ms,
            )
            .err()
            .unwrap()
            .code,
            "access_setup_failed"
        );
    }

    #[test]
    fn dropbear_listens_only_on_loopback_port_2222() {
        let host_key = Path::new("/tmp/dropbear-ed25519-host-key");
        let authorization_dir = Path::new("/tmp/authorization");
        let pid_file = Path::new("/tmp/dropbear.pid");
        let arguments = dropbear_arguments(host_key, authorization_dir, pid_file);
        let rendered: Vec<String> = arguments
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        let listen = rendered
            .windows(2)
            .find(|pair| pair[0] == "-p")
            .map(|pair| pair[1].as_str());
        assert_eq!(listen, Some(FIXED_SSH_TARGET));
        assert_eq!(listen, Some("127.0.0.1:2222"));
        for flag in ["-F", "-E", "-s", "-g", "-j", "-k", "-r", "-D", "-P"] {
            assert!(
                rendered.iter().any(|value| value == flag),
                "missing dropbear flag {flag}"
            );
        }
        assert!(!rendered.iter().any(|value| value.contains("0.0.0.0")));
        assert!(
            !rendered
                .iter()
                .any(|value| value == ":22" || value.ends_with(":22")),
            "listen spec must not be :22"
        );
    }

    #[test]
    fn connector_connect_classification_preserves_http_status_and_timeout() {
        let response = tokio_tungstenite::tungstenite::http::Response::builder()
            .status(503)
            .body(None::<Vec<u8>>)
            .unwrap();
        let refused = classify_connector_connect::<()>(ConnectorConnectResult::Completed(Err(
            WebSocketError::Http(Box::new(response)),
        )))
        .unwrap_err();
        assert_eq!(refused.code(), Some("access_connector_http_refused"));
        assert_eq!(refused.http_status(), Some(503));

        let timeout =
            classify_connector_connect::<()>(ConnectorConnectResult::TimedOut).unwrap_err();
        assert_eq!(timeout.code(), Some("access_connector_connect_timeout"));
        assert_eq!(timeout.http_status(), None);
    }

    #[test]
    fn registration_deadline_reports_the_latest_typed_connector_failure() {
        let (sender, receiver) = mpsc::channel();
        sender
            .send(ConnectorRegistrationEvent::Failed(
                ConnectorAttemptError::HttpRefused(401),
            ))
            .unwrap();
        drop(sender);
        assert_eq!(
            wait_for_connector_registration(&receiver, Instant::now() + Duration::from_secs(1))
                .unwrap_err()
                .code,
            "access_connector_http_refused"
        );

        let (sender, receiver) = mpsc::channel();
        sender
            .send(ConnectorRegistrationEvent::Failed(
                ConnectorAttemptError::TransportFailed,
            ))
            .unwrap();
        sender.send(ConnectorRegistrationEvent::Registered).unwrap();
        assert!(
            wait_for_connector_registration(&receiver, Instant::now() + Duration::from_secs(1))
                .is_ok(),
            "a typed failed attempt must not hide a later successful retry"
        );
    }

    /// Drives `connector_driver` through `script` and returns the delay it
    /// waited after each attempt. The last wait sets the cancel flag.
    fn connector_delays(script: &[Result<(), ConnectorAttemptError>]) -> Vec<Duration> {
        let cancel = AtomicBool::new(false);
        let remaining = std::cell::RefCell::new(
            script
                .iter()
                .copied()
                .collect::<std::collections::VecDeque<_>>(),
        );
        let delays = std::cell::RefCell::new(Vec::new());
        connector_driver(
            || Some(1_000),
            |_| {
                remaining
                    .borrow_mut()
                    .pop_front()
                    .expect("the driver attempts no more than the script")
            },
            |delay| {
                delays.borrow_mut().push(delay);
                if remaining.borrow().is_empty() {
                    cancel.store(true, Ordering::Release);
                }
                cancel.load(Ordering::Acquire)
            },
            |_, _, _, _| {},
            &cancel,
            5_000,
            None,
        );
        assert!(remaining.borrow().is_empty(), "the driver stopped early");
        let delays = delays.into_inner();
        assert_eq!(delays.len(), script.len());
        delays
    }

    #[test]
    fn connector_backs_off_to_the_ceiling_when_refused_after_admission() {
        let mut script = vec![Ok(())];
        script.extend([Err(ConnectorAttemptError::HttpRefused(401)); 10]);
        let delays = connector_delays(&script);
        let after_refusals = &delays[1..];
        // Whole seconds strip the sub-second jitter, which alone could make a
        // ceiling-length wait shorter than the one before it.
        let seconds = after_refusals
            .iter()
            .map(|delay| delay.as_millis() / 1_000)
            .collect::<Vec<_>>();
        assert_eq!(seconds, [8, 16, 32, 64, 128, 256, 300, 300, 300, 300]);
        assert!(seconds.windows(2).all(|pair| pair[0] <= pair[1]));
        for delay in &after_refusals[6..] {
            assert!(delay.as_millis() >= 300_000, "{delay:?}");
            assert!(delay.as_millis() <= 300_250, "{delay:?}");
        }
    }

    #[test]
    fn connector_keeps_the_setup_schedule_when_refused_before_any_admission() {
        let delays = connector_delays(&[Err(ConnectorAttemptError::HttpRefused(401)); 10]);
        for delay in delays {
            assert!(delay.as_millis() <= 8_250, "{delay:?}");
        }
    }

    #[test]
    fn connector_keeps_the_short_schedule_when_unavailable_after_admission() {
        let mut script = vec![Ok(())];
        script.extend([Err(ConnectorAttemptError::HttpRefused(503)); 10]);
        for delay in connector_delays(&script) {
            assert!(delay.as_millis() <= 8_250, "{delay:?}");
        }
    }

    #[test]
    fn connector_refusal_streak_resets_on_a_later_admission() {
        let mut script = vec![Ok(())];
        script.extend([Err(ConnectorAttemptError::HttpRefused(401)); 4]);
        script.push(Err(ConnectorAttemptError::RelayFailed));
        script.push(Err(ConnectorAttemptError::HttpRefused(401)));
        let delays = connector_delays(&script);
        assert!(delays[4].as_millis() >= 64_000, "{:?}", delays[4]);
        let last = *delays.last().unwrap();
        assert!(last.as_millis() <= 8_250, "{last:?}");
    }

    #[test]
    fn connector_driver_reconnects_until_expiry_and_stops_on_cancel() {
        let cancel = Arc::new(AtomicBool::new(false));
        let attempts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let reports = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = attempts.clone();
        let recorded_reports = reports.clone();
        let worker_cancel = cancel.clone();
        let handle = thread::spawn(move || {
            connector_driver(
                || Some(1_000),
                |_registered| {
                    let mut attempts = recorded.lock().unwrap();
                    attempts.push((
                        "wss://access.example/v1/connectors/tun_1",
                        true,
                        CONNECTOR_SUBPROTOCOL_V1,
                    ));
                    if attempts.len() >= 3 {
                        worker_cancel.store(true, Ordering::Release);
                    }
                    Err(ConnectorAttemptError::TransportFailed)
                },
                |_| worker_cancel.load(Ordering::Acquire),
                |elapsed_ms, outcome, code, http_status| {
                    recorded_reports
                        .lock()
                        .unwrap()
                        .push((elapsed_ms, outcome, code, http_status));
                },
                &worker_cancel,
                5_000,
                None,
            );
        });
        handle.join().unwrap();
        let recorded = attempts.lock().unwrap();
        assert_eq!(recorded.len(), 3);
        assert!(
            recorded
                .iter()
                .all(|(endpoint, token_present, subprotocol)| {
                    *endpoint == "wss://access.example/v1/connectors/tun_1"
                        && *token_present
                        && *subprotocol == CONNECTOR_SUBPROTOCOL_V1
                })
        );
        let reports = reports.lock().unwrap();
        assert_eq!(reports.len(), 3);
        assert_eq!(reports[0].1, "retry");
        assert_eq!(reports[0].2, Some("access_connector_transport_failed"));
        assert_eq!(reports[0].3, None);
        assert_eq!(reports[2].1, "failed");

        let connects = std::sync::atomic::AtomicU32::new(0);
        let cancel = AtomicBool::new(false);
        connector_driver(
            || Some(10_000),
            |_| {
                connects.fetch_add(1, Ordering::SeqCst);
                Err(ConnectorAttemptError::TransportFailed)
            },
            |_| false,
            |_, _, _, _| {},
            &cancel,
            5_000,
            None,
        );
        assert_eq!(connects.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn managed_session_stop_joins_the_connector_and_removes_the_exact_root() {
        let _lock = crate::supervisor::tests::PROCESS_TEST_LOCK.lock().unwrap();
        let mut session = ManagedAccessSession::for_test("/bin/sleep", &["30"]).unwrap();
        let root = session.root.clone();
        assert!(root.is_dir());
        session.stop().unwrap();
        assert!(session.dropbear.try_wait().ok().flatten().is_some());
        assert!(session.connector.is_finished());
        assert!(!root.exists());
        session.stop().unwrap();
    }

    /// Poll until the sidecar's death is observed.
    fn await_sidecar_event(session: &mut ManagedAccessSession) -> SidecarEvent {
        for _ in 0..400 {
            match session.sidecar_event_at(Instant::now()) {
                SidecarEvent::Unchanged => thread::sleep(Duration::from_millis(5)),
                event => return event,
            }
        }
        panic!("the sidecar never exited");
    }

    fn counted_respawn(
        program: &'static str,
        args: &'static [&'static str],
    ) -> (
        Arc<std::sync::atomic::AtomicU32>,
        impl FnMut() -> Result<Child, AccessError> + Send + 'static,
    ) {
        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter = calls.clone();
        (calls, move || {
            counter.fetch_add(1, Ordering::SeqCst);
            spawn_test_sidecar(program, args)
        })
    }

    #[test]
    fn a_dead_sidecar_is_respawned_with_the_same_host_key_and_binding() {
        let _lock = crate::supervisor::tests::PROCESS_TEST_LOCK.lock().unwrap();
        let (calls, respawn) = counted_respawn("/bin/sleep", &["30"]);
        let mut session = ManagedAccessSession::for_test("/bin/true", &[])
            .unwrap()
            .with_respawn(respawn, reconnect_delay);
        let host_key_path = session.root.join("dropbear-ed25519-host-key");
        write_private(&host_key_path, b"host-key-bytes").unwrap();
        session.host_public_key = "ssh-ed25519 AAAAtest".into();
        session.host_fingerprint = "SHA256:test".into();
        let ready_before = session.ready_attrs();

        assert_eq!(await_sidecar_event(&mut session), SidecarEvent::Crashed);
        let died_at = Instant::now();
        // Backoff is a schedule, not a sleep: nothing happens before it is due.
        assert_eq!(session.sidecar_event_at(died_at), SidecarEvent::Unchanged);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            session.sidecar_event_at(died_at + Duration::from_secs(600)),
            SidecarEvent::Recovered { .. }
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(session.dropbear.try_wait().unwrap().is_none());
        assert_eq!(
            session.sidecar_event_at(died_at + Duration::from_secs(600)),
            SidecarEvent::Unchanged
        );
        assert_eq!(std::fs::read(&host_key_path).unwrap(), b"host-key-bytes");
        assert_eq!(session.ready_attrs(), ready_before);
        assert_eq!(session.ready_attrs()["fence"], 1);
        assert_eq!(session.ready_attrs()["attachmentId"], "att-test");
        session.stop().unwrap();
    }

    #[test]
    fn a_sidecar_that_always_dies_is_tried_three_times_then_exhausted() {
        let _lock = crate::supervisor::tests::PROCESS_TEST_LOCK.lock().unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter = calls.clone();
        let mut session = ManagedAccessSession::for_test("/bin/true", &[])
            .unwrap()
            .with_respawn(
                move || {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Err(AccessError::new("access_sidecar_failed"))
                },
                reconnect_delay,
            );
        assert_eq!(await_sidecar_event(&mut session), SidecarEvent::Crashed);
        let later = Instant::now() + Duration::from_secs(600);
        assert!(matches!(
            session.sidecar_event_at(later),
            SidecarEvent::RespawnFailed {
                code: "access_sidecar_failed",
                ..
            }
        ));
        assert!(matches!(
            session.sidecar_event_at(later + Duration::from_secs(600)),
            SidecarEvent::RespawnFailed { .. }
        ));
        assert!(matches!(
            session.sidecar_event_at(later + Duration::from_secs(1200)),
            SidecarEvent::Exhausted {
                code: "access_sidecar_failed",
                ..
            }
        ));
        for step in 2..6 {
            assert_eq!(
                session.sidecar_event_at(later + Duration::from_secs(600 * step)),
                SidecarEvent::Unchanged
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), MAX_SIDECAR_RESPAWNS);
        session.stop().unwrap();
    }

    #[test]
    fn the_budget_spans_the_session_so_a_fourth_death_stays_degraded() {
        let _lock = crate::supervisor::tests::PROCESS_TEST_LOCK.lock().unwrap();
        let (calls, respawn) = counted_respawn("/bin/true", &[]);
        let mut session = ManagedAccessSession::for_test("/bin/true", &[])
            .unwrap()
            .with_respawn(respawn, reconnect_delay);
        for _ in 0..MAX_SIDECAR_RESPAWNS {
            assert_eq!(await_sidecar_event(&mut session), SidecarEvent::Crashed);
            assert!(matches!(
                session.sidecar_event_at(Instant::now() + Duration::from_secs(600)),
                SidecarEvent::Recovered { .. }
            ));
        }
        assert_eq!(await_sidecar_event(&mut session), SidecarEvent::Crashed);
        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            session.sidecar_event_at(Instant::now() + Duration::from_secs(3600)),
            SidecarEvent::Unchanged
        );
        assert_eq!(calls.load(Ordering::SeqCst), MAX_SIDECAR_RESPAWNS);
        session.stop().unwrap();
    }

    #[test]
    fn stop_after_a_death_respawns_nothing() {
        let _lock = crate::supervisor::tests::PROCESS_TEST_LOCK.lock().unwrap();
        let (calls, respawn) = counted_respawn("/bin/sleep", &["30"]);
        let mut session = ManagedAccessSession::for_test("/bin/true", &[])
            .unwrap()
            .with_respawn(respawn, |_| Duration::ZERO);
        assert_eq!(await_sidecar_event(&mut session), SidecarEvent::Crashed);
        session.stop().unwrap();
        assert_eq!(
            session.sidecar_event_at(Instant::now() + Duration::from_secs(600)),
            SidecarEvent::Unchanged
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_finished_connector_is_terminal_and_never_respawned() {
        let _lock = crate::supervisor::tests::PROCESS_TEST_LOCK.lock().unwrap();
        let (calls, respawn) = counted_respawn("/bin/sleep", &["30"]);
        let mut session = ManagedAccessSession::for_test("/bin/sleep", &["30"])
            .unwrap()
            .with_respawn(respawn, |_| Duration::ZERO);
        session.connector.cancel.store(true, Ordering::Release);
        assert_eq!(await_sidecar_event(&mut session), SidecarEvent::Crashed);
        terminate_child(&mut session.dropbear).unwrap();
        for _ in 0..5 {
            assert_eq!(
                session.sidecar_event_at(Instant::now() + Duration::from_secs(600)),
                SidecarEvent::Unchanged
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        session.stop().unwrap();
    }

    #[test]
    fn a_connector_that_finishes_while_the_sidecar_is_down_ends_the_respawns() {
        let _lock = crate::supervisor::tests::PROCESS_TEST_LOCK.lock().unwrap();
        let (calls, respawn) = counted_respawn("/bin/sleep", &["30"]);
        let mut session = ManagedAccessSession::for_test("/bin/true", &[])
            .unwrap()
            .with_respawn(respawn, reconnect_delay);
        assert_eq!(await_sidecar_event(&mut session), SidecarEvent::Crashed);
        session.connector.stop().unwrap();
        assert_eq!(
            session.sidecar_event_at(Instant::now() + Duration::from_secs(600)),
            SidecarEvent::Unchanged
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        session.stop().unwrap();
    }

    #[test]
    fn the_production_respawn_re_verifies_the_toolchain_before_spawning() {
        let root = private_root("u6xv-respawner-test").unwrap();
        let mut respawn = dropbear_respawner(
            ManagedRuntimeAccessToolchain {
                runtime_contact_sha256: "0".repeat(64),
                dropbear_sha256: "0".repeat(64),
                dropbearkey_sha256: "0".repeat(64),
            },
            root.join("dropbear-ed25519-host-key"),
            root.join("authorization"),
            root.join("dropbear.pid"),
        );
        assert_eq!(respawn().unwrap_err().code, "access_sidecar_spawn_failed");
        assert!(!root.join("dropbear.pid").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
