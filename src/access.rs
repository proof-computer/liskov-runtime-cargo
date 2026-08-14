//! Closed Runtime SSH provider adapter used after signed first contact.

mod managed;

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use flate2::read::GzDecoder;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tar::Archive;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::logging::RuntimeSshLogEmitter;
use crate::protocol::{
    RuntimeAccessBootstrap, RuntimeAccessLaunchProfile, RuntimeAccessProviderKind,
    RuntimeBootstrapResponse, TailscaleRuntimeAccessBootstrap,
};

pub const RUNTIME_SSH_CREDENTIAL_ENV: &str = "LISKOV_RUNTIME_SSH_CREDENTIAL_V1";
const CREDENTIAL_SCHEMA: &str = "proof.liskov.runtime-ssh-credential.v1";
const MANAGED_CREDENTIAL_SCHEMA_V2: &str = "proof.liskov.runtime-ssh-credential.v2";
const MAX_ARTIFACT_BYTES: usize = 128 * 1024 * 1024;
const MAX_BINARY_BYTES: u64 = 96 * 1024 * 1024;
const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_STARTUP_STDERR_BYTES: usize = 16 * 1024;
/// Budget for short, chatty client commands such as `tailscale status --json`
/// (52 ms when measured in-processor).
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
/// Budget for fetching the provider archive. Processors sit on wildly different
/// links: the artifact took 1320 ms (~21 MB/s) on one measured device, but a
/// processor on a slow connection needs far longer for the same 26.5 MB, and a
/// timeout here is indistinguishable from a broken mirror. 44 KB/s still fits.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);
/// Budget for `tailscale up`. Bringing the tunnel up spans a control-plane
/// handshake, netmap delivery and DERP negotiation, so a high-latency link can
/// take far longer than the 2001 ms measured on a fast one.
const TUNNEL_UP_TIMEOUT: Duration = Duration::from_secs(240);
/// Short budget for the post-failure `status --json` snapshot. This runs while
/// already failing, so it must not extend the failure path meaningfully.
const STATUS_EVIDENCE_TIMEOUT: Duration = Duration::from_secs(10);
/// `tailscale up` is told to give up this much earlier than the harness would
/// kill it, so a link too slow to finish yields the client's own diagnostic on
/// stderr instead of an opaque kill with no exit status.
const TUNNEL_UP_CLIENT_MARGIN: Duration = Duration::from_secs(30);
/// Budget for the daemon to create its LocalAPI socket (294 ms when measured,
/// but a loaded device starting a 26 MB static binary can take longer).
const DAEMON_SOCKET_TIMEOUT: Duration = Duration::from_secs(90);
/// Wall-clock ceiling on the whole of access setup, enforced from outside the
/// setup thread by [`setup_runtime_access_within`].
///
/// Deliberately the sum of every internal leg budget plus a margin, so it can
/// never pre-empt a setup that is slow but progressing. It exists to bound the
/// case where an internal budget cannot be evaluated at all, not to be tight.
/// Tightening it is a follow-up once real leg distributions are known — the
/// measured healthy path is ~2 s.
const ACCESS_SETUP_WATCHDOG: Duration = Duration::from_secs(
    DOWNLOAD_TIMEOUT.as_secs() + DAEMON_SOCKET_TIMEOUT.as_secs() + TUNNEL_UP_TIMEOUT.as_secs() + 60,
);
/// Cadence for "still waiting for the daemon socket" reports. Chosen so a
/// healthy wait produces at most a handful of beats inside
/// [`DAEMON_SOCKET_TIMEOUT`], while a loop that outlives its bound is
/// unmistakable rather than silent.
const SOCKET_WAIT_HEARTBEAT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// How long to let output readers drain after the child is gone. Bounded because
/// a killed child's pipe can be held open by a surviving grandchild, in which
/// case EOF never arrives and an unbounded wait never returns.
const READER_DRAIN_GRACE: Duration = Duration::from_secs(5);
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("{code}")]
pub struct AccessError {
    pub code: &'static str,
}

impl AccessError {
    fn new(code: &'static str) -> Self {
        Self { code }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TailscaleRuntimeSshCredentialV1 {
    schema: String,
    provider: TailscaleRuntimeSshCredentialProvider,
    organization_id: String,
    integration_id: String,
    attachment_id: String,
    application_uid: String,
    deployment_id: String,
    job_id: String,
    policy_digest: String,
    expires_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum TailscaleRuntimeSshCredentialProvider {
    Tailscale {
        #[serde(rename = "authKey")]
        auth_key: String,
    },
}

impl Drop for TailscaleRuntimeSshCredentialProvider {
    fn drop(&mut self) {
        match self {
            Self::Tailscale { auth_key } => auth_key.zeroize(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ManagedRuntimeSshCredentialV2 {
    schema: String,
    provider: ManagedRuntimeSshCredentialProviderV2,
    organization_id: String,
    attachment_id: String,
    application_id: String,
    application_uid: String,
    liskov_deployment_id: String,
    deployment_id: String,
    liskov_job_id: String,
    job_id: String,
    policy_digest: String,
    fence: u64,
    expires_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CompactManagedRuntimeSshCredentialV2 {
    schema: String,
    provider: CompactManagedRuntimeSshCredentialProviderV2,
    attachment_id: String,
    fence: u64,
    expires_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ManagedRuntimeSshCredentialProviderV2 {
    Liskov {
        #[serde(rename = "connectorToken", alias = "connector_token")]
        connector_token: String,
        #[serde(rename = "authorizedKeys", alias = "authorized_keys")]
        authorized_keys: Vec<String>,
        toolchain: ManagedCredentialToolchain,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum CompactManagedRuntimeSshCredentialProviderV2 {
    Liskov {
        #[serde(rename = "connectorToken", alias = "connector_token")]
        connector_token: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ManagedCredentialToolchain {
    runtime_contact_sha256: String,
    dropbear_sha256: String,
    dropbearkey_sha256: String,
}

impl Drop for ManagedRuntimeSshCredentialProviderV2 {
    fn drop(&mut self) {
        match self {
            Self::Liskov {
                connector_token,
                authorized_keys,
                ..
            } => {
                connector_token.zeroize();
                authorized_keys.zeroize();
            }
        }
    }
}

impl Drop for CompactManagedRuntimeSshCredentialProviderV2 {
    fn drop(&mut self) {
        match self {
            Self::Liskov { connector_token } => {
                connector_token.zeroize();
            }
        }
    }
}

pub(super) enum ManagedRuntimeSshCredential {
    V1Full(Box<ManagedRuntimeSshCredentialV2>),
    V1Compact(CompactManagedRuntimeSshCredentialV2),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RuntimeSshCredentialV1 {
    Tailscale(TailscaleRuntimeSshCredentialV1),
    ManagedV1Compact(CompactManagedRuntimeSshCredentialV2),
    ManagedV1Full(Box<ManagedRuntimeSshCredentialV2>),
}

pub enum AccessSession {
    Tailscale(TailscaleAccessSession),
    Managed(managed::ManagedAccessSession),
}

pub struct TailscaleAccessSession {
    daemon: DaemonProcess,
    root: PathBuf,
    pub attachment_id: String,
    pub fence: u64,
    pub device_id: String,
    pub hostname: String,
    pub client_version: String,
    pub client_digest: String,
    degraded_reported: bool,
}

impl AccessSession {
    pub fn binding_attrs(&self) -> serde_json::Value {
        match self {
            Self::Tailscale(session) => session.binding_attrs(),
            Self::Managed(session) => session.binding_attrs(),
        }
    }

    pub fn ready_attrs(&self) -> serde_json::Value {
        match self {
            Self::Tailscale(session) => session.ready_attrs(),
            Self::Managed(session) => session.ready_attrs(),
        }
    }

    pub fn newly_crashed(&mut self) -> bool {
        match self {
            Self::Tailscale(session) => session.newly_crashed(),
            Self::Managed(session) => session.newly_crashed(),
        }
    }

    pub fn stop(&mut self) -> Result<(), AccessError> {
        match self {
            Self::Tailscale(session) => session.stop(),
            Self::Managed(session) => session.stop(),
        }
    }
}

impl Drop for AccessSession {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

impl TailscaleAccessSession {
    fn binding_attrs(&self) -> serde_json::Value {
        serde_json::json!({
            "attachmentId": self.attachment_id,
            "fence": self.fence,
            "providerKind": "tailscale",
        })
    }

    fn ready_attrs(&self) -> serde_json::Value {
        serde_json::json!({
            "attachmentId": self.attachment_id,
            "fence": self.fence,
            "providerKind": "tailscale",
            "deviceId": self.device_id,
            "hostname": self.hostname,
            "clientVersion": self.client_version,
            "clientDigest": self.client_digest,
        })
    }

    fn newly_crashed(&mut self) -> bool {
        if self.degraded_reported {
            return false;
        }
        let crashed = self.daemon.child.try_wait().ok().flatten().is_some();
        if crashed {
            self.degraded_reported = true;
        }
        crashed
    }

    fn stop(&mut self) -> Result<(), AccessError> {
        self.daemon.stop()?;
        std::fs::remove_dir_all(&self.root)
            .map_err(|_| AccessError::new("access_cleanup_failed"))?;
        Ok(())
    }
}

struct DaemonProcess {
    child: Child,
    startup_stderr: Arc<StartupStderr>,
    stderr_thread: Option<thread::JoinHandle<()>>,
}

impl DaemonProcess {
    /// Emit whatever the daemon has written to stderr so far, without
    /// disturbing the capture. Used on the tunnel-failure path, where the
    /// daemon is still running and its own account of events is the evidence.
    fn emit_startup_stderr(&self, logger: &RuntimeSshLogEmitter, exact_auth_key: &str) {
        if let Ok(bytes) = self.startup_stderr.bytes.lock() {
            emit_command_stderr(logger, exact_auth_key, &bytes, false);
        }
    }

    fn disable_startup_capture(&self) {
        self.startup_stderr.enabled.store(false, Ordering::Release);
        if let Ok(mut bytes) = self.startup_stderr.bytes.lock() {
            bytes.zeroize();
        }
    }

    fn startup_exit_error(&mut self, status: std::process::ExitStatus) -> AccessError {
        if let Some(handle) = self.stderr_thread.take() {
            let _ = handle.join();
        }
        let error = self
            .startup_stderr
            .bytes
            .lock()
            .map(|bytes| sidecar_exit_error(status, &bytes))
            .unwrap_or_else(|_| sidecar_exit_error(status, &[]));
        self.disable_startup_capture();
        error
    }

    fn stop(&mut self) -> Result<(), AccessError> {
        self.disable_startup_capture();
        let result = terminate_child(&mut self.child);
        if let Some(handle) = self.stderr_thread.take() {
            let _ = handle.join();
        }
        result
    }
}

struct StartupStderr {
    enabled: AtomicBool,
    bytes: Mutex<Zeroizing<Vec<u8>>>,
}

struct DaemonGuard(Option<DaemonProcess>);

impl DaemonGuard {
    fn emit_startup_stderr(&self, logger: &RuntimeSshLogEmitter, exact_auth_key: &str) {
        if let Some(daemon) = self.0.as_ref() {
            daemon.emit_startup_stderr(logger, exact_auth_key);
        }
    }

    fn child_mut(&mut self) -> &mut Child {
        &mut self.0.as_mut().expect("daemon guard owns child").child
    }

    fn disable_startup_capture(&self) {
        self.0
            .as_ref()
            .expect("daemon guard owns child")
            .disable_startup_capture();
    }

    fn startup_exit_error(&mut self, status: std::process::ExitStatus) -> AccessError {
        self.0
            .as_mut()
            .expect("daemon guard owns child")
            .startup_exit_error(status)
    }

    fn take(mut self) -> DaemonProcess {
        self.0.take().expect("daemon guard owns child")
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        if let Some(daemon) = self.0.as_mut() {
            let _ = daemon.stop();
        }
    }
}

pub(super) fn terminate_child(child: &mut Child) -> Result<(), AccessError> {
    if child
        .try_wait()
        .map_err(|_| AccessError::new("access_cleanup_failed"))?
        .is_some()
    {
        return Ok(());
    }
    let process_group =
        i32::try_from(child.id()).map_err(|_| AccessError::new("access_cleanup_failed"))?;
    // SAFETY: the daemon is started in its own process group and the ID is
    // obtained directly from the live Child handle.
    unsafe {
        libc::kill(-process_group, libc::SIGTERM);
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if child
            .try_wait()
            .map_err(|_| AccessError::new("access_cleanup_failed"))?
            .is_some()
        {
            return Ok(());
        }
        thread::sleep(POLL_INTERVAL);
    }
    // SAFETY: same exact process group, force-stopped only after the grace.
    unsafe {
        libc::kill(-process_group, libc::SIGKILL);
    }
    child
        .wait()
        .map_err(|_| AccessError::new("access_cleanup_failed"))?;
    Ok(())
}

pub fn take_runtime_access_credential(bootstrap: &mut RuntimeBootstrapResponse) -> Option<String> {
    let signed_bootstrap_value = match bootstrap.access.as_mut() {
        Some(RuntimeAccessBootstrap::Managed(access)) => access
            .credential
            .take()
            .and_then(|credential| serde_json::to_string(&credential).ok()),
        Some(RuntimeAccessBootstrap::Tailscale(access)) => access
            .credential
            .take()
            .and_then(|credential| serde_json::to_string(&credential).ok()),
        None => None,
    };
    let environment_value = std::env::var(RUNTIME_SSH_CREDENTIAL_ENV).ok();
    // SAFETY: the binary calls this during single-threaded startup, before the
    // diagnostics/logging workers or any customer process are created.
    unsafe {
        std::env::remove_var(RUNTIME_SSH_CREDENTIAL_ENV);
    }
    signed_bootstrap_value.or(environment_value)
}

pub fn setup_runtime_access(
    bootstrap: &RuntimeBootstrapResponse,
    raw_credential: Option<String>,
) -> Result<Option<AccessSession>, AccessError> {
    setup_runtime_access_with_logger(bootstrap, raw_credential, None)
}
/// Run access setup under a deadline enforced from *outside* the setup thread.
///
/// Every timeout inside setup is cooperative — evaluated by the same thread
/// doing the work — so a thread blocked in a syscall enforces none of them.
/// Deployment `144623` blocked in `setup_in_root`'s `while !socket.exists()`
/// condition and never executed the loop body, so its own 90 s
/// [`DAEMON_SOCKET_TIMEOUT`] was unreachable, `setup_runtime_access` never
/// returned, and the supervisor reached neither its `Ok` nor its `Err` arm. The
/// attachment sat at `setup_started` for the whole schedule with no failure
/// code. Three earlier releases added narrower cooperative timeouts and none of
/// them could fire.
///
/// This bound cannot be defeated the same way: the caller waits on a channel
/// and gives up on its own schedule, whatever the setup thread is doing.
///
/// **A wedged setup thread is leaked on purpose.** Rust cannot cancel a thread
/// blocked in a syscall, and there is no safe way to reclaim it. Leaking one
/// thread — and the tailscaled child it owns, which the runtime's own teardown
/// will outlive — is strictly better than never reporting access failure at
/// all. The workload is unaffected either way: ADR-0040 keeps access
/// degradation isolated from workload health.
pub fn setup_runtime_access_within(
    bootstrap: &RuntimeBootstrapResponse,
    raw_credential: Option<String>,
    provider_logger: Option<RuntimeSshLogEmitter>,
    budget: Duration,
) -> Result<Option<AccessSession>, AccessError> {
    let owned_bootstrap = bootstrap.clone();
    let panic_logger = provider_logger.clone();
    run_with_external_deadline(budget, move || {
        // A panic in setup previously surfaced only as the watchdog's generic
        // Disconnected arm, with the message lost entirely: r7/145133 and
        // r8/145206 both returned silently ~4s into the socket wait with one
        // runtime-ssh record missing, and nothing named the failing line.
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            setup_runtime_access_with_logger(&owned_bootstrap, raw_credential, provider_logger)
        }));
        match attempt {
            Ok(result) => result,
            Err(payload) => {
                if let Some(logger) = panic_logger.as_ref() {
                    logger.panic_report("access_setup", &panic_message(payload.as_ref()));
                }
                Err(AccessError::new("access_setup_panicked"))
            }
        }
    })
}

/// Best-effort text of a panic payload; the two shapes `panic!` produces plus a
/// fallback, so a report is never empty.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// Run `work` on its own thread and stop waiting after `budget`, whatever the
/// thread is doing.
///
/// Split out from [`setup_runtime_access_within`] so the wedge can actually be
/// tested: the interesting input is work that never returns, which cannot be
/// produced through the real setup path.
fn run_with_external_deadline<T: Send + 'static>(
    budget: Duration,
    work: impl FnOnce() -> Result<T, AccessError> + Send + 'static,
) -> Result<T, AccessError> {
    let (sender, receiver) = std::sync::mpsc::channel();
    let spawned = thread::Builder::new()
        .name("liskov-access-setup".into())
        .spawn(move || {
            // A closed receiver means the deadline already passed; drop the
            // result rather than panicking on a send to nobody.
            let _ = sender.send(work());
        });
    if spawned.is_err() {
        // Cannot supervise what we cannot spawn. Fail typed rather than run
        // unbounded on this thread, which is the behaviour being removed.
        return Err(AccessError::new("access_setup_failed"));
    }
    match receiver.recv_timeout(budget) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            Err(AccessError::new("access_setup_timeout"))
        }
        // Sender dropped without sending — the work panicked. Report it rather
        // than block on a channel that can never produce.
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(AccessError::new("access_setup_failed"))
        }
    }
}

/// [`setup_runtime_access_within`] with the default [`ACCESS_SETUP_WATCHDOG`].
pub fn setup_runtime_access_supervised(
    bootstrap: &RuntimeBootstrapResponse,
    raw_credential: Option<String>,
    provider_logger: Option<RuntimeSshLogEmitter>,
) -> Result<Option<AccessSession>, AccessError> {
    setup_runtime_access_within(
        bootstrap,
        raw_credential,
        provider_logger,
        ACCESS_SETUP_WATCHDOG,
    )
}

pub fn setup_runtime_access_with_logger(
    bootstrap: &RuntimeBootstrapResponse,
    raw_credential: Option<String>,
    provider_logger: Option<RuntimeSshLogEmitter>,
) -> Result<Option<AccessSession>, AccessError> {
    let Some(access) = bootstrap.access.as_ref() else {
        return if raw_credential.is_none() {
            Ok(None)
        } else {
            Err(AccessError::new("access_setup_failed"))
        };
    };
    let raw_credential =
        Zeroizing::new(raw_credential.ok_or_else(|| AccessError::new("access_setup_failed"))?);
    let credential = serde_json::from_str::<RuntimeSshCredentialV1>(&raw_credential)
        .map_err(|_| AccessError::new("access_setup_failed"))?;
    match (access, credential) {
        (
            RuntimeAccessBootstrap::Tailscale(access),
            RuntimeSshCredentialV1::Tailscale(credential),
        ) => {
            let auth_key = validate_tailscale_binding(bootstrap, access, credential)
                .map_err(stage_error("access_binding_invalid"))?;
            let stage_logger = provider_logger.as_ref();
            let deadline = setup_deadline(access.setup_deadline_ms)
                .map_err(stage_error("access_deadline_exceeded"))?;
            let archive = timed_stage(stage_logger, "download", || {
                download_artifact(access, deadline).map_err(stage_error("access_download_failed"))
            })?;
            let root = timed_stage(stage_logger, "workspace", || {
                private_root(&access.attachment_id).map_err(stage_error("access_workspace_failed"))
            })?;
            let setup = timed_stage(stage_logger, "bring_up", || {
                setup_in_root(
                    bootstrap,
                    access,
                    &root,
                    &archive,
                    &auth_key,
                    deadline,
                    provider_logger.clone(),
                )
            });
            match setup {
                Ok(session) => Ok(Some(AccessSession::Tailscale(session))),
                Err(error) => {
                    let _ = std::fs::remove_dir_all(root);
                    Err(error)
                }
            }
        }
        (
            RuntimeAccessBootstrap::Managed(access),
            RuntimeSshCredentialV1::ManagedV1Compact(credential),
        ) => managed::setup(
            bootstrap,
            access,
            ManagedRuntimeSshCredential::V1Compact(credential),
        )
        .map(|session| Some(AccessSession::Managed(session))),
        (
            RuntimeAccessBootstrap::Managed(access),
            RuntimeSshCredentialV1::ManagedV1Full(credential),
        ) => managed::setup(
            bootstrap,
            access,
            ManagedRuntimeSshCredential::V1Full(credential),
        )
        .map(|session| Some(AccessSession::Managed(session))),
        _ => Err(AccessError::new("access_setup_failed")),
    }
}

/// Run a setup leg, reporting how long it took and how it ended.
///
/// The production failure modes here are absences — an attachment left at
/// `setup_started` with no terminal event — and an absence names no leg. Timing
/// every leg distinguishes "never returned" from "returned immediately", which
/// are different bugs with different fixes, without needing a shell on the
/// processor (Tailscale being the shell transport, there isn't one).
///
/// Best-effort and never fatal: reporting must not change what the leg returns.
fn timed_stage<T>(
    logger: Option<&RuntimeSshLogEmitter>,
    stage: &'static str,
    run: impl FnOnce() -> Result<T, AccessError>,
) -> Result<T, AccessError> {
    let started = std::time::Instant::now();
    let result = run();
    if let Some(logger) = logger {
        let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match &result {
            Ok(_) => logger.stage(stage, elapsed, "ok", None),
            Err(error) => logger.stage(stage, elapsed, "failed", Some(error.code)),
        }
    }
    result
}

/// Narrow a stage's generic `access_setup_failed` into a stage-specific code
/// while letting already-specific codes (e.g. `access_sidecar_*`) pass through
/// unchanged. Purely diagnostic: every stage code still reports the same typed
/// degradation channel and never alters setup behavior.
fn stage_error(code: &'static str) -> impl Fn(AccessError) -> AccessError {
    move |error| {
        if error.code == "access_setup_failed" {
            AccessError::new(code)
        } else {
            error
        }
    }
}

fn validate_tailscale_binding(
    bootstrap: &RuntimeBootstrapResponse,
    access: &TailscaleRuntimeAccessBootstrap,
    mut credential: TailscaleRuntimeSshCredentialV1,
) -> Result<Zeroizing<String>, AccessError> {
    let now_ms = unix_time_ms().ok_or_else(|| AccessError::new("access_setup_failed"))?;
    if credential.schema != CREDENTIAL_SCHEMA
        || credential.organization_id.is_empty()
        || credential.integration_id.is_empty()
        || credential.attachment_id != access.attachment_id
        || credential.application_uid != bootstrap.application_uid
        || credential.deployment_id != bootstrap.deployment_id
        || !runtime_job_ids_match(&credential.job_id, &bootstrap.job_id)
        || credential.policy_digest != bootstrap.policy_digest
        || credential.expires_at_ms != access.setup_deadline_ms
        || credential.expires_at_ms <= now_ms
        || access.setup_deadline_ms <= now_ms
        || access.provider.kind != RuntimeAccessProviderKind::Tailscale
    {
        return Err(AccessError::new("access_setup_failed"));
    }
    match &mut credential.provider {
        TailscaleRuntimeSshCredentialProvider::Tailscale { auth_key }
            if !auth_key.is_empty() && auth_key.len() <= 512 =>
        {
            Ok(Zeroizing::new(std::mem::take(auth_key)))
        }
        _ => Err(AccessError::new("access_setup_failed")),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct AcurastJobIdentity {
    origin: [u8; 32],
    sequence: u64,
}

/// Acurast exposes the same job through two JSON encodings: the control plane
/// persists `[origin, sequence]`, while the runtime bridge reports
/// `{origin: {kind: "Acurast", source: <hex>}, id: <sequence>}`. Preserve exact
/// matching for opaque IDs, but otherwise compare only a fully parsed Acurast
/// account and safe non-negative sequence. Unknown or malformed forms never
/// broaden credential authority.
fn runtime_job_ids_match(left: &str, right: &str) -> bool {
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

fn download_artifact(
    access: &TailscaleRuntimeAccessBootstrap,
    deadline: std::time::Instant,
) -> Result<Vec<u8>, AccessError> {
    let timeout = remaining_timeout(deadline, DOWNLOAD_TIMEOUT)?;
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(timeout)
        .build();
    let response = agent
        .get(&access.artifact.url)
        .call()
        .map_err(|_| AccessError::new("access_setup_failed"))?;
    let expected_size = usize::try_from(access.artifact.byte_size)
        .ok()
        .filter(|size| *size <= MAX_ARTIFACT_BYTES)
        .ok_or_else(|| AccessError::new("access_setup_failed"))?;
    if response
        .header("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|size| size != expected_size)
    {
        return Err(AccessError::new("access_setup_failed"));
    }
    let mut bytes = Vec::with_capacity(expected_size.min(1024 * 1024));
    response
        .into_reader()
        .take(u64::try_from(expected_size).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AccessError::new("access_setup_failed"))?;
    if bytes.len() != expected_size || hex::encode(Sha256::digest(&bytes)) != access.artifact.sha256
    {
        return Err(AccessError::new("access_setup_failed"));
    }
    Ok(bytes)
}

pub(super) fn private_root(attachment_id: &str) -> Result<PathBuf, AccessError> {
    // The Tailscale daemon binds its control socket under this directory, and
    // that path reaches `bind(2)` inside the PRoot sandbox. PRoot rewrites the
    // guest path to a host path by prepending the (long) rootfs prefix, while
    // the kernel's `sockaddr_un.sun_path` is a hard 108-byte field — so a long
    // guest path silently overflows once translated: the socket never appears,
    // and setup wedges at the socket-wait with no signal. (The Managed/Dropbear
    // provider shares this helper but never binds a unix socket, which is why it
    // works in PRoot with any path length.) Keep the directory name short —
    // `/tmp/lk<8 hex digest><4 hex random>`, 19 bytes — so the socket path
    // (`…/s`, 21 bytes) leaves ample headroom under 108 after translation. The
    // digest keeps the directory attributable to an attachment; the random
    // suffix keeps a retry from colliding with a leftover directory.
    let mut random = [0_u8; 2];
    getrandom::fill(&mut random).map_err(|_| AccessError::new("access_setup_failed"))?;
    let name = format!(
        "lk{}{}",
        &hex::encode(Sha256::digest(attachment_id.as_bytes()))[..8],
        hex::encode(random)
    );
    let root = Path::new("/tmp").join(name);
    std::fs::create_dir(&root).map_err(|_| AccessError::new("access_setup_failed"))?;
    std::fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .map_err(|_| AccessError::new("access_setup_failed"))?;
    Ok(root)
}

fn setup_in_root(
    bootstrap: &RuntimeBootstrapResponse,
    access: &TailscaleRuntimeAccessBootstrap,
    root: &Path,
    archive: &[u8],
    auth_key: &str,
    deadline: std::time::Instant,
    provider_logger: Option<RuntimeSshLogEmitter>,
) -> Result<TailscaleAccessSession, AccessError> {
    // Clone the logger up front: `provider_logger` is moved into `spawn_daemon`
    // below, and every stage here needs to report before that happens.
    let client_logger = provider_logger.clone();
    let stage_logger = client_logger.as_ref();
    let (tailscale, tailscaled) = timed_stage(stage_logger, "extract", || {
        extract_binaries(archive).map_err(stage_error("access_extract_failed"))
    })?;
    let tailscale_path = root.join("tailscale");
    let tailscaled_path = root.join("tailscaled");
    // `s`/`d`, not `tailscaled.sock`/`state`: the socket path is bound inside
    // PRoot and must stay well under 108 bytes after translation — see
    // `private_root` for the full reasoning.
    let socket = root.join("s");
    let state_dir = root.join("d");
    let auth_path = root.join("auth-key");
    // The two client binaries are multi-MiB writes onto PRoot-backed flash on a
    // phone. The auth key and state dir are trivial by comparison and share the
    // stage rather than earning their own.
    timed_stage(stage_logger, "write_binaries", || {
        write_private_file(&tailscale_path, &tailscale, 0o700)
            .map_err(stage_error("access_workspace_failed"))?;
        write_private_file(&tailscaled_path, &tailscaled, 0o700)
            .map_err(stage_error("access_workspace_failed"))?;
        write_private_file(&auth_path, auth_key.as_bytes(), 0o600)
            .map_err(stage_error("access_workspace_failed"))?;
        std::fs::create_dir(&state_dir).map_err(|_| AccessError::new("access_workspace_failed"))
    })?;
    let daemon_deadline = subprocess_deadline(deadline, DAEMON_SOCKET_TIMEOUT)
        .map_err(stage_error("access_deadline_exceeded"))?;
    let mut daemon = DaemonGuard(Some(timed_stage(stage_logger, "daemon_spawn", || {
        spawn_daemon(
            &tailscaled_path,
            &socket,
            &state_dir,
            access.launch_profile,
            provider_logger,
            auth_key,
        )
    })?));
    // Every exit from this loop is reported, including the ones that never
    // happen. On r5/144545 the loop ran 678 s against a 90 s bound and emitted
    // nothing at all, because only the successful exit was stamped — so an
    // absence could not distinguish "never entered" from "entered and never
    // left".
    //
    // The heartbeat is the discriminator. `socket.exists()` is the loop
    // condition and the one call here that could plausibly block forever on a
    // PRoot-backed path; if it does, we see `entered` and then nothing. If the
    // loop is genuinely iterating, beats keep arriving and the bound itself is
    // what failed. Those are different bugs.
    let socket_wait_started = std::time::Instant::now();
    let elapsed_ms =
        |start: std::time::Instant| u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    if let Some(logger) = client_logger.as_ref() {
        logger.stage("daemon_socket", 0, "entered", None);
    }
    let mut next_beat_at = socket_wait_started + SOCKET_WAIT_HEARTBEAT;
    while !socket.exists() {
        if let Some(status) = daemon
            .child_mut()
            .try_wait()
            .map_err(|_| AccessError::new("access_sidecar_failed"))?
        {
            let _ = std::fs::remove_file(&auth_path);
            let error = daemon.startup_exit_error(status);
            if let Some(logger) = client_logger.as_ref() {
                logger.stage(
                    "daemon_socket",
                    elapsed_ms(socket_wait_started),
                    "failed",
                    Some(error.code),
                );
            }
            return Err(error);
        }
        let now = std::time::Instant::now();
        if now >= daemon_deadline {
            let _ = std::fs::remove_file(&auth_path);
            if let Some(logger) = client_logger.as_ref() {
                logger.stage(
                    "daemon_socket",
                    elapsed_ms(socket_wait_started),
                    "failed",
                    Some("access_sidecar_start_timeout"),
                );
            }
            return Err(AccessError::new("access_sidecar_start_timeout"));
        }
        if now >= next_beat_at {
            if let Some(logger) = client_logger.as_ref() {
                logger.stage(
                    "daemon_socket",
                    elapsed_ms(socket_wait_started),
                    "waiting",
                    None,
                );
            }
            next_beat_at = now + SOCKET_WAIT_HEARTBEAT;
        }
        thread::sleep(POLL_INTERVAL);
    }
    if let Some(logger) = client_logger.as_ref() {
        logger.stage("daemon_socket", elapsed_ms(socket_wait_started), "ok", None);
    }
    // Deliberately NOT disabling the daemon's stderr capture here. It used to be
    // dropped the moment the socket appeared — i.e. immediately before `up`,
    // the leg most likely to fail — so a stalled login produced nine seconds of
    // startup noise and then silence. Capture stays on until the session is
    // fully validated below.
    let hostname = runtime_hostname(&bootstrap.application_uid, &bootstrap.deployment_id);
    let auth_argument = format!("file:{}", auth_path.display());
    let up = timed_stage(client_logger.as_ref(), "up", || {
        run_bounded(
            &tailscale_path,
            &[
                OsString::from(format!("--socket={}", socket.display())),
                OsString::from("up"),
                OsString::from(format!("--auth-key={auth_argument}")),
                OsString::from(format!("--hostname={hostname}")),
                OsString::from("--ssh"),
                OsString::from("--accept-dns=false"),
                OsString::from("--accept-routes=false"),
                OsString::from(format!(
                    "--timeout={}s",
                    TUNNEL_UP_TIMEOUT
                        .saturating_sub(TUNNEL_UP_CLIENT_MARGIN)
                        .as_secs()
                )),
            ],
            subprocess_deadline(deadline, TUNNEL_UP_TIMEOUT)
                .map_err(stage_error("access_deadline_exceeded"))?,
            client_logger.as_ref().map(|logger| (logger, auth_key)),
        )
    });
    std::fs::remove_file(&auth_path).map_err(|_| AccessError::new("access_workspace_failed"))?;
    if let Err(error) = up {
        // `up` failing tells us the tunnel did not come up; it does not tell us
        // why. `status --json` does — it distinguishes "never reached the
        // control plane" from "key rejected" from "authenticated but no
        // netmap", which is otherwise only answerable with a shell on the
        // processor, and Tailscale is itself the shell transport.
        report_tunnel_failure_evidence(
            &tailscale_path,
            &socket,
            deadline,
            client_logger.as_ref().map(|logger| (logger, auth_key)),
            &daemon,
        );
        return Err(stage_error("access_up_failed")(error));
    }
    let status = run_bounded_capture(
        &tailscale_path,
        &[
            OsString::from(format!("--socket={}", socket.display())),
            OsString::from("status"),
            OsString::from("--json"),
        ],
        subprocess_deadline(deadline, COMMAND_TIMEOUT)
            .map_err(stage_error("access_deadline_exceeded"))?,
        client_logger.as_ref().map(|logger| (logger, auth_key)),
    )
    .map_err(stage_error("access_status_invalid"))?;
    let status: TailscaleStatus =
        serde_json::from_slice(&status).map_err(|_| AccessError::new("access_status_invalid"))?;
    if status.backend_state != "Running"
        || status.current_tailnet.name != access.expected_tailnet
        || status.self_node.id.is_empty()
        || status.self_node.id.len() > 256
        || status.self_node.dns_name.is_empty()
        || status.self_node.dns_name.len() > 256
    {
        return Err(AccessError::new("access_status_unexpected"));
    }
    daemon.disable_startup_capture();
    Ok(TailscaleAccessSession {
        daemon: daemon.take(),
        root: root.to_path_buf(),
        attachment_id: access.attachment_id.clone(),
        fence: access.fence,
        device_id: status.self_node.id,
        hostname: status.self_node.dns_name.trim_end_matches('.').to_string(),
        client_version: access.artifact.version.clone(),
        client_digest: format!("sha256:{}", access.artifact.sha256),
        degraded_reported: false,
    })
}

fn extract_binaries(archive: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AccessError> {
    let decoder = GzDecoder::new(archive);
    let mut archive = Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|_| AccessError::new("access_setup_failed"))?;
    let mut tailscale = None;
    let mut tailscaled = None;
    for entry in entries {
        let mut entry = entry.map_err(|_| AccessError::new("access_setup_failed"))?;
        let path = entry
            .path()
            .map_err(|_| AccessError::new("access_setup_failed"))?
            .into_owned();
        if path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(AccessError::new("access_setup_failed"));
        }
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            continue;
        }
        if !entry_type.is_file() {
            return Err(AccessError::new("access_setup_failed"));
        }
        let Some(name) = path
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_string)
        else {
            return Err(AccessError::new("access_setup_failed"));
        };
        if !matches!(name.as_str(), "tailscale" | "tailscaled") {
            return Err(AccessError::new("access_setup_failed"));
        }
        if entry.header().size().unwrap_or(u64::MAX) > MAX_BINARY_BYTES {
            return Err(AccessError::new("access_setup_failed"));
        }
        let mut bytes = Vec::new();
        (&mut entry)
            .take(MAX_BINARY_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AccessError::new("access_setup_failed"))?;
        if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_BINARY_BYTES {
            return Err(AccessError::new("access_setup_failed"));
        }
        let slot = if name == "tailscale" {
            &mut tailscale
        } else {
            &mut tailscaled
        };
        if slot.replace(bytes).is_some() {
            return Err(AccessError::new("access_setup_failed"));
        }
    }
    match (tailscale, tailscaled) {
        (Some(tailscale), Some(tailscaled)) => Ok((tailscale, tailscaled)),
        _ => Err(AccessError::new("access_setup_failed")),
    }
}

fn write_private_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), AccessError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|_| AccessError::new("access_setup_failed"))?;
    file.write_all(bytes)
        .map_err(|_| AccessError::new("access_setup_failed"))?;
    file.sync_all()
        .map_err(|_| AccessError::new("access_setup_failed"))
}

fn spawn_daemon(
    binary: &Path,
    socket: &Path,
    state_dir: &Path,
    launch_profile: Option<RuntimeAccessLaunchProfile>,
    provider_logger: Option<RuntimeSshLogEmitter>,
    auth_key: &str,
) -> Result<DaemonProcess, AccessError> {
    let mut command = Command::new(binary);
    command.args(daemon_arguments(socket, state_dir, launch_profile));
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: setpgid is async-signal-safe and performs no allocation.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|error| match error.kind() {
        std::io::ErrorKind::PermissionDenied => AccessError::new("access_sidecar_exec_denied"),
        std::io::ErrorKind::NotFound => AccessError::new("access_sidecar_exec_missing"),
        _ => AccessError::new("access_sidecar_spawn_failed"),
    })?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| AccessError::new("access_sidecar_spawn_failed"))?;
    let startup_stderr = Arc::new(StartupStderr {
        enabled: AtomicBool::new(true),
        bytes: Mutex::new(Zeroizing::new(Vec::with_capacity(MAX_STARTUP_STDERR_BYTES))),
    });
    let reader_state = Arc::clone(&startup_stderr);
    let exact_auth_key = Zeroizing::new(auth_key.to_string());
    let stderr_thread = match thread::Builder::new()
        .name("liskov-daemon-stderr".into())
        .spawn(move || {
            let mut buffer = [0_u8; 4 * 1024];
            let mut line = Vec::with_capacity(1024);
            let mut line_truncated = false;
            while let Ok(read) = stderr.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                if reader_state.enabled.load(Ordering::Acquire) {
                    if let Ok(mut captured) = reader_state.bytes.lock() {
                        if reader_state.enabled.load(Ordering::Acquire) {
                            let remaining = MAX_STARTUP_STDERR_BYTES.saturating_sub(captured.len());
                            captured.extend_from_slice(&buffer[..read.min(remaining)]);
                        }
                    }
                }
                let Some(logger) = provider_logger.as_ref() else {
                    continue;
                };
                for byte in &buffer[..read] {
                    if *byte == b'\n' {
                        logger.raw_tailscaled_line(&line, &exact_auth_key, line_truncated);
                        line.clear();
                        line_truncated = false;
                    } else if line.len() < crate::logging::RUNTIME_SSH_LINE_BYTES {
                        line.push(*byte);
                    } else {
                        line_truncated = true;
                    }
                }
            }
            if !line.is_empty() || line_truncated {
                if let Some(logger) = provider_logger.as_ref() {
                    logger.raw_tailscaled_line(&line, &exact_auth_key, line_truncated);
                }
            }
        }) {
        Ok(handle) => handle,
        Err(_) => {
            let _ = child.kill();
            return Err(AccessError::new("access_thread_spawn_failed"));
        }
    };
    Ok(DaemonProcess {
        child,
        startup_stderr,
        stderr_thread: Some(stderr_thread),
    })
}

fn daemon_arguments(
    socket: &Path,
    state_dir: &Path,
    launch_profile: Option<RuntimeAccessLaunchProfile>,
) -> Vec<OsString> {
    let mut arguments = vec![OsString::from("--tun=userspace-networking")];
    if launch_profile == Some(RuntimeAccessLaunchProfile::TailscaleAcurastProotV1) {
        arguments.push(OsString::from("--netmon-mode=permission-fallback-v4"));
    }
    arguments.extend([
        OsString::from("--state=mem:"),
        OsString::from(format!("--socket={}", socket.display())),
        OsString::from(format!("--statedir={}", state_dir.display())),
    ]);
    arguments
}

fn sidecar_exit_error(status: std::process::ExitStatus, startup_stderr: &[u8]) -> AccessError {
    match status.signal() {
        Some(libc::SIGSYS) => AccessError::new("access_sidecar_syscall_blocked"),
        Some(libc::SIGABRT) | Some(libc::SIGBUS) | Some(libc::SIGILL) | Some(libc::SIGSEGV) => {
            AccessError::new("access_sidecar_crashed")
        }
        Some(_) => AccessError::new("access_sidecar_signaled"),
        None => classify_sidecar_exit(status.success(), startup_stderr),
    }
}

fn classify_sidecar_exit(success: bool, startup_stderr: &[u8]) -> AccessError {
    let stderr = String::from_utf8_lossy(startup_stderr).to_ascii_lowercase();
    let code = if stderr.contains("tailscaled got signal") && stderr.contains("shutting down") {
        "access_sidecar_shutdown_signal"
    } else if stderr.contains("wgengine has been closed; shutting down") {
        "access_sidecar_engine_closed"
    } else if stderr.contains("failed to create state directory:") {
        "access_sidecar_state_directory_failed"
    } else if stderr.contains("tailscaled requires root") {
        "access_sidecar_requires_root"
    } else if stderr.contains("netmon.new:") {
        "access_sidecar_network_monitor_failed"
    } else if stderr.contains("safesocket.listen:") {
        "access_sidecar_socket_failed"
    } else if stderr.contains("getlocalbackend error:") {
        "access_sidecar_backend_failed"
    } else if stderr.contains("ipnserver.run:") {
        "access_sidecar_ipn_server_failed"
    } else if stderr.contains("failed to start netstack:") {
        "access_sidecar_netstack_failed"
    } else if stderr.contains("--statedir (or at least --state) is required") {
        "access_sidecar_state_required"
    } else if success {
        "access_sidecar_exited_cleanly"
    } else {
        "access_sidecar_exited"
    };
    AccessError::new(code)
}

/// Emit a failed client command's bounded stderr through the raw-after-redaction
/// provider log channel — the same path daemon startup stderr uses — so typed
/// `access_up_failed` / `access_status_invalid` degradations carry evidence.
/// Snapshot why the tunnel did not come up, on the failure path only.
///
/// `up` failing says the tunnel is not running; it never says why. The three
/// causes look identical from outside — the daemon never reached the control
/// plane, the auth key was rejected, or it authenticated but got no netmap —
/// and Tailscale is itself the SSH transport, so a shell on the processor is not
/// available to tell them apart. `status --json` distinguishes all three, and
/// the daemon's own stderr explains the surrounding behaviour.
///
/// Everything here is best-effort: this runs while already returning an error,
/// so a failure to collect evidence must never mask the original failure.
fn report_tunnel_failure_evidence(
    tailscale_path: &Path,
    socket: &Path,
    deadline: std::time::Instant,
    failure_logger: Option<(&RuntimeSshLogEmitter, &str)>,
    daemon: &DaemonGuard,
) {
    let Some((logger, exact_auth_key)) = failure_logger else {
        return;
    };
    // The daemon's stderr from startup through the failed login.
    daemon.emit_startup_stderr(logger, exact_auth_key);
    let Ok(status_deadline) = subprocess_deadline(deadline, STATUS_EVIDENCE_TIMEOUT) else {
        return;
    };
    let Ok(output) = run_command(
        tailscale_path,
        &[
            OsString::from(format!("--socket={}", socket.display())),
            OsString::from("status"),
            OsString::from("--json"),
        ],
        status_deadline,
    ) else {
        return;
    };
    // stdout carries the status document; stderr carries the reason it could not
    // be produced. Both are useful, and both go through the same redaction.
    emit_command_stderr(
        logger,
        exact_auth_key,
        &output.stdout,
        output.output_too_large,
    );
    emit_command_stderr(
        logger,
        exact_auth_key,
        &output.stderr,
        output.stderr_truncated,
    );
}

fn emit_command_stderr(
    logger: &RuntimeSshLogEmitter,
    exact_auth_key: &str,
    stderr: &[u8],
    stderr_truncated: bool,
) {
    let mut lines = stderr.split(|byte| *byte == b'\n').peekable();
    while let Some(line) = lines.next() {
        let last = lines.peek().is_none();
        if last && line.is_empty() {
            break;
        }
        logger.raw_tailscaled_line(line, exact_auth_key, last && stderr_truncated);
    }
}

fn run_bounded(
    binary: &Path,
    args: &[OsString],
    deadline: std::time::Instant,
    failure_logger: Option<(&RuntimeSshLogEmitter, &str)>,
) -> Result<(), AccessError> {
    let output = run_command(binary, args, deadline)?;
    if output.status.is_some_and(|status| status.success()) && !output.output_too_large {
        return Ok(());
    }
    if let Some((logger, exact_auth_key)) = failure_logger {
        emit_command_stderr(
            logger,
            exact_auth_key,
            &output.stderr,
            output.stderr_truncated,
        );
    }
    Err(AccessError::new("access_setup_failed"))
}

fn run_bounded_capture(
    binary: &Path,
    args: &[OsString],
    deadline: std::time::Instant,
    failure_logger: Option<(&RuntimeSshLogEmitter, &str)>,
) -> Result<Vec<u8>, AccessError> {
    let output = run_command(binary, args, deadline)?;
    if !output.status.is_some_and(|status| status.success()) || output.output_too_large {
        if let Some((logger, exact_auth_key)) = failure_logger {
            emit_command_stderr(
                logger,
                exact_auth_key,
                &output.stderr,
                output.stderr_truncated,
            );
        }
        return Err(AccessError::new("access_setup_failed"));
    }
    Ok(output.stdout)
}

struct CommandOutput {
    /// `None` means the command exceeded its deadline and was killed.
    status: Option<std::process::ExitStatus>,
    stdout: Vec<u8>,
    output_too_large: bool,
    stderr: Vec<u8>,
    stderr_truncated: bool,
}

fn run_command(
    binary: &Path,
    args: &[OsString],
    deadline: std::time::Instant,
) -> Result<CommandOutput, AccessError> {
    let mut child = Command::new(binary)
        .args(args)
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
    // Readers append into shared buffers instead of returning their result at
    // EOF, because EOF may never arrive: killing a child does not close a pipe
    // that a surviving grandchild still holds open.
    let stdout_buf: Arc<Mutex<(Vec<u8>, bool)>> = Arc::new(Mutex::new((Vec::new(), false)));
    let stderr_buf: Arc<Mutex<(Vec<u8>, bool)>> = Arc::new(Mutex::new((Vec::new(), false)));
    let stdout_sink = Arc::clone(&stdout_buf);
    let stderr_sink = Arc::clone(&stderr_buf);
    // Plain `thread::spawn` panics if the OS refuses a thread — under resource
    // pressure that panic used to surface only as an untyped silent unwind.
    let reader = match thread::Builder::new()
        .name("liskov-cmd-stdout".into())
        .spawn(move || {
            let mut buffer = [0_u8; 8 * 1024];
            while let Ok(read) = stdout.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                if let Ok(mut sink) = stdout_sink.lock() {
                    let remaining = MAX_COMMAND_OUTPUT_BYTES.saturating_sub(sink.0.len());
                    sink.0.extend_from_slice(&buffer[..read.min(remaining)]);
                    sink.1 |= read > remaining;
                }
            }
        }) {
        Ok(handle) => handle,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(AccessError::new("access_thread_spawn_failed"));
        }
    };
    let stderr_reader = match thread::Builder::new()
        .name("liskov-cmd-stderr".into())
        .spawn(move || {
            let mut buffer = [0_u8; 4 * 1024];
            while let Ok(read) = stderr.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                if let Ok(mut sink) = stderr_sink.lock() {
                    let remaining = MAX_STARTUP_STDERR_BYTES.saturating_sub(sink.0.len());
                    sink.0.extend_from_slice(&buffer[..read.min(remaining)]);
                    sink.1 |= read > remaining;
                }
            }
        }) {
        Ok(handle) => handle,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(AccessError::new("access_thread_spawn_failed"));
        }
    };
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| AccessError::new("access_setup_failed"))?
        {
            break Some(status);
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        thread::sleep(POLL_INTERVAL);
    };
    // Give the readers a bounded chance to drain, then take whatever they have.
    // Waiting indefinitely is what wedged the caller: an over-budget `tailscale
    // up` left the access setup hung with no failure ever reported. Partial
    // output is still evidence, and far better than never returning.
    let drain_deadline = std::time::Instant::now() + READER_DRAIN_GRACE;
    while (!reader.is_finished() || !stderr_reader.is_finished())
        && std::time::Instant::now() < drain_deadline
    {
        thread::sleep(POLL_INTERVAL);
    }
    let (stdout, output_too_large) = stdout_buf
        .lock()
        .map(|sink| (sink.0.clone(), sink.1))
        .unwrap_or_else(|_| (Vec::new(), false));
    let (stderr, stderr_truncated) = stderr_buf
        .lock()
        .map(|sink| (sink.0.clone(), sink.1))
        .unwrap_or_else(|_| (Vec::new(), false));
    Ok(CommandOutput {
        status,
        stdout,
        output_too_large,
        stderr,
        stderr_truncated,
    })
}

fn setup_deadline(deadline_ms: u64) -> Result<std::time::Instant, AccessError> {
    let remaining = deadline_ms
        .checked_sub(unix_time_ms().ok_or_else(|| AccessError::new("access_setup_failed"))?)
        .ok_or_else(|| AccessError::new("access_setup_failed"))?;
    Ok(std::time::Instant::now() + Duration::from_millis(remaining))
}

/// Per-leg budget, always still bounded by the absolute setup deadline so no
/// leg can outlive the credential it was issued against.
fn subprocess_deadline(
    absolute_deadline: std::time::Instant,
    budget: Duration,
) -> Result<std::time::Instant, AccessError> {
    let now = std::time::Instant::now();
    if now >= absolute_deadline {
        return Err(AccessError::new("access_setup_failed"));
    }
    Ok(absolute_deadline.min(now + budget))
}

fn remaining_timeout(
    deadline: std::time::Instant,
    budget: Duration,
) -> Result<Duration, AccessError> {
    let now = std::time::Instant::now();
    if now >= deadline {
        return Err(AccessError::new("access_setup_failed"));
    }
    Ok(deadline
        .saturating_duration_since(now)
        .min(budget)
        .max(Duration::from_millis(1)))
}

fn unix_time_ms() -> Option<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis(),
    )
    .ok()
}

fn runtime_hostname(application_uid: &str, deployment_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"runtime-ssh-hostname.v1\0");
    hasher.update(application_uid.as_bytes());
    hasher.update(b"\0");
    hasher.update(deployment_id.as_bytes());
    format!("liskov-{}", &hex::encode(hasher.finalize())[..16])
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TailscaleStatus {
    backend_state: String,
    current_tailnet: TailscaleTailnet,
    #[serde(rename = "Self")]
    self_node: TailscaleSelf,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TailscaleTailnet {
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TailscaleSelf {
    id: String,
    #[serde(rename = "DNSName")]
    dns_name: String,
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::*;
    use crate::protocol::{
        RuntimeAccessArtifact, RuntimeAccessProvider, RuntimeAccessProviderKind,
    };

    #[test]
    fn private_root_socket_path_stays_short_for_sun_path() {
        // The daemon control socket is bound inside PRoot, which prepends a long
        // rootfs prefix to the guest path before it reaches the kernel's
        // 108-byte `sockaddr_un.sun_path`. If this path regrows, tailscaled's
        // socket silently never appears on real processors and setup wedges at
        // the socket-wait. Pin a short budget: the shipped guest socket path is
        // 21 bytes, leaving ~87 bytes for the PRoot prefix (observed ~60-80).
        let root = private_root("attachment-sun-path-regression").unwrap();
        let socket = root.join("s");
        let len = socket.as_os_str().len();
        std::fs::remove_dir_all(&root).unwrap();
        assert!(
            len <= 28,
            "guest socket path is {len} bytes ({}); keep it short so the \
             PRoot-translated host path stays under sun_path's 108-byte limit",
            socket.display()
        );
    }

    fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut encoded = Vec::new();
        {
            let gzip = flate2::write::GzEncoder::new(&mut encoded, flate2::Compression::default());
            let mut archive = tar::Builder::new(gzip);
            for (path, bytes) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(u64::try_from(bytes.len()).unwrap());
                header.set_mode(0o755);
                header.set_cksum();
                archive.append_data(&mut header, path, *bytes).unwrap();
            }
            archive.into_inner().unwrap().finish().unwrap();
        }
        encoded
    }

    #[test]
    fn archive_extraction_accepts_only_unique_regular_safe_binaries() {
        let valid = archive(&[
            ("tailscale_1.0_arm64/tailscale", b"cli"),
            ("tailscale_1.0_arm64/tailscaled", b"daemon"),
        ]);
        assert_eq!(
            extract_binaries(&valid).unwrap(),
            (b"cli".to_vec(), b"daemon".to_vec())
        );

        let duplicate = archive(&[
            ("one/tailscale", b"first"),
            ("two/tailscale", b"second"),
            ("one/tailscaled", b"daemon"),
        ]);
        assert_eq!(
            extract_binaries(&duplicate).unwrap_err().code,
            "access_setup_failed"
        );

        let unexpected = archive(&[
            ("tailscale_1.0_arm64/tailscale", b"cli"),
            ("tailscale_1.0_arm64/tailscaled", b"daemon"),
            ("tailscale_1.0_arm64/install.sh", b"unexpected"),
        ]);
        assert_eq!(
            extract_binaries(&unexpected).unwrap_err().code,
            "access_setup_failed"
        );
    }

    #[test]
    fn constrained_launch_profile_adds_only_the_netmon_argument() {
        let socket = Path::new("/tmp/socket");
        let state = Path::new("/tmp/state");
        let standard = daemon_arguments(socket, state, None);
        assert_eq!(
            standard,
            [
                "--tun=userspace-networking",
                "--state=mem:",
                "--socket=/tmp/socket",
                "--statedir=/tmp/state",
            ]
            .map(OsString::from)
        );
        assert_eq!(
            daemon_arguments(
                socket,
                state,
                Some(RuntimeAccessLaunchProfile::TailscaleStandardV1),
            ),
            standard
        );
        let constrained = daemon_arguments(
            socket,
            state,
            Some(RuntimeAccessLaunchProfile::TailscaleAcurastProotV1),
        );
        assert_eq!(constrained.len(), standard.len() + 1);
        assert_eq!(constrained[0], standard[0]);
        assert_eq!(
            constrained[1],
            OsString::from("--netmon-mode=permission-fallback-v4")
        );
        assert_eq!(constrained[2..], standard[1..]);
    }

    /// Processors sit on very different links, so each leg gets a budget sized
    /// to its work rather than one flat command timeout — but every budget is
    /// still clamped by the absolute setup deadline, so no leg can outlive the
    /// credential it was issued against.
    #[test]
    fn each_leg_gets_its_own_budget_bounded_by_the_setup_deadline() {
        assert!(
            DOWNLOAD_TIMEOUT >= Duration::from_secs(600),
            "26.5 MB must still fit on a slow processor link"
        );
        assert!(
            TUNNEL_UP_TIMEOUT >= Duration::from_secs(240),
            "control handshake plus DERP negotiation needs room on a slow link"
        );
        assert!(DAEMON_SOCKET_TIMEOUT >= Duration::from_secs(60));
        assert!(
            TUNNEL_UP_CLIENT_MARGIN < TUNNEL_UP_TIMEOUT,
            "the client must give up before the harness kills it, or a slow link \
             loses the client's own diagnostic"
        );

        let now = std::time::Instant::now();

        // A generous budget never extends past the absolute deadline.
        let tight = now + Duration::from_secs(5);
        assert!(subprocess_deadline(tight, DOWNLOAD_TIMEOUT).unwrap() <= tight);
        assert!(remaining_timeout(tight, DOWNLOAD_TIMEOUT).unwrap() <= Duration::from_secs(5));

        // With deadline room to spare, the leg's own budget is what applies.
        let roomy = now + Duration::from_secs(3_600);
        let capped = remaining_timeout(roomy, TUNNEL_UP_TIMEOUT).unwrap();
        assert!(capped <= TUNNEL_UP_TIMEOUT && capped > COMMAND_TIMEOUT);

        // An expired deadline still fails closed.
        let past = now - Duration::from_secs(1);
        assert!(subprocess_deadline(past, DOWNLOAD_TIMEOUT).is_err());
        assert!(remaining_timeout(past, DOWNLOAD_TIMEOUT).is_err());
    }

    #[test]
    fn deadline_kill_never_blocks_on_a_held_pipe() {
        // Killing a child does not close a pipe a surviving grandchild still
        // holds, so the reader never sees EOF. Joining it blocked forever, which
        // turned this deadline into a permanent hang: a Tailscale `up` that
        // exceeded its budget left the access setup wedged with no failure ever
        // reported and an attachment frozen at setup_started.
        let _lock = crate::supervisor::tests::PROCESS_TEST_LOCK.lock().unwrap();
        let started = std::time::Instant::now();
        let killed = run_command(
            Path::new("/bin/sh"),
            &[
                OsString::from("-c"),
                // The backgrounded sleep inherits stderr and outlives its parent.
                OsString::from("sleep 60 & echo pre-timeout >&2; sleep 30"),
            ],
            std::time::Instant::now() + Duration::from_secs(1),
        )
        .expect("run_command must return");
        let elapsed = started.elapsed();
        assert_eq!(killed.status, None, "the child must be recorded as killed");
        assert!(
            elapsed < Duration::from_secs(1) + READER_DRAIN_GRACE + Duration::from_secs(5),
            "run_command must return promptly after the deadline, took {elapsed:?}"
        );
        assert!(
            killed.stderr.starts_with(b"pre-timeout"),
            "output written before the kill must still be reported as evidence"
        );
    }

    #[test]
    fn tunnel_failure_evidence_captures_status_stdout_not_just_stderr() {
        // When `up` fails we learn the tunnel is down but not why. The three
        // causes — never reached the control plane, key rejected, authenticated
        // without a netmap — are only distinguishable from `status --json`, and
        // Tailscale is itself the SSH transport so there is no shell to ask.
        // `status` writes its document to STDOUT, so evidence capture that only
        // forwarded stderr (as the failure path did) reported nothing at all.
        let _lock = crate::supervisor::tests::PROCESS_TEST_LOCK.lock().unwrap();
        let shell = Path::new("/bin/sh");
        let output = run_command(
            shell,
            &[
                OsString::from("-c"),
                OsString::from("echo '{\"BackendState\":\"NeedsLogin\"}'; exit 0"),
            ],
            std::time::Instant::now() + Duration::from_secs(10),
        )
        .expect("status command runs");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("NeedsLogin"),
            "the status document must be readable from stdout"
        );
        assert!(
            output.stderr.is_empty(),
            "a healthy status writes nothing to stderr"
        );
    }

    #[test]
    fn status_evidence_budget_is_short_and_bounded_by_the_deadline() {
        // This snapshot runs while already returning a failure, so it must not
        // meaningfully extend the failure path.
        assert!(STATUS_EVIDENCE_TIMEOUT <= Duration::from_secs(15));
        assert!(STATUS_EVIDENCE_TIMEOUT < TUNNEL_UP_TIMEOUT);
        let tight = std::time::Instant::now() + Duration::from_secs(2);
        assert!(subprocess_deadline(tight, STATUS_EVIDENCE_TIMEOUT).unwrap() <= tight);
    }

    #[test]
    fn a_grouped_stage_reports_the_first_failure_not_the_last() {
        // `write_binaries` folds four filesystem operations into one stage, so
        // the code it reports must be the one that actually failed first —
        // otherwise the stage line would misattribute the failure to whichever
        // step happened to be last.
        let mut ran = 0;
        let err = timed_stage(None, "write_binaries", || {
            ran += 1;
            Err::<(), _>(AccessError::new("access_workspace_failed"))?;
            ran += 1;
            Err::<(), _>(AccessError::new("access_extract_failed"))
        })
        .unwrap_err();
        assert_eq!(err.code, "access_workspace_failed");
        assert_eq!(ran, 1, "later steps must not run after the first failure");
    }

    #[test]
    fn the_socket_wait_heartbeat_makes_a_stuck_loop_visible() {
        // r5/144545 sat in this loop for 678s against a 90s bound and emitted
        // nothing, because only the successful exit was stamped. A beat has to
        // land well inside the bound, or "still waiting" stays
        // indistinguishable from "never got here".
        assert!(SOCKET_WAIT_HEARTBEAT < DAEMON_SOCKET_TIMEOUT);
        let beats_inside_bound = DAEMON_SOCKET_TIMEOUT.as_secs() / SOCKET_WAIT_HEARTBEAT.as_secs();
        assert!(
            beats_inside_bound >= 3,
            "a stuck loop must beat several times before its own deadline"
        );
        assert!(
            beats_inside_bound <= 12,
            "but not so often it floods the bounded runtime-ssh queue"
        );
        // The poll has to be finer than the beat or the cadence is meaningless.
        assert!(POLL_INTERVAL < SOCKET_WAIT_HEARTBEAT);
    }

    #[test]
    fn a_wedged_setup_is_reported_instead_of_waited_on() {
        // The whole point: 144623 blocked inside its own loop condition, so its
        // cooperative 90s deadline never ran. This deadline is enforced by a
        // different thread, so work that never returns must still produce a
        // typed failure — promptly, without joining the wedged thread.
        let started = std::time::Instant::now();
        let error = run_with_external_deadline(Duration::from_millis(150), || {
            thread::sleep(Duration::from_secs(60)); // stands in for a blocked syscall
            Ok::<(), AccessError>(())
        })
        .unwrap_err();
        assert_eq!(error.code, "access_setup_timeout");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "must give up on its own schedule, not wait for the wedged thread"
        );
    }

    #[test]
    fn supervision_passes_through_both_outcomes_unchanged() {
        // Supervision must be invisible when the work behaves; a wrapper that
        // rewrote results would trade one silent failure for another.
        let ok =
            run_with_external_deadline(Duration::from_secs(5), || Ok::<_, AccessError>(9)).unwrap();
        assert_eq!(ok, 9);
        let err = run_with_external_deadline(Duration::from_secs(5), || {
            Err::<(), _>(AccessError::new("access_up_failed"))
        })
        .unwrap_err();
        assert_eq!(err.code, "access_up_failed");
    }

    #[test]
    fn a_panicking_setup_reports_rather_than_hanging() {
        // The sender is dropped without a value, which would block a plain recv
        // forever — the failure mode this function exists to remove.
        let error = run_with_external_deadline(Duration::from_secs(5), || {
            panic!("setup panicked");
            #[allow(unreachable_code)]
            Ok::<(), AccessError>(())
        })
        .unwrap_err();
        assert_eq!(error.code, "access_setup_failed");
    }

    #[test]
    fn the_watchdog_can_never_pre_empt_a_progressing_setup() {
        // It bounds the un-evaluable case, not slow-but-working legs, so it must
        // exceed every internal budget it supervises.
        assert!(ACCESS_SETUP_WATCHDOG > DOWNLOAD_TIMEOUT);
        assert!(ACCESS_SETUP_WATCHDOG > DAEMON_SOCKET_TIMEOUT);
        assert!(ACCESS_SETUP_WATCHDOG > TUNNEL_UP_TIMEOUT);
        assert!(
            ACCESS_SETUP_WATCHDOG >= DOWNLOAD_TIMEOUT + DAEMON_SOCKET_TIMEOUT + TUNNEL_UP_TIMEOUT,
            "legs run in sequence, so the ceiling must cover their sum"
        );
    }

    #[test]
    fn a_panic_is_converted_to_a_typed_code_with_its_message_preserved() {
        // The r7/145133 and r8/145206 signature: setup returned silently ~4s in
        // with one record missing. A panic must now surface as a code the
        // server admits, and its text must survive for the panic record.
        // Real catch_unwind payloads, not hand-boxed ones: the Any is the
        // payload itself, and getting that wrong is exactly how a report would
        // read "non-string panic payload" in production.
        let of = |f: fn()| {
            std::panic::catch_unwind(f)
                .map(|_| unreachable!("closure must panic"))
                .unwrap_err()
        };
        assert_eq!(panic_message(of(|| panic!("boom")).as_ref()), "boom");
        assert_eq!(
            panic_message(of(|| panic!("exact text {}", 42)).as_ref()),
            "exact text 42"
        );
        assert_eq!(
            panic_message(of(|| std::panic::panic_any(17_u8)).as_ref()),
            "non-string panic payload"
        );
    }

    #[test]
    fn timing_a_stage_never_changes_what_it_returns() {
        // The whole point of this instrumentation is to observe legs that are
        // already misbehaving, so it must be incapable of altering them. A
        // reporting path that can swallow or rewrite a result would be worse
        // than the blindness it replaces.
        let ok = timed_stage(None, "download", || Ok::<_, AccessError>(7)).unwrap();
        assert_eq!(ok, 7);

        let err = timed_stage(None, "up", || {
            Err::<(), _>(AccessError::new("access_up_failed"))
        })
        .unwrap_err();
        assert_eq!(err.code, "access_up_failed");
    }

    #[test]
    fn stage_error_narrows_only_the_generic_code() {
        assert_eq!(
            stage_error("access_download_failed")(AccessError::new("access_setup_failed")).code,
            "access_download_failed"
        );
        assert_eq!(
            stage_error("access_up_failed")(AccessError::new(
                "access_sidecar_network_monitor_failed"
            ))
            .code,
            "access_sidecar_network_monitor_failed"
        );
    }

    #[test]
    fn run_command_captures_bounded_stderr_and_marks_deadline_kills() {
        let _lock = crate::supervisor::tests::PROCESS_TEST_LOCK.lock().unwrap();
        let shell = Path::new("/bin/sh");
        let failed = run_command(
            shell,
            &[
                OsString::from("-c"),
                OsString::from("echo diagnostic-line >&2; exit 3"),
            ],
            std::time::Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(failed.status.map(|status| status.success()), Some(false));
        assert_eq!(failed.stderr, b"diagnostic-line\n");
        assert!(!failed.stderr_truncated);

        let killed = run_command(
            shell,
            &[
                OsString::from("-c"),
                OsString::from("echo pre-timeout >&2; sleep 30"),
            ],
            std::time::Instant::now() + Duration::from_millis(300),
        )
        .unwrap();
        assert_eq!(killed.status, None);
        assert_eq!(killed.stderr, b"pre-timeout\n");

        assert_eq!(
            run_bounded(
                shell,
                &[OsString::from("-c"), OsString::from("exit 1")],
                std::time::Instant::now() + Duration::from_secs(10),
                None,
            )
            .unwrap_err()
            .code,
            "access_setup_failed"
        );
    }

    #[test]
    fn deterministic_hostname_contains_no_customer_identifier() {
        let hostname = runtime_hostname("app-secret-name", "deployment-secret-name");
        assert!(hostname.starts_with("liskov-"));
        assert_eq!(hostname.len(), 23);
        assert!(!hostname.contains("secret"));
    }

    #[test]
    fn sidecar_exit_taxonomy_is_closed_and_secret_free() {
        assert_eq!(
            sidecar_exit_error(std::process::ExitStatus::from_raw(1 << 8), b"").code,
            "access_sidecar_exited"
        );
        assert_eq!(
            sidecar_exit_error(std::process::ExitStatus::from_raw(0), b"").code,
            "access_sidecar_exited_cleanly"
        );
        assert_eq!(
            sidecar_exit_error(std::process::ExitStatus::from_raw(libc::SIGSYS), b"").code,
            "access_sidecar_syscall_blocked"
        );
        assert_eq!(
            sidecar_exit_error(std::process::ExitStatus::from_raw(libc::SIGSEGV), b"").code,
            "access_sidecar_crashed"
        );
        assert_eq!(
            sidecar_exit_error(std::process::ExitStatus::from_raw(libc::SIGTERM), b"").code,
            "access_sidecar_signaled"
        );
    }

    #[test]
    fn sidecar_stderr_is_bounded_to_closed_secret_free_classifications() {
        let exited = std::process::ExitStatus::from_raw(1 << 8);
        for (stderr, expected) in [
            (
                "tailscaled got signal terminated; shutting down",
                "access_sidecar_shutdown_signal",
            ),
            (
                "wgengine has been closed; shutting down",
                "access_sidecar_engine_closed",
            ),
            (
                "failed to create state directory: permission denied",
                "access_sidecar_state_directory_failed",
            ),
            (
                "tailscaled requires root; use sudo tailscaled",
                "access_sidecar_requires_root",
            ),
            (
                "netmon.New: failed to read Android/PRoot interfaces",
                "access_sidecar_network_monitor_failed",
            ),
            (
                "safesocket.Listen: bind: operation not permitted",
                "access_sidecar_socket_failed",
            ),
            (
                "getLocalBackend error: platform detail",
                "access_sidecar_backend_failed",
            ),
            (
                "ipnserver.Run: platform detail",
                "access_sidecar_ipn_server_failed",
            ),
            (
                "failed to start netstack: platform detail",
                "access_sidecar_netstack_failed",
            ),
            (
                "--statedir (or at least --state) is required",
                "access_sidecar_state_required",
            ),
        ] {
            let error = sidecar_exit_error(exited, stderr.as_bytes());
            assert_eq!(error.code, expected);
            assert!(!error.code.contains("platform detail"));
        }
    }

    #[test]
    fn runtime_job_identity_matches_only_the_same_acurast_origin_and_sequence() {
        let origin_bytes = (0_u8..32).collect::<Vec<_>>();
        let canonical = serde_json::json!([
            {"name": "Acurast", "values": [[origin_bytes.clone()]]},
            133_859
        ])
        .to_string();
        let runtime = serde_json::json!({
            "id": "133859",
            "origin": {
                "kind": "Acurast",
                "source": format!("0x{}", hex::encode(&origin_bytes)),
            }
        })
        .to_string();
        assert!(runtime_job_ids_match(&canonical, &runtime));
        assert!(runtime_job_ids_match("opaque-job", "opaque-job"));

        let other_sequence = runtime.replace("133859", "133860");
        assert!(!runtime_job_ids_match(&canonical, &other_sequence));

        let mut other_origin = origin_bytes.clone();
        other_origin[31] ^= 1;
        let other_origin = runtime.replace(&hex::encode(origin_bytes), &hex::encode(other_origin));
        assert!(!runtime_job_ids_match(&canonical, &other_origin));

        assert!(!runtime_job_ids_match("opaque-job", "other-job"));
        assert!(!runtime_job_ids_match(
            r#"[{"name":"Other","values":[[[0,1,2]]]},1]"#,
            r#"{"id":"1","origin":{"kind":"Other","source":"0000000000000000000000000000000000000000000000000000000000000000"}}"#,
        ));
        assert!(!runtime_job_ids_match(
            r#"[{"name":"Acurast","values":[[[0,1,2]]]},1]"#,
            r#"{"id":"1","origin":{"kind":"Acurast","source":"not-hex"}}"#,
        ));
        assert!(!runtime_job_ids_match(
            r#"[{"name":"Acurast","values":[[[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]]},9007199254740992]"#,
            r#"{"id":"9007199254740992","origin":{"kind":"Acurast","source":"0000000000000000000000000000000000000000000000000000000000000000"}}"#,
        ));
    }

    #[test]
    fn credential_is_bound_to_the_exact_signed_bootstrap() {
        let origin_bytes = (0_u8..32).collect::<Vec<_>>();
        let canonical_job_id = serde_json::json!([
            {"name": "Acurast", "values": [[origin_bytes.clone()]]},
            133_859
        ])
        .to_string();
        let runtime_job_id = serde_json::json!({
            "id": "133859",
            "origin": {
                "kind": "Acurast",
                "source": format!("0x{}", hex::encode(origin_bytes)),
            }
        })
        .to_string();
        let deadline = unix_time_ms().unwrap() + 60_000;
        let access = TailscaleRuntimeAccessBootstrap {
            provider: RuntimeAccessProvider {
                kind: RuntimeAccessProviderKind::Tailscale,
            },
            attachment_id: "att-1".into(),
            expected_tailnet: "example.com".into(),
            setup_deadline_ms: deadline,
            fence: 1,
            launch_profile: None,
            artifact: RuntimeAccessArtifact {
                descriptor_id: "descriptor-1".into(),
                version: "1.80.3".into(),
                url: "https://pkgs.tailscale.com/stable/client.tgz".into(),
                sha256: "1".repeat(64),
                byte_size: 10,
            },
            credential: None,
        };
        let bootstrap = RuntimeBootstrapResponse {
            ok: true,
            domain: "proof.liskov.runtime-bootstrap-response.v2".into(),
            application_uid: "app-uid".into(),
            application_id: "app".into(),
            policy_digest: "sha256:policy".into(),
            deployment_id: "deployment".into(),
            job_id: runtime_job_id,
            processor_id: "processor".into(),
            runtime_instance_id: "instance".into(),
            slipway_url: "https://liskov.example".into(),
            runtime_env: None,
            supervision: None,
            logging: None,
            logging_outage_canary: false,
            diagnostics: None,
            access: Some(RuntimeAccessBootstrap::Tailscale(access.clone())),
        };
        let raw = serde_json::json!({
            "schema": CREDENTIAL_SCHEMA,
            "provider": {"kind": "tailscale", "authKey": "tskey-auth-secret"},
            "organizationId": "org",
            "integrationId": "integration",
            "attachmentId": "att-1",
            "applicationUid": "app-uid",
            "deploymentId": "deployment",
            "jobId": canonical_job_id,
            "policyDigest": "sha256:policy",
            "expiresAtMs": deadline,
        });
        let credential: TailscaleRuntimeSshCredentialV1 =
            serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(
            validate_tailscale_binding(&bootstrap, &access, credential)
                .unwrap()
                .as_str(),
            "tskey-auth-secret"
        );
        let mut substituted = raw;
        substituted["jobId"] = serde_json::json!("other-job");
        let credential: TailscaleRuntimeSshCredentialV1 =
            serde_json::from_value(substituted).unwrap();
        assert_eq!(
            validate_tailscale_binding(&bootstrap, &access, credential)
                .unwrap_err()
                .code,
            "access_setup_failed"
        );
    }

    #[test]
    fn managed_v2_compact_and_full_credentials_are_distinct_closed_variants() {
        let compact = serde_json::json!({
            "schema": MANAGED_CREDENTIAL_SCHEMA_V2,
            "provider": {
                "kind": "liskov",
                "connectorToken": "header.payload.signature"
            },
            "attachmentId": "att-1",
            "fence": 7,
            "expiresAtMs": 1_800_000_000_000_u64
        });
        assert!(matches!(
            serde_json::from_value::<RuntimeSshCredentialV1>(compact).unwrap(),
            RuntimeSshCredentialV1::ManagedV1Compact(_)
        ));

        let full = serde_json::json!({
            "schema": MANAGED_CREDENTIAL_SCHEMA_V2,
            "provider": {
                "kind": "liskov",
                "connectorToken": "header.payload.signature",
                "authorizedKeys": [
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                ],
                "toolchain": {
                    "runtimeContactSha256": "1".repeat(64),
                    "dropbearSha256": "2".repeat(64),
                    "dropbearkeySha256": "3".repeat(64)
                }
            },
            "organizationId": "org-1",
            "attachmentId": "att-1",
            "applicationId": "app-1",
            "applicationUid": "app-uid-1",
            "liskovDeploymentId": "dep-1",
            "deploymentId": "provider-dep-1",
            "liskovJobId": "job-1",
            "jobId": "provider-job-1",
            "policyDigest": "sha256:policy",
            "fence": 7,
            "expiresAtMs": 1_800_000_000_000_u64
        });
        assert!(matches!(
            serde_json::from_value::<RuntimeSshCredentialV1>(full).unwrap(),
            RuntimeSshCredentialV1::ManagedV1Full(_)
        ));

        let retired_v0 = serde_json::json!({
            "schema": CREDENTIAL_SCHEMA,
            "provider": {
                "kind": "liskov",
                "connectorToken": "static-token",
                "operatorPublicKey": "ssh-ed25519 retired"
            },
            "organizationId": "org-1",
            "attachmentId": "att-1",
            "applicationUid": "app-uid-1",
            "deploymentId": "provider-dep-1",
            "jobId": "provider-job-1",
            "policyDigest": "sha256:policy",
            "fence": 7,
            "expiresAtMs": 1_800_000_000_000_u64
        });
        assert!(serde_json::from_value::<RuntimeSshCredentialV1>(retired_v0).is_err());
    }

    #[test]
    fn signed_runtime_bootstrap_credential_is_taken_before_workload_launch() {
        let mut bootstrap: RuntimeBootstrapResponse = serde_json::from_value(serde_json::json!({
            "ok": true,
            "domain": "proof.liskov.runtime-bootstrap-response.v2",
            "applicationUid": "app-uid-1",
            "applicationId": "app-1",
            "policyDigest": "sha256:policy",
            "deploymentId": "dep-1",
            "jobId": "job-1",
            "processorId": "processor-1",
            "runtimeInstanceId": "instance-1",
            "slipwayUrl": "https://liskov.example",
            "access": {
                "provider": {"kind": "liskov"},
                "attachmentId": "att-1",
                "fence": 7,
                "gatewayUrl": "wss://gateway.example",
                "tunnelId": "tunnel_1",
                "protocol": "liskov_access_v1",
                "setupDeadlineMs": 1_800_000_000_000_u64,
                "binding": {
                    "organizationId": "org-1",
                    "applicationId": "app-1",
                    "applicationUid": "app-uid-1",
                    "liskovDeploymentId": "dep-1",
                    "deploymentId": "provider-dep-1",
                    "liskovJobId": "job-1",
                    "jobId": "provider-job-1",
                    "policyDigest": "sha256:policy"
                },
                "authorizedKeyFingerprints": [format!(
                    "SHA256:{}",
                    base64::engine::general_purpose::STANDARD_NO_PAD.encode([1_u8; 32])
                )],
                "toolchain": {
                    "runtimeContactSha256": "1".repeat(64),
                    "dropbearSha256": "2".repeat(64),
                    "dropbearkeySha256": "3".repeat(64)
                },
                "credential": {
                    "schema": MANAGED_CREDENTIAL_SCHEMA_V2,
                    "provider": {
                        "kind": "liskov",
                        "connectorToken": "header.payload.signature"
                    },
                    "attachmentId": "att-1",
                    "fence": 7,
                    "expiresAtMs": 1_800_000_000_000_u64
                }
            }
        }))
        .unwrap();

        let raw = take_runtime_access_credential(&mut bootstrap).unwrap();
        let credential: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            credential["provider"]["connectorToken"],
            "header.payload.signature"
        );
        let RuntimeAccessBootstrap::Managed(access) = bootstrap.access.unwrap() else {
            panic!("managed access expected");
        };
        assert!(access.credential.is_none());
    }

    /// The Tailscale credential moves off the Acurast `setEnvironment` handoff
    /// and into the authenticated bootstrap response. The environment variable
    /// stays as a fallback so a server that has not migrated still works, and
    /// it is scrubbed either way.
    #[test]
    fn tailscale_credential_prefers_the_signed_bootstrap_over_the_environment() {
        let _lock = crate::supervisor::tests::PROCESS_TEST_LOCK.lock().unwrap();

        let bootstrap_json = |credential: Option<serde_json::Value>| {
            let mut access = serde_json::json!({
                "provider": {"kind": "tailscale"},
                "attachmentId": "att-1",
                "expectedTailnet": "example.com",
                "setupDeadlineMs": 1_800_000_000_000_u64,
                "fence": 1,
                "artifact": {
                    "descriptorId": "descriptor-1",
                    "version": "1.98.10-liskov.1",
                    "url": "https://liskov.example/client.tgz",
                    "sha256": "1".repeat(64),
                    "byteSize": 10,
                },
            });
            if let Some(credential) = credential {
                access["credential"] = credential;
            }
            serde_json::from_value::<RuntimeBootstrapResponse>(serde_json::json!({
                "ok": true,
                "domain": "proof.liskov.runtime-bootstrap-response.v2",
                "applicationUid": "app-uid",
                "applicationId": "app",
                "policyDigest": "sha256:policy",
                "deploymentId": "deployment",
                "jobId": "job",
                "processorId": "processor",
                "runtimeInstanceId": "instance",
                "slipwayUrl": "https://liskov.example",
                "access": access,
            }))
            .unwrap()
        };

        let signed = serde_json::json!({
            "schema": CREDENTIAL_SCHEMA,
            "provider": {"kind": "tailscale", "authKey": "tskey-auth-from-bootstrap"},
            "organizationId": "org",
            "integrationId": "integration",
            "attachmentId": "att-1",
            "applicationUid": "app-uid",
            "deploymentId": "deployment",
            "jobId": "job",
            "policyDigest": "sha256:policy",
            "expiresAtMs": 1_800_000_000_000_u64,
        });

        // SAFETY: the process lock serializes the env mutation against the
        // other tests that spawn processes or read this variable.
        unsafe {
            std::env::set_var(RUNTIME_SSH_CREDENTIAL_ENV, "from-environment");
        }
        let mut bootstrap = bootstrap_json(Some(signed));
        let raw = take_runtime_access_credential(&mut bootstrap).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed["provider"]["authKey"], "tskey-auth-from-bootstrap");
        assert!(std::env::var(RUNTIME_SSH_CREDENTIAL_ENV).is_err());
        let RuntimeAccessBootstrap::Tailscale(access) = bootstrap.access.unwrap() else {
            panic!("tailscale access expected");
        };
        assert!(access.credential.is_none(), "credential must be moved out");

        // A server still delivering by environment variable keeps working.
        unsafe {
            std::env::set_var(RUNTIME_SSH_CREDENTIAL_ENV, "from-environment");
        }
        let mut bootstrap = bootstrap_json(None);
        assert_eq!(
            take_runtime_access_credential(&mut bootstrap).as_deref(),
            Some("from-environment")
        );
        assert!(std::env::var(RUNTIME_SSH_CREDENTIAL_ENV).is_err());
    }
}
