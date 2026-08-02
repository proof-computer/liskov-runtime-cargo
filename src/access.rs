//! Customer-owned Tailscale adapter for the Runtime SSH private preview.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use flate2::read::GzDecoder;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tar::Archive;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::protocol::{
    RuntimeAccessBootstrap, RuntimeAccessProviderKind, RuntimeBootstrapResponse,
};

pub const RUNTIME_SSH_CREDENTIAL_ENV: &str = "LISKOV_RUNTIME_SSH_CREDENTIAL_V1";
const CREDENTIAL_SCHEMA: &str = "proof.liskov.runtime-ssh-credential.v1";
const MAX_ARTIFACT_BYTES: usize = 128 * 1024 * 1024;
const MAX_BINARY_BYTES: u64 = 96 * 1024 * 1024;
const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
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
struct RuntimeSshCredentialV1 {
    schema: String,
    provider: RuntimeSshCredentialProvider,
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
enum RuntimeSshCredentialProvider {
    Tailscale {
        #[serde(rename = "authKey")]
        auth_key: String,
    },
}

impl Drop for RuntimeSshCredentialProvider {
    fn drop(&mut self) {
        match self {
            Self::Tailscale { auth_key } => auth_key.zeroize(),
        }
    }
}

pub struct AccessSession {
    daemon: Child,
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
        serde_json::json!({
            "attachmentId": self.attachment_id,
            "fence": self.fence,
            "providerKind": "tailscale",
        })
    }

    pub fn ready_attrs(&self) -> serde_json::Value {
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

    pub fn newly_crashed(&mut self) -> bool {
        if self.degraded_reported {
            return false;
        }
        let crashed = self.daemon.try_wait().ok().flatten().is_some();
        if crashed {
            self.degraded_reported = true;
        }
        crashed
    }

    pub fn stop(&mut self) -> Result<(), AccessError> {
        terminate_child(&mut self.daemon)?;
        std::fs::remove_dir_all(&self.root)
            .map_err(|_| AccessError::new("access_cleanup_failed"))?;
        Ok(())
    }
}

impl Drop for AccessSession {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

struct DaemonGuard(Option<Child>);

impl DaemonGuard {
    fn child_mut(&mut self) -> &mut Child {
        self.0.as_mut().expect("daemon guard owns child")
    }

    fn take(mut self) -> Child {
        self.0.take().expect("daemon guard owns child")
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = terminate_child(child);
        }
    }
}

fn terminate_child(child: &mut Child) -> Result<(), AccessError> {
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

pub fn take_environment_credential() -> Option<String> {
    let value = std::env::var(RUNTIME_SSH_CREDENTIAL_ENV).ok();
    // SAFETY: the binary calls this during single-threaded startup, before the
    // diagnostics/logging workers or any customer process are created.
    unsafe {
        std::env::remove_var(RUNTIME_SSH_CREDENTIAL_ENV);
    }
    value
}

pub fn setup_runtime_access(
    bootstrap: &RuntimeBootstrapResponse,
    raw_credential: Option<String>,
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
    let auth_key = validate_binding(bootstrap, access, credential)?;
    let archive = download_artifact(access)?;
    let root = private_root(&access.attachment_id)?;
    let setup = setup_in_root(bootstrap, access, &root, &archive, &auth_key);
    match setup {
        Ok(session) => Ok(Some(session)),
        Err(error) => {
            let _ = std::fs::remove_dir_all(root);
            Err(error)
        }
    }
}

fn validate_binding(
    bootstrap: &RuntimeBootstrapResponse,
    access: &RuntimeAccessBootstrap,
    mut credential: RuntimeSshCredentialV1,
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
        RuntimeSshCredentialProvider::Tailscale { auth_key }
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

fn download_artifact(access: &RuntimeAccessBootstrap) -> Result<Vec<u8>, AccessError> {
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(COMMAND_TIMEOUT)
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

fn private_root(attachment_id: &str) -> Result<PathBuf, AccessError> {
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|_| AccessError::new("access_setup_failed"))?;
    let name = format!(
        "liskov-runtime-ssh-{}-{}",
        &hex::encode(Sha256::digest(attachment_id.as_bytes()))[..16],
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
    access: &RuntimeAccessBootstrap,
    root: &Path,
    archive: &[u8],
    auth_key: &str,
) -> Result<AccessSession, AccessError> {
    let (tailscale, tailscaled) = extract_binaries(archive)?;
    let tailscale_path = root.join("tailscale");
    let tailscaled_path = root.join("tailscaled");
    write_private_file(&tailscale_path, &tailscale, 0o700)?;
    write_private_file(&tailscaled_path, &tailscaled, 0o700)?;
    let auth_path = root.join("auth-key");
    write_private_file(&auth_path, auth_key.as_bytes(), 0o600)?;
    let socket = root.join("tailscaled.sock");
    let state_dir = root.join("state");
    std::fs::create_dir(&state_dir).map_err(|_| AccessError::new("access_setup_failed"))?;
    let mut daemon = DaemonGuard(Some(spawn_daemon(&tailscaled_path, &socket, &state_dir)?));
    let deadline = setup_deadline(access.setup_deadline_ms)?;
    while !socket.exists() {
        if daemon
            .child_mut()
            .try_wait()
            .map_err(|_| AccessError::new("access_sidecar_failed"))?
            .is_some()
            || std::time::Instant::now() >= deadline
        {
            let _ = std::fs::remove_file(&auth_path);
            return Err(AccessError::new("access_sidecar_failed"));
        }
        thread::sleep(POLL_INTERVAL);
    }
    let hostname = runtime_hostname(&bootstrap.application_uid, &bootstrap.deployment_id);
    let auth_argument = format!("file:{}", auth_path.display());
    let up = run_bounded(
        &tailscale_path,
        &[
            OsString::from(format!("--socket={}", socket.display())),
            OsString::from("up"),
            OsString::from(format!("--auth-key={auth_argument}")),
            OsString::from(format!("--hostname={hostname}")),
            OsString::from("--ssh"),
            OsString::from("--accept-dns=false"),
            OsString::from("--accept-routes=false"),
        ],
        deadline,
    );
    std::fs::remove_file(&auth_path).map_err(|_| AccessError::new("access_setup_failed"))?;
    up?;
    let status = run_bounded_capture(
        &tailscale_path,
        &[
            OsString::from(format!("--socket={}", socket.display())),
            OsString::from("status"),
            OsString::from("--json"),
        ],
        deadline,
    )?;
    let status: TailscaleStatus =
        serde_json::from_slice(&status).map_err(|_| AccessError::new("access_setup_failed"))?;
    if status.backend_state != "Running"
        || status.current_tailnet.name != access.expected_tailnet
        || status.self_node.id.is_empty()
        || status.self_node.id.len() > 256
        || status.self_node.dns_name.is_empty()
        || status.self_node.dns_name.len() > 256
    {
        return Err(AccessError::new("access_setup_failed"));
    }
    Ok(AccessSession {
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
            continue;
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

fn spawn_daemon(binary: &Path, socket: &Path, state_dir: &Path) -> Result<Child, AccessError> {
    let mut command = Command::new(binary);
    command
        .arg("--tun=userspace-networking")
        .arg("--state=mem:")
        .arg(format!("--socket={}", socket.display()))
        .arg(format!("--statedir={}", state_dir.display()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: setpgid is async-signal-safe and performs no allocation.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command
        .spawn()
        .map_err(|_| AccessError::new("access_sidecar_failed"))
}

fn run_bounded(
    binary: &Path,
    args: &[OsString],
    deadline: std::time::Instant,
) -> Result<(), AccessError> {
    let output = run_command(binary, args, deadline)?;
    (output.status.success() && !output.output_too_large)
        .then_some(())
        .ok_or_else(|| AccessError::new("access_setup_failed"))
}

fn run_bounded_capture(
    binary: &Path,
    args: &[OsString],
    deadline: std::time::Instant,
) -> Result<Vec<u8>, AccessError> {
    let output = run_command(binary, args, deadline)?;
    if !output.status.success() || output.output_too_large {
        return Err(AccessError::new("access_setup_failed"));
    }
    Ok(output.stdout)
}

struct CommandOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    output_too_large: bool,
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
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| AccessError::new("access_setup_failed"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| AccessError::new("access_setup_failed"))?;
    let reader = thread::spawn(move || -> std::io::Result<(Vec<u8>, bool)> {
        let mut captured = Vec::new();
        let mut too_large = false;
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            let read = stdout.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            let remaining = MAX_COMMAND_OUTPUT_BYTES.saturating_sub(captured.len());
            captured.extend_from_slice(&buffer[..read.min(remaining)]);
            too_large |= read > remaining;
        }
        Ok((captured, too_large))
    });
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| AccessError::new("access_setup_failed"))?
        {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            return Err(AccessError::new("access_setup_failed"));
        }
        thread::sleep(POLL_INTERVAL);
    };
    let (stdout, output_too_large) = reader
        .join()
        .map_err(|_| AccessError::new("access_setup_failed"))?
        .map_err(|_| AccessError::new("access_setup_failed"))?;
    Ok(CommandOutput {
        status,
        stdout,
        output_too_large,
    })
}

fn setup_deadline(deadline_ms: u64) -> Result<std::time::Instant, AccessError> {
    let remaining = deadline_ms
        .checked_sub(unix_time_ms().ok_or_else(|| AccessError::new("access_setup_failed"))?)
        .ok_or_else(|| AccessError::new("access_setup_failed"))?;
    Ok(std::time::Instant::now() + Duration::from_millis(remaining).min(COMMAND_TIMEOUT))
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
    use super::*;
    use crate::protocol::{
        RuntimeAccessArtifact, RuntimeAccessProvider, RuntimeAccessProviderKind,
    };

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
    }

    #[test]
    fn deterministic_hostname_contains_no_customer_identifier() {
        let hostname = runtime_hostname("app-secret-name", "deployment-secret-name");
        assert!(hostname.starts_with("liskov-"));
        assert_eq!(hostname.len(), 23);
        assert!(!hostname.contains("secret"));
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
        let access = RuntimeAccessBootstrap {
            provider: RuntimeAccessProvider {
                kind: RuntimeAccessProviderKind::Tailscale,
            },
            attachment_id: "att-1".into(),
            expected_tailnet: "example.com".into(),
            setup_deadline_ms: deadline,
            fence: 1,
            artifact: RuntimeAccessArtifact {
                descriptor_id: "descriptor-1".into(),
                version: "1.80.3".into(),
                url: "https://pkgs.tailscale.com/stable/client.tgz".into(),
                sha256: "1".repeat(64),
                byte_size: 10,
            },
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
            access: Some(access.clone()),
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
        let credential: RuntimeSshCredentialV1 = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(
            validate_binding(&bootstrap, &access, credential)
                .unwrap()
                .as_str(),
            "tskey-auth-secret"
        );
        let mut substituted = raw;
        substituted["jobId"] = serde_json::json!("other-job");
        let credential: RuntimeSshCredentialV1 = serde_json::from_value(substituted).unwrap();
        assert_eq!(
            validate_binding(&bootstrap, &access, credential)
                .unwrap_err()
                .code,
            "access_setup_failed"
        );
    }
}
