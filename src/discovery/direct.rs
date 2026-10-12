//! Opt-in direct IPv6 discovery, independent of the legacy Tailscale directory.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use super::MAX_DISCOVERY_BYTES;
mod private_parent;

pub const ADVERTISEMENT_FILE_ENV: &str = "LISKOV_PEER_ADVERTISEMENT_FILE";
pub const DIRECTORY_FILE_ENV: &str = "LISKOV_PEER_DIRECTORY_FILE";
pub const MAX_ADVERTISEMENT_BYTES: usize = 4 * 1024;
const MAX_PEERS: usize = 256;
const MAX_SNAPSHOT_LIFETIME_MS: i64 = 90_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryFailure {
    Unavailable,
    Invalid,
    Stale,
    Oversized,
    Unsupported,
}
impl DiscoveryFailure {
    pub fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Invalid => "invalid",
            Self::Stale => "stale",
            Self::Oversized => "oversized",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvertisementFailure {
    Invalid,
    Oversized,
    Symlink,
    Conflict,
}
impl AdvertisementFailure {
    pub fn code(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::Oversized => "oversized",
            Self::Symlink => "symlink",
            Self::Conflict => "conflict",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    None,
    Direct { generation: u64 },
    ErrorOnly { generation: u64 },
}

struct State {
    generation: u64,
    child_active: bool,
    // Existing v1 freshness semantics: server observedAtMs, not local receipt.
    last_success_at_ms: i64,
    valid_until_ms: Option<i64>,
    failure: Option<DiscoveryFailure>,
}

pub struct DirectPeerDiscovery {
    root: PathBuf,
    custody: private_parent::Directory,
    application_uid: String,
    job_id: String,
    runtime_instance_id: String,
    legacy_mode: bool,
    state: Mutex<State>,
}

impl DirectPeerDiscovery {
    pub fn create(
        parent: &Path,
        application_uid: &str,
        job_id: &str,
        runtime_instance_id: &str,
        legacy_mode: bool,
    ) -> io::Result<Self> {
        let parent_guard = private_parent::Parent::open(parent)?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        let custody =
            parent_guard.allocate(&format!("liskov-direct-peer-{}", hex::encode(random)))?;
        let root = custody.path();
        Ok(Self {
            root,
            custody,
            application_uid: application_uid.into(),
            job_id: job_id.into(),
            runtime_instance_id: runtime_instance_id.into(),
            legacy_mode,
            state: Mutex::new(State {
                generation: 0,
                child_active: false,
                last_success_at_ms: 0,
                valid_until_ms: None,
                failure: None,
            }),
        })
    }

    pub fn advertisement_path(&self) -> PathBuf {
        self.root.join("advertisement.json")
    }

    pub fn directory_path(&self) -> PathBuf {
        self.root.join("directory.json")
    }

    /// A new child must establish a fresh advertisement. A previous process's
    /// file can never renew a lease after a supervised restart.
    pub fn begin_child(&self) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        state.child_active = false;
        state.generation = state.generation.wrapping_add(1);
        self.custody.remove("advertisement.json")?;
        self.custody.remove("directory.json")?;
        state.last_success_at_ms = 0;
        state.valid_until_ms = None;
        state.failure = None;
        state.child_active = true;
        Ok(())
    }

    pub fn end_child(&self) {
        let mut state = self.state.lock().unwrap();
        state.child_active = false;
        state.generation = state.generation.wrapping_add(1);
        // Do not permit an old process's input to be read on a future beat.
        let _ = self.custody.remove("advertisement.json");
    }

    pub fn request_attrs(&self, attrs: &mut Value) -> Request {
        let now_ms = unix_time_ms();
        let state = self.state.lock().unwrap();
        if !state.child_active {
            return Request::None;
        }
        let ad = if self.legacy_mode {
            // Authenticated v1 intent cannot be promoted to v2 by an I/O
            // refusal or by a race removing/replacing its local file.
            match self.custody.exists("advertisement.json") {
                Ok(false) => Ok(None),
                Ok(true) | Err(_) => Err(AdvertisementFailure::Conflict),
            }
        } else {
            read_opened_advertisement(self.custody.read("advertisement.json"), now_ms).and_then(
                |ad| {
                    self.custody
                        .validate()
                        .map_err(|_| AdvertisementFailure::Invalid)?;
                    Ok(ad)
                },
            )
        };
        if !attrs.is_object() {
            *attrs = json!({});
        }
        match ad {
            Ok(Some(ad)) => {
                let failure = if state.valid_until_ms.is_some_and(|until| until <= now_ms) {
                    Some(DiscoveryFailure::Stale)
                } else {
                    state.failure
                };
                attrs["discoveryVersion"] = 2.into();
                attrs["peerService"] = ad.service.into();
                attrs["peerPort"] = ad.port.into();
                attrs["peerTlsFingerprint"] = ad.tls_fingerprint.into();
                attrs["peerReady"] = ad.ready.into();
                if let Some(at) = ad.peer_sync_last_success_at_ms {
                    attrs["peerSyncLastSuccessAtMs"] = at.into();
                }
                if let Some(code) = ad.peer_sync_failure_code {
                    attrs["peerSyncFailureCode"] = code.into();
                }
                if state.last_success_at_ms > 0 {
                    attrs["discoveryLastSuccessAtMs"] = state.last_success_at_ms.into();
                }
                attrs["discoveryRefreshFailed"] = failure.is_some().into();
                if let Some(failure) = failure {
                    attrs["discoveryFailureCode"] = failure.code().into();
                }
                if let Some(expiry) = state
                    .valid_until_ms
                    .filter(|until| *until > now_ms && *until - now_ms <= MAX_SNAPSHOT_LIFETIME_MS)
                {
                    attrs["discoveryValidUntilMs"] = expiry.into();
                }
                Request::Direct {
                    generation: state.generation,
                }
            }
            Ok(None) => {
                // A missing file is normal until a child opts in. Once a
                // previously advertised child removes it, its lease expires
                // server-side; the helper never replays the old attrs.
                Request::None
            }
            Err(failure) => {
                attrs["peerAdvertisementError"] = failure.code().into();
                if failure == AdvertisementFailure::Conflict {
                    // A Tailscale publication keeps the v1 request shape.
                    Request::None
                } else {
                    // A refused local file is still a typed v2 health beat.
                    // It has no endpoint scalars and may only receive a v2
                    // unavailable response, never a complete directory.
                    attrs["discoveryVersion"] = 2.into();
                    Request::ErrorOnly {
                        generation: state.generation,
                    }
                }
            }
        }
    }

    pub fn unavailable(&self, request: Request) {
        self.set_failure(request, DiscoveryFailure::Unavailable);
    }

    pub fn set_failure(&self, request: Request, failure: DiscoveryFailure) {
        let generation = match request {
            Request::None => return,
            Request::Direct { generation } | Request::ErrorOnly { generation } => generation,
        };
        let mut state = self.state.lock().unwrap();
        if state.child_active && state.generation == generation {
            state.failure = Some(failure);
        }
    }

    pub fn accept_response(&self, request: Request, body: &[u8]) -> Result<(), DiscoveryFailure> {
        let (generation, allow_directory) = match request {
            Request::None => return Ok(()),
            Request::Direct { generation } => (generation, true),
            Request::ErrorOnly { generation } => (generation, false),
        };
        let now_ms = unix_time_ms();
        let result = self.validate_and_write(generation, body, now_ms, allow_directory);
        if let Err(failure) = result {
            self.set_failure(request, failure);
        }
        result
    }

    fn validate_and_write(
        &self,
        generation: u64,
        body: &[u8],
        now_ms: i64,
        allow_directory: bool,
    ) -> Result<(), DiscoveryFailure> {
        if body.len() > MAX_DISCOVERY_BYTES + 16 * 1024 {
            return Err(DiscoveryFailure::Oversized);
        }
        let response: Value =
            serde_json::from_slice(body).map_err(|_| DiscoveryFailure::Invalid)?;
        let accepted = response["ok"].as_bool().ok_or(DiscoveryFailure::Invalid)?;
        if !accepted {
            return Err(DiscoveryFailure::Unavailable);
        }
        let snapshot = response
            .get("discovery")
            .ok_or(DiscoveryFailure::Unsupported)?;
        if snapshot.is_null() {
            return Err(DiscoveryFailure::Unsupported);
        }
        if snapshot["schema"] == "liskov.discovery.v2" && snapshot["status"] == "unavailable" {
            if !exact_keys(snapshot, &["schema", "status", "reason"]) {
                return Err(DiscoveryFailure::Invalid);
            }
            return Err(match snapshot["reason"].as_str() {
                Some("unsupported") => DiscoveryFailure::Unsupported,
                Some("invalid") => DiscoveryFailure::Invalid,
                Some("stale") => DiscoveryFailure::Stale,
                Some("overflow") => DiscoveryFailure::Oversized,
                Some("no_ipv6" | "store_unavailable") => DiscoveryFailure::Unavailable,
                _ => DiscoveryFailure::Invalid,
            });
        }
        if !allow_directory {
            // A refused local advertisement cannot turn a server mistake (or
            // delayed response) into a successful empty or populated file.
            return Err(DiscoveryFailure::Invalid);
        }
        let (observed, expiry) = validate_snapshot(
            snapshot,
            &self.application_uid,
            &self.job_id,
            &self.runtime_instance_id,
            now_ms,
        )?;
        let bytes = serialize_directory(snapshot)?;
        if bytes.len() > MAX_DISCOVERY_BYTES {
            return Err(DiscoveryFailure::Oversized);
        }
        let written = (|| -> io::Result<()> {
            let mut file = self.custody.create("next-direct.json")?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            Ok(())
        })();
        if written.is_err() {
            let _ = self.custody.remove("next-direct.json");
            return Err(DiscoveryFailure::Unavailable);
        }
        let mut state = self.state.lock().unwrap();
        let verdict = if !state.child_active
            || state.generation != generation
            || observed <= state.last_success_at_ms
        {
            Err(DiscoveryFailure::Stale)
        } else {
            self.custody
                .rename("next-direct.json", "directory.json")
                .map_err(|_| DiscoveryFailure::Unavailable)?;
            state.last_success_at_ms = observed;
            state.valid_until_ms = Some(expiry);
            state.failure = None;
            Ok(())
        };
        if verdict.is_err() {
            let _ = self.custody.remove("next-direct.json");
        }
        verdict
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Advertisement {
    schema: String,
    service: String,
    port: u16,
    ready: bool,
    tls_fingerprint: String,
    #[serde(default)]
    peer_sync_last_success_at_ms: Option<i64>,
    #[serde(default)]
    peer_sync_failure_code: Option<String>,
}

#[cfg(test)]
fn read_advertisement(
    path: &Path,
    now_ms: i64,
) -> Result<Option<Advertisement>, AdvertisementFailure> {
    use std::os::unix::fs::OpenOptionsExt;
    read_opened_advertisement(
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path),
        now_ms,
    )
}
fn read_opened_advertisement(
    opened: io::Result<File>,
    now_ms: i64,
) -> Result<Option<Advertisement>, AdvertisementFailure> {
    let file = match opened {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(AdvertisementFailure::Symlink);
        }
        Err(_) => return Err(AdvertisementFailure::Invalid),
    };
    let metadata = file.metadata().map_err(|_| AdvertisementFailure::Invalid)?;
    if !metadata.file_type().is_file() {
        return Err(AdvertisementFailure::Invalid);
    }
    if metadata.len() > MAX_ADVERTISEMENT_BYTES as u64 {
        return Err(AdvertisementFailure::Oversized);
    }
    let mut bytes = Vec::new();
    file.take((MAX_ADVERTISEMENT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| AdvertisementFailure::Invalid)?;
    if bytes.len() > MAX_ADVERTISEMENT_BYTES {
        return Err(AdvertisementFailure::Oversized);
    }
    let ad: Advertisement =
        serde_json::from_slice(&bytes).map_err(|_| AdvertisementFailure::Invalid)?;
    if ad.schema != "liskov.peer-advertisement.v2"
        || !valid_service(&ad.service)
        || !(1024..=65535).contains(&ad.port)
        || !valid_fingerprint(&ad.tls_fingerprint)
        || ad
            .peer_sync_last_success_at_ms
            .is_some_and(|at| at <= 0 || at > now_ms)
        || ad.peer_sync_failure_code.as_deref().is_some_and(|code| {
            !matches!(
                code,
                "none" | "connect" | "tls" | "auth" | "identity" | "exchange" | "discovery"
            )
        })
    {
        return Err(AdvertisementFailure::Invalid);
    }
    Ok(Some(ad))
}

fn valid_service(service: &str) -> bool {
    (1..=32).contains(&service.len())
        && service.as_bytes()[0].is_ascii_lowercase()
        && service
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_fingerprint(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn valid_text(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|text| !text.is_empty() && text.len() <= 512)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PeerRevision<'a> {
    job_id: &'a str,
    runtime_instance_id: &'a str,
    service: &'a str,
    provider: &'static str,
    url: &'a str,
    tls_fingerprint: &'a str,
    observed_at_ms: i64,
    valid_until_ms: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DirectorySelf<'a> {
    job_id: &'a str,
    runtime_instance_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DirectorySnapshot<'a> {
    schema: &'static str,
    application_uid: &'a str,
    #[serde(rename = "self")]
    caller: DirectorySelf<'a>,
    revision: &'a str,
    observed_at_ms: i64,
    valid_until_ms: i64,
    peers: Vec<PeerRevision<'a>>,
}

/// Serialize in the owner's typed field order so the file is byte-compatible
/// with the published v2 fixture, independent of response key order.
fn serialize_directory(snapshot: &Value) -> Result<Vec<u8>, DiscoveryFailure> {
    let peers = snapshot["peers"]
        .as_array()
        .ok_or(DiscoveryFailure::Invalid)?
        .iter()
        .map(|peer| PeerRevision {
            job_id: peer["jobId"].as_str().unwrap(),
            runtime_instance_id: peer["runtimeInstanceId"].as_str().unwrap(),
            service: peer["service"].as_str().unwrap(),
            provider: "direct_ipv6",
            url: peer["url"].as_str().unwrap(),
            tls_fingerprint: peer["tlsFingerprint"].as_str().unwrap(),
            observed_at_ms: peer["observedAtMs"].as_i64().unwrap(),
            valid_until_ms: peer["validUntilMs"].as_i64().unwrap(),
        })
        .collect();
    let typed = DirectorySnapshot {
        schema: "liskov.discovery.v2",
        application_uid: snapshot["applicationUid"].as_str().unwrap(),
        caller: DirectorySelf {
            job_id: snapshot["self"]["jobId"].as_str().unwrap(),
            runtime_instance_id: snapshot["self"]["runtimeInstanceId"].as_str().unwrap(),
        },
        revision: snapshot["revision"].as_str().unwrap(),
        observed_at_ms: snapshot["observedAtMs"].as_i64().unwrap(),
        valid_until_ms: snapshot["validUntilMs"].as_i64().unwrap(),
        peers,
    };
    let mut bytes = serde_json::to_vec(&typed).map_err(|_| DiscoveryFailure::Invalid)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn global_unicast_ipv6(address: std::net::Ipv6Addr) -> bool {
    let octets = address.octets();
    (octets[0] & 0xe0) == 0x20 && address.segments()[0..2] != [0x2001, 0x0db8]
}

fn exact_keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
    })
}

fn validate_snapshot(
    snapshot: &Value,
    application_uid: &str,
    job_id: &str,
    runtime_instance_id: &str,
    now_ms: i64,
) -> Result<(i64, i64), DiscoveryFailure> {
    if snapshot["schema"] != "liskov.discovery.v2" {
        return Err(DiscoveryFailure::Unsupported);
    }
    if !exact_keys(
        snapshot,
        &[
            "schema",
            "applicationUid",
            "self",
            "revision",
            "observedAtMs",
            "validUntilMs",
            "peers",
        ],
    ) || !exact_keys(&snapshot["self"], &["jobId", "runtimeInstanceId"])
        || snapshot["applicationUid"] != application_uid
        || snapshot["self"]["jobId"] != job_id
        || snapshot["self"]["runtimeInstanceId"] != runtime_instance_id
        || !valid_text(&snapshot["revision"])
    {
        return Err(DiscoveryFailure::Invalid);
    }
    let observed = snapshot["observedAtMs"]
        .as_i64()
        .ok_or(DiscoveryFailure::Invalid)?;
    let expiry = snapshot["validUntilMs"]
        .as_i64()
        .ok_or(DiscoveryFailure::Invalid)?;
    if observed <= 0 || observed > now_ms + 5_000 || expiry <= now_ms {
        return Err(DiscoveryFailure::Stale);
    }
    if expiry <= observed || expiry > observed.saturating_add(MAX_SNAPSHOT_LIFETIME_MS) {
        return Err(DiscoveryFailure::Invalid);
    }
    let peers = snapshot["peers"]
        .as_array()
        .ok_or(DiscoveryFailure::Invalid)?;
    if peers.len() > MAX_PEERS {
        return Err(DiscoveryFailure::Oversized);
    }
    let mut jobs = BTreeSet::new();
    let mut runtimes = BTreeSet::new();
    let mut revision_peers = Vec::with_capacity(peers.len());
    for peer in peers {
        if !exact_keys(
            peer,
            &[
                "jobId",
                "runtimeInstanceId",
                "service",
                "provider",
                "url",
                "tlsFingerprint",
                "observedAtMs",
                "validUntilMs",
            ],
        ) || !valid_text(&peer["jobId"])
            || !valid_text(&peer["runtimeInstanceId"])
            || !peer["service"].as_str().is_some_and(valid_service)
            || peer["provider"] != "direct_ipv6"
            || !peer["tlsFingerprint"]
                .as_str()
                .is_some_and(valid_fingerprint)
            || peer["jobId"] == job_id
            || peer["runtimeInstanceId"] == runtime_instance_id
        {
            return Err(DiscoveryFailure::Invalid);
        }
        if !jobs.insert(peer["jobId"].as_str().unwrap())
            || !runtimes.insert(peer["runtimeInstanceId"].as_str().unwrap())
        {
            return Err(DiscoveryFailure::Invalid);
        }
        let peer_observed = peer["observedAtMs"]
            .as_i64()
            .ok_or(DiscoveryFailure::Invalid)?;
        let peer_expiry = peer["validUntilMs"]
            .as_i64()
            .ok_or(DiscoveryFailure::Invalid)?;
        if peer_observed <= 0
            || peer_observed > observed
            || peer_observed > now_ms + 5_000
            || peer_expiry <= now_ms
        {
            return Err(DiscoveryFailure::Stale);
        }
        if peer_expiry <= peer_observed
            || peer_expiry > peer_observed.saturating_add(MAX_SNAPSHOT_LIFETIME_MS)
            || peer_expiry > expiry
        {
            return Err(DiscoveryFailure::Invalid);
        }
        let raw = peer["url"].as_str().ok_or(DiscoveryFailure::Invalid)?;
        let url = url::Url::parse(raw).map_err(|_| DiscoveryFailure::Invalid)?;
        let address = match url.host() {
            Some(url::Host::Ipv6(address)) => address,
            _ => return Err(DiscoveryFailure::Invalid),
        };
        if url.scheme() != "https"
            || !global_unicast_ipv6(address)
            || url.port().is_none_or(|port| port < 1024)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || raw != format!("https://[{address}]:{}/", url.port().unwrap())
        {
            return Err(DiscoveryFailure::Invalid);
        }
        revision_peers.push(PeerRevision {
            job_id: peer["jobId"].as_str().unwrap(),
            runtime_instance_id: peer["runtimeInstanceId"].as_str().unwrap(),
            service: peer["service"].as_str().unwrap(),
            provider: "direct_ipv6",
            url: raw,
            tls_fingerprint: peer["tlsFingerprint"].as_str().unwrap(),
            observed_at_ms: peer_observed,
            valid_until_ms: peer_expiry,
        });
    }
    let revision_bytes =
        serde_json::to_vec(&revision_peers).map_err(|_| DiscoveryFailure::Invalid)?;
    let expected_revision = format!("sha256:{}", hex::encode(Sha256::digest(revision_bytes)));
    if snapshot["revision"] != expected_revision {
        return Err(DiscoveryFailure::Invalid);
    }
    Ok((observed, expiry))
}

fn unix_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
fn remove_if_present(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn replaced_parent_or_leaf_cannot_redirect_reads_writes_or_cleanup() {
        for replace_parent in [false, true] {
            let mut random = [0u8; 16];
            getrandom::fill(&mut random).unwrap();
            let parent = std::env::temp_dir().join(format!("11fh-custody-{}", hex::encode(random)));
            fs::create_dir(&parent).unwrap();
            let file =
                DirectPeerDiscovery::create(&parent, "app", "self", "incarnation", false).unwrap();
            file.begin_child().unwrap();
            write_advertisement(&file, &advertisement());
            let request = file.request_attrs(&mut json!({}));
            assert!(matches!(request, Request::Direct { .. }));
            let original = if replace_parent {
                parent.clone()
            } else {
                file.root.clone()
            };
            let moved = original.with_extension("moved");
            fs::rename(&original, &moved).unwrap();
            fs::create_dir(&original).unwrap();
            if replace_parent {
                fs::create_dir(&file.root).unwrap();
            }
            let foreign = file.root.clone();
            fs::write(foreign.join("sentinel"), b"foreign").unwrap();
            fs::write(
                foreign.join("advertisement.json"),
                serde_json::to_vec(&advertisement()).unwrap(),
            )
            .unwrap();
            let mut attrs = json!({});
            assert!(matches!(
                file.request_attrs(&mut attrs),
                Request::ErrorOnly { .. }
            ));
            assert!(attrs.get("peerPort").is_none());
            assert_eq!(
                file.accept_response(
                    request,
                    &serde_json::to_vec(&json!({"ok":true,"discovery":snapshot(unix_time_ms())}))
                        .unwrap()
                ),
                Err(DiscoveryFailure::Unavailable)
            );
            assert!(!foreign.join("directory.json").exists());
            assert!(!foreign.join("next-direct.json").exists());
            assert!(file.begin_child().is_err());
            drop(file);
            assert_eq!(fs::read(foreign.join("sentinel")).unwrap(), b"foreign");
            assert!(foreign.join("advertisement.json").is_file());
            fs::remove_dir_all(&parent).unwrap();
            if moved.exists() {
                fs::remove_dir_all(&moved).unwrap();
            }
        }
    }

    #[test]
    fn legacy_intent_never_becomes_v2_when_parent_or_leaf_is_substituted() {
        for replace_parent in [false, true] {
            let mut random = [0u8; 16];
            getrandom::fill(&mut random).unwrap();
            let parent = std::env::temp_dir().join(format!("11fh-legacy-{}", hex::encode(random)));
            fs::create_dir(&parent).unwrap();
            let file =
                DirectPeerDiscovery::create(&parent, "app", "self", "incarnation", true).unwrap();
            file.begin_child().unwrap();
            write_advertisement(&file, &advertisement());
            let original = if replace_parent {
                parent.clone()
            } else {
                file.root.clone()
            };
            let moved = original.with_extension("moved");
            fs::rename(&original, &moved).unwrap();
            fs::create_dir(&original).unwrap();
            let mut attrs = json!({"discoveryVersion":1});
            assert_eq!(file.request_attrs(&mut attrs), Request::None);
            assert_eq!(attrs["peerAdvertisementError"], "conflict");
            assert_eq!(attrs["discoveryVersion"], 1);
            assert!(attrs.get("peerPort").is_none());
            drop(file);
            fs::remove_dir_all(&parent).unwrap();
            if moved.exists() {
                fs::remove_dir_all(&moved).unwrap();
            }
        }
    }

    #[test]
    fn privacy_mode_changes_refuse_advertisements_and_lease_refresh() {
        let file = file(false);
        file.begin_child().unwrap();
        write_advertisement(&file, &advertisement());
        let request = file.request_attrs(&mut json!({}));
        fs::set_permissions(&file.root, fs::Permissions::from_mode(0o777)).unwrap();
        let mut attrs = json!({});
        assert!(matches!(
            file.request_attrs(&mut attrs),
            Request::ErrorOnly { .. }
        ));
        assert!(attrs.get("peerPort").is_none());
        assert_eq!(
            file.accept_response(
                request,
                &serde_json::to_vec(&json!({"ok":true,"discovery":snapshot(unix_time_ms())}))
                    .unwrap()
            ),
            Err(DiscoveryFailure::Unavailable)
        );
        assert!(!file.directory_path().exists());
        fs::set_permissions(&file.root, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn file(legacy: bool) -> DirectPeerDiscovery {
        DirectPeerDiscovery::create(&std::env::temp_dir(), "app", "self", "incarnation", legacy)
            .unwrap()
    }

    fn advertisement() -> Value {
        json!({
            "schema": "liskov.peer-advertisement.v2",
            "service": "sync",
            "port": 8841,
            "ready": true,
            "tlsFingerprint": format!("sha256:{}", "a".repeat(64)),
            "peerSyncFailureCode": "none",
        })
    }

    fn write_advertisement(file: &DirectPeerDiscovery, ad: &Value) {
        fs::write(file.advertisement_path(), serde_json::to_vec(ad).unwrap()).unwrap();
    }

    fn snapshot(now: i64) -> Value {
        let mut snapshot = json!({
            "schema": "liskov.discovery.v2",
            "applicationUid": "app",
            "self": {"jobId": "self", "runtimeInstanceId": "incarnation"},
            "revision": "",
            "observedAtMs": now,
            "validUntilMs": now + 30_000,
            "peers": [{
                "jobId": "other",
                "runtimeInstanceId": "other-incarnation",
                "service": "sync",
                "provider": "direct_ipv6",
                "url": "https://[2606:4700:4700::1111]:8841/",
                "tlsFingerprint": format!("sha256:{}", "b".repeat(64)),
                "observedAtMs": now,
                "validUntilMs": now + 30_000
            }]
        });
        set_revision(&mut snapshot);
        snapshot
    }

    fn set_revision(snapshot: &mut Value) {
        let peers: Vec<_> = snapshot["peers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|peer| PeerRevision {
                job_id: peer["jobId"].as_str().unwrap(),
                runtime_instance_id: peer["runtimeInstanceId"].as_str().unwrap(),
                service: peer["service"].as_str().unwrap(),
                provider: "direct_ipv6",
                url: peer["url"].as_str().unwrap(),
                tls_fingerprint: peer["tlsFingerprint"].as_str().unwrap(),
                observed_at_ms: peer["observedAtMs"].as_i64().unwrap(),
                valid_until_ms: peer["validUntilMs"].as_i64().unwrap(),
            })
            .collect();
        let bytes = serde_json::to_vec(&peers).unwrap();
        snapshot["revision"] = format!("sha256:{}", hex::encode(Sha256::digest(bytes))).into();
    }

    #[test]
    fn absent_file_never_opts_in_and_valid_file_supplies_only_scalar_attrs() {
        let file = file(false);
        file.begin_child().unwrap();
        let mut attrs = json!({"processAttempt": 0});
        assert_eq!(file.request_attrs(&mut attrs), Request::None);
        assert_eq!(attrs, json!({"processAttempt": 0}));

        write_advertisement(&file, &advertisement());
        let request = file.request_attrs(&mut attrs);
        assert!(matches!(request, Request::Direct { .. }));
        assert_eq!(attrs["discoveryVersion"], 2);
        assert_eq!(attrs["peerService"], "sync");
        assert_eq!(attrs["peerPort"], 8841);
        assert_eq!(attrs["peerReady"], true);
        assert_eq!(attrs["peerSyncFailureCode"], "none");
        assert_eq!(
            attrs["peerTlsFingerprint"],
            advertisement()["tlsFingerprint"]
        );
        assert!(attrs.get("discoveryLastSuccessAtMs").is_none());
        assert!(attrs.get("discoveryFailureCode").is_none());
        assert_eq!(attrs.as_object().unwrap().len(), 8);
        assert!(attrs.to_string().len() < 4096);
    }

    #[test]
    fn malformed_oversized_symlinked_and_secret_bearing_inputs_are_refused() {
        let file = file(false);
        file.begin_child().unwrap();
        for (ad, code) in [
            (json!({"schema": "liskov.peer-advertisement.v2"}), "invalid"),
            (
                {
                    let mut ad = advertisement();
                    ad["privateKey"] = "secret".into();
                    ad
                },
                "invalid",
            ),
            (
                {
                    let mut ad = advertisement();
                    ad["tlsFingerprint"] = "not-a-fingerprint".into();
                    ad
                },
                "invalid",
            ),
        ] {
            write_advertisement(&file, &ad);
            let mut attrs = json!({});
            assert!(matches!(
                file.request_attrs(&mut attrs),
                Request::ErrorOnly { .. }
            ));
            assert_eq!(attrs["discoveryVersion"], 2);
            assert_eq!(attrs["peerAdvertisementError"], code);
            assert_eq!(attrs.as_object().unwrap().len(), 2);
        }
        fs::write(
            file.advertisement_path(),
            vec![b'x'; MAX_ADVERTISEMENT_BYTES + 1],
        )
        .unwrap();
        let mut attrs = json!({});
        assert!(matches!(
            file.request_attrs(&mut attrs),
            Request::ErrorOnly { .. }
        ));
        assert_eq!(attrs["discoveryVersion"], 2);
        assert_eq!(attrs["peerAdvertisementError"], "oversized");
        remove_if_present(&file.advertisement_path()).unwrap();
        symlink("/etc/passwd", file.advertisement_path()).unwrap();
        let mut attrs = json!({});
        assert!(matches!(
            file.request_attrs(&mut attrs),
            Request::ErrorOnly { .. }
        ));
        assert_eq!(attrs["discoveryVersion"], 2);
        assert_eq!(attrs["peerAdvertisementError"], "symlink");
        remove_if_present(&file.advertisement_path()).unwrap();
        let path = CString::new(file.advertisement_path().as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let mut attrs = json!({});
        assert!(matches!(
            file.request_attrs(&mut attrs),
            Request::ErrorOnly { .. }
        ));
        assert_eq!(attrs["discoveryVersion"], 2);
        assert_eq!(attrs["peerAdvertisementError"], "invalid");
    }

    #[test]
    fn v1_mode_wins_explicit_conflict_without_direct_attrs() {
        let file = file(true);
        file.begin_child().unwrap();
        write_advertisement(&file, &advertisement());
        let mut attrs = json!({
            "discoveryVersion": 1,
            "discoveryLastSuccessAtMs": 0,
            "discoveryRefreshFailed": false
        });
        assert_eq!(file.request_attrs(&mut attrs), Request::None);
        assert_eq!(attrs["discoveryVersion"], 1);
        assert_eq!(attrs["peerAdvertisementError"], "conflict");
        assert_eq!(attrs["discoveryLastSuccessAtMs"], 0);
        assert_eq!(attrs["discoveryRefreshFailed"], false);
        assert!(attrs.get("peerService").is_none());
        fs::write(file.advertisement_path(), b"{").unwrap();
        let mut attrs = json!({"discoveryVersion": 1});
        assert_eq!(file.request_attrs(&mut attrs), Request::None);
        assert_eq!(attrs["peerAdvertisementError"], "conflict");
    }

    #[test]
    fn error_only_v2_accepts_unavailable_but_never_writes_or_renews_a_directory() {
        let file = file(false);
        file.begin_child().unwrap();
        write_advertisement(&file, &advertisement());
        let mut attrs = json!({});
        let ready_request = file.request_attrs(&mut attrs);
        let observed = unix_time_ms();
        let good = json!({"ok": true, "discovery": snapshot(observed)});
        file.accept_response(ready_request, &serde_json::to_vec(&good).unwrap())
            .unwrap();
        let original = fs::read(file.directory_path()).unwrap();
        let original_expiry = file.state.lock().unwrap().valid_until_ms;

        fs::write(file.advertisement_path(), b"{").unwrap();
        let mut attrs = json!({"processAttempt": 1, "restartCount": 0});
        let request = file.request_attrs(&mut attrs);
        assert!(matches!(request, Request::ErrorOnly { .. }));
        assert_eq!(
            attrs,
            json!({
                "processAttempt": 1,
                "restartCount": 0,
                "discoveryVersion": 2,
                "peerAdvertisementError": "invalid"
            })
        );
        assert_eq!(
            file.accept_response(request, br#"{"ok":true}"#),
            Err(DiscoveryFailure::Unsupported),
            "an old server does not turn a refusal into a successful directory"
        );
        assert_eq!(fs::read(file.directory_path()).unwrap(), original);
        assert_eq!(file.state.lock().unwrap().valid_until_ms, original_expiry);
        assert_eq!(
            file.state.lock().unwrap().failure,
            Some(DiscoveryFailure::Unsupported)
        );
        let mut retry_attrs = json!({"processAttempt": 1, "restartCount": 0});
        assert!(matches!(
            file.request_attrs(&mut retry_attrs),
            Request::ErrorOnly { .. }
        ));
        assert_eq!(retry_attrs, attrs);
        let unavailable = json!({"ok": true, "discovery": {
            "schema": "liskov.discovery.v2", "status": "unavailable", "reason": "invalid"
        }});
        assert_eq!(
            file.accept_response(request, &serde_json::to_vec(&unavailable).unwrap()),
            Err(DiscoveryFailure::Invalid)
        );
        assert_eq!(fs::read(file.directory_path()).unwrap(), original);
        assert_eq!(file.state.lock().unwrap().valid_until_ms, original_expiry);

        let mut empty = good;
        empty["discovery"]["peers"] = json!([]);
        set_revision(&mut empty["discovery"]);
        empty["discovery"]["observedAtMs"] = (observed + 1).into();
        assert_eq!(
            file.accept_response(request, &serde_json::to_vec(&empty).unwrap()),
            Err(DiscoveryFailure::Invalid),
            "error-only cannot turn a server mistake into complete-empty"
        );
        assert_eq!(fs::read(file.directory_path()).unwrap(), original);
        assert_eq!(file.state.lock().unwrap().valid_until_ms, original_expiry);

        file.end_child();
        file.begin_child().unwrap();
        assert!(!file.directory_path().exists());
        assert_eq!(
            file.accept_response(request, &serde_json::to_vec(&unavailable).unwrap()),
            Err(DiscoveryFailure::Invalid)
        );
        assert!(file.state.lock().unwrap().failure.is_none());
        let mut after_restart = json!({"processAttempt": 0, "restartCount": 1});
        assert_eq!(file.request_attrs(&mut after_restart), Request::None);
        assert_eq!(after_restart.as_object().unwrap().len(), 2);
    }

    #[test]
    fn v2_file_is_atomic_and_preserves_last_good_lease_on_failures() {
        let file = file(false);
        file.begin_child().unwrap();
        write_advertisement(&file, &advertisement());
        let mut attrs = json!({});
        let request = file.request_attrs(&mut attrs);
        let now = unix_time_ms();
        assert_eq!(
            file.accept_response(request, b"[]"),
            Err(DiscoveryFailure::Invalid)
        );
        assert!(!file.directory_path().exists());
        let old_server = json!({"ok": true});
        assert_eq!(
            file.accept_response(request, &serde_json::to_vec(&old_server).unwrap()),
            Err(DiscoveryFailure::Unsupported)
        );
        assert!(
            !file.directory_path().exists(),
            "an old server cannot manufacture a complete empty directory"
        );
        let good = json!({"ok": true, "discovery": snapshot(now)});
        file.accept_response(request, &serde_json::to_vec(&good).unwrap())
            .unwrap();
        let original = fs::read(file.directory_path()).unwrap();
        let metadata = fs::metadata(file.directory_path()).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        assert_eq!(
            file.accept_response(request, &serde_json::to_vec(&old_server).unwrap()),
            Err(DiscoveryFailure::Unsupported)
        );
        let mut attrs = json!({});
        file.request_attrs(&mut attrs);
        assert_eq!(attrs["discoveryLastSuccessAtMs"], now);
        assert_eq!(attrs["discoveryFailureCode"], "unsupported");
        assert_eq!(attrs["discoveryValidUntilMs"], now + 30_000);
        assert_eq!(fs::read(file.directory_path()).unwrap(), original);

        let unavailable: Value = serde_json::from_str(include_str!(
            "../../vectors/liskov-discovery-v2-unavailable.json"
        ))
        .unwrap();
        assert_eq!(
            file.accept_response(
                request,
                &serde_json::to_vec(&json!({"ok": true, "discovery": unavailable})).unwrap()
            ),
            Err(DiscoveryFailure::Unavailable)
        );
        assert_eq!(fs::read(file.directory_path()).unwrap(), original);
        for (reason, expected) in [
            ("overflow", DiscoveryFailure::Oversized),
            ("invalid", DiscoveryFailure::Invalid),
            ("stale", DiscoveryFailure::Stale),
            ("unsupported", DiscoveryFailure::Unsupported),
            ("unexpected", DiscoveryFailure::Invalid),
        ] {
            let response = json!({"ok": true, "discovery": {
                "schema": "liskov.discovery.v2",
                "status": "unavailable",
                "reason": reason
            }});
            assert_eq!(
                file.accept_response(request, &serde_json::to_vec(&response).unwrap()),
                Err(expected)
            );
            assert_eq!(fs::read(file.directory_path()).unwrap(), original);
        }

        let mut foreign = good.clone();
        foreign["discovery"]["self"]["runtimeInstanceId"] = "foreign".into();
        assert_eq!(
            file.accept_response(request, &serde_json::to_vec(&foreign).unwrap()),
            Err(DiscoveryFailure::Invalid)
        );
        let mut stale = good.clone();
        stale["discovery"]["validUntilMs"] = (now - 1).into();
        assert_eq!(
            file.accept_response(request, &serde_json::to_vec(&stale).unwrap()),
            Err(DiscoveryFailure::Stale)
        );
        let mut impossible_order = good.clone();
        impossible_order["discovery"]["peers"][0]["observedAtMs"] = (now + 1).into();
        set_revision(&mut impossible_order["discovery"]);
        assert_eq!(
            file.accept_response(request, &serde_json::to_vec(&impossible_order).unwrap()),
            Err(DiscoveryFailure::Stale),
            "a peer observation cannot postdate the directory observation"
        );
        let mut bad_url = good.clone();
        bad_url["discovery"]["peers"][0]["url"] = "https://example.com:8841/".into();
        assert_eq!(
            file.accept_response(request, &serde_json::to_vec(&bad_url).unwrap()),
            Err(DiscoveryFailure::Invalid)
        );
        let mut secret = good.clone();
        secret["discovery"]["peers"][0]["bearer"] = "secret".into();
        assert_eq!(
            file.accept_response(request, &serde_json::to_vec(&secret).unwrap()),
            Err(DiscoveryFailure::Invalid)
        );
        let mut duplicate = good.clone();
        let mut second = duplicate["discovery"]["peers"][0].clone();
        second["service"] = "other".into();
        duplicate["discovery"]["peers"]
            .as_array_mut()
            .unwrap()
            .push(second);
        set_revision(&mut duplicate["discovery"]);
        assert_eq!(
            file.accept_response(request, &serde_json::to_vec(&duplicate).unwrap()),
            Err(DiscoveryFailure::Invalid),
            "a runtime may advertise only one service even with a valid revision"
        );
        for (job, instance) in [
            ("different-job", "other-incarnation"),
            ("other", "different-incarnation"),
        ] {
            let mut repeated = good.clone();
            let mut second = repeated["discovery"]["peers"][0].clone();
            second["jobId"] = job.into();
            second["runtimeInstanceId"] = instance.into();
            repeated["discovery"]["peers"]
                .as_array_mut()
                .unwrap()
                .push(second);
            set_revision(&mut repeated["discovery"]);
            assert_eq!(
                file.accept_response(request, &serde_json::to_vec(&repeated).unwrap()),
                Err(DiscoveryFailure::Invalid),
                "job and runtime identities are independently unique"
            );
        }
        for (job, instance) in [("self", "other-incarnation"), ("other", "incarnation")] {
            let mut self_peer = good.clone();
            self_peer["discovery"]["peers"][0]["jobId"] = job.into();
            self_peer["discovery"]["peers"][0]["runtimeInstanceId"] = instance.into();
            set_revision(&mut self_peer["discovery"]);
            assert_eq!(
                file.accept_response(request, &serde_json::to_vec(&self_peer).unwrap()),
                Err(DiscoveryFailure::Invalid),
                "either self identity axis must exclude a peer"
            );
        }
        assert_eq!(fs::read(file.directory_path()).unwrap(), original);

        let mut empty = good;
        empty["discovery"]["peers"] = json!([]);
        set_revision(&mut empty["discovery"]);
        assert_eq!(
            file.accept_response(request, &serde_json::to_vec(&empty).unwrap()),
            Err(DiscoveryFailure::Stale),
            "an equal-observed response cannot replace a newer revision"
        );
        assert_eq!(fs::read(file.directory_path()).unwrap(), original);
        empty["discovery"]["observedAtMs"] = (now + 1).into();
        file.accept_response(request, &serde_json::to_vec(&empty).unwrap())
            .unwrap();
        let saved: Value =
            serde_json::from_slice(&fs::read(file.directory_path()).unwrap()).unwrap();
        assert_eq!(saved["peers"], json!([]));
    }

    #[test]
    fn child_restart_clears_input_and_delayed_old_response_cannot_publish() {
        let file = file(false);
        file.begin_child().unwrap();
        write_advertisement(&file, &advertisement());
        let mut attrs = json!({});
        let old_request = file.request_attrs(&mut attrs);
        file.end_child();
        assert!(!file.advertisement_path().exists());
        let mut after_exit = json!({});
        assert_eq!(file.request_attrs(&mut after_exit), Request::None);
        assert!(after_exit.get("peerReady").is_none());
        file.begin_child().unwrap();
        let now = unix_time_ms();
        let response = json!({"ok": true, "discovery": snapshot(now)});
        assert_eq!(
            file.accept_response(old_request, &serde_json::to_vec(&response).unwrap()),
            Err(DiscoveryFailure::Stale)
        );
        assert!(!file.directory_path().exists());
        let mut attrs = json!({});
        assert_eq!(file.request_attrs(&mut attrs), Request::None);
    }

    #[test]
    fn copied_owner_wire_fixtures_keep_their_digest_and_validate_at_fixture_time() {
        let advertisement = include_str!("../../vectors/liskov-discovery-v2-advertisement.json");
        let directory = include_str!("../../vectors/liskov-discovery-v2-directory.json");
        let empty = include_str!("../../vectors/liskov-discovery-v2-complete-empty.json");
        let unavailable = include_str!("../../vectors/liskov-discovery-v2-unavailable.json");
        assert_eq!(
            hex::encode(Sha256::digest(advertisement.as_bytes())),
            "f17b77e8c56512859aaaec8a6684b4e05dbd7d4fedbd83d945bb1d485fe7ce74"
        );
        assert_eq!(
            hex::encode(Sha256::digest(directory.as_bytes())),
            "f1b51194ba9564e98ae035879598a33d3fe80a2389b5f75888e9a465ec012685"
        );
        let file = file(false);
        file.begin_child().unwrap();
        fs::write(file.advertisement_path(), advertisement).unwrap();
        let ad = read_advertisement(&file.advertisement_path(), 1_790_000_000_100)
            .unwrap()
            .unwrap();
        assert_eq!(ad.service, "swarm");
        assert_eq!(ad.peer_sync_failure_code.as_deref(), Some("none"));
        for fixture in [directory, empty] {
            let value: Value = serde_json::from_str(fixture).unwrap();
            validate_snapshot(
                &value,
                "app-0123456789abcdef0123456789abcdef",
                "job-a",
                "instance-a",
                1_790_000_000_100,
            )
            .unwrap();
            assert_eq!(serialize_directory(&value).unwrap(), fixture.as_bytes());
        }
        let wire_file = DirectPeerDiscovery::create(
            &std::env::temp_dir(),
            "app-0123456789abcdef0123456789abcdef",
            "job-a",
            "instance-a",
            false,
        )
        .unwrap();
        wire_file.begin_child().unwrap();
        let generation = wire_file.state.lock().unwrap().generation;
        let wrapped =
            json!({"ok": true, "discovery": serde_json::from_str::<Value>(directory).unwrap()});
        wire_file
            .validate_and_write(
                generation,
                &serde_json::to_vec(&wrapped).unwrap(),
                1_790_000_000_100,
                true,
            )
            .unwrap();
        assert_eq!(
            fs::read(wire_file.directory_path()).unwrap(),
            directory.as_bytes()
        );
        let unavailable: Value = serde_json::from_str(unavailable).unwrap();
        assert_eq!(unavailable["status"], "unavailable");
        let invalid_bytes = include_str!("../../vectors/liskov-discovery-v2-invalid.json");
        assert_eq!(
            hex::encode(Sha256::digest(invalid_bytes.as_bytes())),
            "5df4629dd908661b1dc5294d6ae403030bde972d0338f3bb42076a1e73e77349"
        );
        let invalid: Value = serde_json::from_str(invalid_bytes).unwrap();
        for case in invalid.as_array().unwrap() {
            assert!(
                validate_snapshot(
                    &case["value"],
                    "app-0123456789abcdef0123456789abcdef",
                    "job-a",
                    "instance-a",
                    1_790_000_000_100,
                )
                .is_err(),
                "{}",
                case["name"]
            );
        }
    }
}
