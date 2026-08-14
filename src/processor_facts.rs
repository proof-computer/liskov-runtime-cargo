//! Dormant, authorization-gated processor fact capture for Cargo/PRoot.
//!
//! This module is intentionally isolated from customer arguments, environment,
//! output, and logging. The only production entrypoint is a detached task
//! created after authenticated bootstrap and started immediately before the
//! first customer-process attempt.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as _;
use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::bridge::Bridge;
use crate::diagnostics::canonical_json_bytes;
use crate::protocol::RuntimeBootstrapResponse;

pub const PROCESSOR_FACT_AUTHORIZATION_DOMAIN: &str =
    "proof.liskov.processor-fact-authorization.v1";
pub const PROCESSOR_FACT_RESULT_DOMAIN: &str = "proof.liskov.processor-fact-result.v1";
pub const CARGO_BASELINE_PROFILE: &str = "cargo-baseline-v1";
pub const HELPER_CONTRACT_EPOCH: u64 = 1;
pub const MAX_AUTHORIZATION_LIFETIME_MS: u64 = 5 * 60 * 1000;
pub const AUTHORIZATION_FUTURE_TOLERANCE_MS: u64 = 60 * 1000;
pub const MAX_RESULT_BYTES: usize = 16 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PROPERTY_FILE_BYTES: usize = 1024 * 1024;
const MAX_PROPERTY_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROPERTY_CONTEXT_FILES: usize = 4;
const MAX_PROPERTY_VALUE_BYTES: usize = 64;
const RESULT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
const EGRESS_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_HTTP_RESPONSE_BYTES: usize = 4 * 1024;
const PROPERTY_INFO_PATH: &str = "/dev/__properties__/property_info";
const PROPERTY_DIRECTORY: &str = "/dev/__properties__";
const PROPERTY_AREA_MAGIC: u32 = 0x504f_5250;
const PROPERTY_AREA_VERSION: u32 = 0xfc6e_d0ab;
const PROPERTY_AREA_HEADER_BYTES: usize = 128;
const PROPERTY_INFO_HEADER_BYTES: usize = 24;
const PROPERTY_INFO_TRIE_NODE_BYTES: usize = 28;
const PROPERTY_TRIE_NODE_BYTES: usize = 20;
const PROPERTY_ENTRY_BYTES: usize = 16;
const PROP_INFO_BYTES: usize = 96;
const PROP_VALUE_MAX: usize = 92;
const PROP_LONG_FLAG: u32 = 1 << 16;

const FALLBACK_CONTEXTS: [&str; 4] = [
    "u:object_r:build_prop:s0",
    "u:object_r:exported2_default_prop:s0",
    "u:object_r:exported_default_prop:s0",
    "u:object_r:vendor_default_prop:s0",
];

const ANDROID_PROPERTIES: [(&str, AndroidField); 9] = [
    ("ro.build.version.release", AndroidField::Release),
    ("ro.build.version.sdk", AndroidField::SdkLevel),
    (
        "ro.build.version.security_patch",
        AndroidField::SecurityPatch,
    ),
    ("ro.product.manufacturer", AndroidField::Manufacturer),
    ("ro.product.brand", AndroidField::Brand),
    ("ro.product.model", AndroidField::Model),
    ("ro.product.name", AndroidField::ProductName),
    ("ro.product.device", AndroidField::Device),
    ("ro.board.platform", AndroidField::BoardPlatform),
];

/// The three catalog-admitted fact dimensions. No generic fact name or value
/// map exists, so forbidden properties cannot become serializable by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub enum ProcessorFactKind {
    #[serde(rename = "cargo_android_corroboration.v1")]
    AndroidCorroboration,
    #[serde(rename = "cargo_execution_surface.v1")]
    ExecutionSurface,
    #[serde(rename = "cargo_control_egress.v1")]
    ControlEgress,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessorFactAuthorization {
    domain: String,
    authorization_id: String,
    challenge: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
    profile: String,
    catalog_digest: String,
    helper_contract_epoch: u64,
    expected_helper_version: String,
    expected_helper_digest: String,
    due_fact_kinds: Vec<ProcessorFactKind>,
}

impl std::fmt::Debug for ProcessorFactAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessorFactAuthorization")
            .field("domain", &self.domain)
            .field("profile", &self.profile)
            .field("helper_contract_epoch", &self.helper_contract_epoch)
            .field("due_fact_kinds", &self.due_fact_kinds)
            .finish_non_exhaustive()
    }
}

impl ProcessorFactAuthorization {
    fn structurally_valid(&self) -> bool {
        self.domain == PROCESSOR_FACT_AUTHORIZATION_DOMAIN
            && bounded_identifier(&self.authorization_id, 128)
            && valid_hex(&self.challenge, 32)
            && self.expires_at_ms > self.issued_at_ms
            && self
                .expires_at_ms
                .checked_sub(self.issued_at_ms)
                .is_some_and(|lifetime| lifetime <= MAX_AUTHORIZATION_LIFETIME_MS)
            && self.profile == CARGO_BASELINE_PROFILE
            && valid_sha256(&self.catalog_digest)
            && self.helper_contract_epoch == HELPER_CONTRACT_EPOCH
            && !self.expected_helper_version.is_empty()
            && self.expected_helper_version.len() <= 64
            && self
                .expected_helper_version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
            && valid_sha256(&self.expected_helper_digest)
            && (1..=3).contains(&self.due_fact_kinds.len())
            && self.due_fact_kinds.iter().collect::<BTreeSet<_>>().len()
                == self.due_fact_kinds.len()
    }

    fn valid_at(&self, now_ms: u64) -> bool {
        self.structurally_valid()
            && self.expires_at_ms > now_ms
            && self.issued_at_ms <= now_ms.saturating_add(AUTHORIZATION_FUTURE_TOLERANCE_MS)
    }
}

/// Remove and parse the raw capability independently of bootstrap validity.
/// Any malformed, unknown, or out-of-contract content simply returns `None`.
pub fn take_processor_fact_authorization(
    bootstrap: &mut RuntimeBootstrapResponse,
) -> Option<ProcessorFactAuthorization> {
    let raw = bootstrap.processor_facts.take()?;
    let authorization: ProcessorFactAuthorization = serde_json::from_value(raw).ok()?;
    authorization.structurally_valid().then_some(authorization)
}

#[derive(Clone)]
pub(crate) struct ProcessorFactBinding {
    deployment_id: String,
    job_id: String,
    processor_id: String,
    runtime_instance_id: String,
    result_url: String,
    egress_url: String,
}

impl ProcessorFactBinding {
    pub(crate) fn from_bootstrap(bootstrap: &RuntimeBootstrapResponse) -> Option<Self> {
        let mut base = url::Url::parse(&bootstrap.slipway_url).ok()?;
        if base.scheme() != "https"
            || base.host_str().is_none()
            || base.username() != ""
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return None;
        }
        base.set_path("/api/jobs/processor-facts");
        let result_url = base.to_string();
        base.set_path("/api/jobs/processor-facts/egress");
        let egress_url = base.to_string();
        Some(Self {
            deployment_id: bootstrap.deployment_id.clone(),
            job_id: bootstrap.job_id.clone(),
            processor_id: bootstrap.processor_id.clone(),
            runtime_instance_id: bootstrap.runtime_instance_id.clone(),
            result_url,
            egress_url,
        })
    }
}

pub trait FactClock: Send + Sync {
    fn now_ms(&self) -> Option<u64>;
}

pub struct SystemFactClock;

impl FactClock for SystemFactClock {
    fn now_ms(&self) -> Option<u64> {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis();
        u64::try_from(millis).ok()
    }
}

pub trait ExecutableHasher: Send + Sync {
    fn sha256(&self) -> Option<String>;
}

pub struct ProcSelfExecutableHasher;

impl ExecutableHasher for ProcSelfExecutableHasher {
    fn sha256(&self) -> Option<String> {
        let mut file = File::open("/proc/self/exe").ok()?;
        let size = file.metadata().ok()?.len();
        if size == 0 || size > MAX_EXECUTABLE_BYTES {
            return None;
        }
        let mut hasher = Sha256::new();
        let mut read = 0_u64;
        let mut buffer = [0_u8; 32 * 1024];
        loop {
            let count = file.read(&mut buffer).ok()?;
            if count == 0 {
                break;
            }
            read = read.checked_add(u64::try_from(count).ok()?)?;
            if read > MAX_EXECUTABLE_BYTES {
                return None;
            }
            hasher.update(&buffer[..count]);
        }
        (read == size).then(|| format!("sha256:{}", hex::encode(hasher.finalize())))
    }
}

pub trait FactSigner: Send + Sync {
    fn sign_ed25519(&self, message: &[u8]) -> Option<String>;
}

struct BridgeFactSigner {
    bridge: Arc<dyn Bridge>,
}

impl FactSigner for BridgeFactSigner {
    fn sign_ed25519(&self, message: &[u8]) -> Option<String> {
        let result = self
            .bridge
            .call(
                "signer_sign",
                json!([{"curve": "ed25519", "bytes": hex::encode(message)}]),
            )
            .ok()?;
        let signature = result.get("bytes")?.as_str()?;
        let signature = signature.strip_prefix("0x").unwrap_or(signature);
        valid_hex(signature, 64).then(|| format!("0x{signature}"))
    }
}

pub trait ResultDelivery: Send + Sync {
    fn deliver(&self, url: &str, body: &[u8]) -> bool;
}

pub struct HttpsResultDelivery;

impl ResultDelivery for HttpsResultDelivery {
    fn deliver(&self, url: &str, body: &[u8]) -> bool {
        let agent = ureq::AgentBuilder::new()
            .timeout(RESULT_ATTEMPT_TIMEOUT)
            .redirects(0)
            .try_proxy_from_env(false)
            .https_only(true)
            .max_idle_connections(0)
            .build();
        let response = agent
            .post(url)
            .set("accept", "application/json")
            .set("content-type", "application/json")
            .set(
                "user-agent",
                concat!("liskov-runtime-contact/", env!("CARGO_PKG_VERSION")),
            )
            .send_bytes(body);
        let response = match response {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(ureq::Error::Transport(_)) => return false,
        };
        let status = response.status();
        let mut bounded = Vec::new();
        if response
            .into_reader()
            .take(u64::try_from(MAX_HTTP_RESPONSE_BYTES + 1).unwrap_or(u64::MAX))
            .read_to_end(&mut bounded)
            .is_err()
            || bounded.len() > MAX_HTTP_RESPONSE_BYTES
        {
            return false;
        }
        (200..300).contains(&status)
    }
}

pub trait AndroidFactCollector: Send + Sync {
    fn collect(&self) -> AndroidCorroborationFact;
}

pub trait ExecutionFactCollector: Send + Sync {
    fn collect(&self) -> ExecutionSurfaceFact;
}

pub trait EgressFactCollector: Send + Sync {
    fn collect(&self, endpoint: &str) -> ControlEgressFact;
}

#[derive(Serialize, Clone, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Availability<T> {
    Observed { value: T },
    NotPresent,
    PermissionDenied,
    SurfaceHidden,
    Unsupported,
    ParseError,
}

impl<T: std::fmt::Debug> std::fmt::Debug for Availability<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Observed { .. } => formatter.write_str("Observed([redacted])"),
            Self::NotPresent => formatter.write_str("NotPresent"),
            Self::PermissionDenied => formatter.write_str("PermissionDenied"),
            Self::SurfaceHidden => formatter.write_str("SurfaceHidden"),
            Self::Unsupported => formatter.write_str("Unsupported"),
            Self::ParseError => formatter.write_str("ParseError"),
        }
    }
}

#[derive(Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AndroidCorroborationFact {
    android_release: Availability<String>,
    sdk_level: Availability<String>,
    security_patch: Availability<String>,
    manufacturer: Availability<String>,
    brand: Availability<String>,
    model: Availability<String>,
    product_name: Availability<String>,
    device: Availability<String>,
    board_platform: Availability<String>,
}

impl AndroidCorroborationFact {
    fn uniform(status: Availability<String>) -> Self {
        Self {
            android_release: status.clone(),
            sdk_level: status.clone(),
            security_patch: status.clone(),
            manufacturer: status.clone(),
            brand: status.clone(),
            model: status.clone(),
            product_name: status.clone(),
            device: status.clone(),
            board_platform: status,
        }
    }

    fn set(&mut self, field: AndroidField, value: Availability<String>) {
        match field {
            AndroidField::Release => self.android_release = value,
            AndroidField::SdkLevel => self.sdk_level = value,
            AndroidField::SecurityPatch => self.security_patch = value,
            AndroidField::Manufacturer => self.manufacturer = value,
            AndroidField::Brand => self.brand = value,
            AndroidField::Model => self.model = value,
            AndroidField::ProductName => self.product_name = value,
            AndroidField::Device => self.device = value,
            AndroidField::BoardPlatform => self.board_platform = value,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AndroidField {
    Release,
    SdkLevel,
    SecurityPatch,
    Manufacturer,
    Brand,
    Model,
    ProductName,
    Device,
    BoardPlatform,
}

#[derive(Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KernelAbi {
    major: u64,
    minor: u64,
}

#[derive(Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SeccompClass {
    Disabled,
    Strict,
    Filter,
}

#[derive(Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityClass {
    None,
    Nonzero,
}

#[derive(Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionSurfaceFact {
    architecture: Availability<String>,
    word_size_bits: Availability<u32>,
    page_size_bytes: Availability<u64>,
    kernel_abi: Availability<KernelAbi>,
    no_new_privs: Availability<bool>,
    seccomp: Availability<SeccompClass>,
    effective_capabilities: Availability<CapabilityClass>,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EgressOutcome {
    Success,
    DnsFailed,
    NoFamilyAddress,
    ConnectionFailed,
    Timeout,
    TransportOrTlsFailed,
    HttpUnexpectedStatus,
    ResponseTooLarge,
    InternalError,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FamilyEgressObservation {
    outcome: EgressOutcome,
    resolution_duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_class: Option<String>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ControlEgressFact {
    ipv4: FamilyEgressObservation,
    ipv6: FamilyEgressObservation,
}

#[derive(Serialize, Clone, PartialEq, Eq)]
#[serde(tag = "kind", content = "value")]
enum ProcessorFact {
    #[serde(rename = "cargo_android_corroboration.v1")]
    Android(AndroidCorroborationFact),
    #[serde(rename = "cargo_execution_surface.v1")]
    Execution(ExecutionSurfaceFact),
    #[serde(rename = "cargo_control_egress.v1")]
    Egress(ControlEgressFact),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedProcessorFactResult<'a> {
    domain: &'static str,
    authorization_id: &'a str,
    challenge: &'a str,
    deployment_id: &'a str,
    job_id: &'a str,
    processor_id: &'a str,
    runtime_instance_id: &'a str,
    profile: &'a str,
    catalog_digest: &'a str,
    helper_contract_epoch: u64,
    helper_version: &'static str,
    helper_digest: &'a str,
    capture_started_at_ms: u64,
    capture_completed_at_ms: u64,
    facts: &'a [ProcessorFact],
    facts_digest: &'a str,
}

pub struct ProcessorFactWorkerDependencies<'a> {
    pub clock: &'a dyn FactClock,
    pub executable_hasher: &'a dyn ExecutableHasher,
    pub android: &'a dyn AndroidFactCollector,
    pub execution: &'a dyn ExecutionFactCollector,
    pub egress: &'a dyn EgressFactCollector,
    pub signer: &'a dyn FactSigner,
    pub delivery: &'a dyn ResultDelivery,
}

pub fn compiled_catalog_digest() -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(include_bytes!(
            "../contracts/cargo-baseline-v1.json"
        )))
    )
}

pub(crate) fn detached_processor_fact_task(
    authorization: ProcessorFactAuthorization,
    binding: ProcessorFactBinding,
    bridge: Arc<dyn Bridge>,
) -> Box<dyn FnOnce() + Send> {
    Box::new(move || {
        let clock = SystemFactClock;
        let executable_hasher = ProcSelfExecutableHasher;
        let android = AndroidPropertyCollector::<SecurePropertyFileReader>::default();
        let execution = LinuxExecutionCollector;
        let egress = SystemEgressCollector;
        let signer = BridgeFactSigner { bridge };
        let delivery = HttpsResultDelivery;
        let dependencies = ProcessorFactWorkerDependencies {
            clock: &clock,
            executable_hasher: &executable_hasher,
            android: &android,
            execution: &execution,
            egress: &egress,
            signer: &signer,
            delivery: &delivery,
        };
        let _ = run_processor_fact_worker(&authorization, &binding, &dependencies);
    })
}

pub(crate) fn run_processor_fact_worker(
    authorization: &ProcessorFactAuthorization,
    binding: &ProcessorFactBinding,
    dependencies: &ProcessorFactWorkerDependencies<'_>,
) -> Result<(), ()> {
    let now_ms = dependencies.clock.now_ms().ok_or(())?;
    if !authorization.valid_at(now_ms)
        || authorization.expected_helper_version != env!("CARGO_PKG_VERSION")
        || authorization.catalog_digest != compiled_catalog_digest()
    {
        return Err(());
    }
    let helper_digest = dependencies.executable_hasher.sha256().ok_or(())?;
    if helper_digest != authorization.expected_helper_digest {
        return Err(());
    }

    let capture_started_at_ms = dependencies.clock.now_ms().ok_or(())?;
    if !authorization.valid_at(capture_started_at_ms) {
        return Err(());
    }
    let due = authorization
        .due_fact_kinds
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut facts = Vec::with_capacity(due.len());
    // Canonical catalog order, independent of authorization array order.
    if due.contains(&ProcessorFactKind::AndroidCorroboration) {
        facts.push(ProcessorFact::Android(dependencies.android.collect()));
    }
    if due.contains(&ProcessorFactKind::ExecutionSurface) {
        facts.push(ProcessorFact::Execution(dependencies.execution.collect()));
    }
    if due.contains(&ProcessorFactKind::ControlEgress) {
        facts.push(ProcessorFact::Egress(
            dependencies.egress.collect(&binding.egress_url),
        ));
    }
    let capture_completed_at_ms = dependencies.clock.now_ms().ok_or(())?;
    let facts_value = serde_json::to_value(&facts).map_err(|_| ())?;
    let facts_digest = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(canonical_json_bytes(&facts_value)))
    );
    let unsigned = UnsignedProcessorFactResult {
        domain: PROCESSOR_FACT_RESULT_DOMAIN,
        authorization_id: &authorization.authorization_id,
        challenge: &authorization.challenge,
        deployment_id: &binding.deployment_id,
        job_id: &binding.job_id,
        processor_id: &binding.processor_id,
        runtime_instance_id: &binding.runtime_instance_id,
        profile: &authorization.profile,
        catalog_digest: &authorization.catalog_digest,
        helper_contract_epoch: HELPER_CONTRACT_EPOCH,
        helper_version: env!("CARGO_PKG_VERSION"),
        helper_digest: &helper_digest,
        capture_started_at_ms,
        capture_completed_at_ms,
        facts: &facts,
        facts_digest: &facts_digest,
    };
    let unsigned_value = serde_json::to_value(&unsigned).map_err(|_| ())?;
    let signature_input = canonical_json_bytes(&unsigned_value);
    let signature = dependencies
        .signer
        .sign_ed25519(&signature_input)
        .ok_or(())?;
    let mut signed = unsigned_value;
    let Value::Object(ref mut object) = signed else {
        return Err(());
    };
    object.insert("signature".to_owned(), Value::String(signature));
    let body = canonical_json_bytes(&signed);
    if body.len() > MAX_RESULT_BYTES {
        return Err(());
    }

    for _ in 0..2 {
        if dependencies.clock.now_ms().ok_or(())? >= authorization.expires_at_ms {
            break;
        }
        if dependencies.delivery.deliver(&binding.result_url, &body) {
            break;
        }
    }
    Ok(())
}

fn bounded_identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_sha256(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|digest| valid_hex(digest, 32))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileReadFailure {
    NotFound,
    PermissionDenied,
    UnsafeFile,
    TooLarge,
    Unavailable,
}

pub struct PropertyReadBudget {
    remaining: usize,
}

impl PropertyReadBudget {
    fn new() -> Self {
        Self {
            remaining: MAX_PROPERTY_TOTAL_BYTES,
        }
    }
}

pub trait PropertyFileReader: Send + Sync {
    fn read(&self, path: &str, budget: &mut PropertyReadBudget)
    -> Result<Vec<u8>, FileReadFailure>;
}

#[derive(Default)]
pub struct SecurePropertyFileReader;

impl PropertyFileReader for SecurePropertyFileReader {
    fn read(
        &self,
        path: &str,
        budget: &mut PropertyReadBudget,
    ) -> Result<Vec<u8>, FileReadFailure> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let file = options.open(path).map_err(classify_file_error)?;
        let metadata = file.metadata().map_err(|_| FileReadFailure::Unavailable)?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & (libc::S_IWGRP | libc::S_IWOTH) != 0
        {
            return Err(FileReadFailure::UnsafeFile);
        }
        let length = usize::try_from(metadata.len()).map_err(|_| FileReadFailure::TooLarge)?;
        if length > MAX_PROPERTY_FILE_BYTES || length > budget.remaining {
            return Err(FileReadFailure::TooLarge);
        }
        let bounded_length = length.checked_add(1).ok_or(FileReadFailure::TooLarge)?;
        let mut bytes = Vec::with_capacity(bounded_length);
        file.take(u64::try_from(bounded_length).map_err(|_| FileReadFailure::TooLarge)?)
            .read_to_end(&mut bytes)
            .map_err(|_| FileReadFailure::Unavailable)?;
        if bytes.len() != length {
            return Err(FileReadFailure::Unavailable);
        }
        budget.remaining -= length;
        Ok(bytes)
    }
}

fn classify_file_error(error: std::io::Error) -> FileReadFailure {
    match error.raw_os_error() {
        Some(libc::ENOENT) | Some(libc::ENOTDIR) => FileReadFailure::NotFound,
        Some(libc::EACCES) | Some(libc::EPERM) => FileReadFailure::PermissionDenied,
        Some(libc::ELOOP) => FileReadFailure::UnsafeFile,
        _ => FileReadFailure::Unavailable,
    }
}

#[derive(Default)]
pub struct AndroidPropertyCollector<R = SecurePropertyFileReader> {
    reader: R,
}

impl<R: PropertyFileReader> AndroidFactCollector for AndroidPropertyCollector<R> {
    fn collect(&self) -> AndroidCorroborationFact {
        collect_android_properties(&self.reader)
    }
}

fn collect_android_properties(reader: &dyn PropertyFileReader) -> AndroidCorroborationFact {
    let mut budget = PropertyReadBudget::new();
    match reader.read(PROPERTY_INFO_PATH, &mut budget) {
        Ok(property_info) => collect_with_property_info(reader, &mut budget, &property_info),
        Err(FileReadFailure::NotFound) => collect_with_fallback_contexts(reader, &mut budget),
        Err(error) => AndroidCorroborationFact::uniform(file_failure_availability(error)),
    }
}

fn collect_with_property_info(
    reader: &dyn PropertyFileReader,
    budget: &mut PropertyReadBudget,
    property_info: &[u8],
) -> AndroidCorroborationFact {
    let parser = match PropertyInfoParser::new(property_info) {
        Ok(parser) => parser,
        Err(BinaryFormatError::Unsupported) => {
            return AndroidCorroborationFact::uniform(Availability::Unsupported);
        }
        Err(BinaryFormatError::Malformed) => {
            return AndroidCorroborationFact::uniform(Availability::ParseError);
        }
    };

    let mut by_context: BTreeMap<String, Vec<(&str, AndroidField)>> = BTreeMap::new();
    let mut fact = AndroidCorroborationFact::uniform(Availability::SurfaceHidden);
    for (name, field) in ANDROID_PROPERTIES {
        match parser.context_for(name) {
            Ok(Some(context)) if valid_property_context(&context) => {
                by_context.entry(context).or_default().push((name, field));
            }
            Ok(Some(_)) | Err(BinaryFormatError::Unsupported) => {
                fact.set(field, Availability::Unsupported);
            }
            Ok(None) => fact.set(field, Availability::NotPresent),
            Err(BinaryFormatError::Malformed) => fact.set(field, Availability::ParseError),
        }
    }

    for (index, (context, properties)) in by_context.into_iter().enumerate() {
        if index >= MAX_PROPERTY_CONTEXT_FILES {
            for (_, field) in properties {
                fact.set(field, Availability::SurfaceHidden);
            }
            continue;
        }
        let path = format!("{PROPERTY_DIRECTORY}/{context}");
        match reader.read(&path, budget) {
            Ok(area) => {
                let parser = PropertyAreaParser::new(&area);
                for (name, field) in properties {
                    fact.set(field, normalize_android_value(field, parser.value(name)));
                }
            }
            Err(error) => {
                let status = file_failure_availability(error);
                for (_, field) in properties {
                    fact.set(field, status.clone());
                }
            }
        }
    }
    fact
}

fn collect_with_fallback_contexts(
    reader: &dyn PropertyFileReader,
    budget: &mut PropertyReadBudget,
) -> AndroidCorroborationFact {
    let mut areas = Vec::new();
    let mut strongest_failure = FileReadFailure::NotFound;
    for context in FALLBACK_CONTEXTS {
        let path = format!("{PROPERTY_DIRECTORY}/{context}");
        match reader.read(&path, budget) {
            Ok(bytes) => areas.push(bytes),
            Err(error) => strongest_failure = stronger_file_failure(strongest_failure, error),
        }
    }
    if areas.is_empty() {
        return AndroidCorroborationFact::uniform(file_failure_availability(strongest_failure));
    }

    let mut fact = AndroidCorroborationFact::uniform(Availability::NotPresent);
    for (name, field) in ANDROID_PROPERTIES {
        let mut unresolved = Availability::NotPresent;
        for area in &areas {
            match PropertyAreaParser::new(area).value(name) {
                Ok(Some(value)) => {
                    unresolved = normalize_android_text(field, value);
                    break;
                }
                Ok(None) => {}
                Err(BinaryFormatError::Unsupported) => unresolved = Availability::Unsupported,
                Err(BinaryFormatError::Malformed) => {
                    if !matches!(unresolved, Availability::Unsupported) {
                        unresolved = Availability::ParseError;
                    }
                }
            }
        }
        fact.set(field, unresolved);
    }
    fact
}

fn stronger_file_failure(left: FileReadFailure, right: FileReadFailure) -> FileReadFailure {
    fn rank(value: FileReadFailure) -> u8 {
        match value {
            FileReadFailure::NotFound => 0,
            FileReadFailure::Unavailable => 1,
            FileReadFailure::PermissionDenied => 2,
            FileReadFailure::UnsafeFile | FileReadFailure::TooLarge => 3,
        }
    }
    if rank(right) > rank(left) {
        right
    } else {
        left
    }
}

fn file_failure_availability(error: FileReadFailure) -> Availability<String> {
    match error {
        FileReadFailure::NotFound | FileReadFailure::Unavailable => Availability::SurfaceHidden,
        FileReadFailure::PermissionDenied => Availability::PermissionDenied,
        FileReadFailure::UnsafeFile | FileReadFailure::TooLarge => Availability::Unsupported,
    }
}

fn valid_property_context(context: &str) -> bool {
    let Some(property_type) = context
        .strip_prefix("u:object_r:")
        .and_then(|value| value.strip_suffix(":s0"))
    else {
        return false;
    };
    !property_type.is_empty()
        && property_type.len() <= 64
        && property_type
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn normalize_android_value(
    field: AndroidField,
    result: Result<Option<String>, BinaryFormatError>,
) -> Availability<String> {
    match result {
        Ok(Some(value)) => normalize_android_text(field, value),
        Ok(None) => Availability::NotPresent,
        Err(BinaryFormatError::Unsupported) => Availability::Unsupported,
        Err(BinaryFormatError::Malformed) => Availability::ParseError,
    }
}

fn normalize_android_text(field: AndroidField, value: String) -> Availability<String> {
    let trimmed = value.trim_matches(' ');
    if trimmed.len() > MAX_PROPERTY_VALUE_BYTES
        || !trimmed.is_ascii()
        || !trimmed.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Availability::ParseError;
    }
    match field {
        AndroidField::SdkLevel => {
            if trimmed.is_empty()
                || !trimmed.bytes().all(|byte| byte.is_ascii_digit())
                || (trimmed.len() > 1 && trimmed.starts_with('0'))
                || trimmed
                    .parse::<u16>()
                    .ok()
                    .is_none_or(|sdk| !(1..=999).contains(&sdk))
            {
                return Availability::ParseError;
            }
        }
        AndroidField::SecurityPatch if !valid_iso_date(trimmed) => {
            return Availability::ParseError;
        }
        _ => {}
    }
    Availability::Observed {
        value: trimmed.to_owned(),
    }
}

fn valid_iso_date(value: &str) -> bool {
    if value.len() != 10
        || value.as_bytes()[4] != b'-'
        || value.as_bytes()[7] != b'-'
        || !value
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
    {
        return false;
    }
    let year = value[0..4].parse::<u16>().ok();
    let month = value[5..7].parse::<u8>().ok();
    let day = value[8..10].parse::<u8>().ok();
    let (Some(year), Some(month), Some(day)) = (year, month, day) else {
        return false;
    };
    if year < 2008 || !(1..=12).contains(&month) {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=days).contains(&day)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinaryFormatError {
    Unsupported,
    Malformed,
}

#[derive(Clone, Copy)]
struct CheckedBytes<'a> {
    bytes: &'a [u8],
}

impl CheckedBytes<'_> {
    fn slice(&self, offset: usize, length: usize) -> Result<&[u8], BinaryFormatError> {
        let end = offset
            .checked_add(length)
            .ok_or(BinaryFormatError::Malformed)?;
        self.bytes
            .get(offset..end)
            .ok_or(BinaryFormatError::Malformed)
    }

    fn u32(&self, offset: usize) -> Result<u32, BinaryFormatError> {
        Ok(u32::from_le_bytes(
            self.slice(offset, 4)?
                .try_into()
                .map_err(|_| BinaryFormatError::Malformed)?,
        ))
    }

    fn array_offset(&self, offset: usize, index: usize) -> Result<usize, BinaryFormatError> {
        let item = index.checked_mul(4).ok_or(BinaryFormatError::Malformed)?;
        usize::try_from(
            self.u32(
                offset
                    .checked_add(item)
                    .ok_or(BinaryFormatError::Malformed)?,
            )?,
        )
        .map_err(|_| BinaryFormatError::Malformed)
    }

    fn c_string(&self, offset: usize, max: usize) -> Result<&str, BinaryFormatError> {
        let tail = self
            .bytes
            .get(offset..)
            .ok_or(BinaryFormatError::Malformed)?;
        let end = tail
            .iter()
            .take(max + 1)
            .position(|byte| *byte == 0)
            .ok_or(BinaryFormatError::Malformed)?;
        std::str::from_utf8(&tail[..end]).map_err(|_| BinaryFormatError::Malformed)
    }
}

struct PropertyInfoParser<'a> {
    data: CheckedBytes<'a>,
    contexts_offset: usize,
    root_offset: usize,
}

impl<'a> PropertyInfoParser<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, BinaryFormatError> {
        let data = CheckedBytes { bytes };
        if bytes.len() < PROPERTY_INFO_HEADER_BYTES {
            return Err(BinaryFormatError::Malformed);
        }
        if data.u32(0)? != 1 || data.u32(4)? != 1 {
            return Err(BinaryFormatError::Unsupported);
        }
        if usize::try_from(data.u32(8)?).ok() != Some(bytes.len()) {
            return Err(BinaryFormatError::Malformed);
        }
        let contexts_offset =
            usize::try_from(data.u32(12)?).map_err(|_| BinaryFormatError::Malformed)?;
        let types_offset =
            usize::try_from(data.u32(16)?).map_err(|_| BinaryFormatError::Malformed)?;
        let root_offset =
            usize::try_from(data.u32(20)?).map_err(|_| BinaryFormatError::Malformed)?;
        validate_offset_array(&data, contexts_offset)?;
        validate_offset_array(&data, types_offset)?;
        data.slice(root_offset, PROPERTY_INFO_TRIE_NODE_BYTES)?;
        Ok(Self {
            data,
            contexts_offset,
            root_offset,
        })
    }

    fn context_for(&self, name: &str) -> Result<Option<String>, BinaryFormatError> {
        let mut inherited = u32::MAX;
        let mut remaining = name;
        let mut node = self.root_offset;
        let mut depth = 0_u8;
        loop {
            depth = depth.checked_add(1).ok_or(BinaryFormatError::Malformed)?;
            if depth > 32 {
                return Err(BinaryFormatError::Malformed);
            }
            let entry = self.node_entry(node)?;
            let context = self.data.u32(entry + 8)?;
            if context != u32::MAX {
                inherited = context;
            }
            self.check_prefixes(node, remaining, &mut inherited)?;
            let Some(separator) = remaining.find('.') else {
                break;
            };
            let segment = &remaining[..separator];
            let Some(child) = self.find_child(node, segment)? else {
                break;
            };
            node = child;
            remaining = &remaining[separator + 1..];
        }
        let exact_count =
            usize::try_from(self.data.u32(node + 20)?).map_err(|_| BinaryFormatError::Malformed)?;
        let exact_array =
            usize::try_from(self.data.u32(node + 24)?).map_err(|_| BinaryFormatError::Malformed)?;
        validate_array(&self.data, exact_array, exact_count)?;
        for index in 0..exact_count {
            let entry = self.data.array_offset(exact_array, index)?;
            if self.entry_name(entry)? == remaining {
                let context = self.data.u32(entry + 8)?;
                return self.context(if context != u32::MAX {
                    context
                } else {
                    inherited
                });
            }
        }
        self.check_prefixes(node, remaining, &mut inherited)?;
        self.context(inherited)
    }

    fn context(&self, index: u32) -> Result<Option<String>, BinaryFormatError> {
        if index == u32::MAX {
            return Ok(None);
        }
        let count = usize::try_from(self.data.u32(self.contexts_offset)?)
            .map_err(|_| BinaryFormatError::Malformed)?;
        let index = usize::try_from(index).map_err(|_| BinaryFormatError::Malformed)?;
        if index >= count {
            return Err(BinaryFormatError::Malformed);
        }
        let array = self
            .contexts_offset
            .checked_add(4)
            .ok_or(BinaryFormatError::Malformed)?;
        let offset = self.data.array_offset(array, index)?;
        Ok(Some(self.data.c_string(offset, 96)?.to_owned()))
    }

    fn node_entry(&self, node: usize) -> Result<usize, BinaryFormatError> {
        self.data.slice(node, PROPERTY_INFO_TRIE_NODE_BYTES)?;
        let entry =
            usize::try_from(self.data.u32(node)?).map_err(|_| BinaryFormatError::Malformed)?;
        self.data.slice(entry, PROPERTY_ENTRY_BYTES)?;
        Ok(entry)
    }

    fn entry_name(&self, entry: usize) -> Result<&str, BinaryFormatError> {
        self.data.slice(entry, PROPERTY_ENTRY_BYTES)?;
        let offset =
            usize::try_from(self.data.u32(entry)?).map_err(|_| BinaryFormatError::Malformed)?;
        let length =
            usize::try_from(self.data.u32(entry + 4)?).map_err(|_| BinaryFormatError::Malformed)?;
        if length > 128 {
            return Err(BinaryFormatError::Malformed);
        }
        let bytes = self.data.slice(offset, length)?;
        if self.data.slice(offset + length, 1)? != [0] {
            return Err(BinaryFormatError::Malformed);
        }
        std::str::from_utf8(bytes).map_err(|_| BinaryFormatError::Malformed)
    }

    fn find_child(&self, node: usize, segment: &str) -> Result<Option<usize>, BinaryFormatError> {
        let count =
            usize::try_from(self.data.u32(node + 4)?).map_err(|_| BinaryFormatError::Malformed)?;
        let array =
            usize::try_from(self.data.u32(node + 8)?).map_err(|_| BinaryFormatError::Malformed)?;
        validate_array(&self.data, array, count)?;
        let mut bottom = 0_usize;
        let mut top = count;
        while bottom < top {
            let index = bottom + (top - bottom) / 2;
            let child = self.data.array_offset(array, index)?;
            let child_name = self.entry_name(self.node_entry(child)?)?;
            match child_name.cmp(segment) {
                std::cmp::Ordering::Less => bottom = index + 1,
                std::cmp::Ordering::Greater => top = index,
                std::cmp::Ordering::Equal => return Ok(Some(child)),
            }
        }
        Ok(None)
    }

    fn check_prefixes(
        &self,
        node: usize,
        remaining: &str,
        inherited: &mut u32,
    ) -> Result<(), BinaryFormatError> {
        let count =
            usize::try_from(self.data.u32(node + 12)?).map_err(|_| BinaryFormatError::Malformed)?;
        let array =
            usize::try_from(self.data.u32(node + 16)?).map_err(|_| BinaryFormatError::Malformed)?;
        validate_array(&self.data, array, count)?;
        for index in 0..count {
            let entry = self.data.array_offset(array, index)?;
            if remaining.starts_with(self.entry_name(entry)?) {
                let context = self.data.u32(entry + 8)?;
                if context != u32::MAX {
                    *inherited = context;
                }
                break;
            }
        }
        Ok(())
    }
}

fn validate_offset_array(data: &CheckedBytes<'_>, offset: usize) -> Result<(), BinaryFormatError> {
    let count = usize::try_from(data.u32(offset)?).map_err(|_| BinaryFormatError::Malformed)?;
    let array = offset.checked_add(4).ok_or(BinaryFormatError::Malformed)?;
    validate_array(data, array, count)
}

fn validate_array(
    data: &CheckedBytes<'_>,
    offset: usize,
    count: usize,
) -> Result<(), BinaryFormatError> {
    let bytes = count.checked_mul(4).ok_or(BinaryFormatError::Malformed)?;
    data.slice(offset, bytes).map(|_| ())
}

#[derive(Clone, Copy)]
struct PropertyAreaParser<'a> {
    data: CheckedBytes<'a>,
    used: usize,
}

impl<'a> PropertyAreaParser<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            data: CheckedBytes { bytes },
            used: 0,
        }
    }

    fn validate(mut self) -> Result<Self, BinaryFormatError> {
        if self.data.bytes.len() < PROPERTY_AREA_HEADER_BYTES {
            return Err(BinaryFormatError::Malformed);
        }
        if self.data.u32(8)? != PROPERTY_AREA_MAGIC || self.data.u32(12)? != PROPERTY_AREA_VERSION {
            return Err(BinaryFormatError::Unsupported);
        }
        self.used = usize::try_from(self.data.u32(0)?).map_err(|_| BinaryFormatError::Malformed)?;
        if self.used < PROPERTY_TRIE_NODE_BYTES
            || self.used > self.data.bytes.len() - PROPERTY_AREA_HEADER_BYTES
        {
            return Err(BinaryFormatError::Malformed);
        }
        self.area_slice(0, PROPERTY_TRIE_NODE_BYTES)?;
        Ok(self)
    }

    fn value(self, name: &str) -> Result<Option<String>, BinaryFormatError> {
        let parser = self.validate()?;
        let mut current = 0_usize;
        for segment in name.split('.') {
            if segment.is_empty() {
                return Err(BinaryFormatError::Malformed);
            }
            let children = parser.node_u32(current, 16)?;
            if children == 0 {
                return Ok(None);
            }
            let Some(node) =
                parser.find_area_node(usize::try_from(children).unwrap_or(usize::MAX), segment)?
            else {
                return Ok(None);
            };
            current = node;
        }
        let prop = parser.node_u32(current, 4)?;
        if prop == 0 {
            return Ok(None);
        }
        parser
            .read_prop(
                usize::try_from(prop).map_err(|_| BinaryFormatError::Malformed)?,
                name,
            )
            .map(Some)
    }

    fn area_slice(&self, offset: usize, length: usize) -> Result<&[u8], BinaryFormatError> {
        let end = offset
            .checked_add(length)
            .ok_or(BinaryFormatError::Malformed)?;
        if end > self.used {
            return Err(BinaryFormatError::Malformed);
        }
        self.data.slice(
            PROPERTY_AREA_HEADER_BYTES
                .checked_add(offset)
                .ok_or(BinaryFormatError::Malformed)?,
            length,
        )
    }

    fn area_u32(&self, offset: usize) -> Result<u32, BinaryFormatError> {
        Ok(u32::from_le_bytes(
            self.area_slice(offset, 4)?
                .try_into()
                .map_err(|_| BinaryFormatError::Malformed)?,
        ))
    }

    fn node_u32(&self, node: usize, field: usize) -> Result<u32, BinaryFormatError> {
        self.area_slice(node, PROPERTY_TRIE_NODE_BYTES)?;
        self.area_u32(
            node.checked_add(field)
                .ok_or(BinaryFormatError::Malformed)?,
        )
    }

    fn node_name(&self, node: usize) -> Result<&str, BinaryFormatError> {
        let length =
            usize::try_from(self.node_u32(node, 0)?).map_err(|_| BinaryFormatError::Malformed)?;
        if length > 128 {
            return Err(BinaryFormatError::Malformed);
        }
        let offset = node
            .checked_add(PROPERTY_TRIE_NODE_BYTES)
            .ok_or(BinaryFormatError::Malformed)?;
        let bytes = self.area_slice(offset, length)?;
        if self.area_slice(offset + length, 1)? != [0] {
            return Err(BinaryFormatError::Malformed);
        }
        std::str::from_utf8(bytes).map_err(|_| BinaryFormatError::Malformed)
    }

    fn find_area_node(
        &self,
        mut node: usize,
        segment: &str,
    ) -> Result<Option<usize>, BinaryFormatError> {
        let mut visits = 0_usize;
        while node != 0 {
            visits += 1;
            if visits > self.used / PROPERTY_TRIE_NODE_BYTES + 1 {
                return Err(BinaryFormatError::Malformed);
            }
            match compare_android_node(segment, self.node_name(node)?) {
                std::cmp::Ordering::Equal => return Ok(Some(node)),
                std::cmp::Ordering::Less => {
                    node = usize::try_from(self.node_u32(node, 8)?)
                        .map_err(|_| BinaryFormatError::Malformed)?;
                }
                std::cmp::Ordering::Greater => {
                    node = usize::try_from(self.node_u32(node, 12)?)
                        .map_err(|_| BinaryFormatError::Malformed)?;
                }
            }
        }
        Ok(None)
    }

    fn read_prop(&self, offset: usize, expected_name: &str) -> Result<String, BinaryFormatError> {
        self.area_slice(offset, PROP_INFO_BYTES)?;
        let serial = self.area_u32(offset)?;
        let value_length =
            usize::try_from(serial >> 24).map_err(|_| BinaryFormatError::Malformed)?;
        let name_offset = offset
            .checked_add(PROP_INFO_BYTES)
            .ok_or(BinaryFormatError::Malformed)?;
        let actual_name = self.area_c_string(name_offset, 128)?;
        if actual_name != expected_name {
            return Err(BinaryFormatError::Malformed);
        }
        let value = if serial & PROP_LONG_FLAG != 0 {
            let relative = usize::try_from(self.area_u32(offset + 60)?)
                .map_err(|_| BinaryFormatError::Malformed)?;
            self.area_c_string(
                offset
                    .checked_add(relative)
                    .ok_or(BinaryFormatError::Malformed)?,
                MAX_PROPERTY_VALUE_BYTES,
            )?
        } else {
            if value_length >= PROP_VALUE_MAX {
                return Err(BinaryFormatError::Malformed);
            }
            let value_offset = offset.checked_add(4).ok_or(BinaryFormatError::Malformed)?;
            let value = self.area_slice(value_offset, value_length)?;
            if self.area_slice(value_offset + value_length, 1)? != [0] {
                return Err(BinaryFormatError::Malformed);
            }
            std::str::from_utf8(value).map_err(|_| BinaryFormatError::Malformed)?
        };
        Ok(value.to_owned())
    }

    fn area_c_string(&self, offset: usize, max: usize) -> Result<&str, BinaryFormatError> {
        if offset >= self.used {
            return Err(BinaryFormatError::Malformed);
        }
        let start = PROPERTY_AREA_HEADER_BYTES
            .checked_add(offset)
            .ok_or(BinaryFormatError::Malformed)?;
        let available = self.used - offset;
        let tail = self.data.slice(start, available)?;
        let end = tail
            .iter()
            .take(max + 1)
            .position(|byte| *byte == 0)
            .ok_or(BinaryFormatError::Malformed)?;
        std::str::from_utf8(&tail[..end]).map_err(|_| BinaryFormatError::Malformed)
    }
}

fn compare_android_node(left: &str, right: &str) -> std::cmp::Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxReadFailure {
    PermissionDenied,
    SurfaceHidden,
    Unsupported,
    ParseError,
}

pub trait LinuxSystemReader: Send + Sync {
    fn page_size(&self) -> Result<u64, LinuxReadFailure>;
    fn kernel_release(&self) -> Result<String, LinuxReadFailure>;
    fn proc_status(&self) -> Result<String, LinuxReadFailure>;
}

pub struct SystemLinuxReader;

impl LinuxSystemReader for SystemLinuxReader {
    fn page_size(&self) -> Result<u64, LinuxReadFailure> {
        // SAFETY: sysconf reads an immutable process/kernel setting.
        let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        u64::try_from(value)
            .ok()
            .filter(|value| *value > 0)
            .ok_or(LinuxReadFailure::Unsupported)
    }

    fn kernel_release(&self) -> Result<String, LinuxReadFailure> {
        // SAFETY: uname initializes the complete utsname on success.
        let mut name = unsafe { std::mem::zeroed::<libc::utsname>() };
        // SAFETY: `name` points to writable storage for one utsname.
        if unsafe { libc::uname(&mut name) } != 0 {
            return Err(LinuxReadFailure::SurfaceHidden);
        }
        // SAFETY: successful uname returns nul-terminated arrays.
        let release = unsafe { CStr::from_ptr(name.release.as_ptr()) };
        release
            .to_str()
            .map(str::to_owned)
            .map_err(|_| LinuxReadFailure::ParseError)
    }

    fn proc_status(&self) -> Result<String, LinuxReadFailure> {
        let mut file = File::open("/proc/self/status").map_err(|error| {
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                LinuxReadFailure::PermissionDenied
            } else {
                LinuxReadFailure::SurfaceHidden
            }
        })?;
        let mut bytes = Vec::new();
        file.by_ref()
            .take(64 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| LinuxReadFailure::SurfaceHidden)?;
        if bytes.len() > 64 * 1024 {
            return Err(LinuxReadFailure::Unsupported);
        }
        String::from_utf8(bytes).map_err(|_| LinuxReadFailure::ParseError)
    }
}

pub struct LinuxExecutionCollector;

impl ExecutionFactCollector for LinuxExecutionCollector {
    fn collect(&self) -> ExecutionSurfaceFact {
        collect_execution_surface(&SystemLinuxReader)
    }
}

fn collect_execution_surface(reader: &dyn LinuxSystemReader) -> ExecutionSurfaceFact {
    let page_size_bytes = reader
        .page_size()
        .map(|value| Availability::Observed { value })
        .unwrap_or_else(linux_failure_availability);
    let kernel_abi = match reader.kernel_release() {
        Ok(value) => parse_kernel_abi(&value),
        Err(error) => linux_failure_availability(error),
    };
    let (no_new_privs, seccomp, effective_capabilities) = match reader.proc_status() {
        Ok(status) => parse_proc_status(&status),
        Err(error) => (
            linux_failure_availability(error),
            linux_failure_availability(error),
            linux_failure_availability(error),
        ),
    };
    ExecutionSurfaceFact {
        architecture: Availability::Observed {
            value: std::env::consts::ARCH.to_owned(),
        },
        word_size_bits: Availability::Observed { value: usize::BITS },
        page_size_bytes,
        kernel_abi,
        no_new_privs,
        seccomp,
        effective_capabilities,
    }
}

fn linux_failure_availability<T>(error: LinuxReadFailure) -> Availability<T> {
    match error {
        LinuxReadFailure::PermissionDenied => Availability::PermissionDenied,
        LinuxReadFailure::SurfaceHidden => Availability::SurfaceHidden,
        LinuxReadFailure::Unsupported => Availability::Unsupported,
        LinuxReadFailure::ParseError => Availability::ParseError,
    }
}

fn parse_kernel_abi(release: &str) -> Availability<KernelAbi> {
    let Some((major, rest)) = release.split_once('.') else {
        return Availability::ParseError;
    };
    let minor = rest
        .split(|character: char| !character.is_ascii_digit())
        .next()
        .unwrap_or_default();
    if major.is_empty() || minor.is_empty() || !major.bytes().all(|byte| byte.is_ascii_digit()) {
        return Availability::ParseError;
    }
    let (Ok(major), Ok(minor)) = (major.parse::<u64>(), minor.parse::<u64>()) else {
        return Availability::ParseError;
    };
    Availability::Observed {
        value: KernelAbi { major, minor },
    }
}

fn parse_proc_status(
    status: &str,
) -> (
    Availability<bool>,
    Availability<SeccompClass>,
    Availability<CapabilityClass>,
) {
    let values: BTreeMap<&str, &str> = status
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key, value.trim_matches([' ', '\t'])))
        .collect();
    let no_new_privs = match values.get("NoNewPrivs").copied() {
        Some("0") => Availability::Observed { value: false },
        Some("1") => Availability::Observed { value: true },
        Some(_) => Availability::ParseError,
        None => Availability::NotPresent,
    };
    let seccomp = match values.get("Seccomp").copied() {
        Some("0") => Availability::Observed {
            value: SeccompClass::Disabled,
        },
        Some("1") => Availability::Observed {
            value: SeccompClass::Strict,
        },
        Some("2") => Availability::Observed {
            value: SeccompClass::Filter,
        },
        Some(_) => Availability::ParseError,
        None => Availability::NotPresent,
    };
    let effective_capabilities = match values.get("CapEff").copied() {
        Some(value)
            if !value.is_empty()
                && value.len() <= 64
                && value.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            Availability::Observed {
                value: if value.bytes().all(|byte| byte == b'0') {
                    CapabilityClass::None
                } else {
                    CapabilityClass::Nonzero
                },
            }
        }
        Some(_) => Availability::ParseError,
        None => Availability::NotPresent,
    };
    (no_new_privs, seccomp, effective_capabilities)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressResolutionFailure;

pub trait EgressResolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, EgressResolutionFailure>;
}

pub trait FamilyRequester: Send + Sync {
    fn request(&self, endpoint: &str, address: SocketAddr) -> FamilyRequestResult;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyRequestResult {
    pub outcome: EgressOutcome,
    pub duration_ms: u64,
    pub status_class: Option<String>,
}

pub struct SystemEgressResolver;

impl EgressResolver for SystemEgressResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, EgressResolutionFailure> {
        (host, port)
            .to_socket_addrs()
            .map(|addresses| addresses.collect())
            .map_err(|_| EgressResolutionFailure)
    }
}

pub struct HttpsFamilyRequester;

impl FamilyRequester for HttpsFamilyRequester {
    fn request(&self, endpoint: &str, address: SocketAddr) -> FamilyRequestResult {
        let started = Instant::now();
        let agent = ureq::AgentBuilder::new()
            .timeout(EGRESS_ATTEMPT_TIMEOUT)
            .redirects(0)
            .try_proxy_from_env(false)
            .https_only(true)
            .max_idle_connections(0)
            .resolver(move |_: &str| Ok(vec![address]))
            .build();
        let response = agent
            .get(endpoint)
            .set("accept", "application/json")
            .set(
                "user-agent",
                concat!("liskov-runtime-contact/", env!("CARGO_PKG_VERSION")),
            )
            .call();
        let duration_ms = duration_ms(started.elapsed());
        match response {
            Ok(response) | Err(ureq::Error::Status(_, response)) => {
                let status = response.status();
                let status_class = Some(http_status_class(status));
                let mut body = Vec::new();
                if response
                    .into_reader()
                    .take(u64::try_from(MAX_HTTP_RESPONSE_BYTES + 1).unwrap_or(u64::MAX))
                    .read_to_end(&mut body)
                    .is_err()
                {
                    return FamilyRequestResult {
                        outcome: EgressOutcome::TransportOrTlsFailed,
                        duration_ms,
                        status_class,
                    };
                }
                FamilyRequestResult {
                    outcome: if body.len() > MAX_HTTP_RESPONSE_BYTES {
                        EgressOutcome::ResponseTooLarge
                    } else if status == 204 {
                        EgressOutcome::Success
                    } else {
                        EgressOutcome::HttpUnexpectedStatus
                    },
                    duration_ms,
                    status_class,
                }
            }
            Err(error @ ureq::Error::Transport(_)) => {
                let outcome = match error.kind() {
                    ureq::ErrorKind::ConnectionFailed => EgressOutcome::ConnectionFailed,
                    ureq::ErrorKind::Dns => EgressOutcome::DnsFailed,
                    ureq::ErrorKind::Io if transport_timed_out(&error) => EgressOutcome::Timeout,
                    ureq::ErrorKind::Io
                    | ureq::ErrorKind::BadHeader
                    | ureq::ErrorKind::BadStatus => EgressOutcome::TransportOrTlsFailed,
                    _ => EgressOutcome::InternalError,
                };
                FamilyRequestResult {
                    outcome,
                    duration_ms,
                    status_class: None,
                }
            }
        }
    }
}

fn transport_timed_out(error: &ureq::Error) -> bool {
    let mut source = error.source();
    while let Some(current) = source {
        if current
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| {
                matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                )
            })
        {
            return true;
        }
        source = current.source();
    }
    false
}

fn http_status_class(status: u16) -> String {
    match status {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
    .to_owned()
}

pub struct SystemEgressCollector;

impl EgressFactCollector for SystemEgressCollector {
    fn collect(&self, endpoint: &str) -> ControlEgressFact {
        collect_control_egress(endpoint, &SystemEgressResolver, &HttpsFamilyRequester)
    }
}

pub fn collect_control_egress(
    endpoint: &str,
    resolver: &dyn EgressResolver,
    requester: &dyn FamilyRequester,
) -> ControlEgressFact {
    let parsed = url::Url::parse(endpoint).ok().filter(|url| {
        url.scheme() == "https"
            && matches!(url.host(), Some(url::Host::Domain(_)))
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/api/jobs/processor-facts/egress"
    });
    let Some(parsed) = parsed else {
        return ControlEgressFact {
            ipv4: closed_egress(EgressOutcome::InternalError, 0),
            ipv6: closed_egress(EgressOutcome::InternalError, 0),
        };
    };
    let Some(host) = parsed.host_str() else {
        return ControlEgressFact {
            ipv4: closed_egress(EgressOutcome::InternalError, 0),
            ipv6: closed_egress(EgressOutcome::InternalError, 0),
        };
    };
    let port = parsed.port_or_known_default().unwrap_or(443);
    let resolution_started = Instant::now();
    let addresses = resolver.resolve(host, port);
    let resolution_duration_ms = duration_ms(resolution_started.elapsed());
    let Ok(addresses) = addresses else {
        return ControlEgressFact {
            ipv4: closed_egress(EgressOutcome::DnsFailed, resolution_duration_ms),
            ipv6: closed_egress(EgressOutcome::DnsFailed, resolution_duration_ms),
        };
    };
    let ipv4 = addresses.iter().copied().find(SocketAddr::is_ipv4);
    let ipv6 = addresses.iter().copied().find(SocketAddr::is_ipv6);
    // No address or DNS answer survives this function except the single
    // in-memory address handed to each one-attempt family request.
    thread::scope(|scope| {
        let ipv4_handle =
            ipv4.map(|address| scope.spawn(move || requester.request(endpoint, address)));
        let ipv6_handle =
            ipv6.map(|address| scope.spawn(move || requester.request(endpoint, address)));
        let ipv4 = finish_family(ipv4_handle, resolution_duration_ms);
        let ipv6 = finish_family(ipv6_handle, resolution_duration_ms);
        ControlEgressFact { ipv4, ipv6 }
    })
}

fn finish_family(
    handle: Option<thread::ScopedJoinHandle<'_, FamilyRequestResult>>,
    resolution_duration_ms: u64,
) -> FamilyEgressObservation {
    match handle {
        None => closed_egress(EgressOutcome::NoFamilyAddress, resolution_duration_ms),
        Some(handle) => match handle.join() {
            Ok(result) => FamilyEgressObservation {
                outcome: result.outcome,
                resolution_duration_ms,
                request_duration_ms: Some(result.duration_ms),
                status_class: result.status_class,
            },
            Err(_) => closed_egress(EgressOutcome::InternalError, resolution_duration_ms),
        },
    }
}

fn closed_egress(outcome: EgressOutcome, resolution_duration_ms: u64) -> FamilyEgressObservation {
    FamilyEgressObservation {
        outcome,
        resolution_duration_ms,
        request_duration_ms: None,
        status_class: None,
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(any(test, feature = "fact-probe"))]
#[derive(Default)]
struct FixturePropertyReader {
    files: BTreeMap<String, Result<Vec<u8>, FileReadFailure>>,
}

#[cfg(any(test, feature = "fact-probe"))]
impl PropertyFileReader for FixturePropertyReader {
    fn read(
        &self,
        path: &str,
        budget: &mut PropertyReadBudget,
    ) -> Result<Vec<u8>, FileReadFailure> {
        let value = self
            .files
            .get(path)
            .cloned()
            .unwrap_or(Err(FileReadFailure::NotFound))?;
        if value.len() > MAX_PROPERTY_FILE_BYTES || value.len() > budget.remaining {
            return Err(FileReadFailure::TooLarge);
        }
        budget.remaining -= value.len();
        Ok(value)
    }
}

#[cfg(any(test, feature = "fact-probe"))]
fn fixture_property_info(context: &str, names: &[&str]) -> Vec<u8> {
    let mut bytes = vec![0_u8; PROPERTY_INFO_HEADER_BYTES];
    let contexts_offset = bytes.len();
    push_u32(&mut bytes, 1);
    let context_pointer = bytes.len();
    push_u32(&mut bytes, 0);
    let context_offset = bytes.len();
    bytes.extend_from_slice(context.as_bytes());
    bytes.push(0);
    align_fixture(&mut bytes);
    patch_u32(&mut bytes, context_pointer, context_offset);

    let types_offset = bytes.len();
    push_u32(&mut bytes, 1);
    let type_pointer = bytes.len();
    push_u32(&mut bytes, 0);
    let type_offset = bytes.len();
    bytes.extend_from_slice(b"string\0");
    align_fixture(&mut bytes);
    patch_u32(&mut bytes, type_pointer, type_offset);

    let root_offset = bytes.len();
    bytes.resize(bytes.len() + PROPERTY_INFO_TRIE_NODE_BYTES, 0);
    let root_entry = bytes.len();
    bytes.resize(bytes.len() + PROPERTY_ENTRY_BYTES, 0);
    let root_name = bytes.len();
    bytes.push(0);
    align_fixture(&mut bytes);
    patch_u32(&mut bytes, root_entry, root_name);
    patch_u32(&mut bytes, root_entry + 8, u32::MAX as usize);
    patch_u32(&mut bytes, root_entry + 12, u32::MAX as usize);

    let mut entries = Vec::new();
    for name in names {
        let entry = bytes.len();
        bytes.resize(bytes.len() + PROPERTY_ENTRY_BYTES, 0);
        let name_offset = bytes.len();
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
        align_fixture(&mut bytes);
        patch_u32(&mut bytes, entry, name_offset);
        patch_u32(&mut bytes, entry + 4, name.len());
        patch_u32(&mut bytes, entry + 8, 0);
        patch_u32(&mut bytes, entry + 12, 0);
        entries.push(entry);
    }
    let exact_array = bytes.len();
    for entry in entries {
        push_u32(&mut bytes, u32::try_from(entry).unwrap());
    }
    patch_u32(&mut bytes, root_offset, root_entry);
    patch_u32(&mut bytes, root_offset + 20, names.len());
    patch_u32(&mut bytes, root_offset + 24, exact_array);
    patch_u32(&mut bytes, 0, 1);
    patch_u32(&mut bytes, 4, 1);
    let total_size = bytes.len();
    patch_u32(&mut bytes, 8, total_size);
    patch_u32(&mut bytes, 12, contexts_offset);
    patch_u32(&mut bytes, 16, types_offset);
    patch_u32(&mut bytes, 20, root_offset);
    bytes
}

#[cfg(any(test, feature = "fact-probe"))]
fn fixture_property_area(values: &[(&str, &str)]) -> Vec<u8> {
    let mut bytes = vec![0_u8; PROPERTY_AREA_HEADER_BYTES + 112];
    patch_u32(&mut bytes, 8, PROPERTY_AREA_MAGIC as usize);
    patch_u32(&mut bytes, 12, PROPERTY_AREA_VERSION as usize);
    let mut used = 112_usize;
    for (name, value) in values {
        let mut parent = 0_usize;
        for segment in name.split('.') {
            parent = fixture_insert_area_node(&mut bytes, &mut used, parent, segment);
        }
        let info = fixture_area_allocate(&mut bytes, &mut used, PROP_INFO_BYTES + name.len() + 1);
        patch_area_u32(&mut bytes, info, value.len() << 24);
        let value_offset = PROPERTY_AREA_HEADER_BYTES + info + 4;
        bytes[value_offset..value_offset + value.len()].copy_from_slice(value.as_bytes());
        bytes[value_offset + value.len()] = 0;
        let name_offset = PROPERTY_AREA_HEADER_BYTES + info + PROP_INFO_BYTES;
        bytes[name_offset..name_offset + name.len()].copy_from_slice(name.as_bytes());
        bytes[name_offset + name.len()] = 0;
        patch_area_u32(&mut bytes, parent + 4, info);
    }
    patch_u32(&mut bytes, 0, used);
    bytes.truncate(PROPERTY_AREA_HEADER_BYTES + used);
    bytes
}

#[cfg(any(test, feature = "fact-probe"))]
fn fixture_insert_area_node(
    bytes: &mut Vec<u8>,
    used: &mut usize,
    parent: usize,
    segment: &str,
) -> usize {
    let child_pointer = parent + 16;
    let mut current = read_area_u32(bytes, child_pointer) as usize;
    if current == 0 {
        let node = fixture_new_area_node(bytes, used, segment);
        patch_area_u32(bytes, child_pointer, node);
        return node;
    }
    loop {
        let name_length = read_area_u32(bytes, current) as usize;
        let start = PROPERTY_AREA_HEADER_BYTES + current + PROPERTY_TRIE_NODE_BYTES;
        let current_name = std::str::from_utf8(&bytes[start..start + name_length]).unwrap();
        match compare_android_node(segment, current_name) {
            std::cmp::Ordering::Equal => return current,
            ordering => {
                let pointer = current
                    + if ordering == std::cmp::Ordering::Less {
                        8
                    } else {
                        12
                    };
                let next = read_area_u32(bytes, pointer) as usize;
                if next == 0 {
                    let node = fixture_new_area_node(bytes, used, segment);
                    patch_area_u32(bytes, pointer, node);
                    return node;
                }
                current = next;
            }
        }
    }
}

#[cfg(any(test, feature = "fact-probe"))]
fn fixture_new_area_node(bytes: &mut Vec<u8>, used: &mut usize, name: &str) -> usize {
    let node = fixture_area_allocate(bytes, used, PROPERTY_TRIE_NODE_BYTES + name.len() + 1);
    patch_area_u32(bytes, node, name.len());
    let start = PROPERTY_AREA_HEADER_BYTES + node + PROPERTY_TRIE_NODE_BYTES;
    bytes[start..start + name.len()].copy_from_slice(name.as_bytes());
    bytes[start + name.len()] = 0;
    node
}

#[cfg(any(test, feature = "fact-probe"))]
fn fixture_area_allocate(bytes: &mut Vec<u8>, used: &mut usize, length: usize) -> usize {
    let offset = *used;
    *used += (length + 3) & !3;
    bytes.resize(PROPERTY_AREA_HEADER_BYTES + *used, 0);
    offset
}

#[cfg(any(test, feature = "fact-probe"))]
fn align_fixture(bytes: &mut Vec<u8>) {
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
}

#[cfg(any(test, feature = "fact-probe"))]
fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(any(test, feature = "fact-probe"))]
fn patch_u32(bytes: &mut [u8], offset: usize, value: usize) {
    bytes[offset..offset + 4].copy_from_slice(&u32::try_from(value).unwrap().to_le_bytes());
}

#[cfg(any(test, feature = "fact-probe"))]
fn patch_area_u32(bytes: &mut [u8], offset: usize, value: usize) {
    patch_u32(bytes, PROPERTY_AREA_HEADER_BYTES + offset, value);
}

#[cfg(any(test, feature = "fact-probe"))]
fn read_area_u32(bytes: &[u8], offset: usize) -> u32 {
    let offset = PROPERTY_AREA_HEADER_BYTES + offset;
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

/// AArch64 CI/PRoot entrypoint. It exercises observed, hidden, denied, and
/// malformed property surfaces entirely from in-memory fixtures and performs
/// no resolution, HTTP, bridge, or filesystem operation.
#[cfg(feature = "fact-probe")]
pub fn run_fact_probe_self_test() -> bool {
    const CONTEXT: &str = "u:object_r:build_prop:s0";
    let names = ANDROID_PROPERTIES.map(|(name, _)| name);
    let mut observed = FixturePropertyReader::default();
    observed.files.insert(
        PROPERTY_INFO_PATH.to_owned(),
        Ok(fixture_property_info(CONTEXT, &names)),
    );
    observed.files.insert(
        format!("{PROPERTY_DIRECTORY}/{CONTEXT}"),
        Ok(fixture_property_area(&[
            ("ro.build.version.release", "13"),
            ("ro.build.version.sdk", "33"),
            ("ro.build.version.security_patch", "2023-09-01"),
            ("ro.product.manufacturer", "samsung"),
            ("ro.product.model", "SM-S135DL"),
        ])),
    );
    let fact = collect_android_properties(&observed);
    let observed_ok = matches!(
        fact.model,
        Availability::Observed { ref value } if value == "SM-S135DL"
    ) && matches!(fact.brand, Availability::NotPresent);

    let hidden = collect_android_properties(&FixturePropertyReader::default());
    let hidden_ok = matches!(hidden.model, Availability::SurfaceHidden);
    let mut denied = FixturePropertyReader::default();
    denied.files.insert(
        PROPERTY_INFO_PATH.to_owned(),
        Err(FileReadFailure::PermissionDenied),
    );
    let denied_ok = matches!(
        collect_android_properties(&denied).model,
        Availability::PermissionDenied
    );
    let mut malformed = FixturePropertyReader::default();
    malformed
        .files
        .insert(PROPERTY_INFO_PATH.to_owned(), Ok(vec![0; 24]));
    let malformed_ok = matches!(
        collect_android_properties(&malformed).model,
        Availability::Unsupported
    );
    observed_ok && hidden_ok && denied_ok && malformed_ok
}

#[cfg(all(test, not(feature = "fact-probe")))]
pub fn run_fact_probe_self_test() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::os::unix::fs::symlink;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    const NOW: u64 = 1_800_000_000_000;
    const HELPER_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn bootstrap(processor_facts: Option<Value>) -> RuntimeBootstrapResponse {
        RuntimeBootstrapResponse {
            ok: true,
            domain: "proof.liskov.runtime-bootstrap-response.v2".into(),
            application_uid: "app-uid".into(),
            application_id: "app-id".into(),
            policy_digest: "sha256:policy".into(),
            deployment_id: "deployment".into(),
            job_id: "job".into(),
            processor_id: "processor".into(),
            runtime_instance_id: "instance".into(),
            slipway_url: "https://liskov.example".into(),
            runtime_env: None,
            supervision: None,
            logging: None,
            logging_outage_canary: false,
            diagnostics: None,
            access: None,
            processor_facts,
        }
    }

    fn authorization_value(kinds: &[&str]) -> Value {
        json!({
            "domain": PROCESSOR_FACT_AUTHORIZATION_DOMAIN,
            "authorizationId": "authorization-1",
            "challenge": "11".repeat(32),
            "issuedAtMs": NOW - 1_000,
            "expiresAtMs": NOW + 299_000,
            "profile": CARGO_BASELINE_PROFILE,
            "catalogDigest": compiled_catalog_digest(),
            "helperContractEpoch": HELPER_CONTRACT_EPOCH,
            "expectedHelperVersion": env!("CARGO_PKG_VERSION"),
            "expectedHelperDigest": HELPER_DIGEST,
            "dueFactKinds": kinds,
        })
    }

    fn authorization(kinds: &[&str]) -> ProcessorFactAuthorization {
        serde_json::from_value(authorization_value(kinds)).unwrap()
    }

    fn binding() -> ProcessorFactBinding {
        ProcessorFactBinding::from_bootstrap(&bootstrap(None)).unwrap()
    }

    #[derive(Default)]
    struct Counters {
        hash: AtomicUsize,
        android: AtomicUsize,
        execution: AtomicUsize,
        egress: AtomicUsize,
        signing: AtomicUsize,
    }

    struct FixedClock(u64);

    impl FactClock for FixedClock {
        fn now_ms(&self) -> Option<u64> {
            Some(self.0)
        }
    }

    struct SequenceClock {
        values: Mutex<VecDeque<u64>>,
        fallback: u64,
    }

    impl SequenceClock {
        fn new(values: impl IntoIterator<Item = u64>, fallback: u64) -> Self {
            Self {
                values: Mutex::new(values.into_iter().collect()),
                fallback,
            }
        }
    }

    impl FactClock for SequenceClock {
        fn now_ms(&self) -> Option<u64> {
            Some(
                self.values
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(self.fallback),
            )
        }
    }

    struct CountingHasher<'a> {
        counters: &'a Counters,
        digest: &'a str,
    }

    impl ExecutableHasher for CountingHasher<'_> {
        fn sha256(&self) -> Option<String> {
            self.counters.hash.fetch_add(1, Ordering::SeqCst);
            Some(self.digest.to_owned())
        }
    }

    struct CountingAndroid<'a>(&'a Counters);

    impl AndroidFactCollector for CountingAndroid<'_> {
        fn collect(&self) -> AndroidCorroborationFact {
            self.0.android.fetch_add(1, Ordering::SeqCst);
            AndroidCorroborationFact::uniform(Availability::NotPresent)
        }
    }

    struct CountingExecution<'a>(&'a Counters);

    impl ExecutionFactCollector for CountingExecution<'_> {
        fn collect(&self) -> ExecutionSurfaceFact {
            self.0.execution.fetch_add(1, Ordering::SeqCst);
            ExecutionSurfaceFact {
                architecture: Availability::Observed {
                    value: "aarch64".into(),
                },
                word_size_bits: Availability::Observed { value: 64 },
                page_size_bytes: Availability::Observed { value: 4096 },
                kernel_abi: Availability::Observed {
                    value: KernelAbi {
                        major: 4,
                        minor: 19,
                    },
                },
                no_new_privs: Availability::Observed { value: true },
                seccomp: Availability::Observed {
                    value: SeccompClass::Filter,
                },
                effective_capabilities: Availability::Observed {
                    value: CapabilityClass::None,
                },
            }
        }
    }

    struct CountingEgress<'a>(&'a Counters);

    impl EgressFactCollector for CountingEgress<'_> {
        fn collect(&self, endpoint: &str) -> ControlEgressFact {
            assert_eq!(
                endpoint,
                "https://liskov.example/api/jobs/processor-facts/egress"
            );
            self.0.egress.fetch_add(1, Ordering::SeqCst);
            ControlEgressFact {
                ipv4: closed_egress(EgressOutcome::Success, 1),
                ipv6: closed_egress(EgressOutcome::NoFamilyAddress, 1),
            }
        }
    }

    struct RecordingSigner<'a> {
        counters: &'a Counters,
        inputs: Mutex<Vec<Vec<u8>>>,
    }

    impl FactSigner for RecordingSigner<'_> {
        fn sign_ed25519(&self, message: &[u8]) -> Option<String> {
            self.counters.signing.fetch_add(1, Ordering::SeqCst);
            self.inputs.lock().unwrap().push(message.to_vec());
            Some(format!("0x{}", "ab".repeat(64)))
        }
    }

    struct RecordingDelivery {
        responses: Mutex<VecDeque<bool>>,
        calls: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl RecordingDelivery {
        fn new(responses: impl IntoIterator<Item = bool>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl ResultDelivery for RecordingDelivery {
        fn deliver(&self, url: &str, body: &[u8]) -> bool {
            self.calls
                .lock()
                .unwrap()
                .push((url.to_owned(), body.to_vec()));
            self.responses.lock().unwrap().pop_front().unwrap_or(false)
        }
    }

    #[test]
    fn missing_malformed_unknown_and_duplicate_authorization_are_dormant() {
        let mut absent = bootstrap(None);
        assert!(take_processor_fact_authorization(&mut absent).is_none());
        assert!(absent.processor_facts.is_none());

        for raw in [
            json!("not-an-object"),
            {
                let mut value = authorization_value(&["cargo_execution_surface.v1"]);
                value["unknown"] = json!(true);
                value
            },
            authorization_value(&["future_fact.v1"]),
            authorization_value(&["cargo_execution_surface.v1", "cargo_execution_surface.v1"]),
        ] {
            let mut response = bootstrap(Some(raw));
            assert!(take_processor_fact_authorization(&mut response).is_none());
            assert!(response.processor_facts.is_none());
        }
    }

    #[test]
    fn absent_authorization_performs_no_hash_fact_signing_or_delivery_work() {
        let counters = Counters::default();
        let delivery = RecordingDelivery::new([true]);
        let mut response = bootstrap(None);

        if let Some(authorization) = take_processor_fact_authorization(&mut response) {
            let clock = FixedClock(NOW);
            let hasher = CountingHasher {
                counters: &counters,
                digest: HELPER_DIGEST,
            };
            let android = CountingAndroid(&counters);
            let execution = CountingExecution(&counters);
            let egress = CountingEgress(&counters);
            let signer = RecordingSigner {
                counters: &counters,
                inputs: Mutex::new(Vec::new()),
            };
            let dependencies = ProcessorFactWorkerDependencies {
                clock: &clock,
                executable_hasher: &hasher,
                android: &android,
                execution: &execution,
                egress: &egress,
                signer: &signer,
                delivery: &delivery,
            };
            run_processor_fact_worker(&authorization, &binding(), &dependencies).unwrap();
        }

        assert_eq!(counters.hash.load(Ordering::SeqCst), 0);
        assert_eq!(counters.android.load(Ordering::SeqCst), 0);
        assert_eq!(counters.execution.load(Ordering::SeqCst), 0);
        assert_eq!(counters.egress.load(Ordering::SeqCst), 0);
        assert_eq!(counters.signing.load(Ordering::SeqCst), 0);
        assert!(delivery.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn malformed_processor_facts_never_fail_the_authenticated_bootstrap() {
        let request = crate::protocol::SignedRuntimeBootstrapRequest {
            domain: crate::protocol::RUNTIME_BOOTSTRAP_REQUEST_DOMAIN_V2,
            job_id: "job".into(),
            processor_id: "processor".into(),
            nonce: "instance".into(),
            issued_at_ms: NOW,
            expires_at_ms: NOW + 60_000,
            signature: format!("0x{}", "ab".repeat(64)),
        };
        // RuntimeBootstrapResponse is deserialize-only, so build the wire value.
        let body = json!({
            "ok": true,
            "domain": "proof.liskov.runtime-bootstrap-response.v2",
            "applicationUid": "app-uid",
            "applicationId": "app-id",
            "policyDigest": "sha256:policy",
            "deploymentId": "deployment",
            "jobId": "job",
            "processorId": "processor",
            "runtimeInstanceId": "instance",
            "slipwayUrl": "https://liskov.example",
            "processorFacts": {"future": true},
        });
        let mut parsed =
            crate::protocol::validate_response(&request, &serde_json::to_vec(&body).unwrap())
                .unwrap();
        assert!(take_processor_fact_authorization(&mut parsed).is_none());
    }

    #[test]
    fn expired_wrong_version_catalog_and_executable_digest_read_no_facts() {
        let counters = Counters::default();
        let clock = FixedClock(NOW);
        let hasher = CountingHasher {
            counters: &counters,
            digest: HELPER_DIGEST,
        };
        let android = CountingAndroid(&counters);
        let execution = CountingExecution(&counters);
        let egress = CountingEgress(&counters);
        let signer = RecordingSigner {
            counters: &counters,
            inputs: Mutex::new(Vec::new()),
        };
        let delivery = RecordingDelivery::new([]);
        let dependencies = ProcessorFactWorkerDependencies {
            clock: &clock,
            executable_hasher: &hasher,
            android: &android,
            execution: &execution,
            egress: &egress,
            signer: &signer,
            delivery: &delivery,
        };

        let mut expired = authorization(&["cargo_execution_surface.v1"]);
        expired.issued_at_ms = NOW - 300_000;
        expired.expires_at_ms = NOW;
        assert!(run_processor_fact_worker(&expired, &binding(), &dependencies).is_err());
        assert_eq!(counters.hash.load(Ordering::SeqCst), 0);

        let mut wrong_version = authorization(&["cargo_execution_surface.v1"]);
        wrong_version.expected_helper_version = "0.0.0".into();
        assert!(run_processor_fact_worker(&wrong_version, &binding(), &dependencies).is_err());
        assert_eq!(counters.hash.load(Ordering::SeqCst), 0);

        let mut wrong_catalog = authorization(&["cargo_execution_surface.v1"]);
        wrong_catalog.catalog_digest = format!("sha256:{}", "bb".repeat(32));
        assert!(run_processor_fact_worker(&wrong_catalog, &binding(), &dependencies).is_err());
        assert_eq!(counters.hash.load(Ordering::SeqCst), 0);

        let mut wrong_executable = authorization(&["cargo_execution_surface.v1"]);
        wrong_executable.expected_helper_digest = format!("sha256:{}", "cc".repeat(32));
        assert!(run_processor_fact_worker(&wrong_executable, &binding(), &dependencies).is_err());
        assert_eq!(counters.hash.load(Ordering::SeqCst), 1);
        assert_eq!(counters.execution.load(Ordering::SeqCst), 0);
        assert_eq!(counters.signing.load(Ordering::SeqCst), 0);
        assert!(delivery.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn only_due_dimensions_are_collected_and_ordered_by_catalog() {
        let counters = Counters::default();
        let clock = FixedClock(NOW);
        let hasher = CountingHasher {
            counters: &counters,
            digest: HELPER_DIGEST,
        };
        let android = CountingAndroid(&counters);
        let execution = CountingExecution(&counters);
        let egress = CountingEgress(&counters);
        let signer = RecordingSigner {
            counters: &counters,
            inputs: Mutex::new(Vec::new()),
        };
        let delivery = RecordingDelivery::new([true]);
        let dependencies = ProcessorFactWorkerDependencies {
            clock: &clock,
            executable_hasher: &hasher,
            android: &android,
            execution: &execution,
            egress: &egress,
            signer: &signer,
            delivery: &delivery,
        };
        let authorization =
            authorization(&["cargo_control_egress.v1", "cargo_android_corroboration.v1"]);
        run_processor_fact_worker(&authorization, &binding(), &dependencies).unwrap();
        assert_eq!(counters.android.load(Ordering::SeqCst), 1);
        assert_eq!(counters.execution.load(Ordering::SeqCst), 0);
        assert_eq!(counters.egress.load(Ordering::SeqCst), 1);
        let calls = delivery.calls.lock().unwrap();
        let body: Value = serde_json::from_slice(&calls[0].1).unwrap();
        assert_eq!(body["facts"][0]["kind"], "cargo_android_corroboration.v1");
        assert_eq!(body["facts"][1]["kind"], "cargo_control_egress.v1");
    }

    #[test]
    fn result_signature_digest_bound_and_retry_bytes_are_canonical_and_identical() {
        let counters = Counters::default();
        let clock = FixedClock(NOW);
        let hasher = CountingHasher {
            counters: &counters,
            digest: HELPER_DIGEST,
        };
        let android = CountingAndroid(&counters);
        let execution = CountingExecution(&counters);
        let egress = CountingEgress(&counters);
        let signer = RecordingSigner {
            counters: &counters,
            inputs: Mutex::new(Vec::new()),
        };
        let delivery = RecordingDelivery::new([false, false]);
        let dependencies = ProcessorFactWorkerDependencies {
            clock: &clock,
            executable_hasher: &hasher,
            android: &android,
            execution: &execution,
            egress: &egress,
            signer: &signer,
            delivery: &delivery,
        };
        run_processor_fact_worker(
            &authorization(&["cargo_execution_surface.v1"]),
            &binding(),
            &dependencies,
        )
        .unwrap();

        let calls = delivery.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], calls[1]);
        assert_eq!(
            calls[0].0,
            "https://liskov.example/api/jobs/processor-facts"
        );
        assert!(calls[0].1.len() <= MAX_RESULT_BYTES);
        let mut signed: Value = serde_json::from_slice(&calls[0].1).unwrap();
        assert!(signed.get("origin").is_none());
        assert!(signed.get("organizationId").is_none());
        assert!(signed.get("applicationId").is_none());
        let facts_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(canonical_json_bytes(&signed["facts"])))
        );
        assert_eq!(signed["factsDigest"], facts_digest);
        signed.as_object_mut().unwrap().remove("signature");
        let signature_input = signer.inputs.lock().unwrap();
        assert_eq!(signature_input.as_slice(), &[canonical_json_bytes(&signed)]);
    }

    #[test]
    fn failed_delivery_is_not_retried_after_authorization_expiry() {
        let counters = Counters::default();
        let authorization = authorization(&["cargo_execution_surface.v1"]);
        let clock = SequenceClock::new(
            [NOW, NOW, NOW, NOW, authorization.expires_at_ms],
            authorization.expires_at_ms,
        );
        let hasher = CountingHasher {
            counters: &counters,
            digest: HELPER_DIGEST,
        };
        let android = CountingAndroid(&counters);
        let execution = CountingExecution(&counters);
        let egress = CountingEgress(&counters);
        let signer = RecordingSigner {
            counters: &counters,
            inputs: Mutex::new(Vec::new()),
        };
        let delivery = RecordingDelivery::new([false, true]);
        let dependencies = ProcessorFactWorkerDependencies {
            clock: &clock,
            executable_hasher: &hasher,
            android: &android,
            execution: &execution,
            egress: &egress,
            signer: &signer,
            delivery: &delivery,
        };

        run_processor_fact_worker(&authorization, &binding(), &dependencies).unwrap();

        assert_eq!(delivery.calls.lock().unwrap().len(), 1);
    }

    fn samsung_reader(include_brand: bool) -> FixturePropertyReader {
        const CONTEXT: &str = "u:object_r:build_prop:s0";
        let names = ANDROID_PROPERTIES.map(|(name, _)| name);
        let mut values = vec![
            ("ro.build.version.release", "13"),
            ("ro.build.version.sdk", "33"),
            ("ro.build.version.security_patch", "2023-09-01"),
            ("ro.product.manufacturer", "samsung"),
            ("ro.product.model", "SM-S135DL"),
            ("ro.product.name", "a03sutfnssu"),
            ("ro.product.device", "a03su"),
            ("ro.board.platform", "mt6765"),
        ];
        if include_brand {
            values.push(("ro.product.brand", "samsung"));
        }
        FixturePropertyReader {
            files: BTreeMap::from([
                (
                    PROPERTY_INFO_PATH.to_owned(),
                    Ok(fixture_property_info(CONTEXT, &names)),
                ),
                (
                    format!("{PROPERTY_DIRECTORY}/{CONTEXT}"),
                    Ok(fixture_property_area(&values)),
                ),
            ]),
        }
    }

    #[test]
    fn samsung_android_13_fixture_and_explicit_missing_field_are_exact() {
        let fact = collect_android_properties(&samsung_reader(false));
        assert!(
            matches!(fact.android_release, Availability::Observed { ref value } if value == "13")
        );
        assert!(matches!(fact.sdk_level, Availability::Observed { ref value } if value == "33"));
        assert!(
            matches!(fact.security_patch, Availability::Observed { ref value } if value == "2023-09-01")
        );
        assert!(matches!(fact.model, Availability::Observed { ref value } if value == "SM-S135DL"));
        assert!(matches!(fact.device, Availability::Observed { ref value } if value == "a03su"));
        assert!(
            matches!(fact.board_platform, Availability::Observed { ref value } if value == "mt6765")
        );
        assert!(matches!(fact.brand, Availability::NotPresent));
    }

    #[test]
    fn property_info_and_area_corruption_fail_closed_by_class() {
        let mut truncated = samsung_reader(true);
        truncated
            .files
            .insert(PROPERTY_INFO_PATH.into(), Ok(vec![1, 0, 0]));
        assert!(matches!(
            collect_android_properties(&truncated).model,
            Availability::ParseError
        ));

        let mut unknown_info = samsung_reader(true);
        let info = unknown_info
            .files
            .get_mut(PROPERTY_INFO_PATH)
            .unwrap()
            .as_mut()
            .unwrap();
        patch_u32(info, 0, 2);
        assert!(matches!(
            collect_android_properties(&unknown_info).model,
            Availability::Unsupported
        ));

        let mut corrupt_offset = samsung_reader(true);
        let info = corrupt_offset
            .files
            .get_mut(PROPERTY_INFO_PATH)
            .unwrap()
            .as_mut()
            .unwrap();
        // Explicitly write the largest representable wire offset.
        info[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            collect_android_properties(&corrupt_offset).model,
            Availability::ParseError
        ));

        const CONTEXT: &str = "u:object_r:build_prop:s0";
        let mut unknown_area = samsung_reader(true);
        let area = unknown_area
            .files
            .get_mut(&format!("{PROPERTY_DIRECTORY}/{CONTEXT}"))
            .unwrap()
            .as_mut()
            .unwrap();
        patch_u32(area, 12, 0);
        assert!(matches!(
            collect_android_properties(&unknown_area).model,
            Availability::Unsupported
        ));

        let mut truncated_area = samsung_reader(true);
        truncated_area
            .files
            .get_mut(&format!("{PROPERTY_DIRECTORY}/{CONTEXT}"))
            .unwrap()
            .as_mut()
            .unwrap()
            .truncate(PROPERTY_AREA_HEADER_BYTES + 4);
        assert!(matches!(
            collect_android_properties(&truncated_area).model,
            Availability::ParseError
        ));
    }

    #[test]
    fn unavailable_permission_unsafe_oversized_and_disappearing_files_are_explicit() {
        for (failure, expected) in [
            (FileReadFailure::NotFound, "surface_hidden"),
            (FileReadFailure::PermissionDenied, "permission_denied"),
            (FileReadFailure::UnsafeFile, "unsupported"),
            (FileReadFailure::TooLarge, "unsupported"),
            (FileReadFailure::Unavailable, "surface_hidden"),
        ] {
            let reader = FixturePropertyReader {
                files: BTreeMap::from([(PROPERTY_INFO_PATH.into(), Err(failure))]),
            };
            let value = serde_json::to_value(collect_android_properties(&reader)).unwrap();
            assert_eq!(value["model"]["status"], expected);
        }
    }

    #[test]
    fn secure_reader_rejects_symlinks_without_following_them() {
        let unique = format!(
            "/tmp/liskov-property-symlink-{}-{}",
            std::process::id(),
            NOW
        );
        let _ = std::fs::remove_file(&unique);
        symlink("/etc/passwd", &unique).unwrap();
        let result = SecurePropertyFileReader.read(&unique, &mut PropertyReadBudget::new());
        std::fs::remove_file(&unique).unwrap();
        assert_eq!(result.unwrap_err(), FileReadFailure::UnsafeFile);
    }

    #[test]
    fn property_info_absence_uses_only_compiled_contexts() {
        let area = fixture_property_area(&[("ro.product.model", "SM-S135DL")]);
        let reader = FixturePropertyReader {
            files: BTreeMap::from([(
                format!("{PROPERTY_DIRECTORY}/{}", FALLBACK_CONTEXTS[0]),
                Ok(area),
            )]),
        };
        let fact = collect_android_properties(&reader);
        assert!(matches!(fact.model, Availability::Observed { ref value } if value == "SM-S135DL"));
        assert!(matches!(fact.manufacturer, Availability::NotPresent));
    }

    #[test]
    fn android_serializer_has_no_generic_or_forbidden_field_surface() {
        let serialized =
            serde_json::to_value(collect_android_properties(&samsung_reader(true))).unwrap();
        let object = serialized.as_object().unwrap();
        assert_eq!(object.len(), ANDROID_PROPERTIES.len());
        for forbidden in [
            "imei",
            "serial",
            "androidId",
            "advertisingId",
            "mac",
            "ssid",
            "ipAddress",
            "environment",
            "customer",
            "socName",
            "phoneName",
        ] {
            assert!(object.get(forbidden).is_none());
        }
    }

    struct FixtureLinux {
        page: Result<u64, LinuxReadFailure>,
        release: Result<String, LinuxReadFailure>,
        status: Result<String, LinuxReadFailure>,
    }

    impl LinuxSystemReader for FixtureLinux {
        fn page_size(&self) -> Result<u64, LinuxReadFailure> {
            self.page
        }

        fn kernel_release(&self) -> Result<String, LinuxReadFailure> {
            self.release.clone()
        }

        fn proc_status(&self) -> Result<String, LinuxReadFailure> {
            self.status.clone()
        }
    }

    #[test]
    fn execution_surface_parses_page_kernel_status_and_capability_class() {
        for (capability, expected) in [
            ("0000000000000000", CapabilityClass::None),
            ("0000000000000001", CapabilityClass::Nonzero),
        ] {
            let fact = collect_execution_surface(&FixtureLinux {
                page: Ok(4096),
                release: Ok("4.19.157-perf+vendor-label".into()),
                status: Ok(format!(
                    "Name:\ttest\nNoNewPrivs:\t1\nSeccomp:\t2\nCapEff:\t{capability}\n"
                )),
            });
            assert!(matches!(
                fact.page_size_bytes,
                Availability::Observed { value: 4096 }
            ));
            assert!(matches!(
                fact.kernel_abi,
                Availability::Observed {
                    value: KernelAbi {
                        major: 4,
                        minor: 19
                    }
                }
            ));
            assert!(matches!(
                fact.no_new_privs,
                Availability::Observed { value: true }
            ));
            assert!(matches!(
                fact.seccomp,
                Availability::Observed {
                    value: SeccompClass::Filter
                }
            ));
            assert!(
                matches!(fact.effective_capabilities, Availability::Observed { ref value } if *value == expected)
            );
            let serialized = serde_json::to_string(&fact).unwrap();
            assert!(!serialized.contains("vendor-label"));
            assert!(!serialized.contains(capability));
        }
    }

    #[test]
    fn execution_read_failures_and_malformed_values_are_explicit() {
        let fact = collect_execution_surface(&FixtureLinux {
            page: Err(LinuxReadFailure::Unsupported),
            release: Ok("raw-label".into()),
            status: Err(LinuxReadFailure::PermissionDenied),
        });
        assert!(matches!(fact.page_size_bytes, Availability::Unsupported));
        assert!(matches!(fact.kernel_abi, Availability::ParseError));
        assert!(matches!(fact.no_new_privs, Availability::PermissionDenied));
        assert!(matches!(fact.seccomp, Availability::PermissionDenied));
        assert!(matches!(
            fact.effective_capabilities,
            Availability::PermissionDenied
        ));
    }

    struct FixtureResolver(Result<Vec<SocketAddr>, EgressResolutionFailure>);

    impl EgressResolver for FixtureResolver {
        fn resolve(
            &self,
            _host: &str,
            _port: u16,
        ) -> Result<Vec<SocketAddr>, EgressResolutionFailure> {
            self.0.clone()
        }
    }

    struct FixtureRequester {
        ipv4: FamilyRequestResult,
        ipv6: FamilyRequestResult,
        calls: Mutex<Vec<SocketAddr>>,
    }

    impl FamilyRequester for FixtureRequester {
        fn request(&self, _endpoint: &str, address: SocketAddr) -> FamilyRequestResult {
            self.calls.lock().unwrap().push(address);
            if address.is_ipv4() {
                self.ipv4.clone()
            } else {
                self.ipv6.clone()
            }
        }
    }

    fn family_result(outcome: EgressOutcome) -> FamilyRequestResult {
        FamilyRequestResult {
            outcome,
            duration_ms: 7,
            status_class: (outcome == EgressOutcome::Success).then(|| "2xx".into()),
        }
    }

    #[test]
    fn egress_handles_ipv4_ipv6_dual_stack_dns_failure_and_closed_outcomes() {
        let endpoint = "https://liskov.example/api/jobs/processor-facts/egress";
        let v4: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        for (addresses, expected_v4, expected_v6, calls) in [
            (
                vec![v4],
                EgressOutcome::Success,
                EgressOutcome::NoFamilyAddress,
                1,
            ),
            (
                vec![v6],
                EgressOutcome::NoFamilyAddress,
                EgressOutcome::Success,
                1,
            ),
            (
                vec![v4, v6],
                EgressOutcome::Success,
                EgressOutcome::Success,
                2,
            ),
        ] {
            let requester = FixtureRequester {
                ipv4: family_result(EgressOutcome::Success),
                ipv6: family_result(EgressOutcome::Success),
                calls: Mutex::new(Vec::new()),
            };
            let fact =
                collect_control_egress(endpoint, &FixtureResolver(Ok(addresses)), &requester);
            assert_eq!(fact.ipv4.outcome, expected_v4);
            assert_eq!(fact.ipv6.outcome, expected_v6);
            assert_eq!(requester.calls.lock().unwrap().len(), calls);
            let serialized = serde_json::to_string(&fact).unwrap();
            assert!(!serialized.contains("192.0.2.1"));
            assert!(!serialized.contains("2001:db8"));
            assert!(!serialized.contains("liskov.example"));
        }

        let requester = FixtureRequester {
            ipv4: family_result(EgressOutcome::Success),
            ipv6: family_result(EgressOutcome::Success),
            calls: Mutex::new(Vec::new()),
        };
        let fact = collect_control_egress(
            endpoint,
            &FixtureResolver(Err(EgressResolutionFailure)),
            &requester,
        );
        assert_eq!(fact.ipv4.outcome, EgressOutcome::DnsFailed);
        assert_eq!(fact.ipv6.outcome, EgressOutcome::DnsFailed);
        assert!(requester.calls.lock().unwrap().is_empty());

        for outcome in [
            EgressOutcome::ConnectionFailed,
            EgressOutcome::Timeout,
            EgressOutcome::TransportOrTlsFailed,
            EgressOutcome::HttpUnexpectedStatus,
            EgressOutcome::ResponseTooLarge,
            EgressOutcome::InternalError,
        ] {
            let requester = FixtureRequester {
                ipv4: family_result(outcome),
                ipv6: family_result(EgressOutcome::Success),
                calls: Mutex::new(Vec::new()),
            };
            let fact = collect_control_egress(endpoint, &FixtureResolver(Ok(vec![v4])), &requester);
            assert_eq!(fact.ipv4.outcome, outcome);
        }
    }

    #[test]
    fn future_clock_tolerance_and_five_minute_lifetime_are_strict() {
        let mut value = authorization_value(&["cargo_execution_surface.v1"]);
        value["issuedAtMs"] = json!(NOW + AUTHORIZATION_FUTURE_TOLERANCE_MS + 1);
        value["expiresAtMs"] = json!(NOW + AUTHORIZATION_FUTURE_TOLERANCE_MS + 2);
        let auth: ProcessorFactAuthorization = serde_json::from_value(value).unwrap();
        assert!(!auth.valid_at(NOW));

        let mut too_long = authorization_value(&["cargo_execution_surface.v1"]);
        too_long["issuedAtMs"] = json!(NOW);
        too_long["expiresAtMs"] = json!(NOW + MAX_AUTHORIZATION_LIFETIME_MS + 1);
        let mut response = bootstrap(Some(too_long));
        assert!(take_processor_fact_authorization(&mut response).is_none());
    }
}
