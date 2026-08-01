//! Policy-gated, bounded stdout/stderr forwarding to the canonical Blackbox sink.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::process::{Child, ChildStderr, ChildStdout};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::diagnostics::canonical_json_bytes;
use crate::protocol::RuntimeBootstrapResponse;

const BLACKBOX_CONFIG_ENV: &str = "BLACKBOX_LOG_CONFIG";
const BLACKBOX_CONFIG_DOMAIN_V2: &str = "proof.liskov.blackbox-log-config.v2";
const WRITER_KEY_DERIVATION: &str = "hkdf-sha256-ed25519-v1";
const WRITER_KEY_SALT: &[u8] = b"proof.liskov.blackbox.writer-key.v1";
const WRITER_KEY_INFO: &[u8] = b"Ed25519";
const OUTPUT_CHUNK_BYTES: usize = 3 * 1024;
const OUTPUT_QUEUE_CAPACITY: usize = 128;
const OUTPUT_BYTES_PER_SECOND: u64 = 256 * 1024;
const MAX_BATCH_RECORDS: usize = 32;
const MAX_BATCH_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_SEQUENCE_REBASE_ATTEMPTS: usize = 3;
const MIN_REQUEST_INTERVAL: Duration = Duration::from_millis(100);
const OUTPUT_FLUSH_GRACE: Duration = Duration::from_millis(250);

const BLACKBOX_ENV_NAMES: [&str; 18] = [
    "BLACKBOX_LOG_CONFIG",
    "BLACKBOX_SINK_ID",
    "BLACKBOX_JOB_ID",
    "BLACKBOX_WRITE_URL",
    "BLACKBOX_RESUME_URL",
    "BLACKBOX_LOG_DEK",
    "BLACKBOX_LOG_CONTEXT",
    "BLACKBOX_LOG_TIMEOUT_MS",
    "BLACKBOX_FACTORY_TOKEN",
    "BLACKBOX_FACTORY_ID",
    "BLACKBOX_BASE_URL",
    "BLACKBOX_SPOOL_DIR",
    "BLACKBOX_NETWORK",
    "BLACKBOX_APPLICATION_UID",
    "BLACKBOX_APPLICATION_ID",
    "BLACKBOX_DEPLOYMENT_ID",
    "BLACKBOX_WRITER_KEY_DERIVATION",
    "BLACKBOX_RUNTIME_INSTANCE_ID",
];

pub fn is_blackbox_environment_name(name: &str) -> bool {
    BLACKBOX_ENV_NAMES.contains(&name)
}

#[derive(Clone)]
enum SinkMode {
    Prebound {
        sink_id: String,
        job_id: String,
        write_url: String,
        resume_url: String,
    },
    Factory {
        factory_token: String,
        factory_id: String,
        base_url: String,
        job_id: String,
        network: Option<String>,
        application_uid: String,
        application_id: String,
        deployment_id: String,
    },
}

#[derive(Clone)]
struct BlackboxConfig {
    mode: SinkMode,
    dek: [u8; 32],
    context: Option<String>,
    timeout: Duration,
}

#[derive(Clone)]
struct RuntimeLabels {
    application_uid: String,
    deployment_id: String,
    runtime_instance_id: String,
}

#[derive(Default)]
struct DroppedOutput {
    chunks: AtomicU64,
    bytes: AtomicU64,
}

impl DroppedOutput {
    fn record(&self, bytes: usize) {
        let _ = self
            .chunks
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(1))
            });
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        let _ = self
            .bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(bytes))
            });
    }

    fn take(&self) -> Option<(u64, u64)> {
        let chunks = self.chunks.swap(0, Ordering::Relaxed);
        let bytes = self.bytes.swap(0, Ordering::Relaxed);
        (chunks != 0 || bytes != 0).then_some((chunks, bytes))
    }
}

struct ByteBudget {
    window_started: Instant,
    admitted: u64,
}

impl ByteBudget {
    fn new() -> Self {
        Self {
            window_started: Instant::now(),
            admitted: 0,
        }
    }

    fn admit(&mut self, bytes: usize) -> bool {
        if self.window_started.elapsed() >= Duration::from_secs(1) {
            self.window_started = Instant::now();
            self.admitted = 0;
        }
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        let Some(next) = self.admitted.checked_add(bytes) else {
            return false;
        };
        if next > OUTPUT_BYTES_PER_SECOND {
            return false;
        }
        self.admitted = next;
        true
    }
}

#[derive(Clone)]
struct OutputChunk {
    output_sequence: u64,
    process_attempt: u64,
    stream: &'static str,
    timestamp: String,
    bytes: Vec<u8>,
}

enum LogWork {
    Chunk(OutputChunk),
    Finish(std::sync::mpsc::Sender<()>),
}

pub struct OutputLogger {
    sender: Option<SyncSender<LogWork>>,
    dropped: Arc<DroppedOutput>,
    budget: Arc<Mutex<ByteBudget>>,
    next_output_sequence: Arc<AtomicU64>,
}

impl OutputLogger {
    /// Enables capture only when both the signed bootstrap policy decision and
    /// the canonical Blackbox configuration are valid. Invalid or absent
    /// configuration preserves ordinary inherited output and customer startup.
    pub fn from_environment(bootstrap: &RuntimeBootstrapResponse) -> Option<Self> {
        if !bootstrap.logging_enabled() {
            return None;
        }
        let raw = std::env::var(BLACKBOX_CONFIG_ENV).ok()?;
        let config = BlackboxConfig::parse(&raw, bootstrap).ok()?;
        let http: Arc<dyn LogHttpClient> = if bootstrap.logging_outage_canary_enabled() {
            Arc::new(OutageCanaryHttp)
        } else {
            Arc::new(UreqLogHttpClient::new(config.timeout))
        };
        Self::spawn(config, RuntimeLabels::from(bootstrap), http)
    }

    fn spawn(
        config: BlackboxConfig,
        labels: RuntimeLabels,
        http: Arc<dyn LogHttpClient>,
    ) -> Option<Self> {
        let dropped = Arc::new(DroppedOutput::default());
        let (sender, receiver) = sync_channel(OUTPUT_QUEUE_CAPACITY);
        let worker_dropped = dropped.clone();
        thread::Builder::new()
            .name("liskov-cargo-output".into())
            .spawn(move || {
                if let Some(worker) = LogWorker::new(config, labels, http, worker_dropped) {
                    worker.run(receiver);
                }
            })
            .ok()?;
        Some(Self {
            sender: Some(sender),
            dropped,
            budget: Arc::new(Mutex::new(ByteBudget::new())),
            next_output_sequence: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn capture_child(&self, child: &mut Child, process_attempt: u64) -> OutputAttempt {
        let mut readers = Vec::new();
        if let Some(stdout) = child.stdout.take() {
            readers.push(spawn_reader(
                stdout,
                std::io::stdout(),
                "stdout",
                process_attempt,
                self.sender.as_ref().cloned(),
                self.dropped.clone(),
                self.budget.clone(),
                self.next_output_sequence.clone(),
            ));
        }
        if let Some(stderr) = child.stderr.take() {
            readers.push(spawn_reader(
                stderr,
                std::io::stderr(),
                "stderr",
                process_attempt,
                self.sender.as_ref().cloned(),
                self.dropped.clone(),
                self.budget.clone(),
                self.next_output_sequence.clone(),
            ));
        }
        OutputAttempt { readers }
    }

    pub fn finish(&mut self) {
        let Some(sender) = self.sender.take() else {
            return;
        };
        let (acknowledge, acknowledged) = std::sync::mpsc::channel();
        if sender.try_send(LogWork::Finish(acknowledge)).is_ok() {
            let _ = acknowledged.recv_timeout(OUTPUT_FLUSH_GRACE);
        }
    }

    #[cfg(test)]
    fn enqueue_for_test(&self, chunk: OutputChunk) {
        enqueue_chunk(self.sender.as_ref(), &self.dropped, &self.budget, chunk);
    }
}

/// Exact-application release-canary transport selected only by the bound
/// bootstrap response. It proves that a total logging outage cannot apply
/// backpressure to customer output or alter the customer result.
struct OutageCanaryHttp;

impl LogHttpClient for OutageCanaryHttp {
    fn post(
        &self,
        _url: &str,
        _headers: &[(String, String)],
        _body: &[u8],
    ) -> Result<LogHttpResponse, ()> {
        Err(())
    }
}

impl Drop for OutputLogger {
    fn drop(&mut self) {
        self.finish();
    }
}

pub struct OutputAttempt {
    readers: Vec<OutputReader>,
}

impl OutputAttempt {
    pub fn finish(self) {
        for reader in self.readers {
            if reader.finished.recv_timeout(OUTPUT_FLUSH_GRACE).is_ok() {
                let _ = reader.handle.join();
            }
        }
    }
}

struct OutputReader {
    handle: JoinHandle<()>,
    finished: Receiver<()>,
}

trait OutputRead: Read + Send + 'static {}
impl OutputRead for ChildStdout {}
impl OutputRead for ChildStderr {}

#[allow(clippy::too_many_arguments)]
fn spawn_reader<R, W>(
    mut source: R,
    mut local: W,
    stream: &'static str,
    process_attempt: u64,
    sender: Option<SyncSender<LogWork>>,
    dropped: Arc<DroppedOutput>,
    budget: Arc<Mutex<ByteBudget>>,
    next_output_sequence: Arc<AtomicU64>,
) -> OutputReader
where
    R: OutputRead,
    W: Write + Send + 'static,
{
    let (finished_sender, finished) = std::sync::mpsc::channel();
    let handle = thread::spawn(move || {
        let mut buffer = [0_u8; OUTPUT_CHUNK_BYTES];
        loop {
            let size = match source.read(&mut buffer) {
                Ok(0) => break,
                Ok(size) => size,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            let output_sequence = next_output_sequence.fetch_add(1, Ordering::Relaxed);
            let bytes = buffer[..size].to_vec();
            // The local output path remains authoritative and independent of
            // network admission or delivery.
            let _ = local.write_all(&bytes);
            let _ = local.flush();
            enqueue_chunk(
                sender.as_ref(),
                &dropped,
                &budget,
                OutputChunk {
                    output_sequence,
                    process_attempt,
                    stream,
                    timestamp: utc_timestamp(),
                    bytes,
                },
            );
        }
        let _ = finished_sender.send(());
    });
    OutputReader { handle, finished }
}

fn enqueue_chunk(
    sender: Option<&SyncSender<LogWork>>,
    dropped: &DroppedOutput,
    budget: &Mutex<ByteBudget>,
    chunk: OutputChunk,
) {
    let admitted = budget
        .lock()
        .is_ok_and(|mut budget| budget.admit(chunk.bytes.len()));
    if !admitted {
        dropped.record(chunk.bytes.len());
        return;
    }
    let Some(sender) = sender else {
        dropped.record(chunk.bytes.len());
        return;
    };
    match sender.try_send(LogWork::Chunk(chunk)) {
        Ok(()) => {}
        Err(TrySendError::Full(LogWork::Chunk(chunk)))
        | Err(TrySendError::Disconnected(LogWork::Chunk(chunk))) => {
            dropped.record(chunk.bytes.len());
        }
        Err(TrySendError::Full(LogWork::Finish(_)))
        | Err(TrySendError::Disconnected(LogWork::Finish(_))) => unreachable!(),
    }
}

impl RuntimeLabels {
    fn from(bootstrap: &RuntimeBootstrapResponse) -> Self {
        Self {
            application_uid: bootstrap.application_uid.clone(),
            deployment_id: bootstrap.deployment_id.clone(),
            runtime_instance_id: bootstrap.runtime_instance_id.clone(),
        }
    }
}

impl BlackboxConfig {
    fn parse(raw: &str, bootstrap: &RuntimeBootstrapResponse) -> Result<Self, ()> {
        let value = parse_config_value(raw)?;
        let object = value.as_object().ok_or(())?;
        let domain = field(object, &["domain", "d"]);
        if domain.is_some_and(|domain| domain != BLACKBOX_CONFIG_DOMAIN_V2) {
            return Err(());
        }
        let application_uid = field(object, &["applicationUid", "uid"]);
        let application_id = field(object, &["applicationId", "app"]);
        if domain == Some(BLACKBOX_CONFIG_DOMAIN_V2)
            && (application_uid.is_none() || application_id.is_none())
        {
            return Err(());
        }
        if application_uid.is_some_and(|uid| uid != bootstrap.application_uid)
            || application_id.is_some_and(|id| id != bootstrap.application_id)
            || field(object, &["deploymentId", "dep"])
                .is_some_and(|id| id != bootstrap.deployment_id)
        {
            return Err(());
        }
        if field(object, &["writerKeyDerivation", "wkd"])
            .is_some_and(|value| value != WRITER_KEY_DERIVATION)
        {
            return Err(());
        }
        let dek_text = field(object, &["dek", "k", "logDek"]).ok_or(())?;
        let dek: [u8; 32] = URL_SAFE_NO_PAD
            .decode(dek_text)
            .map_err(|_| ())?
            .try_into()
            .map_err(|_| ())?;
        let context = object
            .get("context")
            .or_else(|| object.get("ctx"))
            .map(|value| {
                value.as_str().map(str::to_string).unwrap_or_else(|| {
                    String::from_utf8_lossy(&canonical_json_bytes(value)).into_owned()
                })
            });
        let timeout_ms = integer_field(object, &["timeoutMs", "flushTimeoutMs"])
            .filter(|timeout| *timeout > 0)
            .unwrap_or(5_000)
            .min(5_000);
        let timeout = Duration::from_millis(timeout_ms);

        let sink_id = field(object, &["sinkId", "sid"]);
        let factory_token = field(object, &["factoryToken", "ft"]);
        let mode = if let (Some(sink_id), None) = (sink_id, factory_token) {
            let job_id = field(object, &["jobId", "jid", "job"]).ok_or(())?;
            if job_id != bootstrap.job_id {
                return Err(());
            }
            let write_url = normalized_https_url(field(object, &["writeUrl", "url"]).ok_or(())?)?;
            let resume_url = match field(object, &["resumeUrl"]) {
                Some(url) => normalized_https_url(url)?,
                None => derive_resume_url(&write_url).ok_or(())?,
            };
            SinkMode::Prebound {
                sink_id: sink_id.to_string(),
                job_id: job_id.to_string(),
                write_url,
                resume_url,
            }
        } else if let (None, Some(factory_token)) = (sink_id, factory_token) {
            let factory_id = field(object, &["factoryId", "fid"])
                .map(str::to_string)
                .or_else(|| parse_factory_id(factory_token))
                .ok_or(())?;
            let base_url = normalized_https_url(field(object, &["baseUrl", "base"]).ok_or(())?)?;
            let job_id = field(object, &["jobId", "jid", "job"]).unwrap_or(&bootstrap.job_id);
            if job_id != bootstrap.job_id {
                return Err(());
            }
            SinkMode::Factory {
                factory_token: factory_token.to_string(),
                factory_id,
                base_url,
                job_id: job_id.to_string(),
                network: field(object, &["network", "net"]).map(str::to_string),
                application_uid: application_uid
                    .unwrap_or(&bootstrap.application_uid)
                    .to_string(),
                application_id: application_id
                    .unwrap_or(&bootstrap.application_id)
                    .to_string(),
                deployment_id: field(object, &["deploymentId", "dep"])
                    .unwrap_or(&bootstrap.deployment_id)
                    .to_string(),
            }
        } else {
            return Err(());
        };
        Ok(Self {
            mode,
            dek,
            context,
            timeout,
        })
    }
}

fn parse_config_value(raw: &str) -> Result<Value, ()> {
    let trimmed = raw.trim();
    if trimmed.starts_with('{') {
        return serde_json::from_str(trimmed).map_err(|_| ());
    }
    for decoded in [URL_SAFE_NO_PAD.decode(trimmed), STANDARD.decode(trimmed)]
        .into_iter()
        .flatten()
    {
        if let Ok(value) = serde_json::from_slice(&decoded) {
            return Ok(value);
        }
    }
    Err(())
}

fn field<'a>(object: &'a Map<String, Value>, names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|name| {
        object
            .get(*name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
    })
}

fn integer_field(object: &Map<String, Value>, names: &[&str]) -> Option<u64> {
    names.iter().find_map(|name| {
        object.get(*name).and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str()?.parse::<u64>().ok())
        })
    })
}

fn normalized_https_url(value: &str) -> Result<String, ()> {
    let url = Url::parse(value).map_err(|_| ())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(());
    }
    Ok(url.to_string())
}

fn derive_resume_url(write_url: &str) -> Option<String> {
    let suffix = "/events";
    write_url
        .strip_suffix(suffix)
        .map(|prefix| format!("{prefix}/resume"))
}

fn parse_factory_id(token: &str) -> Option<String> {
    let rest = token.strip_prefix("bbx_sf_")?;
    let (factory_id, secret) = rest.split_once('_')?;
    (!factory_id.is_empty()
        && !secret.is_empty()
        && factory_id.len() <= 128
        && factory_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".:-".contains(&byte)))
    .then(|| factory_id.to_string())
}

#[derive(Clone)]
struct ResolvedSink {
    sink_id: String,
    job_id: String,
    write_url: String,
    resume_url: String,
    next_sequence: u64,
    previous_hash: Option<String>,
}

#[derive(Clone)]
struct EncryptedRecord {
    value: Value,
}

struct WriterKey {
    key_pair: Ed25519KeyPair,
    public_key_hex: String,
}

impl WriterKey {
    fn derive(dek: &[u8; 32]) -> Result<Self, ()> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, WRITER_KEY_SALT);
        let prk = salt.extract(dek);
        let info = [WRITER_KEY_INFO];
        let output = prk.expand(&info, HkdfSeedLength).map_err(|_| ())?;
        let mut seed = [0_u8; 32];
        output.fill(&mut seed).map_err(|_| ())?;
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| ())?;
        let public_key_hex = hex::encode(key_pair.public_key().as_ref());
        Ok(Self {
            key_pair,
            public_key_hex,
        })
    }
}

struct HkdfSeedLength;

impl hkdf::KeyType for HkdfSeedLength {
    fn len(&self) -> usize {
        32
    }
}

trait LogHttpClient: Send + Sync {
    fn post(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<LogHttpResponse, ()>;
}

struct LogHttpResponse {
    status: u16,
    body: Vec<u8>,
}

struct UreqLogHttpClient {
    agent: ureq::Agent,
}

impl UreqLogHttpClient {
    fn new(timeout: Duration) -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout(timeout)
                .redirects(0)
                .build(),
        }
    }
}

impl LogHttpClient for UreqLogHttpClient {
    fn post(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<LogHttpResponse, ()> {
        let mut request = self.agent.post(url).set(
            "user-agent",
            concat!("liskov-runtime-contact/", env!("CARGO_PKG_VERSION")),
        );
        for (name, value) in headers {
            request = request.set(name, value);
        }
        let result = request.send_bytes(body);
        let (status, response) = match result {
            Ok(response) => (response.status(), response),
            Err(ureq::Error::Status(status, response)) => (status, response),
            Err(ureq::Error::Transport(_)) => return Err(()),
        };
        let mut body = Vec::new();
        response
            .into_reader()
            .take(u64::try_from(MAX_RESPONSE_BYTES).unwrap_or(u64::MAX) + 1)
            .read_to_end(&mut body)
            .map_err(|_| ())?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(());
        }
        Ok(LogHttpResponse { status, body })
    }
}

struct LogWorker {
    config: BlackboxConfig,
    labels: RuntimeLabels,
    http: Arc<dyn LogHttpClient>,
    dropped: Arc<DroppedOutput>,
    writer: WriterKey,
    encryption: LessSafeKey,
    resolved: Option<ResolvedSink>,
    pending_records: VecDeque<EncryptedRecord>,
    pending_batch: Option<Value>,
    last_request: Option<Instant>,
}

impl LogWorker {
    fn new(
        config: BlackboxConfig,
        labels: RuntimeLabels,
        http: Arc<dyn LogHttpClient>,
        dropped: Arc<DroppedOutput>,
    ) -> Option<Self> {
        let writer = WriterKey::derive(&config.dek).ok()?;
        let encryption = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &config.dek).ok()?);
        Some(Self {
            config,
            labels,
            http,
            dropped,
            writer,
            encryption,
            resolved: None,
            pending_records: VecDeque::new(),
            pending_batch: None,
            last_request: None,
        })
    }

    fn run(mut self, receiver: Receiver<LogWork>) {
        loop {
            let work = match receiver.recv() {
                Ok(work) => work,
                Err(_) => break,
            };
            match work {
                LogWork::Chunk(chunk) => {
                    self.admit_chunk(chunk);
                    let finish = self.drain_available(&receiver);
                    let _ = self.flush_once();
                    if let Some(acknowledge) = finish {
                        let _ = acknowledge.send(());
                        break;
                    }
                }
                LogWork::Finish(acknowledge) => {
                    let nested_finish = self.drain_available(&receiver);
                    self.admit_drop_evidence();
                    let _ = self.flush_once();
                    let _ = acknowledge.send(());
                    if let Some(acknowledge) = nested_finish {
                        let _ = acknowledge.send(());
                    }
                    break;
                }
            }
        }
    }

    fn drain_available(
        &mut self,
        receiver: &Receiver<LogWork>,
    ) -> Option<std::sync::mpsc::Sender<()>> {
        let mut finish = None;
        while self.pending_records.len() < MAX_BATCH_RECORDS {
            match receiver.try_recv() {
                Ok(LogWork::Chunk(chunk)) => self.admit_chunk(chunk),
                Ok(LogWork::Finish(acknowledge)) => {
                    finish = Some(acknowledge);
                    break;
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        self.admit_drop_evidence();
        finish
    }

    fn admit_chunk(&mut self, chunk: OutputChunk) {
        if self.pending_records.len() >= MAX_BATCH_RECORDS {
            self.dropped.record(chunk.bytes.len());
            return;
        }
        let (encoding, content) = match std::str::from_utf8(&chunk.bytes) {
            Ok(text) => ("utf8", json!({"text": text})),
            Err(_) => (
                "base64url",
                json!({"bytes": URL_SAFE_NO_PAD.encode(&chunk.bytes)}),
            ),
        };
        let mut details = json!({
            "runtimeInstanceId": self.labels.runtime_instance_id,
            "processAttempt": chunk.process_attempt,
            "outputSequence": chunk.output_sequence,
            "stream": chunk.stream,
            "encoding": encoding,
            "byteLength": chunk.bytes.len(),
            "truncated": false,
        });
        if let (Some(target), Some(content)) = (details.as_object_mut(), content.as_object()) {
            target.extend(content.clone());
        }
        let record = self.base_record(chunk.timestamp, "runtime.cargo.output", details);
        if let Ok(record) = self.encrypt_record(&record) {
            self.pending_records.push_back(record);
        } else {
            self.dropped.record(chunk.bytes.len());
        }
    }

    fn admit_drop_evidence(&mut self) {
        if self.pending_records.len() >= MAX_BATCH_RECORDS {
            return;
        }
        let Some((dropped_chunks, dropped_bytes)) = self.dropped.take() else {
            return;
        };
        let record = self.base_record(
            utc_timestamp(),
            "runtime.cargo.output.dropped",
            json!({
                "runtimeInstanceId": self.labels.runtime_instance_id,
                "droppedChunks": dropped_chunks,
                "droppedBytes": dropped_bytes,
                "truncated": true,
            }),
        );
        if let Ok(record) = self.encrypt_record(&record) {
            self.pending_records.push_back(record);
        }
    }

    fn base_record(&self, timestamp: String, event: &str, details: Value) -> Value {
        let mut record = json!({
            "timestamp": timestamp,
            "event": event,
            "details": details,
        });
        if let Some(context) = &self.config.context {
            record["context"] = json!(context);
        }
        record
    }

    fn encrypt_record(&self, record: &Value) -> Result<EncryptedRecord, ()> {
        let mut iv = [0_u8; 12];
        getrandom::fill(&mut iv).map_err(|_| ())?;
        let mut plaintext = serde_json::to_vec(record).map_err(|_| ())?;
        self.encryption
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(iv),
                Aad::empty(),
                &mut plaintext,
            )
            .map_err(|_| ())?;
        let tag = plaintext.split_off(plaintext.len().checked_sub(16).ok_or(())?);
        Ok(EncryptedRecord {
            value: json!({
                "v": 1,
                "alg": "A256GCM",
                "iv": URL_SAFE_NO_PAD.encode(iv),
                "ciphertext": URL_SAFE_NO_PAD.encode(plaintext),
                "tag": URL_SAFE_NO_PAD.encode(tag),
            }),
        })
    }

    fn flush_once(&mut self) -> Result<(), ()> {
        if self.pending_batch.is_none() {
            if self.pending_records.is_empty() {
                return Ok(());
            }
            if self.resolved.is_none() {
                self.resolved = Some(self.resolve_sink()?);
            }
            self.pending_batch = Some(self.build_batch()?);
        }
        let mut attempts = 0;
        loop {
            let batch = self.pending_batch.as_ref().ok_or(())?.clone();
            let write_url = self.resolved.as_ref().ok_or(())?.write_url.clone();
            let response = self.post_signed(&write_url, &batch, &[])?;
            if (200..300).contains(&response.status) {
                let sequence_end = batch["sequenceEnd"].as_u64().ok_or(())?;
                let chain = if let Some(chain) = parse_chain_response(&response.body) {
                    chain
                } else {
                    let resolved = self.resolved.clone().ok_or(())?;
                    self.resume_sink(&resolved.sink_id, &resolved.job_id, &resolved.resume_url)?
                };
                if chain.0 <= sequence_end {
                    return Err(());
                }
                if let Some(resolved) = &mut self.resolved {
                    resolved.next_sequence = chain.0;
                    resolved.previous_hash = chain.1;
                }
                let sent_count = batch["encrypted"].as_array().map(Vec::len).ok_or(())?;
                for _ in 0..sent_count {
                    self.pending_records.pop_front();
                }
                self.pending_batch = None;
                return Ok(());
            }
            if response.status == 409
                && response_error_code(&response.body).as_deref() == Some("sequence_conflict")
                && attempts < MAX_SEQUENCE_REBASE_ATTEMPTS
            {
                let (next_sequence, previous_hash) =
                    parse_chain_response(&response.body).ok_or(())?;
                if let Some(resolved) = &mut self.resolved {
                    resolved.next_sequence = next_sequence;
                    resolved.previous_hash = previous_hash;
                }
                self.pending_batch = Some(self.build_batch()?);
                attempts += 1;
                continue;
            }
            return Err(());
        }
    }

    fn build_batch(&self) -> Result<Value, ()> {
        let resolved = self.resolved.as_ref().ok_or(())?;
        let mut selected = Vec::new();
        for record in self.pending_records.iter().take(MAX_BATCH_RECORDS) {
            selected.push(record.value.clone());
            let candidate = self.batch_without_id(resolved, &selected)?;
            if canonical_json_bytes(&candidate).len() > MAX_BATCH_BYTES {
                selected.pop();
                break;
            }
        }
        if selected.is_empty() {
            return Err(());
        }
        let mut batch = self.batch_without_id(resolved, &selected)?;
        let digest = Sha256::digest(canonical_json_bytes(&batch));
        batch["batchId"] = json!(format!("0x{}", hex::encode(digest)));
        if canonical_json_bytes(&batch).len() > MAX_BATCH_BYTES {
            return Err(());
        }
        Ok(batch)
    }

    fn batch_without_id(&self, resolved: &ResolvedSink, selected: &[Value]) -> Result<Value, ()> {
        let count = u64::try_from(selected.len()).map_err(|_| ())?;
        let sequence_end = resolved
            .next_sequence
            .checked_add(count.checked_sub(1).ok_or(())?)
            .ok_or(())?;
        Ok(json!({
            "sinkId": resolved.sink_id,
            "jobId": resolved.job_id,
            "writerPublicKey": self.writer.public_key_hex,
            "sequenceStart": resolved.next_sequence,
            "sequenceEnd": sequence_end,
            "previousHash": resolved.previous_hash,
            "createdAt": utc_timestamp(),
            "encrypted": selected,
            "labels": {
                "applicationUid": self.labels.application_uid,
                "deploymentId": self.labels.deployment_id,
                "runtimeInstanceId": self.labels.runtime_instance_id,
                "source": "runtime-cargo-supervisor",
            },
        }))
    }

    fn resolve_sink(&mut self) -> Result<ResolvedSink, ()> {
        match self.config.mode.clone() {
            SinkMode::Prebound {
                sink_id,
                job_id,
                write_url,
                resume_url,
            } => {
                let (next_sequence, previous_hash) =
                    self.resume_sink(&sink_id, &job_id, &resume_url)?;
                Ok(ResolvedSink {
                    sink_id,
                    job_id,
                    write_url,
                    resume_url,
                    next_sequence,
                    previous_hash,
                })
            }
            SinkMode::Factory {
                factory_token,
                factory_id,
                base_url,
                job_id,
                network,
                application_uid,
                application_id,
                deployment_id,
            } => {
                let encoded = encode_path_segment(&factory_id);
                let url = format!(
                    "{}/v1/sink-factories/{encoded}/job-sinks",
                    base_url.trim_end_matches('/')
                );
                let body = without_nulls(json!({
                    "jobId": job_id,
                    "network": network,
                    "applicationUid": application_uid,
                    "applicationId": application_id,
                    "deploymentId": deployment_id,
                }));
                let response = self.post_signed(
                    &url,
                    &body,
                    &[("x-blackbox-sink-factory-token".into(), factory_token)],
                )?;
                if !(200..300).contains(&response.status) {
                    return Err(());
                }
                parse_registration(&response.body, &base_url, &job_id)
            }
        }
    }

    fn resume_sink(
        &mut self,
        sink_id: &str,
        job_id: &str,
        resume_url: &str,
    ) -> Result<(u64, Option<String>), ()> {
        let response = self.post_signed(
            resume_url,
            &json!({
                "jobId": job_id,
                "writerPublicKey": self.writer.public_key_hex,
            }),
            &[],
        )?;
        if !(200..300).contains(&response.status) {
            return Err(());
        }
        let parsed: Value = serde_json::from_slice(&response.body).map_err(|_| ())?;
        if parsed["sinkId"].as_str() != Some(sink_id) {
            return Err(());
        }
        parse_chain(&parsed["chain"])
    }

    fn post_signed(
        &mut self,
        url: &str,
        value: &Value,
        additional_headers: &[(String, String)],
    ) -> Result<LogHttpResponse, ()> {
        if let Some(previous) = self.last_request {
            let remaining = MIN_REQUEST_INTERVAL.saturating_sub(previous.elapsed());
            if !remaining.is_zero() {
                thread::sleep(remaining);
            }
        }
        let target = Url::parse(url).map_err(|_| ())?;
        if target.scheme() != "https" || target.host_str().is_none() {
            return Err(());
        }
        let mut path = target.path().to_string();
        if let Some(query) = target.query() {
            path.push('?');
            path.push_str(query);
        }
        let body = canonical_json_bytes(value);
        let signed_at = utc_timestamp();
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| ())?;
        let nonce = URL_SAFE_NO_PAD.encode(nonce);
        let signing_message = format!(
            "POST\n{path}\n0x{}\n{signed_at}\n{nonce}",
            hex::encode(Sha256::digest(&body))
        );
        let signature = self.writer.key_pair.sign(signing_message.as_bytes());
        let mut headers = vec![
            ("accept".into(), "application/json".into()),
            ("content-type".into(), "application/json".into()),
            (
                "authorization".into(),
                format!(
                    "Ed25519 {}:{}",
                    self.writer.public_key_hex,
                    STANDARD.encode(signature.as_ref())
                ),
            ),
            ("x-signed-at".into(), signed_at),
            ("x-nonce".into(), nonce),
        ];
        headers.extend_from_slice(additional_headers);
        self.last_request = Some(Instant::now());
        self.http.post(url, &headers, &body)
    }
}

fn parse_registration(body: &[u8], base_url: &str, job_id: &str) -> Result<ResolvedSink, ()> {
    let value: Value = serde_json::from_slice(body).map_err(|_| ())?;
    let sink = value.get("sink").unwrap_or(&value);
    let sink_id = sink["sinkId"].as_str().ok_or(())?.to_string();
    let encoded = encode_path_segment(&sink_id);
    let write_url = sink["writeUrl"]
        .as_str()
        .map(normalized_https_url)
        .transpose()?
        .unwrap_or_else(|| {
            format!(
                "{}/v1/sinks/{encoded}/events",
                base_url.trim_end_matches('/')
            )
        });
    let resume_url = sink["resumeUrl"]
        .as_str()
        .map(normalized_https_url)
        .transpose()?
        .or_else(|| derive_resume_url(&write_url))
        .ok_or(())?;
    let (next_sequence, previous_hash) = parse_chain(&value["chain"])?;
    Ok(ResolvedSink {
        sink_id,
        job_id: job_id.to_string(),
        write_url,
        resume_url,
        next_sequence,
        previous_hash,
    })
}

fn parse_chain_response(body: &[u8]) -> Option<(u64, Option<String>)> {
    let value: Value = serde_json::from_slice(body).ok()?;
    parse_chain(&value["chain"]).ok()
}

fn parse_chain(value: &Value) -> Result<(u64, Option<String>), ()> {
    let next_sequence = value["nextSequence"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or(())?;
    let previous_hash = match value.get("previousHash") {
        None | Some(Value::Null) => None,
        Some(Value::String(value))
            if value.len() == 66
                && value.starts_with("0x")
                && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            Some(value.to_ascii_lowercase())
        }
        _ => return Err(()),
    };
    if (next_sequence == 1) != previous_hash.is_none() {
        return Err(());
    }
    Ok((next_sequence, previous_hash))
}

fn response_error_code(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    value["error"].as_str().map(str::to_string)
}

fn encode_path_segment(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn without_nulls(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.retain(|_, value| !value.is_null());
    }
    value
}

fn utc_timestamp() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let seconds = i64::try_from(duration.as_secs()).unwrap_or(i64::MAX);
    let mut broken_down = std::mem::MaybeUninit::<libc::tm>::uninit();
    // SAFETY: `gmtime_r` initializes the provided `tm` for the value address.
    let result = unsafe { libc::gmtime_r(&seconds, broken_down.as_mut_ptr()) };
    if result.is_null() {
        return "1970-01-01T00:00:00.000Z".into();
    }
    // SAFETY: a non-null `gmtime_r` result points to the initialized output.
    let broken_down = unsafe { broken_down.assume_init() };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        broken_down.tm_year.saturating_add(1900),
        broken_down.tm_mon.saturating_add(1),
        broken_down.tm_mday,
        broken_down.tm_hour,
        broken_down.tm_min,
        broken_down.tm_sec,
        duration.subsec_millis(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct RecordedCall {
        url: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    fn bootstrap(logging: Option<Value>) -> RuntimeBootstrapResponse {
        RuntimeBootstrapResponse {
            ok: true,
            domain: "proof.liskov.runtime-bootstrap-response.v2".into(),
            application_uid: "app-uid".into(),
            application_id: "app".into(),
            policy_digest: "digest".into(),
            deployment_id: "deployment".into(),
            job_id: "job".into(),
            processor_id: "processor".into(),
            runtime_instance_id: "instance".into(),
            slipway_url: "https://liskov.example".into(),
            runtime_env: None,
            supervision: None,
            logging,
            logging_outage_canary: false,
        }
    }

    fn config() -> BlackboxConfig {
        BlackboxConfig::parse(
            &json!({
                "sinkId": "sink-stable",
                "jobId": "job",
                "writeUrl": "https://blackbox.test/v1/sinks/sink-stable/events",
                "dek": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            })
            .to_string(),
            &bootstrap(Some(json!({"enabled": true}))),
        )
        .unwrap()
    }

    #[test]
    fn derives_the_canonical_writer_key_and_signature() {
        let config = config();
        let writer = WriterKey::derive(&config.dek).unwrap();
        assert_eq!(
            writer.public_key_hex,
            "ea7aeb9077ce16b49ac40b454b033109f142b1c0bc3ae31338e75ebc42cef592"
        );
        let message = [
            "POST",
            "/v1/sinks/sink-stable/resume",
            "0x96b99efbf6e698912db90f19cfd26d1d321d4db968b9f01d766468a77f8fb9b1",
            "2026-07-16T12:00:00.000Z",
            "stable-nonce",
        ]
        .join("\n");
        assert_eq!(
            STANDARD.encode(writer.key_pair.sign(message.as_bytes()).as_ref()),
            "nLhiQKZ9520GKFkpXazPL6Lajl3A4NPoeBscXPg41iQe8YXDopchSOLLo/ZioseV3+Vat27rNfx7MYSltAqyDQ=="
        );
    }

    #[test]
    fn policy_and_config_identity_fail_closed() {
        assert!(!bootstrap(None).logging_enabled());
        assert!(!bootstrap(Some(json!({"enabled": false}))).logging_enabled());
        assert!(bootstrap(Some(json!({"enabled": true}))).logging_enabled());
        let wrong_job = json!({
            "sinkId": "sink",
            "jobId": "other-job",
            "writeUrl": "https://blackbox.test/v1/sinks/sink/events",
            "dek": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        })
        .to_string();
        assert!(
            BlackboxConfig::parse(&wrong_job, &bootstrap(Some(json!({"enabled": true})))).is_err()
        );
    }

    #[test]
    fn binary_output_is_framed_without_plaintext_in_the_envelope() {
        let config = config();
        let labels = RuntimeLabels::from(&bootstrap(Some(json!({"enabled": true}))));
        let http: Arc<dyn LogHttpClient> = Arc::new(PanicHttp);
        let dropped = Arc::new(DroppedOutput::default());
        let mut worker = LogWorker::new(config, labels, http, dropped).unwrap();
        worker.admit_chunk(OutputChunk {
            output_sequence: 7,
            process_attempt: 2,
            stream: "stderr",
            timestamp: "2026-07-31T12:00:00.000Z".into(),
            bytes: vec![0xff, 0x00, b'x'],
        });
        let encrypted = &worker.pending_records[0].value;
        assert_eq!(encrypted["alg"], "A256GCM");
        assert!(!encrypted.to_string().contains("outputSequence"));
        assert!(!encrypted.to_string().contains("stderr"));
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(encrypted["iv"].as_str().unwrap())
                .unwrap()
                .len(),
            12
        );
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(encrypted["tag"].as_str().unwrap())
                .unwrap()
                .len(),
            16
        );
    }

    #[test]
    fn writes_plaintext_free_runtime_bound_batches_to_the_canonical_sink() {
        let http = Arc::new(RecordingHttp::default());
        let mut logger = OutputLogger::spawn(
            config(),
            RuntimeLabels::from(&bootstrap(Some(json!({"enabled": true})))),
            http.clone(),
        )
        .unwrap();
        logger.enqueue_for_test(OutputChunk {
            output_sequence: 9,
            process_attempt: 3,
            stream: "stdout",
            timestamp: "2026-07-31T12:00:00.000Z".into(),
            bytes: b"super-secret-output".to_vec(),
        });
        logger.finish();

        let calls = http.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert!(calls[0].url.ends_with("/resume"));
        let write = &calls[1];
        assert!(write.url.ends_with("/events"));
        assert!(!String::from_utf8_lossy(&write.body).contains("super-secret-output"));
        let batch: Value = serde_json::from_slice(&write.body).unwrap();
        assert_eq!(batch["sequenceStart"], 1);
        assert_eq!(batch["sequenceEnd"], 1);
        assert_eq!(batch["labels"]["runtimeInstanceId"], "instance");
        assert_eq!(batch["labels"]["source"], "runtime-cargo-supervisor");
        assert_eq!(batch["encrypted"].as_array().unwrap().len(), 1);
        assert!(write.headers.iter().any(|(name, value)| {
            name == "authorization"
                && value.starts_with(
                    "Ed25519 ea7aeb9077ce16b49ac40b454b033109f142b1c0bc3ae31338e75ebc42cef592:",
                )
        }));
    }

    #[test]
    fn rate_limit_records_only_bounded_drop_evidence() {
        let dropped = DroppedOutput::default();
        let mut budget = ByteBudget::new();
        assert!(budget.admit(usize::try_from(OUTPUT_BYTES_PER_SECOND).unwrap()));
        assert!(!budget.admit(1));
        dropped.record(123);
        assert_eq!(dropped.take(), Some((1, 123)));
        assert_eq!(dropped.take(), None);
    }

    #[test]
    fn logging_outage_never_backpressures_capture_admission() {
        let http: Arc<dyn LogHttpClient> = Arc::new(FailingHttp);
        let mut logger = OutputLogger::spawn(
            config(),
            RuntimeLabels::from(&bootstrap(Some(json!({"enabled": true})))),
            http,
        )
        .unwrap();
        let started = Instant::now();
        for output_sequence in 0..1_000 {
            logger.enqueue_for_test(OutputChunk {
                output_sequence,
                process_attempt: 0,
                stream: "stdout",
                timestamp: "2026-07-31T12:00:00.000Z".into(),
                bytes: vec![b'x'; OUTPUT_CHUNK_BYTES],
            });
        }
        assert!(started.elapsed() < Duration::from_millis(100));
        logger.finish();
    }

    #[test]
    fn pending_records_stay_bounded_during_sink_failure() {
        let config = config();
        let labels = RuntimeLabels::from(&bootstrap(Some(json!({"enabled": true}))));
        let http: Arc<dyn LogHttpClient> = Arc::new(FailingHttp);
        let dropped = Arc::new(DroppedOutput::default());
        let mut worker = LogWorker::new(config, labels, http, dropped.clone()).unwrap();
        for output_sequence in 0..1_000 {
            worker.admit_chunk(OutputChunk {
                output_sequence,
                process_attempt: 0,
                stream: "stdout",
                timestamp: "2026-07-31T12:00:00.000Z".into(),
                bytes: vec![b'x'; OUTPUT_CHUNK_BYTES],
            });
        }
        assert_eq!(worker.pending_records.len(), MAX_BATCH_RECORDS);
        assert_eq!(dropped.take(), Some((968, 968 * OUTPUT_CHUNK_BYTES as u64)));
    }

    #[test]
    fn rejects_inconsistent_or_malformed_chain_heads() {
        for value in [
            json!({"nextSequence": 1, "previousHash": format!("0x{}", "ab".repeat(32))}),
            json!({"nextSequence": 2, "previousHash": null}),
            json!({"nextSequence": 2, "previousHash": "0xshort"}),
        ] {
            assert!(parse_chain(&value).is_err(), "value: {value}");
        }
        assert_eq!(
            parse_chain(&json!({"nextSequence": 1, "previousHash": null})),
            Ok((1, None))
        );
    }

    struct PanicHttp;

    struct FailingHttp;

    #[derive(Default)]
    struct RecordingHttp {
        calls: Mutex<Vec<RecordedCall>>,
    }

    impl LogHttpClient for RecordingHttp {
        fn post(
            &self,
            url: &str,
            headers: &[(String, String)],
            body: &[u8],
        ) -> Result<LogHttpResponse, ()> {
            self.calls.lock().unwrap().push(RecordedCall {
                url: url.to_string(),
                headers: headers.to_vec(),
                body: body.to_vec(),
            });
            if url.ends_with("/resume") {
                return Ok(LogHttpResponse {
                    status: 200,
                    body: serde_json::to_vec(&json!({
                        "sinkId": "sink-stable",
                        "chain": {"nextSequence": 1, "previousHash": null}
                    }))
                    .unwrap(),
                });
            }
            let batch: Value = serde_json::from_slice(body).unwrap();
            Ok(LogHttpResponse {
                status: 200,
                body: serde_json::to_vec(&json!({
                    "chain": {
                        "nextSequence": batch["sequenceEnd"].as_u64().unwrap() + 1,
                        "previousHash": batch["batchId"],
                    }
                }))
                .unwrap(),
            })
        }
    }

    impl LogHttpClient for FailingHttp {
        fn post(
            &self,
            _url: &str,
            _headers: &[(String, String)],
            _body: &[u8],
        ) -> Result<LogHttpResponse, ()> {
            Err(())
        }
    }

    impl LogHttpClient for PanicHttp {
        fn post(
            &self,
            _url: &str,
            _headers: &[(String, String)],
            _body: &[u8],
        ) -> Result<LogHttpResponse, ()> {
            panic!("network is not used in this unit test")
        }
    }
}
