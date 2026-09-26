//! Job-side writer and reader of the Liskov state snapshot format
//! (BKLG-20260926-bzbo). The format is owned by liskov-rs
//! `docs/contracts/state-snapshot-format.md` (`onir`, `db6t`); the mirrored
//! vectors in `vectors/state_snapshot_{chunk,manifest}.json` pin it byte for
//! byte.
//!
//! A snapshot is a deterministic tar of a directory, cut by FastCDC 2020 into
//! encrypted chunk objects in a local object directory, plus a signed,
//! hash-chained manifest. The object directory stands in for any data plane.
//! Restore verifies the manifest, its chain link and every chunk while it
//! extracts into a sibling temporary directory, and renames into place only
//! when all of it verified; a refused restore leaves the target untouched.
//!
//! No network, Lockbox or bridge access happens here: the DEK is an argument
//! and the manifest signer is a trait so the bridge can supply it later.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use fastcdc::v2020::FastCDC;
use ring::{aead, hkdf, hmac, signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const CHUNK_FORMAT_VERSION: u8 = 0x01;
pub const CHUNK_NONCE_LEN: usize = 12;
pub const CHUNK_TAG_LEN: usize = 16;
pub const CHUNK_OVERHEAD: usize = 1 + CHUNK_NONCE_LEN + CHUNK_TAG_LEN;

pub const MANIFEST_VERSION: u64 = 1;
pub const SIGNATURE_DOMAIN: &[u8] = b"liskov-state-manifest-v1";

/// FastCDC 2020 boundaries this writer uses. They are the writer's choice,
/// not part of the format.
pub const CHUNK_MIN_BYTES: usize = 256 * 1024;
pub const CHUNK_AVG_BYTES: usize = 1024 * 1024;
pub const CHUNK_MAX_BYTES: usize = 4 * 1024 * 1024;

/// A reader refuses a chunk larger than this before reading it, whoever wrote
/// it, so a restore's memory stays bounded.
pub const MAX_CHUNK_PLAINTEXT_BYTES: u64 = 16 * 1024 * 1024;

const CHUNK_KEY_INFO: &[u8] = b"liskov-state-chunk-key-v1";
const CHUNK_ID_KEY_INFO: &[u8] = b"liskov-state-chunk-id-v1";
const CHUNK_AAD_DOMAIN: &[u8] = b"liskov-state-chunk-v1";
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
/// The tar path of the snapshot root's own entry.
const ROOT_ENTRY: &[u8] = b"./";

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChunkError {
    #[error("state chunk object is truncated ({len} bytes)")]
    ChunkTruncated { len: usize },
    #[error("state chunk format version {0:#04x} is not supported")]
    UnsupportedChunkVersion(u8),
    #[error("state chunk did not decrypt")]
    Decrypt,
    #[error("state chunk plaintext does not match its id")]
    ChunkIdMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest is not well formed: {0}")]
    Malformed(&'static str),
    #[error("manifest plaintextBytes {declared} disagrees with its chunks' sum {chunks}")]
    SizeMismatch { declared: u64, chunks: u64 },
    #[error("manifest signer is not the trusted key")]
    SignerMismatch,
    #[error("manifest signature does not verify")]
    BadSignature,
    #[error("successor manifest is for a different {0}")]
    CrossLineage(&'static str),
    #[error("successor sequence {next} does not advance past {previous}")]
    SequenceNotAdvanced { previous: u64, next: u64 },
    #[error("successor sequence {next} skips past {previous}")]
    SequenceGap { previous: u64, next: u64 },
    #[error("successor names a different predecessor digest")]
    Fork,
}

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error(transparent)]
    Chunk(#[from] ChunkError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error("state snapshot {0} failed")]
    Io(&'static str, #[source] io::Error),
    #[error("state snapshot source is not a directory")]
    SourceNotDirectory,
    #[error("state object directory is inside the snapshot source")]
    OutputInsideSource,
    #[error("state snapshot source entry has an mtime before 1970")]
    MtimeBeforeEpoch,
    #[error("state snapshot source changed while it was read")]
    SourceChanged,
    #[error("state object {0} exists with a different length")]
    ObjectConflict(String),
    #[error("state chunk {0} is missing from the object directory")]
    MissingChunk(String),
    #[error("state chunk {id} is {actual} bytes, the manifest says {expected}")]
    ObjectLength {
        id: String,
        expected: u64,
        actual: u64,
    },
    #[error("state chunk {0} is larger than a reader accepts")]
    ChunkTooLarge(String),
    #[error("state snapshot archive is invalid")]
    Archive(#[source] io::Error),
    #[error("state restore target is not an absent or empty directory")]
    TargetNotEmpty,
    #[error("state restore target has no parent and name")]
    InvalidTarget,
    #[error("state manifest signer was unavailable")]
    Signer,
    #[error("state snapshot randomness was unavailable")]
    Randomness,
    #[error("{error}; removing the temporary restore directory also failed")]
    Cleanup {
        error: Box<SnapshotError>,
        #[source]
        cleanup: io::Error,
    },
}

// ---------------------------------------------------------------------------
// Chunks

struct Len32;

impl hkdf::KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

fn hkdf_32(dek: &[u8; 32], lineage_id: &str, info: &[u8]) -> Zeroizing<[u8; 32]> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, lineage_id.as_bytes()).extract(dek);
    let mut out = Zeroizing::new([0u8; 32]);
    // 32 bytes is far below HKDF-SHA256's 255 * 32 limit, so neither call fails.
    prk.expand(&[info], Len32)
        .and_then(|okm| okm.fill(out.as_mut()))
        .expect("HKDF-SHA256 expands 32 bytes");
    out
}

pub fn derive_chunk_key(dek: &[u8; 32], lineage_id: &str) -> Zeroizing<[u8; 32]> {
    hkdf_32(dek, lineage_id, CHUNK_KEY_INFO)
}

pub fn derive_chunk_id_key(dek: &[u8; 32], lineage_id: &str) -> Zeroizing<[u8; 32]> {
    hkdf_32(dek, lineage_id, CHUNK_ID_KEY_INFO)
}

/// The two keys a lineage's chunks are sealed and named with, derived once.
struct ChunkKeys {
    lineage_id: String,
    seal: aead::LessSafeKey,
    id: hmac::Key,
}

impl ChunkKeys {
    fn new(dek: &[u8; 32], lineage_id: &str) -> Self {
        let seal_key = derive_chunk_key(dek, lineage_id);
        let id_key = derive_chunk_id_key(dek, lineage_id);
        let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, seal_key.as_ref())
            .expect("AES-256-GCM takes a 32-byte key");
        Self {
            lineage_id: lineage_id.to_owned(),
            seal: aead::LessSafeKey::new(unbound),
            id: hmac::Key::new(hmac::HMAC_SHA256, id_key.as_ref()),
        }
    }

    fn chunk_id(&self, plaintext: &[u8]) -> [u8; 32] {
        let tag = hmac::sign(&self.id, plaintext);
        tag.as_ref().try_into().expect("HMAC-SHA256 is 32 bytes")
    }

    fn aad(&self, chunk_id: &[u8; 32]) -> Vec<u8> {
        [CHUNK_AAD_DOMAIN, self.lineage_id.as_bytes(), chunk_id].concat()
    }

    fn seal(&self, nonce: &[u8; CHUNK_NONCE_LEN], plaintext: &[u8]) -> SealedChunk {
        let chunk_id = self.chunk_id(plaintext);
        let mut body = plaintext.to_vec();
        let tag = self
            .seal
            .seal_in_place_separate_tag(
                aead::Nonce::assume_unique_for_key(*nonce),
                aead::Aad::from(self.aad(&chunk_id)),
                &mut body,
            )
            .expect("AES-256-GCM seals a chunk below its length limit");
        let mut object = Vec::with_capacity(CHUNK_OVERHEAD + plaintext.len());
        object.push(CHUNK_FORMAT_VERSION);
        object.extend_from_slice(nonce);
        object.extend_from_slice(&body);
        object.extend_from_slice(tag.as_ref());
        SealedChunk { chunk_id, object }
    }

    fn open(&self, expected_chunk_id: &[u8; 32], object: &[u8]) -> Result<Vec<u8>, ChunkError> {
        if object.len() < CHUNK_OVERHEAD {
            return Err(ChunkError::ChunkTruncated { len: object.len() });
        }
        if object[0] != CHUNK_FORMAT_VERSION {
            return Err(ChunkError::UnsupportedChunkVersion(object[0]));
        }
        let nonce: [u8; CHUNK_NONCE_LEN] = object[1..1 + CHUNK_NONCE_LEN]
            .try_into()
            .expect("nonce slice is 12 bytes");
        let mut body = object[1 + CHUNK_NONCE_LEN..].to_vec();
        let plaintext_len = self
            .seal
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(self.aad(expected_chunk_id)),
                &mut body,
            )
            .map_err(|_| ChunkError::Decrypt)?
            .len();
        body.truncate(plaintext_len);
        hmac::verify(&self.id, &body, expected_chunk_id)
            .map_err(|_| ChunkError::ChunkIdMismatch)?;
        Ok(body)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedChunk {
    pub chunk_id: [u8; 32],
    pub object: Vec<u8>,
}

pub fn chunk_id(dek: &[u8; 32], lineage_id: &str, plaintext: &[u8]) -> [u8; 32] {
    ChunkKeys::new(dek, lineage_id).chunk_id(plaintext)
}

/// Seals one chunk under an explicit nonce. A writer draws a fresh random
/// nonce for every seal; the argument exists so the vectors replay.
pub fn seal_chunk(
    dek: &[u8; 32],
    lineage_id: &str,
    nonce: &[u8; CHUNK_NONCE_LEN],
    plaintext: &[u8],
) -> SealedChunk {
    ChunkKeys::new(dek, lineage_id).seal(nonce, plaintext)
}

pub fn open_chunk(
    dek: &[u8; 32],
    lineage_id: &str,
    expected_chunk_id: &[u8; 32],
    object: &[u8],
) -> Result<Vec<u8>, ChunkError> {
    ChunkKeys::new(dek, lineage_id).open(expected_chunk_id, object)
}

// ---------------------------------------------------------------------------
// Manifest

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipientKind {
    Lockbox,
    Job,
    Customer,
    BrokerShare,
}

impl RecipientKind {
    fn name(self) -> &'static str {
        match self {
            Self::Lockbox => "lockbox",
            Self::Job => "job",
            Self::Customer => "customer",
            Self::BrokerShare => "broker_share",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantPayload {
    pub version: String,
    pub curve_name: String,
    #[serde(with = "hex_bytes")]
    pub sender_public_key: Vec<u8>,
    #[serde(rename = "saltHex", with = "hex_bytes")]
    pub salt: Vec<u8>,
    #[serde(rename = "ciphertextHex", with = "hex_bytes")]
    pub ciphertext: Vec<u8>,
}

/// One recipient's copy of the DEK. This module carries copies it is given
/// into the manifest; it never wraps or unwraps one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WrappedDataKey {
    pub recipient_kind: RecipientKind,
    pub recipient_key_id: String,
    pub dek_version: u64,
    pub grant: GrantPayload,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub v: u64,
    pub org: String,
    pub application: String,
    pub lineage: String,
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "hex32_opt")]
    pub previous_manifest_digest: Option<[u8; 32]>,
    pub writer: ManifestWriter,
    pub captured_at_ms: u64,
    pub dek_version: u64,
    pub plaintext_bytes: u64,
    pub chunks: Vec<ManifestChunk>,
    pub recipients: Vec<WrappedDataKey>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestWriter {
    pub job_id: String,
    pub processor_id: String,
    pub generation: u64,
    #[serde(with = "hex32")]
    pub signer_public_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestChunk {
    #[serde(with = "hex32")]
    pub id: [u8; 32],
    pub plaintext_bytes: u64,
    pub object_bytes: u64,
}

/// A manifest and the signature that travels beside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedManifest {
    pub manifest: Manifest,
    pub signature: [u8; 64],
}

pub fn canonical_bytes(manifest: &Manifest) -> Result<Vec<u8>, ManifestError> {
    check_well_formed(manifest)?;
    let mut out = Encoder::default();
    out.u64(manifest.v);
    out.str(&manifest.org)?;
    out.str(&manifest.application)?;
    out.str(&manifest.lineage)?;
    out.u64(manifest.sequence);
    match &manifest.previous_manifest_digest {
        None => out.0.push(0x00),
        Some(previous) => {
            out.0.push(0x01);
            out.0.extend_from_slice(previous);
        }
    }
    out.str(&manifest.writer.job_id)?;
    out.str(&manifest.writer.processor_id)?;
    out.u64(manifest.writer.generation);
    out.0.extend_from_slice(&manifest.writer.signer_public_key);
    out.u64(manifest.captured_at_ms);
    out.u64(manifest.dek_version);
    out.u64(manifest.plaintext_bytes);
    out.count(manifest.chunks.len())?;
    for chunk in &manifest.chunks {
        out.0.extend_from_slice(&chunk.id);
        out.u64(chunk.plaintext_bytes);
        out.u64(chunk.object_bytes);
    }
    out.count(manifest.recipients.len())?;
    for recipient in &manifest.recipients {
        out.str(recipient.recipient_kind.name())?;
        out.0.extend_from_slice(
            &lower_hex32(&recipient.recipient_key_id)
                .ok_or(ManifestError::Malformed("recipients[].recipientKeyId"))?,
        );
        out.u64(recipient.dek_version);
        out.str(&recipient.grant.version)?;
        out.str(&recipient.grant.curve_name)?;
        out.bytes(&recipient.grant.sender_public_key)?;
        out.bytes(&recipient.grant.salt)?;
        out.bytes(&recipient.grant.ciphertext)?;
    }
    Ok(out.0)
}

pub fn digest(manifest: &Manifest) -> Result<[u8; 32], ManifestError> {
    Ok(Sha256::digest(canonical_bytes(manifest)?).into())
}

/// The Ed25519 key that signs manifests. The job's runtime key lives behind
/// the bridge; [`SeedSigner`] holds a seed for tests and vectors.
pub trait StateSigner {
    fn public_key(&self) -> [u8; 32];
    fn sign_ed25519(&self, message: &[u8]) -> Option<[u8; 64]>;
}

pub struct SeedSigner(signature::Ed25519KeyPair);

impl SeedSigner {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(
            signature::Ed25519KeyPair::from_seed_unchecked(seed)
                .expect("any 32-byte seed is an Ed25519 key"),
        )
    }
}

impl StateSigner for SeedSigner {
    fn public_key(&self) -> [u8; 32] {
        use signature::KeyPair;
        self.0
            .public_key()
            .as_ref()
            .try_into()
            .expect("Ed25519 public keys are 32 bytes")
    }

    fn sign_ed25519(&self, message: &[u8]) -> Option<[u8; 64]> {
        self.0.sign(message).as_ref().try_into().ok()
    }
}

/// Signs a manifest, refusing a signer whose key is not
/// `writer.signerPublicKey`, and checks the signature it got back.
pub fn sign(manifest: &Manifest, signer: &dyn StateSigner) -> Result<[u8; 64], SnapshotError> {
    let manifest_digest = digest(manifest)?;
    if signer.public_key() != manifest.writer.signer_public_key {
        return Err(ManifestError::SignerMismatch.into());
    }
    let signature = signer
        .sign_ed25519(&signed_message(&manifest_digest))
        .ok_or(SnapshotError::Signer)?;
    verify_digest(
        &manifest_digest,
        &signature,
        &manifest.writer.signer_public_key,
    )?;
    Ok(signature)
}

/// Verifies a manifest's signature by the key the reader trusts, returning
/// the manifest's digest.
pub fn verify_signature(
    manifest: &Manifest,
    signature: &[u8; 64],
    trusted_signer: &[u8; 32],
) -> Result<[u8; 32], ManifestError> {
    let manifest_digest = digest(manifest)?;
    if manifest.writer.signer_public_key != *trusted_signer {
        return Err(ManifestError::SignerMismatch);
    }
    verify_digest(&manifest_digest, signature, trusted_signer)?;
    Ok(manifest_digest)
}

/// Checks that `next` is the link after `previous`, a manifest the caller
/// already trusts. It does not check signatures.
pub fn verify_successor(previous: &Manifest, next: &Manifest) -> Result<(), ManifestError> {
    let previous_digest = digest(previous)?;
    check_well_formed(next)?;
    for (field, was, is) in [
        ("org", &previous.org, &next.org),
        ("application", &previous.application, &next.application),
        ("lineage", &previous.lineage, &next.lineage),
    ] {
        if was != is {
            return Err(ManifestError::CrossLineage(field));
        }
    }
    if next.sequence <= previous.sequence {
        return Err(ManifestError::SequenceNotAdvanced {
            previous: previous.sequence,
            next: next.sequence,
        });
    }
    // Well formed, so previous.sequence <= 2^53 - 1 and the addition cannot overflow.
    if next.sequence != previous.sequence + 1 {
        return Err(ManifestError::SequenceGap {
            previous: previous.sequence,
            next: next.sequence,
        });
    }
    if next.previous_manifest_digest != Some(previous_digest) {
        return Err(ManifestError::Fork);
    }
    Ok(())
}

fn signed_message(digest: &[u8; 32]) -> Vec<u8> {
    [SIGNATURE_DOMAIN, digest.as_slice()].concat()
}

fn verify_digest(
    digest: &[u8; 32],
    signature: &[u8; 64],
    signer: &[u8; 32],
) -> Result<(), ManifestError> {
    signature::UnparsedPublicKey::new(&signature::ED25519, signer)
        .verify(&signed_message(digest), signature)
        .map_err(|_| ManifestError::BadSignature)
}

fn check_well_formed(manifest: &Manifest) -> Result<(), ManifestError> {
    let malformed = ManifestError::Malformed;
    if manifest.v != MANIFEST_VERSION {
        return Err(malformed("v"));
    }
    for (field, value) in [
        ("org", &manifest.org),
        ("application", &manifest.application),
        ("lineage", &manifest.lineage),
        ("writer.jobId", &manifest.writer.job_id),
        ("writer.processorId", &manifest.writer.processor_id),
    ] {
        if value.is_empty() {
            return Err(malformed(field));
        }
    }
    if manifest.sequence == 0 {
        return Err(malformed("sequence"));
    }
    if (manifest.sequence == 1) != manifest.previous_manifest_digest.is_none() {
        return Err(malformed("previousManifestDigest"));
    }
    for (field, value) in [
        ("sequence", manifest.sequence),
        ("writer.generation", manifest.writer.generation),
        ("capturedAtMs", manifest.captured_at_ms),
        ("dekVersion", manifest.dek_version),
        ("plaintextBytes", manifest.plaintext_bytes),
    ] {
        if value > MAX_SAFE_INTEGER {
            return Err(malformed(field));
        }
    }
    let mut chunk_sum: u64 = 0;
    for chunk in &manifest.chunks {
        if chunk.plaintext_bytes > MAX_SAFE_INTEGER {
            return Err(malformed("chunks[].plaintextBytes"));
        }
        if chunk.object_bytes > MAX_SAFE_INTEGER {
            return Err(malformed("chunks[].objectBytes"));
        }
        chunk_sum = chunk_sum
            .checked_add(chunk.plaintext_bytes)
            .ok_or(malformed("chunks[].plaintextBytes"))?;
    }
    for recipient in &manifest.recipients {
        if recipient.dek_version != manifest.dek_version {
            return Err(malformed("recipients[].dekVersion"));
        }
        if lower_hex32(&recipient.recipient_key_id).is_none() {
            return Err(malformed("recipients[].recipientKeyId"));
        }
    }
    if chunk_sum != manifest.plaintext_bytes {
        return Err(ManifestError::SizeMismatch {
            declared: manifest.plaintext_bytes,
            chunks: chunk_sum,
        });
    }
    Ok(())
}

fn lower_hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    hex::decode(text).ok()?.try_into().ok()
}

#[derive(Default)]
struct Encoder(Vec<u8>);

impl Encoder {
    fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    fn count(&mut self, len: usize) -> Result<(), ManifestError> {
        let len = u32::try_from(len).map_err(|_| ManifestError::Malformed("length"))?;
        self.0.extend_from_slice(&len.to_be_bytes());
        Ok(())
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<(), ManifestError> {
        self.count(bytes.len())?;
        self.0.extend_from_slice(bytes);
        Ok(())
    }

    fn str(&mut self, text: &str) -> Result<(), ManifestError> {
        self.bytes(text.as_bytes())
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        hex::decode(text).map_err(serde::de::Error::custom)
    }
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(deserializer)?;
        super::lower_hex32(&text)
            .ok_or_else(|| serde::de::Error::custom("expected 64 lowercase hex digits"))
    }
}

mod hex32_opt {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        bytes: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => super::hex32::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        super::hex32::deserialize(deserializer).map(Some)
    }
}

// ---------------------------------------------------------------------------
// Write

/// Everything a manifest says about its snapshot besides its chunks, its
/// place in the chain and its signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotLineage {
    pub org: String,
    pub application: String,
    pub lineage: String,
    pub job_id: String,
    pub processor_id: String,
    pub generation: u64,
    pub dek_version: u64,
    pub captured_at_ms: u64,
    /// Wrapped copies of the DEK, made elsewhere. May be empty.
    pub recipients: Vec<WrappedDataKey>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriteReport {
    /// Chunk objects this write created.
    pub chunks_written: usize,
    /// Chunks whose object already existed, from an earlier snapshot or
    /// earlier in this one, and was not rewritten.
    pub chunks_reused: usize,
    /// Device nodes, sockets and FIFOs left out of the snapshot.
    pub special_files_skipped: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub signed: SignedManifest,
    pub report: WriteReport,
}

/// Snapshots `dir` into chunk objects in `out` and returns the signed
/// manifest. `previous` is the writer's own last manifest of this lineage;
/// the new one chains to it. The directory must not change while it is read:
/// a file whose size changes fails the write.
pub fn write(
    dir: &Path,
    dek: &[u8; 32],
    lineage: &SnapshotLineage,
    previous: Option<&Manifest>,
    signer: &dyn StateSigner,
    out: &Path,
) -> Result<Snapshot, SnapshotError> {
    let mut manifest = Manifest {
        v: MANIFEST_VERSION,
        org: lineage.org.clone(),
        application: lineage.application.clone(),
        lineage: lineage.lineage.clone(),
        sequence: 1,
        previous_manifest_digest: None,
        writer: ManifestWriter {
            job_id: lineage.job_id.clone(),
            processor_id: lineage.processor_id.clone(),
            generation: lineage.generation,
            signer_public_key: signer.public_key(),
        },
        captured_at_ms: lineage.captured_at_ms,
        dek_version: lineage.dek_version,
        plaintext_bytes: 0,
        chunks: Vec::new(),
        recipients: lineage.recipients.clone(),
    };
    if let Some(previous) = previous {
        manifest.sequence = previous
            .sequence
            .checked_add(1)
            .ok_or(ManifestError::Malformed("sequence"))?;
        manifest.previous_manifest_digest = Some(digest(previous)?);
        verify_successor(previous, &manifest)?;
    }
    // Refuse a bad lineage before writing any object.
    check_well_formed(&manifest)?;

    let source_meta = fs::symlink_metadata(dir).map_err(|e| SnapshotError::Io("source", e))?;
    if !source_meta.is_dir() {
        return Err(SnapshotError::SourceNotDirectory);
    }
    fs::create_dir_all(out).map_err(|e| SnapshotError::Io("object directory", e))?;
    let source = dir
        .canonicalize()
        .map_err(|e| SnapshotError::Io("source", e))?;
    let objects = out
        .canonicalize()
        .map_err(|e| SnapshotError::Io("object directory", e))?;
    if objects.starts_with(&source) {
        return Err(SnapshotError::OutputInsideSource);
    }

    let (entries, special_files_skipped) = collect_entries(&source, &source_meta)?;
    let mut sink = ChunkSink {
        keys: ChunkKeys::new(dek, &lineage.lineage),
        out: &objects,
        buffer: Vec::with_capacity(2 * CHUNK_MAX_BYTES),
        chunks: Vec::new(),
        report: WriteReport {
            special_files_skipped,
            ..WriteReport::default()
        },
        error: None,
    };
    let archived = archive_entries(&source, &entries, &mut sink);
    if let Some(error) = sink.error.take() {
        return Err(error);
    }
    archived?;
    sink.flush_all()?;

    manifest.plaintext_bytes = sink.chunks.iter().map(|c| c.plaintext_bytes).sum();
    manifest.chunks = sink.chunks;
    let signature = sign(&manifest, signer)?;
    Ok(Snapshot {
        signed: SignedManifest {
            manifest,
            signature,
        },
        report: sink.report,
    })
}

struct SourceEntry {
    relative: Vec<u8>,
    meta: fs::Metadata,
}

/// Every entry under `root`, sorted by path bytes, and how many special
/// files were skipped. Symlinks are entries, never followed.
fn collect_entries(
    root: &Path,
    root_meta: &fs::Metadata,
) -> Result<(Vec<SourceEntry>, usize), SnapshotError> {
    let mut entries = vec![SourceEntry {
        relative: ROOT_ENTRY.to_vec(),
        meta: root_meta.clone(),
    }];
    let mut skipped = 0;
    let mut pending = vec![(root.to_path_buf(), Vec::new())];
    while let Some((path, relative)) = pending.pop() {
        for child in fs::read_dir(&path).map_err(|e| SnapshotError::Io("source walk", e))? {
            let child = child.map_err(|e| SnapshotError::Io("source walk", e))?;
            let meta = child
                .metadata()
                .map_err(|e| SnapshotError::Io("source walk", e))?;
            let mut child_relative = relative.clone();
            if !child_relative.is_empty() {
                child_relative.push(b'/');
            }
            child_relative.extend_from_slice(child.file_name().as_bytes());
            let kind = meta.file_type();
            if kind.is_dir() {
                pending.push((child.path(), child_relative.clone()));
            } else if !kind.is_file() && !kind.is_symlink() {
                skipped += 1;
                continue;
            }
            entries.push(SourceEntry {
                relative: child_relative,
                meta,
            });
        }
    }
    entries.sort_by(|a, b| a.relative.cmp(&b.relative));
    Ok((entries, skipped))
}

fn archive_entries(
    root: &Path,
    entries: &[SourceEntry],
    sink: &mut ChunkSink<'_>,
) -> Result<(), SnapshotError> {
    let archive_error = SnapshotError::Archive;
    let mut builder = tar::Builder::new(sink);
    for entry in entries {
        let meta = &entry.meta;
        let mut header = tar::Header::new_gnu();
        header.set_mode(meta.mode() & 0o7777);
        header.set_uid(u64::from(meta.uid()));
        header.set_gid(u64::from(meta.gid()));
        header.set_mtime(u64::try_from(meta.mtime()).map_err(|_| SnapshotError::MtimeBeforeEpoch)?);
        header.set_size(0);
        if entry.relative == ROOT_ENTRY {
            // The builder refuses "./" as a path; the root's name is set raw.
            header.set_entry_type(tar::EntryType::Directory);
            header.as_old_mut().name[..ROOT_ENTRY.len()].copy_from_slice(ROOT_ENTRY);
            header.set_cksum();
            builder
                .append(&header, io::empty())
                .map_err(archive_error)?;
            continue;
        }
        let relative = Path::new(std::ffi::OsStr::from_bytes(&entry.relative));
        let path = root.join(relative);
        let kind = meta.file_type();
        if kind.is_dir() {
            header.set_entry_type(tar::EntryType::Directory);
            builder
                .append_data(&mut header, relative, io::empty())
                .map_err(archive_error)?;
        } else if kind.is_symlink() {
            header.set_entry_type(tar::EntryType::Symlink);
            let target = fs::read_link(&path).map_err(|e| SnapshotError::Io("source read", e))?;
            builder
                .append_link(&mut header, relative, target)
                .map_err(archive_error)?;
        } else {
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(meta.len());
            let file = File::open(&path).map_err(|e| SnapshotError::Io("source read", e))?;
            let mut reader = ExactReader {
                inner: file.take(meta.len()),
                remaining: meta.len(),
            };
            builder
                .append_data(&mut header, relative, &mut reader)
                .map_err(|e| {
                    if e.kind() == io::ErrorKind::UnexpectedEof {
                        SnapshotError::SourceChanged
                    } else {
                        SnapshotError::Archive(e)
                    }
                })?;
            let mut probe = [0u8; 1];
            if reader
                .inner
                .into_inner()
                .read(&mut probe)
                .map_err(|e| SnapshotError::Io("source read", e))?
                != 0
            {
                return Err(SnapshotError::SourceChanged);
            }
        }
    }
    builder.finish().map_err(archive_error)
}

/// Yields exactly `remaining` bytes, or fails, so a file that shrinks while
/// it is archived cannot shift every later header.
struct ExactReader {
    inner: io::Take<File>,
    remaining: u64,
}

impl Read for ExactReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buf)?;
        if count == 0 && self.remaining > 0 && !buf.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.remaining -= count as u64;
        Ok(count)
    }
}

/// Receives the tar stream, cuts it with FastCDC 2020 and stores each chunk.
struct ChunkSink<'a> {
    keys: ChunkKeys,
    out: &'a Path,
    buffer: Vec<u8>,
    chunks: Vec<ManifestChunk>,
    report: WriteReport,
    /// The typed failure behind an `io::Error` the tar builder saw.
    error: Option<SnapshotError>,
}

impl ChunkSink<'_> {
    /// Cuts the first chunk off the buffer. With at least `CHUNK_MAX_BYTES`
    /// buffered the cut depends only on the stream, never on how it arrived.
    fn cut_one(&mut self) -> Result<(), SnapshotError> {
        let len = self.buffer.len();
        let (_, cut) = FastCDC::new(
            &self.buffer,
            CHUNK_MIN_BYTES,
            CHUNK_AVG_BYTES,
            CHUNK_MAX_BYTES,
        )
        .cut(0, len);
        let chunk: Vec<u8> = self.buffer.drain(..cut).collect();
        self.store(&chunk)
    }

    fn flush_all(&mut self) -> Result<(), SnapshotError> {
        while !self.buffer.is_empty() {
            self.cut_one()?;
        }
        Ok(())
    }

    fn store(&mut self, plaintext: &[u8]) -> Result<(), SnapshotError> {
        let chunk_id = self.keys.chunk_id(plaintext);
        let name = hex::encode(chunk_id);
        let object_bytes = (CHUNK_OVERHEAD + plaintext.len()) as u64;
        let path = self.out.join(&name);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() && meta.len() == object_bytes => {
                self.report.chunks_reused += 1;
            }
            Ok(_) => return Err(SnapshotError::ObjectConflict(name)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut nonce = [0u8; CHUNK_NONCE_LEN];
                getrandom::fill(&mut nonce).map_err(|_| SnapshotError::Randomness)?;
                let sealed = self.keys.seal(&nonce, plaintext);
                write_object(self.out, &name, &sealed.object)?;
                self.report.chunks_written += 1;
            }
            Err(e) => return Err(SnapshotError::Io("object lookup", e)),
        }
        self.chunks.push(ManifestChunk {
            id: chunk_id,
            plaintext_bytes: plaintext.len() as u64,
            object_bytes,
        });
        Ok(())
    }
}

impl Write for ChunkSink<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.error.is_some() {
            return Err(io::Error::other("state chunk store failed"));
        }
        self.buffer.extend_from_slice(buf);
        while self.buffer.len() >= CHUNK_MAX_BYTES {
            if let Err(error) = self.cut_one() {
                self.error = Some(error);
                return Err(io::Error::other("state chunk store failed"));
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Writes an object under a temporary name and renames it into place, so a
/// reader never sees a partial object under a chunk id.
fn write_object(out: &Path, name: &str, object: &[u8]) -> Result<(), SnapshotError> {
    let temporary = out.join(format!(".{name}.{}.tmp", random_suffix()?));
    let result = (|| {
        let mut file = File::create_new(&temporary)?;
        file.write_all(object)?;
        file.sync_all()?;
        fs::rename(&temporary, out.join(name))
    })();
    result.map_err(|e| {
        let _ = fs::remove_file(&temporary);
        SnapshotError::Io("object write", e)
    })
}

fn random_suffix() -> Result<String, SnapshotError> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|_| SnapshotError::Randomness)?;
    Ok(hex::encode(bytes))
}

// ---------------------------------------------------------------------------
// Restore

/// What a reader trusts before it restores: the signer key it checked on
/// chain, and optionally the head the manifest must follow. Where the head
/// is kept is open (`Q-20260926-iehz`); without one there is no chain check.
#[derive(Clone, Copy, Debug)]
pub struct RestoreTrust<'a> {
    pub signer: &'a [u8; 32],
    pub previous: Option<&'a Manifest>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoreReport {
    pub chunks: usize,
    pub plaintext_bytes: u64,
}

/// Rebuilds a snapshot's directory at `target`, which must be absent or an
/// empty directory. Nothing is placed at `target` unless the signature, the
/// chain link and every chunk verified.
pub fn restore(
    signed: &SignedManifest,
    dek: &[u8; 32],
    trust: RestoreTrust<'_>,
    objects: &Path,
    target: &Path,
) -> Result<RestoreReport, SnapshotError> {
    let manifest = &signed.manifest;
    verify_signature(manifest, &signed.signature, trust.signer)?;
    if let Some(previous) = trust.previous {
        verify_successor(previous, manifest)?;
    }
    for chunk in &manifest.chunks {
        check_object(objects, chunk)?;
    }
    let (parent, name) = match (target.parent(), target.file_name()) {
        (Some(parent), Some(name)) => (
            if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            },
            name,
        ),
        _ => return Err(SnapshotError::InvalidTarget),
    };
    match fs::symlink_metadata(target) {
        Ok(meta) if meta.is_dir() => {
            let mut children = fs::read_dir(target).map_err(|e| SnapshotError::Io("target", e))?;
            if children.next().is_some() {
                return Err(SnapshotError::TargetNotEmpty);
            }
        }
        Ok(_) => return Err(SnapshotError::TargetNotEmpty),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(SnapshotError::Io("target", e)),
    }

    let mut staging_name = std::ffi::OsString::from(".");
    staging_name.push(name);
    staging_name.push(format!(".restore-{}", random_suffix()?));
    let staging = parent.join(staging_name);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .map_err(|e| SnapshotError::Io("restore staging", e))?;

    let result = extract(manifest, dek, objects, &staging).and_then(|report| {
        fs::rename(&staging, target).map_err(|e| SnapshotError::Io("restore rename", e))?;
        Ok(report)
    });
    match result {
        Ok(report) => Ok(report),
        Err(error) => match remove_staging(&staging) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(SnapshotError::Cleanup {
                error: Box::new(error),
                cleanup,
            }),
        },
    }
}

fn check_object(objects: &Path, chunk: &ManifestChunk) -> Result<(), SnapshotError> {
    let name = hex::encode(chunk.id);
    if chunk.plaintext_bytes > MAX_CHUNK_PLAINTEXT_BYTES {
        return Err(SnapshotError::ChunkTooLarge(name));
    }
    if chunk.object_bytes != chunk.plaintext_bytes + CHUNK_OVERHEAD as u64 {
        return Err(ManifestError::Malformed("chunks[].objectBytes").into());
    }
    match fs::symlink_metadata(objects.join(&name)) {
        Ok(meta) if meta.is_file() => {
            if meta.len() != chunk.object_bytes {
                return Err(SnapshotError::ObjectLength {
                    id: name,
                    expected: chunk.object_bytes,
                    actual: meta.len(),
                });
            }
            Ok(())
        }
        Ok(_) => Err(SnapshotError::MissingChunk(name)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(SnapshotError::MissingChunk(name)),
        Err(e) => Err(SnapshotError::Io("object lookup", e)),
    }
}

/// A staging directory may hold read-only directories the archive created;
/// make each writable again so it can be removed.
fn remove_staging(staging: &Path) -> io::Result<()> {
    fn open_up(path: &Path) -> io::Result<()> {
        let meta = fs::symlink_metadata(path)?;
        if meta.is_dir() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            for child in fs::read_dir(path)? {
                open_up(&child?.path())?;
            }
        }
        Ok(())
    }
    open_up(staging)?;
    fs::remove_dir_all(staging)
}

fn extract(
    manifest: &Manifest,
    dek: &[u8; 32],
    objects: &Path,
    staging: &Path,
) -> Result<RestoreReport, SnapshotError> {
    let mut stream = ChunkStream {
        keys: ChunkKeys::new(dek, &manifest.lineage),
        chunks: &manifest.chunks,
        objects,
        next: 0,
        current: Vec::new(),
        position: 0,
        error: None,
    };
    let unpacked = unpack(&mut stream, staging);
    if let Some(error) = stream.error.take() {
        return Err(error);
    }
    let root = unpacked?;
    // Every chunk is verified, including any the archive's end did not need.
    let drained = io::copy(&mut stream, &mut io::sink());
    if let Some(error) = stream.error.take() {
        return Err(error);
    }
    drained.map_err(SnapshotError::Archive)?;

    if let Some((mode, mtime)) = root {
        fs::set_permissions(staging, fs::Permissions::from_mode(mode))
            .map_err(|e| SnapshotError::Io("restore root", e))?;
        set_mtime(staging, mtime)?;
    }
    Ok(RestoreReport {
        chunks: manifest.chunks.len(),
        plaintext_bytes: manifest.plaintext_bytes,
    })
}

/// Unpacks the archive into `staging` and returns the root entry's mode and
/// mtime. Directories are applied last, deepest first, so a read-only
/// directory does not block its own contents. Every mtime is applied here,
/// not by `tar`, which skips directories and turns an mtime of 0 into 1.
fn unpack(
    stream: &mut ChunkStream<'_>,
    staging: &Path,
) -> Result<Option<(u32, u64)>, SnapshotError> {
    let archive_error = SnapshotError::Archive;
    let preserve_owner = effective_uid() == 0;
    let mut archive = tar::Archive::new(stream);
    let mut root = None;
    let mut directories = Vec::new();
    for entry in archive.entries().map_err(archive_error)? {
        let mut entry = entry.map_err(archive_error)?;
        entry.set_preserve_permissions(true);
        entry.set_preserve_mtime(false);
        entry.set_unpack_xattrs(false);
        let header = entry.header();
        let mode = header.mode().map_err(archive_error)? & 0o7777;
        let mtime = header.mtime().map_err(archive_error)?;
        if entry.path_bytes().as_ref() == ROOT_ENTRY {
            root = Some((mode, mtime));
            continue;
        }
        let ownership = if preserve_owner {
            Some(Ownership {
                uid: header.uid().map_err(archive_error)?,
                gid: header.gid().map_err(archive_error)?,
                mode,
                symlink: header.entry_type() == tar::EntryType::Symlink,
            })
        } else {
            None
        };
        if header.entry_type() == tar::EntryType::Directory {
            directories.push((entry, ownership, mtime));
            continue;
        }
        place(&mut entry, staging, ownership, mtime)?;
    }
    directories.sort_by(|(a, ..), (b, ..)| b.path_bytes().cmp(&a.path_bytes()));
    for (mut entry, ownership, mtime) in directories {
        place(&mut entry, staging, ownership, mtime)?;
    }
    Ok(root)
}

fn place<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    staging: &Path,
    ownership: Option<Ownership>,
    mtime: u64,
) -> Result<(), SnapshotError> {
    let path = staging.join(entry.path().map_err(SnapshotError::Archive)?);
    if !entry.unpack_in(staging).map_err(SnapshotError::Archive)? {
        return Err(SnapshotError::Archive(io::Error::other(
            "archive entry escapes the restore directory",
        )));
    }
    if let Some(ownership) = ownership {
        chown(&path, ownership)?;
    }
    set_mtime(&path, mtime)
}

/// Sets an entry's own mtime, never following a symlink.
fn set_mtime(path: &Path, seconds: u64) -> Result<(), SnapshotError> {
    let invalid = |what| SnapshotError::Archive(io::Error::other(what));
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| invalid("restore path contains NUL"))?;
    let seconds = libc::time_t::try_from(seconds).map_err(|_| invalid("mtime out of range"))?;
    // SAFETY: timespec is plain C data; zeroing also clears any padding field.
    let mut times: [libc::timespec; 2] = unsafe { std::mem::zeroed() };
    times[0].tv_nsec = libc::UTIME_OMIT;
    times[1].tv_sec = seconds;
    // SAFETY: c_path is NUL-terminated and times holds the two entries utimensat reads.
    let result = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(SnapshotError::Io(
            "restore mtime",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The owner a root restore applies, and the mode to apply again after it:
/// a chown clears set-id bits.
struct Ownership {
    uid: u64,
    gid: u64,
    mode: u32,
    symlink: bool,
}

fn chown(path: &Path, owner: Ownership) -> Result<(), SnapshotError> {
    let id = |value: u64| {
        u32::try_from(value)
            .map_err(|_| SnapshotError::Archive(io::Error::other("owner id out of range")))
    };
    let (uid, gid) = (Some(id(owner.uid)?), Some(id(owner.gid)?));
    let failed = |e| SnapshotError::Io("restore ownership", e);
    if owner.symlink {
        return std::os::unix::fs::lchown(path, uid, gid).map_err(failed);
    }
    std::os::unix::fs::chown(path, uid, gid).map_err(failed)?;
    fs::set_permissions(path, fs::Permissions::from_mode(owner.mode)).map_err(failed)
}

/// Reads a manifest's chunks in restore order, opening and verifying each
/// one as the archive needs it.
struct ChunkStream<'a> {
    keys: ChunkKeys,
    chunks: &'a [ManifestChunk],
    objects: &'a Path,
    next: usize,
    current: Vec<u8>,
    position: usize,
    /// The typed failure behind an `io::Error` the tar reader saw.
    error: Option<SnapshotError>,
}

impl ChunkStream<'_> {
    fn load(&mut self, chunk: &ManifestChunk) -> Result<Vec<u8>, SnapshotError> {
        let name = hex::encode(chunk.id);
        let file = match File::open(self.objects.join(&name)) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(SnapshotError::MissingChunk(name));
            }
            Err(e) => return Err(SnapshotError::Io("object read", e)),
        };
        let mut object = Vec::with_capacity(chunk.object_bytes as usize);
        file.take(chunk.object_bytes + 1)
            .read_to_end(&mut object)
            .map_err(|e| SnapshotError::Io("object read", e))?;
        if object.len() as u64 != chunk.object_bytes {
            return Err(SnapshotError::ObjectLength {
                id: name,
                expected: chunk.object_bytes,
                actual: object.len() as u64,
            });
        }
        Ok(self.keys.open(&chunk.id, &object)?)
    }
}

impl Read for ChunkStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.error.is_some() {
            return Err(io::Error::other("state chunk refused"));
        }
        while self.position == self.current.len() {
            let Some(chunk) = self.chunks.get(self.next) else {
                return Ok(0);
            };
            match self.load(chunk) {
                Ok(plaintext) => {
                    self.current = plaintext;
                    self.position = 0;
                    self.next += 1;
                }
                Err(error) => {
                    self.error = Some(error);
                    return Err(io::Error::other("state chunk refused"));
                }
            }
        }
        let count = buf.len().min(self.current.len() - self.position);
        buf[..count].copy_from_slice(&self.current[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

impl std::fmt::Debug for ChunkStream<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkStream")
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}

/// The path a chunk object has in an object directory.
pub fn object_path(objects: &Path, chunk_id: &[u8; 32]) -> PathBuf {
    objects.join(hex::encode(chunk_id))
}

#[cfg(test)]
#[path = "state_snapshot_tests.rs"]
mod tests;
