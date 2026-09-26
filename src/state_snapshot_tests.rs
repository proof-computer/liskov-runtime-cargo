use super::*;

use std::collections::BTreeMap;
use std::fs::FileTimes;
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixListener;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CHUNK_VECTORS: &str = include_str!("../vectors/state_snapshot_chunk.json");
const MANIFEST_VECTORS: &str = include_str!("../vectors/state_snapshot_manifest.json");

const DEK: [u8; 32] = [7; 32];
const SEED: [u8; 32] = [0x42; 32];
const BIG_FILE: &str = "nested/deeper/big.bin";
const BIG_FILE_BYTES: usize = 9 * 1024 * 1024;

fn arr<const N: usize>(hex_str: &str) -> [u8; N] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChunkVectors {
    format: String,
    dek_hex: String,
    lineage_id: String,
    chunk_key_hex: String,
    chunk_id_key_hex: String,
    cases: Vec<ChunkCase>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChunkCase {
    name: String,
    plaintext_hex: Option<String>,
    plaintext_generator: Option<PlaintextGenerator>,
    plaintext_sha256_hex: Option<String>,
    nonce_hex: String,
    chunk_id_hex: String,
    object_length: usize,
    object_hex: Option<String>,
    object_sha256_hex: Option<String>,
    object_head_hex: Option<String>,
    object_tail_hex: Option<String>,
}

#[derive(serde::Deserialize)]
struct PlaintextGenerator {
    kind: String,
    length: usize,
}

impl ChunkCase {
    fn plaintext(&self) -> Vec<u8> {
        if let Some(hex_str) = &self.plaintext_hex {
            return hex::decode(hex_str).unwrap();
        }
        let generator = self.plaintext_generator.as_ref().unwrap();
        assert_eq!(generator.kind, "index_mod_256", "{}", self.name);
        (0..generator.length).map(|i| (i % 256) as u8).collect()
    }
}

#[test]
fn chunk_vectors_replay_byte_for_byte() {
    let v: ChunkVectors = serde_json::from_str(CHUNK_VECTORS).unwrap();
    assert_eq!(v.format, "liskov-state-chunk-v1");
    let dek = arr::<32>(&v.dek_hex);
    let lineage = v.lineage_id.as_str();
    assert_eq!(
        hex::encode(*derive_chunk_key(&dek, lineage)),
        v.chunk_key_hex
    );
    assert_eq!(
        hex::encode(*derive_chunk_id_key(&dek, lineage)),
        v.chunk_id_key_hex
    );
    let names: Vec<&str> = v.cases.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["empty", "short-utf8", "one-mebibyte-plus-one"]);

    for case in &v.cases {
        let plaintext = case.plaintext();
        if let Some(expected) = &case.plaintext_sha256_hex {
            assert_eq!(&sha256_hex(&plaintext), expected, "{}", case.name);
        }
        let expected_id = arr::<32>(&case.chunk_id_hex);
        assert_eq!(
            chunk_id(&dek, lineage, &plaintext),
            expected_id,
            "{}",
            case.name
        );

        let sealed = seal_chunk(&dek, lineage, &arr(&case.nonce_hex), &plaintext);
        assert_eq!(sealed.chunk_id, expected_id, "{}", case.name);
        assert_eq!(sealed.object.len(), case.object_length, "{}", case.name);
        assert_eq!(sealed.object.len(), CHUNK_OVERHEAD + plaintext.len());
        if let Some(object_hex) = &case.object_hex {
            assert_eq!(&hex::encode(&sealed.object), object_hex, "{}", case.name);
        }
        if let Some(object_sha) = &case.object_sha256_hex {
            assert_eq!(&sha256_hex(&sealed.object), object_sha, "{}", case.name);
        }
        if let Some(head) = &case.object_head_hex {
            let head = hex::decode(head).unwrap();
            assert_eq!(sealed.object[..head.len()], head[..], "{}", case.name);
        }
        if let Some(tail) = &case.object_tail_hex {
            let tail = hex::decode(tail).unwrap();
            let start = sealed.object.len() - tail.len();
            assert_eq!(sealed.object[start..], tail[..], "{}", case.name);
        }
        assert_eq!(
            open_chunk(&dek, lineage, &expected_id, &sealed.object).unwrap(),
            plaintext,
            "{}",
            case.name
        );
    }
}

#[test]
fn opening_a_chunk_refuses_in_contract_order() {
    let lineage = "stl_open_order";
    let sealed = seal_chunk(&DEK, lineage, &[9; 12], b"liskov state chunk");
    let id = sealed.chunk_id;

    assert_eq!(
        open_chunk(&DEK, lineage, &id, &sealed.object[..28]),
        Err(ChunkError::ChunkTruncated { len: 28 })
    );
    let mut versioned = sealed.object.clone();
    versioned[0] = 0x02;
    assert_eq!(
        open_chunk(&DEK, lineage, &id, &versioned),
        Err(ChunkError::UnsupportedChunkVersion(0x02))
    );
    let mut flipped = sealed.object.clone();
    *flipped.last_mut().unwrap() ^= 1;
    assert_eq!(
        open_chunk(&DEK, lineage, &id, &flipped),
        Err(ChunkError::Decrypt)
    );
    assert_eq!(
        open_chunk(&[8; 32], lineage, &id, &sealed.object),
        Err(ChunkError::Decrypt)
    );
    assert_eq!(
        open_chunk(&DEK, "stl_other", &id, &sealed.object),
        Err(ChunkError::Decrypt)
    );
    // A different id under which the object was sealed: the AAD differs first.
    assert_eq!(
        open_chunk(&DEK, lineage, &[0; 32], &sealed.object),
        Err(ChunkError::Decrypt)
    );
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestVectors {
    format: String,
    signature_domain: String,
    cases: Vec<ManifestCase>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestCase {
    name: String,
    signer_seed_hex: String,
    manifest_json: String,
    canonical_hex: String,
    digest_hex: String,
    signature_hex: String,
}

#[test]
fn manifest_vectors_replay_byte_for_byte() {
    let v: ManifestVectors = serde_json::from_str(MANIFEST_VECTORS).unwrap();
    assert_eq!(v.format, "liskov-state-manifest-v1");
    assert_eq!(v.signature_domain.as_bytes(), SIGNATURE_DOMAIN);
    let names: Vec<&str> = v.cases.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["genesis", "successor"]);

    let mut manifests = Vec::new();
    for case in &v.cases {
        let manifest: Manifest = serde_json::from_str(&case.manifest_json).unwrap();
        assert_eq!(
            serde_json::to_string(&manifest).unwrap(),
            case.manifest_json,
            "{}",
            case.name
        );
        assert_eq!(
            hex::encode(canonical_bytes(&manifest).unwrap()),
            case.canonical_hex,
            "{}",
            case.name
        );
        let manifest_digest = digest(&manifest).unwrap();
        assert_eq!(
            hex::encode(manifest_digest),
            case.digest_hex,
            "{}",
            case.name
        );

        let signer = SeedSigner::from_seed(&arr(&case.signer_seed_hex));
        assert_eq!(
            signer.public_key(),
            manifest.writer.signer_public_key,
            "{}",
            case.name
        );
        let signature = sign(&manifest, &signer).unwrap();
        assert_eq!(hex::encode(signature), case.signature_hex, "{}", case.name);
        assert_eq!(
            verify_signature(&manifest, &signature, &manifest.writer.signer_public_key),
            Ok(manifest_digest),
            "{}",
            case.name
        );
        manifests.push(manifest);
    }
    assert_eq!(
        manifests[1].previous_manifest_digest,
        Some(digest(&manifests[0]).unwrap())
    );
    assert_eq!(verify_successor(&manifests[0], &manifests[1]), Ok(()));
}

#[test]
fn signing_refuses_a_signer_that_is_not_the_named_writer() {
    let v: ManifestVectors = serde_json::from_str(MANIFEST_VECTORS).unwrap();
    let manifest: Manifest = serde_json::from_str(&v.cases[0].manifest_json).unwrap();
    assert!(matches!(
        sign(&manifest, &SeedSigner::from_seed(&SEED)),
        Err(SnapshotError::Manifest(ManifestError::SignerMismatch))
    ));

    struct Lying(SeedSigner);
    impl StateSigner for Lying {
        fn public_key(&self) -> [u8; 32] {
            self.0.public_key()
        }
        fn sign_ed25519(&self, _: &[u8]) -> Option<[u8; 64]> {
            Some([0; 64])
        }
    }
    let lying = Lying(SeedSigner::from_seed(&arr(&v.cases[0].signer_seed_hex)));
    assert!(matches!(
        sign(&manifest, &lying),
        Err(SnapshotError::Manifest(ManifestError::BadSignature))
    ));
}

// ---------------------------------------------------------------------------
// Directory snapshots

struct Fixture {
    base: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "liskov-state-snapshot-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        Self { base }
    }

    fn source(&self) -> PathBuf {
        self.base.join("source")
    }

    fn objects(&self) -> PathBuf {
        self.base.join("objects")
    }

    fn target(&self) -> PathBuf {
        self.base.join("restored")
    }

    /// The base directory's entries, so a refused restore can be shown to
    /// leave nothing behind.
    fn base_entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.base)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = remove_staging(&self.base);
    }
}

fn lineage(captured_at_ms: u64) -> SnapshotLineage {
    SnapshotLineage {
        org: "org_bzbo".into(),
        application: "app_bzbo".into(),
        lineage: "stl_bzbo_lineage".into(),
        job_id: "job_bzbo".into(),
        processor_id: "processor_bzbo".into(),
        generation: 3,
        dek_version: 1,
        captured_at_ms,
        recipients: Vec::new(),
    }
}

/// Deterministic, incompressible bytes so FastCDC finds real boundaries.
fn pseudo_random(len: usize) -> Vec<u8> {
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

fn set_mtime(path: &Path, seconds: u64) {
    File::open(path)
        .unwrap()
        .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(seconds)))
        .unwrap();
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// Nested directories, an empty file, a 9 MiB file, a symlink, a path longer
/// than a plain tar name, and non-default modes and mtimes.
fn build_tree(root: &Path) {
    fs::create_dir_all(root.join("nested/deeper")).unwrap();
    let long_dir = root.join("l".repeat(70));
    fs::create_dir(&long_dir).unwrap();
    fs::write(
        long_dir.join(format!("{}.txt", "m".repeat(70))),
        b"long path",
    )
    .unwrap();
    fs::write(root.join("empty"), b"").unwrap();
    fs::write(root.join("a-b.txt"), b"sorts between a and a/").unwrap();
    fs::write(root.join("private.txt"), b"owner read only").unwrap();
    fs::write(root.join("nested/deeper/run.sh"), b"#!/bin/sh\nexit 0\n").unwrap();
    fs::write(root.join(BIG_FILE), pseudo_random(BIG_FILE_BYTES)).unwrap();
    symlink("nested/deeper/run.sh", root.join("link")).unwrap();
    symlink("../missing-target", root.join("nested/dangling")).unwrap();

    set_mode(&root.join("empty"), 0o600);
    set_mode(&root.join("private.txt"), 0o400);
    set_mode(&root.join("nested/deeper/run.sh"), 0o751);
    set_mode(&root.join(BIG_FILE), 0o640);
    set_mode(&root.join("nested"), 0o700);
    set_mode(&root.join("nested/deeper"), 0o750);
    set_mode(root, 0o710);

    let long_file = format!("{}/{}.txt", "l".repeat(70), "m".repeat(70));
    let mut seconds = 1_700_000_000;
    for file in [
        long_file.as_str(),
        "empty",
        "a-b.txt",
        "private.txt",
        "nested/deeper/run.sh",
        BIG_FILE,
    ] {
        seconds += 1000;
        set_mtime(&root.join(file), seconds);
    }
    // An mtime of 0 is kept as 0.
    set_mtime(&root.join("a-b.txt"), 0);
    // Directories last, deepest first: creating an entry moves its mtime.
    for dir in ["nested/deeper", "nested", &"l".repeat(70), ""] {
        seconds += 1000;
        set_mtime(&root.join(dir), seconds);
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Observed {
    kind: &'static str,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
    /// SHA-256 of the file bytes or the link target, so a failure prints
    /// something readable.
    content: String,
}

/// Every entry under `root`, including `root` itself as "".
fn observe(root: &Path) -> BTreeMap<String, Observed> {
    let mut seen = BTreeMap::new();
    let mut pending = vec![(root.to_path_buf(), String::new())];
    while let Some((path, relative)) = pending.pop() {
        let meta = fs::symlink_metadata(&path).unwrap();
        let (kind, mtime, content) = if meta.is_dir() {
            for child in fs::read_dir(&path).unwrap() {
                let child = child.unwrap();
                let name = child.file_name().into_string().unwrap();
                let child_relative = if relative.is_empty() {
                    name
                } else {
                    format!("{relative}/{name}")
                };
                pending.push((child.path(), child_relative));
            }
            ("dir", meta.mtime(), Vec::new())
        } else if meta.file_type().is_symlink() {
            let target = fs::read_link(&path).unwrap();
            (
                "symlink",
                meta.mtime(),
                target.as_os_str().as_bytes().to_vec(),
            )
        } else {
            ("file", meta.mtime(), fs::read(&path).unwrap())
        };
        seen.insert(
            relative,
            Observed {
                kind,
                mode: meta.mode() & 0o7777,
                uid: meta.uid(),
                gid: meta.gid(),
                mtime,
                content: format!("{} bytes, sha256 {}", content.len(), sha256_hex(&content)),
            },
        );
    }
    seen
}

/// Compares two observed trees entry by entry, so a failure names the path.
fn assert_same_tree(actual: &BTreeMap<String, Observed>, expected: &BTreeMap<String, Observed>) {
    for (path, entry) in expected {
        assert_eq!(actual.get(path), Some(entry), "{path:?}");
    }
    let extra: Vec<&String> = actual
        .keys()
        .filter(|k| !expected.contains_key(*k))
        .collect();
    assert!(extra.is_empty(), "unexpected entries {extra:?}");
}

fn object_names(objects: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(objects)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn trust<'a>(signer: &'a [u8; 32], previous: Option<&'a Manifest>) -> RestoreTrust<'a> {
    RestoreTrust { signer, previous }
}

#[test]
fn a_directory_round_trips_with_identical_content_and_metadata() {
    let fixture = Fixture::new("round-trip");
    let source = fixture.source();
    build_tree(&source);
    let signer = SeedSigner::from_seed(&SEED);

    let snapshot = write(
        &source,
        &DEK,
        &lineage(1),
        None,
        &signer,
        &fixture.objects(),
    )
    .unwrap();
    let manifest = &snapshot.signed.manifest;
    assert_eq!(manifest.sequence, 1);
    assert_eq!(manifest.previous_manifest_digest, None);
    assert_eq!(manifest.writer.signer_public_key, signer.public_key());
    assert!(
        manifest.plaintext_bytes > BIG_FILE_BYTES as u64,
        "the stream holds the whole tree"
    );
    assert!(manifest.chunks.len() >= 3, "9 MiB cuts into several chunks");
    for chunk in &manifest.chunks {
        assert!(chunk.plaintext_bytes <= CHUNK_MAX_BYTES as u64);
        assert_eq!(
            chunk.object_bytes,
            chunk.plaintext_bytes + CHUNK_OVERHEAD as u64
        );
    }
    assert_eq!(snapshot.report.chunks_written, manifest.chunks.len());
    assert_eq!(snapshot.report.chunks_reused, 0);
    assert_eq!(snapshot.report.special_files_skipped, 0);
    assert_eq!(
        object_names(&fixture.objects()),
        {
            let mut ids: Vec<String> = manifest.chunks.iter().map(|c| hex::encode(c.id)).collect();
            ids.sort();
            ids
        },
        "the object directory holds exactly the chunks, with no temporary files"
    );
    assert_eq!(
        verify_signature(manifest, &snapshot.signed.signature, &signer.public_key()),
        Ok(digest(manifest).unwrap())
    );

    let report = restore(
        &snapshot.signed,
        &DEK,
        trust(&signer.public_key(), None),
        &fixture.objects(),
        &fixture.target(),
    )
    .unwrap();
    assert_eq!(report.chunks, manifest.chunks.len());
    assert_eq!(report.plaintext_bytes, manifest.plaintext_bytes);

    let expected = observe(&source);
    assert_eq!(expected.len(), 12);
    assert_eq!(expected[""].mode, 0o710);
    assert_eq!(expected["private.txt"].mode, 0o400);
    assert!(expected[BIG_FILE].content.starts_with("9437184 bytes"));
    assert_same_tree(&observe(&fixture.target()), &expected);
    assert_eq!(fixture.base_entries(), ["objects", "restored", "source"]);
}

#[test]
fn the_archive_is_deterministic() {
    let fixture = Fixture::new("deterministic");
    let source = fixture.source();
    build_tree(&source);
    let signer = SeedSigner::from_seed(&SEED);
    let first = write(
        &source,
        &DEK,
        &lineage(1),
        None,
        &signer,
        &fixture.objects(),
    )
    .unwrap();
    let second = write(
        &source,
        &DEK,
        &lineage(1),
        None,
        &signer,
        &fixture.objects(),
    )
    .unwrap();
    assert_eq!(first.signed, second.signed);
    assert_eq!(second.report.chunks_written, 0);
    assert_eq!(
        second.report.chunks_reused,
        second.signed.manifest.chunks.len()
    );
}

#[test]
fn a_second_snapshot_writes_only_the_changed_chunks_and_chains_to_the_first() {
    let fixture = Fixture::new("incremental");
    let source = fixture.source();
    build_tree(&source);
    let signer = SeedSigner::from_seed(&SEED);
    let first = write(
        &source,
        &DEK,
        &lineage(1),
        None,
        &signer,
        &fixture.objects(),
    )
    .unwrap();

    // Change one byte in the middle of the 9 MiB file, keeping its mtime so
    // only its data moves.
    let big = source.join(BIG_FILE);
    let mtime = fs::metadata(&big).unwrap().modified().unwrap();
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&big)
        .unwrap();
    file.seek(SeekFrom::Start(4 * 1024 * 1024 + 12345)).unwrap();
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte).unwrap();
    file.seek(SeekFrom::Current(-1)).unwrap();
    file.write_all(&[byte[0] ^ 0xff]).unwrap();
    file.set_times(FileTimes::new().set_modified(mtime))
        .unwrap();
    drop(file);

    let second = write(
        &source,
        &DEK,
        &lineage(2),
        Some(&first.signed.manifest),
        &signer,
        &fixture.objects(),
    )
    .unwrap();
    let (m1, m2) = (&first.signed.manifest, &second.signed.manifest);

    let old: std::collections::HashSet<_> = m1.chunks.iter().map(|c| c.id).collect();
    let new_ids: Vec<_> = m2.chunks.iter().filter(|c| !old.contains(&c.id)).collect();
    // One flipped byte inside a chunk changes that chunk and nothing else: the
    // byte sits far from any boundary, so no cut point moves.
    assert_eq!(new_ids.len(), 1);
    assert_eq!(second.report.chunks_written, 1);
    assert_eq!(second.report.chunks_reused, m2.chunks.len() - 1);
    assert_eq!(m2.chunks.len(), m1.chunks.len());
    assert_eq!(
        object_names(&fixture.objects()).len(),
        m1.chunks.len() + 1,
        "the object directory gained exactly one object"
    );

    assert_eq!(m2.sequence, 2);
    assert_eq!(m2.previous_manifest_digest, Some(digest(m1).unwrap()));
    assert_eq!(verify_successor(m1, m2), Ok(()));

    restore(
        &second.signed,
        &DEK,
        trust(&signer.public_key(), Some(m1)),
        &fixture.objects(),
        &fixture.target(),
    )
    .unwrap();
    assert_same_tree(&observe(&fixture.target()), &observe(&source));

    // The first snapshot is still whole: its chunks were never rewritten.
    let earlier = fixture.base.join("earlier");
    restore(
        &first.signed,
        &DEK,
        trust(&signer.public_key(), None),
        &fixture.objects(),
        &earlier,
    )
    .unwrap();
    let restored = fs::read(earlier.join(BIG_FILE)).unwrap();
    assert_eq!(restored, pseudo_random(BIG_FILE_BYTES));
}

/// A written snapshot, for the refusal tests.
fn snapshot_of_tree(fixture: &Fixture) -> (Snapshot, SeedSigner) {
    build_tree(&fixture.source());
    let signer = SeedSigner::from_seed(&SEED);
    let snapshot = write(
        &fixture.source(),
        &DEK,
        &lineage(1),
        None,
        &signer,
        &fixture.objects(),
    )
    .unwrap();
    (snapshot, signer)
}

#[test]
fn restore_refuses_a_missing_chunk_and_leaves_the_target_untouched() {
    let fixture = Fixture::new("missing");
    let (snapshot, signer) = snapshot_of_tree(&fixture);
    let missing = &snapshot.signed.manifest.chunks[1];
    fs::remove_file(object_path(&fixture.objects(), &missing.id)).unwrap();
    let before = fixture.base_entries();

    let refused = restore(
        &snapshot.signed,
        &DEK,
        trust(&signer.public_key(), None),
        &fixture.objects(),
        &fixture.target(),
    );
    assert!(
        matches!(&refused, Err(SnapshotError::MissingChunk(id)) if *id == hex::encode(missing.id)),
        "{refused:?}"
    );
    assert!(!fixture.target().exists());
    assert_eq!(fixture.base_entries(), before);
}

#[test]
fn restore_refuses_a_corrupted_chunk_and_leaves_the_target_untouched() {
    let fixture = Fixture::new("corrupted");
    let (snapshot, signer) = snapshot_of_tree(&fixture);
    // The last chunk, so extraction has already written into the staging
    // directory when the corruption is found.
    let last = snapshot.signed.manifest.chunks.last().unwrap();
    let path = object_path(&fixture.objects(), &last.id);
    let mut object = fs::read(&path).unwrap();
    let middle = object.len() / 2;
    object[middle] ^= 0x01;
    fs::write(&path, &object).unwrap();

    // An existing empty target directory stays exactly as it was.
    fs::create_dir(fixture.target()).unwrap();
    set_mode(&fixture.target(), 0o705);
    set_mtime(&fixture.target(), 1_600_000_000);
    let target_before = observe(&fixture.target());
    let before = fixture.base_entries();

    let refused = restore(
        &snapshot.signed,
        &DEK,
        trust(&signer.public_key(), None),
        &fixture.objects(),
        &fixture.target(),
    );
    assert!(
        matches!(refused, Err(SnapshotError::Chunk(ChunkError::Decrypt))),
        "{refused:?}"
    );
    assert_eq!(observe(&fixture.target()), target_before);
    assert_eq!(
        fixture.base_entries(),
        before,
        "the staging directory is gone"
    );

    // A truncated object is refused before any extraction.
    fs::write(&path, &object[..object.len() - 1]).unwrap();
    let refused = restore(
        &snapshot.signed,
        &DEK,
        trust(&signer.public_key(), None),
        &fixture.objects(),
        &fixture.target(),
    );
    assert!(
        matches!(refused, Err(SnapshotError::ObjectLength { .. })),
        "{refused:?}"
    );
    assert_eq!(observe(&fixture.target()), target_before);
}

#[test]
fn restore_refuses_a_manifest_whose_signature_fails() {
    let fixture = Fixture::new("signature");
    let (snapshot, signer) = snapshot_of_tree(&fixture);
    let before = fixture.base_entries();

    let mut forged = snapshot.signed.clone();
    forged.signature[5] ^= 0x01;
    let refused = restore(
        &forged,
        &DEK,
        trust(&signer.public_key(), None),
        &fixture.objects(),
        &fixture.target(),
    );
    assert!(
        matches!(
            refused,
            Err(SnapshotError::Manifest(ManifestError::BadSignature))
        ),
        "{refused:?}"
    );

    // A changed manifest under the original signature.
    let mut altered = snapshot.signed.clone();
    altered.manifest.captured_at_ms += 1;
    let refused = restore(
        &altered,
        &DEK,
        trust(&signer.public_key(), None),
        &fixture.objects(),
        &fixture.target(),
    );
    assert!(
        matches!(
            refused,
            Err(SnapshotError::Manifest(ManifestError::BadSignature))
        ),
        "{refused:?}"
    );

    // A valid signature by a key the reader does not trust.
    let other = SeedSigner::from_seed(&[0x24; 32]).public_key();
    let refused = restore(
        &snapshot.signed,
        &DEK,
        trust(&other, None),
        &fixture.objects(),
        &fixture.target(),
    );
    assert!(
        matches!(
            refused,
            Err(SnapshotError::Manifest(ManifestError::SignerMismatch))
        ),
        "{refused:?}"
    );
    assert!(!fixture.target().exists());
    assert_eq!(fixture.base_entries(), before);
}

#[test]
fn restore_refuses_a_manifest_that_does_not_chain_to_the_supplied_previous() {
    let fixture = Fixture::new("chain");
    let (first, signer) = snapshot_of_tree(&fixture);
    let second = write(
        &fixture.source(),
        &DEK,
        &lineage(2),
        Some(&first.signed.manifest),
        &signer,
        &fixture.objects(),
    )
    .unwrap();
    // Another genesis of the same lineage: the same place in the chain as
    // `first`, but a different manifest.
    let rival = write(
        &fixture.source(),
        &DEK,
        &lineage(99),
        None,
        &signer,
        &fixture.objects(),
    )
    .unwrap();
    let before = fixture.base_entries();
    let restore_after = |signed: &SignedManifest, previous: &Manifest| {
        restore(
            signed,
            &DEK,
            trust(&signer.public_key(), Some(previous)),
            &fixture.objects(),
            &fixture.target(),
        )
    };

    let fork = restore_after(&second.signed, &rival.signed.manifest);
    assert!(
        matches!(fork, Err(SnapshotError::Manifest(ManifestError::Fork))),
        "{fork:?}"
    );
    let rollback = restore_after(&first.signed, &second.signed.manifest);
    assert!(
        matches!(
            rollback,
            Err(SnapshotError::Manifest(
                ManifestError::SequenceNotAdvanced {
                    previous: 2,
                    next: 1
                }
            ))
        ),
        "{rollback:?}"
    );
    let replay = restore_after(&first.signed, &first.signed.manifest);
    assert!(
        matches!(
            replay,
            Err(SnapshotError::Manifest(
                ManifestError::SequenceNotAdvanced { .. }
            ))
        ),
        "{replay:?}"
    );
    let mut other_lineage = lineage(1);
    other_lineage.lineage = "stl_other".into();
    let stranger = write(
        &fixture.source(),
        &DEK,
        &other_lineage,
        None,
        &signer,
        &fixture.objects(),
    )
    .unwrap();
    let cross = restore_after(&second.signed, &stranger.signed.manifest);
    assert!(
        matches!(
            cross,
            Err(SnapshotError::Manifest(ManifestError::CrossLineage(
                "lineage"
            )))
        ),
        "{cross:?}"
    );
    assert!(!fixture.target().exists());
    assert_eq!(fixture.base_entries(), before);

    restore_after(&second.signed, &first.signed.manifest).unwrap();
}

#[test]
fn special_files_are_skipped_and_counted() {
    let fixture = Fixture::new("special");
    let source = fixture.source();
    fs::create_dir_all(source.join("run")).unwrap();
    fs::write(source.join("data"), b"kept").unwrap();
    let _listener = UnixListener::bind(source.join("run/app.sock")).unwrap();
    let signer = SeedSigner::from_seed(&SEED);

    let snapshot = write(
        &source,
        &DEK,
        &lineage(1),
        None,
        &signer,
        &fixture.objects(),
    )
    .unwrap();
    assert_eq!(snapshot.report.special_files_skipped, 1);
    restore(
        &snapshot.signed,
        &DEK,
        trust(&signer.public_key(), None),
        &fixture.objects(),
        &fixture.target(),
    )
    .unwrap();
    assert_eq!(fs::read(fixture.target().join("data")).unwrap(), b"kept");
    assert!(fixture.target().join("run").is_dir());
    assert!(!fixture.target().join("run/app.sock").exists());
}

#[test]
fn an_empty_directory_round_trips() {
    let fixture = Fixture::new("empty-dir");
    fs::create_dir(fixture.source()).unwrap();
    let signer = SeedSigner::from_seed(&SEED);
    let snapshot = write(
        &fixture.source(),
        &DEK,
        &lineage(1),
        None,
        &signer,
        &fixture.objects(),
    )
    .unwrap();
    restore(
        &snapshot.signed,
        &DEK,
        trust(&signer.public_key(), None),
        &fixture.objects(),
        &fixture.target(),
    )
    .unwrap();
    assert_same_tree(&observe(&fixture.target()), &observe(&fixture.source()));
}

#[test]
fn write_and_restore_refuse_unsafe_locations() {
    let fixture = Fixture::new("locations");
    let (snapshot, signer) = snapshot_of_tree(&fixture);

    let inside = write(
        &fixture.source(),
        &DEK,
        &lineage(1),
        None,
        &signer,
        &fixture.source().join("objects"),
    );
    assert!(
        matches!(inside, Err(SnapshotError::OutputInsideSource)),
        "{inside:?}"
    );

    let not_a_dir = write(
        &fixture.source().join("empty"),
        &DEK,
        &lineage(1),
        None,
        &signer,
        &fixture.objects(),
    );
    assert!(
        matches!(not_a_dir, Err(SnapshotError::SourceNotDirectory)),
        "{not_a_dir:?}"
    );

    let mut nameless = lineage(1);
    nameless.job_id.clear();
    let malformed = write(
        &fixture.source(),
        &DEK,
        &nameless,
        None,
        &signer,
        &fixture.base.join("never-created"),
    );
    assert!(
        matches!(
            malformed,
            Err(SnapshotError::Manifest(ManifestError::Malformed(
                "writer.jobId"
            )))
        ),
        "{malformed:?}"
    );
    assert!(!fixture.base.join("never-created").exists());

    fs::create_dir(fixture.target()).unwrap();
    fs::write(fixture.target().join("keep"), b"existing").unwrap();
    let occupied = restore(
        &snapshot.signed,
        &DEK,
        trust(&signer.public_key(), None),
        &fixture.objects(),
        &fixture.target(),
    );
    assert!(
        matches!(occupied, Err(SnapshotError::TargetNotEmpty)),
        "{occupied:?}"
    );
    assert_eq!(
        fs::read(fixture.target().join("keep")).unwrap(),
        b"existing"
    );

    let wrong_dek = restore(
        &snapshot.signed,
        &[8; 32],
        trust(&signer.public_key(), None),
        &fixture.objects(),
        &fixture.base.join("wrong-dek"),
    );
    assert!(
        matches!(wrong_dek, Err(SnapshotError::Chunk(ChunkError::Decrypt))),
        "{wrong_dek:?}"
    );
    assert!(!fixture.base.join("wrong-dek").exists());
}

#[test]
fn a_file_that_changes_size_while_archived_fails_the_write() {
    let fixture = Fixture::new("changing");
    let source = fixture.source();
    fs::create_dir(&source).unwrap();
    fs::write(source.join("grows"), b"abc").unwrap();
    let meta = fs::symlink_metadata(&source).unwrap();
    let (entries, _) = collect_entries(&source.canonicalize().unwrap(), &meta).unwrap();
    fs::write(source.join("grows"), b"abcdef").unwrap();
    let mut sink = ChunkSink {
        keys: ChunkKeys::new(&DEK, "stl_changing"),
        out: &fixture.base,
        buffer: Vec::new(),
        chunks: Vec::new(),
        report: WriteReport::default(),
        error: None,
    };
    let grown = archive_entries(&source, &entries, &mut sink);
    assert!(
        matches!(grown, Err(SnapshotError::SourceChanged)),
        "{grown:?}"
    );

    fs::write(source.join("grows"), b"a").unwrap();
    let mut sink = ChunkSink {
        keys: ChunkKeys::new(&DEK, "stl_changing"),
        out: &fixture.base,
        buffer: Vec::new(),
        chunks: Vec::new(),
        report: WriteReport::default(),
        error: None,
    };
    let shrunk = archive_entries(&source, &entries, &mut sink);
    assert!(
        matches!(shrunk, Err(SnapshotError::SourceChanged)),
        "{shrunk:?}"
    );
}

#[test]
fn restored_times_are_the_snapshot_times() {
    // A guard on the fixture itself: the times compared above are the ones
    // `build_tree` set, not the time the test ran.
    let fixture = Fixture::new("times");
    build_tree(&fixture.source());
    let observed = observe(&fixture.source());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // Symlinks keep their creation time; std cannot set a link's own times.
    for (path, entry) in observed.iter().filter(|(_, e)| e.kind != "symlink") {
        assert!(entry.mtime < now - 86_400, "{path} kept a fixture mtime");
    }
}
