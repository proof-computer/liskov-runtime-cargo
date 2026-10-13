//! Dark Cargo payload companion contract (ADR-0230/0232).
//!
//! The descriptor is outside the archive. Its compact JSON field order is the
//! declaration order below; inventories are sorted by ASCII path. Hash those
//! bytes separately from the archive, then bind both in the artifact record.
//! Validation describes metadata only: admission must still inspect the actual
//! archive, verify bytes, and resolve producer/ABI authority with existing owners.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub const CARGO_PAYLOAD_FORMAT_V1: &str = "liskov.cargo-payload.v1";
pub const PAYLOAD_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
pub const MAX_PAYLOAD_ENTRIES: usize = 256;
pub const MAX_PAYLOAD_EXPANDED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadEncryptionV1 {
    None,
    Signer,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PayloadTargetAbiV1 {
    pub os: String,
    pub architecture: String,
    pub environment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadProducerKindV1 {
    Member,
    GithubWorkflow,
}

/// Server-verified producer attribution, never upload or execution authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PayloadProducerV1 {
    pub kind: PayloadProducerKindV1,
    pub subject: String,
    pub source_revision: String,
    pub build_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PayloadEntryV1 {
    Directory {
        path: String,
    },
    RegularFile {
        path: String,
        size_bytes: u64,
        digest: String,
        executable: bool,
    },
}

impl PayloadEntryV1 {
    pub fn path(&self) -> &str {
        match self {
            Self::Directory { path } | Self::RegularFile { path, .. } => path,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CargoPayloadDescriptorV1 {
    pub format: String,
    pub artifact_digest: String,
    pub artifact_size_bytes: u64,
    pub encryption: PayloadEncryptionV1,
    pub target_abi: PayloadTargetAbiV1,
    pub entries: Vec<PayloadEntryV1>,
    pub entrypoints: Vec<String>,
    pub producer: PayloadProducerV1,
}

/// Closed, secret-free errors; no untrusted path or provenance is echoed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadDescriptorRefusal {
    UnsupportedFormat,
    UnsupportedEncryption,
    InvalidDigest,
    InvalidSize,
    InvalidAbi,
    InvalidProvenance,
    InvalidPath,
    InvalidInventory,
    InvalidEntrypoint,
    ExpansionLimit,
    Overflow,
}

pub fn is_payload_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Portable relative archive paths. No normalization, escaping or aliases.
pub fn is_payload_relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 256
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}

fn provenance_text(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 256
        && text
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"\"\\".contains(&b))
}

impl CargoPayloadDescriptorV1 {
    /// The archive byte ceiling is supplied by the existing artifact owner;
    /// this contract never substitutes or raises a configured upload limit.
    pub fn validate(&self, artifact_limit_bytes: u64) -> Result<(), PayloadDescriptorRefusal> {
        use PayloadDescriptorRefusal as R;
        if self.format != CARGO_PAYLOAD_FORMAT_V1 {
            return Err(R::UnsupportedFormat);
        }
        if self.encryption != PayloadEncryptionV1::None {
            return Err(R::UnsupportedEncryption);
        }
        if !is_payload_sha256_digest(&self.artifact_digest) {
            return Err(R::InvalidDigest);
        }
        if self.artifact_size_bytes == 0
            || self.artifact_size_bytes > artifact_limit_bytes
            || self.artifact_size_bytes > PAYLOAD_MAX_SAFE_INTEGER
        {
            return Err(R::InvalidSize);
        }
        // Syntax only; the existing catalogue owner decides actual ABI support.
        if ![
            &self.target_abi.os,
            &self.target_abi.architecture,
            &self.target_abi.environment,
        ]
        .iter()
        .all(|text| {
            !text.is_empty()
                && text.len() <= 64
                && text
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
        }) {
            return Err(R::InvalidAbi);
        }
        if ![
            &self.producer.subject,
            &self.producer.source_revision,
            &self.producer.build_id,
        ]
        .iter()
        .all(|text| provenance_text(text))
        {
            return Err(R::InvalidProvenance);
        }
        if self.entries.is_empty() || self.entries.len() > MAX_PAYLOAD_ENTRIES {
            return Err(R::InvalidInventory);
        }
        let mut previous = None;
        let mut files = BTreeSet::new();
        let mut executables = BTreeSet::new();
        let mut expanded = 0u64;
        for entry in &self.entries {
            let path = entry.path();
            if !is_payload_relative_path(path) {
                return Err(R::InvalidPath);
            }
            if previous.is_some_and(|previous| previous >= path) {
                return Err(R::InvalidInventory);
            }
            previous = Some(path);
            if let PayloadEntryV1::RegularFile {
                size_bytes,
                digest,
                executable,
                ..
            } = entry
            {
                if !is_payload_sha256_digest(digest) {
                    return Err(R::InvalidDigest);
                }
                expanded = expanded.checked_add(*size_bytes).ok_or(R::Overflow)?;
                files.insert(path);
                if *executable {
                    executables.insert(path);
                }
            }
        }
        if expanded > MAX_PAYLOAD_EXPANDED_BYTES {
            return Err(R::ExpansionLimit);
        }
        // A file cannot also be a directory implicitly used by another entry.
        for entry in &self.entries {
            let path = entry.path();
            for (index, _) in path.match_indices('/') {
                if files.contains(&path[..index]) {
                    return Err(R::InvalidInventory);
                }
            }
        }
        if self.entrypoints.is_empty()
            || self.entrypoints.len() > MAX_PAYLOAD_ENTRIES
            || self.entrypoints.windows(2).any(|p| p[0] >= p[1])
            || self
                .entrypoints
                .iter()
                .any(|p| !executables.contains(p.as_str()))
        {
            return Err(R::InvalidEntrypoint);
        }
        Ok(())
    }
}
