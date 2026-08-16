//! `proof.liskov.processor-hardware.v1` — the bounded, allowlisted hardware
//! source-readings payload (BKLG-20260710-e0ws Slice 3 stage 5b; ADR-0079).
//!
//! The payload reuses the `cargo-baseline-v1` collectors and closed fact
//! structs from `processor_facts` — there is no generic name/value map, so
//! the ADR-0079 forbidden catalog (serial, IMEI, second IMEI, MAC, SSID,
//! Android identifiers, credentials, customer arguments/environment,
//! unrestricted proc/sysfs dumps) is impossible to emit by construction.
//! The canonical bytes are pinned byte-identical to the `liskov-rs`
//! server codec through the shared `processor-hardware-v1` vector.
//!
//! The payload never travels and is never logged in Slice 3: the coverage
//! producer commits to its canonical digest inside the signed
//! coverage-result envelope and then drops it. Transport is Slice 4 work.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::diagnostics::canonical_json_bytes;
use crate::processor_facts::{
    AndroidCorroborationFact, AndroidFactCollector, CARGO_BASELINE_PROFILE, ExecutionFactCollector,
    ExecutionSurfaceFact,
};

pub const LISKOV_PROCESSOR_HARDWARE_DOMAIN_V1: &str = "proof.liskov.processor-hardware.v1";

/// The sanitized source-readings payload, wire-identical to the server's
/// strict codec: exactly these six fields, closed fact structs beneath.
#[derive(Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HardwareSourceReadingsV1 {
    domain: &'static str,
    profile: &'static str,
    helper_version: String,
    collected_at_ms: u64,
    android: AndroidCorroborationFact,
    execution: ExecutionSurfaceFact,
}

impl HardwareSourceReadingsV1 {
    pub(crate) fn new(
        helper_version: String,
        collected_at_ms: u64,
        android: AndroidCorroborationFact,
        execution: ExecutionSurfaceFact,
    ) -> Self {
        Self {
            domain: LISKOV_PROCESSOR_HARDWARE_DOMAIN_V1,
            profile: CARGO_BASELINE_PROFILE,
            helper_version,
            collected_at_ms,
            android,
            execution,
        }
    }
}

/// Read the allowlisted surfaces through the existing availability-first
/// `cargo-baseline-v1` collectors. Collection cannot fail structurally —
/// every unavailable surface keeps its exact reason.
pub(crate) fn collect_hardware_source_readings(
    collected_at_ms: u64,
    android: &dyn AndroidFactCollector,
    execution: &dyn ExecutionFactCollector,
) -> HardwareSourceReadingsV1 {
    HardwareSourceReadingsV1::new(
        env!("CARGO_PKG_VERSION").to_owned(),
        collected_at_ms,
        android.collect(),
        execution.collect(),
    )
}

/// The digest the signed coverage envelope commits to when the metric
/// payload is a hardware capture.
pub(crate) fn hardware_metric_digest(readings: &HardwareSourceReadingsV1) -> Option<String> {
    let value = serde_json::to_value(readings).ok()?;
    Some(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(canonical_json_bytes(&value)))
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::Value;

    use super::*;
    use crate::processor_facts::{Availability, CapabilityClass, KernelAbi, SeccompClass};

    pub(crate) fn fixture_android() -> AndroidCorroborationFact {
        AndroidCorroborationFact {
            android_release: Availability::Observed { value: "13".into() },
            sdk_level: Availability::Observed { value: "33".into() },
            security_patch: Availability::Observed {
                value: "2023-09-01".into(),
            },
            manufacturer: Availability::Observed {
                value: "samsung".into(),
            },
            brand: Availability::Observed {
                value: "samsung".into(),
            },
            model: Availability::Observed {
                value: "SM-S135DL".into(),
            },
            product_name: Availability::Observed {
                value: "a03sutfnssu".into(),
            },
            device: Availability::Observed {
                value: "a03su".into(),
            },
            board_platform: Availability::Observed {
                value: "mt6765".into(),
            },
        }
    }

    pub(crate) fn fixture_execution() -> ExecutionSurfaceFact {
        ExecutionSurfaceFact {
            architecture: Availability::Observed {
                value: "aarch64".into(),
            },
            word_size_bits: Availability::Observed { value: 64 },
            page_size_bytes: Availability::Observed { value: 4_096 },
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

    /// Cross-repo parity anchor: the payload built from the closed fact
    /// structs canonicalizes to exactly the bytes the `liskov-rs` server
    /// codec pinned in the shared vector, and to the same digest.
    #[test]
    fn matches_the_shared_processor_hardware_vector() {
        let fixture: Value = include_str!("../vectors/processor-hardware-v1.json")
            .parse()
            .expect("shared fixture parses");
        let readings = HardwareSourceReadingsV1::new(
            "0.10.30".into(),
            1_755_350_000_000,
            fixture_android(),
            fixture_execution(),
        );
        let canonical = canonical_json_bytes(&serde_json::to_value(&readings).unwrap());
        assert_eq!(
            std::str::from_utf8(&canonical).unwrap(),
            fixture["canonicalSourceReadings"].as_str().unwrap(),
        );
        assert_eq!(
            hardware_metric_digest(&readings).unwrap(),
            fixture["sourceReadingsDigest"].as_str().unwrap(),
        );
    }

    /// The serialized field set is closed: exactly the vector's field
    /// census, nothing dynamic, no forbidden surface representable.
    #[test]
    fn serialized_payload_carries_exactly_the_allowlisted_fields() {
        let readings = HardwareSourceReadingsV1::new(
            "0.10.30".into(),
            1,
            fixture_android(),
            fixture_execution(),
        );
        let value = serde_json::to_value(&readings).unwrap();
        let top: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let mut sorted = top.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            [
                "android",
                "collectedAtMs",
                "domain",
                "execution",
                "helperVersion",
                "profile",
            ]
        );
        let android: Vec<&str> = value["android"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let mut android_sorted = android.clone();
        android_sorted.sort_unstable();
        assert_eq!(
            android_sorted,
            [
                "androidRelease",
                "boardPlatform",
                "brand",
                "device",
                "manufacturer",
                "model",
                "productName",
                "sdkLevel",
                "securityPatch",
            ]
        );
        let execution: Vec<&str> = value["execution"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let mut execution_sorted = execution.clone();
        execution_sorted.sort_unstable();
        assert_eq!(
            execution_sorted,
            [
                "architecture",
                "effectiveCapabilities",
                "kernelAbi",
                "noNewPrivs",
                "pageSizeBytes",
                "seccomp",
                "wordSizeBits",
            ]
        );
    }
}
