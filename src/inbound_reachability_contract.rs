//! Inbound reachability v1 wire contract. Authoritative source: liskov-rs
//! slipway-executor-contracts; independent producer/prober copies share vectors.
//!
//! Each family's verdict is minted and authenticated by the prober on its own,
//! because the two verdicts come from two separate requests over two separate
//! address families. The device assembles them; it can drop one, but the MAC
//! means it can never write one.
use serde::{Deserialize, Serialize};

/// The device binds inside this range: a Cargo workload cannot bind below 1024.
pub const INBOUND_PORT_MIN: u16 = 20_000;
pub const INBOUND_PORT_MAX: u16 = 60_000;
pub const INBOUND_NONCE_BYTES: usize = 32;
pub const INBOUND_SIGNATURE_BYTES: usize = 64;
/// Every wait is two seconds: a firewalled processor is the common case and
/// must cost the probe the same as a reachable one.
pub const INBOUND_CONNECT_TIMEOUT_MS: u64 = 2_000;
pub const INBOUND_READ_TIMEOUT_MS: u64 = 2_000;
/// Whole-check ceiling, both families in parallel.
pub const INBOUND_BUDGET_MS: u64 = 4_000;
/// Bytes the prober will read before giving up on a reply.
pub const INBOUND_READ_CAP: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboundFamily {
    V4,
    V6,
}
impl InboundFamily {
    pub fn code(self) -> &'static str {
        match self {
            Self::V4 => "v4",
            Self::V6 => "v6",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboundVerdict {
    /// Connected, and the listener returned a signature-shaped reply.
    Reachable,
    ConnectTimeout,
    ConnectRefused,
    /// The connection failed for a reason that is neither a refusal, a timeout,
    /// nor a missing route. Kept distinct so it cannot inflate any of those.
    ConnectFailed,
    /// Connected, but nothing signature-shaped came back.
    NoSignature,
    /// The prober itself has no route for this family. Never a processor fact:
    /// a platform limitation is not evidence about a device's firewall.
    ProberNoEgress,
}
impl InboundVerdict {
    pub fn code(self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::ConnectTimeout => "connect_timeout",
            Self::ConnectRefused => "connect_refused",
            Self::ConnectFailed => "connect_failed",
            Self::NoSignature => "no_signature",
            Self::ProberNoEgress => "prober_no_egress",
        }
    }
    /// Whether this verdict is the prober's claim that a path exists. Only a
    /// reachable verdict carries a signature for the server to check.
    pub fn is_reachable(self) -> bool {
        matches!(self, Self::Reachable)
    }
}

/// One family's prober-authenticated verdict, embedded verbatim by the device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InboundFamilyVerdict {
    pub version: u8,
    pub challenge_digest: String,
    pub region: String,
    pub family: InboundFamily,
    pub verdict: InboundVerdict,
    pub connect_ms: u64,
    /// The prober's nonce for this attempt, lowercase hex, 32 bytes.
    pub nonce: String,
    /// Exactly the bytes the listener returned, when they were signature-shaped.
    /// The prober cannot check them — it does not hold the device's key — so it
    /// attests only that these bytes came back over the path it opened.
    pub signature: Option<String>,
    pub mac: String,
}

/// The device-assembled block: unsigned timing plus the signed verdicts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InboundReachabilityV1 {
    pub version: u8,
    pub started_at_ms: u64,
    pub duration_ms: u64,
    pub families: Vec<InboundFamilyVerdict>,
}

fn lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

impl InboundFamilyVerdict {
    pub fn validate(&self) -> Result<(), String> {
        let invalid = || "invalid inbound reachability v1".to_string();
        if self.version != 1 || self.region != "lhr" {
            return Err(invalid());
        }
        if !lower_hex(&self.nonce, INBOUND_NONCE_BYTES) {
            return Err(invalid());
        }
        if self
            .challenge_digest
            .strip_prefix("sha256:")
            .is_none_or(|d| !lower_hex(d, 32))
        {
            return Err(invalid());
        }
        if !lower_hex(&self.mac, 32) {
            return Err(invalid());
        }
        if self.connect_ms > INBOUND_CONNECT_TIMEOUT_MS {
            return Err(invalid());
        }
        // A signature exists exactly when the prober got a path and a reply.
        match (&self.signature, self.verdict.is_reachable()) {
            (Some(signature), true) => {
                let hex = signature.strip_prefix("0x").ok_or_else(invalid)?;
                if !lower_hex(hex, INBOUND_SIGNATURE_BYTES) {
                    return Err(invalid());
                }
            }
            (None, false) => {}
            _ => return Err(invalid()),
        }
        // A refused connection is immediate; a timeout consumed the whole wait.
        if self.verdict == InboundVerdict::ConnectTimeout
            && self.connect_ms != INBOUND_CONNECT_TIMEOUT_MS
        {
            return Err(invalid());
        }
        if self.verdict == InboundVerdict::ProberNoEgress && self.connect_ms != 0 {
            return Err(invalid());
        }
        Ok(())
    }
}

impl InboundReachabilityV1 {
    pub fn validate(&self) -> Result<(), String> {
        let invalid = || "invalid inbound reachability v1".to_string();
        if self.version != 1 || self.duration_ms > INBOUND_BUDGET_MS {
            return Err(invalid());
        }
        if self.families.is_empty() || self.families.len() > 2 {
            return Err(invalid());
        }
        let mut seen: Vec<InboundFamily> = Vec::with_capacity(2);
        for family in &self.families {
            family.validate()?;
            if seen.contains(&family.family) {
                return Err(invalid());
            }
            seen.push(family.family);
            // One probe, one challenge: every verdict must name the same one.
            if family.challenge_digest != self.families[0].challenge_digest {
                return Err(invalid());
            }
        }
        Ok(())
    }

    /// The verdict for one family, if the device presented one.
    pub fn family(&self, family: InboundFamily) -> Option<&InboundFamilyVerdict> {
        self.families.iter().find(|f| f.family == family)
    }
}

/// A well-formed block, shared by the catalog test and by every copy's tests.
#[cfg(test)]
pub fn sample_block(challenge_digest: &str) -> InboundReachabilityV1 {
    let verdict = |family, verdict, connect_ms, signature: Option<&str>| InboundFamilyVerdict {
        version: 1,
        challenge_digest: challenge_digest.to_string(),
        region: "lhr".into(),
        family,
        verdict,
        connect_ms,
        nonce: "a".repeat(64),
        signature: signature.map(str::to_string),
        mac: "b".repeat(64),
    };
    InboundReachabilityV1 {
        version: 1,
        started_at_ms: 1_700_000_000_000,
        duration_ms: 2_041,
        families: vec![
            verdict(
                InboundFamily::V4,
                InboundVerdict::Reachable,
                41,
                Some(&format!("0x{}", "c".repeat(128))),
            ),
            verdict(
                InboundFamily::V6,
                InboundVerdict::ConnectTimeout,
                INBOUND_CONNECT_TIMEOUT_MS,
                None,
            ),
        ],
    }
}

#[cfg(test)]
mod catalog_tests {
    use super::*;

    fn keys(value: &serde_json::Value) -> Vec<String> {
        let mut keys: Vec<String> = value
            .as_object()
            .unwrap()
            .keys()
            .map(ToString::to_string)
            .collect();
        keys.sort();
        keys
    }
    fn admitted(catalog: &serde_json::Value, field: &str) -> Vec<String> {
        let mut names: Vec<String> = catalog[field]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn catalog_and_closed_wire_fields_agree() {
        let catalog: serde_json::Value =
            serde_json::from_str(include_str!("../contracts/inbound-reachability-v1.json"))
                .unwrap();
        let block = sample_block("sha256:{}".replace("{}", &"1".repeat(64)).as_str());
        block.validate().unwrap();
        let value = serde_json::to_value(&block).unwrap();
        assert_eq!(keys(&value), admitted(&catalog, "fields"));
        assert_eq!(
            keys(&value["families"][0]),
            admitted(&catalog, "familyFields")
        );
        assert_eq!(catalog["currentProfile"], false);
        assert_eq!(catalog["factKind"], "inbound_reachability");
        assert_eq!(catalog["bounds"]["budgetMs"], INBOUND_BUDGET_MS);
        assert_eq!(
            catalog["bounds"]["connectTimeoutMs"],
            INBOUND_CONNECT_TIMEOUT_MS
        );
        assert_eq!(catalog["bounds"]["readTimeoutMs"], INBOUND_READ_TIMEOUT_MS);
        assert_eq!(catalog["bounds"]["nonceBytes"], INBOUND_NONCE_BYTES);
        assert_eq!(catalog["bounds"]["signatureBytes"], INBOUND_SIGNATURE_BYTES);
        assert_eq!(catalog["bounds"]["portMin"], INBOUND_PORT_MIN);
        assert_eq!(catalog["bounds"]["portMax"], INBOUND_PORT_MAX);
        // The catalog forbids addresses; the wire has nowhere to put one.
        let serialized = serde_json::to_string(&block).unwrap();
        assert!(!serialized.contains("address") && !serialized.contains("ip"));
    }

    #[test]
    fn validation_refuses_a_block_that_claims_more_than_the_prober_said() {
        let digest = format!("sha256:{}", "1".repeat(64));
        let reachable_without_signature = |mut b: InboundReachabilityV1| {
            b.families[0].signature = None;
            b
        };
        let unreachable_with_signature = |mut b: InboundReachabilityV1| {
            b.families[1].signature = Some(format!("0x{}", "c".repeat(128)));
            b
        };
        let duplicate_family = |mut b: InboundReachabilityV1| {
            b.families[1].family = InboundFamily::V4;
            b
        };
        let mixed_challenges = |mut b: InboundReachabilityV1| {
            b.families[1].challenge_digest = format!("sha256:{}", "2".repeat(64));
            b
        };
        let short_timeout = |mut b: InboundReachabilityV1| {
            b.families[1].connect_ms = 5;
            b
        };
        let over_budget = |mut b: InboundReachabilityV1| {
            b.duration_ms = INBOUND_BUDGET_MS + 1;
            b
        };
        let no_families = |mut b: InboundReachabilityV1| {
            b.families.clear();
            b
        };
        for mutate in [
            reachable_without_signature,
            unreachable_with_signature,
            duplicate_family,
            mixed_challenges,
            short_timeout,
            over_budget,
            no_families,
        ] {
            assert!(mutate(sample_block(&digest)).validate().is_err());
        }
        assert!(sample_block(&digest).validate().is_ok());
    }
}

/// The producer cannot check the prober's MAC — it holds no key, which is the
/// whole point — but it must agree with the contract owner on every field name
/// and bound, or the block it assembles will refuse at admission.
#[cfg(test)]
mod vector_tests {
    use super::*;

    #[test]
    fn the_shared_vector_parses_and_validates_against_this_copy() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../vectors/processor-coverage-inbound-v1.json"
        ))
        .unwrap();
        let block: InboundReachabilityV1 =
            serde_json::from_value(vector["inboundReachability"].clone()).unwrap();
        block.validate().unwrap();
        assert_eq!(
            block.family(InboundFamily::V4).unwrap().verdict,
            InboundVerdict::Reachable
        );
        assert_eq!(
            block.family(InboundFamily::V6).unwrap().verdict,
            InboundVerdict::ConnectTimeout
        );
        // Re-serializing must not change a byte: an unknown or renamed field
        // here is a protocol break the server would refuse in production.
        assert_eq!(
            serde_json::to_value(&block).unwrap(),
            vector["inboundReachability"]
        );
    }
}
