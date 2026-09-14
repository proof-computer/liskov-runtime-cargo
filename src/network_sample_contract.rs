//! Network sample v1 wire contract. Authoritative source: liskov-rs
//! slipway-executor-contracts; independent producer/prober copies share vectors.
use serde::{Deserialize, Serialize};

pub const NETWORK_PROBER_URL: &str = "https://liskov-network-prober.fly.dev";
pub const SAMPLE_BUDGET_MS: u64 = 30_000;
pub const DOWNLOAD_CAP: u64 = 111_000_000;
pub const UPLOAD_CAP: u64 = 11_000_000;
pub const UDP_PORT: u16 = 5000;
pub const UDP_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkStatus {
    Succeeded,
    Failed,
    SkippedBudget,
    Unreachable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkError {
    DnsFailed,
    ConnectFailed,
    TlsFailed,
    Timeout,
    HttpStatus,
    InvalidResponse,
    ByteCountMismatch,
    RateLimited,
    TokenRefused,
    BudgetExhausted,
    ReceiptUnavailable,
}
impl NetworkError {
    pub fn code(self) -> &'static str {
        match self {
            Self::DnsFailed => "dns_failed",
            Self::ConnectFailed => "connect_failed",
            Self::TlsFailed => "tls_failed",
            Self::Timeout => "timeout",
            Self::HttpStatus => "http_status",
            Self::InvalidResponse => "invalid_response",
            Self::ByteCountMismatch => "byte_count_mismatch",
            Self::RateLimited => "rate_limited",
            Self::TokenRefused => "token_refused",
            Self::BudgetExhausted => "budget_exhausted",
            Self::ReceiptUnavailable => "receipt_unavailable",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkLegId {
    Download1m,
    Upload1m,
    Download10m,
    Upload10m,
    Download100m,
}
impl NetworkLegId {
    pub fn bytes(self) -> u64 {
        match self {
            Self::Download1m | Self::Upload1m => 1_000_000,
            Self::Download10m | Self::Upload10m => 10_000_000,
            Self::Download100m => 100_000_000,
        }
    }
    pub fn download(self) -> bool {
        !matches!(self, Self::Upload1m | Self::Upload10m)
    }
    pub fn timeout_ms(self) -> u64 {
        match self {
            Self::Download1m | Self::Upload1m => 4_000,
            Self::Download10m | Self::Upload10m => 8_000,
            Self::Download100m => 12_000,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkLeg {
    pub id: NetworkLegId,
    pub status: NetworkStatus,
    pub start_offset_us: u64,
    pub duration_us: u64,
    pub bytes: u64,
    pub error: Option<NetworkError>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UdpEcho {
    pub sequence: u16,
    pub received_us: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UdpSample {
    pub status: NetworkStatus,
    pub start_offset_us: u64,
    pub duration_us: u64,
    pub sent_us: Vec<u64>,
    /// Unique echoes in arrival order. Times are relative to the UDP leg.
    pub echoes: Vec<UdpEcho>,
    pub error: Option<NetworkError>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkMetrics {
    /// Integer kilobits/s: divide by 1000 to display Mbit/s.
    pub download_kbps: Option<u64>,
    pub upload_kbps: Option<u64>,
    pub median_rtt_us: Option<u64>,
    pub p90_rtt_us: Option<u64>,
    pub jitter_us: Option<u64>,
    pub loss_bps: Option<u16>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptLeg {
    pub id: NetworkLegId,
    pub bytes: u64,
    pub duration_us: u64,
    pub complete: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkReceipt {
    pub version: u8,
    pub challenge_digest: String,
    pub expires_at_sec: u32,
    pub region: String,
    pub legs: Vec<ReceiptLeg>,
    pub udp_echoes: u16,
    pub mac: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkSampleV1 {
    pub version: u8,
    pub started_at_ms: u64,
    pub duration_ms: u64,
    pub region: String,
    pub ipv4_egress: bool,
    pub ipv6_egress: bool,
    pub legs: Vec<NetworkLeg>,
    pub udp: UdpSample,
    pub metrics: NetworkMetrics,
    pub receipt: Option<NetworkReceipt>,
    pub errors: Vec<NetworkError>,
}
impl NetworkSampleV1 {
    pub fn derive_metrics(&self) -> NetworkMetrics {
        let rate = |download| {
            self.legs
                .iter()
                .filter(|l| {
                    l.id.download() == download
                        && l.status == NetworkStatus::Succeeded
                        && l.duration_us > 0
                })
                .max_by_key(|l| l.id.bytes())
                .map(|l| l.bytes * 8_000 / l.duration_us)
        };
        let mut rtts = Vec::new();
        let mut jitter = 0i64;
        let mut previous: Option<i64> = None;
        for echo in &self.udp.echoes {
            if let Some(sent) = self.udp.sent_us.get(usize::from(echo.sequence)) {
                let rtt = echo.received_us.saturating_sub(*sent);
                rtts.push(rtt);
                if let Some(last) = previous {
                    let difference = (rtt as i64 - last).abs();
                    // RFC3550 Appendix A.8 fixed-point estimator (scale 16).
                    jitter += difference - ((jitter + 8) >> 4);
                }
                previous = Some(rtt as i64);
            }
        }
        rtts.sort_unstable();
        let median = if rtts.is_empty() {
            None
        } else {
            Some((rtts[(rtts.len() - 1) / 2] + rtts[rtts.len() / 2]) / 2)
        };
        NetworkMetrics {
            download_kbps: rate(true),
            upload_kbps: rate(false),
            median_rtt_us: median,
            p90_rtt_us: if rtts.is_empty() {
                None
            } else {
                Some(rtts[(rtts.len() * 9).div_ceil(10) - 1])
            },
            jitter_us: if rtts.len() < 2 {
                None
            } else {
                Some((jitter >> 4) as u64)
            },
            loss_bps: if self.udp.sent_us.is_empty() {
                None
            } else {
                Some(
                    ((self.udp.sent_us.len().saturating_sub(rtts.len())) * 10_000
                        / self.udp.sent_us.len()) as u16,
                )
            },
        }
    }
    pub fn bandwidth_failed(&self) -> bool {
        let attempted: Vec<_> = self
            .legs
            .iter()
            .filter(|l| l.id.download() && l.status != NetworkStatus::SkippedBudget)
            .collect();
        !attempted.is_empty()
            && attempted
                .iter()
                .all(|l| l.status != NetworkStatus::Succeeded)
    }
    pub fn validate(&self) -> Result<(), String> {
        let invalid = || "invalid network sample v1".to_string();
        if self.version != 1
            || self.region != "lhr"
            || self.duration_ms > SAMPLE_BUDGET_MS
            || self.started_at_ms > 9_007_199_254_710_991
            || self.errors.len() > 4
            || self.legs.len() > 5
            || self.udp.sent_us.len() > 20
            || self.udp.echoes.len() > self.udp.sent_us.len()
        {
            return Err(invalid());
        }
        if self.legs.windows(2).any(|w| {
            w[0].id >= w[1].id
                || w[0].start_offset_us.saturating_add(w[0].duration_us) > w[1].start_offset_us
        }) || self.legs.first().is_some_and(|l| {
            l.start_offset_us
                < self
                    .udp
                    .start_offset_us
                    .saturating_add(self.udp.duration_us)
        }) {
            return Err(invalid());
        }
        for leg in &self.legs {
            let prior = match leg.id {
                NetworkLegId::Download10m => Some(NetworkLegId::Download1m),
                NetworkLegId::Upload10m => Some(NetworkLegId::Upload1m),
                NetworkLegId::Download100m => Some(NetworkLegId::Download10m),
                _ => None,
            };
            if let Some(prior) = prior {
                if !self.legs.iter().any(|l| {
                    l.id == prior
                        && l.status == NetworkStatus::Succeeded
                        && l.duration_us > 0
                        && if leg.id == NetworkLegId::Download100m {
                            l.duration_us < 4_000_000
                        } else {
                            l.bytes
                                .checked_mul(8_000)
                                .is_some_and(|bits| bits / l.duration_us >= 4_000)
                        }
                }) {
                    return Err(invalid());
                }
            }
        }
        let limit_us = self.duration_ms * 1_000;
        let mut ids = std::collections::BTreeSet::new();
        for leg in &self.legs {
            if !ids.insert(leg.id)
                || leg.bytes > leg.id.bytes()
                || leg.duration_us > leg.id.timeout_ms() * 1_000
                || leg.start_offset_us.saturating_add(leg.duration_us) > limit_us
                || (leg.status == NetworkStatus::Succeeded
                    && (leg.bytes != leg.id.bytes() || leg.error.is_some()))
                || (leg.status == NetworkStatus::SkippedBudget
                    && (leg.bytes != 0 || leg.duration_us != 0))
            {
                return Err(invalid());
            }
        }
        if self.udp.duration_us > 3_000_000
            || self
                .udp
                .start_offset_us
                .saturating_add(self.udp.duration_us)
                > limit_us
            || self.udp.sent_us.windows(2).any(|w| w[0] >= w[1])
            || self.udp.sent_us.iter().any(|t| *t > self.udp.duration_us)
            || self
                .udp
                .echoes
                .windows(2)
                .any(|w| w[0].received_us > w[1].received_us)
        {
            return Err(invalid());
        }
        let mut sequences = std::collections::BTreeSet::new();
        for echo in &self.udp.echoes {
            let sent = self
                .udp
                .sent_us
                .get(usize::from(echo.sequence))
                .ok_or_else(invalid)?;
            if !sequences.insert(echo.sequence)
                || echo.received_us < *sent
                || echo.received_us > self.udp.duration_us
            {
                return Err(invalid());
            }
        }
        if (self.udp.status == NetworkStatus::Succeeded && self.udp.echoes.is_empty())
            || (self.udp.status == NetworkStatus::SkippedBudget && !self.udp.sent_us.is_empty())
            || self.metrics != self.derive_metrics()
        {
            return Err(invalid());
        }
        if let Some(receipt) = &self.receipt {
            if receipt.version != 1
                || receipt.region != self.region
                || receipt.legs.len() > 5
                || receipt.udp_echoes > 64
            {
                return Err(invalid());
            }
            let mut ids = std::collections::BTreeSet::new();
            for leg in &receipt.legs {
                if !ids.insert(leg.id) || leg.bytes > leg.id.bytes() || leg.duration_us > 30_000_000
                {
                    return Err(invalid());
                }
            }
            for leg in self
                .legs
                .iter()
                .filter(|l| l.status == NetworkStatus::Succeeded)
            {
                if !receipt
                    .legs
                    .iter()
                    .any(|r| r.id == leg.id && r.complete && r.bytes == leg.bytes)
                {
                    return Err(invalid());
                }
            }
            if usize::from(receipt.udp_echoes) < self.udp.echoes.len() {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod catalog_tests {
    #[test]
    fn catalog_and_closed_wire_fields_agree() {
        let catalog: serde_json::Value =
            serde_json::from_str(include_str!("../contracts/network-sample-v1.json")).unwrap();
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../vectors/processor-coverage-network-v1.json"
        ))
        .unwrap();
        let sample: super::NetworkSampleV1 =
            serde_json::from_value(vector["result"]["networkSample"].clone()).unwrap();
        sample.validate().unwrap();
        let actual = serde_json::to_value(sample).unwrap();
        let mut keys: Vec<_> = actual
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        keys.sort_unstable();
        let mut admitted: Vec<_> = catalog["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        admitted.sort_unstable();
        assert_eq!(keys, admitted);
        assert_eq!(catalog["currentProfile"], false);
        assert_eq!(catalog["bounds"]["sampleMs"], super::SAMPLE_BUDGET_MS);
        assert_eq!(catalog["bounds"]["downloadBytes"], super::DOWNLOAD_CAP);
        assert_eq!(catalog["bounds"]["uploadBytes"], super::UPLOAD_CAP);
    }
}
