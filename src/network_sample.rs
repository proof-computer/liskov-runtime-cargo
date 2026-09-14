//! One deadline-bounded, authorized sample. All effects have an offline seam.
use crate::network_sample_contract::*;
use std::{future::Future, pin::Pin};
mod transport;
pub use transport::SystemNetworkSampler;
type Pending<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;
pub trait NetworkSampler: Send + Sync {
    fn sample(&self, url: &str, challenge: &str, started_at_ms: u64) -> NetworkSampleV1;
}
pub trait NetworkTransport {
    fn elapsed_us(&self) -> u64;
    fn prepare(&mut self) -> Pending<'_, (bool, bool, Option<NetworkError>)>;
    fn udp(&mut self) -> Pending<'_, UdpSample>;
    fn transfer(&mut self, id: NetworkLegId) -> Pending<'_, NetworkLeg>;
    fn receipt(&mut self) -> Pending<'_, Result<NetworkReceipt, NetworkError>>;
}
fn skipped_udp(start: u64) -> UdpSample {
    UdpSample {
        status: NetworkStatus::SkippedBudget,
        start_offset_us: start,
        duration_us: 0,
        sent_us: vec![],
        echoes: vec![],
        error: Some(NetworkError::BudgetExhausted),
    }
}
pub async fn collect_sample(
    transport: &mut dyn NetworkTransport,
    started_at_ms: u64,
) -> NetworkSampleV1 {
    let (ipv4, ipv6, error) = transport.prepare().await;
    let mut sample = NetworkSampleV1 {
        version: 1,
        started_at_ms,
        duration_ms: 0,
        region: "lhr".into(),
        ipv4_egress: ipv4,
        ipv6_egress: ipv6,
        legs: vec![],
        udp: skipped_udp(transport.elapsed_us().min(30_000_000)),
        metrics: NetworkMetrics::default(),
        receipt: None,
        errors: error.into_iter().collect(),
    };
    // Reserve one second for authenticated accounting; UDP runs without bulk traffic.
    if transport.elapsed_us() + 3_000_000 <= 29_000_000 {
        sample.udp = transport.udp().await;
    }
    for id in [
        NetworkLegId::Download1m,
        NetworkLegId::Upload1m,
        NetworkLegId::Download10m,
        NetworkLegId::Upload10m,
        NetworkLegId::Download100m,
    ] {
        let precursor = match id {
            NetworkLegId::Download10m => Some(NetworkLegId::Download1m),
            NetworkLegId::Upload10m => Some(NetworkLegId::Upload1m),
            NetworkLegId::Download100m => Some(NetworkLegId::Download10m),
            _ => None,
        };
        if let Some(prior) = precursor {
            let eligible = sample.legs.iter().any(|l| {
                l.id == prior
                    && l.status == NetworkStatus::Succeeded
                    && l.duration_us > 0
                    && if id == NetworkLegId::Download100m {
                        l.duration_us < 4_000_000
                    } else {
                        l.bytes * 8_000 / l.duration_us >= 4_000
                    }
            });
            if !eligible {
                continue;
            }
        }
        let start = transport.elapsed_us().min(30_000_000);
        let leg = if start + id.timeout_ms() * 1_000 > 29_000_000 {
            NetworkLeg {
                id,
                status: NetworkStatus::SkippedBudget,
                start_offset_us: start,
                duration_us: 0,
                bytes: 0,
                error: Some(NetworkError::BudgetExhausted),
            }
        } else {
            transport.transfer(id).await
        };
        sample.legs.push(leg);
    }
    if transport.elapsed_us() <= 29_000_000 {
        match transport.receipt().await {
            Ok(r) => sample.receipt = Some(r),
            Err(e) => sample.errors.push(e),
        }
    } else {
        sample.errors.push(NetworkError::ReceiptUnavailable);
    }
    sample.duration_ms = transport.elapsed_us().div_ceil(1_000).min(SAMPLE_BUDGET_MS);
    sample.metrics = sample.derive_metrics();
    // A dropped HTTP transfer can race the receipt snapshot; never claim it is
    // authoritative unless the completed legs actually agree with that snapshot.
    if sample.receipt.is_some() && sample.validate().is_err() {
        sample.receipt = None;
        sample.errors.push(NetworkError::ReceiptUnavailable);
    }
    sample
}
pub fn coverage_outcomes(sample: &NetworkSampleV1) -> Vec<crate::coverage::CoverageOutcome> {
    use crate::coverage::{CoverageOutcome, CoverageOutcomeStatus, CoverageProbeError};
    let make = |id: &str,
                status: NetworkStatus,
                start: u64,
                end: u64,
                sent: u64,
                received: u64,
                errors: Vec<NetworkError>| {
        let started_at_ms = sample.started_at_ms + start / 1000;
        let completed_at_ms = sample.started_at_ms + end / 1000;
        CoverageOutcome {
            probe_id: id.into(),
            region: sample.region.clone(),
            status: match status {
                NetworkStatus::Succeeded => CoverageOutcomeStatus::Succeeded,
                NetworkStatus::Failed => CoverageOutcomeStatus::Failed,
                NetworkStatus::SkippedBudget => CoverageOutcomeStatus::SkippedBudget,
                NetworkStatus::Unreachable => CoverageOutcomeStatus::Unreachable,
            },
            started_at_ms,
            completed_at_ms,
            duration_ms: completed_at_ms - started_at_ms,
            bytes_sent: sent,
            bytes_received: received,
            errors: errors
                .into_iter()
                .map(|e| CoverageProbeError {
                    code: e.code().into(),
                    message: e.code().into(),
                })
                .collect(),
        }
    };
    let mut outcomes = vec![];
    for download in [true, false] {
        let legs: Vec<_> = sample
            .legs
            .iter()
            .filter(|l| l.id.download() == download)
            .collect();
        let status = if legs.iter().any(|l| l.status == NetworkStatus::Succeeded) {
            NetworkStatus::Succeeded
        } else if legs.iter().any(|l| l.status == NetworkStatus::Failed) {
            NetworkStatus::Failed
        } else if legs.iter().any(|l| l.status == NetworkStatus::Unreachable) {
            NetworkStatus::Unreachable
        } else {
            NetworkStatus::SkippedBudget
        };
        let bytes = legs.iter().map(|l| l.bytes).sum();
        let start = legs.iter().map(|l| l.start_offset_us).min().unwrap_or(0);
        let end = legs
            .iter()
            .map(|l| l.start_offset_us + l.duration_us)
            .max()
            .unwrap_or(start);
        outcomes.push(make(
            if download {
                "bandwidth-download"
            } else {
                "bandwidth-upload"
            },
            status,
            start,
            end,
            if download { 0 } else { bytes },
            if download { bytes } else { 0 },
            legs.iter().filter_map(|l| l.error).collect(),
        ));
    }
    let udp = &sample.udp;
    outcomes.push(make(
        "udp-path",
        udp.status,
        udp.start_offset_us,
        udp.start_offset_us + udp.duration_us,
        udp.sent_us.len() as u64 * 64,
        udp.echoes.len() as u64 * 64,
        udp.error.into_iter().collect(),
    ));
    outcomes
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        now: u64,
        slow: bool,
    }
    impl NetworkTransport for Fake {
        fn elapsed_us(&self) -> u64 {
            self.now
        }
        fn prepare(&mut self) -> Pending<'_, (bool, bool, Option<NetworkError>)> {
            Box::pin(async { (true, true, None) })
        }
        fn udp(&mut self) -> Pending<'_, UdpSample> {
            Box::pin(async {
                let start = self.now;
                self.now += 3_000_000;
                UdpSample {
                    status: NetworkStatus::Succeeded,
                    start_offset_us: start,
                    duration_us: 3_000_000,
                    sent_us: vec![0, 100_000, 200_000],
                    echoes: vec![
                        UdpEcho {
                            sequence: 0,
                            received_us: 20_000,
                        },
                        UdpEcho {
                            sequence: 2,
                            received_us: 225_000,
                        },
                    ],
                    error: None,
                }
            })
        }
        fn transfer(&mut self, id: NetworkLegId) -> Pending<'_, NetworkLeg> {
            Box::pin(async move {
                let start = self.now;
                let duration = if self.slow { 3_000_000 } else { 100_000 };
                self.now += duration;
                NetworkLeg {
                    id,
                    status: NetworkStatus::Succeeded,
                    start_offset_us: start,
                    duration_us: duration,
                    bytes: id.bytes(),
                    error: None,
                }
            })
        }
        fn receipt(&mut self) -> Pending<'_, Result<NetworkReceipt, NetworkError>> {
            Box::pin(async { Err(NetworkError::ReceiptUnavailable) })
        }
    }
    #[tokio::test]
    async fn ladder_loss_and_deadline() {
        let fast = collect_sample(
            &mut Fake {
                now: 0,
                slow: false,
            },
            1000,
        )
        .await;
        assert_eq!(fast.legs.len(), 5);
        assert_eq!(fast.metrics.loss_bps, Some(3333));
        assert_eq!(fast.metrics.median_rtt_us, Some(22500));
        assert!(fast.validate().is_ok());
        let slow = collect_sample(&mut Fake { now: 0, slow: true }, 1000).await;
        assert_eq!(slow.legs.len(), 2);
        assert!(slow.validate().is_ok());
        let budget = collect_sample(
            &mut Fake {
                now: 25_000_000,
                slow: false,
            },
            1000,
        )
        .await;
        assert!(
            budget
                .legs
                .iter()
                .all(|l| l.status == NetworkStatus::SkippedBudget)
        );
        assert!(budget.duration_ms <= 30_000);
        assert!(budget.validate().is_ok());
    }
}

#[cfg(test)]
mod vector_tests {
    #[test]
    fn signed_network_vector_is_canonical_and_recomputable() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../vectors/processor-coverage-network-v1.json"
        ))
        .unwrap();
        let result: crate::coverage::CoverageResultV1 =
            serde_json::from_value(v["result"].clone()).unwrap();
        result.network_sample.as_ref().unwrap().validate().unwrap();
        let value = serde_json::to_value(&result).unwrap();
        assert_eq!(
            crate::diagnostics::canonical_json_bytes(&value),
            v["canonicalSigningPayload"].as_str().unwrap().as_bytes()
        );
        let outcomes = super::coverage_outcomes(result.network_sample.as_ref().unwrap());
        for o in outcomes {
            assert!(result.outcomes.iter().any(|actual| *actual == o));
        }
    }
}

/// Final cancellation guard, including any adapter bug or resolver stall.
pub async fn collect_bounded(
    transport: &mut dyn NetworkTransport,
    started_at_ms: u64,
) -> NetworkSampleV1 {
    match tokio::time::timeout(
        std::time::Duration::from_millis(SAMPLE_BUDGET_MS),
        collect_sample(transport, started_at_ms),
    )
    .await
    {
        Ok(sample) => sample,
        Err(_) => {
            let mut sample = skipped_sample(started_at_ms);
            sample.duration_ms = SAMPLE_BUDGET_MS;
            sample.errors = vec![NetworkError::Timeout];
            sample
        }
    }
}
pub fn skipped_sample(started_at_ms: u64) -> NetworkSampleV1 {
    NetworkSampleV1 {
        version: 1,
        started_at_ms,
        duration_ms: 0,
        region: "lhr".into(),
        ipv4_egress: false,
        ipv6_egress: false,
        legs: vec![],
        udp: skipped_udp(0),
        metrics: NetworkMetrics::default(),
        receipt: None,
        errors: vec![NetworkError::BudgetExhausted],
    }
}
#[cfg(test)]
mod deadline_tests {
    use super::*;
    struct Hung;
    impl NetworkTransport for Hung {
        fn elapsed_us(&self) -> u64 {
            0
        }
        fn prepare(&mut self) -> Pending<'_, (bool, bool, Option<NetworkError>)> {
            Box::pin(std::future::pending())
        }
        fn udp(&mut self) -> Pending<'_, UdpSample> {
            panic!("prepare has not finished")
        }
        fn transfer(&mut self, _: NetworkLegId) -> Pending<'_, NetworkLeg> {
            panic!("prepare has not finished")
        }
        fn receipt(&mut self) -> Pending<'_, Result<NetworkReceipt, NetworkError>> {
            panic!("prepare has not finished")
        }
    }
    #[tokio::test(start_paused = true)]
    async fn stalled_resolver_cannot_outlive_the_whole_budget() {
        let start = tokio::time::Instant::now();
        let sample = collect_bounded(&mut Hung, 1000).await;
        assert_eq!(start.elapsed(), std::time::Duration::from_secs(30));
        assert_eq!(sample.duration_ms, 30000);
        sample.validate().unwrap();
    }
}
