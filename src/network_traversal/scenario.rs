//! Closed fact-probe protocol. The request selects a fixed, wholly owned fixture.

use std::io::Read;

use serde::{Deserialize, Serialize};

use super::*;

const MAX_INPUT_BYTES: u64 = 256;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Scenario {
    TraversalSmoke,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u8,
    scenario: Scenario,
}

fn read_request(input: impl Read) -> Option<Request> {
    let mut bytes = Vec::new();
    input
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return None;
    }
    let request: Request = serde_json::from_slice(&bytes).ok()?;
    (request.version == 1).then_some(request)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Transcript {
    version: u8,
    scenario: Scenario,
    udp_behaviour: UdpBehaviour,
    pcp: Pcp,
    pair: Pair,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UdpBehaviour {
    mapping: TraversalOutcome,
    filtering: TraversalOutcome,
    sent_datagrams: u16,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Pcp {
    baseline: TraversalOutcome,
    create: TraversalOutcome,
    verification: TraversalOutcome,
    lease_seconds: u32,
    cleanup: TraversalCleanup,
    sent_datagrams: u16,
    control_requests: u16,
    external_dialbacks: u16,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Pair {
    direct: TraversalOutcome,
    relay_control: TraversalOutcome,
}

fn pcp_summary(report: MappingRunReport) -> Option<Pcp> {
    let [row] = report.methods.as_slice() else {
        return None;
    };
    let (baseline, create, verification, lease_seconds) = (
        row.baseline?.outcome,
        row.create?,
        row.verification?.outcome,
        row.granted_lease_sec?,
    );
    if [baseline, create, verification] != [TraversalOutcome::Succeeded; 3]
        || row.cleanup != TraversalCleanup::ConfirmedDeleted
        || row.expiry_unknown
        || report.stopped.is_some()
    {
        return None;
    }
    Some(Pcp {
        baseline,
        create,
        verification,
        lease_seconds,
        cleanup: row.cleanup,
        sent_datagrams: report.sent_datagrams,
        control_requests: report.control_requests,
        external_dialbacks: report.external_dialbacks,
    })
}

/// Reads one bounded request before opening the fixtures. Output contains only
/// correlated outcomes and exact counts, without addresses or transient proofs.
pub fn run_offline_traversal_scenario(input: impl Read) -> Result<String, &'static str> {
    let request = read_request(input).ok_or("invalid scenario input")?;
    match request.scenario {
        Scenario::TraversalSmoke => {
            let udp = behaviour::fixture::run().ok_or("UDP behaviour fixture failed")?;
            let pcp = lifecycle::fixture::run()
                .and_then(pcp_summary)
                .ok_or("PCP fixture failed")?;
            if !run_pair_fact_fixture() {
                return Err("paired UDP fixture failed");
            }
            serde_json::to_string(&Transcript {
                version: request.version,
                scenario: request.scenario,
                udp_behaviour: UdpBehaviour {
                    mapping: udp.mapping.outcome,
                    filtering: udp.filtering.outcome,
                    sent_datagrams: udp.sent_datagrams,
                },
                pcp,
                pair: Pair {
                    direct: TraversalOutcome::Succeeded,
                    relay_control: TraversalOutcome::Succeeded,
                },
            })
            .map_err(|_| "transcript encoding failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_unknown_and_malformed_scenarios_are_rejected_at_input() {
        for invalid in [
            "",
            "{}",
            r#"{"version":2,"scenario":"traversal-smoke"}"#,
            r#"{"version":1,"scenario":"observe"}"#,
            r#"{"version":1,"version":1,"scenario":"traversal-smoke"}"#,
            r#"{"version":1,"scenario":"traversal-smoke","endpoint":"127.0.0.1:5351"}"#,
            r#"{"version":1,"scenario":"traversal-smoke"} {}"#,
        ] {
            assert_eq!(
                run_offline_traversal_scenario(invalid.as_bytes()),
                Err("invalid scenario input")
            );
        }
        let oversized = format!(
            "{}{}",
            " ".repeat(MAX_INPUT_BYTES as usize),
            r#"{"version":1,"scenario":"traversal-smoke"}"#
        );
        assert_eq!(
            run_offline_traversal_scenario(oversized.as_bytes()),
            Err("invalid scenario input")
        );
    }

    #[test]
    fn loopback_collectors_match_the_harness_transcript() {
        let input = include_bytes!("../../tools/qemu-proot/traversal-scenario-v1.json");
        let expected = include_str!("../../tools/qemu-proot/traversal-transcript-v1.json");
        assert_eq!(
            run_offline_traversal_scenario(input.as_slice()).unwrap(),
            expected.trim_end()
        );
    }
}
