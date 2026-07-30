use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Value, json};

use crate::bridge::{BridgeError, RequestIdStyle, UnixBridge};
use crate::precontact::DiagnosticFailure;

pub const BRIDGE_PROBE_DOMAIN: &str = "proof.liskov.runtime-bridge-probe.v1";
pub const BRIDGE_PROBE_BUDGET: Duration = Duration::from_secs(15);
const MAX_PROBE_CALL: Duration = Duration::from_secs(5);

pub trait ProbeBridge {
    fn probe_call(
        &self,
        method: &str,
        params: Value,
        id_style: RequestIdStyle,
        timeout: Duration,
    ) -> Result<Value, BridgeError>;
}

impl ProbeBridge for UnixBridge {
    fn probe_call(
        &self,
        method: &str,
        params: Value,
        id_style: RequestIdStyle,
        timeout: Duration,
    ) -> Result<Value, BridgeError> {
        self.call_with_options(method, params, id_style, timeout)
    }
}

pub trait ProbeRuntime {
    fn elapsed(&self) -> Duration;
}

pub struct SystemProbeRuntime {
    started: Instant,
}

impl Default for SystemProbeRuntime {
    fn default() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl ProbeRuntime for SystemProbeRuntime {
    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeObservation {
    pub method: &'static str,
    pub id_style: &'static str,
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_code: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeProbeReport {
    pub domain: &'static str,
    pub observations: Vec<ProbeObservation>,
}

impl BridgeProbeReport {
    pub fn terminal_failure(&self) -> Option<DiagnosticFailure> {
        // The owned pre-contact contract permits one terminal report. Prefer
        // the observations that decide whether signed bootstrap v2 or a
        // signer-backed fallback is possible, while retaining the complete
        // closed-enum report on stderr for controlled probes.
        ["signer_sign", "deployment_id", "deployment_publicKeys"]
            .into_iter()
            .find_map(|method| {
                self.observations
                    .iter()
                    .find(|observation| observation.method == method && observation.outcome != "ok")
            })
            .or_else(|| {
                self.observations
                    .iter()
                    .find(|observation| observation.outcome != "ok")
            })
            .map(|observation| DiagnosticFailure {
                stage: "bridge.probe",
                method: observation.method,
                code: observation.outcome,
                rpc_code: observation.rpc_code,
            })
    }
}

struct ProbeSpec {
    method: &'static str,
    params: Value,
    id_style: RequestIdStyle,
    shape: fn(&Value) -> bool,
}

pub fn run_bridge_probe(bridge: &UnixBridge, runtime: &dyn ProbeRuntime) -> BridgeProbeReport {
    run_bridge_probe_with(bridge, runtime)
}

pub fn run_bridge_probe_with(
    bridge: &dyn ProbeBridge,
    runtime: &dyn ProbeRuntime,
) -> BridgeProbeReport {
    let harmless = hex::encode(b"proof.liskov.runtime-bridge-probe.v1\0harmless-capability-check");
    let specs = [
        ProbeSpec {
            method: "signer_sign",
            params: json!([{"curve": "ed25519", "bytes": harmless}]),
            id_style: RequestIdStyle::Long,
            shape: signature_shape,
        },
        ProbeSpec {
            method: "deployment_id",
            params: json!([]),
            id_style: RequestIdStyle::Long,
            shape: deployment_id_shape,
        },
        ProbeSpec {
            method: "deployment_publicKeys",
            params: json!([]),
            id_style: RequestIdStyle::Long,
            shape: public_keys_shape,
        },
        ProbeSpec {
            method: "processor_version",
            params: json!([]),
            id_style: RequestIdStyle::DocumentedShort,
            shape: version_shape,
        },
        ProbeSpec {
            method: "processor_version",
            params: json!([]),
            id_style: RequestIdStyle::Long,
            shape: version_shape,
        },
        ProbeSpec {
            method: "deployment_ipfsHash",
            params: json!([]),
            id_style: RequestIdStyle::Long,
            shape: ipfs_hash_shape,
        },
        ProbeSpec {
            method: "deployment_assignedProcessors",
            params: json!([]),
            id_style: RequestIdStyle::Long,
            shape: assigned_processors_shape,
        },
    ];
    let mut observations = Vec::with_capacity(specs.len());
    for spec in specs {
        let id_style = match spec.id_style {
            RequestIdStyle::DocumentedShort => "documented-short",
            RequestIdStyle::Long => "liskov-long",
        };
        let Some(remaining) = BRIDGE_PROBE_BUDGET.checked_sub(runtime.elapsed()) else {
            observations.push(ProbeObservation {
                method: spec.method,
                id_style,
                outcome: "bridge_timeout",
                rpc_code: None,
            });
            continue;
        };
        let timeout = remaining.min(MAX_PROBE_CALL);
        let (outcome, rpc_code) =
            match bridge.probe_call(spec.method, spec.params, spec.id_style, timeout) {
                Ok(result) if (spec.shape)(&result) => ("ok", None),
                Ok(_) => ("bridge_result_shape", None),
                Err(error) => (error.failure_code(), error.rpc_code()),
            };
        observations.push(ProbeObservation {
            method: spec.method,
            id_style,
            outcome,
            rpc_code,
        });
    }
    BridgeProbeReport {
        domain: BRIDGE_PROBE_DOMAIN,
        observations,
    }
}

fn bounded_text(value: Option<&Value>, max: usize) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|text| !text.is_empty() && text.len() <= max)
}

fn normalized_hex(value: Option<&Value>, bytes: usize) -> bool {
    value
        .and_then(Value::as_str)
        .map(|text| text.strip_prefix("0x").unwrap_or(text))
        .is_some_and(|text| {
            text.len() == bytes * 2 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

fn version_shape(value: &Value) -> bool {
    bounded_text(value.get("version"), 128)
}

fn deployment_id_shape(value: &Value) -> bool {
    bounded_text(value.get("id"), 1_024)
        && value
            .get("origin")
            .and_then(Value::as_object)
            .is_some_and(|origin| {
                bounded_text(origin.get("kind"), 128) && bounded_text(origin.get("source"), 1_024)
            })
}

fn ipfs_hash_shape(value: &Value) -> bool {
    bounded_text(value.get("ipfsHash"), 256)
}

fn public_keys_shape(value: &Value) -> bool {
    normalized_hex(
        value.get("publicKeys").and_then(|keys| keys.get("ed25519")),
        32,
    )
}

fn assigned_processors_shape(value: &Value) -> bool {
    value
        .get("processors")
        .and_then(Value::as_object)
        .is_some_and(|processors| {
            !processors.is_empty()
                && processors.len() <= 1_024
                && processors.iter().all(|(address, keys)| {
                    !address.is_empty() && address.len() <= 256 && keys.is_object()
                })
        })
}

fn signature_shape(value: &Value) -> bool {
    normalized_hex(value.get("bytes"), 64)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;

    struct FakeBridge {
        calls: Mutex<Vec<(String, Value, RequestIdStyle, Duration)>>,
        replies: Mutex<VecDeque<Result<Value, BridgeError>>>,
    }

    impl ProbeBridge for FakeBridge {
        fn probe_call(
            &self,
            method: &str,
            params: Value,
            id_style: RequestIdStyle,
            timeout: Duration,
        ) -> Result<Value, BridgeError> {
            self.calls
                .lock()
                .unwrap()
                .push((method.to_owned(), params, id_style, timeout));
            self.replies.lock().unwrap().pop_front().unwrap()
        }
    }

    struct FakeRuntime(Duration);

    impl ProbeRuntime for FakeRuntime {
        fn elapsed(&self) -> Duration {
            self.0
        }
    }

    fn successful_replies() -> Vec<Result<Value, BridgeError>> {
        vec![
            Ok(json!({"bytes": "cd".repeat(64)})),
            Ok(json!({"id": "7", "origin": {"kind": "Acurast", "source": "ab"}})),
            Ok(json!({"publicKeys": {"ed25519": "ab".repeat(32)}})),
            Ok(json!({"version": "1.25.1"})),
            Ok(json!({"version": "1.25.1"})),
            Ok(json!({"ipfsHash": "bafy-test"})),
            Ok(json!({"processors": {"processor-1": {"ed25519": "ab".repeat(32)}}})),
        ]
    }

    #[test]
    fn probes_documented_and_long_ids_with_only_closed_outcomes() {
        let bridge = FakeBridge {
            calls: Mutex::new(Vec::new()),
            replies: Mutex::new(successful_replies().into()),
        };
        let report = run_bridge_probe_with(&bridge, &FakeRuntime(Duration::ZERO));
        assert!(report.terminal_failure().is_none());
        assert_eq!(report.observations.len(), 7);
        assert_eq!(report.observations[3].id_style, "documented-short");
        assert_eq!(report.observations[4].id_style, "liskov-long");
        assert!(
            report
                .observations
                .iter()
                .all(|observation| observation.outcome == "ok")
        );
        let calls = bridge.calls.lock().unwrap();
        assert_eq!(calls[3].2, RequestIdStyle::DocumentedShort);
        assert_eq!(calls[4].2, RequestIdStyle::Long);
        assert_eq!(
            calls[0].1[0]["bytes"],
            hex::encode(b"proof.liskov.runtime-bridge-probe.v1\0harmless-capability-check")
        );
    }

    #[test]
    fn records_rpc_code_and_result_shape_without_response_data() {
        let mut replies = successful_replies();
        replies[1] = Ok(json!({"unexpected": "sensitive"}));
        replies[0] = Err(BridgeError::RpcError {
            code: Some(-32_601),
        });
        let bridge = FakeBridge {
            calls: Mutex::new(Vec::new()),
            replies: Mutex::new(replies.into()),
        };
        let report = run_bridge_probe_with(&bridge, &FakeRuntime(Duration::ZERO));
        assert_eq!(report.observations[1].outcome, "bridge_result_shape");
        assert_eq!(report.observations[0].outcome, "bridge_rpc_error");
        assert_eq!(report.observations[0].rpc_code, Some(-32_601));
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains("sensitive"));
    }

    #[test]
    fn shared_budget_cannot_mask_signing_or_deployment_identity() {
        struct AdvancingRuntime(Mutex<VecDeque<Duration>>);

        impl ProbeRuntime for AdvancingRuntime {
            fn elapsed(&self) -> Duration {
                self.0.lock().unwrap().pop_front().unwrap()
            }
        }

        let bridge = FakeBridge {
            calls: Mutex::new(Vec::new()),
            replies: Mutex::new(successful_replies().into()),
        };
        let runtime = AdvancingRuntime(Mutex::new(
            [
                Duration::ZERO,
                Duration::from_secs(5),
                Duration::from_secs(10),
                Duration::from_secs(15) + Duration::from_millis(1),
                Duration::from_secs(15) + Duration::from_millis(2),
                Duration::from_secs(15) + Duration::from_millis(3),
                Duration::from_secs(15) + Duration::from_millis(4),
            ]
            .into(),
        ));
        let report = run_bridge_probe_with(&bridge, &runtime);
        let calls = bridge.calls.lock().unwrap();
        assert_eq!(
            calls
                .iter()
                .map(|(method, _, _, _)| method.as_str())
                .collect::<Vec<_>>(),
            vec!["signer_sign", "deployment_id", "deployment_publicKeys"]
        );
        assert_eq!(report.observations[0].outcome, "ok");
        assert_eq!(report.observations[1].outcome, "ok");
        assert_eq!(report.observations[2].outcome, "ok");
        assert!(
            report.observations[3..]
                .iter()
                .all(|observation| observation.outcome == "bridge_timeout")
        );
    }

    #[test]
    fn terminal_report_prioritizes_signing_then_identity_capabilities() {
        let report = BridgeProbeReport {
            domain: BRIDGE_PROBE_DOMAIN,
            observations: vec![
                ProbeObservation {
                    method: "processor_version",
                    id_style: "documented-short",
                    outcome: "bridge_json",
                    rpc_code: None,
                },
                ProbeObservation {
                    method: "deployment_id",
                    id_style: "liskov-long",
                    outcome: "bridge_result_shape",
                    rpc_code: None,
                },
                ProbeObservation {
                    method: "deployment_publicKeys",
                    id_style: "liskov-long",
                    outcome: "bridge_rpc_error",
                    rpc_code: Some(-32_601),
                },
                ProbeObservation {
                    method: "signer_sign",
                    id_style: "liskov-long",
                    outcome: "bridge_timeout",
                    rpc_code: None,
                },
            ],
        };

        let failure = report.terminal_failure().unwrap();
        assert_eq!(failure.method, "signer_sign");
        assert_eq!(failure.code, "bridge_timeout");

        let mut without_signer_failure = report.clone();
        without_signer_failure.observations[3].outcome = "ok";
        let failure = without_signer_failure.terminal_failure().unwrap();
        assert_eq!(failure.method, "deployment_id");
        assert_eq!(failure.code, "bridge_result_shape");

        without_signer_failure.observations[1].outcome = "ok";
        let failure = without_signer_failure.terminal_failure().unwrap();
        assert_eq!(failure.method, "deployment_publicKeys");
        assert_eq!(failure.code, "bridge_rpc_error");
        assert_eq!(failure.rpc_code, Some(-32_601));

        without_signer_failure.observations[2].outcome = "ok";
        let failure = without_signer_failure.terminal_failure().unwrap();
        assert_eq!(failure.method, "processor_version");
        assert_eq!(failure.code, "bridge_json");
    }

    #[test]
    fn shared_budget_prevents_any_late_bridge_call() {
        let bridge = FakeBridge {
            calls: Mutex::new(Vec::new()),
            replies: Mutex::new(VecDeque::new()),
        };
        let report = run_bridge_probe_with(
            &bridge,
            &FakeRuntime(BRIDGE_PROBE_BUDGET + Duration::from_millis(1)),
        );
        assert!(bridge.calls.lock().unwrap().is_empty());
        assert_eq!(report.observations.len(), 7);
        assert!(
            report
                .observations
                .iter()
                .all(|observation| observation.outcome == "bridge_timeout")
        );
    }
}
