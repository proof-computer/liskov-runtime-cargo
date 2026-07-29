use std::ffi::OsString;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use liskov_runtime_cargo::bridge::UnixBridge;
use liskov_runtime_cargo::http::UreqHttpClient;
use liskov_runtime_cargo::precontact::{
    DiagnosticFailure, MAX_PRECONTACT_RESPONSE_BYTES, PRECONTACT_HTTP_TIMEOUT, PrecontactReporter,
};
use liskov_runtime_cargo::probe::{SystemProbeRuntime, run_bridge_probe};
use liskov_runtime_cargo::{
    DEFAULT_CORE_URL, ExecCommand, RunError, contact_then_exec, establish_runtime_contact,
};

#[derive(Debug, Parser)]
#[command(
    name = "liskov-runtime-contact",
    version,
    about = "Establish signed Liskov runtime contact, then exec the customer command"
)]
struct Cli {
    /// Liskov core base URL
    #[arg(long, value_name = "URL")]
    core_url: Option<String>,

    /// Emit canary-only stage exit codes instead of the stable public categories
    #[arg(long, hide = true)]
    diagnostic_exit_codes: bool,

    /// Run the controlled bridge capability probe before signed contact
    #[arg(long, hide = true)]
    bridge_probe: bool,

    /// Customer command and arguments; must follow `--`
    #[arg(last = true, required = true, num_args = 1.., allow_hyphen_values = true)]
    command: Vec<OsString>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let core_url = cli
        .core_url
        .or_else(|| std::env::var("LISKOV_CORE_URL").ok())
        .unwrap_or_else(|| DEFAULT_CORE_URL.to_owned());
    let diagnostic_http =
        UreqHttpClient::with_limits(PRECONTACT_HTTP_TIMEOUT, MAX_PRECONTACT_RESPONSE_BYTES);
    let reporter = std::env::var("PROOF_SLIPWAY_BOOTSTRAP")
        .ok()
        .and_then(|raw| {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|duration| i64::try_from(duration.as_millis()).ok())?;
            PrecontactReporter::parse(&raw, now_ms).ok()
        });
    if let Some(reporter) = &reporter {
        let _ = reporter.report_started(&diagnostic_http);
    }
    let bridge_socket = match std::env::var("BRIDGE_SOCKET") {
        Ok(value) if !value.is_empty() => value,
        _ => {
            if let Some(reporter) = &reporter {
                let _ = reporter.report_failed(
                    &diagnostic_http,
                    DiagnosticFailure {
                        stage: "bridge.discovery",
                        method: "bridge_discovery",
                        code: "bridge_socket_construction",
                        rpc_code: None,
                    },
                );
            }
            eprintln!("liskov-runtime-contact: BRIDGE_SOCKET is required");
            return ExitCode::from(2);
        }
    };

    if cli.bridge_probe {
        let bridge = match UnixBridge::new(&bridge_socket) {
            Ok(bridge) => bridge,
            Err(error) => {
                if let Some(reporter) = &reporter {
                    let _ = reporter.report_failed(
                        &diagnostic_http,
                        DiagnosticFailure::bridge("bridge.discovery", "bridge_discovery", &error),
                    );
                }
                eprintln!("liskov-runtime-contact: bridge probe failed");
                return ExitCode::from(70);
            }
        };
        let probe = run_bridge_probe(&bridge, &SystemProbeRuntime::default());
        eprintln!(
            "liskov-runtime-contact: bridge-probe {}",
            serde_json::to_string(&probe).unwrap_or_else(|_| {
                "{\"domain\":\"proof.liskov.runtime-bridge-probe.v1\",\"observations\":[]}"
                    .to_owned()
            })
        );
        if let Some(failure) = probe.first_failure() {
            if let Some(reporter) = &reporter {
                let _ = reporter.report_failed(&diagnostic_http, failure);
            }
            return ExitCode::from(70);
        }
    }

    match contact_then_exec(
        || {
            establish_runtime_contact(&core_url, &bridge_socket)
                .inspect_err(|error| {
                    if let Some(reporter) = &reporter {
                        let _ = reporter.report_failed(
                            &diagnostic_http,
                            DiagnosticFailure::from_contact(error),
                        );
                    }
                })
                .map(|_| ())
        },
        &ExecCommand,
        &cli.command,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(RunError::Contact(error)) => {
            eprintln!("liskov-runtime-contact: {error}");
            let status = if cli.diagnostic_exit_codes {
                error.diagnostic_exit_code()
            } else {
                error.exit_category() as u8
            };
            ExitCode::from(status)
        }
        Err(RunError::Exec(_)) => {
            eprintln!("liskov-runtime-contact: customer command could not be executed");
            ExitCode::from(126)
        }
    }
}
