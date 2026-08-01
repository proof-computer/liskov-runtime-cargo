use std::ffi::OsString;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use liskov_runtime_cargo::bridge::UnixBridge;
use liskov_runtime_cargo::http::UreqHttpClient;
use liskov_runtime_cargo::precontact::{
    DiagnosticFailure, MAX_PRECONTACT_RESPONSE_BYTES, PRECONTACT_HTTP_TIMEOUT, PrecontactError,
    PrecontactReporter,
};
use liskov_runtime_cargo::probe::{SystemProbeRuntime, run_bridge_probe};
use liskov_runtime_cargo::{
    DEFAULT_CORE_URL, SupervisorExit, establish_runtime_contact, load_runtime_environment,
    supervise_with_environment_and_access,
};

#[derive(Debug, Parser)]
#[command(
    name = "liskov-runtime-contact",
    version,
    about = "Establish signed Liskov runtime contact, then supervise the customer command"
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

fn precontact_probe_line(phase: &'static str, error: &PrecontactError) -> String {
    format!(
        "liskov-runtime-contact: precontact {{\"domain\":\"proof.liskov.runtime-precontact-probe.v1\",\"phase\":\"{phase}\",\"outcome\":\"{}\"}}",
        error.probe_code()
    )
}

fn emit_precontact_probe(phase: &'static str, error: &PrecontactError) {
    eprintln!("{}", precontact_probe_line(phase, error));
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let core_url = cli
        .core_url
        .or_else(|| std::env::var("LISKOV_CORE_URL").ok())
        .unwrap_or_else(|| DEFAULT_CORE_URL.to_owned());
    let diagnostic_http =
        UreqHttpClient::with_limits(PRECONTACT_HTTP_TIMEOUT, MAX_PRECONTACT_RESPONSE_BYTES);
    let reporter = match std::env::var("PROOF_SLIPWAY_BOOTSTRAP") {
        Ok(raw) => {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|duration| i64::try_from(duration.as_millis()).ok());
            match now_ms
                .ok_or(PrecontactError::Invalid)
                .and_then(|now_ms| PrecontactReporter::parse(&raw, now_ms))
            {
                Ok(reporter) => Some(reporter),
                Err(error) => {
                    if cli.bridge_probe {
                        emit_precontact_probe("setup", &error);
                    }
                    None
                }
            }
        }
        Err(_) => {
            if cli.bridge_probe {
                emit_precontact_probe("setup", &PrecontactError::Missing);
            }
            None
        }
    };
    if let Some(reporter) = &reporter {
        let outcome = reporter.report_started(&diagnostic_http);
        if cli.bridge_probe {
            if let Err(error) = outcome {
                emit_precontact_probe("started", &error);
            }
        }
    }
    let bridge_socket = match std::env::var("BRIDGE_SOCKET") {
        Ok(value) if !value.is_empty() => value,
        _ => {
            if let Some(reporter) = &reporter {
                let outcome = reporter.report_failed(
                    &diagnostic_http,
                    DiagnosticFailure {
                        stage: "bridge.discovery",
                        method: "bridge_discovery",
                        code: "bridge_socket_construction",
                        rpc_code: None,
                    },
                );
                if cli.bridge_probe {
                    if let Err(error) = outcome {
                        emit_precontact_probe("failed", &error);
                    }
                }
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
                    if let Err(report_error) = reporter.report_failed(
                        &diagnostic_http,
                        DiagnosticFailure::bridge("bridge.discovery", "bridge_discovery", &error),
                    ) {
                        emit_precontact_probe("failed", &report_error);
                    }
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
        if let Some(failure) = probe.terminal_failure() {
            if let Some(reporter) = &reporter {
                if let Err(error) = reporter.report_failed(&diagnostic_http, failure) {
                    emit_precontact_probe("failed", &error);
                }
            }
            return ExitCode::from(70);
        }
    }

    let contact_started = Instant::now();
    let bootstrap =
        match establish_runtime_contact(&core_url, &bridge_socket).inspect_err(|error| {
            if let Some(reporter) = &reporter {
                let outcome = reporter
                    .report_failed(&diagnostic_http, DiagnosticFailure::from_contact(error));
                if cli.bridge_probe {
                    if let Err(report_error) = outcome {
                        emit_precontact_probe("failed", &report_error);
                    }
                }
            }
        }) {
            Ok(bootstrap) => bootstrap,
            Err(error) => {
                eprintln!("liskov-runtime-contact: {error}");
                let status = if cli.diagnostic_exit_codes {
                    error.diagnostic_exit_code()
                } else {
                    error.exit_category() as u8
                };
                return ExitCode::from(status);
            }
        };
    let bridge = match UnixBridge::new(&bridge_socket) {
        Ok(bridge) => bridge,
        Err(_) => {
            eprintln!("liskov-runtime-contact: bridge setup failed after contact");
            return ExitCode::from(70);
        }
    };
    let runtime_environment = match load_runtime_environment(&bootstrap, &bridge) {
        Ok(environment) => environment,
        Err(error) => {
            eprintln!("liskov-runtime-contact: {error}");
            return ExitCode::from(error.exit_status());
        }
    };
    let runtime_access_credential = liskov_runtime_cargo::access::take_environment_credential();
    match supervise_with_environment_and_access(
        &cli.command,
        &bootstrap,
        Arc::new(bridge),
        contact_started.elapsed(),
        &runtime_environment,
        runtime_access_credential,
    ) {
        SupervisorExit::Code(code) => ExitCode::from(u8::try_from(code).unwrap_or(70)),
        SupervisorExit::Signal(signal) => propagate_signal(signal),
    }
}

fn propagate_signal(signal: i32) -> ExitCode {
    // SAFETY: restore the default disposition and deliver the exact customer
    // terminating signal to this process after all supervised cleanup.
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
    ExitCode::from(u8::try_from(128_i32.saturating_add(signal)).unwrap_or(70))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controlled_precontact_probe_line_is_closed_and_redacted() {
        let line = precontact_probe_line("started", &PrecontactError::ResponseBinding);
        assert_eq!(
            line,
            "liskov-runtime-contact: precontact \
             {\"domain\":\"proof.liskov.runtime-precontact-probe.v1\",\
             \"phase\":\"started\",\"outcome\":\"response_binding\"}"
        );
        for forbidden in ["lrp1_", "https://", "token", "signature", "response body"] {
            assert!(!line.contains(forbidden));
        }
    }
}
