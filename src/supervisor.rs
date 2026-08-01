//! Long-running customer-process authority for newly finalized Cargo bundles.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;
use sha2::{Digest, Sha256};

use crate::access::{AccessSession, setup_runtime_access};
use crate::bridge::Bridge;
use crate::diagnostics::{
    AsyncDiagnosticReporter, DIAGNOSTIC_HTTP_TIMEOUT, DiagnosticStatus,
    MAX_DIAGNOSTIC_RESPONSE_BYTES,
};
use crate::http::{HttpClient, UreqHttpClient};
use crate::logging::OutputLogger;
use crate::protocol::{RestartLimit, RuntimeBootstrapResponse, SupervisionMode, SupervisionPolicy};

const HEALTH_CADENCE: Duration = Duration::from_secs(30);
const MAX_INITIAL_HEALTH_JITTER: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const STABILITY_RESET: Duration = Duration::from_secs(300);
const FINAL_RUNWAY: Duration = Duration::from_secs(5);
const FORWARDED_SIGNAL_GRACE: Duration = Duration::from_secs(5);
const CLEANUP_GRACE: Duration = Duration::from_millis(500);
const BACKOFF_PROFILE: &[u8] = b"runtime-cargo-backoff.v1\0";

static PENDING_SIGNAL: AtomicI32 = AtomicI32::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorExit {
    Code(i32),
    Signal(i32),
}

#[derive(Debug, Clone, Copy)]
struct EffectivePolicy {
    mode: SupervisionMode,
    schedule_deadline: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureReason {
    ExitNonzero(i32),
    SignalUnexpected(i32),
}

impl FailureReason {
    fn restart_reason(self) -> &'static str {
        match self {
            Self::ExitNonzero(_) => "exit_nonzero",
            Self::SignalUnexpected(_) => "signal_unexpected",
        }
    }

    fn fatal_code(self) -> &'static str {
        match self {
            Self::ExitNonzero(_) => "process_exit_nonzero",
            Self::SignalUnexpected(_) => "process_signal_unexpected",
        }
    }
}

pub fn supervise(
    command: &[OsString],
    bootstrap: &RuntimeBootstrapResponse,
    bridge: Arc<dyn Bridge>,
    bootstrap_elapsed: Duration,
) -> SupervisorExit {
    supervise_with_environment(
        command,
        bootstrap,
        bridge,
        bootstrap_elapsed,
        &BTreeMap::new(),
    )
}

pub fn supervise_with_environment(
    command: &[OsString],
    bootstrap: &RuntimeBootstrapResponse,
    bridge: Arc<dyn Bridge>,
    bootstrap_elapsed: Duration,
    runtime_environment: &BTreeMap<String, String>,
) -> SupervisorExit {
    supervise_with_environment_and_access(
        command,
        bootstrap,
        bridge,
        bootstrap_elapsed,
        runtime_environment,
        None,
    )
}

pub fn supervise_with_environment_and_access(
    command: &[OsString],
    bootstrap: &RuntimeBootstrapResponse,
    bridge: Arc<dyn Bridge>,
    bootstrap_elapsed: Duration,
    runtime_environment: &BTreeMap<String, String>,
    runtime_access_credential: Option<String>,
) -> SupervisorExit {
    let http: Arc<dyn HttpClient> = Arc::new(UreqHttpClient::with_limits(
        DIAGNOSTIC_HTTP_TIMEOUT,
        MAX_DIAGNOSTIC_RESPONSE_BYTES,
    ));
    let mut reporter = AsyncDiagnosticReporter::spawn(bootstrap, bridge, http);
    let access_binding = bootstrap.access.as_ref().map(|access| {
        json!({
            "attachmentId": access.attachment_id,
            "fence": access.fence,
            "providerKind": "tailscale",
        })
    });
    if let Some(attrs) = access_binding.clone() {
        report(
            &mut reporter
                .as_mut()
                .map(|reporter| reporter as &mut dyn RuntimeReporter),
            "runtime.access.setup_started",
            DiagnosticStatus::Started,
            None,
            attrs,
        );
    }
    let mut access_session = match setup_runtime_access(bootstrap, runtime_access_credential) {
        Ok(session) => session,
        Err(error) => {
            if let Some(attrs) = access_binding {
                report(
                    &mut reporter
                        .as_mut()
                        .map(|reporter| reporter as &mut dyn RuntimeReporter),
                    "runtime.access.degraded",
                    DiagnosticStatus::Failed,
                    Some(error.code),
                    attrs,
                );
            }
            None
        }
    };
    if let Some(session) = access_session.as_ref() {
        report(
            &mut reporter
                .as_mut()
                .map(|reporter| reporter as &mut dyn RuntimeReporter),
            "runtime.access.ready",
            DiagnosticStatus::Succeeded,
            None,
            session.ready_attrs(),
        );
    }
    let result = supervise_with_reporter_and_environment(
        command,
        bootstrap,
        bootstrap_elapsed,
        runtime_environment,
        reporter
            .as_mut()
            .map(|reporter| reporter as &mut dyn RuntimeReporter),
        access_session.as_mut(),
    );
    if let Some(session) = access_session.as_mut() {
        let attrs = session.binding_attrs();
        let (stage, status, code) = match session.stop() {
            Ok(()) => ("runtime.access.stopped", DiagnosticStatus::Succeeded, None),
            Err(_) => (
                "runtime.access.degraded",
                DiagnosticStatus::Failed,
                Some("access_cleanup_failed"),
            ),
        };
        report(
            &mut reporter
                .as_mut()
                .map(|reporter| reporter as &mut dyn RuntimeReporter),
            stage,
            status,
            code,
            attrs,
        );
    }
    result
}

trait RuntimeReporter {
    fn report(
        &mut self,
        stage: &'static str,
        status: DiagnosticStatus,
        code: Option<&'static str>,
        attrs: serde_json::Value,
    );
}

impl RuntimeReporter for AsyncDiagnosticReporter {
    fn report(
        &mut self,
        stage: &'static str,
        status: DiagnosticStatus,
        code: Option<&'static str>,
        attrs: serde_json::Value,
    ) {
        self.report(stage, status, code, attrs);
    }
}

#[cfg(test)]
fn supervise_with_reporter(
    command: &[OsString],
    bootstrap: &RuntimeBootstrapResponse,
    bootstrap_elapsed: Duration,
    reporter: Option<&mut dyn RuntimeReporter>,
) -> SupervisorExit {
    supervise_with_reporter_and_environment(
        command,
        bootstrap,
        bootstrap_elapsed,
        &BTreeMap::new(),
        reporter,
        None,
    )
}

fn supervise_with_reporter_and_environment(
    command: &[OsString],
    bootstrap: &RuntimeBootstrapResponse,
    bootstrap_elapsed: Duration,
    runtime_environment: &BTreeMap<String, String>,
    mut reporter: Option<&mut dyn RuntimeReporter>,
    mut access_session: Option<&mut AccessSession>,
) -> SupervisorExit {
    if command.is_empty() {
        report(
            &mut reporter,
            "runtime.fatal.cargo.process",
            DiagnosticStatus::Failed,
            Some("process_start_failed"),
            json!({"processAttempt": 0, "restartCount": 0}),
        );
        return SupervisorExit::Code(126);
    }
    let _process_authority = match install_process_authority() {
        Ok(authority) => authority,
        Err(_) => {
            report(
                &mut reporter,
                "runtime.fatal.cargo.supervisor",
                DiagnosticStatus::Failed,
                Some("internal_failure"),
                json!({}),
            );
            return SupervisorExit::Code(70);
        }
    };

    let policy = effective_policy(
        bootstrap.supervision_policy(),
        bootstrap_elapsed,
        Instant::now(),
    );
    let environment = sanitized_environment(runtime_environment);
    let output_logger = OutputLogger::from_environment(bootstrap);
    let mut process_attempt = 0_u64;
    let mut restart_count = 0_u64;
    let mut consecutive_failures = 0_u32;

    loop {
        if let Some(session) = access_session.as_deref_mut() {
            if session.newly_crashed() {
                report(
                    &mut reporter,
                    "runtime.access.degraded",
                    DiagnosticStatus::Failed,
                    Some("access_sidecar_failed"),
                    session.binding_attrs(),
                );
            }
        }
        if let Some(signal) = take_signal() {
            return SupervisorExit::Signal(signal);
        }
        let started_at = Instant::now();
        let child = spawn_customer(command, &environment, output_logger.is_some());
        let mut child = match child {
            Ok(child) => child,
            Err(_) => {
                report(
                    &mut reporter,
                    "runtime.fatal.cargo.process",
                    DiagnosticStatus::Failed,
                    Some("process_start_failed"),
                    json!({
                        "processAttempt": process_attempt,
                        "restartCount": restart_count,
                    }),
                );
                return SupervisorExit::Code(126);
            }
        };
        let output_attempt = output_logger
            .as_ref()
            .map(|logger| logger.capture_child(&mut child, process_attempt));
        let process_group = i32::try_from(child.id()).unwrap_or(i32::MAX);
        report(
            &mut reporter,
            "runtime.cargo.process.started",
            DiagnosticStatus::Started,
            None,
            json!({
                "processAttempt": process_attempt,
                "restartCount": restart_count,
            }),
        );

        let jitter = initial_health_jitter(&bootstrap.runtime_instance_id, process_attempt);
        let mut next_health = Instant::now() + jitter;
        let mut forwarded_signal = None;
        let mut forced_cleanup = false;
        let status = loop {
            if let Some(session) = access_session.as_deref_mut() {
                if session.newly_crashed() {
                    report(
                        &mut reporter,
                        "runtime.access.degraded",
                        DiagnosticStatus::Failed,
                        Some("access_sidecar_failed"),
                        session.binding_attrs(),
                    );
                }
            }
            if let Some(signal) = take_signal() {
                if forwarded_signal.is_none() {
                    if signal_process_group(process_group, signal).is_err() {
                        let cleanup_complete = terminate_and_reap_group(process_group);
                        report(
                            &mut reporter,
                            "runtime.fatal.cargo.supervisor",
                            DiagnosticStatus::Failed,
                            Some("signal_forward_failed"),
                            json!({
                                "processAttempt": process_attempt,
                                "restartCount": restart_count,
                                "cleanupComplete": cleanup_complete,
                            }),
                        );
                        return SupervisorExit::Code(70);
                    }
                    forwarded_signal = Some((signal, Instant::now()));
                }
            }
            if let Some((_, forwarded_at)) = forwarded_signal {
                if !forced_cleanup && forwarded_at.elapsed() >= FORWARDED_SIGNAL_GRACE {
                    let _ = signal_process_group(process_group, libc::SIGKILL);
                    forced_cleanup = true;
                }
            }
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(_) => {
                    let cleanup_complete = terminate_and_reap_group(process_group);
                    report(
                        &mut reporter,
                        "runtime.fatal.cargo.supervisor",
                        DiagnosticStatus::Failed,
                        Some("wait_failed"),
                        json!({
                            "processAttempt": process_attempt,
                            "restartCount": restart_count,
                            "cleanupComplete": cleanup_complete,
                        }),
                    );
                    return SupervisorExit::Code(70);
                }
            }
            if Instant::now() >= next_health {
                report(
                    &mut reporter,
                    "runtime.health",
                    DiagnosticStatus::Info,
                    None,
                    json!({
                        "processAttempt": process_attempt,
                        "restartCount": restart_count,
                    }),
                );
                next_health = Instant::now() + HEALTH_CADENCE;
            }
            thread::sleep(POLL_INTERVAL);
        };
        let uptime = started_at.elapsed();
        let cleanup_complete = terminate_and_reap_group(process_group);
        if let Some(output_attempt) = output_attempt {
            output_attempt.finish();
        }
        if !cleanup_complete {
            report(
                &mut reporter,
                "runtime.fatal.cargo.supervisor",
                DiagnosticStatus::Failed,
                Some("cleanup_failed"),
                json!({
                    "processAttempt": process_attempt,
                    "restartCount": restart_count,
                    "cleanupComplete": false,
                }),
            );
            return SupervisorExit::Code(70);
        }

        if forwarded_signal.is_some() {
            if let Some(code) = status.code() {
                report(
                    &mut reporter,
                    "runtime.cargo.process.exited",
                    if code == 0 {
                        DiagnosticStatus::Succeeded
                    } else {
                        DiagnosticStatus::Failed
                    },
                    None,
                    json!({
                        "processAttempt": process_attempt,
                        "restartCount": restart_count,
                        "exitCode": code,
                        "uptimeMs": duration_ms(uptime),
                        "final": true,
                        "cleanupComplete": cleanup_complete,
                    }),
                );
                return SupervisorExit::Code(code);
            }
            let signal = status.signal().unwrap_or(libc::SIGKILL);
            report(
                &mut reporter,
                "runtime.cargo.process.signaled",
                DiagnosticStatus::Info,
                None,
                json!({
                    "processAttempt": process_attempt,
                    "restartCount": restart_count,
                    "signal": signal,
                    "signalSource": "supervisor_forwarded",
                    "uptimeMs": duration_ms(uptime),
                    "final": true,
                    "cleanupComplete": cleanup_complete,
                }),
            );
            return SupervisorExit::Signal(signal);
        }

        if let Some(code) = status.code() {
            if code == 0 {
                report(
                    &mut reporter,
                    "runtime.cargo.process.exited",
                    DiagnosticStatus::Succeeded,
                    None,
                    json!({
                        "processAttempt": process_attempt,
                        "restartCount": restart_count,
                        "exitCode": code,
                        "uptimeMs": duration_ms(uptime),
                        "final": true,
                        "cleanupComplete": cleanup_complete,
                    }),
                );
                return SupervisorExit::Code(code);
            }
            let failure = FailureReason::ExitNonzero(code);
            match restart_delay(
                policy,
                process_attempt,
                restart_count,
                consecutive_failures,
                uptime,
                &bootstrap.runtime_instance_id,
                Instant::now(),
            ) {
                Ok(delay) => {
                    report_attempt_failure(
                        &mut reporter,
                        failure,
                        process_attempt,
                        restart_count,
                        uptime,
                        cleanup_complete,
                        false,
                    );
                    schedule_restart(&mut reporter, failure, process_attempt, delay);
                    if let Some(signal) = sleep_interruptibly(delay) {
                        return SupervisorExit::Signal(signal);
                    }
                }
                Err(disposition) => {
                    report_final_failure(
                        &mut reporter,
                        failure,
                        disposition,
                        process_attempt,
                        restart_count,
                        uptime,
                        cleanup_complete,
                    );
                    return SupervisorExit::Code(code);
                }
            }
        } else {
            let signal = status.signal().unwrap_or(libc::SIGKILL);
            let failure = FailureReason::SignalUnexpected(signal);
            match restart_delay(
                policy,
                process_attempt,
                restart_count,
                consecutive_failures,
                uptime,
                &bootstrap.runtime_instance_id,
                Instant::now(),
            ) {
                Ok(delay) => {
                    report_attempt_failure(
                        &mut reporter,
                        failure,
                        process_attempt,
                        restart_count,
                        uptime,
                        cleanup_complete,
                        false,
                    );
                    schedule_restart(&mut reporter, failure, process_attempt, delay);
                    if let Some(signal) = sleep_interruptibly(delay) {
                        return SupervisorExit::Signal(signal);
                    }
                }
                Err(disposition) => {
                    report_final_failure(
                        &mut reporter,
                        failure,
                        disposition,
                        process_attempt,
                        restart_count,
                        uptime,
                        cleanup_complete,
                    );
                    return SupervisorExit::Signal(signal);
                }
            }
        }
        consecutive_failures = if uptime >= STABILITY_RESET {
            1
        } else {
            consecutive_failures.saturating_add(1)
        };
        process_attempt = process_attempt.saturating_add(1);
        restart_count = restart_count.saturating_add(1);
    }
}

fn report(
    reporter: &mut Option<&mut dyn RuntimeReporter>,
    stage: &'static str,
    status: DiagnosticStatus,
    code: Option<&'static str>,
    attrs: serde_json::Value,
) {
    if let Some(reporter) = reporter.as_deref_mut() {
        reporter.report(stage, status, code, attrs);
    }
}

fn report_attempt_failure(
    reporter: &mut Option<&mut dyn RuntimeReporter>,
    failure: FailureReason,
    process_attempt: u64,
    restart_count: u64,
    uptime: Duration,
    cleanup_complete: bool,
    final_attempt: bool,
) {
    match failure {
        FailureReason::ExitNonzero(code) => report(
            reporter,
            "runtime.cargo.process.exited",
            DiagnosticStatus::Failed,
            None,
            json!({
                "processAttempt": process_attempt,
                "restartCount": restart_count,
                "exitCode": code,
                "uptimeMs": duration_ms(uptime),
                "final": final_attempt,
                "cleanupComplete": cleanup_complete,
            }),
        ),
        FailureReason::SignalUnexpected(signal) => report(
            reporter,
            "runtime.cargo.process.signaled",
            DiagnosticStatus::Failed,
            None,
            json!({
                "processAttempt": process_attempt,
                "restartCount": restart_count,
                "signal": signal,
                "signalSource": "child_unexpected",
                "uptimeMs": duration_ms(uptime),
                "final": final_attempt,
                "cleanupComplete": cleanup_complete,
            }),
        ),
    }
}

fn report_final_failure(
    reporter: &mut Option<&mut dyn RuntimeReporter>,
    failure: FailureReason,
    disposition: &'static str,
    process_attempt: u64,
    restart_count: u64,
    uptime: Duration,
    cleanup_complete: bool,
) {
    let mut attrs = json!({
        "processAttempt": process_attempt,
        "restartCount": restart_count,
        "uptimeMs": duration_ms(uptime),
        "cleanupComplete": cleanup_complete,
        "restartDisposition": disposition,
    });
    match failure {
        FailureReason::ExitNonzero(code) => attrs["exitCode"] = json!(code),
        FailureReason::SignalUnexpected(signal) => attrs["signal"] = json!(signal),
    }
    report(
        reporter,
        "runtime.fatal.cargo.process",
        DiagnosticStatus::Failed,
        Some(failure.fatal_code()),
        attrs,
    );
}

fn schedule_restart(
    reporter: &mut Option<&mut dyn RuntimeReporter>,
    failure: FailureReason,
    process_attempt: u64,
    delay: Duration,
) {
    report(
        reporter,
        "runtime.cargo.process.restart_scheduled",
        DiagnosticStatus::Info,
        None,
        json!({
            "fromProcessAttempt": process_attempt,
            "toProcessAttempt": process_attempt.saturating_add(1),
            "reason": failure.restart_reason(),
            "delayMs": duration_ms(delay),
        }),
    );
}

fn spawn_customer(
    command: &[OsString],
    environment: &[(OsString, OsString)],
    capture_output: bool,
) -> std::io::Result<std::process::Child> {
    let mut child = Command::new(&command[0]);
    child
        .args(&command[1..])
        .env_clear()
        .envs(environment.iter().cloned())
        .stdin(Stdio::inherit());
    if capture_output {
        child.stdout(Stdio::piped()).stderr(Stdio::piped());
    } else {
        child.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    }
    // SAFETY: this closure calls only async-signal-safe libc functions between
    // fork and exec, does not allocate, and reports failure through `last_os_error`.
    unsafe {
        child.pre_exec(|| {
            reset_supported_signal_handlers();
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    child.spawn()
}

fn sanitized_environment(
    runtime_environment: &BTreeMap<String, String>,
) -> Vec<(OsString, OsString)> {
    merge_runtime_environment(
        sanitize_environment_values(std::env::vars_os()),
        runtime_environment,
    )
}

fn merge_runtime_environment(
    mut environment: Vec<(OsString, OsString)>,
    runtime_environment: &BTreeMap<String, String>,
) -> Vec<(OsString, OsString)> {
    for (name, value) in runtime_environment {
        environment.retain(|(existing, _)| existing.to_str() != Some(name.as_str()));
        environment.push((name.into(), value.into()));
    }
    environment
}

fn sanitize_environment_values(
    values: impl IntoIterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    values
        .into_iter()
        .filter(|(key, _)| {
            !matches!(
                key.to_str(),
                Some(
                    "PROOF_SLIPWAY_BOOTSTRAP"
                        | "LISKOV_CARGO_SUPERVISION_CANARY_JSON"
                        | "LISKOV_RUNTIME_SSH_CREDENTIAL_V1"
                )
            )
        })
        .collect()
}

fn effective_policy(
    policy: Option<SupervisionPolicy>,
    bootstrap_elapsed: Duration,
    now: Instant,
) -> EffectivePolicy {
    let Some(policy) = policy else {
        return EffectivePolicy {
            mode: SupervisionMode::Never,
            schedule_deadline: None,
        };
    };
    let Some(server_remaining_ms) = policy.schedule_end_ms.checked_sub(policy.server_time_ms)
    else {
        return EffectivePolicy {
            mode: SupervisionMode::Never,
            schedule_deadline: None,
        };
    };
    let remaining = Duration::from_millis(server_remaining_ms).saturating_sub(bootstrap_elapsed);
    let Some(schedule_deadline) = now.checked_add(remaining) else {
        return EffectivePolicy {
            mode: SupervisionMode::Never,
            schedule_deadline: None,
        };
    };
    EffectivePolicy {
        mode: policy.mode,
        schedule_deadline: Some(schedule_deadline),
    }
}

#[allow(clippy::too_many_arguments)]
fn restart_delay(
    policy: EffectivePolicy,
    process_attempt: u64,
    restart_count: u64,
    consecutive_failures: u32,
    uptime: Duration,
    runtime_instance_id: &str,
    now: Instant,
) -> Result<Duration, &'static str> {
    let SupervisionMode::OnFailure { restart_limit } = policy.mode else {
        return Err("policy_never");
    };
    if let RestartLimit::Attempts { max_restarts } = restart_limit {
        if restart_count >= u64::from(max_restarts) {
            return Err("attempt_limit_reached");
        }
    }
    let Some(deadline) = policy.schedule_deadline else {
        return Err("schedule_end_reached");
    };
    let remaining = deadline.saturating_duration_since(now);
    if remaining <= FINAL_RUNWAY {
        return Err("schedule_end_reached");
    }
    let failure_index = if uptime >= STABILITY_RESET {
        0
    } else {
        consecutive_failures
    };
    let normal = deterministic_backoff(runtime_instance_id, process_attempt, failure_index);
    Ok(normal.min(remaining.saturating_sub(FINAL_RUNWAY)))
}

pub fn deterministic_backoff(
    runtime_instance_id: &str,
    process_attempt: u64,
    consecutive_failure: u32,
) -> Duration {
    let exponent = consecutive_failure.min(6);
    let ceiling_ms = (1_000_u64 << exponent).min(60_000);
    let floor_ms = ceiling_ms / 2;
    let mut hasher = Sha256::new();
    hasher.update(BACKOFF_PROFILE);
    hasher.update(runtime_instance_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(process_attempt.to_be_bytes());
    let digest = hasher.finalize();
    let sample = u64::from_be_bytes(digest[..8].try_into().expect("eight digest bytes"));
    let delay_ms = floor_ms + sample % (ceiling_ms - floor_ms + 1);
    Duration::from_millis(delay_ms)
}

fn initial_health_jitter(runtime_instance_id: &str, process_attempt: u64) -> Duration {
    let mut hasher = Sha256::new();
    hasher.update(b"runtime-cargo-health-jitter.v1\0");
    hasher.update(runtime_instance_id.as_bytes());
    hasher.update(process_attempt.to_be_bytes());
    let digest = hasher.finalize();
    let sample = u64::from_be_bytes(digest[..8].try_into().expect("eight digest bytes"));
    let max_ms = u64::try_from(MAX_INITIAL_HEALTH_JITTER.as_millis()).unwrap_or(30_000);
    Duration::from_millis(sample % (max_ms + 1))
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn sleep_interruptibly(duration: Duration) -> Option<i32> {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        if let Some(signal) = take_signal() {
            return Some(signal);
        }
        thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
    None
}

extern "C" fn capture_signal(signal: i32) {
    let _ = PENDING_SIGNAL.compare_exchange(0, signal, Ordering::Relaxed, Ordering::Relaxed);
}

const SUPPORTED_SIGNALS: [i32; 6] = [
    libc::SIGHUP,
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGUSR1,
    libc::SIGUSR2,
    libc::SIGTERM,
];

struct ProcessAuthorityGuard {
    previous_handlers: [libc::sighandler_t; SUPPORTED_SIGNALS.len()],
    was_subreaper: i32,
}

impl Drop for ProcessAuthorityGuard {
    fn drop(&mut self) {
        // SAFETY: restore the process attributes captured by
        // `install_process_authority` after supervision has stopped.
        unsafe {
            for (signal, handler) in SUPPORTED_SIGNALS.into_iter().zip(self.previous_handlers) {
                libc::signal(signal, handler);
            }
            libc::prctl(libc::PR_SET_CHILD_SUBREAPER, self.was_subreaper, 0, 0, 0);
        }
    }
}

fn install_process_authority() -> std::io::Result<ProcessAuthorityGuard> {
    PENDING_SIGNAL.store(0, Ordering::Relaxed);
    // SAFETY: PR_SET_CHILD_SUBREAPER changes only this process attribute and
    // `signal` installs the async-signal-safe atomic handler above.
    unsafe {
        let mut was_subreaper = 0_i32;
        if libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut was_subreaper, 0, 0, 0) == -1 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let mut previous_handlers = [libc::SIG_DFL; SUPPORTED_SIGNALS.len()];
        for (index, signal) in SUPPORTED_SIGNALS.into_iter().enumerate() {
            let previous = libc::signal(signal, capture_signal as libc::sighandler_t);
            if previous == libc::SIG_ERR {
                for (installed_signal, handler) in SUPPORTED_SIGNALS
                    .into_iter()
                    .zip(previous_handlers)
                    .take(index)
                {
                    libc::signal(installed_signal, handler);
                }
                libc::prctl(libc::PR_SET_CHILD_SUBREAPER, was_subreaper, 0, 0, 0);
                return Err(std::io::Error::last_os_error());
            }
            previous_handlers[index] = previous;
        }
        Ok(ProcessAuthorityGuard {
            previous_handlers,
            was_subreaper,
        })
    }
}

fn reset_supported_signal_handlers() {
    // SAFETY: called only in `pre_exec`; resetting dispositions to default is
    // async-signal-safe and ensures the customer does not inherit the handler.
    unsafe {
        for signal in SUPPORTED_SIGNALS {
            libc::signal(signal, libc::SIG_DFL);
        }
    }
}

fn take_signal() -> Option<i32> {
    match PENDING_SIGNAL.swap(0, Ordering::Relaxed) {
        0 => None,
        signal => Some(signal),
    }
}

fn signal_process_group(process_group: i32, signal: i32) -> std::io::Result<()> {
    // SAFETY: negative PID targets exactly the child-created process group.
    let result = unsafe { libc::kill(-process_group, signal) };
    if result == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    Ok(())
}

fn process_group_exists(process_group: i32) -> bool {
    // SAFETY: signal zero performs an existence/permission check only.
    let result = unsafe { libc::kill(-process_group, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn terminate_and_reap_group(process_group: i32) -> bool {
    if process_group <= 0 {
        return false;
    }
    let _ = signal_process_group(process_group, libc::SIGTERM);
    let deadline = Instant::now() + CLEANUP_GRACE;
    while process_group_exists(process_group) && Instant::now() < deadline {
        reap_descendants();
        thread::sleep(POLL_INTERVAL);
    }
    if process_group_exists(process_group) {
        let _ = signal_process_group(process_group, libc::SIGKILL);
    }
    let deadline = Instant::now() + CLEANUP_GRACE;
    while process_group_exists(process_group) && Instant::now() < deadline {
        reap_descendants();
        thread::sleep(POLL_INTERVAL);
    }
    reap_descendants();
    !process_group_exists(process_group)
}

fn reap_descendants() {
    loop {
        let mut status = 0_i32;
        // SAFETY: WNOHANG only reaps children already in a waitable state.
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid <= 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    static PROCESS_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn bootstrap(supervision: serde_json::Value) -> RuntimeBootstrapResponse {
        RuntimeBootstrapResponse {
            ok: true,
            domain: "proof.liskov.runtime-bootstrap-response.v2".into(),
            application_uid: "app-uid".into(),
            application_id: "app".into(),
            policy_digest: "digest".into(),
            deployment_id: "deployment".into(),
            job_id: "job".into(),
            processor_id: "processor".into(),
            runtime_instance_id: "runtime-instance".into(),
            slipway_url: "https://liskov.example".into(),
            runtime_env: None,
            supervision: Some(supervision),
            logging: None,
            logging_outage_canary: false,
            access: None,
        }
    }

    #[test]
    fn deterministic_equal_jitter_stays_in_every_locked_range() {
        for (failure, ceiling) in [
            (0, 1_000),
            (1, 2_000),
            (2, 4_000),
            (3, 8_000),
            (4, 16_000),
            (5, 32_000),
            (6, 60_000),
            (20, 60_000),
        ] {
            let first = deterministic_backoff("instance", u64::from(failure), failure);
            let second = deterministic_backoff("instance", u64::from(failure), failure);
            assert_eq!(first, second);
            assert!(first >= Duration::from_millis(ceiling / 2));
            assert!(first <= Duration::from_millis(ceiling));
        }
        assert_eq!(
            deterministic_backoff("instance", 0, 0),
            Duration::from_millis(874)
        );
        assert_eq!(
            deterministic_backoff("instance", 1, 1),
            Duration::from_millis(1_183)
        );
        assert_eq!(
            deterministic_backoff("instance", 6, 6),
            Duration::from_millis(38_596)
        );
    }

    #[test]
    fn attempt_zero_and_schedule_end_fail_closed() {
        let now = Instant::now();
        let count_zero = EffectivePolicy {
            mode: SupervisionMode::OnFailure {
                restart_limit: RestartLimit::Attempts { max_restarts: 0 },
            },
            schedule_deadline: Some(now + Duration::from_secs(60)),
        };
        assert_eq!(
            restart_delay(count_zero, 0, 0, 0, Duration::ZERO, "instance", now,),
            Err("attempt_limit_reached")
        );

        let expired = EffectivePolicy {
            mode: SupervisionMode::OnFailure {
                restart_limit: RestartLimit::ScheduleEnd,
            },
            schedule_deadline: Some(now + Duration::from_millis(4_999)),
        };
        assert_eq!(
            restart_delay(expired, 0, 0, 0, Duration::ZERO, "instance", now,),
            Err("schedule_end_reached")
        );

        let exact_runway = EffectivePolicy {
            schedule_deadline: Some(now + FINAL_RUNWAY),
            ..expired
        };
        assert_eq!(
            restart_delay(exact_runway, 0, 0, 0, Duration::ZERO, "instance", now,),
            Err("schedule_end_reached")
        );
    }

    #[test]
    fn final_delay_is_shortened_to_leave_five_second_runway() {
        let now = Instant::now();
        let policy = EffectivePolicy {
            mode: SupervisionMode::OnFailure {
                restart_limit: RestartLimit::ScheduleEnd,
            },
            schedule_deadline: Some(now + Duration::from_millis(5_100)),
        };
        assert_eq!(
            restart_delay(policy, 0, 0, 0, Duration::ZERO, "instance", now,),
            Ok(Duration::from_millis(100))
        );
    }

    #[test]
    fn five_minute_uptime_resets_the_backoff_streak() {
        let now = Instant::now();
        let policy = EffectivePolicy {
            mode: SupervisionMode::OnFailure {
                restart_limit: RestartLimit::ScheduleEnd,
            },
            schedule_deadline: Some(now + Duration::from_secs(600)),
        };
        assert_eq!(
            restart_delay(policy, 7, 7, 6, STABILITY_RESET, "instance", now,),
            Ok(deterministic_backoff("instance", 7, 0))
        );
    }

    #[test]
    fn attempt_limit_counts_completed_restarts() {
        let now = Instant::now();
        let policy = EffectivePolicy {
            mode: SupervisionMode::OnFailure {
                restart_limit: RestartLimit::Attempts { max_restarts: 2 },
            },
            schedule_deadline: Some(now + Duration::from_secs(600)),
        };
        assert!(restart_delay(policy, 1, 1, 1, Duration::ZERO, "instance", now).is_ok());
        assert_eq!(
            restart_delay(policy, 2, 2, 2, Duration::ZERO, "instance", now),
            Err("attempt_limit_reached")
        );
    }

    #[test]
    fn bootstrap_elapsed_time_is_removed_before_monotonic_anchoring() {
        let now = Instant::now();
        let effective = effective_policy(
            bootstrap(json!({
                "mode": "on_failure",
                "restartLimit": {"kind": "schedule_end"},
                "serverTimeMs": 10_000,
                "scheduleEndMs": 20_000,
            }))
            .supervision_policy(),
            Duration::from_secs(3),
            now,
        );
        assert_eq!(
            effective.schedule_deadline,
            Some(now + Duration::from_secs(7))
        );
    }

    #[test]
    fn sanitizes_only_internal_credential_values() {
        let environment = sanitize_environment_values([
            ("PROOF_SLIPWAY_BOOTSTRAP".into(), "secret".into()),
            ("LISKOV_RUNTIME_SSH_CREDENTIAL_V1".into(), "secret".into()),
            ("LISKOV_SUPERVISOR_TEST_VISIBLE".into(), "yes".into()),
        ]);
        assert!(
            !environment
                .iter()
                .any(|(key, _)| key == "PROOF_SLIPWAY_BOOTSTRAP")
        );
        assert!(
            environment
                .iter()
                .any(|(key, value)| { key == "LISKOV_SUPERVISOR_TEST_VISIBLE" && value == "yes" })
        );
    }

    #[test]
    fn runtime_environment_overrides_inherited_customer_values() {
        let runtime_environment = BTreeMap::from([("MODE".to_string(), "new".to_string())]);
        let environment = merge_runtime_environment(
            sanitize_environment_values([
                ("MODE".into(), "old".into()),
                ("VISIBLE".into(), "yes".into()),
            ]),
            &runtime_environment,
        );
        assert_eq!(
            environment
                .iter()
                .find(|(name, _)| name == "MODE")
                .map(|(_, value)| value),
            Some(&OsString::from("new"))
        );
        assert!(
            environment
                .iter()
                .any(|(name, value)| name == "VISIBLE" && value == "yes")
        );
    }

    #[test]
    fn captured_runtime_environment_reaches_the_customer_process() {
        let _lock = PROCESS_TEST_LOCK.lock().unwrap();
        let never = bootstrap(json!({
            "mode": "never",
            "serverTimeMs": 1,
            "scheduleEndMs": 60_001,
        }));
        let runtime_environment =
            BTreeMap::from([("LISKOV_SUPERVISOR_TEST_VALUE".into(), "signed".into())]);
        assert_eq!(
            supervise_with_reporter_and_environment(
                &[
                    "/bin/sh".into(),
                    "-c".into(),
                    "test \"$LISKOV_SUPERVISOR_TEST_VALUE\" = signed".into(),
                ],
                &never,
                Duration::ZERO,
                &runtime_environment,
                None,
                None,
            ),
            SupervisorExit::Code(0)
        );
    }

    #[test]
    fn propagates_exact_ordinary_exit_and_unexpected_signal() {
        let _lock = PROCESS_TEST_LOCK.lock().unwrap();
        let never = bootstrap(json!({
            "mode": "never",
            "serverTimeMs": 1,
            "scheduleEndMs": 60_001,
        }));
        assert_eq!(
            supervise_with_reporter(
                &["/bin/sh".into(), "-c".into(), "exit 7".into()],
                &never,
                Duration::ZERO,
                None,
            ),
            SupervisorExit::Code(7)
        );
        assert_eq!(
            supervise_with_reporter(
                &["/bin/sh".into(), "-c".into(), "kill -TERM $$".into(),],
                &never,
                Duration::ZERO,
                None,
            ),
            SupervisorExit::Signal(libc::SIGTERM)
        );
    }

    #[test]
    fn restarts_the_same_exact_command_once_without_overlap() {
        let _lock = PROCESS_TEST_LOCK.lock().unwrap();
        let marker = std::env::temp_dir().join(format!(
            "liskov-runtime-cargo-fail-once-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&marker);
        let command = vec![
            "/bin/sh".into(),
            "-c".into(),
            "if [ -f \"$1\" ]; then exit 0; else : > \"$1\"; exit 9; fi".into(),
            "liskov-fail-once".into(),
            marker.as_os_str().to_owned(),
        ];
        let policy = bootstrap(json!({
            "mode": "on_failure",
            "restartLimit": {"kind": "attempts", "maxRestarts": 1},
            "serverTimeMs": 1,
            "scheduleEndMs": 60_001,
        }));
        assert_eq!(
            supervise_with_reporter(&command, &policy, Duration::ZERO, None),
            SupervisorExit::Code(0)
        );
        assert!(marker.exists());
        std::fs::remove_file(marker).unwrap();
    }

    #[test]
    fn forwards_operator_signal_without_restarting() {
        let _lock = PROCESS_TEST_LOCK.lock().unwrap();
        let never = bootstrap(json!({
            "mode": "never",
            "serverTimeMs": 1,
            "scheduleEndMs": 60_001,
        }));
        let signaler = thread::spawn(|| {
            thread::sleep(Duration::from_millis(100));
            PENDING_SIGNAL.store(libc::SIGTERM, Ordering::Relaxed);
        });
        assert_eq!(
            supervise_with_reporter(
                &["/bin/sh".into(), "-c".into(), "sleep 5".into()],
                &never,
                Duration::ZERO,
                None,
            ),
            SupervisorExit::Signal(libc::SIGTERM)
        );
        signaler.join().unwrap();
    }

    #[test]
    fn preserves_exit_code_when_customer_handles_forwarded_signal() {
        let _lock = PROCESS_TEST_LOCK.lock().unwrap();
        let marker = std::env::temp_dir().join(format!(
            "liskov-runtime-cargo-signal-ready-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&marker);
        let never = bootstrap(json!({
            "mode": "never",
            "serverTimeMs": 1,
            "scheduleEndMs": 60_001,
        }));
        let marker_for_signal = marker.clone();
        let signaler = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !marker_for_signal.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            assert!(marker_for_signal.exists());
            PENDING_SIGNAL.store(libc::SIGTERM, Ordering::Relaxed);
        });
        let command = vec![
            "/bin/sh".into(),
            "-c".into(),
            "trap 'exit 23' TERM; : > \"$1\"; while :; do sleep 1; done".into(),
            "liskov-signal-trap".into(),
            marker.as_os_str().to_owned(),
        ];
        assert_eq!(
            supervise_with_reporter(&command, &never, Duration::ZERO, None),
            SupervisorExit::Code(23)
        );
        signaler.join().unwrap();
        std::fs::remove_file(marker).unwrap();
    }
}
