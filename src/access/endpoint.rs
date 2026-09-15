//! Private HTTP endpoint publication on the attachment's tailnet
//! (`BKLG-20260907-lg5y`).
//!
//! Once the tunnel is `Running`, each declared local port is published with
//! `tailscale serve --bg --http=<port>` to a loopback proxy. Reachability is
//! derived from the provider's own serve configuration, never assumed:
//!
//! - The handler must be keyed by the node's MagicDNS name and proxy to
//!   loopback. A request to the tailnet IP is not routed; this was measured as
//!   a 404 in the lg5y serve spike under the Acurast PRoot profile.
//! - Funnel must be off, which is what keeps the endpoint private.
//!
//! Local liveness and readiness probes are separate from reachability and
//! never imply it. A publication or probe failure degrades that endpoint only;
//! the tunnel and the workload keep running.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};

use super::{TailscaleAccessSession, json_object_slice, run_command};
use crate::protocol::{EndpointProbe, TailscaleEndpointPublication};

pub const ENDPOINT_PUBLISHED_STAGE: &str = "runtime.access.endpoint_published";
pub const ENDPOINT_READY_STAGE: &str = "runtime.access.endpoint_ready";
pub const ENDPOINT_DEGRADED_STAGE: &str = "runtime.access.endpoint_degraded";

/// Private to the tailnet, and gated by the customer's own ACLs.
const REACHABILITY_CLASS: &str = "network_gated";
const SERVE_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const SERVE_RESET_TIMEOUT: Duration = Duration::from_secs(10);
/// Probes run inline in the supervision loop, so a dead port must not delay
/// signal forwarding for long.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const PROBE_INTERVAL: Duration = Duration::from_secs(15);
const MAX_PROBE_RESPONSE_BYTES: u64 = 64 * 1024;

/// One endpoint diagnostic, reported on both the signed diagnostic and the
/// runtime-SSH log stream.
#[derive(Debug, Clone, PartialEq)]
pub struct EndpointEvent {
    pub stage: &'static str,
    pub succeeded: bool,
    pub failure_code: Option<&'static str>,
    pub attrs: Value,
}

/// A declared publication and what is known about it so far.
pub(super) struct EndpointSlot {
    publication: TailscaleEndpointPublication,
    published: bool,
    readiness: Option<bool>,
    finished: bool,
    next_probe_at: Instant,
}

pub(super) fn declared(publications: &[TailscaleEndpointPublication]) -> Vec<EndpointSlot> {
    publications
        .iter()
        .cloned()
        .map(|publication| EndpointSlot {
            publication,
            published: false,
            readiness: None,
            finished: false,
            next_probe_at: Instant::now(),
        })
        .collect()
}

impl super::AccessSession {
    /// Publish every declared private endpoint. Call once, after the tunnel is
    /// ready. A managed session publishes nothing.
    pub fn publish_endpoints(&mut self) -> Vec<EndpointEvent> {
        match self {
            Self::Tailscale(session) => session.publish_endpoints(),
            Self::Managed(_) => Vec::new(),
        }
    }

    /// Endpoint readiness changes that are due. Cheap between probe intervals.
    pub fn endpoint_changes(&mut self) -> Vec<EndpointEvent> {
        match self {
            Self::Tailscale(session) => session.endpoint_readiness_changes(Instant::now()),
            Self::Managed(_) => Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeVerdict {
    Pass,
    Fail,
    Unsupported,
}

impl TailscaleAccessSession {
    fn socket_path(&self) -> PathBuf {
        self.root.join("s")
    }

    fn tailscale_path(&self) -> PathBuf {
        self.root.join("tailscale")
    }

    fn endpoint_attrs(&self, publication: &TailscaleEndpointPublication) -> Value {
        json!({
            "attachmentId": self.attachment_id,
            "fence": self.fence,
            "providerKind": "tailscale",
            "useSite": publication.use_site,
            "localPort": publication.local_port,
        })
    }

    /// Publish every declared endpoint not yet published. Call once the tunnel
    /// is ready.
    pub(super) fn publish_endpoints(&mut self) -> Vec<EndpointEvent> {
        let tailscale = self.tailscale_path();
        let socket = self.socket_path();
        let mut events = Vec::new();
        for index in 0..self.endpoints.len() {
            let slot = &self.endpoints[index];
            if slot.published || slot.finished {
                continue;
            }
            let publication = slot.publication.clone();
            let mut attrs = self.endpoint_attrs(&publication);
            match publish_one(&tailscale, &socket, &self.hostname, publication.local_port) {
                Ok(()) => {
                    attrs["serviceName"] = json!(publication.service_name);
                    attrs["dnsName"] = json!(self.hostname);
                    attrs["reachabilityClass"] = json!(REACHABILITY_CLASS);
                    events.push(EndpointEvent {
                        stage: ENDPOINT_PUBLISHED_STAGE,
                        succeeded: true,
                        failure_code: None,
                        attrs,
                    });
                    let slot = &mut self.endpoints[index];
                    slot.published = true;
                    if readiness_probe(&publication).is_none() {
                        // Nothing further to observe: reachability was verified
                        // from the provider's configuration just now.
                        slot.readiness = Some(true);
                        slot.finished = true;
                        events.push(EndpointEvent {
                            stage: ENDPOINT_READY_STAGE,
                            succeeded: true,
                            failure_code: None,
                            attrs: self.endpoint_attrs(&publication),
                        });
                    }
                }
                Err(code) => {
                    self.endpoints[index].finished = true;
                    events.push(EndpointEvent {
                        stage: ENDPOINT_DEGRADED_STAGE,
                        succeeded: false,
                        failure_code: Some(code),
                        attrs,
                    });
                }
            }
        }
        events
    }

    /// Re-probe published endpoints that are due and report only changes.
    pub(super) fn endpoint_readiness_changes(&mut self, now: Instant) -> Vec<EndpointEvent> {
        let mut events = Vec::new();
        for index in 0..self.endpoints.len() {
            let slot = &self.endpoints[index];
            if !slot.published || slot.finished || now < slot.next_probe_at {
                continue;
            }
            let publication = slot.publication.clone();
            let Some(probe) = readiness_probe(&publication) else {
                continue;
            };
            let verdict = run_probe(probe, publication.local_port);
            let slot = &mut self.endpoints[index];
            slot.next_probe_at = now + PROBE_INTERVAL;
            let (readiness, finished, event) = readiness_transition(slot.readiness, verdict);
            slot.readiness = readiness;
            slot.finished |= finished;
            if let Some((stage, failure_code)) = event {
                events.push(EndpointEvent {
                    stage,
                    succeeded: failure_code.is_none(),
                    failure_code,
                    attrs: self.endpoint_attrs(&publication),
                });
            }
        }
        events
    }

    /// Withdraw every publication before the daemon stops. Best effort: device
    /// teardown removes the node, and with it every serve handler.
    pub(super) fn reset_serve(&self) {
        if self.endpoints.iter().any(|slot| slot.published) {
            let _ = run_command(
                &self.tailscale_path(),
                &serve_reset_arguments(&self.socket_path()),
                Instant::now() + SERVE_RESET_TIMEOUT,
            );
        }
    }
}

fn publish_one(
    tailscale: &Path,
    socket: &Path,
    dns_name: &str,
    local_port: u16,
) -> Result<(), &'static str> {
    let served = run_command(
        tailscale,
        &serve_arguments(socket, local_port),
        Instant::now() + SERVE_COMMAND_TIMEOUT,
    )
    .map_err(|_| "access_serve_failed")?;
    if !served.status.is_some_and(|status| status.success()) || served.output_too_large {
        return Err("access_serve_failed");
    }
    // Like `status --json`, the document is the authority, not the exit code.
    let status = run_command(
        tailscale,
        &serve_status_arguments(socket),
        Instant::now() + SERVE_COMMAND_TIMEOUT,
    )
    .map_err(|_| "access_serve_status_invalid")?;
    if status.status.is_none() || status.output_too_large {
        return Err("access_serve_status_invalid");
    }
    verify_private_publication(&status.stdout, dns_name, local_port)
}

fn socket_argument(socket: &Path) -> OsString {
    OsString::from(format!("--socket={}", socket.display()))
}

fn serve_arguments(socket: &Path, local_port: u16) -> Vec<OsString> {
    vec![
        socket_argument(socket),
        "serve".into(),
        "--bg".into(),
        "--yes".into(),
        format!("--http={local_port}").into(),
        format!("http://127.0.0.1:{local_port}").into(),
    ]
}

fn serve_status_arguments(socket: &Path) -> Vec<OsString> {
    vec![
        socket_argument(socket),
        "serve".into(),
        "status".into(),
        "--json".into(),
    ]
}

fn serve_reset_arguments(socket: &Path) -> Vec<OsString> {
    vec![socket_argument(socket), "serve".into(), "reset".into()]
}

#[derive(Deserialize, Default)]
struct ServeConfig {
    #[serde(default, rename = "TCP")]
    tcp: BTreeMap<String, TcpPortHandler>,
    #[serde(default, rename = "Web")]
    web: BTreeMap<String, WebServerConfig>,
    #[serde(default, rename = "AllowFunnel")]
    allow_funnel: BTreeMap<String, bool>,
}

#[derive(Deserialize)]
struct TcpPortHandler {
    #[serde(default, rename = "HTTP")]
    http: bool,
    #[serde(default, rename = "HTTPS")]
    https: bool,
    #[serde(default, rename = "TCPForward")]
    tcp_forward: Option<String>,
}

#[derive(Deserialize)]
struct WebServerConfig {
    #[serde(default, rename = "Handlers")]
    handlers: BTreeMap<String, HttpHandler>,
}

#[derive(Deserialize)]
struct HttpHandler {
    #[serde(default, rename = "Proxy")]
    proxy: Option<String>,
}

/// Prove, from the provider's own serve configuration, that `local_port` is
/// published privately. The listener must be plain HTTP on the port, the
/// handler must be keyed by the node's MagicDNS name and proxy only to
/// loopback, and Funnel must be off.
fn verify_private_publication(
    document: &[u8],
    dns_name: &str,
    local_port: u16,
) -> Result<(), &'static str> {
    let config: ServeConfig = serde_json::from_slice(json_object_slice(document))
        .map_err(|_| "access_serve_status_invalid")?;
    if config.allow_funnel.values().any(|allowed| *allowed) {
        return Err("access_endpoint_public");
    }
    let listener_ok = config
        .tcp
        .get(&local_port.to_string())
        .is_some_and(|handler| handler.http && !handler.https && handler.tcp_forward.is_none());
    let host = format!("{}:{local_port}", dns_name.trim_end_matches('.'));
    let expected_proxy = format!("http://127.0.0.1:{local_port}");
    let handler_ok = config.web.get(&host).is_some_and(|web| {
        web.handlers.len() == 1
            && web
                .handlers
                .get("/")
                .and_then(|handler| handler.proxy.as_deref())
                == Some(expected_proxy.as_str())
    });
    if listener_ok && handler_ok {
        Ok(())
    } else {
        Err("access_serve_unexpected")
    }
}

/// Readiness is observed through the declared `ready` probe, or `live` when
/// only liveness is declared.
fn readiness_probe(publication: &TailscaleEndpointPublication) -> Option<&EndpointProbe> {
    publication
        .health
        .as_ref()
        .and_then(|health| health.ready.as_ref().or(health.live.as_ref()))
}

/// The next readiness state, whether probing is finished, and the event (stage
/// and failure code) to report.
type ReadinessStep = (
    Option<bool>,
    bool,
    Option<(&'static str, Option<&'static str>)>,
);

/// Only transitions report, so a steady endpoint is silent.
fn readiness_transition(previous: Option<bool>, verdict: ProbeVerdict) -> ReadinessStep {
    match verdict {
        ProbeVerdict::Pass if previous != Some(true) => {
            (Some(true), false, Some((ENDPOINT_READY_STAGE, None)))
        }
        ProbeVerdict::Pass => (previous, false, None),
        ProbeVerdict::Fail if previous == Some(true) => (
            Some(false),
            false,
            Some((ENDPOINT_DEGRADED_STAGE, Some("access_probe_failed"))),
        ),
        ProbeVerdict::Fail => (previous, false, None),
        // Executing customer commands as probes is not implemented yet. Report
        // that once, by name, rather than claiming a readiness it never
        // observed.
        ProbeVerdict::Unsupported => (
            Some(false),
            true,
            Some((ENDPOINT_DEGRADED_STAGE, Some("access_probe_unsupported"))),
        ),
    }
}

fn run_probe(probe: &EndpointProbe, local_port: u16) -> ProbeVerdict {
    match probe {
        EndpointProbe::Http { path, contains } => match http_get_loopback(local_port, path) {
            Some((status, body))
                if (200..300).contains(&status)
                    && contains.as_ref().is_none_or(|needle| {
                        !needle.is_empty()
                            && body
                                .windows(needle.len())
                                .any(|window| window == needle.as_bytes())
                    }) =>
            {
                ProbeVerdict::Pass
            }
            _ => ProbeVerdict::Fail,
        },
        EndpointProbe::Tcp { port } => {
            if TcpStream::connect_timeout(
                &SocketAddr::from((Ipv4Addr::LOCALHOST, *port)),
                PROBE_TIMEOUT,
            )
            .is_ok()
            {
                ProbeVerdict::Pass
            } else {
                ProbeVerdict::Fail
            }
        }
        EndpointProbe::Exec { .. } => ProbeVerdict::Unsupported,
    }
}

/// A bounded HTTP/1.0 GET against loopback. Returns the status and body.
fn http_get_loopback(port: u16, path: &str) -> Option<(u16, Vec<u8>)> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        PROBE_TIMEOUT,
    )
    .ok()?;
    stream.set_read_timeout(Some(PROBE_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(PROBE_TIMEOUT)).ok()?;
    // One write: a server may answer after the first bytes it sees, and closing
    // with request bytes still unread resets the connection.
    let request =
        format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    let mut response = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                response.extend_from_slice(&buffer[..read]);
                if response.len() as u64 > MAX_PROBE_RESPONSE_BYTES {
                    return None;
                }
            }
            // A reset after the answer arrived still leaves a complete answer.
            Err(_) if !response.is_empty() => break,
            Err(_) => return None,
        }
    }
    let head_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    let status_line = std::str::from_utf8(&response[..head_end])
        .ok()?
        .lines()
        .next()?;
    let mut parts = status_line.split_whitespace();
    if !parts.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let status = parts.next()?.parse().ok()?;
    Some((status, response[head_end + 4..].to_vec()))
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    const DNS: &str = "liskov-prt-e22e799c1638.tail3b99c3.ts.net";

    /// Verbatim from the lg5y serve spike: the fork client under the Acurast
    /// PRoot profile, published with `serve --bg --yes --http=18123`.
    const SPIKE_STATUS: &str = r#"{  "TCP": {    "18123": {      "HTTP": true    }  },  "Web": {    "liskov-prt-e22e799c1638.tail3b99c3.ts.net:18123": {      "Handlers": {        "/": {          "Proxy": "http://127.0.0.1:18123"        }      }    }  }}"#;

    #[test]
    fn serve_arguments_publish_plain_http_to_loopback_only() {
        let socket = Path::new("/private/s");
        assert_eq!(
            serve_arguments(socket, 8123),
            [
                "--socket=/private/s",
                "serve",
                "--bg",
                "--yes",
                "--http=8123",
                "http://127.0.0.1:8123",
            ]
            .map(OsString::from)
        );
        assert_eq!(
            serve_status_arguments(socket),
            ["--socket=/private/s", "serve", "status", "--json"].map(OsString::from)
        );
        assert_eq!(
            serve_reset_arguments(socket),
            ["--socket=/private/s", "serve", "reset"].map(OsString::from)
        );
    }

    #[test]
    fn the_spike_serve_configuration_is_a_private_publication() {
        assert_eq!(
            verify_private_publication(SPIKE_STATUS.as_bytes(), DNS, 18123),
            Ok(())
        );
        let with_banner = format!("Warning: something\n{SPIKE_STATUS}\n");
        assert_eq!(
            verify_private_publication(with_banner.as_bytes(), &format!("{DNS}."), 18123),
            Ok(())
        );
    }

    #[test]
    fn funnel_makes_an_endpoint_public_and_is_refused() {
        let mut document: Value = serde_json::from_str(SPIKE_STATUS).unwrap();
        document["AllowFunnel"] = json!({ format!("{DNS}:18123"): true });
        assert_eq!(
            verify_private_publication(document.to_string().as_bytes(), DNS, 18123),
            Err("access_endpoint_public")
        );
        document["AllowFunnel"] = json!({ format!("{DNS}:18123"): false });
        assert_eq!(
            verify_private_publication(document.to_string().as_bytes(), DNS, 18123),
            Ok(())
        );
    }

    #[test]
    fn anything_but_the_exact_loopback_handler_on_the_magicdns_name_is_refused() {
        let spike: Value = serde_json::from_str(SPIKE_STATUS).unwrap();
        let refused = |document: Value, dns: &str, port: u16| {
            verify_private_publication(document.to_string().as_bytes(), dns, port)
                == Err("access_serve_unexpected")
        };
        assert!(refused(spike.clone(), DNS, 8123), "another port");
        assert!(
            refused(spike.clone(), "other.tail3b99c3.ts.net", 18123),
            "another node"
        );

        let mut by_ip = spike.clone();
        by_ip["Web"] = json!({ "100.64.0.9:18123": spike["Web"][format!("{DNS}:18123")] });
        assert!(refused(by_ip, DNS, 18123), "keyed by tailnet IP");

        let mut exposed = spike.clone();
        exposed["Web"][format!("{DNS}:18123")]["Handlers"]["/"]["Proxy"] =
            json!("http://0.0.0.0:18123");
        assert!(refused(exposed, DNS, 18123), "not a loopback proxy");

        let mut extra_path = spike.clone();
        extra_path["Web"][format!("{DNS}:18123")]["Handlers"]["/admin"] =
            json!({"Proxy": "http://127.0.0.1:9000"});
        assert!(refused(extra_path, DNS, 18123), "an extra handler");

        let mut https = spike.clone();
        https["TCP"]["18123"] = json!({"HTTPS": true});
        assert!(refused(https, DNS, 18123), "not plain HTTP");

        let mut forward = spike.clone();
        forward["TCP"]["18123"] = json!({"HTTP": true, "TCPForward": "127.0.0.1:18123"});
        assert!(refused(forward, DNS, 18123), "a raw TCP forward");

        let mut no_listener = spike;
        no_listener["TCP"] = json!({});
        assert!(refused(no_listener, DNS, 18123), "no listener");

        assert_eq!(
            verify_private_publication(b"not json", DNS, 18123),
            Err("access_serve_status_invalid")
        );
    }

    fn one_response_server(response: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                // Read the whole request head, as a real server would.
                let mut request = Vec::new();
                let mut buffer = [0_u8; 512];
                while !request.windows(4).any(|window| window == b"\r\n\r\n")
                    && request.len() < 8192
                {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(read) => request.extend_from_slice(&buffer[..read]),
                    }
                }
                let _ = stream.write_all(response.as_bytes());
            }
        });
        port
    }

    fn closed_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn http_probes_require_a_success_status_and_the_declared_body() {
        let ok = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nOk.\n";
        let http = |path: &str, contains: Option<&str>| EndpointProbe::Http {
            path: path.into(),
            contains: contains.map(str::to_string),
        };
        assert_eq!(
            run_probe(&http("/ping", None), one_response_server(ok)),
            ProbeVerdict::Pass
        );
        assert_eq!(
            run_probe(
                &http("/replicas_status", Some("Ok.")),
                one_response_server(ok)
            ),
            ProbeVerdict::Pass
        );
        assert_eq!(
            run_probe(
                &http("/replicas_status", Some("Ready")),
                one_response_server(ok)
            ),
            ProbeVerdict::Fail
        );
        assert_eq!(
            run_probe(
                &http("/ping", None),
                one_response_server("HTTP/1.1 503 Service Unavailable\r\n\r\n")
            ),
            ProbeVerdict::Fail
        );
        assert_eq!(
            run_probe(&http("/ping", None), one_response_server("garbage")),
            ProbeVerdict::Fail
        );
        assert_eq!(
            run_probe(&http("/ping", None), closed_port()),
            ProbeVerdict::Fail
        );
    }

    #[test]
    fn tcp_probes_connect_and_exec_probes_are_named_unsupported() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let open = listener.local_addr().unwrap().port();
        assert_eq!(
            run_probe(&EndpointProbe::Tcp { port: open }, 1),
            ProbeVerdict::Pass
        );
        drop(listener);
        assert_eq!(
            run_probe(
                &EndpointProbe::Tcp {
                    port: closed_port()
                },
                1
            ),
            ProbeVerdict::Fail
        );
        assert_eq!(
            run_probe(
                &EndpointProbe::Exec {
                    argv: vec!["/bin/true".into()]
                },
                1
            ),
            ProbeVerdict::Unsupported
        );
    }

    #[test]
    fn readiness_reports_only_transitions() {
        use ProbeVerdict::{Fail, Pass, Unsupported};
        assert_eq!(
            readiness_transition(None, Pass),
            (Some(true), false, Some((ENDPOINT_READY_STAGE, None)))
        );
        assert_eq!(
            readiness_transition(Some(true), Pass),
            (Some(true), false, None)
        );
        assert_eq!(readiness_transition(None, Fail), (None, false, None));
        assert_eq!(
            readiness_transition(Some(true), Fail),
            (
                Some(false),
                false,
                Some((ENDPOINT_DEGRADED_STAGE, Some("access_probe_failed")))
            )
        );
        assert_eq!(
            readiness_transition(Some(false), Fail),
            (Some(false), false, None)
        );
        assert_eq!(
            readiness_transition(Some(false), Pass),
            (Some(true), false, Some((ENDPOINT_READY_STAGE, None)))
        );
        assert_eq!(
            readiness_transition(None, Unsupported),
            (
                Some(false),
                true,
                Some((ENDPOINT_DEGRADED_STAGE, Some("access_probe_unsupported")))
            )
        );
    }
}
