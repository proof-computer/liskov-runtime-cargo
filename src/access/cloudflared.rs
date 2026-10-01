//! The supervised `cloudflared` connector of a Cloudflare named tunnel
//! (`BKLG-20261001-phw4`): the exact argv and environment it starts with, a
//! classifier for its log lines, and the supervision state machine that
//! respawns it within the helper's sidecar budget.
//!
//! Nothing spawns `cloudflared` yet. The wiring packet named in
//! `BKLG-20260803-41f4` adds the bootstrap field, the binary fetch and the
//! diagnostic emission.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "wired by the Cloudflare driver packet named in BKLG-20260803-41f4"
    )
)]

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::managed::MAX_SIDECAR_RESPAWNS;
use super::{AccessError, terminate_child_within};

/// The only place the connector token travels. `/proc/<pid>/cmdline` is
/// readable inside the job, so the token never appears in argv.
pub(super) const TOKEN_ENVIRONMENT_VARIABLE: &str = "TUNNEL_TOKEN";
/// A drained connector gets this long between SIGTERM and SIGKILL.
pub(super) const DRAIN_GRACE: Duration = Duration::from_secs(10);
/// A connector holding no registered connection this long is restarted.
pub(super) const REREGISTRATION_WINDOW: Duration = Duration::from_secs(30);
const MAX_TOKEN_BYTES: usize = 4096;
const MAX_LOCATION_BYTES: usize = 16;

pub(super) const REGISTERED_CODE: &str = "ingress_connector_registered";
pub(super) const UNREGISTERED_CODE: &str = "ingress_connector_unregistered";
pub(super) const EXITED_CODE: &str = "ingress_connector_exited";
pub(super) const RESPAWN_BUDGET_SPENT_CODE: &str = "ingress_connector_respawn_budget_spent";
/// The default `localhost:0` listener fails to resolve under PRoot and the
/// process exits before dialling the edge. A respawn repeats it: this is a
/// helper bug, not an edge fault.
pub(super) const METRICS_LISTENER_FAILED_CODE: &str = "ingress_connector_metrics_listener_failed";
const METRICS_ADDRESS_REFUSED_CODE: &str = "ingress_connector_metrics_address_refused";
const TOKEN_INVALID_CODE: &str = "ingress_connector_token_invalid";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Protocol {
    Quic,
    Http2,
}

impl Protocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::Quic => "quic",
            Self::Http2 => "http2",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "quic" => Some(Self::Quic),
            "http2" => Some(Self::Http2),
            _ => None,
        }
    }
}

/// `cloudflared tunnel --no-autoupdate --metrics 127.0.0.1:<port> --protocol
/// <quic|http2> run`. The token is not an argument.
pub(super) fn cloudflared_arguments(metrics_port: NonZeroU16, protocol: Protocol) -> Vec<OsString> {
    vec![
        OsString::from("tunnel"),
        OsString::from("--no-autoupdate"),
        OsString::from("--metrics"),
        OsString::from(format!("{}:{metrics_port}", Ipv4Addr::LOCALHOST)),
        OsString::from("--protocol"),
        OsString::from(protocol.as_str()),
        OsString::from("run"),
    ]
}

struct ConnectorToken(Zeroizing<String>);

impl fmt::Debug for ConnectorToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectorToken(<redacted>)")
    }
}

/// What every launch of one connector shares: its loopback metrics port and
/// its token. The protocol is chosen per launch by [`ConnectorSupervision`].
#[derive(Debug)]
pub(super) struct LaunchPlan {
    metrics_port: NonZeroU16,
    token: ConnectorToken,
}

impl LaunchPlan {
    /// Refuses a metrics listener other than `127.0.0.1:<non-zero port>` and a
    /// token that is empty, oversized or not printable ASCII.
    pub(super) fn new(metrics: SocketAddr, token: &str) -> Result<Self, AccessError> {
        if metrics.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return Err(AccessError::new(METRICS_ADDRESS_REFUSED_CODE));
        }
        let metrics_port = NonZeroU16::new(metrics.port())
            .ok_or_else(|| AccessError::new(METRICS_ADDRESS_REFUSED_CODE))?;
        if token.is_empty()
            || token.len() > MAX_TOKEN_BYTES
            || !token.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(AccessError::new(TOKEN_INVALID_CODE));
        }
        Ok(Self {
            metrics_port,
            token: ConnectorToken(Zeroizing::new(token.to_owned())),
        })
    }

    pub(super) fn arguments(&self, protocol: Protocol) -> Vec<OsString> {
        cloudflared_arguments(self.metrics_port, protocol)
    }

    /// Exactly the variables the plan adds to the child's environment.
    pub(super) fn environment(&self) -> [(&'static str, &str); 1] {
        [(TOKEN_ENVIRONMENT_VARIABLE, self.token.0.as_str())]
    }

    /// The command for one launch, in its own process group so a drain
    /// signals the whole connector. It is not spawned here.
    pub(super) fn command(&self, program: &Path, protocol: Protocol) -> Command {
        let mut command = Command::new(program);
        command
            .args(self.arguments(protocol))
            .envs(self.environment())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .process_group(0);
        command
    }
}

/// SIGTERM the connector's process group, wait up to [`DRAIN_GRACE`], then
/// SIGKILL and reap.
pub(super) fn drain_connector(child: &mut Child) -> Result<(), AccessError> {
    terminate_child_within(child, DRAIN_GRACE)
}

/// One connector log line, typed. A connection id (a UUID) and a location are
/// copied; no other text from a line is retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ConnectorEvent {
    MetricsListening(u16),
    Registering {
        conn_index: u8,
        protocol: Protocol,
    },
    Registered {
        conn_index: u8,
        connection_id: String,
        location: String,
        protocol: Protocol,
    },
    Unregistered {
        conn_index: u8,
    },
    Retrying,
    /// Fatal before any dial.
    MetricsListenerFailed,
    Exited,
    Benign(&'static str),
    Unclassified,
}

const LOG_LEVELS: [&str; 5] = ["DBG", "INF", "WRN", "ERR", "FTL"];

/// Recorded under PRoot on 2026-08-06; none stopped the connector registering.
const BENIGN_MESSAGES: [(&str, &str); 6] = [
    (
        "Failed to determine the IPv4 for this machine",
        "ipv4_undetermined",
    ),
    (
        "open /proc/sys/net/ipv4/ping_group_range: permission denied",
        "icmp_ping_group_denied",
    ),
    (
        "failed to create ICMPv4 proxy, only ICMPv6 proxy is created",
        "icmpv4_proxy_unavailable",
    ),
    (
        "Failed to initialize DNS local resolver",
        "dns_local_resolver_unavailable",
    ),
    ("QUIC MTU updated", "quic_mtu_updated"),
    ("Connection terminated", "connection_terminated"),
];

pub(super) fn classify(line: &str) -> ConnectorEvent {
    let message = log_message(line);
    if let Some(address) = message.strip_prefix("Starting metrics server on ") {
        return metrics_listening(address).unwrap_or(ConnectorEvent::Unclassified);
    }
    if let Some(fields) = message.strip_prefix("Registering tunnel connection ") {
        return registering(fields).unwrap_or(ConnectorEvent::Unclassified);
    }
    if let Some(fields) = message.strip_prefix("Registered tunnel connection ") {
        return registered(fields).unwrap_or(ConnectorEvent::Unclassified);
    }
    if let Some(fields) = message.strip_prefix("Unregistered tunnel connection ") {
        return field(fields, "connIndex")
            .and_then(|index| index.parse().ok())
            .map(|conn_index| ConnectorEvent::Unregistered { conn_index })
            .unwrap_or(ConnectorEvent::Unclassified);
    }
    if message.starts_with("Retrying connection in ") {
        return ConnectorEvent::Retrying;
    }
    // Both the `ERR` line and cloudflared's unprefixed top-level fatal.
    if message.starts_with("Error opening metrics server listener") {
        return ConnectorEvent::MetricsListenerFailed;
    }
    if message.starts_with("no more connections active and exiting") {
        return ConnectorEvent::Exited;
    }
    // The rootfs's LAN resolver refusing; cloudflared falls back.
    if message.starts_with("dial udp ") && message.contains(":53: ") {
        return ConnectorEvent::Benign("lan_dns_unreachable");
    }
    BENIGN_MESSAGES
        .iter()
        .find(|(prefix, _)| message.starts_with(prefix))
        .map(|(_, label)| ConnectorEvent::Benign(label))
        .unwrap_or(ConnectorEvent::Unclassified)
}

/// The message after an optional RFC 3339 timestamp and level.
fn log_message(line: &str) -> &str {
    let mut rest = line.trim();
    if let Some((first, tail)) = rest.split_once(' ') {
        if is_timestamp(first) {
            rest = tail.trim_start();
        }
    }
    if let Some((first, tail)) = rest.split_once(' ') {
        if LOG_LEVELS.contains(&first) {
            rest = tail.trim_start();
        }
    }
    rest
}

fn is_timestamp(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes.len() >= 20
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[10] == b'T'
}

fn field<'a>(fields: &'a str, key: &str) -> Option<&'a str> {
    fields
        .split_whitespace()
        .filter_map(|pair| pair.split_once('='))
        .find(|(name, _)| *name == key)
        .map(|(_, value)| value)
}

fn metrics_listening(address: &str) -> Option<ConnectorEvent> {
    let address: SocketAddr = address.trim_end().strip_suffix("/metrics")?.parse().ok()?;
    if address.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) || address.port() == 0 {
        return None;
    }
    Some(ConnectorEvent::MetricsListening(address.port()))
}

fn registering(fields: &str) -> Option<ConnectorEvent> {
    Some(ConnectorEvent::Registering {
        conn_index: field(fields, "connIndex")?.parse().ok()?,
        protocol: Protocol::parse(field(fields, "protocol")?)?,
    })
}

fn registered(fields: &str) -> Option<ConnectorEvent> {
    let connection_id = field(fields, "connection").filter(|id| is_uuid(id))?;
    let location = field(fields, "location").filter(|location| {
        !location.is_empty()
            && location.len() <= MAX_LOCATION_BYTES
            && location.bytes().all(|byte| byte.is_ascii_alphanumeric())
    })?;
    Some(ConnectorEvent::Registered {
        conn_index: field(fields, "connIndex")?.parse().ok()?,
        connection_id: connection_id.to_owned(),
        location: location.to_owned(),
        protocol: Protocol::parse(field(fields, "protocol")?)?,
    })
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ConnectorState {
    /// Launched on `protocol`; no connection registered yet.
    Starting { protocol: Protocol },
    /// At least one connection registered since launch. `connections` is
    /// what is registered now; `orphaned_since` is when it last became empty.
    Registered {
        protocol: Protocol,
        connection_id: String,
        location: String,
        connections: BTreeSet<u8>,
        orphaned_since: Option<Instant>,
    },
    /// `stop()` was requested; waiting for the connector to exit.
    Draining,
    /// The connector died and was reported; the next launch, on `protocol`,
    /// is due at `retry_at`.
    Down {
        retry_at: Instant,
        protocol: Protocol,
    },
    /// Never launched again. `code` is `None` after a requested stop.
    Terminal { code: Option<&'static str> },
}

/// What the supervisor must do after a transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Directive {
    None,
    /// Report `code`; the child needs nothing.
    Report(&'static str),
    /// Report `code` and stop the child, which is alive but holds no
    /// connection.
    ReportAndStop(&'static str),
    /// [`drain_connector`] the child, then report its exit.
    Drain,
    /// Launch the connector again on `protocol`.
    Respawn(Protocol),
}

/// The connector's supervision, after the shape of the managed Dropbear
/// sidecar (`managed.rs`): [`MAX_SIDECAR_RESPAWNS`] respawns on QUIC with the
/// same backoff, then one last respawn on HTTP/2. It never sleeps; the
/// supervisor feeds it log events, child exits and clock ticks.
#[derive(Debug)]
pub(super) struct ConnectorSupervision {
    state: ConnectorState,
    respawns_used: u32,
    respawn_delay: fn(u32) -> Duration,
}

impl ConnectorSupervision {
    pub(super) fn new() -> Self {
        Self {
            state: ConnectorState::Starting {
                protocol: Protocol::Quic,
            },
            respawns_used: 0,
            respawn_delay: reconnect_delay,
        }
    }

    pub(super) fn state(&self) -> &ConnectorState {
        &self.state
    }

    pub(super) fn respawns_used(&self) -> u32 {
        self.respawns_used
    }

    pub(super) fn observe(&mut self, event: &ConnectorEvent, now: Instant) -> Directive {
        match self.state {
            ConnectorState::Terminal { .. } | ConnectorState::Down { .. } => Directive::None,
            ConnectorState::Draining => {
                if *event == ConnectorEvent::Exited {
                    self.state = ConnectorState::Terminal { code: None };
                }
                Directive::None
            }
            ConnectorState::Starting { .. } | ConnectorState::Registered { .. } => match event {
                ConnectorEvent::MetricsListenerFailed => {
                    self.state = ConnectorState::Terminal {
                        code: Some(METRICS_LISTENER_FAILED_CODE),
                    };
                    Directive::Report(METRICS_LISTENER_FAILED_CODE)
                }
                ConnectorEvent::Exited => self.child_exited(now),
                ConnectorEvent::Registered {
                    conn_index,
                    connection_id,
                    location,
                    protocol,
                } => self.registered(*conn_index, connection_id, location, *protocol),
                ConnectorEvent::Unregistered { conn_index } => {
                    if let ConnectorState::Registered {
                        connections,
                        orphaned_since,
                        ..
                    } = &mut self.state
                    {
                        if connections.remove(conn_index) && connections.is_empty() {
                            *orphaned_since = Some(now);
                        }
                    }
                    Directive::None
                }
                _ => Directive::None,
            },
        }
    }

    fn registered(
        &mut self,
        conn_index: u8,
        connection_id: &str,
        location: &str,
        protocol: Protocol,
    ) -> Directive {
        match &mut self.state {
            ConnectorState::Registered {
                connections,
                orphaned_since,
                ..
            } => {
                let was_orphaned = connections.is_empty();
                connections.insert(conn_index);
                *orphaned_since = None;
                if was_orphaned {
                    Directive::Report(REGISTERED_CODE)
                } else {
                    Directive::None
                }
            }
            _ => {
                self.state = ConnectorState::Registered {
                    protocol,
                    connection_id: connection_id.to_owned(),
                    location: location.to_owned(),
                    connections: BTreeSet::from([conn_index]),
                    orphaned_since: None,
                };
                Directive::Report(REGISTERED_CODE)
            }
        }
    }

    /// The child process exited (observed by wait or by its exit line).
    pub(super) fn child_exited(&mut self, now: Instant) -> Directive {
        match self.state {
            ConnectorState::Starting { .. } | ConnectorState::Registered { .. } => {
                Directive::Report(self.plan_respawn(now, EXITED_CODE))
            }
            ConnectorState::Draining => {
                self.state = ConnectorState::Terminal { code: None };
                Directive::None
            }
            ConnectorState::Down { .. } | ConnectorState::Terminal { .. } => Directive::None,
        }
    }

    /// Advance timers: the re-registration window and a due respawn.
    pub(super) fn tick(&mut self, now: Instant) -> Directive {
        match self.state {
            ConnectorState::Registered {
                orphaned_since: Some(since),
                ..
            } if now.saturating_duration_since(since) >= REREGISTRATION_WINDOW => {
                Directive::ReportAndStop(self.plan_respawn(now, UNREGISTERED_CODE))
            }
            ConnectorState::Down { retry_at, protocol } if now >= retry_at => {
                self.respawns_used += 1;
                self.state = ConnectorState::Starting { protocol };
                Directive::Respawn(protocol)
            }
            _ => Directive::None,
        }
    }

    pub(super) fn stop(&mut self) -> Directive {
        match self.state {
            ConnectorState::Starting { .. } | ConnectorState::Registered { .. } => {
                self.state = ConnectorState::Draining;
                Directive::Drain
            }
            ConnectorState::Down { .. } => {
                self.state = ConnectorState::Terminal { code: None };
                Directive::None
            }
            ConnectorState::Draining | ConnectorState::Terminal { .. } => Directive::None,
        }
    }

    /// Down on QUIC while the budget lasts, then once on HTTP/2, then
    /// Terminal. Returns the code to report.
    fn plan_respawn(&mut self, now: Instant, code: &'static str) -> &'static str {
        let protocol = match self.respawns_used.cmp(&MAX_SIDECAR_RESPAWNS) {
            Ordering::Less => Protocol::Quic,
            Ordering::Equal => Protocol::Http2,
            Ordering::Greater => {
                self.state = ConnectorState::Terminal {
                    code: Some(RESPAWN_BUDGET_SPENT_CODE),
                };
                return RESPAWN_BUDGET_SPENT_CODE;
            }
        };
        self.state = ConnectorState::Down {
            retry_at: now + (self.respawn_delay)(self.respawns_used),
            protocol,
        };
        code
    }
}

/// The managed sidecar's backoff (`managed::reconnect_delay`, private to that
/// module, which this packet leaves unchanged): 250 ms doubling to 8 s, plus
/// 0–250 ms jitter.
fn reconnect_delay(attempt: u32) -> Duration {
    let exponent = attempt.min(5);
    let base_ms = 250_u64.saturating_mul(1_u64 << exponent).min(8_000);
    let mut jitter = [0_u8; 2];
    let jitter_ms = if getrandom::fill(&mut jitter).is_ok() {
        u64::from(u16::from_le_bytes(jitter)) % 251
    } else {
        0
    };
    Duration::from_millis(base_ms.saturating_add(jitter_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../tests/fixtures/cloudflared-2026.7.3-r12.log");
    const TOKEN: &str = "eyJhIjoiMDEyMzQ1Njc4OWFiY2RlZiIsInQiOiJ0dW5uZWwiLCJzIjoic2VjcmV0In0=";

    fn port(value: u16) -> NonZeroU16 {
        NonZeroU16::new(value).unwrap()
    }

    fn fixture_lines() -> Vec<&'static str> {
        FIXTURE
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
            .collect()
    }

    fn fixture_line(prefix: &str) -> &'static str {
        fixture_lines()
            .into_iter()
            .find(|line| line.contains(prefix))
            .unwrap()
    }

    fn feed(
        supervision: &mut ConnectorSupervision,
        lines: &[&str],
        now: Instant,
    ) -> Vec<Directive> {
        lines
            .iter()
            .map(|line| supervision.observe(&classify(line), now))
            .collect()
    }

    fn registered_supervision(now: Instant) -> ConnectorSupervision {
        let mut supervision = ConnectorSupervision {
            respawn_delay: |attempt| Duration::from_secs(u64::from(attempt) + 1),
            ..ConnectorSupervision::new()
        };
        supervision.observe(&classify(fixture_line("Registered tunnel")), now);
        assert!(matches!(
            supervision.state(),
            ConnectorState::Registered { .. }
        ));
        supervision
    }

    #[test]
    fn cloudflared_arguments_carry_the_loopback_metrics_listener_and_no_token() {
        let quic = cloudflared_arguments(port(18096), Protocol::Quic);
        assert_eq!(
            quic,
            [
                "tunnel",
                "--no-autoupdate",
                "--metrics",
                "127.0.0.1:18096",
                "--protocol",
                "quic",
                "run",
            ]
            .map(OsString::from)
        );
        let http2 = cloudflared_arguments(port(18096), Protocol::Http2);
        assert_eq!(http2[5], OsString::from("http2"));
        for argument in quic.iter().chain(&http2) {
            assert!(!argument.to_string_lossy().contains("--token"));
        }
    }

    #[test]
    fn the_launch_plan_puts_the_token_only_in_the_environment() {
        let plan = LaunchPlan::new("127.0.0.1:18096".parse().unwrap(), TOKEN).unwrap();
        assert_eq!(plan.environment(), [("TUNNEL_TOKEN", TOKEN)]);
        assert_eq!(
            plan.arguments(Protocol::Quic),
            cloudflared_arguments(port(18096), Protocol::Quic)
        );
        for argument in plan.arguments(Protocol::Http2) {
            assert!(!argument.to_string_lossy().contains(TOKEN));
        }
        let debug = format!("{plan:?}");
        assert!(!debug.contains(TOKEN), "{debug}");
        assert!(debug.contains("<redacted>"));

        let command = plan.command(Path::new("/opt/liskov/cloudflared"), Protocol::Quic);
        assert_eq!(command.get_program(), "/opt/liskov/cloudflared");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            plan.arguments(Protocol::Quic)
        );
        assert_eq!(
            command.get_envs().collect::<Vec<_>>(),
            [(
                std::ffi::OsStr::new("TUNNEL_TOKEN"),
                Some(std::ffi::OsStr::new(TOKEN))
            )]
        );
    }

    #[test]
    fn the_launch_plan_refuses_a_non_loopback_or_zero_metrics_listener_and_a_bad_token() {
        for address in [
            "0.0.0.0:18096",
            "127.0.0.2:18096",
            "[::1]:18096",
            "127.0.0.1:0",
        ] {
            assert_eq!(
                LaunchPlan::new(address.parse().unwrap(), TOKEN)
                    .unwrap_err()
                    .code,
                METRICS_ADDRESS_REFUSED_CODE,
                "{address}"
            );
        }
        let oversized = "a".repeat(MAX_TOKEN_BYTES + 1);
        for token in [
            "",
            "two words",
            "nul\0byte",
            "tab\tbyte",
            "é",
            oversized.as_str(),
        ] {
            assert_eq!(
                LaunchPlan::new("127.0.0.1:18096".parse().unwrap(), token)
                    .unwrap_err()
                    .code,
                TOKEN_INVALID_CODE
            );
        }
    }

    #[test]
    fn every_recorded_line_classifies_to_its_event() {
        let registered = ConnectorEvent::Registered {
            conn_index: 0,
            connection_id: "95693ab4-8163-476e-9cca-041afdc7ec34".to_owned(),
            location: "lhr09".to_owned(),
            protocol: Protocol::Quic,
        };
        let expected = [
            ConnectorEvent::Benign("lan_dns_unreachable"),
            ConnectorEvent::Benign("ipv4_undetermined"),
            ConnectorEvent::Benign("icmp_ping_group_denied"),
            ConnectorEvent::Benign("icmpv4_proxy_unavailable"),
            ConnectorEvent::Benign("dns_local_resolver_unavailable"),
            ConnectorEvent::MetricsListening(18096),
            ConnectorEvent::Registering {
                conn_index: 0,
                protocol: Protocol::Quic,
            },
            registered,
            ConnectorEvent::Benign("quic_mtu_updated"),
            ConnectorEvent::MetricsListenerFailed,
            ConnectorEvent::MetricsListenerFailed,
            ConnectorEvent::Benign("connection_terminated"),
            ConnectorEvent::Exited,
            ConnectorEvent::Unregistered { conn_index: 0 },
            ConnectorEvent::Retrying,
        ];
        let lines = fixture_lines();
        assert_eq!(lines.len(), expected.len());
        for (line, expected) in lines.iter().zip(&expected) {
            let event = classify(line);
            assert_ne!(event, ConnectorEvent::Unclassified, "{line}");
            assert_eq!(&event, expected, "{line}");
        }
    }

    #[test]
    fn classification_tolerates_timestamps_and_field_order_and_refuses_malformed_fields() {
        assert_eq!(
            classify(
                "2026-08-06T12:46:10Z INF Registered tunnel connection connIndex=1 \
                 connection=95693AB4-8163-476E-9CCA-041AFDC7EC34 event=0 ip=198.41.192.57 \
                 location=lhr09 protocol=http2"
            ),
            ConnectorEvent::Registered {
                conn_index: 1,
                connection_id: "95693AB4-8163-476E-9CCA-041AFDC7EC34".to_owned(),
                location: "lhr09".to_owned(),
                protocol: Protocol::Http2,
            }
        );
        assert_eq!(
            classify("2026-08-06T12:46:11Z INF Retrying connection in up to 2s connIndex=0"),
            ConnectorEvent::Retrying
        );
        for line in [
            "INF Starting metrics server on 0.0.0.0:18096/metrics",
            "INF Starting metrics server on 127.0.0.1:0/metrics",
            "INF Registered tunnel connection connection=not-a-uuid connIndex=0 location=lhr09 protocol=quic",
            "INF Registered tunnel connection connection=95693ab4-8163-476e-9cca-041afdc7ec34 connIndex=0 location=lhr/09 protocol=quic",
            "INF Registered tunnel connection connection=95693ab4-8163-476e-9cca-041afdc7ec34 connIndex=0 location=lhr09 protocol=websocket",
            "DBG Registering tunnel connection connIndex=x protocol=quic",
            "INF Unregistered tunnel connection connIndex=300",
            "INF Tunnel connection curve preferences: [X25519MLKEM768]",
        ] {
            assert_eq!(classify(line), ConnectorEvent::Unclassified, "{line}");
        }
    }

    #[test]
    fn the_recorded_success_sequence_reaches_registered_on_quic_at_lhr09() {
        let lines = fixture_lines();
        let end = lines
            .iter()
            .position(|line| line.contains("QUIC MTU updated"))
            .unwrap();
        let mut supervision = ConnectorSupervision::new();
        let directives = feed(&mut supervision, &lines[..=end], Instant::now());
        assert_eq!(
            directives
                .into_iter()
                .filter(|directive| *directive != Directive::None)
                .collect::<Vec<_>>(),
            [Directive::Report(REGISTERED_CODE)]
        );
        let ConnectorState::Registered {
            protocol,
            connection_id,
            location,
            connections,
            orphaned_since,
        } = supervision.state()
        else {
            panic!("{:?}", supervision.state());
        };
        assert_eq!(*protocol, Protocol::Quic);
        assert_eq!(location, "lhr09");
        assert_eq!(connection_id, "95693ab4-8163-476e-9cca-041afdc7ec34");
        assert_eq!(*connections, BTreeSet::from([0]));
        assert_eq!(*orphaned_since, None);
        assert_eq!(supervision.respawns_used(), 0);
    }

    #[test]
    fn the_recorded_metrics_failure_is_terminal_at_once_without_a_respawn() {
        let now = Instant::now();
        let mut supervision = ConnectorSupervision::new();
        let directives = feed(
            &mut supervision,
            &[
                fixture_line("dial udp"),
                fixture_line("ERR Error opening metrics"),
                fixture_line("Error opening metrics server listener: failed"),
            ],
            now,
        );
        assert_eq!(
            directives,
            [
                Directive::None,
                Directive::Report(METRICS_LISTENER_FAILED_CODE),
                Directive::None,
            ]
        );
        assert_eq!(supervision.child_exited(now), Directive::None);
        assert_eq!(
            supervision.tick(now + Duration::from_secs(60)),
            Directive::None
        );
        assert_eq!(
            *supervision.state(),
            ConnectorState::Terminal {
                code: Some(METRICS_LISTENER_FAILED_CODE)
            }
        );
        assert_eq!(supervision.respawns_used(), 0);
    }

    #[test]
    fn an_exit_after_registered_goes_down_with_the_sidecar_backoff() {
        let now = Instant::now();
        let mut supervision = ConnectorSupervision::new();
        supervision.observe(&classify(fixture_line("Registered tunnel")), now);
        assert_eq!(
            supervision.observe(&classify(fixture_line("no more connections")), now),
            Directive::Report(EXITED_CODE)
        );
        let ConnectorState::Down { retry_at, protocol } = *supervision.state() else {
            panic!("{:?}", supervision.state());
        };
        assert_eq!(protocol, Protocol::Quic);
        let delay = retry_at - now;
        assert!(
            (Duration::from_millis(250)..=Duration::from_millis(500)).contains(&delay),
            "{delay:?}"
        );
        // The child's own exit, observed after its exit line, is not a second death.
        assert_eq!(supervision.child_exited(now), Directive::None);
        assert_eq!(
            supervision.tick(retry_at - Duration::from_millis(1)),
            Directive::None
        );
        assert_eq!(
            supervision.tick(retry_at),
            Directive::Respawn(Protocol::Quic)
        );
        assert_eq!(supervision.respawns_used(), 1);
    }

    #[test]
    fn three_exits_spend_the_quic_budget_then_one_respawn_runs_on_http2() {
        let mut now = Instant::now();
        let mut supervision = registered_supervision(now);
        let mut planned = Vec::new();
        for attempt in 0..=MAX_SIDECAR_RESPAWNS {
            assert_eq!(
                supervision.child_exited(now),
                Directive::Report(EXITED_CODE)
            );
            let ConnectorState::Down { retry_at, protocol } = *supervision.state() else {
                panic!("{:?}", supervision.state());
            };
            assert_eq!(retry_at, now + Duration::from_secs(u64::from(attempt) + 1));
            now = retry_at;
            assert_eq!(supervision.tick(now), Directive::Respawn(protocol));
            assert_eq!(*supervision.state(), ConnectorState::Starting { protocol });
            planned.push(protocol);
        }
        assert_eq!(
            planned,
            [
                Protocol::Quic,
                Protocol::Quic,
                Protocol::Quic,
                Protocol::Http2
            ]
        );
        assert_eq!(supervision.respawns_used(), MAX_SIDECAR_RESPAWNS + 1);
        assert_eq!(
            supervision.child_exited(now),
            Directive::Report(RESPAWN_BUDGET_SPENT_CODE)
        );
        assert_eq!(
            *supervision.state(),
            ConnectorState::Terminal {
                code: Some(RESPAWN_BUDGET_SPENT_CODE)
            }
        );
        assert_eq!(
            supervision.tick(now + Duration::from_secs(60)),
            Directive::None
        );
    }

    #[test]
    fn every_connection_unregistered_for_the_window_restarts_the_live_child() {
        let now = Instant::now();
        let unregistered = classify(fixture_line("Unregistered"));
        let retrying = classify(fixture_line("Retrying"));

        let mut supervision = registered_supervision(now);
        assert_eq!(supervision.observe(&unregistered, now), Directive::None);
        assert_eq!(supervision.observe(&retrying, now), Directive::None);
        assert_eq!(
            supervision.tick(now + REREGISTRATION_WINDOW - Duration::from_millis(1)),
            Directive::None
        );
        let deadline = now + REREGISTRATION_WINDOW;
        assert_eq!(
            supervision.tick(deadline),
            Directive::ReportAndStop(UNREGISTERED_CODE)
        );
        assert_eq!(
            *supervision.state(),
            ConnectorState::Down {
                retry_at: deadline + Duration::from_secs(1),
                protocol: Protocol::Quic
            }
        );
        // Stopping the orphaned child is not a second death.
        assert_eq!(supervision.child_exited(deadline), Directive::None);

        // Re-registration inside the window keeps the connector.
        let mut supervision = registered_supervision(now);
        supervision.observe(&unregistered, now);
        assert_eq!(
            supervision.observe(
                &classify(fixture_line("Registered tunnel")),
                now + Duration::from_secs(5)
            ),
            Directive::Report(REGISTERED_CODE)
        );
        assert_eq!(
            supervision.tick(now + REREGISTRATION_WINDOW * 2),
            Directive::None
        );
        assert!(matches!(
            supervision.state(),
            ConnectorState::Registered {
                orphaned_since: None,
                ..
            }
        ));
    }

    #[test]
    fn stop_drains_a_registered_connector_and_reaps_it_within_the_grace() {
        let _lock = crate::supervisor::tests::PROCESS_TEST_LOCK.lock().unwrap();
        let mut child = super::super::spawn_test_sidecar("/bin/sleep", &["30"]).unwrap();
        let mut supervision = registered_supervision(Instant::now());

        assert_eq!(supervision.stop(), Directive::Drain);
        assert_eq!(*supervision.state(), ConnectorState::Draining);
        let started = Instant::now();
        drain_connector(&mut child).unwrap();
        assert!(started.elapsed() < DRAIN_GRACE, "{:?}", started.elapsed());
        assert!(child.try_wait().unwrap().is_some());
        assert_eq!(supervision.child_exited(Instant::now()), Directive::None);
        assert_eq!(
            *supervision.state(),
            ConnectorState::Terminal { code: None }
        );
        assert_eq!(supervision.stop(), Directive::None);

        // The exit line during a drain is the same ending.
        let mut supervision = registered_supervision(Instant::now());
        supervision.stop();
        supervision.observe(
            &classify(fixture_line("Connection terminated")),
            Instant::now(),
        );
        assert_eq!(*supervision.state(), ConnectorState::Draining);
        supervision.observe(
            &classify(fixture_line("no more connections")),
            Instant::now(),
        );
        assert_eq!(
            *supervision.state(),
            ConnectorState::Terminal { code: None }
        );

        // A connector waiting to respawn has nothing to drain.
        let mut supervision = registered_supervision(Instant::now());
        supervision.child_exited(Instant::now());
        assert_eq!(supervision.stop(), Directive::None);
        assert_eq!(
            *supervision.state(),
            ConnectorState::Terminal { code: None }
        );
    }

    #[test]
    fn the_reconnect_delay_matches_the_sidecar_backoff_bounds() {
        for (attempt, base_ms) in [
            (0, 250),
            (1, 500),
            (2, 1_000),
            (3, 2_000),
            (5, 8_000),
            (9, 8_000),
        ] {
            let delay = reconnect_delay(attempt);
            assert!(
                (Duration::from_millis(base_ms)..=Duration::from_millis(base_ms + 250))
                    .contains(&delay),
                "{attempt}: {delay:?}"
            );
        }
    }
}
