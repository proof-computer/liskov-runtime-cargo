//! Evidence probe for the Acurast Tunnel bridge surface and the constrained
//! runtime's network syscalls.
//!
//! Feature-gated (`--features tunnel-probe`) and excluded from the release
//! artifact: this binary exists to gather provider evidence from a live
//! processor, never to run in a customer deployment.
//!
//! Every line on stdout is NDJSON. Results are redacted before printing.

use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr as UnixSocketAddr, UnixListener};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use liskov_runtime_cargo::tunnel_probe::{
    self, CONTEXT_METHODS, METHOD_CERT_PEM, METHOD_START, METHOD_STATUS, METHOD_STOP,
    MUTATING_METHODS, ProbeClient, READ_ONLY_METHODS, READ_ONLY_NAME_CANDIDATES, START_TIMEOUT,
    TUNNEL_PROBE_DOMAIN,
};
use serde_json::{Value, json};

const BRIDGE_SOCKET_ENV: &str = "BRIDGE_SOCKET";

#[derive(Parser, Debug)]
#[command(
    name = "liskov-tunnel-probe",
    about = "Acurast Tunnel and constrained-runtime evidence probe (not for production use)"
)]
struct Cli {
    /// Abstract bridge socket name. Defaults to $BRIDGE_SOCKET.
    #[arg(long, global = true)]
    socket_name: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Walk the read-only method matrix and collect processor context.
    Discover,
    /// Report the current tunnel status.
    Status,
    /// Report the stored certificate as a digest summary only.
    Cert,
    /// Start a tunnel from a spec file. Mutates processor state.
    Start {
        #[arg(long)]
        params_file: PathBuf,
        #[arg(long)]
        yes_mutate: bool,
    },
    /// Stop the active tunnel. Mutates processor state.
    Stop {
        #[arg(long)]
        yes_mutate: bool,
    },
    /// Issue an arbitrary bridge method (escape hatch for shape iteration).
    Call {
        #[arg(long)]
        method: String,
        /// JSON file holding the full `params` value. Defaults to `[]`.
        #[arg(long)]
        params_file: Option<PathBuf>,
        #[arg(long)]
        yes_mutate: bool,
    },
    /// Probe the network syscalls the constrained runtime may deny.
    EnvProbe {
        /// TCP reachability target.
        #[arg(long, default_value = "1.1.1.1:443")]
        tcp_target: String,
        /// UDP target; port 7844 is the QUIC port cloudflared needs.
        #[arg(long, default_value = "1.1.1.1:7844")]
        udp_target: String,
    },
    /// Serve a loopback HTTP endpoint for a tunnel to forward to.
    Serve {
        #[arg(long, default_value = "127.0.0.1:18080")]
        listen: String,
        #[arg(long)]
        body_tag: String,
        #[arg(long, default_value_t = 1800)]
        duration_secs: u64,
        #[arg(long, default_value_t = 256)]
        max_requests: usize,
    },
    /// Test-only scripted bridge server (used by the offline self-test).
    FakeBridge {
        #[arg(long)]
        socket: String,
        /// JSON file mapping method name -> reply body (`result` or `error`).
        #[arg(long)]
        replies_file: PathBuf,
        #[arg(long, default_value_t = 16)]
        max_requests: usize,
    },
}

fn emit(value: &Value) {
    println!("{value}");
    let _ = std::io::stdout().flush();
}

fn fail(reason: &str, detail: &str) -> ! {
    emit(&json!({"event": "fatal", "reason": reason, "detail": detail}));
    std::process::exit(2);
}

fn resolve_socket_name(cli: &Cli) -> String {
    if let Some(name) = &cli.socket_name {
        return name.clone();
    }
    match std::env::var(BRIDGE_SOCKET_ENV) {
        // The value is never printed: only whether it was present.
        Ok(value) if !value.is_empty() => value,
        _ => fail(
            "bridge_socket_missing",
            "pass --socket-name or set BRIDGE_SOCKET",
        ),
    }
}

fn client(cli: &Cli) -> ProbeClient {
    let name = resolve_socket_name(cli);
    match ProbeClient::new(name) {
        Ok(client) => client,
        Err(error) => fail("bridge_socket_invalid", error.failure_code()),
    }
}

fn read_json(path: &PathBuf) -> Value {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => fail("params_file_unreadable", &error.to_string()),
    };
    match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(error) => fail("params_file_invalid_json", &error.to_string()),
    }
}

fn call_and_emit(client: &ProbeClient, method: &str, params: Value, timeout: Duration) -> Value {
    let reply = client.call_with_timeout(method, params.clone(), timeout);
    let observation = tunnel_probe::observe(method, &params, reply);
    let value = serde_json::to_value(&observation).unwrap_or(Value::Null);
    emit(&value);
    value
}

fn main() {
    let cli = Cli::parse();
    emit(&json!({
        "event": "start",
        "domain": TUNNEL_PROBE_DOMAIN,
        "bridgeSocket": if std::env::var(BRIDGE_SOCKET_ENV).is_ok_and(|v| !v.is_empty()) {
            "present"
        } else {
            "absent"
        },
    }));

    match &cli.command {
        Command::Discover => run_discover(&cli),
        Command::Status => {
            let client = client(&cli);
            let observation =
                call_and_emit(&client, METHOD_STATUS, json!([]), Duration::from_secs(5));
            emit(&summarize_status(&observation));
        }
        Command::Cert => {
            let client = client(&cli);
            call_and_emit(&client, METHOD_CERT_PEM, json!([]), Duration::from_secs(5));
        }
        Command::Start {
            params_file,
            yes_mutate,
        } => run_start(&cli, params_file, *yes_mutate),
        Command::Stop { yes_mutate } => {
            require_mutate(*yes_mutate, METHOD_STOP);
            let client = client(&cli);
            call_and_emit(&client, METHOD_STOP, json!([]), Duration::from_secs(30));
        }
        Command::Call {
            method,
            params_file,
            yes_mutate,
        } => {
            if !READ_ONLY_METHODS.contains(&method.as_str()) && !*yes_mutate {
                fail(
                    "mutation_not_authorized",
                    &format!("{method} is not on the read-only allowlist; pass --yes-mutate"),
                );
            }
            let params = params_file.as_ref().map_or_else(|| json!([]), read_json);
            let client = client(&cli);
            call_and_emit(&client, method, params, START_TIMEOUT);
        }
        Command::EnvProbe {
            tcp_target,
            udp_target,
        } => run_env_probe(tcp_target, udp_target),
        Command::Serve {
            listen,
            body_tag,
            duration_secs,
            max_requests,
        } => run_serve(listen, body_tag, *duration_secs, *max_requests),
        Command::FakeBridge {
            socket,
            replies_file,
            max_requests,
        } => run_fake_bridge(socket, replies_file, *max_requests),
    }

    emit(&json!({"event": "summary", "domain": TUNNEL_PROBE_DOMAIN}));
}

fn require_mutate(yes_mutate: bool, method: &str) {
    if !yes_mutate {
        fail(
            "mutation_not_authorized",
            &format!("{method} changes processor state; pass --yes-mutate"),
        );
    }
    debug_assert!(MUTATING_METHODS.contains(&method));
}

fn summarize_status(observation: &Value) -> Value {
    let ordinal = observation
        .get("result")
        .and_then(Value::as_i64)
        .or_else(|| {
            observation
                .get("result")
                .and_then(|result| result.get("status"))
                .and_then(Value::as_i64)
        });
    match ordinal {
        Some(ordinal) => json!({
            "event": "tunnelStatus",
            "ordinal": ordinal,
            "state": tunnel_probe::decode_tunnel_status(ordinal),
        }),
        None => json!({"event": "tunnelStatus", "state": "undecodable"}),
    }
}

fn run_discover(cli: &Cli) {
    let client = client(cli);
    for method in CONTEXT_METHODS {
        call_and_emit(&client, method, json!([]), Duration::from_secs(5));
    }
    // Read-only names only: the matrix must never start a tunnel as a side
    // effect of discovery.
    for method in READ_ONLY_NAME_CANDIDATES {
        assert!(
            !MUTATING_METHODS.contains(method),
            "discover matrix must stay read-only"
        );
        let observation = call_and_emit(&client, method, json!([]), Duration::from_secs(5));
        if method == &METHOD_STATUS {
            emit(&summarize_status(&observation));
        }
    }
}

fn run_start(cli: &Cli, params_file: &PathBuf, yes_mutate: bool) {
    require_mutate(yes_mutate, METHOD_START);
    let spec = read_json(params_file);
    // A spec is a bare object here; the wire wants it as params[0].
    let spec = match &spec {
        Value::Array(items) if items.len() == 1 => items[0].clone(),
        other => other.clone(),
    };
    if let Err(problems) = tunnel_probe::validate_spec(&spec) {
        emit(&json!({"event": "specInvalid", "problems": problems}));
        fail("spec_invalid", "see specInvalid event");
    }
    emit(&json!({"event": "specAccepted", "spec": tunnel_probe::summarize_spec(&spec)}));

    let client = client(cli);
    let observation = call_and_emit(&client, METHOD_START, json!([spec]), START_TIMEOUT);
    if let Some(result) = observation.get("result") {
        if let Some(info) = tunnel_probe::parse_tunnel_info(result) {
            emit(&json!({"event": "tunnelInfo", "info": info}));
        }
    }
}

// ---------------------------------------------------------------------------
// Environment probe
// ---------------------------------------------------------------------------

fn emit_check(check: &str, ok: bool, errno: Option<i32>, detail: Option<String>) {
    let mut value = json!({"event": "check", "check": check, "ok": ok});
    if let Some(errno) = errno {
        value["errno"] = json!(errno);
        value["errnoName"] = json!(errno_name(errno));
    }
    if let Some(detail) = detail {
        value["detail"] = json!(detail);
    }
    emit(&value);
}

fn errno_name(errno: i32) -> &'static str {
    match errno {
        libc::EPERM => "EPERM",
        libc::EACCES => "EACCES",
        libc::EAFNOSUPPORT => "EAFNOSUPPORT",
        libc::EPROTONOSUPPORT => "EPROTONOSUPPORT",
        libc::ENOENT => "ENOENT",
        libc::ETIMEDOUT => "ETIMEDOUT",
        libc::ECONNREFUSED => "ECONNREFUSED",
        libc::ENETUNREACH => "ENETUNREACH",
        libc::EHOSTUNREACH => "EHOSTUNREACH",
        libc::EINVAL => "EINVAL",
        _ => "OTHER",
    }
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn run_env_probe(tcp_target: &str, udp_target: &str) {
    // 1. Netlink socket: tailscaled needed a permission fallback for this.
    // SAFETY: plain socket(2) with constant arguments; the fd is closed below.
    let netlink = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
    if netlink < 0 {
        emit_check("netlink_socket", false, Some(last_errno()), None);
    } else {
        emit_check("netlink_socket", true, None, None);
        // SAFETY: `netlink` is a valid fd this function owns.
        unsafe { libc::close(netlink) };
    }

    // 2/3. SO_MARK and SO_BINDTODEVICE: denied under faked-root PRoot.
    // SAFETY: plain socket(2); fd closed after the setsockopt probes.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if sock < 0 {
        emit_check("tcp_socket_create", false, Some(last_errno()), None);
    } else {
        let mark: libc::c_int = 1;
        // SAFETY: `sock` is valid; `mark` outlives the call and its size matches.
        let rc = unsafe {
            libc::setsockopt(
                sock,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                std::ptr::from_ref(&mark).cast(),
                std::mem::size_of_val(&mark) as libc::socklen_t,
            )
        };
        emit_check("so_mark", rc == 0, (rc != 0).then(last_errno), None);

        let device = c"lo";
        // SAFETY: `sock` is valid; the device name is a NUL-terminated literal.
        let rc = unsafe {
            libc::setsockopt(
                sock,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                device.as_ptr().cast(),
                2,
            )
        };
        emit_check("so_bindtodevice", rc == 0, (rc != 0).then(last_errno), None);
        // SAFETY: `sock` is a valid fd this function owns.
        unsafe { libc::close(sock) };
    }

    // 4/5. /proc/net reads: magicsock endpoint discovery depends on these.
    for path in ["/proc/net/tcp", "/proc/net/udp"] {
        match std::fs::read_to_string(path) {
            Ok(text) => emit_check(
                &format!("read{}", path.replace('/', "_")),
                true,
                None,
                Some(format!("{} bytes", text.len())),
            ),
            Err(error) => emit_check(
                &format!("read{}", path.replace('/', "_")),
                false,
                error.raw_os_error(),
                None,
            ),
        }
    }

    // 6. Outbound TCP: proven reachable for liskov.proof.computer on 2026-08-05.
    probe_tcp(tcp_target);
    // 7. Outbound UDP on the QUIC port: the cloudflared unknown.
    probe_udp(udp_target);
}

fn resolve_one(target: &str) -> Option<SocketAddr> {
    match target.to_socket_addrs() {
        Ok(mut addrs) => addrs.next(),
        Err(error) => {
            emit_check(
                "dns_resolve",
                false,
                error.raw_os_error(),
                Some(target.to_string()),
            );
            None
        }
    }
}

fn probe_tcp(target: &str) {
    let Some(addr) = resolve_one(target) else {
        return;
    };
    emit_check(
        "dns_resolve",
        true,
        None,
        Some(format!("{target} -> {}", ip_family(addr))),
    );
    match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
        Ok(stream) => {
            let _ = stream.shutdown(Shutdown::Both);
            emit_check("tcp_connect", true, None, Some(target.to_string()));
        }
        Err(error) => emit_check(
            "tcp_connect",
            false,
            error.raw_os_error(),
            Some(target.to_string()),
        ),
    }
}

fn probe_udp(target: &str) {
    let Some(addr) = resolve_one(target) else {
        return;
    };
    let bind = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = match UdpSocket::bind(bind) {
        Ok(socket) => socket,
        Err(error) => {
            emit_check("udp_bind", false, error.raw_os_error(), None);
            return;
        }
    };
    emit_check("udp_bind", true, None, None);

    match socket.connect(addr) {
        Ok(()) => emit_check("udp_connect", true, None, Some(target.to_string())),
        Err(error) => {
            emit_check(
                "udp_connect",
                false,
                error.raw_os_error(),
                Some(target.to_string()),
            );
            return;
        }
    }
    // A send that returns without error only proves the local stack accepted
    // the datagram; it is not evidence the peer received it.
    match socket.send(b"liskov-tunnel-probe") {
        Ok(sent) => emit_check("udp_send", true, None, Some(format!("{sent} bytes"))),
        Err(error) => emit_check("udp_send", false, error.raw_os_error(), None),
    }
}

fn ip_family(addr: SocketAddr) -> &'static str {
    match addr.ip() {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
    }
}

// ---------------------------------------------------------------------------
// Loopback HTTP listener
// ---------------------------------------------------------------------------

fn run_serve(listen: &str, body_tag: &str, duration_secs: u64, max_requests: usize) {
    let addr: SocketAddr = match listen.parse() {
        Ok(addr) => addr,
        Err(error) => fail("listen_invalid", &error.to_string()),
    };
    // Customer workloads only listen on loopback; the probe holds itself to the
    // same rule so it can never become an unintended public service.
    if !addr.ip().is_loopback() {
        fail("listen_not_loopback", "serve only binds 127.0.0.1/::1");
    }
    let listener = match TcpListener::bind(addr) {
        Ok(listener) => listener,
        Err(error) => fail("listen_failed", &error.to_string()),
    };
    emit(&json!({"event": "listening", "addr": addr.to_string(), "bodyTag": body_tag}));

    let deadline = Instant::now() + Duration::from_secs(duration_secs);
    let mut served = 0usize;
    for stream in listener.incoming() {
        if Instant::now() >= deadline || served >= max_requests {
            break;
        }
        let Ok(mut stream) = stream else { continue };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let peer = stream
            .peer_addr()
            .map_or_else(|_| "unknown".to_string(), |peer| peer.to_string());

        let mut reader = BufReader::new(match stream.try_clone() {
            Ok(clone) => clone,
            Err(_) => continue,
        });
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() {
            continue;
        }
        let mut method = String::new();
        let mut path = String::new();
        let mut parts = request_line.split_whitespace();
        if let Some(value) = parts.next() {
            method = value.to_string();
        }
        if let Some(value) = parts.next() {
            path = value.to_string();
        }

        // Cloudflare and the Acurast relay both add headers that prove the
        // request arrived through the tunnel rather than from localhost.
        let mut host = String::new();
        let mut cf_ray = String::new();
        let mut forwarded_for = String::new();
        loop {
            let mut header = String::new();
            match reader.read_line(&mut header) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
            let trimmed = header.trim_end();
            if trimmed.is_empty() {
                break;
            }
            let lower = trimmed.to_ascii_lowercase();
            if let Some(value) = lower.strip_prefix("host:") {
                host = value.trim().to_string();
            } else if let Some(value) = lower.strip_prefix("cf-ray:") {
                cf_ray = value.trim().to_string();
            } else if let Some(value) = lower.strip_prefix("x-forwarded-for:") {
                forwarded_for = value.trim().to_string();
            }
        }

        let body = format!("liskov-tunnel-probe {body_tag} {path}\n");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
        let _ = stream.shutdown(Shutdown::Both);

        served += 1;
        emit(&json!({
            "event": "request",
            "method": method,
            "path": path,
            "host": host,
            "cfRay": cf_ray,
            "xForwardedFor": forwarded_for,
            "peer": peer,
            "served": served,
        }));
    }
    emit(&json!({"event": "served", "count": served}));
}

// ---------------------------------------------------------------------------
// Scripted bridge server (offline self-test only)
// ---------------------------------------------------------------------------

fn run_fake_bridge(socket_name: &str, replies_file: &PathBuf, max_requests: usize) {
    let replies = read_json(replies_file);
    let address = match UnixSocketAddr::from_abstract_name(socket_name.as_bytes()) {
        Ok(address) => address,
        Err(error) => fail("fake_bridge_address", &error.to_string()),
    };
    let listener = match UnixListener::bind_addr(&address) {
        Ok(listener) => listener,
        Err(error) => fail("fake_bridge_bind", &error.to_string()),
    };
    emit(&json!({"event": "fakeBridgeReady", "socket": socket_name}));

    let mut handled = 0usize;
    while handled < max_requests {
        let Ok((stream, _)) = listener.accept() else {
            break;
        };
        let mut reader = BufReader::new(match stream.try_clone() {
            Ok(clone) => clone,
            Err(_) => continue,
        });
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
            continue;
        }
        let Ok(request): Result<Value, _> = serde_json::from_str(line.trim_end()) else {
            continue;
        };
        let method = request["method"].as_str().unwrap_or_default().to_string();
        let id = request["id"].clone();
        let scripted = replies.get(&method).cloned().unwrap_or_else(|| {
            json!({"error": {"code": tunnel_probe::JSON_RPC_METHOD_NOT_FOUND, "message": "Method not found"}})
        });

        let mut response = json!({"jsonrpc": "2.0", "id": id});
        if let Some(error) = scripted.get("error") {
            response["error"] = error.clone();
        } else {
            response["result"] = scripted.get("result").cloned().unwrap_or(Value::Null);
        }
        let mut bytes = serde_json::to_vec(&response).unwrap_or_default();
        bytes.push(b'\n');
        let mut stream = stream;
        let _ = stream.write_all(&bytes);
        let _ = stream.flush();
        let _ = stream.shutdown(Shutdown::Both);

        handled += 1;
        emit(&json!({"event": "fakeBridgeServed", "method": method, "handled": handled}));
    }
    emit(&json!({"event": "fakeBridgeDone", "handled": handled}));
}
