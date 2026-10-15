//! Route-selected local gateway discovery and bounded router-control adapters.
//!
//! The grant reserver does not call this module. A caller has to ask. The
//! selected gateway and its interface live only in the return value: nothing
//! here is logged or stored. A UDP socket's local address is not a gateway,
//! and a connected subnet is not turned into one by adding one to the network
//! address.
//!
//! Permitted route sources are a bounded `/proc/net/route` read and, only when
//! that file is unavailable, a bounded IPv4 netlink dump. The dump keeps
//! unicast routes from the main table only, which is the table `/proc/net/route`
//! lists. Neither `getifaddrs` nor `AF_NETLINK` is required. When every
//! permitted source is unavailable the result is [`GatewayDiscovery::Unsupported`].

use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use super::TraversalRouterProtocol;

pub const ROUTE_TABLE_MAX_BYTES: usize = 16 * 1024;
pub const ROUTE_TABLE_MAX_RECORDS: usize = 128;
pub const CONTROL_MAX_BYTES: usize = 1100;
pub const CONTROL_LOCATION_MAX_BYTES: usize = 512;
pub const ROUTER_CONTROL_PORT: u16 = 5351;
/// One SOAP action, its HTTP framing, and the matching response. This is
/// larger than a PCP datagram and smaller than a device description.
pub const UPNP_SOAP_MAX_BYTES: usize = 4096;

const INTERFACE_NAME_MAX: usize = 15;
const RTF_GATEWAY: u32 = 0x0002;
/// `NLMSG_GOODSIZE` on a kernel with 16 KiB pages. A smaller buffer truncates
/// a dump datagram and splices the next one at a misaligned offset.
const NETLINK_RECV_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteRecord {
    pub destination: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Ipv4Addr,
    pub has_gateway: bool,
    pub interface_index: u32,
    pub interface_name: [u8; INTERFACE_NAME_MAX],
    pub interface_name_len: u8,
    pub metric: u32,
}

impl RouteRecord {
    pub fn new(
        destination: Ipv4Addr,
        prefix_len: u8,
        gateway: Ipv4Addr,
        has_gateway: bool,
        metric: u32,
    ) -> Self {
        Self {
            destination,
            prefix_len,
            gateway,
            has_gateway,
            interface_index: 0,
            interface_name: [0; INTERFACE_NAME_MAX],
            interface_name_len: 0,
            metric,
        }
    }

    fn interface_name(&self) -> &[u8] {
        &self.interface_name[..self.interface_name_len as usize]
    }
}

/// Gateway and interface chosen for this call. Drop it when the call ends.
/// `Debug` redacts the gateway: the address is not a log field.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SelectedGateway {
    gateway: Ipv4Addr,
    interface_index: u32,
    interface_name: [u8; INTERFACE_NAME_MAX],
    interface_name_len: u8,
}

impl std::fmt::Debug for SelectedGateway {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SelectedGateway")
            .field("gateway", &"<redacted>")
            .finish()
    }
}

impl SelectedGateway {
    pub fn gateway(self) -> Ipv4Addr {
        self.gateway
    }

    pub fn interface_index(self) -> u32 {
        self.interface_index
    }

    pub fn interface_name(&self) -> Option<&str> {
        let name = &self.interface_name[..self.interface_name_len as usize];
        if name.is_empty() {
            None
        } else {
            std::str::from_utf8(name).ok()
        }
    }

    fn from_record(record: &RouteRecord) -> Self {
        Self {
            gateway: record.gateway,
            interface_index: record.interface_index,
            interface_name: record.interface_name,
            interface_name_len: record.interface_name_len,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteReadError {
    Unavailable,
    Bounded,
    Cancelled,
    Malformed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayDiscovery {
    Selected(SelectedGateway),
    Unsupported,
    InvalidGateway,
    Cancelled,
    Bounded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouterProtocol {
    Pcp,
    NatPmp,
    UpnpIgd,
}

impl From<TraversalRouterProtocol> for RouterProtocol {
    fn from(protocol: TraversalRouterProtocol) -> Self {
        match protocol {
            TraversalRouterProtocol::Pcp => Self::Pcp,
            TraversalRouterProtocol::NatPmp => Self::NatPmp,
            TraversalRouterProtocol::UpnpIgd => Self::UpnpIgd,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlRefusal {
    Unsupported,
    WrongTarget,
    Oversize,
    Cancelled,
    Bounded,
}

/// One bounded exchange. The adapter chooses the destination; the transport
/// must send there and nowhere else.
pub trait ControlTransport {
    fn exchange(
        &mut self,
        destination: SocketAddr,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, ControlRefusal>;
}

pub(crate) fn discover_loaded(
    routes: &[RouteRecord],
    cancelled: &dyn Fn() -> bool,
) -> GatewayDiscovery {
    if cancelled() {
        return GatewayDiscovery::Cancelled;
    }
    if routes.len() > ROUTE_TABLE_MAX_RECORDS {
        return GatewayDiscovery::Bounded;
    }
    select_gateway(routes)
}

/// Read `proc_path` first. Netlink runs only when that read is unavailable or
/// malformed, and only through `netlink`. Neither source is assumed to exist.
pub(crate) fn discover_with_sources(
    proc_routes: Result<Vec<RouteRecord>, RouteReadError>,
    netlink: &mut dyn FnMut() -> Result<Vec<RouteRecord>, RouteReadError>,
    cancelled: &dyn Fn() -> bool,
) -> GatewayDiscovery {
    if cancelled() {
        return GatewayDiscovery::Cancelled;
    }
    let loaded = match proc_routes {
        Ok(routes) => Ok(routes),
        Err(RouteReadError::Bounded) => return GatewayDiscovery::Bounded,
        Err(RouteReadError::Cancelled) => return GatewayDiscovery::Cancelled,
        Err(RouteReadError::Unavailable | RouteReadError::Malformed) => {
            if cancelled() {
                return GatewayDiscovery::Cancelled;
            }
            netlink()
        }
    };
    match loaded {
        Ok(routes) => discover_loaded(&routes, cancelled),
        Err(RouteReadError::Unavailable | RouteReadError::Malformed) => {
            GatewayDiscovery::Unsupported
        }
        Err(RouteReadError::Bounded) => GatewayDiscovery::Bounded,
        Err(RouteReadError::Cancelled) => GatewayDiscovery::Cancelled,
    }
}

/// Host discovery. Not called by grant reservation or the released helper.
pub fn discover_local_gateway(cancelled: &dyn Fn() -> bool) -> GatewayDiscovery {
    discover_at_path(Path::new("/proc/net/route"), cancelled)
}

pub fn discover_at_path(proc_path: &Path, cancelled: &dyn Fn() -> bool) -> GatewayDiscovery {
    if cancelled() {
        return GatewayDiscovery::Cancelled;
    }
    let proc_routes = read_proc_net_route(proc_path, cancelled);
    let mut netlink = || read_netlink_routes(cancelled);
    discover_with_sources(proc_routes, &mut netlink, cancelled)
}

pub fn parse_proc_net_route(text: &str) -> Result<Vec<RouteRecord>, RouteReadError> {
    if text.len() > ROUTE_TABLE_MAX_BYTES {
        return Err(RouteReadError::Bounded);
    }
    let mut routes = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if index == 0 && line.starts_with("Iface") {
            continue;
        }
        if line.is_empty() {
            continue;
        }
        if routes.len() == ROUTE_TABLE_MAX_RECORDS {
            return Err(RouteReadError::Bounded);
        }
        routes.push(parse_proc_route_line(line)?);
    }
    Ok(routes)
}

pub fn read_proc_net_route(
    path: &Path,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<RouteRecord>, RouteReadError> {
    if cancelled() {
        return Err(RouteReadError::Cancelled);
    }
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return Err(RouteReadError::Unavailable),
    };
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if cancelled() {
            return Err(RouteReadError::Cancelled);
        }
        let read = file
            .read(&mut chunk)
            .map_err(|_| RouteReadError::Unavailable)?;
        if read == 0 {
            break;
        }
        if buffer.len().saturating_add(read) > ROUTE_TABLE_MAX_BYTES {
            return Err(RouteReadError::Bounded);
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let text = std::str::from_utf8(&buffer).map_err(|_| RouteReadError::Malformed)?;
    parse_proc_net_route(text)
}

fn parse_proc_route_line(line: &str) -> Result<RouteRecord, RouteReadError> {
    let mut fields = line.split_whitespace();
    let interface = fields.next().ok_or(RouteReadError::Malformed)?;
    let destination = parse_proc_address(fields.next().ok_or(RouteReadError::Malformed)?)?;
    let gateway = parse_proc_address(fields.next().ok_or(RouteReadError::Malformed)?)?;
    let flags = parse_proc_hex(fields.next().ok_or(RouteReadError::Malformed)?)?;
    let _refcnt = fields.next().ok_or(RouteReadError::Malformed)?;
    let _use = fields.next().ok_or(RouteReadError::Malformed)?;
    let metric = fields
        .next()
        .ok_or(RouteReadError::Malformed)?
        .parse::<u32>()
        .map_err(|_| RouteReadError::Malformed)?;
    let mask = parse_proc_address(fields.next().ok_or(RouteReadError::Malformed)?)?;
    let prefix_len = prefix_len(mask).ok_or(RouteReadError::Malformed)?;
    let mut record = RouteRecord::new(
        destination,
        prefix_len,
        gateway,
        flags & RTF_GATEWAY != 0,
        metric,
    );
    record.interface_name_len = interface_name_bytes(interface)?;
    record.interface_name[..record.interface_name_len as usize]
        .copy_from_slice(&interface.as_bytes()[..record.interface_name_len as usize]);
    Ok(record)
}

fn parse_proc_hex(text: &str) -> Result<u32, RouteReadError> {
    u32::from_str_radix(text, 16).map_err(|_| RouteReadError::Malformed)
}

/// `/proc/net/route` prints each address as the little-endian kernel word.
fn parse_proc_address(text: &str) -> Result<Ipv4Addr, RouteReadError> {
    if text.len() != 8 {
        return Err(RouteReadError::Malformed);
    }
    let word = parse_proc_hex(text)?;
    let raw = word.to_be_bytes();
    Ok(Ipv4Addr::new(raw[3], raw[2], raw[1], raw[0]))
}

fn prefix_len(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let ones = bits.leading_ones();
    let expected = if ones == 0 {
        0
    } else {
        u32::MAX << (32 - ones)
    };
    (bits == expected).then_some(ones as u8)
}

fn interface_name_bytes(name: &str) -> Result<u8, RouteReadError> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes.len() > INTERFACE_NAME_MAX
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(RouteReadError::Malformed);
    }
    Ok(bytes.len() as u8)
}

fn select_gateway(routes: &[RouteRecord]) -> GatewayDiscovery {
    let mut best: Option<&RouteRecord> = None;
    let mut saw_invalid = false;
    let mut ambiguous = false;
    for route in routes {
        if route.destination != Ipv4Addr::UNSPECIFIED || route.prefix_len != 0 || !route.has_gateway
        {
            continue;
        }
        if !acceptable_gateway(route.gateway) {
            saw_invalid = true;
            continue;
        }
        match best {
            None => best = Some(route),
            Some(current) if route.metric < current.metric => {
                best = Some(route);
                ambiguous = false;
            }
            Some(current) if route.metric == current.metric && route.gateway != current.gateway => {
                ambiguous = true;
            }
            Some(current)
                if route.metric == current.metric
                    && route.gateway == current.gateway
                    && interface_before(route, current) =>
            {
                best = Some(route);
            }
            Some(_) => {}
        }
    }
    if ambiguous {
        return GatewayDiscovery::Unsupported;
    }
    match best {
        Some(route) => GatewayDiscovery::Selected(SelectedGateway::from_record(route)),
        None if saw_invalid => GatewayDiscovery::InvalidGateway,
        None => GatewayDiscovery::Unsupported,
    }
}

fn acceptable_gateway(gateway: Ipv4Addr) -> bool {
    if gateway.is_unspecified()
        || gateway.is_broadcast()
        || gateway.is_multicast()
        || gateway.is_loopback()
    {
        return false;
    }
    gateway.octets()[0] < 240
}

fn interface_before(candidate: &RouteRecord, current: &RouteRecord) -> bool {
    (candidate.interface_index, candidate.interface_name())
        < (current.interface_index, current.interface_name())
}

fn read_netlink_routes(cancelled: &dyn Fn() -> bool) -> Result<Vec<RouteRecord>, RouteReadError> {
    if cancelled() {
        return Err(RouteReadError::Cancelled);
    }
    let bytes = dump_netlink(cancelled)?;
    parse_netlink_route_dump(&bytes)
}

fn dump_netlink(cancelled: &dyn Fn() -> bool) -> Result<Vec<u8>, RouteReadError> {
    if cancelled() {
        return Err(RouteReadError::Cancelled);
    }
    // SAFETY: socket(2) is called with constant arguments. A negative fd owns
    // nothing; a non-negative fd is closed by `OwnedSocket`.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(RouteReadError::Unavailable);
    }
    let socket = OwnedSocket(fd);
    let timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 250_000,
    };
    // SAFETY: `socket` owns the descriptor. `timeout` is a `timeval` that
    // outlives this setsockopt, and the length matches that type.
    let set = unsafe {
        libc::setsockopt(
            socket.0,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::from_ref(&timeout).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if set != 0 {
        return Err(RouteReadError::Unavailable);
    }
    // SAFETY: `sockaddr_nl` is a plain address. Zero is the unspecified
    // netlink name; `nl_family` is set before bind.
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // SAFETY: `socket` owns the descriptor. `address` is a `sockaddr_nl` for
    // the length passed, and bind does not retain the pointer.
    let bound = unsafe {
        libc::bind(
            socket.0,
            std::ptr::from_ref(&address).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bound != 0 {
        return Err(RouteReadError::Unavailable);
    }
    let request = netlink_dump_request();
    // SAFETY: `socket` owns the descriptor. `request` outlives send and the
    // length is its byte count.
    let sent = unsafe { libc::send(socket.0, request.as_ptr().cast(), request.len(), 0) };
    if sent < 0 || sent as usize != request.len() {
        return Err(RouteReadError::Unavailable);
    }
    let mut accumulated = Vec::new();
    let mut buffer = [0u8; NETLINK_RECV_BYTES];
    for _ in 0..8 {
        if cancelled() {
            return Err(RouteReadError::Cancelled);
        }
        // SAFETY: `socket` owns the descriptor. `buffer` is writable for its
        // full length. `MSG_TRUNC` makes recv return the real datagram length
        // without retaining `buffer`.
        let received = unsafe {
            libc::recv(
                socket.0,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_TRUNC,
            )
        };
        if received < 0 {
            return Err(RouteReadError::Unavailable);
        }
        if received == 0 {
            break;
        }
        let received = received as usize;
        if received > buffer.len() {
            return Err(RouteReadError::Malformed);
        }
        if accumulated.len().saturating_add(received) > ROUTE_TABLE_MAX_BYTES {
            return Err(RouteReadError::Bounded);
        }
        accumulated.extend_from_slice(&buffer[..received]);
        if netlink_dump_finished(&accumulated) {
            return Ok(accumulated);
        }
    }
    if netlink_dump_finished(&accumulated) {
        Ok(accumulated)
    } else if accumulated.is_empty() {
        Err(RouteReadError::Unavailable)
    } else {
        Err(RouteReadError::Bounded)
    }
}

struct OwnedSocket(i32);

impl Drop for OwnedSocket {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: `self.0` is the fd from a successful socket(2), and this
            // drop runs once.
            unsafe { libc::close(self.0) };
        }
    }
}

fn netlink_dump_request() -> Vec<u8> {
    let mut request = vec![0u8; 16 + 12];
    let length = u32::try_from(request.len()).unwrap_or(u32::MAX);
    request[0..4].copy_from_slice(&length.to_ne_bytes());
    request[4..6].copy_from_slice(&(libc::RTM_GETROUTE).to_ne_bytes());
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    request[6..8].copy_from_slice(&flags.to_ne_bytes());
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    request[16] = libc::AF_INET as u8;
    request
}

fn netlink_dump_finished(bytes: &[u8]) -> bool {
    let mut offset = 0;
    while offset + 16 <= bytes.len() {
        let length =
            u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap_or([0; 4])) as usize;
        let kind = u16::from_ne_bytes(bytes[offset + 4..offset + 6].try_into().unwrap_or([0; 2]));
        if length < 16 || offset.saturating_add(length) > bytes.len() {
            return false;
        }
        if kind == libc::NLMSG_DONE as u16 {
            return true;
        }
        offset = offset.saturating_add(align4(length));
    }
    false
}

fn parse_netlink_route_dump(bytes: &[u8]) -> Result<Vec<RouteRecord>, RouteReadError> {
    if bytes.len() > ROUTE_TABLE_MAX_BYTES {
        return Err(RouteReadError::Bounded);
    }
    let mut routes = Vec::new();
    let mut offset = 0;
    let mut finished = false;
    while offset + 16 <= bytes.len() {
        let length =
            u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap_or([0; 4])) as usize;
        let kind = u16::from_ne_bytes(bytes[offset + 4..offset + 6].try_into().unwrap_or([0; 2]));
        if length < 16 || offset.saturating_add(length) > bytes.len() {
            return Err(RouteReadError::Malformed);
        }
        if kind == libc::NLMSG_DONE as u16 {
            finished = true;
            break;
        }
        if kind == libc::NLMSG_ERROR as u16 {
            return Err(RouteReadError::Unavailable);
        }
        if kind == libc::RTM_NEWROUTE {
            if routes.len() == ROUTE_TABLE_MAX_RECORDS {
                return Err(RouteReadError::Bounded);
            }
            if let Some(route) = parse_route_message(&bytes[offset + 16..offset + length]) {
                routes.push(route);
            }
        }
        offset = offset.saturating_add(align4(length));
    }
    if finished {
        Ok(routes)
    } else {
        Err(RouteReadError::Malformed)
    }
}

fn parse_route_message(body: &[u8]) -> Option<RouteRecord> {
    if body.len() < 12 || body[0] != libc::AF_INET as u8 {
        return None;
    }
    let prefix_len = body[1];
    if prefix_len > 32 {
        return None;
    }
    // `/proc/net/route` lists the main table. A dump of every table would let
    // a lower-metric policy route replace that gateway.
    if body[7] != libc::RTN_UNICAST {
        return None;
    }
    let mut destination = Ipv4Addr::UNSPECIFIED;
    let mut gateway = Ipv4Addr::UNSPECIFIED;
    let mut has_gateway = false;
    let mut interface_index = 0;
    let mut metric = 0;
    let mut table_from_attr = None;
    let mut cursor = align4(12);
    while cursor + 4 <= body.len() {
        let attr_len = u16::from_ne_bytes(body[cursor..cursor + 2].try_into().ok()?) as usize;
        let attr_type = u16::from_ne_bytes(body[cursor + 2..cursor + 4].try_into().ok()?);
        if attr_len < 4 || cursor.saturating_add(attr_len) > body.len() {
            return None;
        }
        let data = &body[cursor + 4..cursor + attr_len];
        if attr_type == libc::RTA_DST && data.len() == 4 {
            destination = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
        } else if attr_type == libc::RTA_GATEWAY && data.len() == 4 {
            gateway = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
            has_gateway = true;
        } else if attr_type == libc::RTA_OIF && data.len() == 4 {
            interface_index = u32::from_ne_bytes(data.try_into().ok()?);
        } else if attr_type == libc::RTA_PRIORITY && data.len() == 4 {
            metric = u32::from_ne_bytes(data.try_into().ok()?);
        } else if attr_type == libc::RTA_TABLE && data.len() == 4 {
            table_from_attr = Some(u32::from_ne_bytes(data.try_into().ok()?));
        }
        cursor = cursor.saturating_add(align4(attr_len));
    }
    let table = if body[4] == libc::RT_TABLE_COMPAT {
        table_from_attr?
    } else {
        u32::from(body[4])
    };
    if table != u32::from(libc::RT_TABLE_MAIN) {
        return None;
    }
    if prefix_len == 0 {
        destination = Ipv4Addr::UNSPECIFIED;
    }
    Some(RouteRecord {
        destination,
        prefix_len,
        gateway,
        has_gateway,
        interface_index,
        interface_name: [0; INTERFACE_NAME_MAX],
        interface_name_len: 0,
        metric,
    })
}

fn align4(value: usize) -> usize {
    value.saturating_add(3) & !3
}

pub fn exchange_with_gateway(
    gateway: &SelectedGateway,
    protocol: RouterProtocol,
    location: Option<&str>,
    request: &[u8],
    transport: &mut dyn ControlTransport,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, ControlRefusal> {
    if cancelled() {
        return Err(ControlRefusal::Cancelled);
    }
    if request.is_empty() {
        return Err(ControlRefusal::Unsupported);
    }
    if request.len() > CONTROL_MAX_BYTES {
        return Err(ControlRefusal::Oversize);
    }
    let destination = control_destination(gateway, protocol, location)?;
    let mut response = [0u8; CONTROL_MAX_BYTES];
    let received = transport.exchange(destination, request, &mut response)?;
    if cancelled() {
        return Err(ControlRefusal::Cancelled);
    }
    if received > CONTROL_MAX_BYTES {
        return Err(ControlRefusal::Bounded);
    }
    Ok(response[..received].to_vec())
}

/// Whether [`exchange_upnp_soap`] handed the request to `transport`.
///
/// [`UpnpSoapReply::Refused`] is a local check: an empty or oversize body,
/// cancellation, or a control URL that is not the selected gateway. Nothing
/// was sent. [`UpnpSoapReply::Exchanged`] means `transport.exchange` was
/// called. An error in that arm is a lost reply, including when the transport
/// reports [`ControlRefusal::Unsupported`], [`ControlRefusal::Oversize`], or
/// [`ControlRefusal::WrongTarget`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum UpnpSoapReply {
    Refused(ControlRefusal),
    Exchanged(Result<Vec<u8>, ControlRefusal>),
}

/// SOAP bytes for the descriptor's control URL. The destination is the
/// selected gateway or the call fails before `transport` is used. Redirects
/// are not followed: this function exchanges one buffer and returns it.
pub(crate) fn exchange_upnp_soap(
    gateway: &SelectedGateway,
    location: &str,
    request: &[u8],
    transport: &mut dyn ControlTransport,
    cancelled: &dyn Fn() -> bool,
) -> UpnpSoapReply {
    if request.is_empty() {
        return UpnpSoapReply::Refused(ControlRefusal::Unsupported);
    }
    if request.len() > UPNP_SOAP_MAX_BYTES {
        return UpnpSoapReply::Refused(ControlRefusal::Oversize);
    }
    // Already cancelled: do not hand the request to the transport.
    if cancelled() {
        return UpnpSoapReply::Refused(ControlRefusal::Cancelled);
    }
    let destination = match control_destination(gateway, RouterProtocol::UpnpIgd, Some(location)) {
        Ok(destination) => destination,
        Err(refusal) => return UpnpSoapReply::Refused(refusal),
    };
    let mut response = [0u8; UPNP_SOAP_MAX_BYTES];
    let received = match transport.exchange(destination, request, &mut response) {
        Ok(received) => received,
        // The request was handed off. The router may already have applied it.
        Err(refusal) => return UpnpSoapReply::Exchanged(Err(refusal)),
    };
    // A completed read is kept even if cancellation became true while the
    // gateway was answering. Dropping that body would hide an overlong grant.
    // Callers check `cancelled` again before the next mutation.
    // A full buffer is treated as truncated. A complete SOAP reply fits under
    // the cap, so filling it is not a successful read.
    if received >= UPNP_SOAP_MAX_BYTES {
        return UpnpSoapReply::Exchanged(Err(ControlRefusal::Bounded));
    }
    UpnpSoapReply::Exchanged(Ok(response[..received].to_vec()))
}

fn control_destination(
    gateway: &SelectedGateway,
    protocol: RouterProtocol,
    location: Option<&str>,
) -> Result<SocketAddr, ControlRefusal> {
    match protocol {
        RouterProtocol::Pcp | RouterProtocol::NatPmp => {
            if location.is_some() {
                return Err(ControlRefusal::WrongTarget);
            }
            Ok(SocketAddr::new(
                IpAddr::V4(gateway.gateway()),
                ROUTER_CONTROL_PORT,
            ))
        }
        RouterProtocol::UpnpIgd => {
            upnp_location(gateway, location.ok_or(ControlRefusal::WrongTarget)?)
        }
    }
}

fn upnp_location(gateway: &SelectedGateway, location: &str) -> Result<SocketAddr, ControlRefusal> {
    if location.len() > CONTROL_LOCATION_MAX_BYTES {
        return Err(ControlRefusal::Oversize);
    }
    let url = url::Url::parse(location).map_err(|_| ControlRefusal::WrongTarget)?;
    if url.scheme() != "http" || !url.username().is_empty() || url.password().is_some() {
        return Err(ControlRefusal::WrongTarget);
    }
    let host = match url.host() {
        Some(url::Host::Ipv4(address)) if address == gateway.gateway() => address,
        _ => return Err(ControlRefusal::WrongTarget),
    };
    let port = url.port_or_known_default().unwrap_or(0);
    if port == 0 {
        return Err(ControlRefusal::WrongTarget);
    }
    Ok(SocketAddr::new(IpAddr::V4(host), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn never() -> bool {
        false
    }

    fn route(
        destination: Ipv4Addr,
        prefix: u8,
        gateway: Ipv4Addr,
        has_gateway: bool,
        metric: u32,
        name: &str,
    ) -> RouteRecord {
        let mut record = RouteRecord::new(destination, prefix, gateway, has_gateway, metric);
        record.interface_name_len = name.len() as u8;
        record.interface_name[..name.len()].copy_from_slice(name.as_bytes());
        record
    }

    fn selected(discovery: GatewayDiscovery) -> SelectedGateway {
        match discovery {
            GatewayDiscovery::Selected(gateway) => gateway,
            other => panic!("expected a gateway, got {other:?}"),
        }
    }

    #[test]
    fn missing_and_on_link_routes_do_not_invent_a_gateway() {
        assert_eq!(discover_loaded(&[], &never), GatewayDiscovery::Unsupported);
        // 10.1.2.0/24 on-link has no gateway. The local socket 10.1.2.15 and
        // the subnet guess 10.1.2.1 are not candidates.
        let on_link = route(
            Ipv4Addr::new(10, 1, 2, 0),
            24,
            Ipv4Addr::UNSPECIFIED,
            false,
            0,
            "eth0",
        );
        assert_eq!(
            discover_loaded(&[on_link], &never),
            GatewayDiscovery::Unsupported
        );
    }

    #[test]
    fn lowest_metric_default_wins_among_specific_routes() {
        let routes = [
            route(
                Ipv4Addr::new(10, 1, 2, 0),
                24,
                Ipv4Addr::UNSPECIFIED,
                false,
                0,
                "eth0",
            ),
            route(
                Ipv4Addr::UNSPECIFIED,
                0,
                Ipv4Addr::new(192, 168, 0, 2),
                true,
                200,
                "eth1",
            ),
            route(
                Ipv4Addr::UNSPECIFIED,
                0,
                Ipv4Addr::new(192, 168, 0, 1),
                true,
                100,
                "eth0",
            ),
        ];
        let gateway = selected(discover_loaded(&routes, &never));
        assert_eq!(gateway.gateway(), Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(gateway.interface_name(), Some("eth0"));
    }

    #[test]
    fn tied_distinct_defaults_are_unsupported_and_same_gateway_is_not() {
        let tie = [
            route(
                Ipv4Addr::UNSPECIFIED,
                0,
                Ipv4Addr::new(192, 168, 0, 1),
                true,
                10,
                "eth0",
            ),
            route(
                Ipv4Addr::UNSPECIFIED,
                0,
                Ipv4Addr::new(192, 168, 0, 2),
                true,
                10,
                "eth1",
            ),
        ];
        assert_eq!(discover_loaded(&tie, &never), GatewayDiscovery::Unsupported);
        let same = [
            route(
                Ipv4Addr::UNSPECIFIED,
                0,
                Ipv4Addr::new(192, 168, 0, 1),
                true,
                10,
                "eth1",
            ),
            route(
                Ipv4Addr::UNSPECIFIED,
                0,
                Ipv4Addr::new(192, 168, 0, 1),
                true,
                10,
                "eth0",
            ),
        ];
        let gateway = selected(discover_loaded(&same, &never));
        assert_eq!(gateway.gateway(), Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(gateway.interface_name(), Some("eth0"));
    }

    #[test]
    fn invalid_gateways_stay_distinct_from_a_missing_route() {
        for gateway in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(240, 0, 0, 1),
        ] {
            let routes = [route(Ipv4Addr::UNSPECIFIED, 0, gateway, true, 1, "eth0")];
            assert_eq!(
                discover_loaded(&routes, &never),
                GatewayDiscovery::InvalidGateway,
                "{gateway}"
            );
        }
        let mixed = [
            route(
                Ipv4Addr::UNSPECIFIED,
                0,
                Ipv4Addr::UNSPECIFIED,
                true,
                1,
                "eth0",
            ),
            route(
                Ipv4Addr::UNSPECIFIED,
                0,
                Ipv4Addr::new(192, 168, 0, 1),
                true,
                50,
                "eth0",
            ),
        ];
        assert_eq!(
            selected(discover_loaded(&mixed, &never)).gateway(),
            Ipv4Addr::new(192, 168, 0, 1)
        );
    }

    #[test]
    fn cancellation_discards_a_selected_gateway_and_skips_the_load() {
        let routes = [route(
            Ipv4Addr::UNSPECIFIED,
            0,
            Ipv4Addr::new(192, 168, 0, 1),
            true,
            1,
            "eth0",
        )];
        assert_eq!(
            discover_loaded(&routes, &|| true),
            GatewayDiscovery::Cancelled
        );
        let mut loads = 0;
        let mut netlink = || {
            loads += 1;
            Ok(routes.to_vec())
        };
        let discovery =
            discover_with_sources(Err(RouteReadError::Unavailable), &mut netlink, &|| true);
        assert_eq!(discovery, GatewayDiscovery::Cancelled);
        assert_eq!(loads, 0);
    }

    #[test]
    fn proc_fixture_selects_the_little_endian_default_gateway() {
        let text = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
eth1\t00000000\t0200A8C0\t0003\t0\t0\t200\t00000000\t0\t0\t0
eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
";
        let routes = parse_proc_net_route(text).unwrap();
        let gateway = selected(discover_loaded(&routes, &never));
        assert_eq!(gateway.gateway(), Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(gateway.interface_name(), Some("eth0"));
    }

    #[test]
    fn oversized_proc_input_and_record_count_are_bounded() {
        let mut text = "Iface Destination Gateway Flags RefCnt Use Metric Mask\n".to_string();
        text.push_str(&"x".repeat(ROUTE_TABLE_MAX_BYTES));
        assert_eq!(parse_proc_net_route(&text), Err(RouteReadError::Bounded));
        let line = "eth0 00000000 0100A8C0 0003 0 0 1 00000000 0 0 0\n";
        let many = line.repeat(ROUTE_TABLE_MAX_RECORDS + 1);
        assert_eq!(parse_proc_net_route(&many), Err(RouteReadError::Bounded));
    }

    #[test]
    fn proc_file_read_stops_at_the_byte_cap() {
        let dir = std::env::temp_dir().join(format!(
            "liskov-gateway-{}-{}",
            std::process::id(),
            "bounded"
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("route");
        std::fs::write(&path, vec![b'a'; ROUTE_TABLE_MAX_BYTES + 1]).unwrap();
        let read = read_proc_net_route(&path, &never);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(read, Err(RouteReadError::Bounded));
    }

    #[test]
    fn source_fallback_never_scans_past_an_available_table() {
        let routes = vec![route(
            Ipv4Addr::UNSPECIFIED,
            0,
            Ipv4Addr::new(192, 168, 0, 9),
            true,
            1,
            "eth0",
        )];
        let mut netlink_calls = 0;
        let mut netlink = || {
            netlink_calls += 1;
            Ok(vec![route(
                Ipv4Addr::UNSPECIFIED,
                0,
                Ipv4Addr::new(198, 51, 100, 1),
                true,
                1,
                "eth9",
            )])
        };
        let discovery = discover_with_sources(Ok(routes.clone()), &mut netlink, &never);
        assert_eq!(netlink_calls, 0);
        assert_eq!(selected(discovery).gateway(), Ipv4Addr::new(192, 168, 0, 9));

        let mut fallback_netlink = || Ok(routes.clone());
        let fallback = discover_with_sources(
            Err(RouteReadError::Unavailable),
            &mut fallback_netlink,
            &never,
        );
        assert_eq!(selected(fallback).gateway(), Ipv4Addr::new(192, 168, 0, 9));
        let mut none = || Err(RouteReadError::Unavailable);
        assert_eq!(
            discover_with_sources(Err(RouteReadError::Unavailable), &mut none, &never),
            GatewayDiscovery::Unsupported
        );
        let mut skipped = 0;
        let mut skipped_netlink = || {
            skipped += 1;
            Ok(Vec::new())
        };
        assert_eq!(
            discover_with_sources(Err(RouteReadError::Bounded), &mut skipped_netlink, &never),
            GatewayDiscovery::Bounded
        );
        assert_eq!(skipped, 0);
    }

    #[test]
    fn present_proc_file_does_not_ask_netlink() {
        let dir = std::env::temp_dir().join(format!("liskov-gateway-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("route");
        std::fs::write(
            &path,
            "Iface Destination Gateway Flags RefCnt Use Metric Mask\neth0 00000000 0100A8C0 0003 0 0 10 00000000\n",
        )
        .unwrap();
        let discovery = discover_at_path(&path, &never);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(selected(discovery).gateway(), Ipv4Addr::new(192, 168, 0, 1));
    }

    #[test]
    fn netlink_dump_selects_only_the_default_gateway() {
        let dump = sample_dump(&[
            sample_route(24, Ipv4Addr::new(10, 1, 2, 0), None, 2, 0),
            sample_route(
                0,
                Ipv4Addr::UNSPECIFIED,
                Some(Ipv4Addr::new(192, 168, 0, 1)),
                3,
                15,
            ),
        ]);
        let routes = parse_netlink_route_dump(&dump).unwrap();
        let gateway = selected(discover_loaded(&routes, &never));
        assert_eq!(gateway.gateway(), Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(gateway.interface_index(), 3);
        assert_eq!(gateway.interface_name(), None);
    }

    #[test]
    fn netlink_keeps_the_main_unicast_default_and_ignores_other_tables() {
        let mut policy = sample_route(
            0,
            Ipv4Addr::UNSPECIFIED,
            Some(Ipv4Addr::new(10, 0, 0, 1)),
            2,
            0,
        );
        policy.table = 100;
        let mut wide = sample_route(
            0,
            Ipv4Addr::UNSPECIFIED,
            Some(Ipv4Addr::new(10, 1, 0, 1)),
            3,
            0,
        );
        wide.table = 1000;
        wide.table_attribute = true;
        let mut local = sample_route(
            0,
            Ipv4Addr::UNSPECIFIED,
            Some(Ipv4Addr::new(10, 2, 0, 1)),
            4,
            0,
        );
        local.route_type = libc::RTN_LOCAL;
        let main = sample_route(
            0,
            Ipv4Addr::UNSPECIFIED,
            Some(Ipv4Addr::new(192, 168, 0, 1)),
            1,
            100,
        );
        let routes = parse_netlink_route_dump(&sample_dump(&[policy, wide, local, main])).unwrap();
        assert_eq!(
            selected(discover_loaded(&routes, &never)).gateway(),
            Ipv4Addr::new(192, 168, 0, 1)
        );
        let mut only_policy = sample_route(
            0,
            Ipv4Addr::UNSPECIFIED,
            Some(Ipv4Addr::new(10, 0, 0, 1)),
            2,
            0,
        );
        only_policy.table = 100;
        let ignored = parse_netlink_route_dump(&sample_dump(&[only_policy])).unwrap();
        assert_eq!(
            discover_loaded(&ignored, &never),
            GatewayDiscovery::Unsupported
        );
    }

    #[test]
    fn missing_proc_file_uses_the_real_netlink_socket() {
        let discovery = discover_at_path(Path::new("/no/such/liskov-proc-net-route"), &never);
        assert_ne!(discovery, GatewayDiscovery::Cancelled);
        assert_ne!(discovery, GatewayDiscovery::Bounded);
        if af_netlink_denied() {
            assert_eq!(discovery, GatewayDiscovery::Unsupported);
        }
    }

    #[test]
    fn malformed_proc_file_does_not_become_a_selected_gateway() {
        let text = "not-a-route-table\neth0 00000000 0100A8C0\n";
        assert_eq!(parse_proc_net_route(text), Err(RouteReadError::Malformed));
        let dir =
            std::env::temp_dir().join(format!("liskov-gateway-malformed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("route");
        std::fs::write(&path, text).unwrap();
        let discovery = discover_at_path(&path, &never);
        let _ = std::fs::remove_dir_all(&dir);
        assert_ne!(discovery, GatewayDiscovery::Cancelled);
        assert_ne!(discovery, GatewayDiscovery::Bounded);
        if af_netlink_denied() {
            assert_eq!(discovery, GatewayDiscovery::Unsupported);
        }
    }

    #[test]
    fn control_exchange_reaches_only_the_selected_gateway() {
        let gateway = selected(discover_loaded(
            &[route(
                Ipv4Addr::UNSPECIFIED,
                0,
                Ipv4Addr::new(192, 0, 2, 1),
                true,
                1,
                "eth0",
            )],
            &never,
        ));
        let mut transport = RecordingTransport {
            calls: Vec::new(),
            response: b"ok".to_vec(),
            fail: None,
        };
        let response = exchange_with_gateway(
            &gateway,
            RouterProtocol::Pcp,
            None,
            b"map",
            &mut transport,
            &never,
        )
        .unwrap();
        assert_eq!(response, b"ok");
        assert_eq!(
            transport.calls,
            vec![(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), ROUTER_CONTROL_PORT),
                b"map".to_vec()
            )]
        );
        transport.calls.clear();
        exchange_with_gateway(
            &gateway,
            RouterProtocol::NatPmp,
            None,
            b"map",
            &mut transport,
            &never,
        )
        .unwrap();
        assert_eq!(transport.calls[0].0.port(), ROUTER_CONTROL_PORT);

        assert_eq!(
            exchange_with_gateway(
                &gateway,
                RouterProtocol::Pcp,
                Some("http://198.51.100.9/"),
                b"map",
                &mut transport,
                &never,
            ),
            Err(ControlRefusal::WrongTarget)
        );
        assert_eq!(
            exchange_with_gateway(
                &gateway,
                RouterProtocol::UpnpIgd,
                Some("http://198.51.100.9/ctl"),
                b"map",
                &mut transport,
                &never,
            ),
            Err(ControlRefusal::WrongTarget)
        );
        assert_eq!(
            exchange_with_gateway(
                &gateway,
                RouterProtocol::UpnpIgd,
                Some("http://router.example/ctl"),
                b"map",
                &mut transport,
                &never,
            ),
            Err(ControlRefusal::WrongTarget)
        );
        assert_eq!(
            exchange_with_gateway(
                &gateway,
                RouterProtocol::UpnpIgd,
                Some("https://192.0.2.1/ctl"),
                b"map",
                &mut transport,
                &never,
            ),
            Err(ControlRefusal::WrongTarget)
        );
        assert_eq!(
            exchange_with_gateway(
                &gateway,
                RouterProtocol::UpnpIgd,
                Some("http://user:secret@192.0.2.1/ctl"),
                b"map",
                &mut transport,
                &never,
            ),
            Err(ControlRefusal::WrongTarget)
        );
        transport.calls.clear();
        exchange_with_gateway(
            &gateway,
            RouterProtocol::UpnpIgd,
            Some("http://192.0.2.1:52869/ctl"),
            b"<e/>",
            &mut transport,
            &never,
        )
        .unwrap();
        assert_eq!(
            transport.calls[0].0,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 52869)
        );
    }

    #[test]
    fn control_io_is_bounded_and_cancellation_drops_the_reply() {
        let gateway = selected(discover_loaded(
            &[route(
                Ipv4Addr::UNSPECIFIED,
                0,
                Ipv4Addr::new(192, 0, 2, 1),
                true,
                1,
                "eth0",
            )],
            &never,
        ));
        let mut transport = RecordingTransport {
            calls: Vec::new(),
            response: b"ok".to_vec(),
            fail: None,
        };
        assert_eq!(
            exchange_with_gateway(
                &gateway,
                RouterProtocol::Pcp,
                None,
                &[],
                &mut transport,
                &never,
            ),
            Err(ControlRefusal::Unsupported)
        );
        assert_eq!(
            exchange_with_gateway(
                &gateway,
                RouterProtocol::Pcp,
                None,
                &vec![1; CONTROL_MAX_BYTES + 1],
                &mut transport,
                &never,
            ),
            Err(ControlRefusal::Oversize)
        );
        assert!(transport.calls.is_empty());
        assert_eq!(
            exchange_with_gateway(
                &gateway,
                RouterProtocol::Pcp,
                None,
                b"map",
                &mut transport,
                &|| true,
            ),
            Err(ControlRefusal::Cancelled)
        );
        assert!(transport.calls.is_empty());
        assert_eq!(
            exchange_with_gateway(
                &gateway,
                RouterProtocol::UpnpIgd,
                Some(&format!(
                    "http://192.0.2.1/{}",
                    "a".repeat(CONTROL_LOCATION_MAX_BYTES)
                )),
                b"map",
                &mut transport,
                &never,
            ),
            Err(ControlRefusal::Oversize)
        );
        transport.fail = Some(ControlRefusal::Bounded);
        assert_eq!(
            exchange_with_gateway(
                &gateway,
                RouterProtocol::NatPmp,
                None,
                b"map",
                &mut transport,
                &never,
            ),
            Err(ControlRefusal::Bounded)
        );
    }

    #[test]
    fn router_protocol_names_match_the_grant_codec() {
        assert_eq!(
            RouterProtocol::from(TraversalRouterProtocol::Pcp),
            RouterProtocol::Pcp
        );
        assert_eq!(
            RouterProtocol::from(TraversalRouterProtocol::NatPmp),
            RouterProtocol::NatPmp
        );
        assert_eq!(
            RouterProtocol::from(TraversalRouterProtocol::UpnpIgd),
            RouterProtocol::UpnpIgd
        );
    }

    #[test]
    fn upnp_soap_exchange_stays_on_the_selected_gateway_and_under_the_cap() {
        let gateway = selected(discover_loaded(
            &[route(
                Ipv4Addr::UNSPECIFIED,
                0,
                Ipv4Addr::new(192, 0, 2, 1),
                true,
                1,
                "eth0",
            )],
            &never,
        ));
        let mut transport = RecordingTransport {
            calls: Vec::new(),
            response: b"ok".to_vec(),
            fail: None,
        };
        let response = exchange_upnp_soap(
            &gateway,
            "http://192.0.2.1:52869/ctl",
            b"<e/>",
            &mut transport,
            &never,
        );
        assert_eq!(response, UpnpSoapReply::Exchanged(Ok(b"ok".to_vec())));
        assert_eq!(
            transport.calls[0].0,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 52869)
        );
        transport.calls.clear();
        assert_eq!(
            exchange_upnp_soap(
                &gateway,
                "http://198.51.100.9/ctl",
                b"<e/>",
                &mut transport,
                &never,
            ),
            UpnpSoapReply::Refused(ControlRefusal::WrongTarget)
        );
        assert!(transport.calls.is_empty());
        assert_eq!(
            exchange_upnp_soap(
                &gateway,
                "http://192.0.2.1/ctl",
                &vec![1; UPNP_SOAP_MAX_BYTES + 1],
                &mut transport,
                &never,
            ),
            UpnpSoapReply::Refused(ControlRefusal::Oversize)
        );
        assert!(transport.calls.is_empty());
        transport.fail = Some(ControlRefusal::Unsupported);
        assert_eq!(
            exchange_upnp_soap(
                &gateway,
                "http://192.0.2.1:52869/ctl",
                b"<e/>",
                &mut transport,
                &never,
            ),
            UpnpSoapReply::Exchanged(Err(ControlRefusal::Unsupported))
        );
        assert_eq!(transport.calls.len(), 1);
    }

    struct RecordingTransport {
        calls: Vec<(SocketAddr, Vec<u8>)>,
        response: Vec<u8>,
        fail: Option<ControlRefusal>,
    }

    impl ControlTransport for RecordingTransport {
        fn exchange(
            &mut self,
            destination: SocketAddr,
            request: &[u8],
            response: &mut [u8],
        ) -> Result<usize, ControlRefusal> {
            self.calls.push((destination, request.to_vec()));
            if let Some(refusal) = self.fail {
                return Err(refusal);
            }
            let length = self.response.len().min(response.len());
            response[..length].copy_from_slice(&self.response[..length]);
            Ok(length)
        }
    }

    struct SampleRoute {
        prefix: u8,
        destination: Ipv4Addr,
        gateway: Option<Ipv4Addr>,
        interface_index: u32,
        metric: u32,
        table: u32,
        route_type: u8,
        table_attribute: bool,
    }

    fn sample_route(
        prefix: u8,
        destination: Ipv4Addr,
        gateway: Option<Ipv4Addr>,
        interface_index: u32,
        metric: u32,
    ) -> SampleRoute {
        SampleRoute {
            prefix,
            destination,
            gateway,
            interface_index,
            metric,
            table: u32::from(libc::RT_TABLE_MAIN),
            route_type: libc::RTN_UNICAST,
            table_attribute: false,
        }
    }

    fn af_netlink_denied() -> bool {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd >= 0 {
            unsafe { libc::close(fd) };
            return false;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    fn sample_dump(routes: &[SampleRoute]) -> Vec<u8> {
        let mut dump = Vec::new();
        for route in routes {
            let mut attributes = Vec::new();
            if route.prefix != 0 {
                push_attr(&mut attributes, libc::RTA_DST, &route.destination.octets());
            }
            if let Some(gateway) = route.gateway {
                push_attr(&mut attributes, libc::RTA_GATEWAY, &gateway.octets());
            }
            push_attr(
                &mut attributes,
                libc::RTA_OIF,
                &route.interface_index.to_ne_bytes(),
            );
            push_attr(
                &mut attributes,
                libc::RTA_PRIORITY,
                &route.metric.to_ne_bytes(),
            );
            let table_byte = if route.table_attribute || route.table > u32::from(u8::MAX) {
                push_attr(&mut attributes, libc::RTA_TABLE, &route.table.to_ne_bytes());
                libc::RT_TABLE_COMPAT
            } else {
                route.table as u8
            };
            let mut body = vec![
                libc::AF_INET as u8,
                route.prefix,
                0,
                0,
                table_byte,
                0,
                0,
                route.route_type,
            ];
            body.extend_from_slice(&0u32.to_ne_bytes());
            body.extend_from_slice(&attributes);
            push_nlmsg(&mut dump, libc::RTM_NEWROUTE, &body);
        }
        push_nlmsg(&mut dump, libc::NLMSG_DONE as u16, &[]);
        dump
    }

    fn push_attr(buffer: &mut Vec<u8>, kind: u16, data: &[u8]) {
        let length = 4 + data.len();
        buffer.extend_from_slice(&(length as u16).to_ne_bytes());
        buffer.extend_from_slice(&kind.to_ne_bytes());
        buffer.extend_from_slice(data);
        while buffer.len() % 4 != 0 {
            buffer.push(0);
        }
    }

    fn push_nlmsg(buffer: &mut Vec<u8>, kind: u16, body: &[u8]) {
        let length = 16 + body.len();
        buffer.extend_from_slice(&(length as u32).to_ne_bytes());
        buffer.extend_from_slice(&kind.to_ne_bytes());
        buffer.extend_from_slice(&0u16.to_ne_bytes());
        buffer.extend_from_slice(&1u32.to_ne_bytes());
        buffer.extend_from_slice(&0u32.to_ne_bytes());
        buffer.extend_from_slice(body);
        while buffer.len() % 4 != 0 {
            buffer.push(0);
        }
    }
}
