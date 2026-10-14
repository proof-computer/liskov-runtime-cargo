//! Bounded UPnP IGD discovery. SSDP and device XML stay on the seams below.
//!
//! Nothing here sends AddPortMapping, DeletePortMapping, or a mapping-table
//! query. A caller has to ask. The descriptor keeps the gateway-local control
//! target and the service kind. It does not keep a UDN, serial, service id, or
//! the raw advertisement. `Debug` redacts the gateway address. Replies and
//! documents are capped by bytes, depth, and the caller's deadline. A missing
//! route or a missing UDP primitive is [`IgdDiscovery::Unsupported`].

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use super::{
    CONTROL_LOCATION_MAX_BYTES, CONTROL_MAX_BYTES, GatewayDiscovery, RouteRecord, SelectedGateway,
    discover_loaded,
};

pub const IGD_SSDP_ADDRESS: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
pub const IGD_SSDP_PORT: u16 = 1900;
pub const IGD_SSDP_MAX_BYTES: usize = CONTROL_MAX_BYTES;
pub const IGD_SSDP_MAX_REPLIES: usize = 4;
pub const IGD_XML_MAX_BYTES: usize = 16 * 1024;
pub const IGD_XML_MAX_DEPTH: usize = 16;
pub const IGD_MAX_SERVICE_CANDIDATES: usize = 4;
pub const IGD_MAX_DOCUMENT_FETCHES: usize = 2;
pub const IGD_SEARCH_BUDGET: Duration = Duration::from_millis(1_000);
pub const IGD_HTTP_BUDGET: Duration = Duration::from_millis(1_000);

const WAN_IP_V1: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";
const WAN_IP_V2: &str = "urn:schemas-upnp-org:service:WANIPConnection:2";
const WAN_PPP_V1: &str = "urn:schemas-upnp-org:service:WANPPPConnection:1";
const WAN_PPP_V2: &str = "urn:schemas-upnp-org:service:WANPPPConnection:2";
const SSDP_MSEARCH: &str = "\
M-SEARCH * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\n\
MX: 1\r\n\
ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
\r\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IgdServiceKind {
    WanIpConnection,
    WanPppConnection,
}

/// Gateway-local IGD control target. The address is not a debug field.
#[derive(Clone, PartialEq, Eq)]
pub struct IgdControlDescriptor {
    service: IgdServiceKind,
    gateway: Ipv4Addr,
    port: u16,
    path_and_query: String,
}

impl std::fmt::Debug for IgdControlDescriptor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IgdControlDescriptor")
            .field("service", &self.service)
            .field("gateway", &"<redacted>")
            .field("port", &self.port)
            .field("path_and_query", &self.path_and_query)
            .finish()
    }
}

impl IgdControlDescriptor {
    pub fn service(&self) -> IgdServiceKind {
        self.service
    }

    pub fn gateway(&self) -> Ipv4Addr {
        self.gateway
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn path_and_query(&self) -> &str {
        &self.path_and_query
    }

    pub fn socket(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(self.gateway), self.port)
    }

    /// HTTP target for a later caller. This value is not written to a log here.
    pub fn control_target(&self) -> String {
        format!(
            "http://{}:{}{}",
            self.gateway, self.port, self.path_and_query
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IgdRefusal {
    Cancelled,
    Deadline,
    Bounded,
    Malformed,
    MalformedPort,
    WrongTarget,
    Redirect,
    Entity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IgdDiscovery {
    Found(IgdControlDescriptor),
    Unsupported,
    NotAdvertised,
    Refused(IgdRefusal),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IgdIoError {
    Unavailable,
    Cancelled,
    Deadline,
    Bounded,
    Malformed,
    Redirect,
}

pub trait IgdSearch {
    fn search(
        &mut self,
        destination: SocketAddr,
        request: &[u8],
        cancelled: &dyn Fn() -> bool,
        deadline_exceeded: &dyn Fn() -> bool,
    ) -> Result<Vec<Vec<u8>>, IgdIoError>;
}

pub trait IgdDocuments {
    fn get(
        &mut self,
        url: &str,
        socket: SocketAddr,
        cancelled: &dyn Fn() -> bool,
        deadline_exceeded: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, IgdIoError>;
}

pub struct HostSsdpSearch {
    interface_index: u32,
}

impl IgdSearch for HostSsdpSearch {
    fn search(
        &mut self,
        destination: SocketAddr,
        request: &[u8],
        cancelled: &dyn Fn() -> bool,
        deadline_exceeded: &dyn Fn() -> bool,
    ) -> Result<Vec<Vec<u8>>, IgdIoError> {
        exchange_ssdp(
            destination,
            self.interface_index,
            request,
            IGD_SEARCH_BUDGET,
            cancelled,
            deadline_exceeded,
        )
    }
}

pub struct HostIgdDocuments;

impl IgdDocuments for HostIgdDocuments {
    fn get(
        &mut self,
        url: &str,
        socket: SocketAddr,
        cancelled: &dyn Fn() -> bool,
        deadline_exceeded: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, IgdIoError> {
        let path = url
            .split_once("://")
            .and_then(|(_, rest)| rest.find('/').map(|index| &rest[index..]))
            .ok_or(IgdIoError::Malformed)?;
        let host = match socket {
            SocketAddr::V4(address) => format!("{}:{}", address.ip(), address.port()),
            SocketAddr::V6(_) => return Err(IgdIoError::Malformed),
        };
        bounded_http_get(socket, &host, path, cancelled, deadline_exceeded)
    }
}

pub fn discover_igd_from_routes(
    routes: &[RouteRecord],
    search: &mut dyn IgdSearch,
    documents: &mut dyn IgdDocuments,
    cancelled: &dyn Fn() -> bool,
    deadline_exceeded: &dyn Fn() -> bool,
) -> IgdDiscovery {
    match discover_loaded(routes, cancelled) {
        GatewayDiscovery::Selected(gateway) => {
            discover_igd(&gateway, search, documents, cancelled, deadline_exceeded)
        }
        GatewayDiscovery::Unsupported => IgdDiscovery::Unsupported,
        GatewayDiscovery::InvalidGateway => IgdDiscovery::Refused(IgdRefusal::WrongTarget),
        GatewayDiscovery::Cancelled => IgdDiscovery::Refused(IgdRefusal::Cancelled),
        GatewayDiscovery::Bounded => IgdDiscovery::Refused(IgdRefusal::Bounded),
    }
}

pub fn discover_igd_via_multicast(
    gateway: &SelectedGateway,
    documents: &mut dyn IgdDocuments,
    cancelled: &dyn Fn() -> bool,
    deadline_exceeded: &dyn Fn() -> bool,
) -> IgdDiscovery {
    let mut search = HostSsdpSearch {
        interface_index: gateway.interface_index(),
    };
    discover_igd(
        gateway,
        &mut search,
        documents,
        cancelled,
        deadline_exceeded,
    )
}

pub fn discover_igd(
    gateway: &SelectedGateway,
    search: &mut dyn IgdSearch,
    documents: &mut dyn IgdDocuments,
    cancelled: &dyn Fn() -> bool,
    deadline_exceeded: &dyn Fn() -> bool,
) -> IgdDiscovery {
    if cancelled() {
        return IgdDiscovery::Refused(IgdRefusal::Cancelled);
    }
    if deadline_exceeded() {
        return IgdDiscovery::Refused(IgdRefusal::Deadline);
    }
    let destination = SocketAddr::new(IpAddr::V4(IGD_SSDP_ADDRESS), IGD_SSDP_PORT);
    let replies = match search.search(
        destination,
        SSDP_MSEARCH.as_bytes(),
        cancelled,
        deadline_exceeded,
    ) {
        Ok(replies) => replies,
        Err(error) => return io_discovery(error),
    };
    if replies.len() > IGD_SSDP_MAX_REPLIES {
        return IgdDiscovery::Refused(IgdRefusal::Bounded);
    }
    let mut saw_wrong_target = false;
    let mut saw_bad_port = false;
    let mut saw_malformed = false;
    let mut fetches = 0usize;
    for reply in &replies {
        if cancelled() {
            return IgdDiscovery::Refused(IgdRefusal::Cancelled);
        }
        if deadline_exceeded() {
            return IgdDiscovery::Refused(IgdRefusal::Deadline);
        }
        if reply.len() > IGD_SSDP_MAX_BYTES {
            return IgdDiscovery::Refused(IgdRefusal::Bounded);
        }
        let location = match ssdp_location(gateway.gateway(), reply) {
            Ok(location) => location,
            Err(IgdRefusal::MalformedPort) => {
                return IgdDiscovery::Refused(IgdRefusal::MalformedPort);
            }
            Err(IgdRefusal::WrongTarget) => {
                saw_wrong_target = true;
                continue;
            }
            Err(IgdRefusal::Malformed) => {
                saw_malformed = true;
                continue;
            }
            Err(refusal) => return IgdDiscovery::Refused(refusal),
        };
        if fetches == IGD_MAX_DOCUMENT_FETCHES {
            return IgdDiscovery::Refused(IgdRefusal::Bounded);
        }
        fetches = fetches.saturating_add(1);
        let body = match documents.get(&location.url, location.socket, cancelled, deadline_exceeded)
        {
            Ok(body) => body,
            Err(IgdIoError::Malformed) => {
                saw_malformed = true;
                continue;
            }
            Err(error) => return io_discovery(error),
        };
        if body.len() > IGD_XML_MAX_BYTES {
            return IgdDiscovery::Refused(IgdRefusal::Bounded);
        }
        let candidates = match parse_device_xml(&body) {
            Ok(candidates) => candidates,
            Err(IgdRefusal::Malformed) => {
                saw_malformed = true;
                continue;
            }
            Err(refusal) => return IgdDiscovery::Refused(refusal),
        };
        match select_control(gateway.gateway(), &location.url, &candidates) {
            Ok(Some(descriptor)) => return IgdDiscovery::Found(descriptor),
            Ok(None) => {}
            Err(IgdRefusal::WrongTarget) => saw_wrong_target = true,
            Err(IgdRefusal::MalformedPort) => saw_bad_port = true,
            Err(refusal) => return IgdDiscovery::Refused(refusal),
        }
    }
    if saw_wrong_target {
        IgdDiscovery::Refused(IgdRefusal::WrongTarget)
    } else if saw_bad_port {
        IgdDiscovery::Refused(IgdRefusal::MalformedPort)
    } else if saw_malformed {
        IgdDiscovery::Refused(IgdRefusal::Malformed)
    } else {
        IgdDiscovery::NotAdvertised
    }
}

fn io_discovery(error: IgdIoError) -> IgdDiscovery {
    match error {
        IgdIoError::Unavailable => IgdDiscovery::Unsupported,
        IgdIoError::Cancelled => IgdDiscovery::Refused(IgdRefusal::Cancelled),
        IgdIoError::Deadline => IgdDiscovery::Refused(IgdRefusal::Deadline),
        IgdIoError::Bounded => IgdDiscovery::Refused(IgdRefusal::Bounded),
        IgdIoError::Malformed => IgdDiscovery::Refused(IgdRefusal::Malformed),
        IgdIoError::Redirect => IgdDiscovery::Refused(IgdRefusal::Redirect),
    }
}

struct ResolvedLocation {
    url: String,
    socket: SocketAddr,
}

#[derive(Debug, PartialEq, Eq)]
struct ServiceCandidate {
    service: IgdServiceKind,
    control_url: String,
}

fn ssdp_location(gateway: Ipv4Addr, reply: &[u8]) -> Result<ResolvedLocation, IgdRefusal> {
    if reply.contains(&0) {
        return Err(IgdRefusal::Malformed);
    }
    let text = std::str::from_utf8(reply).map_err(|_| IgdRefusal::Malformed)?;
    let mut lines = text.split(['\r', '\n']).filter(|line| !line.is_empty());
    let status = lines.next().ok_or(IgdRefusal::Malformed)?;
    if !(status.starts_with("HTTP/1.1 200") || status.starts_with("HTTP/1.0 200")) {
        return Err(IgdRefusal::Malformed);
    }
    let mut location = None;
    let mut search_target = None;
    let mut headers = 0usize;
    for line in lines {
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(IgdRefusal::Malformed);
        }
        headers = headers.saturating_add(1);
        if headers > 32 {
            return Err(IgdRefusal::Bounded);
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(IgdRefusal::Malformed);
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("LOCATION") {
            if location.is_some_and(|current: &str| current != value) {
                return Err(IgdRefusal::Malformed);
            }
            location = Some(value);
        } else if name.eq_ignore_ascii_case("ST") {
            search_target = Some(value);
        }
    }
    let location = location.ok_or(IgdRefusal::Malformed)?;
    let search_target = search_target.ok_or(IgdRefusal::Malformed)?;
    if !ssdp_target_is_igd(search_target) {
        return Err(IgdRefusal::Malformed);
    }
    validate_gateway_url(gateway, location)
}

fn ssdp_target_is_igd(value: &str) -> bool {
    value.contains("urn:schemas-upnp-org:device:InternetGatewayDevice")
        || value.contains(WAN_IP_V1)
        || value.contains(WAN_IP_V2)
        || value.contains(WAN_PPP_V1)
        || value.contains(WAN_PPP_V2)
}

fn select_control(
    gateway: Ipv4Addr,
    base: &str,
    candidates: &[ServiceCandidate],
) -> Result<Option<IgdControlDescriptor>, IgdRefusal> {
    let mut ip_connection = None;
    let mut ppp_connection = None;
    let mut saw_wrong_target = false;
    let mut saw_bad_port = false;
    for candidate in candidates {
        if ip_connection.is_some() {
            break;
        }
        match resolve_control(gateway, base, &candidate.control_url) {
            Ok(target) => match candidate.service {
                IgdServiceKind::WanIpConnection => ip_connection = Some(target),
                IgdServiceKind::WanPppConnection if ppp_connection.is_none() => {
                    ppp_connection = Some(target);
                }
                IgdServiceKind::WanPppConnection => {}
            },
            Err(IgdRefusal::WrongTarget) => saw_wrong_target = true,
            Err(IgdRefusal::MalformedPort) => saw_bad_port = true,
            Err(refusal) => return Err(refusal),
        }
    }
    if let Some(target) = ip_connection {
        return Ok(Some(descriptor_from(
            IgdServiceKind::WanIpConnection,
            gateway,
            target,
        )));
    }
    if let Some(target) = ppp_connection {
        return Ok(Some(descriptor_from(
            IgdServiceKind::WanPppConnection,
            gateway,
            target,
        )));
    }
    if saw_wrong_target {
        Err(IgdRefusal::WrongTarget)
    } else if saw_bad_port {
        Err(IgdRefusal::MalformedPort)
    } else {
        Ok(None)
    }
}

struct ValidatedTarget {
    port: u16,
    path_and_query: String,
}

fn descriptor_from(
    service: IgdServiceKind,
    gateway: Ipv4Addr,
    target: ValidatedTarget,
) -> IgdControlDescriptor {
    IgdControlDescriptor {
        service,
        gateway,
        port: target.port,
        path_and_query: target.path_and_query,
    }
}

fn resolve_control(
    gateway: Ipv4Addr,
    base: &str,
    control: &str,
) -> Result<ValidatedTarget, IgdRefusal> {
    if let Some(refusal) = reject_control_syntax(control) {
        return Err(refusal);
    }
    let joined = if control.contains("://") {
        control.to_owned()
    } else {
        let base = url::Url::parse(base).map_err(|_| IgdRefusal::Malformed)?;
        base.join(control)
            .map_err(|_| IgdRefusal::Malformed)?
            .to_string()
    };
    let location = validate_gateway_url(gateway, &joined)?;
    Ok(ValidatedTarget {
        port: location.socket.port(),
        path_and_query: location
            .url
            .split_once("://")
            .and_then(|(_, rest)| rest.find('/').map(|index| rest[index..].to_owned()))
            .ok_or(IgdRefusal::Malformed)?,
    })
}

fn reject_control_syntax(control: &str) -> Option<IgdRefusal> {
    if control.len() > CONTROL_LOCATION_MAX_BYTES {
        return Some(IgdRefusal::Bounded);
    }
    if control.starts_with("//")
        || control.contains('\\')
        || control.contains('@')
        || control
            .split(['/', '\\', '?'])
            .any(|segment| segment == "..")
        || control
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Some(IgdRefusal::WrongTarget);
    }
    if looks_like_bad_port(control) {
        return Some(IgdRefusal::MalformedPort);
    }
    None
}

fn validate_gateway_url(gateway: Ipv4Addr, raw: &str) -> Result<ResolvedLocation, IgdRefusal> {
    if raw.len() > CONTROL_LOCATION_MAX_BYTES {
        return Err(IgdRefusal::Bounded);
    }
    if raw.contains('@') || raw.contains('\\') || raw.contains(' ') {
        return Err(IgdRefusal::WrongTarget);
    }
    let url = match url::Url::parse(raw) {
        Ok(url) => url,
        Err(_) => {
            return Err(if looks_like_bad_port(raw) {
                IgdRefusal::MalformedPort
            } else {
                IgdRefusal::Malformed
            });
        }
    };
    if url.scheme() != "http" || !url.username().is_empty() || url.password().is_some() {
        return Err(IgdRefusal::WrongTarget);
    }
    if url.fragment().is_some() {
        return Err(IgdRefusal::Malformed);
    }
    let host = match url.host() {
        Some(url::Host::Ipv4(address)) if address == gateway => address,
        Some(url::Host::Ipv4(_)) => return Err(IgdRefusal::WrongTarget),
        _ => return Err(IgdRefusal::WrongTarget),
    };
    let Some(port) = url.port_or_known_default() else {
        return Err(IgdRefusal::MalformedPort);
    };
    if port == 0 {
        return Err(IgdRefusal::MalformedPort);
    }
    let path = url.path();
    if path.split('/').any(|segment| segment == "..") {
        return Err(IgdRefusal::WrongTarget);
    }
    let mut reconstructed = format!("http://{host}:{port}{path}");
    if let Some(query) = url.query() {
        if query.contains('@') || query.contains('\\') || query.bytes().any(|byte| byte == b' ') {
            return Err(IgdRefusal::WrongTarget);
        }
        reconstructed.push('?');
        reconstructed.push_str(query);
    }
    if reconstructed.len() > CONTROL_LOCATION_MAX_BYTES {
        return Err(IgdRefusal::Bounded);
    }
    Ok(ResolvedLocation {
        url: reconstructed,
        socket: SocketAddr::new(IpAddr::V4(host), port),
    })
}

fn looks_like_bad_port(raw: &str) -> bool {
    let Some(rest) = raw.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let Some((_, port)) = authority.rsplit_once(':') else {
        return false;
    };
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return true;
    }
    port.parse::<u16>().ok().is_none_or(|value| value == 0)
}

fn parse_device_xml(body: &[u8]) -> Result<Vec<ServiceCandidate>, IgdRefusal> {
    if body.len() > IGD_XML_MAX_BYTES {
        return Err(IgdRefusal::Bounded);
    }
    if body.contains(&0) {
        return Err(IgdRefusal::Malformed);
    }
    let text = std::str::from_utf8(body).map_err(|_| IgdRefusal::Malformed)?;
    let mut parser = XmlParser {
        input: text,
        index: 0,
        depth: 0,
        stack: Vec::new(),
        text_target: TextTarget::Ignore,
        buffer: String::new(),
        in_service: false,
        service_type: None,
        control_url: None,
        candidates: Vec::new(),
    };
    parser.parse()?;
    Ok(parser.candidates)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TextTarget {
    Ignore,
    ServiceType,
    ControlUrl,
}

struct Frame {
    name: String,
    target: TextTarget,
}

struct XmlParser<'a> {
    input: &'a str,
    index: usize,
    depth: usize,
    stack: Vec<Frame>,
    text_target: TextTarget,
    buffer: String,
    in_service: bool,
    service_type: Option<String>,
    control_url: Option<String>,
    candidates: Vec<ServiceCandidate>,
}

impl XmlParser<'_> {
    fn parse(&mut self) -> Result<(), IgdRefusal> {
        if let Some(stripped) = self.input.strip_prefix('\u{feff}') {
            self.input = stripped;
        }
        self.skip_ascii_whitespace();
        if self.rest().starts_with("<?") {
            self.skip_processing_instruction()?;
            self.skip_ascii_whitespace();
        }
        while self.index < self.input.len() {
            if self.rest().starts_with('<') {
                self.markup()?;
            } else {
                self.text()?;
            }
        }
        if !self.stack.is_empty() || self.in_service {
            return Err(IgdRefusal::Malformed);
        }
        Ok(())
    }

    fn rest(&self) -> &str {
        &self.input[self.index..]
    }

    fn markup(&mut self) -> Result<(), IgdRefusal> {
        let rest = self.rest();
        if rest.starts_with("<!--") {
            self.skip_comment()
        } else if rest.starts_with("<![") {
            Err(IgdRefusal::Malformed)
        } else if rest.starts_with("<!") {
            Err(IgdRefusal::Entity)
        } else if rest.starts_with("<?") {
            Err(IgdRefusal::Malformed)
        } else if rest.starts_with("</") {
            self.end_tag()
        } else {
            self.start_tag()
        }
    }

    fn skip_comment(&mut self) -> Result<(), IgdRefusal> {
        let rest = self.rest();
        let Some(end) = rest.find("-->") else {
            return Err(IgdRefusal::Malformed);
        };
        if end < 4 || rest[4..end].contains("--") {
            return Err(IgdRefusal::Malformed);
        }
        self.index = self.index.saturating_add(end).saturating_add(3);
        Ok(())
    }

    fn skip_processing_instruction(&mut self) -> Result<(), IgdRefusal> {
        let rest = self.rest();
        if !rest.starts_with("<?xml") {
            return Err(IgdRefusal::Malformed);
        }
        let Some(end) = rest.find("?>") else {
            return Err(IgdRefusal::Malformed);
        };
        if rest[2..end].contains('<') {
            return Err(IgdRefusal::Malformed);
        }
        self.index = self.index.saturating_add(end).saturating_add(2);
        Ok(())
    }

    fn start_tag(&mut self) -> Result<(), IgdRefusal> {
        self.index = self.index.saturating_add(1);
        let name = self.read_name()?;
        let self_closing = self.read_attributes()?;
        let local = local_name(&name);
        let target = match local {
            "serviceType" => TextTarget::ServiceType,
            "controlURL" => TextTarget::ControlUrl,
            _ => TextTarget::Ignore,
        };
        if local == "service" {
            if self.in_service {
                return Err(IgdRefusal::Malformed);
            }
            self.in_service = true;
            self.service_type = None;
            self.control_url = None;
        }
        if self_closing {
            if local == "service" {
                self.in_service = false;
            }
            return Ok(());
        }
        self.depth = self.depth.saturating_add(1);
        if self.depth > IGD_XML_MAX_DEPTH {
            return Err(IgdRefusal::Bounded);
        }
        if target != TextTarget::Ignore {
            if self.text_target != TextTarget::Ignore {
                return Err(IgdRefusal::Malformed);
            }
            self.text_target = target;
            self.buffer.clear();
        }
        self.stack.push(Frame { name, target });
        Ok(())
    }

    fn end_tag(&mut self) -> Result<(), IgdRefusal> {
        self.index = self.index.saturating_add(2);
        let name = self.read_name()?;
        self.skip_ascii_whitespace();
        if !self.rest().starts_with('>') {
            return Err(IgdRefusal::Malformed);
        }
        self.index = self.index.saturating_add(1);
        let frame = self.stack.pop().ok_or(IgdRefusal::Malformed)?;
        if frame.name != name {
            return Err(IgdRefusal::Malformed);
        }
        self.depth = self.depth.saturating_sub(1);
        if frame.target != TextTarget::Ignore {
            let text = std::mem::take(&mut self.buffer);
            let text = text.trim_matches(|character: char| character.is_ascii_whitespace());
            self.text_target = TextTarget::Ignore;
            if !text.is_empty() {
                match frame.target {
                    TextTarget::ServiceType => self.service_type = Some(text.to_owned()),
                    TextTarget::ControlUrl => self.control_url = Some(text.to_owned()),
                    TextTarget::Ignore => {}
                }
            }
        }
        if local_name(&name) == "service" {
            self.finish_service()?;
        }
        Ok(())
    }

    fn finish_service(&mut self) -> Result<(), IgdRefusal> {
        self.in_service = false;
        let service_type = self.service_type.take();
        let control_url = self.control_url.take();
        let Some(service_type) = service_type else {
            return Ok(());
        };
        let Some(control_url) = control_url else {
            return Ok(());
        };
        let Some(service) = service_kind(&service_type) else {
            return Ok(());
        };
        if self.candidates.len() == IGD_MAX_SERVICE_CANDIDATES {
            return Err(IgdRefusal::Bounded);
        }
        self.candidates.push(ServiceCandidate {
            service,
            control_url,
        });
        Ok(())
    }

    fn read_attributes(&mut self) -> Result<bool, IgdRefusal> {
        let mut attributes = 0usize;
        loop {
            self.skip_ascii_whitespace();
            let rest = self.rest();
            if rest.starts_with("/>") {
                self.index = self.index.saturating_add(2);
                return Ok(true);
            }
            if rest.starts_with('>') {
                self.index = self.index.saturating_add(1);
                return Ok(false);
            }
            if rest.is_empty() {
                return Err(IgdRefusal::Malformed);
            }
            attributes = attributes.saturating_add(1);
            if attributes > 16 {
                return Err(IgdRefusal::Bounded);
            }
            let _name = self.read_name()?;
            self.skip_ascii_whitespace();
            if !self.rest().starts_with('=') {
                return Err(IgdRefusal::Malformed);
            }
            self.index = self.index.saturating_add(1);
            self.skip_ascii_whitespace();
            self.read_attribute_value()?;
        }
    }

    fn read_attribute_value(&mut self) -> Result<(), IgdRefusal> {
        let rest = self.rest();
        let quote = rest.chars().next().ok_or(IgdRefusal::Malformed)?;
        if quote != '"' && quote != '\'' {
            return Err(IgdRefusal::Malformed);
        }
        self.index = self.index.saturating_add(quote.len_utf8());
        let start = self.index;
        while self.index < self.input.len() {
            let character = self.input[self.index..]
                .chars()
                .next()
                .ok_or(IgdRefusal::Malformed)?;
            if character == quote {
                let raw = &self.input[start..self.index];
                decode_text(raw, &mut String::new(), true)?;
                self.index = self.index.saturating_add(character.len_utf8());
                return Ok(());
            }
            if character == '<' {
                return Err(IgdRefusal::Malformed);
            }
            self.index = self.index.saturating_add(character.len_utf8());
        }
        Err(IgdRefusal::Malformed)
    }

    fn text(&mut self) -> Result<(), IgdRefusal> {
        let start = self.index;
        while self.index < self.input.len() && !self.rest().starts_with('<') {
            let character = self.input[self.index..]
                .chars()
                .next()
                .ok_or(IgdRefusal::Malformed)?;
            self.index = self.index.saturating_add(character.len_utf8());
        }
        let raw = &self.input[start..self.index];
        if self.text_target == TextTarget::Ignore {
            decode_text(raw, &mut String::new(), true)?;
        } else {
            decode_text(raw, &mut self.buffer, false)?;
            if self.buffer.len() > CONTROL_LOCATION_MAX_BYTES {
                return Err(IgdRefusal::Bounded);
            }
        }
        Ok(())
    }

    fn read_name(&mut self) -> Result<String, IgdRefusal> {
        let start = self.index;
        let rest = self.rest();
        let mut chars = rest.chars();
        let Some(first) = chars.next() else {
            return Err(IgdRefusal::Malformed);
        };
        if !first.is_ascii_alphabetic() && first != '_' {
            return Err(IgdRefusal::Malformed);
        }
        self.index = self.index.saturating_add(first.len_utf8());
        while let Some(character) = self.rest().chars().next() {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | ':') {
                self.index = self.index.saturating_add(character.len_utf8());
            } else {
                break;
            }
        }
        let name = &self.input[start..self.index];
        if name.is_empty() || name.len() > 64 {
            return Err(IgdRefusal::Malformed);
        }
        Ok(name.to_owned())
    }

    fn skip_ascii_whitespace(&mut self) {
        while let Some(character) = self.rest().chars().next() {
            if character.is_ascii_whitespace() {
                self.index = self.index.saturating_add(character.len_utf8());
            } else {
                break;
            }
        }
    }
}

fn local_name(name: &str) -> &str {
    name.rsplit_once(':')
        .map(|(_, local)| local)
        .unwrap_or(name)
}

fn service_kind(value: &str) -> Option<IgdServiceKind> {
    match value {
        WAN_IP_V1 | WAN_IP_V2 => Some(IgdServiceKind::WanIpConnection),
        WAN_PPP_V1 | WAN_PPP_V2 => Some(IgdServiceKind::WanPppConnection),
        _ => None,
    }
}

fn decode_text(raw: &str, output: &mut String, discard: bool) -> Result<(), IgdRefusal> {
    let bytes = raw.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'&' {
            let character = raw[index..].chars().next().ok_or(IgdRefusal::Malformed)?;
            if !discard {
                output.push(character);
            }
            index = index.saturating_add(character.len_utf8());
            continue;
        }
        let rest = &raw[index..];
        let Some(end) = rest.find(';') else {
            return Err(IgdRefusal::Entity);
        };
        if end > 8 {
            return Err(IgdRefusal::Entity);
        }
        let token = &rest[..=end];
        let character = match token {
            "&amp;" => '&',
            "&lt;" => '<',
            "&gt;" => '>',
            "&quot;" => '"',
            "&apos;" => '\'',
            _ => return Err(IgdRefusal::Entity),
        };
        if !discard {
            output.push(character);
        }
        index = index.saturating_add(token.len());
    }
    Ok(())
}

fn exchange_ssdp(
    destination: SocketAddr,
    interface_index: u32,
    request: &[u8],
    budget: Duration,
    cancelled: &dyn Fn() -> bool,
    deadline_exceeded: &dyn Fn() -> bool,
) -> Result<Vec<Vec<u8>>, IgdIoError> {
    if cancelled() {
        return Err(IgdIoError::Cancelled);
    }
    if deadline_exceeded() {
        return Err(IgdIoError::Deadline);
    }
    if request.is_empty() || request.len() > IGD_SSDP_MAX_BYTES {
        return Err(IgdIoError::Bounded);
    }
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .map_err(|_| IgdIoError::Unavailable)?;
    if destination.ip().is_multicast() && interface_index != 0 {
        bind_multicast_interface(&socket, interface_index)?;
    }
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|_| IgdIoError::Unavailable)?;
    socket
        .send_to(request, destination)
        .map_err(|_| IgdIoError::Unavailable)?;
    let mut replies = Vec::new();
    let mut buffer = [0u8; IGD_SSDP_MAX_BYTES + 1];
    let started = Instant::now();
    while started.elapsed() < budget && replies.len() < IGD_SSDP_MAX_REPLIES {
        if cancelled() {
            return Err(IgdIoError::Cancelled);
        }
        if deadline_exceeded() {
            return Err(IgdIoError::Deadline);
        }
        match socket.recv_from(&mut buffer) {
            Ok((0, _)) => continue,
            Ok((length, _)) if length > IGD_SSDP_MAX_BYTES => return Err(IgdIoError::Bounded),
            Ok((length, _)) => replies.push(buffer[..length].to_vec()),
            Err(error)
                if error.kind() == std::io::ErrorKind::TimedOut
                    || error.kind() == std::io::ErrorKind::WouldBlock =>
            {
                if !replies.is_empty() {
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(IgdIoError::Unavailable),
        }
    }
    Ok(replies)
}

fn bind_multicast_interface(socket: &UdpSocket, interface_index: u32) -> Result<(), IgdIoError> {
    let index = i32::try_from(interface_index).map_err(|_| IgdIoError::Unavailable)?;
    let request = libc::ip_mreqn {
        imr_multiaddr: libc::in_addr { s_addr: 0 },
        imr_address: libc::in_addr { s_addr: 0 },
        imr_ifindex: index,
    };
    // SAFETY: `socket` is a live UDP socket. `ip_mreqn` is a plain integer
    // struct, and the length passed to setsockopt matches that struct.
    let result = unsafe {
        libc::setsockopt(
            std::os::fd::AsRawFd::as_raw_fd(socket),
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_IF,
            &request as *const libc::ip_mreqn as *const libc::c_void,
            std::mem::size_of::<libc::ip_mreqn>() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(IgdIoError::Unavailable)
    }
}

fn bounded_http_get(
    socket: SocketAddr,
    host: &str,
    path_and_query: &str,
    cancelled: &dyn Fn() -> bool,
    deadline_exceeded: &dyn Fn() -> bool,
) -> Result<Vec<u8>, IgdIoError> {
    if cancelled() {
        return Err(IgdIoError::Cancelled);
    }
    if deadline_exceeded() {
        return Err(IgdIoError::Deadline);
    }
    if !path_and_query.starts_with('/')
        || path_and_query
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
        || host
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(IgdIoError::Malformed);
    }
    let mut stream = TcpStream::connect_timeout(&socket, IGD_HTTP_BUDGET)
        .map_err(|_| IgdIoError::Unavailable)?;
    stream
        .set_read_timeout(Some(IGD_HTTP_BUDGET))
        .map_err(|_| IgdIoError::Unavailable)?;
    stream
        .set_write_timeout(Some(IGD_HTTP_BUDGET))
        .map_err(|_| IgdIoError::Unavailable)?;
    let request =
        format!("GET {path_and_query} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if request.len() > CONTROL_MAX_BYTES {
        return Err(IgdIoError::Bounded);
    }
    stream
        .write_all(request.as_bytes())
        .map_err(|_| IgdIoError::Unavailable)?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 1024];
    let limit = 8 * 1024 + IGD_XML_MAX_BYTES;
    loop {
        if cancelled() {
            return Err(IgdIoError::Cancelled);
        }
        if deadline_exceeded() {
            return Err(IgdIoError::Deadline);
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(length) => {
                if raw.len().saturating_add(length) > limit {
                    return Err(IgdIoError::Bounded);
                }
                raw.extend_from_slice(&chunk[..length]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error)
                if error.kind() == std::io::ErrorKind::TimedOut
                    || error.kind() == std::io::ErrorKind::WouldBlock =>
            {
                return Err(IgdIoError::Deadline);
            }
            Err(_) => return Err(IgdIoError::Unavailable),
        }
    }
    parse_http_response(&raw)
}

fn parse_http_response(raw: &[u8]) -> Result<Vec<u8>, IgdIoError> {
    let text = std::str::from_utf8(raw).map_err(|_| IgdIoError::Malformed)?;
    let Some((head, body)) = text.split_once("\r\n\r\n") else {
        return Err(IgdIoError::Malformed);
    };
    let mut lines = head.split("\r\n");
    let status = lines.next().ok_or(IgdIoError::Malformed)?;
    let code = status
        .split_whitespace()
        .nth(1)
        .ok_or(IgdIoError::Malformed)?;
    if matches!(code, "301" | "302" | "303" | "307" | "308") {
        return Err(IgdIoError::Redirect);
    }
    if code != "200" {
        return Err(IgdIoError::Malformed);
    }
    let mut content_length = None;
    let mut headers = 0usize;
    for line in lines {
        headers = headers.saturating_add(1);
        if headers > 32 || line.starts_with(' ') || line.starts_with('\t') {
            return Err(IgdIoError::Malformed);
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(IgdIoError::Malformed);
        };
        if name.eq_ignore_ascii_case("Transfer-Encoding")
            && !value.trim().eq_ignore_ascii_case("identity")
        {
            return Err(IgdIoError::Malformed);
        }
        if name.eq_ignore_ascii_case("Content-Length") {
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| IgdIoError::Malformed)?,
            );
        }
    }
    if content_length.is_some_and(|length| length > IGD_XML_MAX_BYTES)
        || body.len() > IGD_XML_MAX_BYTES
    {
        return Err(IgdIoError::Bounded);
    }
    if let Some(length) = content_length {
        if body.len() != length {
            return Err(IgdIoError::Malformed);
        }
    }
    Ok(body.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    const DEVICE_XML: &str = include_str!("../../vectors/igd-wanip-device.xml");
    const ENTITY_XML: &str = include_str!("../../vectors/igd-adversarial-entities.xml");
    const EXTERNAL_XML: &str = include_str!("../../vectors/igd-external-control.xml");
    const LIMITS: &str = include_str!("../../vectors/igd-discovery-v1.json");

    fn never() -> bool {
        false
    }

    fn gateway() -> SelectedGateway {
        match discover_loaded(
            &[RouteRecord::new(
                Ipv4Addr::UNSPECIFIED,
                0,
                Ipv4Addr::new(192, 0, 2, 1),
                true,
                1,
            )],
            &never,
        ) {
            GatewayDiscovery::Selected(gateway) => gateway,
            other => panic!("expected a gateway, got {other:?}"),
        }
    }

    fn ssdp(location: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1\r\nLOCATION: {location}\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
        )
        .into_bytes()
    }

    struct ScriptedSearch {
        result: Result<Vec<Vec<u8>>, IgdIoError>,
        destination: Option<SocketAddr>,
        request: Vec<u8>,
        calls: usize,
    }

    impl IgdSearch for ScriptedSearch {
        fn search(
            &mut self,
            destination: SocketAddr,
            request: &[u8],
            _cancelled: &dyn Fn() -> bool,
            _deadline_exceeded: &dyn Fn() -> bool,
        ) -> Result<Vec<Vec<u8>>, IgdIoError> {
            self.calls = self.calls.saturating_add(1);
            self.destination = Some(destination);
            self.request = request.to_vec();
            self.result.clone()
        }
    }

    struct ScriptedDocs {
        body: Result<Vec<u8>, IgdIoError>,
        calls: Vec<String>,
    }

    impl IgdDocuments for ScriptedDocs {
        fn get(
            &mut self,
            url: &str,
            _socket: SocketAddr,
            _cancelled: &dyn Fn() -> bool,
            _deadline_exceeded: &dyn Fn() -> bool,
        ) -> Result<Vec<u8>, IgdIoError> {
            self.calls.push(url.to_owned());
            self.body.clone()
        }
    }

    fn search_of(result: Result<Vec<Vec<u8>>, IgdIoError>) -> ScriptedSearch {
        ScriptedSearch {
            result,
            destination: None,
            request: Vec::new(),
            calls: 0,
        }
    }

    fn docs_of(body: Result<Vec<u8>, IgdIoError>) -> ScriptedDocs {
        ScriptedDocs {
            body,
            calls: Vec::new(),
        }
    }

    #[test]
    fn limits_match_the_discovery_vector() {
        let limits: serde_json::Value = serde_json::from_str(LIMITS).unwrap();
        assert_eq!(limits["ssdpAddress"], IGD_SSDP_ADDRESS.to_string());
        assert_eq!(limits["ssdpPort"].as_u64(), Some(u64::from(IGD_SSDP_PORT)));
        assert_eq!(
            limits["ssdpMaxBytes"].as_u64(),
            Some(IGD_SSDP_MAX_BYTES as u64)
        );
        assert_eq!(
            limits["ssdpMaxReplies"].as_u64(),
            Some(IGD_SSDP_MAX_REPLIES as u64)
        );
        assert_eq!(
            limits["xmlMaxBytes"].as_u64(),
            Some(IGD_XML_MAX_BYTES as u64)
        );
        assert_eq!(
            limits["xmlMaxDepth"].as_u64(),
            Some(IGD_XML_MAX_DEPTH as u64)
        );
        assert_eq!(
            limits["controlUrlMaxBytes"].as_u64(),
            Some(CONTROL_LOCATION_MAX_BYTES as u64)
        );
        assert_eq!(
            limits["maxServiceCandidates"].as_u64(),
            Some(IGD_MAX_SERVICE_CANDIDATES as u64)
        );
        assert_eq!(
            limits["maxDocumentFetches"].as_u64(),
            Some(IGD_MAX_DOCUMENT_FETCHES as u64)
        );
        assert_eq!(
            limits["searchBudgetMs"].as_u64(),
            Some(u64::try_from(IGD_SEARCH_BUDGET.as_millis()).unwrap())
        );
        assert_eq!(
            limits["httpBudgetMs"].as_u64(),
            Some(u64::try_from(IGD_HTTP_BUDGET.as_millis()).unwrap())
        );
    }

    #[test]
    fn selected_gateway_xml_yields_a_wan_ip_descriptor_without_identifiers() {
        let gateway = gateway();
        let mut search = search_of(Ok(vec![ssdp("http://192.0.2.1:5000/rootDesc.xml")]));
        let mut documents = docs_of(Ok(DEVICE_XML.as_bytes().to_vec()));
        let found = discover_igd(&gateway, &mut search, &mut documents, &never, &never);
        let IgdDiscovery::Found(descriptor) = found else {
            panic!("expected a descriptor, got {found:?}");
        };
        assert_eq!(descriptor.service(), IgdServiceKind::WanIpConnection);
        assert_eq!(descriptor.gateway(), Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(descriptor.port(), 5000);
        assert_eq!(descriptor.path_and_query(), "/ctl/IPConn");
        assert_eq!(
            descriptor.control_target(),
            "http://192.0.2.1:5000/ctl/IPConn"
        );
        assert_eq!(
            search.destination,
            Some(SocketAddr::new(IpAddr::V4(IGD_SSDP_ADDRESS), IGD_SSDP_PORT))
        );
        assert_eq!(search.request, SSDP_MSEARCH.as_bytes());
        assert!(
            !search
                .request
                .windows(14)
                .any(|window| window == b"AddPortMapping")
        );
        assert_eq!(
            documents.calls,
            vec!["http://192.0.2.1:5000/rootDesc.xml".to_owned()]
        );
        let rendered = format!("{descriptor:?}");
        for secret in [
            "11111111",
            "secret-serial",
            "should-not-be-retained",
            "aaaaaaaa-bbbb",
            "WANIPConn1",
            "rootDesc",
            "<service",
        ] {
            assert!(
                !rendered.contains(secret),
                "{secret} leaked into {rendered}"
            );
        }
    }

    #[test]
    fn discovery_timeout_fetches_nothing() {
        let gateway = gateway();
        let mut search = search_of(Err(IgdIoError::Deadline));
        let mut documents = docs_of(Ok(DEVICE_XML.as_bytes().to_vec()));
        assert_eq!(
            discover_igd(&gateway, &mut search, &mut documents, &never, &never),
            IgdDiscovery::Refused(IgdRefusal::Deadline)
        );
        assert!(documents.calls.is_empty());
        let mut search = search_of(Ok(vec![ssdp("http://192.0.2.1/rootDesc.xml")]));
        assert_eq!(
            discover_igd(&gateway, &mut search, &mut documents, &never, &|| true),
            IgdDiscovery::Refused(IgdRefusal::Deadline)
        );
        assert_eq!(search.calls, 0);
    }

    #[test]
    fn missing_route_or_multicast_primitive_is_unsupported() {
        let mut search = search_of(Ok(vec![ssdp("http://192.0.2.1/rootDesc.xml")]));
        let mut documents = docs_of(Ok(DEVICE_XML.as_bytes().to_vec()));
        assert_eq!(
            discover_igd_from_routes(&[], &mut search, &mut documents, &never, &never),
            IgdDiscovery::Unsupported
        );
        assert_eq!(search.calls, 0);
        let invalid = [RouteRecord::new(
            Ipv4Addr::UNSPECIFIED,
            0,
            Ipv4Addr::new(127, 0, 0, 1),
            true,
            1,
        )];
        assert_eq!(
            discover_igd_from_routes(&invalid, &mut search, &mut documents, &never, &never),
            IgdDiscovery::Refused(IgdRefusal::WrongTarget)
        );
        assert_eq!(search.calls, 0);
        let gateway = gateway();
        let mut search = search_of(Err(IgdIoError::Unavailable));
        assert_eq!(
            discover_igd(&gateway, &mut search, &mut documents, &never, &never),
            IgdDiscovery::Unsupported
        );
        assert!(documents.calls.is_empty());
    }

    #[test]
    fn adversarial_xml_and_foreign_urls_do_not_produce_a_descriptor() {
        let gateway = gateway();
        let cases = [
            (
                Ok(vec![ssdp("http://192.0.2.1/rootDesc.xml")]),
                Ok(ENTITY_XML.as_bytes().to_vec()),
                IgdDiscovery::Refused(IgdRefusal::Entity),
            ),
            (
                Ok(vec![ssdp("http://192.0.2.1/rootDesc.xml")]),
                Ok(EXTERNAL_XML.as_bytes().to_vec()),
                IgdDiscovery::Refused(IgdRefusal::WrongTarget),
            ),
            (
                Ok(vec![ssdp("http://198.51.100.9/rootDesc.xml")]),
                Ok(DEVICE_XML.as_bytes().to_vec()),
                IgdDiscovery::Refused(IgdRefusal::WrongTarget),
            ),
            (
                Ok(vec![ssdp("http://10.1.2.50:80/rootDesc.xml")]),
                Ok(DEVICE_XML.as_bytes().to_vec()),
                IgdDiscovery::Refused(IgdRefusal::WrongTarget),
            ),
            (
                Ok(vec![ssdp("http://user:secret@192.0.2.1/rootDesc.xml")]),
                Ok(DEVICE_XML.as_bytes().to_vec()),
                IgdDiscovery::Refused(IgdRefusal::WrongTarget),
            ),
            (
                Ok(vec![ssdp("http://192.0.2.1:99999/rootDesc.xml")]),
                Ok(DEVICE_XML.as_bytes().to_vec()),
                IgdDiscovery::Refused(IgdRefusal::MalformedPort),
            ),
            (
                Ok(vec![ssdp("http://192.0.2.1/rootDesc.xml")]),
                Ok(br#"<?xml version="1.0"?><root><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>http://192.0.2.1:0/ctl</controlURL></service></root>"#.to_vec()),
                IgdDiscovery::Refused(IgdRefusal::MalformedPort),
            ),
            (
                Err(IgdIoError::Redirect),
                Ok(DEVICE_XML.as_bytes().to_vec()),
                IgdDiscovery::Refused(IgdRefusal::Redirect),
            ),
        ];
        for (index, (replies, body, expected)) in cases.into_iter().enumerate() {
            let mut search = search_of(replies);
            let mut documents = docs_of(body);
            let found = discover_igd(&gateway, &mut search, &mut documents, &never, &never);
            assert_eq!(found, expected, "case {index}");
            assert!(
                documents
                    .calls
                    .iter()
                    .all(|url| url.starts_with("http://192.0.2.1")),
                "fetched outside the gateway: {:?}",
                documents.calls
            );
        }
    }

    #[test]
    fn redirect_is_not_followed() {
        let gateway = gateway();
        let mut search = search_of(Ok(vec![ssdp("http://192.0.2.1/rootDesc.xml")]));
        let mut documents = docs_of(Err(IgdIoError::Redirect));
        assert_eq!(
            discover_igd(&gateway, &mut search, &mut documents, &never, &never),
            IgdDiscovery::Refused(IgdRefusal::Redirect)
        );
        assert_eq!(
            documents.calls,
            vec!["http://192.0.2.1:80/rootDesc.xml".to_owned()]
        );
    }

    #[test]
    fn deep_and_oversize_documents_are_bounded() {
        let gateway = gateway();
        let mut deep = String::from("<?xml version=\"1.0\"?>");
        for _ in 0..=IGD_XML_MAX_DEPTH {
            deep.push_str("<a>");
        }
        deep.push('t');
        for _ in 0..=IGD_XML_MAX_DEPTH {
            deep.push_str("</a>");
        }
        let mut search = search_of(Ok(vec![ssdp("http://192.0.2.1/rootDesc.xml")]));
        let mut documents = docs_of(Ok(deep.into_bytes()));
        assert_eq!(
            discover_igd(&gateway, &mut search, &mut documents, &never, &never),
            IgdDiscovery::Refused(IgdRefusal::Bounded)
        );
        let mut search = search_of(Ok(vec![ssdp("http://192.0.2.1/rootDesc.xml")]));
        let mut documents = docs_of(Ok(vec![b'a'; IGD_XML_MAX_BYTES + 1]));
        assert_eq!(
            discover_igd(&gateway, &mut search, &mut documents, &never, &never),
            IgdDiscovery::Refused(IgdRefusal::Bounded)
        );
        let mut oversized = ssdp("http://192.0.2.1/rootDesc.xml");
        oversized.extend(std::iter::repeat_n(b' ', IGD_SSDP_MAX_BYTES));
        let mut search = search_of(Ok(vec![oversized]));
        let mut documents = docs_of(Ok(DEVICE_XML.as_bytes().to_vec()));
        assert_eq!(
            discover_igd(&gateway, &mut search, &mut documents, &never, &never),
            IgdDiscovery::Refused(IgdRefusal::Bounded)
        );
        assert!(documents.calls.is_empty());
    }

    #[test]
    fn numeric_and_custom_entities_are_not_expanded() {
        let xml = b"<?xml version=\"1.0\"?><root><service>\
            <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
            <controlURL>http://192.0.2.1/&#47;ctl</controlURL></service></root>";
        assert_eq!(parse_device_xml(xml), Err(IgdRefusal::Entity));
        let attribute = b"<?xml version=\"1.0\"?><root><service id=\"&xxe;\">\
            <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
            <controlURL>/ctl</controlURL></service></root>";
        assert_eq!(parse_device_xml(attribute), Err(IgdRefusal::Entity));
    }

    #[test]
    fn a_commented_declaration_does_not_hide_a_real_one_or_reject_the_comment() {
        let commented = b"<?xml version=\"1.0\"?><!-- <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> -->\
            <root><service><serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>\
            <controlURL>/ctl/PPP</controlURL></service></root>";
        let candidates = parse_device_xml(commented).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].service, IgdServiceKind::WanPppConnection);
        assert_eq!(
            parse_device_xml(ENTITY_XML.as_bytes()),
            Err(IgdRefusal::Entity)
        );
    }

    #[test]
    fn ppp_only_device_stays_a_ppp_descriptor() {
        let gateway = gateway();
        let xml = b"<?xml version=\"1.0\"?><root><service>\
            <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:2</serviceType>\
            <controlURL>ctl/PPP</controlURL></service></root>";
        let mut search = search_of(Ok(vec![ssdp("http://192.0.2.1:5000/rootDesc.xml")]));
        let mut documents = docs_of(Ok(xml.to_vec()));
        let IgdDiscovery::Found(descriptor) =
            discover_igd(&gateway, &mut search, &mut documents, &never, &never)
        else {
            panic!("expected ppp");
        };
        assert_eq!(descriptor.service(), IgdServiceKind::WanPppConnection);
        assert_eq!(descriptor.path_and_query(), "/ctl/PPP");
        assert_eq!(descriptor.port(), 5000);
    }

    #[test]
    fn localhost_http_rejects_a_redirect_and_an_oversize_body() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 512];
            let _ = stream.read(&mut request);
            assert!(!request.windows(13).any(|window| window == b"198.51.100.9"));
            let response = b"HTTP/1.0 302 Found\r\nLocation: http://198.51.100.9/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(response);
        });
        let redirected = bounded_http_get(address, "127.0.0.1", "/rootDesc.xml", &never, &never);
        assert_eq!(redirected, Err(IgdIoError::Redirect));
        server.join().unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 256];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(&vec![b'x'; IGD_XML_MAX_BYTES + 1]);
        });
        let bounded = bounded_http_get(address, "127.0.0.1", "/rootDesc.xml", &never, &never);
        assert_eq!(bounded, Err(IgdIoError::Bounded));
        server.join().unwrap();
    }

    #[test]
    fn localhost_ssdp_exchange_is_bounded_and_does_not_wait_for_silence_after_a_reply() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = socket.local_addr().unwrap();
        let server = thread::spawn(move || {
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut buffer = [0u8; 2048];
            let (length, from) = socket.recv_from(&mut buffer).unwrap();
            assert!(buffer[..length].starts_with(b"M-SEARCH"));
            assert!(
                !buffer[..length]
                    .windows(14)
                    .any(|window| window == b"AddPortMapping")
            );
            let reply = b"HTTP/1.1 200 OK\r\n\r\n";
            socket.send_to(reply, from).unwrap();
        });
        let started = Instant::now();
        let replies = exchange_ssdp(
            address,
            0,
            SSDP_MSEARCH.as_bytes(),
            IGD_SEARCH_BUDGET,
            &never,
            &never,
        )
        .unwrap();
        assert_eq!(replies, vec![b"HTTP/1.1 200 OK\r\n\r\n".to_vec()]);
        assert!(started.elapsed() < Duration::from_millis(800));
        server.join().unwrap();

        assert_eq!(
            exchange_ssdp(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
                0,
                SSDP_MSEARCH.as_bytes(),
                Duration::from_millis(1),
                &|| true,
                &never,
            ),
            Err(IgdIoError::Cancelled)
        );
    }
}
