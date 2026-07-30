use std::io::{BufRead, BufReader, Read, Write};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;

pub const DEFAULT_MAX_BRIDGE_RESPONSE_BYTES: usize = 64 * 1024;
const BRIDGE_TIMEOUT: Duration = Duration::from_secs(5);

pub trait Bridge {
    fn call(&self, method: &str, params: Value) -> Result<Value, BridgeError>;
}

#[derive(Debug)]
pub struct UnixBridge {
    socket_name: String,
    next_id: AtomicU64,
    max_response_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestIdStyle {
    Long,
    DocumentedShort,
}

impl UnixBridge {
    pub fn new(socket_name: impl Into<String>) -> Result<Self, BridgeError> {
        let socket_name = socket_name.into();
        if socket_name.is_empty() || socket_name.as_bytes().contains(&0) {
            return Err(BridgeError::InvalidSocketName);
        }
        Ok(Self {
            socket_name,
            next_id: AtomicU64::new(1),
            max_response_bytes: DEFAULT_MAX_BRIDGE_RESPONSE_BYTES,
        })
    }

    #[cfg(test)]
    fn with_max_response_bytes(
        socket_name: impl Into<String>,
        max_response_bytes: usize,
    ) -> Result<Self, BridgeError> {
        let mut bridge = Self::new(socket_name)?;
        bridge.max_response_bytes = max_response_bytes;
        Ok(bridge)
    }

    pub fn call_with_options(
        &self,
        method: &str,
        params: Value,
        id_style: RequestIdStyle,
        timeout: Duration,
    ) -> Result<Value, BridgeError> {
        let sequence = self.next_id.fetch_add(1, Ordering::Relaxed);
        let id = match id_style {
            RequestIdStyle::Long => format!("liskov-runtime-contact-{sequence}"),
            RequestIdStyle::DocumentedShort => sequence.to_string(),
        };
        let request = RpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id: id.clone(),
        };
        let mut request_bytes = serde_json::to_vec(&request).map_err(BridgeError::InvalidJson)?;
        request_bytes.push(b'\n');

        let address = SocketAddr::from_abstract_name(self.socket_name.as_bytes())
            .map_err(BridgeError::InvalidSocketAddress)?;
        let mut stream = UnixStream::connect_addr(&address).map_err(BridgeError::Connect)?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(BridgeError::TimeoutConfiguration)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(BridgeError::TimeoutConfiguration)?;
        stream
            .write_all(&request_bytes)
            .map_err(BridgeError::Write)?;
        stream.flush().map_err(BridgeError::Write)?;

        let mut response_bytes = Vec::new();
        let mut reader = BufReader::new(stream)
            .take(u64::try_from(self.max_response_bytes).unwrap_or(u64::MAX) + 1);
        match reader.read_until(b'\n', &mut response_bytes) {
            Ok(0) => return Err(BridgeError::Eof),
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(BridgeError::Timeout);
            }
            Err(error) => return Err(BridgeError::Read(error)),
        }
        if response_bytes.len() > self.max_response_bytes {
            return Err(BridgeError::ResponseTooLarge);
        }
        if response_bytes.last() != Some(&b'\n') {
            return Err(BridgeError::Eof);
        }
        response_bytes.pop();

        let response: Value =
            serde_json::from_slice(&response_bytes).map_err(BridgeError::InvalidJson)?;
        if response["jsonrpc"] != json!("2.0") {
            return Err(BridgeError::JsonRpcVersion);
        }
        if response["id"] != json!(id) {
            return Err(BridgeError::IdMismatch);
        }
        if let Some(error) = response.get("error") {
            let code = error
                .get("code")
                .and_then(Value::as_i64)
                .and_then(|code| i32::try_from(code).ok());
            return Err(BridgeError::RpcError { code });
        }
        response
            .get("result")
            .cloned()
            .ok_or(BridgeError::MissingResult)
    }
}

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("BRIDGE_SOCKET must name a non-empty abstract Unix socket")]
    InvalidSocketName,
    #[error("could not construct the bridge socket address")]
    InvalidSocketAddress(#[source] std::io::Error),
    #[error("bridge connection failed")]
    Connect(#[source] std::io::Error),
    #[error("bridge timeout configuration failed")]
    TimeoutConfiguration(#[source] std::io::Error),
    #[error("bridge request failed")]
    Write(#[source] std::io::Error),
    #[error("bridge response failed")]
    Read(#[source] std::io::Error),
    #[error("bridge response timed out")]
    Timeout,
    #[error("bridge response ended before a complete reply")]
    Eof,
    #[error("bridge response exceeded the size limit")]
    ResponseTooLarge,
    #[error("bridge response was not valid JSON")]
    InvalidJson(#[source] serde_json::Error),
    #[error("bridge response did not use JSON-RPC 2.0")]
    JsonRpcVersion,
    #[error("bridge response id did not match the request")]
    IdMismatch,
    #[error("bridge returned an RPC error")]
    RpcError { code: Option<i32> },
    #[error("bridge response omitted result")]
    MissingResult,
}

impl BridgeError {
    pub fn failure_code(&self) -> &'static str {
        match self {
            Self::InvalidSocketName | Self::InvalidSocketAddress(_) => "bridge_socket_construction",
            Self::Connect(_) => "bridge_connect",
            Self::TimeoutConfiguration(_) => "bridge_timeout_configuration",
            Self::Write(_) => "bridge_write",
            Self::Read(_) => "bridge_read",
            Self::Timeout => "bridge_timeout",
            Self::Eof => "bridge_eof",
            Self::ResponseTooLarge => "bridge_reply_oversized",
            Self::InvalidJson(_) => "bridge_json",
            Self::JsonRpcVersion => "bridge_jsonrpc_version",
            Self::IdMismatch => "bridge_id_mismatch",
            Self::RpcError { .. } => "bridge_rpc_error",
            Self::MissingResult => "bridge_missing_result",
        }
    }

    pub fn rpc_code(&self) -> Option<i32> {
        match self {
            Self::RpcError { code } => *code,
            _ => None,
        }
    }
}

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    method: &'a str,
    params: Value,
    id: String,
}

impl Bridge for UnixBridge {
    fn call(&self, method: &str, params: Value) -> Result<Value, BridgeError> {
        self.call_with_options(
            method,
            params,
            RequestIdStyle::DocumentedShort,
            BRIDGE_TIMEOUT,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    use super::*;

    static SOCKET_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn serve_once<F>(response: F) -> (String, thread::JoinHandle<Value>)
    where
        F: FnOnce(&Value) -> Vec<u8> + Send + 'static,
    {
        let socket_name = format!(
            "liskov-runtime-contact-test-{}-{}",
            std::process::id(),
            SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let address = SocketAddr::from_abstract_name(socket_name.as_bytes()).unwrap();
        let listener = UnixListener::bind_addr(&address).unwrap();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            let mut reader = BufReader::new(stream);
            reader.read_line(&mut line).unwrap();
            let request: Value = serde_json::from_str(line.trim_end()).unwrap();
            let bytes = response(&request);
            reader.get_mut().write_all(&bytes).unwrap();
            request
        });
        (socket_name, handle)
    }

    #[test]
    fn frames_one_newline_delimited_request_with_processor_compatible_id() {
        let (socket_name, handle) = serve_once(|request| {
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "result": {"id": "job-1"},
                "id": request["id"],
            }))
            .unwrap()
            .into_iter()
            .chain([b'\n'])
            .collect()
        });

        let result = UnixBridge::new(socket_name)
            .unwrap()
            .call("deployment_id", json!([]))
            .unwrap();
        assert_eq!(result, json!({"id": "job-1"}));

        let request = handle.join().unwrap();
        assert_eq!(request["jsonrpc"], "2.0");
        assert_eq!(request["method"], "deployment_id");
        assert_eq!(request["params"], json!([]));
        assert_eq!(request["id"], "1");
    }

    #[test]
    fn processor_compatible_id_is_a_unique_decimal_uint_after_prior_calls() {
        let (socket_name, handle) = serve_once(|request| {
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "result": {"version": "1.25.1"},
                "id": request["id"],
            }))
            .unwrap()
            .into_iter()
            .chain([b'\n'])
            .collect()
        });
        let bridge = UnixBridge::new(socket_name).unwrap();
        bridge.next_id.store(4, Ordering::Relaxed);
        bridge
            .call_with_options(
                "processor_version",
                json!([]),
                RequestIdStyle::DocumentedShort,
                Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(handle.join().unwrap()["id"], "4");
    }

    #[test]
    fn classifies_processor_raw_rejection_of_long_id_as_invalid_json() {
        let (socket_name, handle) = serve_once(|_| b"Invalid Request\n".to_vec());
        let bridge = UnixBridge::new(socket_name).unwrap();
        let error = bridge
            .call_with_options(
                "signer_sign",
                json!([{"curve": "ed25519", "bytes": "00"}]),
                RequestIdStyle::Long,
                Duration::from_secs(1),
            )
            .unwrap_err();
        assert!(matches!(error, BridgeError::InvalidJson(_)));
        assert_eq!(error.failure_code(), "bridge_json");
        assert_eq!(handle.join().unwrap()["id"], "liskov-runtime-contact-1");
    }

    #[test]
    fn rejects_rpc_errors_without_exposing_the_reply() {
        let (socket_name, handle) = serve_once(|request| {
            format!(
                "{{\"jsonrpc\":\"2.0\",\"error\":{{\"code\":-32000,\"message\":\"secret\"}},\"id\":{}}}\n",
                serde_json::to_string(&request["id"]).unwrap()
            )
            .into_bytes()
        });
        let error = UnixBridge::new(socket_name)
            .unwrap()
            .call("deployment_id", json!([]))
            .unwrap_err();
        assert!(matches!(
            error,
            BridgeError::RpcError { code: Some(-32000) }
        ));
        handle.join().unwrap();
    }

    #[test]
    fn rejects_missing_newline() {
        let (socket_name, handle) = serve_once(|request| {
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "result": {},
                "id": request["id"],
            }))
            .unwrap()
        });
        let error = UnixBridge::new(socket_name)
            .unwrap()
            .call("deployment_id", json!([]))
            .unwrap_err();
        assert!(matches!(error, BridgeError::Eof));
        handle.join().unwrap();
    }

    #[test]
    fn rejects_oversized_responses() {
        let (socket_name, handle) = serve_once(|_| vec![b'x'; 33]);
        let error = UnixBridge::with_max_response_bytes(socket_name, 32)
            .unwrap()
            .call("deployment_id", json!([]))
            .unwrap_err();
        assert!(matches!(error, BridgeError::ResponseTooLarge));
        handle.join().unwrap();
    }

    #[test]
    fn separates_jsonrpc_version_id_rpc_code_and_missing_result() {
        let cases = [
            (
                json!({"jsonrpc": "1.0", "result": {}, "id": "unused"}),
                "bridge_jsonrpc_version",
            ),
            (
                json!({"jsonrpc": "2.0", "result": {}, "id": "wrong"}),
                "bridge_id_mismatch",
            ),
            (
                json!({"jsonrpc": "2.0", "error": {"code": -32601}, "id": "unused"}),
                "bridge_rpc_error",
            ),
            (
                json!({"jsonrpc": "2.0", "id": "unused"}),
                "bridge_missing_result",
            ),
        ];
        for (mut response, expected) in cases {
            let (socket_name, handle) = serve_once(move |request| {
                if response["id"] == "unused" {
                    response["id"] = request["id"].clone();
                }
                serde_json::to_vec(&response)
                    .unwrap()
                    .into_iter()
                    .chain([b'\n'])
                    .collect()
            });
            let error = UnixBridge::new(socket_name)
                .unwrap()
                .call("processor_version", json!([]))
                .unwrap_err();
            assert_eq!(error.failure_code(), expected);
            if expected == "bridge_rpc_error" {
                assert_eq!(error.rpc_code(), Some(-32601));
            }
            handle.join().unwrap();
        }
    }

    #[test]
    fn failure_codes_cover_the_closed_bridge_taxonomy() {
        let io_error = || std::io::Error::other("not exposed");
        let json_error = || serde_json::from_slice::<Value>(b"{").unwrap_err();
        let cases = [
            (BridgeError::InvalidSocketName, "bridge_socket_construction"),
            (
                BridgeError::InvalidSocketAddress(io_error()),
                "bridge_socket_construction",
            ),
            (BridgeError::Connect(io_error()), "bridge_connect"),
            (
                BridgeError::TimeoutConfiguration(io_error()),
                "bridge_timeout_configuration",
            ),
            (BridgeError::Write(io_error()), "bridge_write"),
            (BridgeError::Read(io_error()), "bridge_read"),
            (BridgeError::Timeout, "bridge_timeout"),
            (BridgeError::Eof, "bridge_eof"),
            (BridgeError::ResponseTooLarge, "bridge_reply_oversized"),
            (BridgeError::InvalidJson(json_error()), "bridge_json"),
            (BridgeError::JsonRpcVersion, "bridge_jsonrpc_version"),
            (BridgeError::IdMismatch, "bridge_id_mismatch"),
            (BridgeError::RpcError { code: None }, "bridge_rpc_error"),
            (BridgeError::MissingResult, "bridge_missing_result"),
        ];
        for (error, code) in cases {
            assert_eq!(error.failure_code(), code);
        }
    }
}
