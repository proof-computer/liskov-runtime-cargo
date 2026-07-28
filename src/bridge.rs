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
}

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("BRIDGE_SOCKET must name a non-empty abstract Unix socket")]
    InvalidSocketName,
    #[error("could not construct the bridge socket address")]
    InvalidSocketAddress(#[source] std::io::Error),
    #[error("bridge connection failed")]
    Connect(#[source] std::io::Error),
    #[error("bridge request failed")]
    Write(#[source] std::io::Error),
    #[error("bridge response failed")]
    Read(#[source] std::io::Error),
    #[error("bridge response exceeded the size limit")]
    ResponseTooLarge,
    #[error("bridge response was not newline terminated")]
    MissingNewline,
    #[error("bridge response was not valid JSON")]
    InvalidJson(#[source] serde_json::Error),
    #[error("bridge response did not match JSON-RPC 2.0")]
    InvalidEnvelope,
    #[error("bridge returned an RPC error")]
    RpcError,
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
        let id = format!(
            "liskov-runtime-contact-{}",
            self.next_id.fetch_add(1, Ordering::Relaxed)
        );
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
            .set_read_timeout(Some(BRIDGE_TIMEOUT))
            .map_err(BridgeError::Connect)?;
        stream
            .set_write_timeout(Some(BRIDGE_TIMEOUT))
            .map_err(BridgeError::Connect)?;
        stream
            .write_all(&request_bytes)
            .map_err(BridgeError::Write)?;
        stream.flush().map_err(BridgeError::Write)?;

        let mut response_bytes = Vec::new();
        let mut reader = BufReader::new(stream)
            .take(u64::try_from(self.max_response_bytes).unwrap_or(u64::MAX) + 1);
        reader
            .read_until(b'\n', &mut response_bytes)
            .map_err(BridgeError::Read)?;
        if response_bytes.len() > self.max_response_bytes {
            return Err(BridgeError::ResponseTooLarge);
        }
        if response_bytes.last() != Some(&b'\n') {
            return Err(BridgeError::MissingNewline);
        }
        response_bytes.pop();

        let response: Value =
            serde_json::from_slice(&response_bytes).map_err(BridgeError::InvalidJson)?;
        if response["jsonrpc"] != json!("2.0") || response["id"] != json!(id) {
            return Err(BridgeError::InvalidEnvelope);
        }
        if response.get("error").is_some() {
            return Err(BridgeError::RpcError);
        }
        response
            .get("result")
            .cloned()
            .ok_or(BridgeError::InvalidEnvelope)
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
    fn frames_one_newline_delimited_request_with_matching_id() {
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
        assert_eq!(request["id"], "liskov-runtime-contact-1");
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
        assert!(matches!(error, BridgeError::RpcError));
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
        assert!(matches!(error, BridgeError::MissingNewline));
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
}
