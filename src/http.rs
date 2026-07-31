use std::io::Read;
use std::time::Duration;

use thiserror::Error;

pub const DEFAULT_MAX_HTTP_RESPONSE_BYTES: usize = 256 * 1024;
pub const HTTP_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

pub trait HttpClient: Send + Sync {
    fn post(&self, url: &str, body: &[u8]) -> Result<HttpResponse, HttpError>;
}

#[derive(Debug)]
pub struct UreqHttpClient {
    agent: ureq::Agent,
    max_response_bytes: usize,
}

impl UreqHttpClient {
    pub fn with_limits(timeout: Duration, max_response_bytes: usize) -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout(timeout)
                .redirects(0)
                .build(),
            max_response_bytes,
        }
    }
}

impl Default for UreqHttpClient {
    fn default() -> Self {
        Self::with_limits(HTTP_ATTEMPT_TIMEOUT, DEFAULT_MAX_HTTP_RESPONSE_BYTES)
    }
}

#[derive(Debug, Error)]
pub enum HttpError {
    #[error("HTTP transport failed")]
    Transport,
    #[error("HTTP response exceeded the size limit")]
    ResponseTooLarge,
}

impl HttpClient for UreqHttpClient {
    fn post(&self, url: &str, body: &[u8]) -> Result<HttpResponse, HttpError> {
        let result = self
            .agent
            .post(url)
            .set("accept", "application/json")
            .set("content-type", "application/json")
            .set(
                "user-agent",
                concat!("liskov-runtime-contact/", env!("CARGO_PKG_VERSION")),
            )
            .send_bytes(body);

        let (status, response) = match result {
            Ok(response) => (response.status(), response),
            Err(ureq::Error::Status(status, response)) => (status, response),
            Err(ureq::Error::Transport(_)) => return Err(HttpError::Transport),
        };
        let mut body = Vec::new();
        response
            .into_reader()
            .take(u64::try_from(self.max_response_bytes).unwrap_or(u64::MAX) + 1)
            .read_to_end(&mut body)
            .map_err(|_| HttpError::Transport)?;
        if body.len() > self.max_response_bytes {
            return Err(HttpError::ResponseTooLarge);
        }
        Ok(HttpResponse { status, body })
    }
}
