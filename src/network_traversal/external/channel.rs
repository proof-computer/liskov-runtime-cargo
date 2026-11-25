use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::http::HttpResponse;

pub(super) const MAX_LINE: usize = 64 * 1024;
pub(super) const POLL_MS: u64 = 20;
static TERMINATED: AtomicBool = AtomicBool::new(false);

extern "C" fn terminate(_: libc::c_int) {
    TERMINATED.store(true, Ordering::Relaxed);
}

pub(super) fn cancelled() -> bool {
    TERMINATED.load(Ordering::Relaxed)
}

pub(super) struct Signal(libc::sigaction);

impl Signal {
    pub(super) fn install() -> io::Result<Self> {
        // SAFETY: The action is initialized and the handler only sets a lock-free flag.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            let mut previous: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = terminate as *const () as libc::sighandler_t;
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(libc::SIGTERM, &action, &mut previous) == 0 {
                Ok(Self(previous))
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }
}

impl Drop for Signal {
    fn drop(&mut self) {
        // SAFETY: Restore the action previously returned by sigaction.
        unsafe { libc::sigaction(libc::SIGTERM, &self.0, std::ptr::null_mut()) };
    }
}

struct Nonblocking {
    fd: RawFd,
    flags: libc::c_int,
}

impl Nonblocking {
    fn new(fd: RawFd) -> io::Result<Self> {
        // SAFETY: The descriptor belongs to the fact-probe process. It stays open.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, flags })
    }

    fn ready(&self, events: libc::c_short, until: Option<Instant>, stop: bool) -> io::Result<()> {
        loop {
            if stop && cancelled() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let remaining = match until {
                Some(end) => end.saturating_duration_since(Instant::now()).as_millis(),
                None => u128::from(POLL_MS),
            };
            if remaining == 0 {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let mut pollfd = libc::pollfd {
                fd: self.fd,
                events,
                revents: 0,
            };
            // SAFETY: pollfd is initialized and valid for one entry.
            let result =
                unsafe { libc::poll(&mut pollfd, 1, remaining.min(POLL_MS.into()) as i32) };
            if result > 0 {
                return Ok(());
            }
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }
}

impl Drop for Nonblocking {
    fn drop(&mut self) {
        // SAFETY: The descriptor is still open and the flags were read from it.
        unsafe { libc::fcntl(self.fd, libc::F_SETFL, self.flags) };
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Reply {
    Response { status: u16, body: String },
}

#[derive(Serialize)]
struct Control<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    path: &'a str,
    body: String,
}

pub(super) struct Channel {
    // Drop the descriptors in reverse order if they share file status flags.
    output: Nonblocking,
    input: Nonblocking,
    buffered: Vec<u8>,
    pending: bool,
}

impl Channel {
    pub(super) fn stdio() -> io::Result<Self> {
        let input = Nonblocking::new(libc::STDIN_FILENO)?;
        let output = Nonblocking::new(libc::STDOUT_FILENO)?;
        Ok(Self {
            output,
            input,
            buffered: Vec::new(),
            pending: false,
        })
    }

    pub(super) fn request(&mut self) -> io::Result<Vec<u8>> {
        self.line(MAX_LINE, None)
    }

    fn line(&mut self, limit: usize, until: Option<Instant>) -> io::Result<Vec<u8>> {
        let mut checked = 0;
        loop {
            if cancelled() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            if until.is_some_and(|end| Instant::now() >= end) {
                return Err(io::ErrorKind::TimedOut.into());
            }
            if let Some(index) = self.buffered[checked..].iter().position(|&b| b == b'\n') {
                let end = checked + index;
                if end > limit {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let tail = self.buffered.split_off(end + 1);
                let mut line = std::mem::replace(&mut self.buffered, tail);
                line.pop();
                return Ok(line);
            }
            if self.buffered.len() > limit {
                return Err(io::ErrorKind::InvalidData.into());
            }
            checked = self.buffered.len();
            let mut bytes = [0; 4096];
            self.input.ready(libc::POLLIN, until, true)?;
            // SAFETY: bytes is valid for the length passed, and fd remains open.
            let count =
                unsafe { libc::read(self.input.fd, bytes.as_mut_ptr().cast(), bytes.len()) };
            if count == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            if count < 0 {
                let error = io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) {
                    continue;
                }
                return Err(error);
            }
            self.buffered.extend_from_slice(&bytes[..count as usize]);
        }
    }

    fn write(&mut self, value: &impl Serialize, until: Instant, stop: bool) -> io::Result<()> {
        let mut record = serde_json::to_vec(value)?;
        record.push(b'\n');
        let mut sent = 0;
        while sent < record.len() {
            // Once a line starts, finish it so cancellation can still emit a transcript.
            self.output
                .ready(libc::POLLOUT, Some(until), stop && sent == 0)?;
            let rest = &record[sent..];
            // SAFETY: rest is valid for the length passed, and fd remains open.
            let count = unsafe { libc::write(self.output.fd, rest.as_ptr().cast(), rest.len()) };
            if count < 0 {
                let error = io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) {
                    continue;
                }
                return Err(error);
            }
            if count == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            sent += count as usize;
        }
        Ok(())
    }

    pub(super) fn start(&mut self, path: &str, body: &[u8], until: Instant) -> io::Result<()> {
        if self.pending {
            return Err(io::ErrorKind::InvalidData.into());
        }
        // A failed or incomplete exchange poisons the channel so a late reply
        // cannot be taken as the answer to a later request.
        self.pending = true;
        self.write(
            &Control {
                kind: "control",
                path,
                body: STANDARD.encode(body),
            },
            until,
            true,
        )
    }

    pub(super) fn response(&mut self, limit: usize, until: Instant) -> io::Result<HttpResponse> {
        let line = self.line(
            base64::encoded_len(limit, true).expect("bounded response size") + 128,
            Some(until),
        )?;
        let Reply::Response { status, body } = serde_json::from_slice(&line)?;
        if body.len() > base64::encoded_len(limit, true).expect("bounded response size") {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let body = STANDARD
            .decode(body)
            .map_err(|_| io::ErrorKind::InvalidData)?;
        if body.len() > limit {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.pending = false;
        Ok(HttpResponse { status, body })
    }

    pub(super) fn transcript(&mut self, value: &impl Serialize) -> io::Result<()> {
        self.write(value, Instant::now() + Duration::from_secs(2), false)
    }
}
