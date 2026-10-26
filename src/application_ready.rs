//! Opt-in application readiness on Cargo `runtime.health` (ADR-0250).
//!
//! The helper opts in only when the signed runtime-env map contains
//! `LISKOV_APPLICATION_READINESS=v1`. It then gives the child
//! `LISKOV_APPLICATION_READY_FILE` inside the same `0700` directory as the
//! direct-discovery files, and every health beat carries `applicationReadiness`:
//! `pending` until that path is a regular file of at most 4 KiB, then `ready`.
//! The bytes are ignored. A symlink is not followed. Each child start removes
//! the file, so a restarted child is `pending` until it writes the file again.

use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Value, json};

use crate::discovery::direct::DirectPeerDiscovery;

pub const OPT_IN_ENV: &str = "LISKOV_APPLICATION_READINESS";
pub const OPT_IN_VALUE: &str = "v1";
pub const READY_FILE_ENV: &str = "LISKOV_APPLICATION_READY_FILE";
pub const READY_ATTR: &str = "applicationReadiness";
/// Same cap as a peer advertisement. Larger files stay `pending`.
pub const MAX_READY_BYTES: usize = 4 * 1024;

pub fn opted_in(runtime_environment: &std::collections::BTreeMap<String, String>) -> bool {
    runtime_environment.get(OPT_IN_ENV).map(String::as_str) == Some(OPT_IN_VALUE)
}

/// The signed opt-in, bound to the direct-discovery custody directory when
/// that directory exists.
pub struct ApplicationReady {
    peer: Option<Arc<DirectPeerDiscovery>>,
}

impl ApplicationReady {
    pub fn bind(peer: Arc<DirectPeerDiscovery>) -> Self {
        Self { peer: Some(peer) }
    }

    /// The signed map opted in and the private directory could not be created.
    /// Beats stay `pending`. The child is given no path.
    pub fn unavailable() -> Self {
        Self { peer: None }
    }

    pub fn path(&self) -> Option<PathBuf> {
        self.peer.as_ref().map(|peer| peer.application_ready_path())
    }

    /// A new child must not inherit the previous process's ready file.
    pub fn begin_child(&self) {
        if let Some(peer) = &self.peer {
            if peer.remove_application_ready().is_err() {
                eprintln!("liskov application readiness reset failed");
            }
        }
    }

    pub fn write_attr(&self, attrs: &mut Value) {
        if !attrs.is_object() {
            *attrs = json!({});
        }
        attrs[READY_ATTR] = json!(self.state());
    }

    fn state(&self) -> &'static str {
        match &self.peer {
            Some(peer) if file_is_ready(peer.open_application_ready()) => "ready",
            _ => "pending",
        }
    }
}

impl Drop for ApplicationReady {
    fn drop(&mut self) {
        if let Some(peer) = &self.peer {
            let _ = peer.remove_application_ready();
        }
    }
}

/// Advertisement open rules, without parsing. `Ok` from `open` has already
/// refused to follow a symlink (`O_NOFOLLOW`). A FIFO or other non-regular
/// node, and anything over [`MAX_READY_BYTES`], stays pending. The read
/// discards the bytes and closes the growth race the length check alone misses.
fn file_is_ready(opened: io::Result<File>) -> bool {
    let file = match opened {
        Ok(file) => file,
        Err(_) => return false,
    };
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return false,
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_READY_BYTES as u64 {
        return false;
    }
    let mut bytes = Vec::new();
    if file
        .take((MAX_READY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return false;
    }
    bytes.len() <= MAX_READY_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;

    fn peer() -> Arc<DirectPeerDiscovery> {
        Arc::new(
            DirectPeerDiscovery::create(&std::env::temp_dir(), "app", "job", "instance", false)
                .unwrap(),
        )
    }

    fn readiness(ready: &ApplicationReady) -> String {
        let mut attrs = json!({});
        ready.write_attr(&mut attrs);
        attrs[READY_ATTR].as_str().unwrap().to_owned()
    }

    #[test]
    fn only_the_exact_signed_literal_opts_in() {
        let mut map = std::collections::BTreeMap::new();
        assert!(!opted_in(&map));
        map.insert(OPT_IN_ENV.into(), "v1 ".into());
        assert!(!opted_in(&map));
        map.insert(OPT_IN_ENV.into(), "V1".into());
        assert!(!opted_in(&map));
        map.insert(OPT_IN_ENV.into(), OPT_IN_VALUE.into());
        assert!(opted_in(&map));
    }

    #[test]
    fn missing_symlink_fifo_and_oversize_stay_pending_and_a_regular_file_is_ready() {
        let peer = peer();
        let ready = ApplicationReady::bind(peer.clone());
        let path = ready.path().unwrap();
        assert_eq!(readiness(&ready), "pending");

        std::fs::write(&path, b"").unwrap();
        assert_eq!(readiness(&ready), "ready");
        std::fs::write(&path, vec![b'x'; MAX_READY_BYTES]).unwrap();
        assert_eq!(readiness(&ready), "ready");
        std::fs::write(&path, vec![b'x'; MAX_READY_BYTES + 1]).unwrap();
        assert_eq!(readiness(&ready), "pending");
        std::fs::remove_file(&path).unwrap();

        let target = path.with_extension("target");
        std::fs::write(&target, b"followed-would-be-ready").unwrap();
        symlink(&target, &path).unwrap();
        assert_eq!(readiness(&ready), "pending", "symlink is not followed");
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(&target).unwrap();

        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: c_path is a NUL-terminated path in the private directory this
        // test owns. mkfifo creates one node there and does not follow links.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert_eq!(readiness(&ready), "pending", "fifo is not a regular file");
        std::fs::remove_file(&path).unwrap();

        std::fs::write(&path, b"ignored").unwrap();
        ready.begin_child();
        assert!(!path.exists());
        assert_eq!(readiness(&ready), "pending");
    }

    #[test]
    fn unavailable_opt_in_has_no_path_and_stays_pending() {
        let ready = ApplicationReady::unavailable();
        assert!(ready.path().is_none());
        assert_eq!(readiness(&ready), "pending");
        ready.begin_child();
    }

    #[test]
    fn custody_drop_removes_a_ready_file_left_in_the_private_directory() {
        let peer = peer();
        let root = peer.application_ready_path().parent().unwrap().to_owned();
        std::fs::write(peer.application_ready_path(), b"ready").unwrap();
        drop(peer);
        assert!(!root.exists());
    }

    #[test]
    fn the_attr_keeps_the_full_direct_beat_within_32_scalars() {
        // Owner fixture is the fullest checked-in direct beat (27). The live
        // reader can also emit discoveryFailureCode and discoveryValidUntilMs
        // on that same beat. applicationReadiness is the one new scalar.
        let signed: Value = serde_json::from_str(include_str!(
            "../vectors/liskov-discovery-v2-signed-health-request.json"
        ))
        .unwrap();
        let mut attrs = signed["attrs"].clone();
        assert_eq!(attrs.as_object().unwrap().len(), 27);
        attrs["discoveryFailureCode"] = json!("unsupported");
        attrs["discoveryValidUntilMs"] = json!(1);
        attrs[READY_ATTR] = json!("pending");
        let object = attrs.as_object().unwrap();
        assert_eq!(object.len(), 30);
        assert!(object.len() <= 32);
        for value in object.values() {
            assert!(!value.is_array() && !value.is_object());
        }
    }
}
