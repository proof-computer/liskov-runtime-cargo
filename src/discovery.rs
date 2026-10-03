//! A private, atomically replaced advisory service directory for the workload.
use crate::protocol::{RuntimeAccessBootstrap, RuntimeBootstrapResponse};
use serde_json::Value;
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicI64, Ordering},
};

pub const MAX_DISCOVERY_BYTES: usize = 512 * 1024;
pub const DISCOVERY_FILE_ENV: &str = "LISKOV_DISCOVERY_FILE";
pub const PEER_PROXY_ENV: &str = "LISKOV_PEER_PROXY";

pub struct DiscoveryFile {
    root: PathBuf,
    application_uid: String,
    job_id: String,
    runtime_instance_id: String,
    last_success: AtomicI64,
    failed: AtomicBool,
}
impl DiscoveryFile {
    pub fn for_bootstrap(bootstrap: &RuntimeBootstrapResponse) -> io::Result<Option<Self>> {
        if !matches!(&bootstrap.access, Some(RuntimeAccessBootstrap::Tailscale(a)) if !a.publications.is_empty())
        {
            return Ok(None);
        }
        Self::create(
            &std::env::temp_dir(),
            &bootstrap.application_uid,
            &bootstrap.job_id,
            &bootstrap.runtime_instance_id,
        )
        .map(Some)
    }
    pub(crate) fn create(
        parent: &Path,
        application_uid: &str,
        job_id: &str,
        runtime_instance_id: &str,
    ) -> io::Result<Self> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        let root = parent.join(format!("liskov-discovery-{}", hex::encode(random)));
        DirBuilder::new().mode(0o700).create(&root)?;
        Ok(Self {
            root,
            application_uid: application_uid.into(),
            job_id: job_id.into(),
            runtime_instance_id: runtime_instance_id.into(),
            last_success: AtomicI64::new(0),
            failed: AtomicBool::new(false),
        })
    }
    pub fn path(&self) -> PathBuf {
        self.root.join("discovery.json")
    }
    pub fn request_attrs(&self, attrs: &mut Value) {
        if !attrs.is_object() {
            *attrs = serde_json::json!({});
        }
        attrs["discoveryVersion"] = 1.into();
        attrs["discoveryLastSuccessAtMs"] = self.last_success.load(Ordering::Acquire).into();
        attrs["discoveryRefreshFailed"] = self.failed.load(Ordering::Acquire).into();
    }
    pub fn unavailable(&self) {
        self.failed.store(true, Ordering::Release);
    }
    pub fn accept_response(&self, body: &[u8]) -> io::Result<()> {
        let result = self.accept(body);
        self.failed.store(result.is_err(), Ordering::Release);
        result
    }
    fn accept(&self, body: &[u8]) -> io::Result<()> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid discovery response");
        if body.len() > MAX_DISCOVERY_BYTES + 16 * 1024 {
            return Err(invalid());
        }
        let response: Value = serde_json::from_slice(body).map_err(|_| invalid())?;
        if response["ok"] != true {
            return Err(invalid());
        }
        let snapshot = &response["discovery"];
        validate_snapshot(snapshot).map_err(|_| invalid())?;
        if snapshot["applicationUid"] != self.application_uid
            || snapshot["self"]["jobId"] != self.job_id
            || snapshot["self"]["runtimeInstanceId"] != self.runtime_instance_id
        {
            return Err(invalid());
        }
        let observed = snapshot["observedAtMs"].as_i64().ok_or_else(invalid)?;
        if observed < self.last_success.load(Ordering::Acquire) {
            return Err(invalid());
        }
        let bytes = serde_json::to_vec(snapshot).map_err(|_| invalid())?;
        if bytes.len() > MAX_DISCOVERY_BYTES {
            return Err(invalid());
        }
        let temp = self.root.join("next.json");
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temp, self.path())
        })();
        if result.is_err() && temp.exists() {
            fs::remove_file(&temp)?;
        }
        result?;
        self.last_success.store(observed, Ordering::Release);
        Ok(())
    }
}
impl Drop for DiscoveryFile {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.root) {
            eprintln!("liskov discovery cleanup failed: {:?}", error.kind());
        }
    }
}

/// Shared wire checks, independent of filesystem or runtime identity.
pub fn validate_snapshot(v: &Value) -> Result<(), &'static str> {
    fn text(v: &Value) -> bool {
        v.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 512)
    }
    if v["schema"] != "liskov.discovery.v1"
        || !text(&v["applicationUid"])
        || !text(&v["self"]["jobId"])
        || !text(&v["self"]["runtimeInstanceId"])
        || !text(&v["revision"])
        || v["observedAtMs"].as_i64().is_none_or(|n| n < 0)
    {
        return Err("identity");
    }
    let peers = v["peers"]
        .as_array()
        .filter(|p| p.len() <= 256)
        .ok_or("peers")?;
    let mut identities = std::collections::BTreeSet::new();
    for peer in peers {
        if !text(&peer["jobId"])
            || !text(&peer["instanceId"])
            || !identities.insert(peer["instanceId"].as_str().unwrap())
        {
            return Err("peer identity");
        }
        let services = peer["services"]
            .as_array()
            .filter(|s| s.len() <= 32)
            .ok_or("services")?;
        let mut names = std::collections::BTreeSet::new();
        let mut total = 0;
        for service in services {
            if !text(&service["name"])
                || !names.insert(service["name"].as_str().unwrap())
                || service["protocol"] != "http"
            {
                return Err("service");
            }
            let endpoints = service["endpoints"].as_array().ok_or("endpoints")?;
            total += endpoints.len();
            if total > 32 {
                return Err("endpoint bound");
            }
            let mut names = std::collections::BTreeSet::new();
            for e in endpoints {
                if !text(&e["name"])
                    || !names.insert(e["name"].as_str().unwrap())
                    || e["provider"] != "tailscale"
                    || !matches!(
                        e["state"].as_str(),
                        Some("pending" | "published" | "ready" | "degraded")
                    )
                {
                    return Err("endpoint");
                }
                if !e["observedAtMs"].is_null() && e["observedAtMs"].as_i64().is_none_or(|n| n < 0)
                {
                    return Err("endpoint time");
                }
                if let Some(raw) = e["url"].as_str() {
                    let url = url::Url::parse(raw).map_err(|_| "url")?;
                    if url.scheme() != "http"
                        || !url.username().is_empty()
                        || url.password().is_some()
                        || !url.host_str().is_some_and(|h| h.ends_with(".ts.net"))
                        || url.query().is_some()
                        || url.fragment().is_some()
                        || url.path() != "/"
                    {
                        return Err("url");
                    }
                } else if !e["url"].is_null() || e["state"] == "ready" || e["state"] == "published"
                {
                    return Err("url");
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn response(at: i64) -> Value {
        json!({"ok":true,"discovery":{
        "schema":"liskov.discovery.v1","applicationUid":"app","self":{"jobId":"a","runtimeInstanceId":"nonce"},
        "revision":"r1","observedAtMs":at,"peers":[]}})
    }

    #[test]
    fn accepts_shared_owner_wire_fixture() {
        let v: Value =
            serde_json::from_str(include_str!("../contracts/liskov-discovery-v1.json")).unwrap();
        validate_snapshot(&v).unwrap();
    }
    #[test]
    fn atomic_file_preserves_last_good_on_missing_foreign_older_or_invalid_response() {
        let file = DiscoveryFile::create(&std::env::temp_dir(), "app", "a", "nonce").unwrap();
        assert!(!file.path().exists());
        file.accept_response(&serde_json::to_vec(&response(100)).unwrap())
            .unwrap();
        let original = fs::read(file.path()).unwrap();
        for bad in [json!({"ok":true}), response(99), {
            let mut v = response(101);
            v["discovery"]["self"]["runtimeInstanceId"] = "other".into();
            v
        }] {
            assert!(
                file.accept_response(&serde_json::to_vec(&bad).unwrap())
                    .is_err()
            );
            assert_eq!(fs::read(file.path()).unwrap(), original);
        }
        file.accept_response(&serde_json::to_vec(&response(101)).unwrap())
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(file.path()).unwrap()).unwrap()["observedAtMs"],
            101
        );
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(file.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
