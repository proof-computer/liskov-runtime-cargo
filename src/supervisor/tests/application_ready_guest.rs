use super::*;
use crate::bridge::{Bridge, BridgeError};
use crate::diagnostics::canonical_json_bytes;
use crate::http::{HttpClient, HttpError, HttpResponse};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;
use std::time::Duration;

const FIXTURE: &str = "LISKOV_APPLICATION_READY_FIXTURE";
const HOST_TMP: &str = "/data/user/0/liskov-11fh-processor/cache";
const TEST_NAME: &str = "supervisor::tests::application_ready_guest::guest_reports_pending_then_ready_and_pending_again_after_restart";

struct Signer {
    calls: Mutex<Vec<String>>,
}
impl Bridge for Signer {
    fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, BridgeError> {
        assert_eq!(method, "signer_sign");
        self.calls
            .lock()
            .unwrap()
            .push(params[0]["bytes"].as_str().unwrap().to_owned());
        Ok(json!({"bytes": "ab".repeat(64)}))
    }
}

struct Core {
    requests: Mutex<Vec<serde_json::Value>>,
    pending: String,
    ready: String,
    restarted: String,
}
impl HttpClient for Core {
    fn post(&self, _: &str, body: &[u8]) -> Result<HttpResponse, HttpError> {
        let request: serde_json::Value = serde_json::from_slice(body).unwrap();
        if request["stage"] == "runtime.health" {
            let attempt = request["attrs"]["processAttempt"].as_u64();
            match (attempt, request["attrs"]["applicationReadiness"].as_str()) {
                (Some(0), Some("pending")) => {
                    let _ = fs::write(&self.pending, b"1");
                }
                (Some(0), Some("ready")) => {
                    let _ = fs::write(&self.ready, b"1");
                }
                (Some(1), Some("pending")) => {
                    let _ = fs::write(&self.restarted, b"1");
                }
                _ => {}
            }
        }
        self.requests.lock().unwrap().push(request);
        Ok(HttpResponse {
            status: 200,
            body: Vec::new(),
        })
    }
}

#[test]
fn guest_reports_pending_then_ready_and_pending_again_after_restart() {
    if std::env::var_os(FIXTURE).is_none() {
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(FIXTURE, "1")
            .env("TMPDIR", HOST_TMP)
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let _lock = PROCESS_TEST_LOCK.lock().unwrap();
    let pid = std::process::id();
    let pending = format!("/tmp/liskov-app-ready-{pid}-pending");
    let ready_signal = format!("/tmp/liskov-app-ready-{pid}-ready");
    let restarted = format!("/tmp/liskov-app-ready-{pid}-restarted");
    let life = format!("/tmp/liskov-app-ready-{pid}-life");
    let _cleanup = Remove(vec![
        pending.clone(),
        ready_signal.clone(),
        restarted.clone(),
        life.clone(),
    ]);
    for path in [&pending, &ready_signal, &restarted, &life] {
        let _ = fs::remove_file(path);
    }

    let mut bound = bootstrap(json!({
        "mode": "on_failure",
        "restartLimit": {"kind": "attempts", "maxRestarts": 1},
        "serverTimeMs": 1,
        "scheduleEndMs": 180_001,
    }));
    bound.runtime_instance_id = "app-ready-721".into();
    assert!(initial_health_jitter(&bound.runtime_instance_id, 0) < Duration::from_secs(2));
    assert!(initial_health_jitter(&bound.runtime_instance_id, 1) < Duration::from_secs(2));
    let peer = prepare_direct_peer(&bound).unwrap();
    let ready = Arc::new(crate::application_ready::ApplicationReady::bind(
        peer.clone(),
    ));
    let root = ready.path().unwrap().parent().unwrap().to_owned();
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let signed = BTreeMap::from([
        (
            crate::application_ready::OPT_IN_ENV.into(),
            crate::application_ready::OPT_IN_VALUE.into(),
        ),
        (
            crate::application_ready::READY_FILE_ENV.into(),
            "/forged/ready".into(),
        ),
        ("APP_READY_PENDING".into(), pending.clone()),
        ("APP_READY_READY".into(), ready_signal.clone()),
        ("APP_READY_RESTARTED".into(), restarted.clone()),
        ("APP_READY_LIFE".into(), life.clone()),
    ]);
    let environment = discovery_environment(
        &signed,
        &bound,
        None,
        Some(peer.as_ref()),
        None,
        Some(ready.as_ref()),
    );
    assert_eq!(
        environment[crate::application_ready::READY_FILE_ENV],
        ready.path().unwrap().to_string_lossy()
    );
    let core = Arc::new(Core {
        requests: Mutex::new(Vec::new()),
        pending,
        ready: ready_signal,
        restarted,
    });
    let signer = Arc::new(Signer {
        calls: Mutex::new(Vec::new()),
    });
    let mut reporter = AsyncDiagnosticReporter::spawn_with_direct_peer(
        &bound,
        signer.clone(),
        core.clone(),
        None,
        Some(peer.clone()),
        Some(ready.clone()),
    )
    .unwrap();
    let child = r#"set -eu
        test "$LISKOV_APPLICATION_READINESS" = v1
        test -n "$LISKOV_APPLICATION_READY_FILE"
        test "$(dirname "$LISKOV_APPLICATION_READY_FILE")" = "$(dirname "$LISKOV_PEER_ADVERTISEMENT_FILE")"
        if test ! -f "$APP_READY_LIFE"; then
            i=0
            while test ! -f "$APP_READY_PENDING"; do
                i=$((i+1)); test "$i" -lt 800; sleep 0.05
            done
            test ! -e "$LISKOV_APPLICATION_READY_FILE"
            : > "$LISKOV_APPLICATION_READY_FILE"
            i=0
            while test ! -f "$APP_READY_READY"; do
                i=$((i+1)); test "$i" -lt 800; sleep 0.05
            done
            : > "$APP_READY_LIFE"
            exit 1
        fi
        test ! -e "$LISKOV_APPLICATION_READY_FILE"
        i=0
        while test ! -f "$APP_READY_RESTARTED"; do
            i=$((i+1)); test "$i" -lt 800; sleep 0.05
        done
        exit 0
    "#;
    assert_eq!(
        supervise_with_reporter_and_environment(
            &["/bin/sh".into(), "-c".into(), child.into()],
            &bound,
            Duration::ZERO,
            &environment,
            Some(&mut reporter),
            None,
            None,
            None,
            Vec::new(),
            Path::new(NO_THERMAL_CLASS),
            Path::new(NO_PROC)
        ),
        SupervisorExit::Code(0)
    );
    drop(reporter);
    let requests = core.requests.lock().unwrap();
    let health: Vec<_> = requests
        .iter()
        .filter(|request| request["stage"] == "runtime.health")
        .cloned()
        .collect::<Vec<_>>();
    drop(requests);
    let attempt0: Vec<_> = health
        .iter()
        .filter(|request| request["attrs"]["processAttempt"] == 0)
        .collect();
    let ready_at = attempt0
        .iter()
        .position(|request| request["attrs"]["applicationReadiness"] == "ready")
        .expect("a ready beat after the child writes the file");
    assert!(ready_at > 0, "a pending beat precedes ready");
    assert!(
        attempt0[..ready_at]
            .iter()
            .all(|request| request["attrs"]["applicationReadiness"] == "pending")
    );
    let attempt1: Vec<_> = health
        .iter()
        .filter(|request| request["attrs"]["processAttempt"] == 1)
        .collect();
    assert!(!attempt1.is_empty());
    assert!(
        attempt1
            .iter()
            .all(|request| request["attrs"]["applicationReadiness"] == "pending")
    );
    for request in &health {
        let attrs = request["attrs"].as_object().unwrap();
        assert!(attrs.len() <= 32);
        assert!(attrs["applicationReadiness"].is_string());
    }
    let mut unsigned = attempt0[ready_at].clone();
    unsigned.as_object_mut().unwrap().remove("signature");
    let canonical = hex::encode(canonical_json_bytes(&unsigned));
    assert!(
        signer
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|bytes| bytes == &canonical)
    );
    drop(ready);
    drop(peer);
    assert!(
        !root.exists(),
        "private state is cleaned through its creating boundary"
    );
}

struct Remove(Vec<String>);
impl Drop for Remove {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}
