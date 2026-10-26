use super::*;
use crate::bridge::{Bridge, BridgeError};
use crate::diagnostics::canonical_json_bytes;
use crate::http::{HttpClient, HttpError, HttpResponse};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

const FIXTURE: &str = "LISKOV_GUEST_DIRECT_FIXTURE";
const HOST_TMP: &str = "/data/user/0/liskov-11fh-processor/cache";
const TEST_NAME: &str = "supervisor::tests::guest_direct_handoff::guest_private_startup_handoff_and_signed_advertisement";

#[derive(Default)]
struct Signer {
    calls: Mutex<Vec<serde_json::Value>>,
}
impl Bridge for Signer {
    fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, BridgeError> {
        assert_eq!(method, "signer_sign");
        self.calls.lock().unwrap().push(params);
        Ok(json!({"bytes": "ab".repeat(64)}))
    }
}
#[derive(Default)]
struct Core {
    requests: Mutex<Vec<serde_json::Value>>,
}
impl HttpClient for Core {
    fn post(&self, _: &str, body: &[u8]) -> Result<HttpResponse, HttpError> {
        let request: serde_json::Value = serde_json::from_slice(body).unwrap();
        self.requests.lock().unwrap().push(request.clone());
        if request["attrs"]["discoveryVersion"] != 2 {
            return Ok(HttpResponse {
                status: 200,
                body: Vec::new(),
            });
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        Ok(HttpResponse {
            status: 200,
            body: serde_json::to_vec(&json!({"ok":true,"discovery":{
                "schema":"liskov.discovery.v2", "applicationUid":request["applicationUid"],
                "self":{"jobId":request["jobId"],"runtimeInstanceId":request["runtimeInstanceId"]},
                "revision":format!("sha256:{}",hex::encode(Sha256::digest(b"[]"))),
                "observedAtMs":now,"validUntilMs":now+30_000,"peers":[]
            }}))
            .unwrap(),
        })
    }
}

#[test]
fn guest_private_startup_handoff_and_signed_advertisement() {
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
    assert_eq!(std::env::var("TMPDIR").unwrap(), HOST_TMP);
    assert!(!Path::new(HOST_TMP).exists());
    let mut bound = bootstrap(json!({"mode":"never","serverTimeMs":1,"scheduleEndMs":60_001}));
    bound.runtime_instance_id = "guest-direct-fixture-128".into();
    assert!(initial_health_jitter(&bound.runtime_instance_id, 0) < Duration::from_secs(2));
    let peer = prepare_direct_peer(&bound).unwrap();
    let root = peer.advertisement_path().parent().unwrap().to_owned();
    assert!(root.starts_with("/tmp"));
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let signed = BTreeMap::from([
        ("TMPDIR".into(), "/signed/customer/tmp".into()),
        (
            crate::discovery::direct::ADVERTISEMENT_FILE_ENV.into(),
            "/forged/advertisement".into(),
        ),
        (
            crate::discovery::direct::DIRECTORY_FILE_ENV.into(),
            "/forged/directory".into(),
        ),
    ]);
    let environment = discovery_environment(&signed, &bound, None, Some(&peer), None, None);
    let signer = Arc::new(Signer::default());
    let core = Arc::new(Core::default());
    let mut reporter = AsyncDiagnosticReporter::spawn_with_direct_peer(
        &bound,
        signer.clone(),
        core.clone(),
        None,
        Some(peer.clone()),
        None,
    )
    .unwrap();
    let child = r#"set -eu
        test "$TMPDIR" = /signed/customer/tmp
        test "$LISKOV_RUNTIME_INSTANCE_ID" = guest-direct-fixture-128
        test -d "$(dirname "$LISKOV_PEER_ADVERTISEMENT_FILE")"
        test "$(dirname "$LISKOV_PEER_ADVERTISEMENT_FILE")" = "$(dirname "$LISKOV_PEER_DIRECTORY_FILE")"
        printf '%s' '{"schema":"liskov.peer-advertisement.v2","service":"sync","port":8841,"ready":true,"tlsFingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","peerSyncFailureCode":"none"}' > "$LISKOV_PEER_ADVERTISEMENT_FILE.next"
        chmod 600 "$LISKOV_PEER_ADVERTISEMENT_FILE.next"
        mv "$LISKOV_PEER_ADVERTISEMENT_FILE.next" "$LISKOV_PEER_ADVERTISEMENT_FILE"
        i=0
        while test ! -s "$LISKOV_PEER_DIRECTORY_FILE"; do
            i=$((i+1)); test "$i" -lt 200; sleep 0.05
        done
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
    let health = requests
        .iter()
        .find(|v| v["attrs"]["discoveryVersion"] == 2)
        .unwrap();
    assert_eq!(health["stage"], "runtime.health");
    assert_eq!(health["attrs"]["peerPort"], 8841);
    assert_eq!(health["attrs"]["peerReady"], true);
    assert!(health["signature"].as_str().is_some());
    let mut unsigned = health.clone();
    unsigned.as_object_mut().unwrap().remove("signature");
    let canonical = hex::encode(canonical_json_bytes(&unsigned));
    assert!(
        signer
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|params| params[0]["bytes"] == canonical)
    );
    assert!(
        !peer.advertisement_path().exists(),
        "exit ends old advertisement authority"
    );
    // Same custody race as the application-ready guest: the diagnostic worker
    // can still hold the directory after drop(reporter) returns.
    let release_deadline = Instant::now() + Duration::from_secs(5);
    while Arc::strong_count(&peer) > 1 && Instant::now() < release_deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        Arc::strong_count(&peer),
        1,
        "diagnostic worker released private custody"
    );
    drop(peer);
    assert!(
        !root.exists(),
        "private state is cleaned through its creating boundary"
    );
    // The invalid inherited parent can still refuse legacy-v1 allocation. Its
    // authenticated publication intent must not turn into direct-v2 admission.
    bound.access = Some(
        serde_json::from_value(json!({
            "provider":{"kind":"tailscale"}, "attachmentId":"tail-1",
            "expectedTailnet":"example.com", "setupDeadlineMs":1_800_000_000_000_u64,
            "fence":1,"artifact":{"descriptorId":"descriptor-1",
            "version":"1.98.10-liskov.1","url":"https://liskov.example/client.tgz",
            "sha256":"1".repeat(64),"byteSize":10},
            "publications":[{"useSite":"/ingress/swarm/private/provider",
            "serviceName":"swarm","localPort":8841}]
        }))
        .unwrap(),
    );
    assert!(bound.access.as_ref().unwrap().valid());
    assert!(crate::discovery::DiscoveryFile::for_bootstrap(&bound).is_err());
    let legacy = prepare_direct_peer(&bound).unwrap();
    legacy.begin_child().unwrap();
    fs::write(legacy.advertisement_path(), br#"{"schema":"liskov.peer-advertisement.v2","service":"sync","port":8841,"ready":true,"tlsFingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#).unwrap();
    let mut attrs = json!({});
    assert_eq!(
        legacy.request_attrs(&mut attrs),
        crate::discovery::direct::Request::None
    );
    assert_eq!(attrs["peerAdvertisementError"], "conflict");
    assert!(attrs.get("discoveryVersion").is_none());
}
