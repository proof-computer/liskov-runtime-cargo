//! This fixture was emitted by the production bootstrap + secrets-service
//! PostgreSQL regression in liskov-rs (BKLG-20260904-3r7f).
use super::*;
use crate::bridge::BridgeError;
use crate::diagnostics::canonical_json_bytes;
use crate::http::{HttpError, HttpResponse};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Mutex;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../tests/fixtures/customer-secret-service-v2.json"
    ))
    .unwrap()
}

struct BridgeFixture {
    fixture: Value,
    /// The one encryption key the processor exposes: `p256` or `secp256k1`.
    key_curve: &'static str,
    decrypt_params: Mutex<Vec<Value>>,
}
impl Bridge for BridgeFixture {
    fn call(&self, method: &str, params: Value) -> Result<Value, BridgeError> {
        Ok(match method {
            "deployment_encryptionKeys" => {
                json!({ "encryptionKeys": { self.key_curve: self.fixture["recipientPublicKey"] } })
            }
            "signer_sign" => json!({ "bytes": "11".repeat(64) }),
            "signer_decrypt" => {
                self.decrypt_params.lock().unwrap().push(params);
                json!({ "bytes": hex::encode(canonical_json_bytes(&self.fixture["plaintext"])) })
            }
            _ => panic!("unexpected bridge method"),
        })
    }
}
struct ServiceFixture {
    fixture: Value,
    requests: Mutex<Vec<Value>>,
}
impl HttpClient for ServiceFixture {
    fn post(&self, url: &str, body: &[u8]) -> Result<HttpResponse, HttpError> {
        self.requests
            .lock()
            .unwrap()
            .push(serde_json::from_slice(body).unwrap());
        let response = if url.ends_with("/secret-bootstrap") {
            &self.fixture["secretBootstrap"]
        } else {
            assert!(url.ends_with("/secret-requests"));
            &self.fixture["response"]
        };
        Ok(HttpResponse {
            status: 200,
            body: serde_json::to_vec(response).unwrap(),
        })
    }
}

fn load(fixture: &Value) -> Result<CustomerSecretDelivery, LogConfigSecretError> {
    load_on(fixture, "p256").0
}

fn load_on(
    fixture: &Value,
    key_curve: &'static str,
) -> (
    Result<CustomerSecretDelivery, LogConfigSecretError>,
    Vec<Value>,
) {
    let bootstrap: RuntimeBootstrapResponse =
        serde_json::from_value(fixture["bootstrap"].clone()).unwrap();
    let http = ServiceFixture {
        fixture: fixture.clone(),
        requests: Mutex::new(Vec::new()),
    };
    let bridge = BridgeFixture {
        fixture: fixture.clone(),
        key_curve,
        decrypt_params: Mutex::new(Vec::new()),
    };
    let result = load_customer_secrets_with(
        &bootstrap,
        &bridge,
        &http,
        "https://secrets.example",
        fixture["nowMs"].as_u64().unwrap(),
        [1; 16],
        [2; 16],
    );
    if result.is_ok()
        && bootstrap
            .secrets
            .as_ref()
            .and_then(|s| s.customer_required)
            .is_some()
    {
        let requests = http.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[1]["requestedSecretIds"],
            fixture["request"]["requestedSecretIds"]
        );
        assert_eq!(requests[1]["applicationUid"], bootstrap.application_uid);
        for request in requests.iter() {
            assert_eq!(
                request["responseEncryptionKey"],
                fixture["recipientPublicKey"]
            );
        }
    }
    (result, bridge.decrypt_params.into_inner().unwrap())
}

#[test]
fn production_service_fixture_delivers_the_exact_customer_environment_value() {
    let result = load(&fixture()).unwrap();
    assert_eq!(
        result.environment,
        BTreeMap::from([("USER_SECRET".into(), "customer-secret-value".into())])
    );
    assert!(result.files.is_empty());
}

#[test]
fn a_secp256k1_only_processor_installs_the_customer_secret_decrypted_on_secp256k1() {
    let mut fixture = fixture();
    let encrypted = &mut fixture["response"]["encryptedPayload"];
    encrypted["version"] = json!("acurast-secp256k1-hkdf-aes-256-gcm-v1");
    encrypted["curveName"] = json!("secp256k1");
    encrypted
        .as_object_mut()
        .unwrap()
        .remove("encryptedPayloadDigest");
    let digest = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(canonical_json_bytes(encrypted)))
    );
    encrypted["encryptedPayloadDigest"] = json!(digest);
    let sent = encrypted.clone();

    let (result, decrypts) = load_on(&fixture, "secp256k1");

    assert_eq!(
        result.unwrap().environment,
        BTreeMap::from([("USER_SECRET".into(), "customer-secret-value".into())])
    );
    assert_eq!(
        decrypts,
        [json!([{
            "curve": "secp256k1",
            "publicKey": sent["senderPublicKey"],
            "salt": sent["saltHex"],
            "bytes": sent["ciphertextHex"],
        }])]
    );
}

#[test]
fn old_and_logging_only_bootstraps_do_not_start_customer_hydration() {
    let mut fixture = fixture();
    fixture["bootstrap"]["secrets"]
        .as_object_mut()
        .unwrap()
        .remove("customerRequired");
    let result = load(&fixture).unwrap();
    assert!(result.environment.is_empty());
}

#[test]
fn foreign_job_and_secret_metadata_substitutions_are_refused() {
    for field in [
        "applicationUid",
        "applicationId",
        "policyDigest",
        "deploymentId",
        "jobId",
        "processorId",
    ] {
        let mut fixture = fixture();
        fixture["response"][field] = json!("foreign");
        assert!(load(&fixture).is_err(), "{field}");
    }
    let mut fixture = fixture();
    fixture["response"]["secretVersions"][0]["name"] = json!("OTHER_SECRET");
    assert!(load(&fixture).is_err());
}

#[test]
fn partial_and_duplicate_secret_groups_are_refused_before_installation() {
    let fixture = fixture();
    let version = fixture["response"]["secretVersions"][0].clone();
    let ids = ["diagnostic-lockbox-marker".to_owned()];
    assert!(validate_versions(&json!([version.clone(), version.clone()]), &ids).is_err());
    assert!(validate_deliveries(&json!([]), &json!([version])).is_err());
}

#[test]
fn production_file_service_fixture_is_decoded_and_installed_as_one_delivery() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/file-secret-service-v2.json"
    ))
    .unwrap();
    let delivery = load(&fixture).unwrap();
    assert_eq!(delivery.environment["USER_SECRET"], "customer-secret-value");
    let root = std::env::temp_dir().join(format!("liskov-e287-wire-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    crate::file_secrets::install_at(&root, &delivery.files, |_| Ok(())).unwrap();
    assert_eq!(
        std::fs::read(root.join("run/secrets/tls-config")).unwrap(),
        b"  private config\nwith trailing newline\n"
    );
    std::fs::remove_dir_all(root).unwrap();
}
