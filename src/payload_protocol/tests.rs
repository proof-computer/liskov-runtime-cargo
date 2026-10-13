use super::descriptor::*;
use super::*;
use serde_json::{Value, json};

fn fixtures() -> Value {
    serde_json::from_str(include_str!("../../vectors/payload-download-v1.json")).unwrap()
}

fn envelope() -> SignedPayloadDownloadRequestV1 {
    serde_json::from_value(fixtures()["valid"][0]["envelope"].clone()).unwrap()
}

#[test]
fn golden_messages_pin_exact_cross_language_signing_bytes() {
    let fixture = fixtures();
    for row in fixture["valid"].as_array().unwrap() {
        let signed =
            SignedPayloadDownloadRequestV1::parse(&serde_json::to_vec(&row["envelope"]).unwrap())
                .unwrap();
        assert_eq!(
            signed.request.message().unwrap(),
            row["messageUtf8"].as_str().unwrap().as_bytes()
        );
        assert_eq!(
            signed.request.request_digest().unwrap(),
            row["messageDigest"]
        );
        assert_eq!(serde_json::to_value(&signed).unwrap(), row["envelope"]);
        assert_eq!(hex::decode(&signed.signature).unwrap().len(), 64);
    }
    // Signature verification/signing is independently executed by the Python
    // and Node fixture proofs. This target pins their exact Rust input bytes.
    let descriptor: Value =
        serde_json::from_str(include_str!("../../vectors/payload-descriptor-v1.json")).unwrap();
    let typed: CargoPayloadDescriptorV1 =
        serde_json::from_value(descriptor["descriptor"].clone()).unwrap();
    let bytes = canonical_payload_descriptor_bytes(&typed, 8 * 1024 * 1024).unwrap();
    assert_eq!(
        bytes,
        descriptor["canonicalUtf8"].as_str().unwrap().as_bytes()
    );
    assert_eq!(
        format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
        descriptor["descriptorDigest"]
    );
    let archive = include_bytes!("../../vectors/payload-archive-v1.tar.gz");
    assert_eq!(typed.artifact_size_bytes as usize, archive.len());
    assert_eq!(
        format!("sha256:{}", hex::encode(Sha256::digest(archive))),
        descriptor["archiveDigest"]
    );
    assert_ne!(descriptor["archiveDigest"], descriptor["descriptorDigest"]);
}

#[test]
fn golden_refusals_bind_transport_time_and_canonical_authority_facts() {
    let fixtures = fixtures();
    let expected: PayloadDownloadBindingV1 =
        serde_json::from_value(fixtures["expectedBinding"].clone()).unwrap();
    for row in fixtures["invalid"].as_array().unwrap() {
        let parsed =
            SignedPayloadDownloadRequestV1::parse(&serde_json::to_vec(&row["envelope"]).unwrap());
        let error = match row["phase"].as_str().unwrap() {
            "parse" => parsed.unwrap_err(),
            "binding" => parsed
                .unwrap()
                .request
                .validate_binding(&expected)
                .unwrap_err(),
            "transport" => parsed
                .unwrap()
                .request
                .validate_transport(
                    row["method"].as_str().unwrap(),
                    row["target"].as_str().unwrap(),
                    row["rangeHeader"].as_str(),
                    row["nowMs"].as_i64().unwrap(),
                )
                .unwrap_err(),
            "signature" => {
                let signed = parsed.unwrap();
                let key = hex::decode(fixtures["publicKeyHex"].as_str().unwrap()).unwrap();
                assert!(
                    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
                        .verify(
                            &signed.request.message().unwrap(),
                            &hex::decode(signed.signature).unwrap()
                        )
                        .is_err()
                );
                PayloadDownloadRefusal::InvalidSignature
            }
            phase => panic!("unknown fixture phase {phase}"),
        };
        assert_eq!(
            serde_json::to_value(error).unwrap(),
            row["reason"],
            "{}",
            row["name"]
        );
    }
}

#[test]
fn parse_fails_closed_on_oversize_unknown_duplicate_and_missing_fields() {
    assert_eq!(
        SignedPayloadDownloadRequestV1::parse(&vec![b' '; 8193]),
        Err(PayloadDownloadRefusal::EnvelopeTooLarge)
    );
    let mut value = serde_json::to_value(envelope()).unwrap();
    value["request"]["storageUrl"] = json!("https://untrusted.invalid");
    assert_eq!(
        SignedPayloadDownloadRequestV1::parse(&serde_json::to_vec(&value).unwrap()),
        Err(PayloadDownloadRefusal::MalformedEnvelope)
    );
    value["request"]
        .as_object_mut()
        .unwrap()
        .remove("storageUrl");
    value["request"].as_object_mut().unwrap().remove("workload");
    assert_eq!(
        SignedPayloadDownloadRequestV1::parse(&serde_json::to_vec(&value).unwrap()),
        Err(PayloadDownloadRefusal::MalformedEnvelope)
    );
    let original = serde_json::to_string(&envelope()).unwrap();
    let duplicate = original.replacen(
        "\"method\":\"GET\"",
        "\"method\":\"GET\",\"method\":\"POST\"",
        1,
    );
    assert_eq!(
        SignedPayloadDownloadRequestV1::parse(duplicate.as_bytes()),
        Err(PayloadDownloadRefusal::MalformedEnvelope)
    );
    let mut signed = envelope();
    signed.signature = "AA".repeat(64);
    assert_eq!(
        SignedPayloadDownloadRequestV1::parse(&serde_json::to_vec(&signed).unwrap()),
        Err(PayloadDownloadRefusal::InvalidSignature)
    );
}

#[test]
fn ranges_preserve_zero_and_refuse_aliases_and_out_of_object_reads() {
    let single = PayloadDownloadRangeV1::from_header(Some("bytes=0-0")).unwrap();
    assert_eq!(
        single.select(1).unwrap(),
        PayloadByteSelectionV1 {
            offset: 0,
            length: 1
        }
    );
    assert_eq!(
        PayloadDownloadRangeV1::Whole {}.select(10).unwrap(),
        PayloadByteSelectionV1 {
            offset: 0,
            length: 10
        }
    );
    assert_eq!(
        single.select(0),
        Err(PayloadDownloadRefusal::RangeUnsatisfiable)
    );
    for header in [
        "bytes=00-1",
        "bytes=0-01",
        "bytes=0-",
        "bytes=-1",
        "bytes=0-1,2-3",
        "Bytes=0-1",
        " bytes=0-1",
        "bytes=+0-1",
        "bytes=5-4",
        "bytes=0-18446744073709551616",
    ] {
        assert_eq!(
            PayloadDownloadRangeV1::from_header(Some(header)),
            Err(PayloadDownloadRefusal::InvalidRange),
            "{header}"
        );
    }
    let range = PayloadDownloadRangeV1::Bytes {
        start: 1,
        end_inclusive: 2,
    };
    assert_eq!(
        range.select(2),
        Err(PayloadDownloadRefusal::RangeUnsatisfiable)
    );
}

#[test]
fn exact_time_transport_and_workload_bindings_accept_and_expiry_refuses() {
    let signed = envelope();
    let request = signed.request;
    let mut binding: PayloadDownloadBindingV1 =
        serde_json::from_value(fixtures()["expectedBinding"].clone()).unwrap();
    request.validate_binding(&binding).unwrap();
    request
        .validate_transport("GET", &request.request_target, None, request.issued_at_ms)
        .unwrap();
    request
        .validate_transport(
            "GET",
            &request.request_target,
            None,
            request.expires_at_ms - 1,
        )
        .unwrap();
    binding.authorization_expires_at_ms -= 1;
    assert_eq!(
        request.validate_binding(&binding),
        Err(PayloadDownloadRefusal::Expired)
    );
    let row = fixtures()["valid"][2]["envelope"].clone();
    let workload: SignedPayloadDownloadRequestV1 = serde_json::from_value(row).unwrap();
    binding.authorization_expires_at_ms += 1;
    binding.workload = workload.request.workload.clone();
    workload.request.validate_binding(&binding).unwrap();
}

#[test]
fn owner_descriptor_negative_fixtures_refuse_and_raw_hashes_pin_provenance() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../vectors/payload-descriptor-v1.json")).unwrap();
    for row in fixture["invalid"].as_array().unwrap() {
        let parsed = serde_json::from_value::<CargoPayloadDescriptorV1>(row["descriptor"].clone());
        match parsed {
            Ok(descriptor) => assert_eq!(
                serde_json::to_value(descriptor.validate(8 * 1024 * 1024).unwrap_err()).unwrap(),
                row["reason"],
                "{}",
                row["name"]
            ),
            Err(_) => assert_eq!(row["reason"], "malformed"),
        }
    }
    for (bytes, expected) in [
        (
            include_bytes!("../../vectors/payload-archive-v1.tar.gz").as_slice(),
            "fcc6a000c99ec202381c89f826c219a347e904d2cd20febeea50b26ea84e7b60",
        ),
        (
            include_bytes!("../../vectors/payload-descriptor-v1.json").as_slice(),
            "e2209c44993577f224ce557b4b6b57329d89369d8cefd98ac89a1a90a27abc55",
        ),
        (
            include_bytes!("../../vectors/payload-download-v1.json").as_slice(),
            "3ed90d91529d24a5b8ee75db289b0fddc521bda8a8d52895f93f76c9cc817559",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(bytes)), expected);
    }
    let fixture = fixtures();
    let seed = hex::decode(fixture["testOnlySeedHex"].as_str().unwrap()).unwrap();
    let key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    for row in fixture["valid"].as_array().unwrap() {
        let envelope: SignedPayloadDownloadRequestV1 =
            serde_json::from_value(row["envelope"].clone()).unwrap();
        assert_eq!(
            hex::encode(key.sign(&envelope.request.message().unwrap()).as_ref()),
            envelope.signature
        );
    }
}
