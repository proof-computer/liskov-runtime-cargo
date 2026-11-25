use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::STANDARD};
use liskov_runtime_cargo::network_traversal::*;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde_json::{Value, json};

const KEY: [u8; 32] = [7; 32];
const WAIT: Duration = Duration::from_secs(6);

struct Probe {
    child: Child,
    input: Option<ChildStdin>,
    output: Receiver<Value>,
}

impl Probe {
    fn new() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_liskov-fact-probe"))
            .arg("--traversal-external")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let reader = BufReader::new(child.stdout.take().unwrap());
        let (tx, output) = mpsc::channel();
        std::thread::spawn(move || {
            for line in reader.lines() {
                let line = line.unwrap();
                let record: Value = serde_json::from_str(&line).unwrap();
                if tx.send(record).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            input,
            output,
        }
    }

    fn send(&mut self, value: &Value) {
        let input = self.input.as_mut().unwrap();
        serde_json::to_writer(&mut *input, value).unwrap();
        input.write_all(b"\n").unwrap();
    }

    fn respond(&mut self, body: Value) {
        self.send(&json!({
            "type": "response", "status": 200,
            "body": STANDARD.encode(serde_json::to_vec(&body).unwrap())
        }));
    }

    fn next(&self) -> Value {
        self.output.recv_timeout(WAIT).expect("probe record")
    }

    fn signal(&self) {
        // SAFETY: The child is ours and has not been reaped.
        let result = unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
        assert_eq!(result, 0);
    }

    fn finish(mut self, success: bool) {
        let end = Instant::now() + WAIT;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < end, "probe exit timed out");
            std::thread::sleep(Duration::from_millis(5));
        };
        let mut stderr = String::new();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert_eq!(status.success(), success, "{status}: {stderr}");
        if success {
            assert!(stderr.is_empty(), "{stderr}");
        } else {
            assert!(
                matches!(
                    stderr.trim_end(),
                    "invalid_request" | "invalid_endpoint" | "invalid_grant" | "cancelled"
                ),
                "{stderr}"
            );
        }
        assert!(matches!(
            self.output.recv_timeout(WAIT),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn descriptor(name: &str) -> TraversalDescriptorV1 {
    let vectors: Value =
        serde_json::from_str(include_str!("../vectors/network-traversal-v1.json")).unwrap();
    let row = vectors["descriptors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == name)
        .unwrap();
    serde_json::from_value(row["descriptor"].clone()).unwrap()
}

fn request(collector: &str, descriptor: &TraversalDescriptorV1) -> Value {
    let capability: Value =
        serde_json::from_slice(&encode_traversal_capability(&KEY, descriptor).unwrap()).unwrap();
    json!({
        "version": 2, "scenario": "external-loopback", "collector": collector,
        "originMs": descriptor.issued_at_ms + 1,
        "grant": {
            "capability": capability, "artifactDigest": descriptor.artifact_digest,
            "claimAuthorityDigest": descriptor.claim_authority_digest,
            "jobExpiresAtMs": descriptor.expires_at_ms,
        }
    })
}

fn socket(address: IpAddr) -> UdpSocket {
    let socket = UdpSocket::bind((address, 0)).unwrap();
    socket.set_read_timeout(Some(WAIT)).unwrap();
    socket
}

fn receive(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut bytes = [0; 1024];
    let (n, from) = socket.recv_from(&mut bytes).unwrap();
    (bytes[..n].to_vec(), from)
}

fn send(socket: &UdpSocket, bytes: &[u8], destination: SocketAddr) {
    assert_eq!(socket.send_to(bytes, destination).unwrap(), bytes.len());
}

fn frame(address: SocketAddr, body: &[u8]) -> Vec<u8> {
    let mut bytes = match address.ip() {
        IpAddr::V4(ip) => [vec![1], ip.octets().to_vec()].concat(),
        IpAddr::V6(ip) => [vec![2], ip.octets().to_vec()].concat(),
    };
    bytes.extend(address.port().to_be_bytes());
    bytes.extend(body);
    bytes
}

fn unframe(bytes: &[u8]) -> (SocketAddr, &[u8]) {
    let (address, rest) = match bytes {
        [1, a, b, c, d, rest @ ..] => (Ipv4Addr::new(*a, *b, *c, *d).into(), rest),
        [2, rest @ ..] => {
            let (address, rest) = rest.split_at(16);
            (
                Ipv6Addr::from(<[u8; 16]>::try_from(address).unwrap()).into(),
                rest,
            )
        }
        _ => panic!("invalid fixture frame"),
    };
    (
        SocketAddr::new(address, u16::from_be_bytes(rest[..2].try_into().unwrap())),
        &rest[2..],
    )
}

fn ledger<'a>(record: &'a Value, collector: &str) -> &'a [Value] {
    assert_eq!(record["type"], "transcript");
    assert_eq!(record["version"], 2);
    assert_eq!(record["collector"], collector);
    assert!(record["refusal"].is_null(), "{record}");
    let rows = record["sockets"].as_array().unwrap();
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row["index"], index);
        let local: SocketAddr = row["local"].as_str().unwrap().parse().unwrap();
        assert!(local.ip().is_loopback());
        assert_ne!(local.port(), 0);
        assert_eq!(row.as_object().unwrap().len(), 7);
    }
    rows
}

fn observation_request(ingress: SocketAddr) -> (Value, [SocketAddr; 3]) {
    let descriptor = descriptor("observe");
    let addresses = [
        "127.0.0.1:31001".parse().unwrap(),
        "127.0.0.1:31002".parse().unwrap(),
        "127.0.0.2:31001".parse().unwrap(),
    ];
    let [ap, aq, bp] = addresses.map(|address| {
        json!({
            "address": address, "mappingQualified": true, "filteringQualified": true
        })
    });
    let mut request = request("udp-behaviour", &descriptor);
    request["session"] = json!("11".repeat(16));
    request["natIngress"] = json!(ingress);
    request["endpoints"] =
        json!({"revision":descriptor.endpoint_set_revision, "ap":ap, "aq":aq, "bp":bp});
    (request, addresses)
}

fn mapping_request(descriptor: &TraversalDescriptorV1, router: SocketAddr) -> Value {
    let mut request = request("mapping", descriptor);
    let consent = descriptor.mapping.as_ref().unwrap();
    request["consent"] = json!({
        "consentReference": consent.consent_reference,
        "processorAllowlistDigest": consent.processor_allowlist_digest,
        "exclusiveReservationDigest": consent.exclusive_reservation_digest,
    });
    request["endpoints"] = json!({
        "router": router, "pathSource":"127.0.0.1", "observedAddress":"127.0.0.1"
    });
    request["method"] = json!("pcp");
    request["transport"] = json!("udp");
    request["signerSeed"] = json!(hex::encode([19; 32]));
    request
}

fn reject(input: &str) {
    let mut probe = Probe::new();
    let mut stdin = probe.input.take().unwrap();
    stdin.write_all(input.as_bytes()).unwrap();
    drop(stdin);
    // finish asserts that stdout closes without any control or transcript.
    probe.finish(false);
}

#[test]
fn closed_requests_emit_no_records() {
    let (template, _) = observation_request("127.0.0.1:35000".parse().unwrap());
    for template in [template.clone(), {
        let mut mixed = template;
        mixed["endpoints"]["ap"]["address"] = json!("[::1]:31001");
        mixed
    }] {
        let line = template.to_string();
        for invalid in [
            "{".into(),
            format!("{line} {{}}"),
            format!("{{\"version\":2,{}", &line[1..]),
            format!("{}{line}", " ".repeat(65_536)),
        ] {
            reject(&format!("{invalid}\n"));
        }
        for (field, value) in [
            ("version", json!(1)),
            ("scenario", json!("traversal-smoke")),
            ("collector", json!("other")),
            ("surplus", json!(1)),
            ("natIngress", json!("[::1]:35000")),
        ] {
            let mut invalid = template.clone();
            invalid[field] = value;
            reject(&format!("{invalid}\n"));
        }
        for address in [
            "10.0.0.1:31002",
            "192.0.2.1:31002",
            "0.0.0.0:31002",
            "127.0.0.1:0",
            "[::1]:31002",
        ] {
            let mut invalid = template.clone();
            invalid["endpoints"]["aq"]["address"] = json!(address);
            reject(&format!("{invalid}\n"));
        }
        reject(&line); // even valid JSON requires a complete newline-delimited record
    }
    let request = mapping_request(&descriptor("mapping"), "127.0.0.1:35000".parse().unwrap());
    for (field, value) in [("transport", "tcp"), ("method", "upnp-igd")] {
        let mut invalid = request.clone();
        invalid[field] = json!(value);
        reject(&format!("{invalid}\n"));
    }
}

fn behaviour_run(address_dependent: bool) -> Value {
    let relay = socket(Ipv4Addr::LOCALHOST.into());
    let (request, addresses) = observation_request(relay.local_addr().unwrap());
    let mut probe = Probe::new();
    probe.send(&request);
    let mut trace = Vec::new();
    for index in 0..20 {
        let (wire, local) = receive(&relay);
        let (remote, body) = unframe(&wire);
        let ingress = addresses.iter().position(|addr| *addr == remote).unwrap();
        trace.push((local, remote, body.to_vec()));
        assert_eq!(&body[..4], b"LNT1");
        assert_eq!(body.len(), 96);
        let proof = body[4] == 2;
        let outgoing = if proof && body[5] != 0 {
            usize::from(body[5])
        } else {
            ingress
        };
        let mut reply = body.to_vec();
        reply[4] = if proof { 3 } else { 1 };
        reply[6] = ingress as u8;
        reply[7] = outgoing as u8;
        reply[40..72].fill(0x71);
        if proof {
            reply.resize(128, 0);
            reply[96] = 4;
            reply[97..101].copy_from_slice(&[
                127,
                0,
                0,
                1 + u8::from(address_dependent && ingress == 2),
            ]);
            reply[113..115].copy_from_slice(&local.port().to_be_bytes());
        }
        if index == 0 {
            let untrusted = socket(Ipv4Addr::LOCALHOST.into());
            let mut forged = reply.clone();
            forged[40..72].fill(0x39);
            send(&untrusted, &frame(addresses[outgoing], &forged), local);
            send(&relay, &[1, 127], local);
        }
        send(&relay, &frame(addresses[outgoing], &reply), local);
    }
    let record = probe.next();
    probe.finish(true);
    let rows = ledger(&record, "udp-behaviour");
    assert_eq!(rows.len(), 2);
    assert_ne!(trace[0].0, trace[8].0);
    for (index, (rows, packets)) in rows.iter().zip([&trace[..8], &trace[8..]]).enumerate() {
        assert_eq!(rows["seam"], "behaviour");
        assert_eq!(rows["local"], packets[0].0.to_string());
        assert!(packets.iter().all(|(local, _, _)| *local == packets[0].0));
        assert_eq!(rows["sentDatagrams"], packets.len());
        assert_eq!(
            rows["sentBytes"],
            packets
                .iter()
                .map(|(_, _, bytes)| bytes.len() + 7)
                .sum::<usize>()
        );
        assert_eq!(
            rows["receivedDatagrams"],
            packets.len() + if index == 0 { 2 } else { 0 }
        );
        assert_eq!(
            rows["receivedBytes"],
            packets.len() / 2 * (96 + 7 + 128 + 7) + if index == 0 { 96 + 7 + 2 } else { 0 }
        );
    }
    assert!(
        trace[..8]
            .iter()
            .all(|(_, remote, _)| *remote == addresses[0])
    );
    assert!(
        addresses
            .iter()
            .all(|address| trace[8..].iter().any(|(_, remote, _)| remote == address))
    );
    record
}

#[test]
fn behaviour_classifies_distinct_reflectors_and_separates_socket_phases() {
    let independent = behaviour_run(false);
    let dependent = behaviour_run(true);
    assert_eq!(independent["result"]["sentDatagrams"], 20);
    assert_eq!(
        independent["result"]["filtering"]["outcome"],
        "endpoint_independent"
    );
    assert_eq!(
        independent["result"]["mapping"]["outcome"],
        "endpoint_independent"
    );
    assert_eq!(
        dependent["result"]["mapping"]["outcome"],
        "address_dependent"
    );
}

#[test]
fn sigterm_during_collection_emits_the_transcript_and_exits_cleanly() {
    let relay = socket(Ipv4Addr::LOCALHOST.into());
    let (request, _) = observation_request(relay.local_addr().unwrap());
    let mut probe = Probe::new();
    probe.send(&request);
    let (_, local) = receive(&relay);
    probe.signal();
    let record = probe.next();
    probe.finish(true);
    let rows = ledger(&record, "udp-behaviour");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["local"], local.to_string());
    assert_eq!(record["result"]["filtering"]["reason"], "cancelled");
}

fn control(record: Value) -> (String, Vec<u8>) {
    assert_eq!(record["type"], "control", "{record}");
    (
        record["path"].as_str().unwrap().into(),
        STANDARD.decode(record["body"].as_str().unwrap()).unwrap(),
    )
}

fn verify_signature(signer: &[u8], message: &[u8], signature: &str) {
    let bytes = hex::decode(signature.strip_prefix("0x").unwrap()).unwrap();
    UnparsedPublicKey::new(&ED25519, signer)
        .verify(message, &bytes)
        .unwrap();
}

fn path(
    probe: &mut Probe,
    socket: &UdpSocket,
    descriptor: &TraversalDescriptorV1,
    stage: TraversalStage,
    nonce: [u8; 32],
) -> SocketAddr {
    let (path, body) = control(probe.next());
    assert_eq!(path, "/v1/traversal/path/check");
    let body: Value = serde_json::from_slice(&body).unwrap();
    let capability = body["capability"].as_str().unwrap();
    assert_eq!(
        decode_traversal_capability(&KEY, capability.as_bytes(), descriptor.issued_at_ms + 1)
            .unwrap(),
        *descriptor
    );
    assert_eq!(body["transport"], "udp");
    assert_eq!(body["family"], "v4");
    let (method, mapped) = if stage == TraversalStage::Baseline {
        (TraversalMethod::Unassisted, Value::Null)
    } else {
        (TraversalMethod::Pcp, json!("127.0.0.1"))
    };
    assert_eq!(body["method"], json!(method));
    assert_eq!(body["mappingAddress"], mapped);
    let port = body["port"].as_u64().unwrap().try_into().unwrap();
    let listener = (Ipv4Addr::LOCALHOST, port).into();
    send(socket, &nonce, listener);
    assert_eq!(receive(socket), (nonce.to_vec(), listener));
    let transcript = TraversalTranscriptV1 {
        version: 1,
        domain: TRAVERSAL_EXTERNAL_PATH_DOMAIN.into(),
        descriptor_digest: descriptor.binding_digest().unwrap(),
        run_id: descriptor.run_id.clone(),
        pair_id: None,
        participant_role: None,
        authority: TraversalEvidenceAuthority::ExternalPath,
        stage,
        method,
        transport: TraversalTransport::Udp,
        family: TraversalFamily::V4,
        challenge: hex::encode(nonce),
        peer_challenge: None,
        expires_at_ms: descriptor.expires_at_ms,
        outcome: TraversalOutcome::Succeeded,
        elapsed_ms: 0,
        granted_lease_sec: None,
        cleanup: None,
        protocol_error: None,
        error_class: None,
    };
    let observation = json!({ "transcript": transcript, "detail": "reachable", "observationMac": "7a".repeat(32) });
    probe.respond(observation.clone());
    let (path, body) = control(probe.next());
    assert_eq!(path, "/v1/traversal/path/receipt");
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["capability"], capability);
    assert_eq!(body["observation"], observation);
    let key = Ed25519KeyPair::from_seed_unchecked(&[19; 32]).unwrap();
    let signature = body["deviceSignature"].as_str().unwrap();
    verify_signature(
        key.public_key().as_ref(),
        &transcript.signing_message().unwrap(),
        signature,
    );
    let mut receipt = TraversalReceiptV1 {
        version: 1,
        transcript,
        device_signature: signature.into(),
        mac: String::new(),
    };
    sign_traversal_receipt(&KEY, &mut receipt).unwrap();
    probe.respond(json!(receipt));
    listener
}

fn pcp_reply(request: &[u8], lease: u32) -> [u8; PCP_MAP_PACKET_BYTES] {
    let mut response = [0; PCP_MAP_PACKET_BYTES];
    response[..2].copy_from_slice(&[2, 0x81]);
    response[4..8].copy_from_slice(&lease.to_be_bytes());
    response[8..12].copy_from_slice(&100u32.to_be_bytes());
    response[24..44].copy_from_slice(&request[24..44]);
    response[54..56].fill(0xff);
    response[56..60].copy_from_slice(&Ipv4Addr::LOCALHOST.octets());
    response
}

fn pcp_run(lease: u32, cancel: bool) -> Value {
    let descriptor = descriptor("mapping");
    let router = socket(Ipv4Addr::LOCALHOST.into());
    let dialback = socket(Ipv4Addr::LOCALHOST.into());
    let mut probe = Probe::new();
    probe.send(&mapping_request(&descriptor, router.local_addr().unwrap()));
    let listener = path(
        &mut probe,
        &dialback,
        &descriptor,
        TraversalStage::Baseline,
        [7; 32],
    );
    let (create, client) = receive(&router);
    assert_eq!(create.len(), PCP_MAP_PACKET_BYTES);
    assert_eq!(&create[..2], &[2, 1]);
    assert_eq!(&create[4..8], &60u32.to_be_bytes());
    assert_eq!(create[36], 17);
    assert_eq!(&create[40..42], &listener.port().to_be_bytes());
    if cancel {
        probe.signal();
    }
    send(&router, &pcp_reply(&create, lease), client);
    if !cancel {
        assert_eq!(
            path(
                &mut probe,
                &dialback,
                &descriptor,
                TraversalStage::MappingVerify,
                [8; 32]
            ),
            listener
        );
    }
    let (delete, delete_client) = receive(&router);
    assert_eq!(delete_client, client);
    assert_eq!(delete.len(), PCP_MAP_PACKET_BYTES);
    assert_eq!(&delete[4..8], &[0; 4]);
    assert_eq!(&delete[24..44], &create[24..44]);
    send(&router, &pcp_reply(&delete, 0), client);
    let record = probe.next();
    probe.finish(true);
    let rows = ledger(&record, "mapping");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["seam"], "mapping-listener");
    assert_eq!(rows[0]["local"], listener.to_string());
    let echoes = if cancel { 1 } else { 2 };
    assert_eq!(rows[0]["sentDatagrams"], echoes);
    assert_eq!(rows[0]["receivedDatagrams"], echoes);
    assert_eq!(rows[0]["sentBytes"], echoes * 32);
    assert_eq!(rows[0]["receivedBytes"], echoes * 32);
    assert_eq!(rows[1]["seam"], "router-client");
    assert_eq!(rows[1]["local"], client.to_string());
    assert_eq!(rows[1]["sentDatagrams"], 2);
    assert_eq!(rows[1]["receivedDatagrams"], 2);
    assert_eq!(rows[1]["sentBytes"], 2 * PCP_MAP_PACKET_BYTES);
    assert_eq!(rows[1]["receivedBytes"], 2 * PCP_MAP_PACKET_BYTES);
    record["result"].clone()
}

#[test]
fn mapping_reports_granted_lease_and_cleans_up_after_sigterm() {
    let ordinary = pcp_run(60, false);
    let clamped = pcp_run(30, false);
    let stopped = pcp_run(60, true);
    for report in [&ordinary, &clamped, &stopped] {
        assert_eq!(report["discovery"], "succeeded");
        let row = &report["methods"][0];
        assert_eq!(row["baseline"]["outcome"], "succeeded");
        assert_eq!(row["create"], "succeeded");
        assert_eq!(row["cleanup"], "confirmed_deleted");
        assert_eq!(row["expiryUnknown"], false);
    }
    for report in [&ordinary, &clamped] {
        assert_eq!(report["methods"][0]["verification"]["outcome"], "succeeded");
        assert_eq!(report["controlRequests"], 6);
        assert_eq!(report["externalDialbacks"], 2);
        assert!(report["stopped"].is_null());
    }
    assert_eq!(ordinary["methods"][0]["grantedLeaseSec"], 60);
    assert_eq!(clamped["methods"][0]["grantedLeaseSec"], 30);
    assert_eq!(stopped["stopped"], "graceful_shutdown");
    assert!(stopped["methods"][0]["verification"].is_null());
}

struct PairFixture {
    descriptors: [TraversalDescriptorV1; 2],
    handles: [String; 2],
    until: u64,
    coordinator: SocketAddr,
    registered: [Option<SocketAddr>; 2],
    relay_ready: [bool; 2],
    blocked: bool,
    sent: [usize; 2],
    direct: [usize; 2],
    relayed: [usize; 2],
}

impl PairFixture {
    fn new(blocked: bool) -> Self {
        let descriptors = ["pair_first", "pair_second"].map(|name| {
            let mut descriptor = descriptor(name);
            descriptor.budgets.experiment_ms = 3_000;
            descriptor.budgets.cleanup_reserve_ms = 300;
            for (role, peer) in descriptor
                .pair
                .as_mut()
                .unwrap()
                .participants
                .iter_mut()
                .enumerate()
            {
                let key = Ed25519KeyPair::from_seed_unchecked(&[role as u8 + 1; 32]).unwrap();
                peer.runtime_signer = format!("0x{}", hex::encode(key.public_key().as_ref()));
            }
            descriptor
        });
        let until = descriptors[0].issued_at_ms + 2_701;
        Self {
            descriptors,
            handles: [10, 11].map(|role| format!("{role:032x}")),
            until,
            coordinator: "[::1]:31001".parse().unwrap(),
            registered: [None; 2],
            relay_ready: [false; 2],
            blocked,
            sent: [0; 2],
            direct: [0; 2],
            relayed: [0; 2],
        }
    }

    fn request(&self, role: usize, ingress: SocketAddr) -> Value {
        let mut request = request("pair", &self.descriptors[role]);
        request["natIngress"] = json!(ingress);
        request["signerSeed"] = json!(hex::encode([role as u8 + 1; 32]));
        request["endpoints"] = json!({
            "coordinator": self.coordinator, "revision": self.descriptors[role].endpoint_set_revision,
        });
        request
    }

    fn reply(&mut self, role: usize, record: Value) -> Value {
        let (path, body) = control(record);
        if path == "/v1/traversal/pair/enroll" {
            let descriptor = &self.descriptors[role];
            assert_eq!(
                decode_traversal_capability(&KEY, &body, descriptor.issued_at_ms + 1).unwrap(),
                *descriptor
            );
            return json!({"session": self.handles[role], "untilMs": self.until});
        }
        assert_eq!(path, "/v1/traversal/pair/control");
        let request: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(request["session"], self.handles[role]);
        let (phase, progress, candidate) = match request["action"].as_str().unwrap() {
            "candidates" if self.registered.iter().all(Option::is_some) => {
                ("direct", "ready", self.registered[1 - role])
            }
            "candidates" => ("direct", "awaiting_endpoint", None),
            "relay" => {
                self.relay_ready[role] = true;
                if self.relay_ready[1 - role] {
                    ("relay_control", "ready", None)
                } else {
                    ("direct", "awaiting_relay", None)
                }
            }
            _ => panic!("unexpected pair action"),
        };
        json!({"phase": phase, "progress": progress, "candidate": candidate, "untilMs": self.until})
    }

    fn datagram(&mut self, ingress: &UdpSocket, wire: &[u8], source: SocketAddr) {
        let (destination, packet) = unframe(wire);
        let value: Value = serde_json::from_slice(packet).unwrap();
        if destination != self.coordinator {
            assert_eq!(
                value["domain"],
                "liskov.network-traversal-pair-direct-udp.v1"
            );
            let role = self
                .registered
                .iter()
                .position(|addr| *addr == Some(source))
                .unwrap();
            assert_eq!(self.registered[1 - role], Some(destination));
            self.sent[role] += 1;
            self.direct[role] += 1;
            if !self.blocked {
                send(ingress, &frame(source, packet), destination);
            }
            return;
        }
        let role = self
            .handles
            .iter()
            .position(|handle| value["session"] == *handle)
            .unwrap();
        let cookie = format!("{role:064x}");
        self.sent[role] += 1;
        if let Some(registered) = self.registered[role] {
            assert_eq!(source, registered);
        }
        let (reply, to) = match value["kind"].as_str().unwrap() {
            "cookie" => (
                json!({
                    "kind": "cookie", "session": value["session"], "transaction": value["transaction"], "cookie": cookie,
                }),
                source,
            ),
            "register" => {
                assert_eq!(value["cookie"], cookie);
                assert!(self.registered[role].replace(source).is_none());
                return;
            }
            "relay" => {
                assert!(self.relay_ready.iter().all(|ready| *ready));
                assert_eq!(value["cookie"], cookie);
                assert!(self.direct[role] > 0);
                self.relayed[role] += 1;
                let from = &self.descriptors[role];
                let to = &self.descriptors[1 - role];
                (
                    json!({
                        "domain": "liskov.network-traversal-relay-control.v1",
                        "pairId": from.pair.as_ref().unwrap().pair_id,
                        "sender": from.binding_digest().unwrap(), "recipient": to.binding_digest().unwrap(),
                        "sequence": value["sequence"], "frame": value["frame"], "expiresAtMs": self.until,
                        "mac": "13".repeat(32)
                    }),
                    self.registered[1 - role].unwrap(),
                )
            }
            _ => panic!("unexpected pair datagram"),
        };
        send(
            ingress,
            &frame(self.coordinator, &serde_json::to_vec(&reply).unwrap()),
            to,
        );
    }
}

fn pair_run(blocked: bool) -> [NetworkTraversalV1; 2] {
    let relay = socket(Ipv6Addr::LOCALHOST.into());
    relay
        .set_read_timeout(Some(Duration::from_millis(5)))
        .unwrap();
    let mut fixture = PairFixture::new(blocked);
    let mut probes = [Probe::new(), Probe::new()];
    for (role, probe) in probes.iter_mut().enumerate() {
        probe.send(&fixture.request(role, relay.local_addr().unwrap()));
    }
    let mut records = [None, None];
    let end = Instant::now() + WAIT;
    let mut packet = [0; 1024];
    while records.iter().any(Option::is_none) {
        assert!(Instant::now() < end, "pair timed out");
        match relay.recv_from(&mut packet) {
            Ok((n, from)) => fixture.datagram(&relay, &packet[..n], from),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("relay receive: {error}"),
        }
        for (role, probe) in probes.iter_mut().enumerate() {
            if records[role].is_some() {
                continue;
            }
            match probe.output.try_recv() {
                Ok(record) if record["type"] == "transcript" => records[role] = Some(record),
                Ok(record) => probe.respond(fixture.reply(role, record)),
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => panic!("pair probe exited without transcript"),
            }
        }
    }
    let reports = std::array::from_fn(|role| {
        let record = records[role].take().unwrap();
        let rows = ledger(&record, "pair");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["seam"], "pair");
        assert_eq!(
            rows[0]["local"],
            fixture.registered[role].unwrap().to_string()
        );
        assert_eq!(rows[0]["sentDatagrams"], fixture.sent[role]);
        assert!(fixture.direct[role] > 0);
        assert_eq!(fixture.relayed[role], 2);
        let report: NetworkTraversalV1 = serde_json::from_value(record["result"].clone()).unwrap();
        assert_eq!(report.phases.len(), 2, "{record}");
        assert_eq!(report.proofs.len(), 2);
        for proof in &report.proofs {
            let TraversalProofV1::DeviceSignature {
                transcript,
                signature,
            } = proof
            else {
                panic!("expected device signature")
            };
            let public_key = Ed25519KeyPair::from_seed_unchecked(&[role as u8 + 1; 32]).unwrap();
            verify_signature(
                public_key.public_key().as_ref(),
                &transcript.signing_message().unwrap(),
                signature,
            );
        }
        report
    });
    for probe in probes {
        probe.finish(true);
    }
    for (index, stage) in [TraversalStage::Direct, TraversalStage::RelayControl]
        .into_iter()
        .enumerate()
    {
        for report in &reports {
            assert_eq!(report.phases[index].stage, stage);
        }
        let result = validate_pair_transcripts(
            &fixture.descriptors[0],
            &fixture.descriptors[1],
            reports[0].proofs[index].transcript(),
            reports[1].proofs[index].transcript(),
            fixture.until,
        );
        assert_eq!(
            result.is_ok(),
            !blocked || stage == TraversalStage::RelayControl
        );
    }
    reports
}

#[test]
fn pair_corroborates_direct_and_relay_and_separates_blocked_direct_traffic() {
    let direct = pair_run(false);
    let blocked = pair_run(true);
    for (direct, blocked) in direct.iter().zip(blocked.iter()) {
        assert_eq!(direct.phases[0].outcome, TraversalOutcome::Succeeded);
        assert_eq!(
            blocked.phases[0].outcome,
            TraversalOutcome::DirectNotEstablishedInTest
        );
        assert_eq!(direct.phases[1].outcome, TraversalOutcome::Succeeded);
        assert_eq!(blocked.phases[1].outcome, TraversalOutcome::Succeeded);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn sigterm_before_the_request_newline_refuses_without_a_transcript() {
    let mut probe = Probe::new();
    probe
        .input
        .as_mut()
        .unwrap()
        .write_all(b"{\"version\":2")
        .unwrap();
    // Wait for the actual signal handler installation without completing stdin.
    let status = format!("/proc/{}/status", probe.child.id());
    let end = Instant::now() + WAIT;
    loop {
        let status = std::fs::read_to_string(&status).unwrap();
        let caught = status
            .lines()
            .find_map(|line| line.strip_prefix("SigCgt:"))
            .unwrap();
        let mask = u64::from_str_radix(caught.trim(), 16).unwrap();
        if mask & (1 << (libc::SIGTERM - 1)) != 0 {
            break;
        }
        assert!(
            Instant::now() < end,
            "signal handler installation timed out"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    probe.signal();
    probe.finish(false);
}
