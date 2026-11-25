use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::processor_facts::FactSigner;

use super::super::lifecycle::fixture::{CLIENT, ROUTER, selected_gateway};
use super::super::*;
use super::channel::{Channel, cancelled};
use super::request::MappingEndpoints;
use super::socket::{Ledger, Seam, Socket};
use super::{Clock, FixtureSigner};

const CHECK_PATH: &str = "/v1/traversal/path/check";
const RECEIPT_PATH: &str = "/v1/traversal/path/receipt";
const ROUTER_WAIT: Duration = Duration::from_millis(500);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PathRequest<'a> {
    capability: &'a str,
    method: TraversalMethod,
    transport: TraversalTransport,
    family: TraversalFamily,
    port: u16,
    mapping_address: Option<Ipv4Addr>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Detail {
    Reachable,
    Refused,
    Timeout,
    MissingResponse,
    ShortResponse,
    WrongTransaction,
    MissingEgress,
    BudgetExhausted,
    UnverifiableEndpoint,
    ConnectFailed,
}

// The observation is relayed intact as structured wire data to path/receipt.
// Its MAC is opaque to the helper, as with the existing pair control seam.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Observation {
    transcript: TraversalTranscriptV1,
    detail: Detail,
    observation_mac: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptRequest<'a> {
    capability: &'a str,
    observation: &'a Observation,
    device_signature: &'a str,
}

struct Listener {
    socket: Socket,
    port: u16,
    response_done: Arc<AtomicBool>,
}

impl MappingListener for Listener {
    fn port(&self) -> u16 {
        self.port
    }

    fn answer_challenge(
        &mut self,
        _stage: TraversalStage,
        source: IpAddr,
        remaining: Duration,
    ) -> Result<[u8; 32], MappingStop> {
        let end = Instant::now() + remaining;
        let stop = || cancelled() || self.response_done.load(Ordering::Acquire);
        let mut bytes = [0; 33];
        loop {
            let (count, peer) = self
                .socket
                .receive(&mut bytes, end, &stop)
                .map_err(|_| map_stop())?;
            if peer.ip() != source {
                continue;
            }
            let nonce =
                <[u8; 32]>::try_from(&bytes[..count]).map_err(|_| MappingStop::InvalidBinding)?;
            self.socket
                .send(&nonce, peer, end, &stop)
                .map_err(|_| map_stop())?;
            return Ok(nonce);
        }
    }
}

fn map_stop() -> MappingStop {
    if cancelled() {
        MappingStop::GracefulShutdown
    } else {
        MappingStop::Deadline
    }
}

fn control_stop(error: io::Error) -> MappingStop {
    match error.kind() {
        io::ErrorKind::InvalidData => MappingStop::InvalidBinding,
        io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => map_stop(),
        _ => MappingStop::Unsupported,
    }
}

pub(super) struct Adapter<'a> {
    pub clock: Clock,
    pub ledger: Ledger,
    pub control: &'a mut Channel,
    pub capability: &'a str,
    pub signer: &'a FixtureSigner,
    pub endpoints: MappingEndpoints,
    response_done: Arc<AtomicBool>,
    observation: Option<Observation>,
    router: Option<Socket>,
}

impl Adapter<'_> {
    pub(super) fn collect(
        mut self,
        session: MappingSession,
        plan: MappingMethodPlan,
        digest: [u8; 32],
    ) -> Option<MappingRunReport> {
        let gateway = selected_gateway()?;
        let reservation = ExclusiveReservation::new(ROUTER, digest)?;
        Some(run_mapping_lifecycle(
            session,
            &[plan],
            MappingGateway {
                gateway: &gateway,
                reservation: &reservation,
                local_address: CLIENT,
                external_address: self.endpoints.external_address,
                igd: None,
                discovery_datagrams: 0,
                discovery_control_requests: 0,
            },
            &mut self,
        ))
    }
}

impl<'a> Adapter<'a> {
    pub(super) fn new(
        clock: Clock,
        ledger: Ledger,
        control: &'a mut Channel,
        capability: &'a str,
        signer: &'a FixtureSigner,
        endpoints: MappingEndpoints,
    ) -> Self {
        Self {
            clock,
            ledger,
            control,
            capability,
            signer,
            endpoints,
            response_done: Arc::new(AtomicBool::new(false)),
            observation: None,
            router: None,
        }
    }
}

impl MappingRuntime for Adapter<'_> {
    fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    fn observed_address(&self) -> Ipv4Addr {
        self.endpoints.observed_address
    }

    fn stop(&self) -> Option<MappingStop> {
        cancelled().then_some(MappingStop::GracefulShutdown)
    }

    fn nonce(&mut self) -> Result<[u8; 12], MappingStop> {
        super::random().map_err(|_| MappingStop::Unsupported)
    }

    fn bind_fresh(
        &mut self,
        transport: MappedPortProtocol,
    ) -> Result<Box<dyn MappingListener>, MappingStop> {
        if transport != MappedPortProtocol::Udp {
            return Err(MappingStop::Unsupported);
        }
        let socket = NativeMappingListener::bind_loopback_udp()?;
        let port = socket
            .local_addr()
            .map_err(|_| MappingStop::Unsupported)?
            .port();
        let socket = self
            .ledger
            .track(socket, None, Seam::MappingListener)
            .map_err(|_| MappingStop::Unsupported)?;
        Ok(Box::new(Listener {
            socket,
            port,
            response_done: self.response_done.clone(),
        }))
    }

    fn path_check(
        &mut self,
        listener: &mut dyn MappingListener,
        check: MappingPathCheck,
        deadline_ms: u64,
    ) -> Result<MappingPathEvidence, MappingStop> {
        let until = self.clock.deadline(deadline_ms);
        let request = PathRequest {
            capability: self.capability,
            method: check.method,
            transport: check.transport,
            family: check.family,
            port: check.port,
            // The lifecycle calls mapping verification only after comparing
            // the router-discovered address to the control-observed address.
            mapping_address: (check.stage == TraversalStage::MappingVerify)
                .then_some(self.observed_address()),
        };
        let body = serde_json::to_vec(&request).map_err(|_| MappingStop::InvalidBinding)?;
        self.control
            .start(CHECK_PATH, &body, until)
            .map_err(control_stop)?;
        self.response_done.store(false, Ordering::Release);
        let (reply, echo) = std::thread::scope(|scope| {
            let control = &mut *self.control;
            let done = &self.response_done;
            let reader = scope.spawn(move || {
                let response = control.response(TRAVERSAL_BLOCK_MAX_BYTES, until);
                done.store(true, Ordering::Release);
                response
            });
            let remaining = until.saturating_duration_since(Instant::now());
            let echo = listener.answer_challenge(
                check.stage,
                self.endpoints.path_source.into(),
                remaining,
            );
            Ok::<_, MappingStop>((reader.join().map_err(|_| MappingStop::Unsupported)?, echo))
        })?;
        let reply = reply.map_err(control_stop)?;
        if reply.status != 200 {
            return Err(MappingStop::InvalidBinding);
        }
        let observation: Observation =
            serde_json::from_slice(&reply.body).map_err(|_| MappingStop::InvalidBinding)?;
        if !lower_hex(&observation.observation_mac, 32) {
            return Err(MappingStop::InvalidBinding);
        }
        let evidence = MappingPathEvidence {
            transcript: observation.transcript.clone(),
            echoed_challenge: echo.ok(),
        };
        self.observation = Some(observation);
        Ok(evidence)
    }

    fn attest_path(
        &mut self,
        transcript: &TraversalTranscriptV1,
        deadline_ms: u64,
    ) -> Result<(), MappingStop> {
        let observation = self.observation.take().ok_or(MappingStop::InvalidBinding)?;
        if observation.transcript != *transcript {
            return Err(MappingStop::InvalidBinding);
        }
        let signed = transcript
            .signing_message()
            .map_err(|_| MappingStop::InvalidBinding)?;
        let signature = self
            .signer
            .sign_ed25519(&signed)
            .ok_or(MappingStop::InvalidBinding)?;
        let request = ReceiptRequest {
            capability: self.capability,
            observation: &observation,
            device_signature: &signature,
        };
        let body = serde_json::to_vec(&request).map_err(|_| MappingStop::InvalidBinding)?;
        let until = self.clock.deadline(deadline_ms);
        self.control
            .start(RECEIPT_PATH, &body, until)
            .map_err(control_stop)?;
        let reply = self
            .control
            .response(TRAVERSAL_BLOCK_MAX_BYTES, until)
            .map_err(control_stop)?;
        if reply.status != 200 {
            return Err(MappingStop::InvalidBinding);
        }
        let receipt: TraversalReceiptV1 =
            serde_json::from_slice(&reply.body).map_err(|_| MappingStop::InvalidBinding)?;
        if receipt.version != 1
            || receipt.transcript != *transcript
            || receipt.device_signature != signature
            || !lower_hex(&receipt.mac, 32)
        {
            return Err(MappingStop::InvalidBinding);
        }
        Ok(())
    }

    fn router_exchange(
        &mut self,
        destination: SocketAddr,
        request: &[u8],
        response: &mut [u8],
        deadline_ms: u64,
    ) -> Result<usize, ControlRefusal> {
        if destination != (ROUTER, ROUTER_CONTROL_PORT).into() {
            return Err(ControlRefusal::WrongTarget);
        }
        let router = self.endpoints.router;
        let socket = match &self.router {
            Some(socket) => socket,
            None => self.router.insert(
                self.ledger
                    .bind(router, None, Seam::RouterClient)
                    .map_err(|_| ControlRefusal::Bounded)?,
            ),
        };
        let until = self
            .clock
            .deadline(deadline_ms)
            .min(Instant::now() + ROUTER_WAIT);
        // Let a create already in flight yield its owned handle on SIGTERM.
        // The lifecycle fences new ordinary requests and sends any owned delete.
        socket
            .send(request, router, until, &|| false)
            .map_err(|_| ControlRefusal::Bounded)?;
        loop {
            let (count, peer) = socket
                .receive(response, until, &|| false)
                .map_err(|_| ControlRefusal::Bounded)?;
            if peer == router {
                return Ok(count);
            }
        }
    }
}
