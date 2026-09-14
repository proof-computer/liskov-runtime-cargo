use super::*;
use futures_util::stream;
use hickory_resolver::TokioAsyncResolver;
use reqwest::{Client, Response};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    time::{Instant, timeout, timeout_at},
};
pub struct SystemNetworkSampler;
impl NetworkSampler for SystemNetworkSampler {
    fn sample(&self, url: &str, challenge: &str, started_at_ms: u64) -> NetworkSampleV1 {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        match runtime {
            Ok(runtime) => runtime.block_on(collect_bounded(
                &mut Live::new(url, challenge),
                started_at_ms,
            )),
            Err(_) => NetworkSampleV1 {
                version: 1,
                started_at_ms,
                duration_ms: 0,
                region: "lhr".into(),
                ipv4_egress: false,
                ipv6_egress: false,
                legs: vec![],
                udp: skipped_udp(0),
                metrics: NetworkMetrics::default(),
                receipt: None,
                errors: vec![NetworkError::ConnectFailed],
            },
        }
    }
}
struct Live {
    url: String,
    challenge: String,
    start: Instant,
    v4: Option<IpAddr>,
    client: Option<Client>,
}
impl Live {
    fn new(url: &str, challenge: &str) -> Self {
        Self {
            url: url.into(),
            challenge: challenge.into(),
            start: Instant::now(),
            v4: None,
            client: None,
        }
    }
    fn clock(&self) -> u64 {
        self.start.elapsed().as_micros().min(30_000_000) as u64
    }
    fn client(ip: IpAddr) -> Result<Client, NetworkError> {
        Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve("liskov-network-prober.fly.dev", SocketAddr::new(ip, 443))
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(12))
            .pool_max_idle_per_host(1)
            .build()
            .map_err(|_| NetworkError::ConnectFailed)
    }
}
async fn bounded_json(mut response: Response) -> Result<Vec<u8>, NetworkError> {
    if !response.status().is_success() {
        return Err(status_error(response.status().as_u16()));
    }
    let mut bytes = vec![];
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| NetworkError::InvalidResponse)?
    {
        if bytes.len() + chunk.len() > 4096 {
            return Err(NetworkError::InvalidResponse);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
fn status_error(status: u16) -> NetworkError {
    match status {
        404 => NetworkError::TokenRefused,
        429 => NetworkError::RateLimited,
        _ => NetworkError::HttpStatus,
    }
}
impl NetworkTransport for Live {
    fn elapsed_us(&self) -> u64 {
        self.clock()
    }
    fn prepare(&mut self) -> Pending<'_, (bool, bool, Option<NetworkError>)> {
        Box::pin(async move {
            if self.url != NETWORK_PROBER_URL {
                return (false, false, Some(NetworkError::InvalidResponse));
            }
            let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
                Ok(r) => r,
                Err(_) => return (false, false, Some(NetworkError::DnsFailed)),
            };
            // Async DNS has its own one-second deadline, rather than a libc
            // resolver thread that can outlive the complete sampling budget.
            let lookups = timeout(Duration::from_secs(1), async {
                tokio::join!(
                    resolver.ipv4_lookup("liskov-network-prober.fly.dev"),
                    resolver.ipv6_lookup("liskov-network-prober.fly.dev")
                )
            })
            .await;
            let (v4, v6) = match lookups {
                Ok((a, aaaa)) => (
                    a.ok()
                        .and_then(|r| r.iter().next().map(|a| IpAddr::V4(a.0))),
                    aaaa.ok()
                        .and_then(|r| r.iter().next().map(|a| IpAddr::V6(a.0))),
                ),
                Err(_) => return (false, false, Some(NetworkError::DnsFailed)),
            };
            self.v4 = v4;
            let check = |ip: Option<IpAddr>| async move {
                let client = Self::client(ip?).ok()?;
                let ok = timeout(Duration::from_secs(1), async {
                    let response = client
                        .get(format!("{NETWORK_PROBER_URL}/v1/healthz"))
                        .send()
                        .await
                        .ok()?;
                    let value: serde_json::Value =
                        serde_json::from_slice(&bounded_json(response).await.ok()?).ok()?;
                    (value["ok"] == true && value["region"] == "lhr").then_some(())
                })
                .await
                .ok()
                .flatten();
                ok.map(|()| client)
            };
            let (c4, c6) = tokio::join!(check(v4), check(v6));
            let flags = (c4.is_some(), c6.is_some());
            self.client = c4.or(c6);
            (
                flags.0,
                flags.1,
                if self.client.is_none() {
                    Some(NetworkError::ConnectFailed)
                } else {
                    None
                },
            )
        })
    }
    fn udp(&mut self) -> Pending<'_, UdpSample> {
        Box::pin(async move {
            let offset = self.clock();
            let start = Instant::now();
            let mut result = UdpSample {
                status: NetworkStatus::Unreachable,
                start_offset_us: offset,
                duration_us: 0,
                sent_us: vec![],
                echoes: vec![],
                error: Some(NetworkError::ConnectFailed),
            };
            let Some(ip) = self.v4 else {
                return result;
            };
            let mut token = [0u8; 32];
            if hex::decode_to_slice(self.challenge.strip_prefix("0x").unwrap_or(""), &mut token)
                .is_err()
            {
                result.error = Some(NetworkError::TokenRefused);
                return result;
            }
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(_) => return result,
            };
            if socket.connect(SocketAddr::new(ip, UDP_PORT)).await.is_err() {
                return result;
            }
            let stop = start + Duration::from_secs(3);
            let mut received = [false; 20];
            let mut buffer = [0u8; UDP_BYTES + 1];
            loop {
                let next = result.sent_us.len();
                let send_at = start + Duration::from_millis(next as u64 * 100);
                tokio::select! {
                    _=tokio::time::sleep_until(stop)=>break,
                    _=tokio::time::sleep_until(send_at),if next<20=>{
                        let sent=start.elapsed().as_micros().min(3_000_000) as u64;
                        let mut packet=[0u8;UDP_BYTES];packet[..32].copy_from_slice(&token);packet[32..34].copy_from_slice(&(next as u16).to_be_bytes());packet[34..42].copy_from_slice(&sent.to_be_bytes());packet[42..46].copy_from_slice(b"LNP1");
                        match timeout_at(stop,socket.send(&packet)).await { Ok(Ok(UDP_BYTES))=>result.sent_us.push(sent),_=>break }
                    },
                    reply=socket.recv(&mut buffer)=>{
                        let n=match reply { Ok(n)=>n,Err(_)=>break };
                        if n!=UDP_BYTES||buffer[..32]!=token||&buffer[42..46]!=b"LNP1"||buffer[46..64].iter().any(|b|*b!=0) { continue; }
                        let seq=u16::from_be_bytes([buffer[32],buffer[33]]) as usize;
                        if seq>=result.sent_us.len()||received[seq] { continue; }
                        if u64::from_be_bytes(buffer[34..42].try_into().expect("fixed packet"))!=result.sent_us[seq] { continue; }
                        received[seq]=true;result.echoes.push(UdpEcho { sequence:seq as u16,received_us:start.elapsed().as_micros().min(3_000_000) as u64 });
                    }
                }
            }
            result.duration_us = start.elapsed().as_micros().min(3_000_000) as u64;
            if !result.echoes.is_empty() {
                result.status = NetworkStatus::Succeeded;
                result.error = None;
            } else if !result.sent_us.is_empty() {
                result.error = Some(NetworkError::Timeout);
            }
            result
        })
    }
    fn transfer(&mut self, id: NetworkLegId) -> Pending<'_, NetworkLeg> {
        Box::pin(async move {
            let offset = self.clock();
            let start = Instant::now();
            let count = Arc::new(AtomicU64::new(0));
            let mut leg = NetworkLeg {
                id,
                status: NetworkStatus::Unreachable,
                start_offset_us: offset,
                duration_us: 0,
                bytes: 0,
                error: Some(NetworkError::ConnectFailed),
            };
            let Some(client) = self.client.as_ref() else {
                return leg;
            };
            let operation = async {
                if id.download() {
                    let size = match id {
                        NetworkLegId::Download1m => "1m",
                        NetworkLegId::Download10m => "10m",
                        _ => "100m",
                    };
                    let mut response = client
                        .get(format!("{}/v1/blob/{size}", self.url))
                        .query(&[("t", &self.challenge)])
                        .header("accept-encoding", "identity")
                        .send()
                        .await
                        .map_err(|_| NetworkError::ConnectFailed)?;
                    if !response.status().is_success() {
                        return Err(status_error(response.status().as_u16()));
                    }
                    if response.content_length() != Some(id.bytes())
                        || response
                            .headers()
                            .get("x-liskov-region")
                            .and_then(|v| v.to_str().ok())
                            != Some("lhr")
                    {
                        return Err(NetworkError::InvalidResponse);
                    }
                    while let Some(chunk) = response
                        .chunk()
                        .await
                        .map_err(|_| NetworkError::InvalidResponse)?
                    {
                        let offset = count.load(Ordering::Relaxed);
                        if offset + chunk.len() as u64 > id.bytes()
                            || !chunk
                                .iter()
                                .enumerate()
                                .all(|(i, b)| *b == ((offset + i as u64) % 251) as u8)
                        {
                            return Err(NetworkError::ByteCountMismatch);
                        }
                        count.fetch_add(chunk.len() as u64, Ordering::Relaxed);
                    }
                    if count.load(Ordering::Relaxed) != id.bytes() {
                        return Err(NetworkError::ByteCountMismatch);
                    }
                } else {
                    let sent = count.clone();
                    let body = stream::unfold(0u64, move |offset| {
                        let sent = sent.clone();
                        async move {
                            if offset >= id.bytes() {
                                return None;
                            }
                            let n = (id.bytes() - offset).min(16384) as usize;
                            sent.fetch_add(n as u64, Ordering::Relaxed);
                            Some((Ok::<_, std::io::Error>(vec![0u8; n]), offset + n as u64))
                        }
                    });
                    let response = client
                        .post(format!("{}/v1/upload", self.url))
                        .query(&[("t", &self.challenge)])
                        .header("content-length", id.bytes())
                        .body(reqwest::Body::wrap_stream(body))
                        .send()
                        .await
                        .map_err(|_| NetworkError::ConnectFailed)?;
                    let value: serde_json::Value =
                        serde_json::from_slice(&bounded_json(response).await?)
                            .map_err(|_| NetworkError::InvalidResponse)?;
                    if value["bytes"].as_u64() != Some(id.bytes()) || value["region"] != "lhr" {
                        return Err(NetworkError::ByteCountMismatch);
                    }
                }
                Ok(())
            };
            let outcome = timeout(Duration::from_millis(id.timeout_ms()), operation)
                .await
                .unwrap_or(Err(NetworkError::Timeout));
            leg.duration_us = start
                .elapsed()
                .as_micros()
                .min(u128::from(id.timeout_ms() * 1000)) as u64;
            leg.bytes = count.load(Ordering::Relaxed).min(id.bytes());
            match outcome {
                Ok(()) => {
                    leg.status = NetworkStatus::Succeeded;
                    leg.error = None;
                }
                Err(e) => {
                    leg.status = NetworkStatus::Failed;
                    leg.error = Some(e);
                }
            }
            leg
        })
    }
    fn receipt(&mut self) -> Pending<'_, Result<NetworkReceipt, NetworkError>> {
        Box::pin(async move {
            let Some(client) = self.client.as_ref() else {
                return Err(NetworkError::ReceiptUnavailable);
            };
            timeout(Duration::from_secs(1), async {
                let response = client
                    .get(format!("{}/v1/receipt", self.url))
                    .query(&[("t", &self.challenge)])
                    .send()
                    .await
                    .map_err(|_| NetworkError::ReceiptUnavailable)?;
                serde_json::from_slice(&bounded_json(response).await?)
                    .map_err(|_| NetworkError::ReceiptUnavailable)
            })
            .await
            .unwrap_or(Err(NetworkError::ReceiptUnavailable))
        })
    }
}
