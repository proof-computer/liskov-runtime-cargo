use std::net::SocketAddr;

use super::super::{TraversalParticipantRole, lower_hex};
use serde::{Deserialize, Serialize};

pub(super) const ENROLL_PATH: &str = "/v1/traversal/pair/enroll";
pub(super) const CONTROL_PATH: &str = "/v1/traversal/pair/control";
pub(super) const COOKIE_PADDING: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
pub(super) const RELAY_DOMAIN: &str = "liskov.network-traversal-relay-control.v1";
pub(super) const DIRECT_DOMAIN: &str = "liskov.network-traversal-pair-direct-udp.v1";
pub(super) const DATAGRAM_MAX: usize = 512;
pub(super) const CONTROL_RESPONSE_MAX: usize = 1024;

pub(super) fn valid_nonce(value: &str) -> bool {
    lower_hex(value, 16) && value.bytes().any(|b| b != b'0')
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Action {
    Candidates,
    Relay,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Control<'a> {
    pub session: &'a str,
    pub action: Action,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Enrollment {
    pub session: String,
    pub until_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Direct,
    RelayControl,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Progress {
    PeerAbsent,
    AwaitingEndpoint,
    Ready,
    AwaitingRelay,
    Cancelled,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Status {
    pub phase: Phase,
    pub progress: Progress,
    pub candidate: Option<SocketAddr>,
    pub until_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Refusal {
    pub status: String,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum Request<'a> {
    Cookie {
        session: &'a str,
        transaction: &'a str,
        padding: &'static str,
    },
    Register {
        session: &'a str,
        transaction: &'a str,
        cookie: &'a str,
    },
    Relay {
        session: &'a str,
        transaction: &'a str,
        cookie: &'a str,
        sequence: u16,
        frame: Frame,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Registration {
    Cookie {
        session: String,
        transaction: String,
        cookie: String,
    },
    Registered,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    content = "nonce",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum Frame {
    Challenge(String),
    Response(String),
}

impl Frame {
    pub fn nonce(&self) -> &str {
        match self {
            Self::Challenge(nonce) | Self::Response(nonce) => nonce,
        }
    }

    pub fn sequence(&self) -> u16 {
        match self {
            Self::Challenge(_) => 0,
            Self::Response(_) => 1,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DirectFrame<'a> {
    pub domain: &'a str,
    pub pair_binding: &'a str,
    pub role: TraversalParticipantRole,
    pub frame: Frame,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RelayDelivery {
    pub domain: String,
    pub pair_id: String,
    pub sender: String,
    pub recipient: String,
    pub sequence: u16,
    pub frame: Frame,
    pub expires_at_ms: u64,
    pub mac: String,
}
