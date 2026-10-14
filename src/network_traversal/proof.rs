use super::*;

pub const TRAVERSAL_EXTERNAL_PATH_DOMAIN: &str = "proof.liskov.network-traversal-external-path.v1";
pub const TRAVERSAL_ROUTER_RESPONSE_DOMAIN: &str =
    "proof.liskov.network-traversal-device-router.v1";
pub const TRAVERSAL_DIRECT_PEER_DOMAIN: &str = "proof.liskov.network-traversal-helper-direct.v1";
pub const TRAVERSAL_RELAY_PEER_DOMAIN: &str = "proof.liskov.network-traversal-helper-relay.v1";
pub const TRAVERSAL_BEHAVIOUR_DOMAIN: &str = "proof.liskov.network-traversal-observed-behaviour.v1";
pub const TRAVERSAL_REGISTRATION_DOMAIN: &str =
    "proof.liskov.network-traversal-endpoint-registration.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalEvidenceAuthority {
    ExternalPath,
    DeviceReportedRouter,
    HelperObservedPeer,
    ProberObservedRegistration,
    ProberObservedBehaviour,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalStage {
    Discovery,
    Baseline,
    MappingCreate,
    MappingVerify,
    MappingCleanup,
    EndpointRegistration,
    Direct,
    RelayControl,
    MappingBehaviour,
    FilteringBehaviour,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalMethod {
    Unassisted,
    UdpMapping,
    UdpFiltering,
    Pcp,
    NatPmp,
    UpnpIgd,
    Pair,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalTransport {
    Tcp,
    Udp,
    RouterControl,
    RelayControl,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalFamily {
    V4,
    V6,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalOutcome {
    Succeeded,
    Failed,
    UnsupportedTopology,
    UnsupportedRuntimeApi,
    UnsupportedSafeOwnership,
    UnsupportedFiniteLease,
    UnverifiableEndpoint,
    SkippedBudget,
    NotStarted,
    DirectNotEstablishedInTest,
    OneWayPeer,
    PeerAbsent,
    WrongPeer,
    LateJoin,
    CandidateRebinding,
    BudgetExhausted,
    ProberNoEgress,
    CreationOutcomeUnknown,
    ExpiryUnknown,
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalErrorClass {
    Timeout,
    ConnectFailed,
    InvalidResponse,
    RateLimited,
    TokenRefused,
    BudgetExhausted,
    MappingConflict,
    LeaseRefused,
    CleanupFailed,
    ProberUnavailable,
    PeerUnavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalCleanup {
    ConfirmedDeleted,
    DeleteFailed,
    LeaseExpiryPending,
    NotCreated,
    CreationOutcomeUnknown,
    ExpiryUnknown,
}

/// Transient device-signature transcript. No addresses, router XML, tokens or packets.
/// Domain is signed with every other field; helpers/probers cannot recast relay as direct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraversalTranscriptV1 {
    pub version: u8,
    pub domain: String,
    pub descriptor_digest: String,
    pub run_id: String,
    pub pair_id: Option<String>,
    pub participant_role: Option<TraversalParticipantRole>,
    pub authority: TraversalEvidenceAuthority,
    pub stage: TraversalStage,
    pub method: TraversalMethod,
    pub transport: TraversalTransport,
    pub family: TraversalFamily,
    pub challenge: String,
    /// Outbound and received peer nonces cross-match between signed pair halves.
    pub peer_challenge: Option<String>,
    pub expires_at_ms: u64,
    pub outcome: TraversalOutcome,
    pub elapsed_ms: u64,
    /// Router response is device-reported even when independently verified later.
    pub granted_lease_sec: Option<u16>,
    pub cleanup: Option<TraversalCleanup>,
    pub protocol_error: Option<u16>,
    pub error_class: Option<TraversalErrorClass>,
}
pub(crate) fn proof_domain(
    authority: TraversalEvidenceAuthority,
    stage: TraversalStage,
    method: TraversalMethod,
    transport: TraversalTransport,
) -> Result<&'static str, TraversalRefusal> {
    use TraversalEvidenceAuthority::*;
    use TraversalMethod::*;
    use TraversalStage::*;
    use TraversalTransport::*;
    match authority {
        ExternalPath
            if matches!(stage, Baseline | MappingVerify)
                && matches!(transport, Tcp | Udp)
                && ((stage == Baseline && method == Unassisted)
                    || (stage == MappingVerify && matches!(method, Pcp | NatPmp | UpnpIgd))) =>
        {
            Ok(TRAVERSAL_EXTERNAL_PATH_DOMAIN)
        }
        DeviceReportedRouter
            if matches!(stage, Discovery | MappingCreate | MappingCleanup)
                && transport == RouterControl
                && matches!(method, Pcp | NatPmp | UpnpIgd) =>
        {
            Ok(TRAVERSAL_ROUTER_RESPONSE_DOMAIN)
        }
        HelperObservedPeer if stage == Direct && transport == Udp && method == Pair => {
            Ok(TRAVERSAL_DIRECT_PEER_DOMAIN)
        }
        HelperObservedPeer
            if stage == TraversalStage::RelayControl
                && transport == TraversalTransport::RelayControl
                && method == Pair =>
        {
            Ok(TRAVERSAL_RELAY_PEER_DOMAIN)
        }
        ProberObservedRegistration
            if stage == EndpointRegistration && transport == Udp && method == Pair =>
        {
            Ok(TRAVERSAL_REGISTRATION_DOMAIN)
        }
        ProberObservedBehaviour
            if transport == Udp
                && ((stage == MappingBehaviour && method == UdpMapping)
                    || (stage == FilteringBehaviour && method == UdpFiltering)) =>
        {
            Ok(TRAVERSAL_BEHAVIOUR_DOMAIN)
        }
        _ => Err(TraversalRefusal::InvalidProof),
    }
}
impl TraversalTranscriptV1 {
    pub fn validate(&self) -> Result<(), TraversalRefusal> {
        use TraversalEvidenceAuthority::*;
        use TraversalMethod::*;
        use TraversalStage::*;
        if self.version != 1 {
            return Err(TraversalRefusal::UnknownVersion);
        }
        if !digest(&self.descriptor_digest)
            || !lower_hex(&self.run_id, 16)
            || !lower_hex(&self.challenge, 32)
            || self.expires_at_ms > SAFE_INTEGER
            || self.elapsed_ms > TRAVERSAL_EXPERIMENT_MAX_MS
        {
            return Err(TraversalRefusal::InvalidBinding);
        }
        let domain = proof_domain(self.authority, self.stage, self.method, self.transport)?;
        if self.domain != domain {
            return Err(TraversalRefusal::WrongDomain);
        }
        if matches!(
            self.outcome,
            TraversalOutcome::EndpointIndependent
                | TraversalOutcome::AddressDependent
                | TraversalOutcome::AddressAndPortDependent
        ) && !matches!(self.stage, MappingBehaviour | FilteringBehaviour)
        {
            return Err(TraversalRefusal::InvalidProof);
        }
        if self.outcome == TraversalOutcome::CreationOutcomeUnknown
            && !matches!(self.stage, MappingCreate | MappingCleanup)
            || self.outcome == TraversalOutcome::ExpiryUnknown && self.stage != MappingCleanup
            || matches!(
                self.outcome,
                TraversalOutcome::DirectNotEstablishedInTest
                    | TraversalOutcome::OneWayPeer
                    | TraversalOutcome::PeerAbsent
                    | TraversalOutcome::WrongPeer
                    | TraversalOutcome::LateJoin
                    | TraversalOutcome::CandidateRebinding
            ) && !matches!(self.stage, Direct | RelayControl)
        {
            return Err(TraversalRefusal::InvalidProof);
        }
        if self.stage == MappingCreate
            && self.outcome == TraversalOutcome::Succeeded
            && self.granted_lease_sec.is_none()
            || self.stage != MappingCleanup && self.cleanup.is_some()
            || !matches!(self.stage, MappingCreate | MappingCleanup)
                && self.granted_lease_sec.is_some()
        {
            return Err(TraversalRefusal::InvalidProof);
        }
        if self.method == Pair {
            if self.pair_id.as_deref().is_none_or(|s| !lower_hex(s, 16))
                || self.participant_role.is_none()
            {
                return Err(TraversalRefusal::InvalidPair);
            }
        } else if self.pair_id.is_some() || self.participant_role.is_some() {
            return Err(TraversalRefusal::InvalidPair);
        }
        if self.authority != DeviceReportedRouter
            && (self.granted_lease_sec.is_some()
                || self.cleanup.is_some()
                || self.protocol_error.is_some())
        {
            return Err(TraversalRefusal::InvalidProof);
        }
        // Overlong grants are reportable refusals, never accepted finite leases.
        if self.granted_lease_sec.is_some_and(|s| s == 0 || s > 120)
            && self.outcome != TraversalOutcome::UnsupportedFiniteLease
        {
            return Err(TraversalRefusal::InvalidProof);
        }
        if self.outcome == TraversalOutcome::Succeeded && self.error_class.is_some()
            || self.outcome == TraversalOutcome::Failed && self.error_class.is_none()
        {
            return Err(TraversalRefusal::InvalidProof);
        }
        if self.stage == MappingCreate
            && self.outcome == TraversalOutcome::CreationOutcomeUnknown
            && self.granted_lease_sec.is_some()
        {
            return Err(TraversalRefusal::InvalidProof);
        }
        if self
            .peer_challenge
            .as_deref()
            .is_some_and(|s| !lower_hex(s, 32))
            || self.peer_challenge.is_some() && !matches!(self.stage, Direct | RelayControl)
            || matches!(self.stage, Direct | RelayControl)
                && self.outcome == TraversalOutcome::Succeeded
                && self.peer_challenge.is_none()
        {
            return Err(TraversalRefusal::InvalidProof);
        }
        if let Some(cleanup) = self.cleanup {
            let consistent = match cleanup {
                TraversalCleanup::ConfirmedDeleted => self.outcome == TraversalOutcome::Succeeded,
                TraversalCleanup::DeleteFailed => self.outcome == TraversalOutcome::Failed,
                TraversalCleanup::LeaseExpiryPending => self.outcome == TraversalOutcome::Unknown,
                TraversalCleanup::NotCreated => self.outcome == TraversalOutcome::NotStarted,
                TraversalCleanup::CreationOutcomeUnknown => {
                    self.outcome == TraversalOutcome::CreationOutcomeUnknown
                }
                TraversalCleanup::ExpiryUnknown => self.outcome == TraversalOutcome::ExpiryUnknown,
            };
            if !consistent {
                return Err(TraversalRefusal::InvalidProof);
            }
        }
        if self.stage == MappingCleanup && self.cleanup.is_none() {
            return Err(TraversalRefusal::InvalidProof);
        }
        bounded(self, TRAVERSAL_BLOCK_MAX_BYTES)
    }
    pub fn signing_message(&self) -> Result<Vec<u8>, TraversalRefusal> {
        self.validate()?;
        canonical(self)
    }
    pub fn validate_scope(
        &self,
        descriptor: &TraversalDescriptorV1,
        now_ms: u64,
    ) -> Result<(), TraversalRefusal> {
        self.validate()?;
        descriptor.validate_at(now_ms)?;
        if self.descriptor_digest != descriptor.binding_digest()?
            || self.run_id != descriptor.run_id
            || self.expires_at_ms != descriptor.expires_at_ms
            || self.participant_role != descriptor.participant_role
            || self.pair_id.as_deref() != descriptor.pair.as_ref().map(|p| p.pair_id.as_str())
        {
            return Err(TraversalRefusal::InvalidBinding);
        }
        let operation = phase_operation(self.stage, self.method, self.transport)?;
        if self.granted_lease_sec.is_some_and(|lease| {
            descriptor
                .mapping
                .as_ref()
                .is_some_and(|c| lease > c.maximum_lease_sec)
        }) && self.outcome != TraversalOutcome::UnsupportedFiniteLease
        {
            return Err(TraversalRefusal::InvalidConsent);
        }
        if !descriptor.operations.contains(&operation)
            || self.elapsed_ms > descriptor.budgets.experiment_ms
        {
            return Err(TraversalRefusal::InvalidScope);
        }
        Ok(())
    }
}

/// MAC attests external path/registration plus the bytes returned by the device.
/// It does NOT verify the device signature. Admission must verify that separately.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraversalReceiptV1 {
    pub version: u8,
    pub transcript: TraversalTranscriptV1,
    pub device_signature: String,
    pub mac: String,
}

pub(crate) fn phase_operation(
    stage: TraversalStage,
    method: TraversalMethod,
    transport: TraversalTransport,
) -> Result<TraversalOperation, TraversalRefusal> {
    Ok(match (stage, method, transport) {
        (TraversalStage::MappingBehaviour, _, _) => TraversalOperation::ObserveMapping,
        (TraversalStage::FilteringBehaviour, _, _) => TraversalOperation::ObserveFiltering,
        (TraversalStage::Discovery, _, _) => TraversalOperation::DiscoverGateway,
        (TraversalStage::Baseline, _, TraversalTransport::Tcp) => TraversalOperation::BaselineTcp,
        (TraversalStage::Baseline, _, TraversalTransport::Udp) => TraversalOperation::BaselineUdp,
        (TraversalStage::EndpointRegistration, _, _) => TraversalOperation::RegisterEndpoint,
        (TraversalStage::Direct, _, _) => TraversalOperation::PairDirectUdp,
        (TraversalStage::RelayControl, _, _) => TraversalOperation::PairRelayControl,
        (_, TraversalMethod::Pcp, _) => TraversalOperation::MapPcp,
        (_, TraversalMethod::NatPmp, _) => TraversalOperation::MapNatPmp,
        (_, TraversalMethod::UpnpIgd, _) => TraversalOperation::MapUpnp,
        _ => return Err(TraversalRefusal::InvalidProof),
    })
}

/// Validate corroborating halves after independently verifying both runtime
/// signatures. This is helper-observed evidence, never a prober direct-path claim.
pub fn validate_pair_transcripts(
    first_descriptor: &TraversalDescriptorV1,
    second_descriptor: &TraversalDescriptorV1,
    first: &TraversalTranscriptV1,
    second: &TraversalTranscriptV1,
    now_ms: u64,
) -> Result<(), TraversalRefusal> {
    validate_traversal_pair(first_descriptor, second_descriptor)?;
    first.validate_scope(first_descriptor, now_ms)?;
    second.validate_scope(second_descriptor, now_ms)?;
    if first.authority != TraversalEvidenceAuthority::HelperObservedPeer
        || second.authority != TraversalEvidenceAuthority::HelperObservedPeer
        || first.stage != second.stage
        || first.transport != second.transport
        || first.family != second.family
        || first.outcome != TraversalOutcome::Succeeded
        || second.outcome != TraversalOutcome::Succeeded
        || first.peer_challenge.as_deref() != Some(second.challenge.as_str())
        || second.peer_challenge.as_deref() != Some(first.challenge.as_str())
    {
        return Err(TraversalRefusal::InvalidProof);
    }
    Ok(())
}
