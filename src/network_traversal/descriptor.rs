use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalMode {
    Observe,
    Mapping,
    Pair,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalOperation {
    DiscoverGateway,
    ObserveMapping,
    ObserveFiltering,
    BaselineTcp,
    BaselineUdp,
    RegisterEndpoint,
    MapPcp,
    MapNatPmp,
    MapUpnp,
    PairDirectUdp,
    PairRelayControl,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalRouterProtocol {
    Pcp,
    NatPmp,
    UpnpIgd,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalParticipantRole {
    First,
    Second,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraversalBudgets {
    pub experiment_ms: u64,
    pub cleanup_reserve_ms: u64,
    pub outbound_datagrams: u16,
    pub datagram_bytes: u16,
    pub control_requests: u16,
    pub external_dialbacks: u16,
    pub relay_bytes_per_direction: u32,
    pub concurrent_mapping_leases: u8,
    /// Reserved before create, unavailable to discovery/retries even on a lost reply.
    pub cleanup_datagrams: u16,
    pub cleanup_control_requests: u16,
}
impl TraversalBudgets {
    pub fn validate(&self) -> Result<(), TraversalRefusal> {
        // ADR-0234 ceilings may be reduced by a frozen profile, never expanded.
        if self.experiment_ms == 0
            || self.experiment_ms > TRAVERSAL_EXPERIMENT_MAX_MS
            || self.cleanup_reserve_ms == 0
            || self.cleanup_reserve_ms > TRAVERSAL_CLEANUP_RESERVE_MS
            || self.cleanup_reserve_ms >= self.experiment_ms
            || self.outbound_datagrams > 64
            || self.datagram_bytes > 512
            || self.control_requests > 12
            || self.external_dialbacks > 4
            || self.relay_bytes_per_direction > 65_536
            || self.concurrent_mapping_leases > 2
            || self.cleanup_datagrams > self.outbound_datagrams
            || self.cleanup_control_requests > self.control_requests
            || (self.outbound_datagrams > 0 && self.datagram_bytes == 0)
        {
            return Err(TraversalRefusal::InvalidBudget);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraversalMappingConsent {
    pub consent_reference: String,
    pub processor_allowlist_digest: String,
    pub exclusive_reservation_digest: String,
    pub prior_uncertainty_resolved: bool,
    pub finite_expiry_verified: bool,
    pub expires_at_ms: u64,
    pub protocols: Vec<TraversalRouterProtocol>,
    pub requested_lease_sec: u16,
    pub maximum_lease_sec: u16,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraversalParticipant {
    pub role: TraversalParticipantRole,
    pub launch_instance_digest: String,
    pub claim_authority_digest: String,
    pub runtime_signer: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraversalPair {
    pub pair_id: String,
    pub expires_at_ms: u64,
    /// Fixed ordered slots; never a list of candidates or raw job identities.
    pub participants: [TraversalParticipant; 2],
}

/// Full descriptor travels over bounded authenticated control, never each UDP packet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraversalDescriptorV1 {
    pub version: u8,
    pub run_id: String,
    pub mode: TraversalMode,
    pub claim_authority_digest: String,
    pub profile_version: String,
    pub catalog_version: String,
    pub artifact_digest: String,
    pub helper_version: String,
    pub helper_digest: String,
    pub endpoint_set_revision: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub deadline_ms: u64,
    pub operations: Vec<TraversalOperation>,
    pub budgets: TraversalBudgets,
    pub mapping: Option<TraversalMappingConsent>,
    pub pair: Option<TraversalPair>,
    pub participant_role: Option<TraversalParticipantRole>,
}
impl TraversalDescriptorV1 {
    pub fn validate(&self) -> Result<(), TraversalRefusal> {
        if self.version != 1 {
            return Err(TraversalRefusal::UnknownVersion);
        }
        if !lower_hex(&self.run_id, 16)
            || ![
                &self.claim_authority_digest,
                &self.artifact_digest,
                &self.helper_digest,
            ]
            .into_iter()
            .all(|s| digest(s))
            || ![
                &self.profile_version,
                &self.catalog_version,
                &self.helper_version,
                &self.endpoint_set_revision,
            ]
            .into_iter()
            .all(|s| text(s))
        {
            return Err(TraversalRefusal::InvalidBinding);
        }
        self.budgets.validate()?;
        if self.expires_at_ms > SAFE_INTEGER
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > TRAVERSAL_CAPABILITY_MAX_MS
            || self.deadline_ms <= self.issued_at_ms
            || self.deadline_ms > self.expires_at_ms
        {
            return Err(TraversalRefusal::InvalidDeadline);
        }
        if self.operations.is_empty()
            || self.operations.len() > 11
            || self.operations.windows(2).any(|w| w[0] >= w[1])
        {
            return Err(TraversalRefusal::InvalidScope);
        }
        for op in &self.operations {
            use TraversalOperation::*;
            let allowed = match op {
                MapPcp | MapNatPmp | MapUpnp => self.mode == TraversalMode::Mapping,
                RegisterEndpoint | PairDirectUdp | PairRelayControl => {
                    self.mode == TraversalMode::Pair
                }
                DiscoverGateway | ObserveMapping | ObserveFiltering | BaselineTcp | BaselineUdp => {
                    self.mode != TraversalMode::Pair
                }
            };
            if !allowed {
                return Err(TraversalRefusal::InvalidScope);
            }
        }
        match (self.mode, &self.mapping) {
            (TraversalMode::Mapping, Some(consent)) => {
                if !text(&consent.consent_reference)
                    || !digest(&consent.processor_allowlist_digest)
                    || !digest(&consent.exclusive_reservation_digest)
                    || !consent.prior_uncertainty_resolved
                    || !consent.finite_expiry_verified
                    || consent.expires_at_ms < self.expires_at_ms
                    || consent.expires_at_ms > SAFE_INTEGER
                    || consent.requested_lease_sec != 60
                    || consent.maximum_lease_sec < 60
                    || consent.maximum_lease_sec > 120
                    || consent.protocols.is_empty()
                    || consent.protocols.len() > 3
                    || consent.protocols.windows(2).any(|w| w[0] >= w[1])
                    || self.budgets.concurrent_mapping_leases == 0
                {
                    return Err(TraversalRefusal::InvalidConsent);
                }
                let mutates = |protocol| match protocol {
                    TraversalRouterProtocol::Pcp => TraversalOperation::MapPcp,
                    TraversalRouterProtocol::NatPmp => TraversalOperation::MapNatPmp,
                    TraversalRouterProtocol::UpnpIgd => TraversalOperation::MapUpnp,
                };
                if consent
                    .protocols
                    .iter()
                    .any(|p| !self.operations.contains(&mutates(*p)))
                    || [
                        TraversalRouterProtocol::Pcp,
                        TraversalRouterProtocol::NatPmp,
                        TraversalRouterProtocol::UpnpIgd,
                    ]
                    .into_iter()
                    .any(|p| {
                        self.operations.contains(&mutates(p)) && !consent.protocols.contains(&p)
                    })
                    || self.budgets.cleanup_datagrams
                        < u16::from(self.budgets.concurrent_mapping_leases)
                    || self.budgets.cleanup_control_requests
                        < u16::from(self.budgets.concurrent_mapping_leases)
                {
                    return Err(TraversalRefusal::InvalidConsent);
                }
            }
            (TraversalMode::Mapping, None) => return Err(TraversalRefusal::InvalidConsent),
            (_, Some(_)) => return Err(TraversalRefusal::InvalidScope),
            (_, None)
                if self.budgets.concurrent_mapping_leases != 0
                    || self.budgets.cleanup_datagrams != 0
                    || self.budgets.cleanup_control_requests != 0 =>
            {
                return Err(TraversalRefusal::InvalidScope);
            }
            _ => {}
        }
        match (self.mode, &self.pair, self.participant_role) {
            (TraversalMode::Pair, Some(pair), Some(role)) => {
                let [a, b] = &pair.participants;
                if !lower_hex(&pair.pair_id, 16)
                    || pair.expires_at_ms != self.expires_at_ms
                    || a.role != TraversalParticipantRole::First
                    || b.role != TraversalParticipantRole::Second
                    || a.launch_instance_digest == b.launch_instance_digest
                    || a.claim_authority_digest == b.claim_authority_digest
                    || pair.participants.iter().any(|p| {
                        !digest(&p.launch_instance_digest)
                            || !digest(&p.claim_authority_digest)
                            || p.runtime_signer
                                .strip_prefix("0x")
                                .is_none_or(|s| !lower_hex(s, 32))
                    })
                    || pair
                        .participants
                        .iter()
                        .find(|p| p.role == role)
                        .is_none_or(|p| p.claim_authority_digest != self.claim_authority_digest)
                {
                    return Err(TraversalRefusal::InvalidPair);
                }
            }
            (TraversalMode::Pair, _, _) => return Err(TraversalRefusal::InvalidPair),
            (_, None, None) => {}
            _ => return Err(TraversalRefusal::InvalidScope),
        }
        if self.mode != TraversalMode::Pair && self.budgets.relay_bytes_per_direction != 0 {
            return Err(TraversalRefusal::InvalidScope);
        }
        bounded(self, TRAVERSAL_BLOCK_MAX_BYTES)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TraversalRefusal> {
        self.validate()?;
        canonical(self)
    }
    pub fn binding_digest(&self) -> Result<String, TraversalRefusal> {
        Ok(sha256(&self.canonical_bytes()?))
    }
    pub fn validate_at(&self, now_ms: u64) -> Result<(), TraversalRefusal> {
        self.validate()?;
        if now_ms < self.issued_at_ms {
            return Err(TraversalRefusal::NotYetValid);
        }
        if now_ms >= self.expires_at_ms {
            return Err(TraversalRefusal::Expired);
        }
        Ok(())
    }
    /// Delivery reserve comes from the frozen existing helper profile, never a client override.
    /// Cleanup is already inside experiment_ms; it must not be added twice.
    pub fn can_start(
        &self,
        now_ms: u64,
        job_expires_at_ms: u64,
        delivery_reserve_ms: u64,
    ) -> Result<(), TraversalRefusal> {
        self.validate_at(now_ms)?;
        let end = now_ms
            .checked_add(self.budgets.experiment_ms)
            .ok_or(TraversalRefusal::InsufficientTime)?;
        let delivered = end
            .checked_add(delivery_reserve_ms)
            .ok_or(TraversalRefusal::InsufficientTime)?;
        if end > self.deadline_ms || delivered > self.expires_at_ms.min(job_expires_at_ms) {
            return Err(TraversalRefusal::InsufficientTime);
        }
        Ok(())
    }
}

/// Pair halves must agree on the entire frozen experiment except their own
/// claim/role. Neither a guessable pair id nor matching profile alone is enough.
pub fn validate_traversal_pair(
    first: &TraversalDescriptorV1,
    second: &TraversalDescriptorV1,
) -> Result<(), TraversalRefusal> {
    first.validate()?;
    second.validate()?;
    if first.mode != TraversalMode::Pair
        || first.participant_role != Some(TraversalParticipantRole::First)
        || second.participant_role != Some(TraversalParticipantRole::Second)
    {
        return Err(TraversalRefusal::InvalidPair);
    }
    let mut counterpart = first.clone();
    counterpart.participant_role = second.participant_role;
    counterpart.claim_authority_digest = second.claim_authority_digest.clone();
    if counterpart != *second {
        return Err(TraversalRefusal::InvalidPair);
    }
    Ok(())
}
