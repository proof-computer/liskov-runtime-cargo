use super::*;

/// Each participant reports only its own half. Admission joins the two independently
/// authorized halves; one helper cannot turn its signature into peer corroboration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkTraversalV1 {
    pub version: u8,
    pub descriptor_digest: String,
    pub run_id: String,
    pub mode: TraversalMode,
    pub started_at_ms: u64,
    pub duration_ms: u64,
    pub phases: Vec<TraversalPhaseV1>,
    /// Transient proof input, not an authorization to persist raw signed payloads.
    pub proofs: Vec<TraversalProofV1>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraversalPhaseV1 {
    pub stage: TraversalStage,
    pub method: TraversalMethod,
    pub transport: TraversalTransport,
    pub family: TraversalFamily,
    pub authority: TraversalEvidenceAuthority,
    pub outcome: TraversalOutcome,
    pub elapsed_ms: u64,
    pub granted_lease_sec: Option<u16>,
    pub cleanup: Option<TraversalCleanup>,
    pub protocol_error: Option<u16>,
    pub error_class: Option<TraversalErrorClass>,
    pub proof_digest: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TraversalProofV1 {
    ProberReceipt {
        receipt: TraversalReceiptV1,
    },
    DeviceSignature {
        transcript: TraversalTranscriptV1,
        signature: String,
    },
}
impl TraversalProofV1 {
    pub fn transcript(&self) -> &TraversalTranscriptV1 {
        match self {
            Self::ProberReceipt { receipt } => &receipt.transcript,
            Self::DeviceSignature { transcript, .. } => transcript,
        }
    }
    pub fn binding_digest(&self) -> Result<String, TraversalRefusal> {
        Ok(sha256(&canonical(self)?))
    }
    pub fn validate(&self) -> Result<(), TraversalRefusal> {
        self.transcript().validate()?;
        match self {
            Self::ProberReceipt { receipt } => {
                traversal_receipt_message(receipt)?;
                if !lower_hex(&receipt.mac, 32) {
                    return Err(TraversalRefusal::InvalidMac);
                }
            }
            Self::DeviceSignature {
                transcript,
                signature,
            } => {
                if !matches!(
                    transcript.authority,
                    TraversalEvidenceAuthority::DeviceReportedRouter
                        | TraversalEvidenceAuthority::HelperObservedPeer
                ) || signature
                    .strip_prefix("0x")
                    .is_none_or(|s| !lower_hex(s, 64))
                {
                    return Err(TraversalRefusal::InvalidProof);
                }
            }
        }
        Ok(())
    }
}
impl TraversalPhaseV1 {
    fn matches(&self, t: &TraversalTranscriptV1) -> bool {
        self.stage == t.stage
            && self.method == t.method
            && self.transport == t.transport
            && self.family == t.family
            && self.authority == t.authority
            && self.outcome == t.outcome
            && self.elapsed_ms == t.elapsed_ms
            && self.granted_lease_sec == t.granted_lease_sec
            && self.cleanup == t.cleanup
            && self.protocol_error == t.protocol_error
            && self.error_class == t.error_class
    }
}
impl NetworkTraversalV1 {
    pub fn validate(&self) -> Result<(), TraversalRefusal> {
        if self.version != 1 {
            return Err(TraversalRefusal::UnknownVersion);
        }
        // Check serialized size before walking attacker-controlled lists.
        bounded(self, TRAVERSAL_BLOCK_MAX_BYTES)?;
        if !digest(&self.descriptor_digest)
            || !lower_hex(&self.run_id, 16)
            || self.started_at_ms > SAFE_INTEGER
            || self.duration_ms > TRAVERSAL_EXPERIMENT_MAX_MS
            || self
                .started_at_ms
                .checked_add(self.duration_ms)
                .is_none_or(|end| end > SAFE_INTEGER)
            || self.phases.is_empty()
            || self.phases.len() > 16
            || self.proofs.len() > 8
        {
            return Err(TraversalRefusal::InvalidBinding);
        }
        let mut used = std::collections::BTreeSet::new();
        for proof in &self.proofs {
            proof.validate()?;
            if proof.transcript().descriptor_digest != self.descriptor_digest
                || proof.transcript().run_id != self.run_id
            {
                return Err(TraversalRefusal::InvalidBinding);
            }
        }
        for phase in &self.phases {
            proof::proof_domain(phase.authority, phase.stage, phase.method, phase.transport)?;
            if phase.elapsed_ms > self.duration_ms {
                return Err(TraversalRefusal::InvalidDeadline);
            }
            if let Some(reference) = &phase.proof_digest {
                if !digest(reference) || !used.insert(reference.clone()) {
                    return Err(TraversalRefusal::InvalidProof);
                }
                let proof = self
                    .proofs
                    .iter()
                    .find(|p| p.binding_digest().as_ref() == Ok(reference))
                    .ok_or(TraversalRefusal::InvalidProof)?;
                if !phase.matches(proof.transcript()) {
                    return Err(TraversalRefusal::InvalidProof);
                }
            } else {
                // Unsupported/not-started summaries cannot claim authenticated attempted success.
                if !matches!(
                    phase.outcome,
                    TraversalOutcome::UnsupportedTopology
                        | TraversalOutcome::UnsupportedRuntimeApi
                        | TraversalOutcome::UnsupportedSafeOwnership
                        | TraversalOutcome::SkippedBudget
                        | TraversalOutcome::NotStarted
                ) || phase.granted_lease_sec.is_some()
                    || phase.cleanup.is_some()
                    || phase.protocol_error.is_some()
                {
                    return Err(TraversalRefusal::InvalidProof);
                }
            }
            match self.mode {
                TraversalMode::Observe
                    if matches!(
                        phase.stage,
                        TraversalStage::MappingCreate
                            | TraversalStage::MappingVerify
                            | TraversalStage::MappingCleanup
                            | TraversalStage::Direct
                            | TraversalStage::RelayControl
                            | TraversalStage::EndpointRegistration
                    ) =>
                {
                    return Err(TraversalRefusal::InvalidScope);
                }
                TraversalMode::Mapping
                    if matches!(
                        phase.stage,
                        TraversalStage::Direct
                            | TraversalStage::RelayControl
                            | TraversalStage::EndpointRegistration
                    ) =>
                {
                    return Err(TraversalRefusal::InvalidScope);
                }
                TraversalMode::Pair
                    if !matches!(
                        phase.stage,
                        TraversalStage::EndpointRegistration
                            | TraversalStage::Direct
                            | TraversalStage::RelayControl
                    ) =>
                {
                    return Err(TraversalRefusal::InvalidScope);
                }
                _ => {}
            }
        }
        if used.len() != self.proofs.len() {
            return Err(TraversalRefusal::InvalidProof);
        }
        Ok(())
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
            || self.mode != descriptor.mode
        {
            return Err(TraversalRefusal::InvalidBinding);
        }
        if self.started_at_ms < descriptor.issued_at_ms
            || self.started_at_ms > now_ms
            || self.started_at_ms + self.duration_ms > now_ms
            || self.started_at_ms + self.duration_ms > descriptor.deadline_ms
            || self.duration_ms > descriptor.budgets.experiment_ms
        {
            return Err(TraversalRefusal::InvalidDeadline);
        }
        for phase in &self.phases {
            if !descriptor.operations.contains(&proof::phase_operation(
                phase.stage,
                phase.method,
                phase.transport,
            )?) {
                return Err(TraversalRefusal::InvalidScope);
            }
        }
        for proof in &self.proofs {
            proof.transcript().validate_scope(descriptor, now_ms)?;
        }
        Ok(())
    }
}

/// Signature field plus a 64-byte hex signature, reserved inside the 16 KiB cap.
const SIGNATURE_JSON_RESERVE: usize = 148;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedCoverageResultV1 {
    #[serde(flatten)]
    pub result: crate::coverage::CoverageResultV1,
    pub signature: String,
}

pub fn coverage_signing_message(
    result: &crate::coverage::CoverageResultV1,
) -> Result<Vec<u8>, TraversalRefusal> {
    if let Some(traversal) = &result.network_traversal {
        traversal.validate()?;
        bounded(
            result,
            TRAVERSAL_ENVELOPE_MAX_BYTES - SIGNATURE_JSON_RESERVE,
        )?;
    }
    let value = serde_json::to_value(result).map_err(|_| TraversalRefusal::Malformed)?;
    Ok(crate::diagnostics::canonical_json_bytes(&value))
}

/// Closed native signed-envelope codec for the new branch. Legacy v1 decoding
/// and its existing limits are unchanged. Callers must still verify signatures.
pub fn decode_traversal_coverage_envelope(
    bytes: &[u8],
) -> Result<SignedCoverageResultV1, TraversalRefusal> {
    if bytes.len() > TRAVERSAL_ENVELOPE_MAX_BYTES {
        return Err(TraversalRefusal::Oversize);
    }
    let signed: SignedCoverageResultV1 =
        serde_json::from_slice(bytes).map_err(|_| TraversalRefusal::Malformed)?;
    if signed.result.network_traversal.is_none() {
        return Err(TraversalRefusal::InvalidScope);
    }
    coverage_signing_message(&signed.result)?;
    if signed
        .signature
        .strip_prefix("0x")
        .is_none_or(|s| !lower_hex(s, 64))
    {
        return Err(TraversalRefusal::InvalidProof);
    }
    Ok(signed)
}

pub fn encode_traversal_coverage_envelope(
    signed: &SignedCoverageResultV1,
) -> Result<Vec<u8>, TraversalRefusal> {
    let bytes = serde_json::to_vec(signed).map_err(|_| TraversalRefusal::Malformed)?;
    decode_traversal_coverage_envelope(&bytes)?;
    Ok(bytes)
}
