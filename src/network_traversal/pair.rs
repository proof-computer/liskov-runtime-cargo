//! ADR-0234 pair collection for an explicitly authorized, dormant caller.
//! Each helper owns one grant and uses one unconnected socket. Rendezvous owns
//! candidate selection, and only two independently signed results corroborate
//! the helper-observed path. The released helper does not invoke this module.

#[cfg(any(test, feature = "fact-probe"))]
mod fixture;
mod run;
mod transport;
pub(super) mod wire;

pub use transport::{HttpsPairNetwork, PairIoError, PairNetwork};

use super::*;
use crate::processor_facts::FactSigner;
use run::Run;
use wire::Phase;

pub struct PairBindings<'a> {
    pub claim_authority_digest: &'a str,
    pub artifact_digest: &'a str,
    pub helper: &'a TraversalHelperIdentity,
    pub runtime_signer: &'a str,
}

/// A one-shot session constructed from this helper's authenticated bootstrap.
/// It neither requests the other grant nor holds a capability/receipt MAC key.
pub struct PairSession {
    capability: TraversalCapabilityV1,
    reservation: Reservation,
    started_at_ms: u64,
    descriptor_digest: String,
    pair_binding: String,
    pair_id: String,
    role: TraversalParticipantRole,
    signer_key: [u8; 32],
}

impl PairSession {
    pub fn from_authenticated_bootstrap(
        capability: TraversalCapabilityV1,
        bindings: PairBindings<'_>,
        now_ms: u64,
        job_expires_at_ms: u64,
    ) -> Result<Self, TraversalRefusal> {
        let descriptor = &capability.descriptor;
        let reservation = match reserve_traversal(&ReserveInput {
            grant: Some(&capability),
            now_ms,
            job_expires_at_ms,
            artifact_digest: bindings.artifact_digest,
            helper: bindings.helper,
            effects: &NopTraversalEffects,
        }) {
            ReserveOutcome::Reserved(reservation) => reservation,
            ReserveOutcome::Refused(reason) => return Err(reason),
            _ => return Err(TraversalRefusal::InsufficientTime),
        };
        let (Some(pair), Some(role)) = (&descriptor.pair, descriptor.participant_role) else {
            return Err(TraversalRefusal::InvalidPair);
        };
        let me = &pair.participants[match role {
            TraversalParticipantRole::First => 0,
            TraversalParticipantRole::Second => 1,
        }];
        if me.claim_authority_digest != bindings.claim_authority_digest
            || me.runtime_signer != bindings.runtime_signer
        {
            return Err(TraversalRefusal::InvalidBinding);
        }
        if !descriptor
            .operations
            .contains(&TraversalOperation::RegisterEndpoint)
            || !descriptor.operations.iter().any(|operation| {
                matches!(
                    operation,
                    TraversalOperation::PairDirectUdp | TraversalOperation::PairRelayControl
                )
            })
        {
            return Err(TraversalRefusal::InvalidScope);
        }
        let mut signer_key = [0; 32];
        hex::decode_to_slice(&me.runtime_signer[2..], &mut signer_key)
            .map_err(|_| TraversalRefusal::InvalidBinding)?;
        Ok(Self {
            descriptor_digest: descriptor.binding_digest()?,
            pair_binding: sha256(&canonical(pair)?),
            pair_id: pair.pair_id.clone(),
            capability,
            reservation,
            started_at_ms: now_ms,
            role,
            signer_key,
        })
    }

    /// Return an address-free traversal block. The run drops its socket,
    /// candidate tuples and coordinator frames before signing the transcripts.
    pub fn collect(
        self,
        network: &mut dyn PairNetwork,
        signer: &dyn FactSigner,
    ) -> Result<NetworkTraversalV1, TraversalRefusal> {
        let now_ms = network.now_ms();
        let descriptor = &self.capability.descriptor;
        descriptor.validate_at(now_ms)?;
        if network.endpoint_revision() != descriptor.endpoint_set_revision
            || now_ms < self.started_at_ms
        {
            return Err(TraversalRefusal::InvalidBinding);
        }
        let family = if network.coordinator().is_ipv4() {
            TraversalFamily::V4
        } else {
            TraversalFamily::V6
        };
        let observations = Run::collect(&self, network)?;
        let now_ms = network.now_ms();
        let duration_ms = now_ms
            .min(self.reservation.collector_end_ms)
            .saturating_sub(self.started_at_ms);
        let mut result = NetworkTraversalV1 {
            version: 1,
            descriptor_digest: self.descriptor_digest.clone(),
            run_id: descriptor.run_id.clone(),
            mode: TraversalMode::Pair,
            started_at_ms: self.started_at_ms,
            duration_ms,
            phases: Vec::new(),
            proofs: Vec::new(),
        };
        for observation in observations {
            let (stage, transport, domain) = match observation.phase {
                Phase::Direct => (
                    TraversalStage::Direct,
                    TraversalTransport::Udp,
                    TRAVERSAL_DIRECT_PEER_DOMAIN,
                ),
                Phase::RelayControl => (
                    TraversalStage::RelayControl,
                    TraversalTransport::RelayControl,
                    TRAVERSAL_RELAY_PEER_DOMAIN,
                ),
            };
            let authority = TraversalEvidenceAuthority::HelperObservedPeer;
            let elapsed_ms = observation
                .stopped_at_ms
                .saturating_sub(self.started_at_ms)
                .min(duration_ms);
            let mut phase = TraversalPhaseV1 {
                stage,
                method: TraversalMethod::Pair,
                transport,
                family,
                authority,
                outcome: observation.outcome,
                elapsed_ms,
                granted_lease_sec: None,
                cleanup: None,
                protocol_error: None,
                error_class: observation.error_class,
                proof_digest: None,
            };
            let transcript = TraversalTranscriptV1 {
                version: 1,
                domain: domain.into(),
                descriptor_digest: self.descriptor_digest.clone(),
                run_id: descriptor.run_id.clone(),
                pair_id: Some(self.pair_id.clone()),
                participant_role: Some(self.role),
                authority,
                stage,
                method: phase.method,
                transport,
                family,
                challenge: commit_nonce(domain, &observation.challenge),
                peer_challenge: observation
                    .peer_challenge
                    .map(|nonce| commit_nonce(domain, &nonce)),
                expires_at_ms: descriptor.expires_at_ms,
                outcome: phase.outcome,
                elapsed_ms,
                granted_lease_sec: None,
                cleanup: None,
                protocol_error: None,
                error_class: phase.error_class,
            };
            transcript.validate_scope(descriptor, now_ms)?;
            let bytes = transcript.signing_message()?;
            let signature = signer
                .sign_ed25519(&bytes)
                .ok_or(TraversalRefusal::InvalidProof)?;
            self.verify_signature(&bytes, &signature)?;
            let proof = TraversalProofV1::DeviceSignature {
                transcript,
                signature,
            };
            phase.proof_digest = Some(proof.binding_digest()?);
            result.proofs.push(proof);
            result.phases.push(phase);
        }
        result.validate_scope(descriptor, now_ms)?;
        Ok(result)
    }

    fn verify_signature(&self, message: &[u8], signature: &str) -> Result<(), TraversalRefusal> {
        let value = signature
            .strip_prefix("0x")
            .filter(|value| lower_hex(value, 64))
            .ok_or(TraversalRefusal::InvalidProof)?;
        let mut signature = [0; 64];
        hex::decode_to_slice(value, &mut signature).map_err(|_| TraversalRefusal::InvalidProof)?;
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, self.signer_key)
            .verify(message, &signature)
            .map_err(|_| TraversalRefusal::InvalidProof)
    }
}

fn commit_nonce(domain: &str, nonce: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update([0]);
    hash.update(nonce.as_bytes());
    hex::encode(hash.finalize())
}

#[cfg(test)]
mod tests;

/// Offline loopback proof used by the feature-gated fact probe under QEMU.
#[cfg(feature = "fact-probe")]
pub fn run_pair_fact_fixture() -> bool {
    let paired = fixture::paired(fixture::Topology::Direct);
    fixture::corroborated(&paired, TraversalStage::Direct)
        && fixture::corroborated(&paired, TraversalStage::RelayControl)
}
