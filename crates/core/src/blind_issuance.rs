// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Client-side blind issuance flow for privacy-preserving credential issuance.
//!
//! This module implements the wallet's half of the blind attestation protocol.
//! The flow has five steps:
//!
//! 1. The user receives an Ed25519-signed [`DobAttestation`] from a trusted issuer
//!    (for example, a government motor registry).
//! 2. The wallet generates random `r_bits` locally using a CSPRNG.
//! 3. The wallet sends the attestation together with `r_bits` to the Provii
//!    issuer API.
//! 4. Provii computes a Pedersen commitment over the attested date-of-birth and
//!    signs the resulting credential header with RedJubjub.
//! 5. The wallet stores a [`CredentialV2`] containing `dob_days` and `r_bits`,
//!    which are later consumed by the zero knowledge prover.
//!
//! # Security properties
//!
//! * The issuer never observes the commitment `C` or the randomness `r_bits`,
//!   so issuance is unlinkable to later verification sessions.
//! * The user cannot fabricate `dob_days` because Provii re-derives the value
//!   from the Ed25519-attested payload.
//! * Attestations are single-use: the issuer API tracks nonces with a TTL to
//!   prevent replay.
//! * The RedJubjub signature on the credential header is unlinkable to the
//!   original Ed25519 attestation.

use crate::error::{Result, WalletError};
use crate::issuance::R_BITS_LEN;
use crate::types::{CredentialV2, SignedCredentialHeader};
use provii_crypto_commit::{generate_commitment_randomness, pedersen_commit_dob_validated};
use provii_crypto_commons::attestation::DobAttestation;
use provii_crypto_commons::CredMsgV2;
use provii_crypto_sig_redjubjub;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Wire-format request payload sent to the blind issuance endpoint.
///
/// Both fields are base64url-encoded (no padding). The `r_bits` field carries
/// commitment randomness and is zeroised on drop.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct BlindIssuanceRequest {
    /// Base64url-encoded [`DobAttestation`] (Ed25519-signed by the issuer).
    #[zeroize(skip)]
    pub attestation: String,

    /// Base64url-encoded commitment randomness. This value is secret and MUST
    /// NOT be logged or transmitted to any party other than the Provii issuer
    /// API.
    pub r_bits: String,
}

impl core::fmt::Debug for BlindIssuanceRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlindIssuanceRequest")
            .field("attestation", &self.attestation)
            .field("r_bits", &"[REDACTED]")
            .finish()
    }
}

/// Wire-format response payload returned by the blind issuance endpoint.
///
/// Contains the RedJubjub-signed credential header that the wallet combines
/// with its locally held `dob_days` and `r_bits` to produce a full
/// [`CredentialV2`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindIssuanceResponse {
    /// RedJubjub-signed credential header produced by the Provii issuer API.
    pub credential: SignedCredentialHeader,
}

/// State machine for the wallet side of the blind issuance protocol.
///
/// Holds the decoded attestation, the locally generated commitment randomness,
/// and the date-of-birth extracted from the attestation. After the caller
/// obtains a signed credential header from the Provii issuer API, calling
/// [`BlindIssuanceFlow::finalize`] verifies the Pedersen commitment and
/// assembles the complete [`CredentialV2`].
///
/// # Usage
///
/// ```ignore
/// // 1. Receive the attestation from the issuer via deep link.
/// let flow = BlindIssuanceFlow::from_attestation(&attestation_b64)?;
///
/// // 2. Build the request payload for the Provii issuer API.
/// let request = flow.prepare_request()?;
///
/// // 3. POST the request; receive a signed credential header.
/// let response = send_to_provii(request).await?;
///
/// // 4. Verify the commitment and assemble the credential.
/// let credential = flow.finalize(response.credential)?;
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BlindIssuanceFlow {
    /// Decoded attestation received from the issuer.
    #[zeroize(skip)]
    attestation: DobAttestation,

    /// CSPRNG-generated commitment randomness (one bit per element).
    r_bits: Vec<bool>,

    /// Date-of-birth expressed as days since the Unix epoch, extracted from
    /// the attestation at construction time.
    dob_days: i32,
}

impl core::fmt::Debug for BlindIssuanceFlow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlindIssuanceFlow")
            .field("issuer_id", &self.attestation.issuer_id)
            .field("dob_days", &"[REDACTED]")
            .field("r_bits_len", &self.r_bits.len())
            .finish()
    }
}

impl BlindIssuanceFlow {
    /// Construct a new flow from a base64url-encoded [`DobAttestation`].
    ///
    /// Decodes and deserialises the attestation, extracts `dob_days`, and
    /// generates fresh commitment randomness via [`generate_commitment_randomness`].
    ///
    /// # Errors
    ///
    /// Returns [`WalletError::InvalidInput`] if `attestation_b64` is not valid
    /// base64url or does not deserialise to a well-formed [`DobAttestation`].
    pub fn from_attestation(attestation_b64: &str) -> Result<Self> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        // Decode base64
        let attestation_bytes = URL_SAFE_NO_PAD
            .decode(attestation_b64)
            .map_err(|e| WalletError::InvalidInput(format!("Invalid base64: {}", e)))?;

        // Parse JSON
        let attestation: DobAttestation = serde_json::from_slice(&attestation_bytes)
            .map_err(|e| WalletError::InvalidInput(format!("Invalid attestation JSON: {}", e)))?;

        // Extract dob_days
        let dob_days = attestation.dob_days;

        let mut rng = rand::rngs::OsRng;
        let mut r_bits_z = generate_commitment_randomness(&mut rng, R_BITS_LEN);
        let r_bits = std::mem::take(&mut *r_bits_z);

        Ok(Self {
            attestation,
            r_bits,
            dob_days,
        })
    }

    /// Construct a flow with a fixed PRNG seed (deterministic testing only).
    #[cfg(test)]
    pub fn from_attestation_with_seed(attestation_b64: &str, seed: [u8; 32]) -> Result<Self> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use rand::SeedableRng;

        let attestation_bytes = URL_SAFE_NO_PAD
            .decode(attestation_b64)
            .map_err(|e| WalletError::InvalidInput(format!("Invalid base64: {}", e)))?;

        let attestation: DobAttestation = serde_json::from_slice(&attestation_bytes)
            .map_err(|e| WalletError::InvalidInput(format!("Invalid attestation JSON: {}", e)))?;

        let dob_days = attestation.dob_days;
        let mut rng = rand::rngs::StdRng::from_seed(seed);
        let mut r_bits_z = generate_commitment_randomness(&mut rng, R_BITS_LEN);
        let r_bits = std::mem::take(&mut *r_bits_z);

        Ok(Self {
            attestation,
            r_bits,
            dob_days,
        })
    }

    /// Return the issuer identifier from the underlying attestation.
    pub fn issuer_id(&self) -> &str {
        &self.attestation.issuer_id
    }

    /// Return the Unix-epoch timestamp recorded in the attestation.
    pub fn attestation_timestamp(&self) -> u64 {
        self.attestation.timestamp
    }

    /// Serialise the attestation and commitment randomness into a
    /// [`BlindIssuanceRequest`] ready to POST to the Provii issuer API.
    ///
    /// # Errors
    ///
    /// Returns [`WalletError::SerializationError`] if the attestation cannot be
    /// serialised to JSON (should not happen for a well-formed attestation).
    pub fn prepare_request(&self) -> Result<BlindIssuanceRequest> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        // Serialize attestation to JSON
        let attestation_json = serde_json::to_vec(&self.attestation).map_err(|e| {
            WalletError::SerializationError(format!("Failed to serialize attestation: {}", e))
        })?;

        // Encode attestation
        let attestation_b64 = URL_SAFE_NO_PAD.encode(&attestation_json);

        // Pack r_bits to bytes and encode
        let r_bytes = crate::issuance::bits::pack_bits(&self.r_bits);
        let r_bits_b64 = URL_SAFE_NO_PAD.encode(&r_bytes);

        Ok(BlindIssuanceRequest {
            attestation: attestation_b64,
            r_bits: r_bits_b64,
        })
    }

    /// Verify the Pedersen commitment and assemble a complete [`CredentialV2`].
    ///
    /// Re-computes the commitment from the locally held `dob_days` and
    /// `r_bits`, then checks it against the `c_bytes` field of the signed
    /// header returned by the Provii issuer API. If they match, the private
    /// fields are spliced in and the full credential is returned.
    ///
    /// This method consumes `self` so that `r_bits` can be moved into the
    /// credential without an extra allocation.
    ///
    /// # Errors
    ///
    /// Returns [`WalletError::ValidationFailed`] if the locally computed
    /// commitment does not match the one in the header.
    pub fn finalize(mut self, header: SignedCredentialHeader) -> Result<CredentialV2> {
        if header.v != 2 {
            return Err(WalletError::ValidationFailed(format!(
                "unsupported credential version: expected 2, got {}",
                header.v
            )));
        }
        if header.iat == 0 || header.exp == 0 {
            return Err(WalletError::ValidationFailed(
                "credential timestamps must not be zero".to_string(),
            ));
        }
        if header.iat > header.exp {
            return Err(WalletError::ValidationFailed(format!(
                "credential iat ({}) exceeds exp ({})",
                header.iat, header.exp
            )));
        }

        // Verify the commitment matches what we expect
        let expected_c =
            pedersen_commit_dob_validated(self.dob_days, &self.r_bits).map_err(|e| {
                WalletError::ValidationFailed(format!("Commitment validation failed: {:?}", e))
            })?;

        if !bool::from(expected_c.ct_eq(&header.c_bytes)) {
            return Err(WalletError::ValidationFailed(
                "Commitment mismatch - server computed different commitment than expected"
                    .to_string(),
            ));
        }

        let cred_msg = CredMsgV2 {
            v: header.v,
            kid: header.kid.clone(),
            c: header.c_bytes,
            iat: header.iat,
            exp: header.exp,
            schema: header.schema.clone(),
        };
        provii_crypto_sig_redjubjub::verify_cred_v2(&cred_msg, &header.sig_rj, &header.issuer_vk)
            .map_err(|e| {
            WalletError::ValidationFailed(format!("RedJubjub signature verification failed: {}", e))
        })?;

        // Take ownership of r_bits before drop
        let r_bits = core::mem::take(&mut self.r_bits);
        let dob_days = self.dob_days;

        // Assemble final credential with private fields
        Ok(CredentialV2 {
            v: header.v,
            kid: header.kid,
            issuer_vk: header.issuer_vk,
            sig_rj: header.sig_rj,
            c_bytes: header.c_bytes,
            iat: header.iat,
            exp: header.exp,
            schema: header.schema,
            dob_days: Some(dob_days),
            r_bits: Some(r_bits),
        })
    }

    /// Compute and return the expected Pedersen commitment bytes.
    ///
    /// # Privacy warning
    ///
    /// The returned value reveals information about `dob_days` when combined
    /// with `r_bits`. This method is gated behind `#[cfg(test)]` or the
    /// `debug-crypto` feature and MUST NOT be called in production builds.
    #[cfg(any(test, feature = "debug-crypto"))]
    pub fn expected_commitment(&self) -> Result<[u8; 32]> {
        pedersen_commit_dob_validated(self.dob_days, &self.r_bits).map_err(|e| {
            WalletError::ValidationFailed(format!("Commitment validation failed: {:?}", e))
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used
)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    fn create_test_attestation(
    ) -> std::result::Result<(DobAttestation, String), Box<dyn std::error::Error>> {
        use ed25519_dalek::SigningKey;
        use rand::{rngs::OsRng, RngCore};

        // Generate test signing key
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);

        // Create attestation
        let dob_days = 18000; // ~49 years old
        let issuer_id = "test-issuer";
        let timestamp = chrono::Utc::now().timestamp() as u64;
        let nonce = [0u8; 32];

        let attestation =
            DobAttestation::create(dob_days, issuer_id, timestamp, nonce, &signing_key)?;

        // Encode as base64
        let attestation_json = serde_json::to_vec(&attestation)?;
        let attestation_b64 = URL_SAFE_NO_PAD.encode(&attestation_json);

        Ok((attestation, attestation_b64))
    }

    #[test]
    fn test_from_attestation() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (attestation, attestation_b64) = create_test_attestation()?;

        let flow = BlindIssuanceFlow::from_attestation(&attestation_b64)?;

        assert_eq!(flow.issuer_id(), attestation.issuer_id);
        assert_eq!(flow.attestation_timestamp(), attestation.timestamp);
        assert_eq!(flow.r_bits.len(), R_BITS_LEN);
        Ok(())
    }

    #[test]
    fn test_prepare_request() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (_, attestation_b64) = create_test_attestation()?;

        let flow = BlindIssuanceFlow::from_attestation(&attestation_b64)?;
        let request = flow.prepare_request()?;

        // Verify attestation can be decoded
        let decoded_attestation = URL_SAFE_NO_PAD.decode(&request.attestation)?;
        assert!(!decoded_attestation.is_empty());

        // Verify r_bits can be decoded
        let decoded_r_bits = URL_SAFE_NO_PAD.decode(&request.r_bits)?;
        assert_eq!(decoded_r_bits.len(), R_BITS_LEN.div_ceil(8));
        Ok(())
    }

    #[test]
    fn test_deterministic_flow() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (_, attestation_b64) = create_test_attestation()?;
        let seed = [42u8; 32];

        let flow1 = BlindIssuanceFlow::from_attestation_with_seed(&attestation_b64, seed)?;
        let flow2 = BlindIssuanceFlow::from_attestation_with_seed(&attestation_b64, seed)?;

        // Same seed should produce same r_bits
        assert_eq!(flow1.r_bits, flow2.r_bits);
        assert_eq!(flow1.expected_commitment()?, flow2.expected_commitment()?);
        Ok(())
    }

    #[test]
    fn test_invalid_base64() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let result = BlindIssuanceFlow::from_attestation("not-valid-base64!!!");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_invalid_json() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let invalid_json = URL_SAFE_NO_PAD.encode("not json");
        let result = BlindIssuanceFlow::from_attestation(&invalid_json);
        assert!(result.is_err());
        Ok(())
    }

    // ============================================================
    // RedJubjub signature verification tests for BlindIssuanceFlow
    // ============================================================

    /// Helper: build a signed [`SignedCredentialHeader`] whose commitment matches
    /// the one expected by `flow`.
    fn create_signed_header_for_flow(
        flow: &BlindIssuanceFlow,
    ) -> std::result::Result<SignedCredentialHeader, Box<dyn std::error::Error>> {
        let c_bytes = flow.expected_commitment()?;

        let sk = provii_crypto_sig_redjubjub::SigningKey::random();
        let vk = sk.verification_key().to_bytes();
        let cred_msg = provii_crypto_commons::CredMsgV2 {
            v: 2,
            kid: "test-key".to_string(),
            c: c_bytes,
            iat: 1000000,
            exp: 2000000,
            schema: "provii.age/0".to_string(),
        };
        let sig_rj = provii_crypto_sig_redjubjub::sign_cred_v2(&cred_msg, &sk.to_bytes())?;

        Ok(SignedCredentialHeader {
            v: 2,
            kid: "test-key".to_string(),
            issuer_vk: vk,
            sig_rj,
            c_bytes,
            iat: 1000000,
            exp: 2000000,
            schema: "provii.age/0".to_string(),
        })
    }

    #[test]
    fn test_blind_finalize_valid_signature() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let (_, attestation_b64) = create_test_attestation()?;
        let seed = [42u8; 32];
        let flow = BlindIssuanceFlow::from_attestation_with_seed(&attestation_b64, seed)?;

        let header = create_signed_header_for_flow(&flow)?;
        let result = flow.finalize(header);
        assert!(
            result.is_ok(),
            "valid signature must be accepted: {:?}",
            result
        );
        Ok(())
    }

    #[test]
    fn test_blind_finalize_rejects_invalid_signature(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // An all-zero sig_rj is not a valid RedJubjub signature.
        let (_, attestation_b64) = create_test_attestation()?;
        let seed = [42u8; 32];
        let flow = BlindIssuanceFlow::from_attestation_with_seed(&attestation_b64, seed)?;
        let c_bytes = flow.expected_commitment()?;

        let sk = provii_crypto_sig_redjubjub::SigningKey::random();
        let vk = sk.verification_key().to_bytes();
        let header = SignedCredentialHeader {
            v: 2,
            kid: "test-key".to_string(),
            issuer_vk: vk,
            sig_rj: [0u8; 64], // invalid
            c_bytes,
            iat: 1000000,
            exp: 2000000,
            schema: "provii.age/0".to_string(),
        };

        let result = flow.finalize(header);
        assert!(result.is_err(), "all-zero signature must be rejected");
        if let Err(WalletError::ValidationFailed(msg)) = result {
            assert!(msg.contains("RedJubjub"), "error must mention RedJubjub");
        } else {
            return Err("Expected ValidationFailed error".into());
        }
        Ok(())
    }

    #[test]
    fn test_blind_finalize_rejects_tampered_signature(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // A valid signature with one flipped byte must be rejected.
        let (_, attestation_b64) = create_test_attestation()?;
        let seed = [42u8; 32];
        let flow = BlindIssuanceFlow::from_attestation_with_seed(&attestation_b64, seed)?;

        let mut header = create_signed_header_for_flow(&flow)?;
        // Flip the last byte of sig_rj.
        header.sig_rj[63] ^= 0xFF;

        let result = flow.finalize(header);
        assert!(result.is_err(), "tampered signature must be rejected");
        Ok(())
    }

    #[test]
    fn test_blind_finalize_rejects_commitment_mismatch(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // A header whose commitment doesn't match must fail before sig verification.
        let (_, attestation_b64) = create_test_attestation()?;
        let seed = [42u8; 32];
        let flow = BlindIssuanceFlow::from_attestation_with_seed(&attestation_b64, seed)?;

        // Sign a header with a different (wrong) commitment.
        let wrong_c = [0xFFu8; 32];
        let sk = provii_crypto_sig_redjubjub::SigningKey::random();
        let vk = sk.verification_key().to_bytes();
        let cred_msg = provii_crypto_commons::CredMsgV2 {
            v: 2,
            kid: "test-key".to_string(),
            c: wrong_c,
            iat: 1000000,
            exp: 2000000,
            schema: "provii.age/0".to_string(),
        };
        let sig_rj = provii_crypto_sig_redjubjub::sign_cred_v2(&cred_msg, &sk.to_bytes())?;
        let header = SignedCredentialHeader {
            v: 2,
            kid: "test-key".to_string(),
            issuer_vk: vk,
            sig_rj,
            c_bytes: wrong_c,
            iat: 1000000,
            exp: 2000000,
            schema: "provii.age/0".to_string(),
        };

        let result = flow.finalize(header);
        assert!(result.is_err(), "wrong commitment must be rejected");
        if let Err(WalletError::ValidationFailed(msg)) = result {
            assert!(
                msg.contains("Commitment mismatch"),
                "error must mention Commitment mismatch"
            );
        } else {
            return Err("Expected ValidationFailed error for commitment mismatch".into());
        }
        Ok(())
    }

    // ====================================================================
    // Mutation-coverage tests: kill surviving mutants in blind_issuance.rs
    // ====================================================================

    /// Kill: blind_issuance.rs:244 replace || with && in BlindIssuanceFlow::finalize
    /// When only iat==0 (but exp!=0), finalize must reject. With && mutant,
    /// (iat==0 && exp==0) would be false when only one is zero.
    #[test]
    fn test_blind_finalize_rejects_zero_iat_only(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (_, attestation_b64) = create_test_attestation()?;
        let seed = [42u8; 32];
        let flow = BlindIssuanceFlow::from_attestation_with_seed(&attestation_b64, seed)?;
        let c_bytes = flow.expected_commitment()?;

        let sk = provii_crypto_sig_redjubjub::SigningKey::random();
        let vk = sk.verification_key().to_bytes();
        let cred_msg = provii_crypto_commons::CredMsgV2 {
            v: 2,
            kid: "test-key".to_string(),
            c: c_bytes,
            iat: 0, // zero iat
            exp: 2000000,
            schema: "provii.age/0".to_string(),
        };
        let sig_rj = provii_crypto_sig_redjubjub::sign_cred_v2(&cred_msg, &sk.to_bytes())?;

        let header = SignedCredentialHeader {
            v: 2,
            kid: "test-key".to_string(),
            issuer_vk: vk,
            sig_rj,
            c_bytes,
            iat: 0,
            exp: 2000000,
            schema: "provii.age/0".to_string(),
        };

        let result = flow.finalize(header);
        assert!(result.is_err(), "zero iat alone must be rejected");
        if let Err(WalletError::ValidationFailed(msg)) = result {
            assert!(
                msg.contains("timestamps must not be zero"),
                "error should mention zero timestamps, got: {}",
                msg
            );
        } else {
            return Err("Expected ValidationFailed for zero iat".into());
        }
        Ok(())
    }

    /// Kill: blind_issuance.rs:244 replace || with && (second case: only exp==0)
    #[test]
    fn test_blind_finalize_rejects_zero_exp_only(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (_, attestation_b64) = create_test_attestation()?;
        let seed = [42u8; 32];
        let flow = BlindIssuanceFlow::from_attestation_with_seed(&attestation_b64, seed)?;
        let c_bytes = flow.expected_commitment()?;

        let sk = provii_crypto_sig_redjubjub::SigningKey::random();
        let vk = sk.verification_key().to_bytes();
        let cred_msg = provii_crypto_commons::CredMsgV2 {
            v: 2,
            kid: "test-key".to_string(),
            c: c_bytes,
            iat: 1000000,
            exp: 0, // zero exp
            schema: "provii.age/0".to_string(),
        };
        let sig_rj = provii_crypto_sig_redjubjub::sign_cred_v2(&cred_msg, &sk.to_bytes())?;

        let header = SignedCredentialHeader {
            v: 2,
            kid: "test-key".to_string(),
            issuer_vk: vk,
            sig_rj,
            c_bytes,
            iat: 1000000,
            exp: 0,
            schema: "provii.age/0".to_string(),
        };

        let result = flow.finalize(header);
        assert!(result.is_err(), "zero exp alone must be rejected");
        if let Err(WalletError::ValidationFailed(msg)) = result {
            assert!(
                msg.contains("timestamps must not be zero"),
                "error should mention zero timestamps, got: {}",
                msg
            );
        } else {
            return Err("Expected ValidationFailed for zero exp".into());
        }
        Ok(())
    }

    /// Kill: blind_issuance.rs:249 replace > with == in BlindIssuanceFlow::finalize
    /// When iat > exp (e.g. iat=2000000, exp=1000000), finalize must reject.
    /// The == mutant would only reject when iat==exp, not when iat>exp.
    #[test]
    fn test_blind_finalize_rejects_iat_exceeds_exp(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (_, attestation_b64) = create_test_attestation()?;
        let seed = [42u8; 32];
        let flow = BlindIssuanceFlow::from_attestation_with_seed(&attestation_b64, seed)?;
        let c_bytes = flow.expected_commitment()?;

        let sk = provii_crypto_sig_redjubjub::SigningKey::random();
        let vk = sk.verification_key().to_bytes();
        let cred_msg = provii_crypto_commons::CredMsgV2 {
            v: 2,
            kid: "test-key".to_string(),
            c: c_bytes,
            iat: 2000000,
            exp: 1000000, // exp < iat
            schema: "provii.age/0".to_string(),
        };
        let sig_rj = provii_crypto_sig_redjubjub::sign_cred_v2(&cred_msg, &sk.to_bytes())?;

        let header = SignedCredentialHeader {
            v: 2,
            kid: "test-key".to_string(),
            issuer_vk: vk,
            sig_rj,
            c_bytes,
            iat: 2000000,
            exp: 1000000,
            schema: "provii.age/0".to_string(),
        };

        let result = flow.finalize(header);
        assert!(result.is_err(), "iat > exp must be rejected");
        if let Err(WalletError::ValidationFailed(msg)) = result {
            assert!(
                msg.contains("iat") && msg.contains("exceeds") && msg.contains("exp"),
                "error should mention iat exceeds exp, got: {}",
                msg
            );
        } else {
            return Err("Expected ValidationFailed for iat > exp".into());
        }
        Ok(())
    }

    /// Kill: blind_issuance.rs:249 replace > with >= in BlindIssuanceFlow::finalize
    /// When iat == exp (both non-zero), finalize must ACCEPT (>= would reject it).
    #[test]
    fn test_blind_finalize_accepts_iat_equals_exp(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (_, attestation_b64) = create_test_attestation()?;
        let seed = [42u8; 32];
        let flow = BlindIssuanceFlow::from_attestation_with_seed(&attestation_b64, seed)?;
        let c_bytes = flow.expected_commitment()?;

        let sk = provii_crypto_sig_redjubjub::SigningKey::random();
        let vk = sk.verification_key().to_bytes();
        let cred_msg = provii_crypto_commons::CredMsgV2 {
            v: 2,
            kid: "test-key".to_string(),
            c: c_bytes,
            iat: 1500000,
            exp: 1500000, // iat == exp
            schema: "provii.age/0".to_string(),
        };
        let sig_rj = provii_crypto_sig_redjubjub::sign_cred_v2(&cred_msg, &sk.to_bytes())?;

        let header = SignedCredentialHeader {
            v: 2,
            kid: "test-key".to_string(),
            issuer_vk: vk,
            sig_rj,
            c_bytes,
            iat: 1500000,
            exp: 1500000,
            schema: "provii.age/0".to_string(),
        };

        let result = flow.finalize(header);
        assert!(
            result.is_ok(),
            "iat == exp (both non-zero) must be accepted, got: {:?}",
            result.err()
        );
        Ok(())
    }
}
