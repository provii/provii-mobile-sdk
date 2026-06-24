// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Credential issuance: Pedersen commitment computation and credential finalisation.
//!
//! This module handles the on-device portion of credential issuance. The wallet
//! computes a Pedersen commitment over the user's date of birth with a random
//! blinding factor, sends the commitment to the issuer for signing, then
//! finalises the credential by combining the signed header with the private
//! fields (DOB and blinding bits) that remain on device.
//!
//! The [`bits`] submodule provides pack/unpack helpers for converting the 128-bit
//! blinding factor between `Vec<bool>` and a compact byte representation suitable
//! for storage and transport.

use crate::error::{Result, WalletError};
use crate::types::{CredentialV2, IssuerTrustAnchor, SignedCredentialHeader, TrustedIssuerKey};
use provii_crypto_commit::{generate_commitment_randomness, pedersen_commit_dob_validated};
use provii_crypto_commons::CredMsgV2;
use provii_crypto_sig_redjubjub;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of the blinding factor in bits. All commitment randomness vectors
/// must be exactly this length.
pub const R_BITS_LEN: usize = 128;

/// Components produced by a Pedersen commitment computation.
///
/// Contains the original DOB (days since epoch), the random blinding bits, and
/// the resulting 32-byte commitment. The blinding bits and DOB are zeroised on
/// drop because they constitute secret witness material.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CommitmentParts {
    pub dob_days: i32,
    pub r_bits: Vec<bool>,
    #[zeroize(skip)]
    pub c_bytes: [u8; 32],
}

impl core::fmt::Debug for CommitmentParts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CommitmentParts")
            .field("dob_days", &"[REDACTED]")
            .field("r_bits", &"[REDACTED]")
            .field("c_bytes", &self.c_bytes)
            .finish()
    }
}

/// Compute a Pedersen commitment to a date of birth using cryptographically
/// random blinding.
///
/// Generates [`R_BITS_LEN`] random blinding bits via the platform CSPRNG and
/// evaluates the Pedersen commitment. Returns the DOB, blinding bits, and
/// resulting 32-byte commitment grouped in [`CommitmentParts`].
pub fn compute_commitment(dob_days: i32) -> Result<CommitmentParts> {
    let mut rng = rand::rngs::OsRng;
    let mut r_bits = generate_commitment_randomness(&mut rng, R_BITS_LEN);
    let c_bytes = pedersen_commit_dob_validated(dob_days, &r_bits).map_err(|e| {
        WalletError::ValidationFailed(format!("Commitment generation failed: {:?}", e))
    })?;

    Ok(CommitmentParts {
        dob_days,
        r_bits: std::mem::take(&mut *r_bits),
        c_bytes,
    })
}

/// Compute a commitment with a fixed PRNG seed (deterministic testing only).
#[cfg(test)]
pub fn compute_commitment_with_seed(dob_days: i32, seed: [u8; 32]) -> Result<CommitmentParts> {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::from_seed(seed);
    let mut r_bits = generate_commitment_randomness(&mut rng, R_BITS_LEN);
    let c_bytes = pedersen_commit_dob_validated(dob_days, &r_bits).map_err(|e| {
        WalletError::ValidationFailed(format!("Commitment generation failed: {:?}", e))
    })?;

    Ok(CommitmentParts {
        dob_days,
        r_bits: std::mem::take(&mut *r_bits),
        c_bytes,
    })
}

/// Finalise a credential by combining the issuer-signed header with private fields.
///
/// Validates that `r_bits` is exactly [`R_BITS_LEN`] bits, then recomputes the
/// Pedersen commitment from `dob_days` and `r_bits` to verify it matches the
/// commitment in `header`. Returns the assembled [`CredentialV2`] on success, or
/// an error if the length check or commitment verification fails.
pub fn finalize_credential(
    header: SignedCredentialHeader,
    dob_days: i32,
    r_bits: Vec<bool>,
) -> Result<CredentialV2> {
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

    if r_bits.len() != R_BITS_LEN {
        return Err(WalletError::InvalidInput(format!(
            "r_bits must be {} bits, got {}",
            R_BITS_LEN,
            r_bits.len()
        )));
    }

    let expected_c = pedersen_commit_dob_validated(dob_days, &r_bits).map_err(|e| {
        WalletError::ValidationFailed(format!("Commitment validation failed: {:?}", e))
    })?;
    if !bool::from(expected_c.ct_eq(&header.c_bytes)) {
        return Err(WalletError::ValidationFailed(
            "Commitment mismatch - private fields don't match signed commitment".to_string(),
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

/// Assemble a credential from borrowed components.
///
/// Convenience wrapper around [`finalize_credential`] that accepts references
/// instead of owned values, cloning internally. Useful when the caller needs to
/// retain ownership of the header and blinding bits after assembly.
pub fn assemble_credential(
    header: &SignedCredentialHeader,
    dob_days: i32,
    r_bits: &[bool],
) -> Result<CredentialV2> {
    finalize_credential(header.clone(), dob_days, r_bits.to_vec())
}

/// Parse a JWKS JSON document into a list of trusted issuer keys.
///
/// Only entries with `"kty": "OKP"` and `"crv": "JUBJUB"` are extracted.
/// The `x` field must be a base64url-encoded 32-byte value. Entries that fail
/// these checks are silently skipped so that unrecognised key types in the
/// JWKS do not cause wholesale rejection.
///
/// # Errors
///
/// Returns [`WalletError::SerializationError`] if the top-level JSON structure
/// is invalid (not an object with a `keys` array).
pub fn parse_jwks_into_keys(jwks_json: &str) -> Result<Vec<TrustedIssuerKey>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let jwks: serde_json::Value = serde_json::from_str(jwks_json)
        .map_err(|e| WalletError::SerializationError(format!("invalid JWKS JSON: {}", e)))?;

    let keys_array = jwks
        .get("keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| WalletError::SerializationError("JWKS missing 'keys' array".to_string()))?;

    let mut result = Vec::new();

    for entry in keys_array {
        // Filter for OKP / JUBJUB only.
        let kty = entry.get("kty").and_then(|v| v.as_str()).unwrap_or("");
        let crv = entry.get("crv").and_then(|v| v.as_str()).unwrap_or("");
        if kty != "OKP" || crv != "JUBJUB" {
            continue;
        }

        let kid = match entry.get("kid").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };

        let x_b64 = match entry.get("x").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue,
        };

        let x_bytes = match URL_SAFE_NO_PAD.decode(x_b64) {
            Ok(b) => b,
            Err(_) => continue,
        };

        if x_bytes.len() != 32 {
            continue;
        }

        let mut vk = [0u8; 32];
        vk.copy_from_slice(&x_bytes);

        result.push(TrustedIssuerKey { kid, vk });
    }

    Ok(result)
}

/// Validate that the issuer verification key in a credential header is present
/// in the trust anchor.
///
/// All 32-byte `vk` comparisons are performed with [`subtle::ConstantTimeEq`]
/// to prevent timing side-channels. Kid comparison uses ordinary string
/// equality because `kid` is a public identifier.
///
/// # Errors
///
/// Returns [`WalletError::SecurityError`] when:
///
/// * The trust anchor contains no keys.
/// * No key in the anchor matches the header's `issuer_vk`.
pub fn validate_issuer_vk(
    header: &SignedCredentialHeader,
    anchor: &IssuerTrustAnchor,
) -> Result<()> {
    if anchor.keys.is_empty() {
        return Err(WalletError::SecurityError(
            "issuer trust anchor contains no keys".to_string(),
        ));
    }

    // Walk every trusted key and compare vk in constant time. Using
    // subtle::ConstantTimeEq ensures the comparison time is independent of
    // which byte position first differs, preventing oracle attacks.
    let header_vk = &header.issuer_vk;
    for trusted_key in &anchor.keys {
        if bool::from(header_vk.ct_eq(&trusted_key.vk)) {
            return Ok(());
        }
    }

    Err(WalletError::SecurityError(
        "issuer verification key not in trust anchor".to_string(),
    ))
}

/// Conversion between `Vec<bool>` blinding bits and a compact packed-byte form.
///
/// Packing stores 8 bits per byte, MSB first. Unpacking reverses the process,
/// truncating to the requested bit count.
pub mod bits {
    /// Pack a bool slice into bytes (8 bits per byte, MSB first).
    #[allow(clippy::arithmetic_side_effects)] // shift index bounded by chunks(8): i in 0..=7
    pub fn pack_bits(bits: &[bool]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(bits.len().div_ceil(8));

        for chunk in bits.chunks(8) {
            let mut byte = 0u8;
            for (i, &bit) in chunk.iter().enumerate() {
                if bit {
                    byte |= 1 << (7 - i);
                }
            }
            bytes.push(byte);
        }

        bytes
    }

    /// Unpack bytes back into a bool vector, returning at most `bit_count` bits.
    #[allow(clippy::arithmetic_side_effects)] // shift index bounded by 0..8 loop: i in 0..=7
    pub fn unpack_bits(bytes: &[u8], bit_count: usize) -> Vec<bool> {
        let mut bits = Vec::with_capacity(bit_count);

        for byte in bytes {
            for i in 0..8 {
                if bits.len() >= bit_count {
                    break;
                }
                bits.push((byte & (1 << (7 - i))) != 0);
            }
        }

        bits.truncate(bit_count);
        bits
    }
}

/// Parse a DOB from an ISO 8601 date string (`YYYY-MM-DD`) into days since
/// the Unix epoch (1970-01-01). Pre-epoch dates return negative values.
pub fn parse_dob_iso(dob_iso: &str) -> Result<i32> {
    use chrono::NaiveDate;

    let dob = NaiveDate::parse_from_str(dob_iso, "%Y-%m-%d").map_err(|e| {
        WalletError::InvalidInput(format!("Invalid date format (expected YYYY-MM-DD): {}", e))
    })?;

    let epoch = NaiveDate::from_ymd_opt(1970, 1, 1)
        .ok_or_else(|| WalletError::InvalidInput("Failed to create epoch date".to_string()))?;

    #[allow(clippy::arithmetic_side_effects)] // chrono date subtraction cannot overflow i64
    let days = (dob - epoch).num_days();

    i32::try_from(days)
        .map_err(|_| WalletError::InvalidInput(format!("DOB days ({days}) exceeds i32 range")))
}

/// Convert days since the Unix epoch back to an ISO 8601 date string (`YYYY-MM-DD`).
pub fn days_to_iso(days: i32) -> Result<String> {
    use chrono::{Duration, NaiveDate};

    let epoch = NaiveDate::from_ymd_opt(1970, 1, 1)
        .ok_or_else(|| WalletError::InvalidInput("Failed to create epoch date".to_string()))?;
    let date = epoch
        .checked_add_signed(Duration::days(i64::from(days)))
        .ok_or_else(|| {
            WalletError::InvalidInput(format!("Days value ({days}) out of calendar range"))
        })?;
    Ok(date.format("%Y-%m-%d").to_string())
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::string_slice,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used
)]
#[path = "issuance_tests.rs"]
mod tests;

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::string_slice,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used
)]
#[path = "issuance_comprehensive_tests.rs"]
mod comprehensive_tests;

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::string_slice,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used
)]
#[path = "issuance_trust_anchor_tests.rs"]
mod trust_anchor_tests;
