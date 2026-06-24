// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Credential lifecycle management for the Provii wallet.
//!
//! A [`CredentialV2`] represents an issued age credential containing a Pedersen
//! commitment, a RedJubjub signature from the issuer, and (optionally) the
//! secret witness values `dob_days` and `r_bits` needed for proof generation.
//!
//! This module provides serialisation, deserialisation, validation, storage key
//! derivation, fingerprinting, and batch validation. Secret fields are never
//! included in JSON output; only the trusted bincode storage path preserves
//! them. See [`CredentialV2::redacted`] for the redaction strategy.

use crate::types::{CredentialMetadata, CredentialV2};
use blake3;
use serde_json;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors that can occur during credential parsing, validation, or
/// serialisation.
#[derive(Debug, Error)]
pub enum CredentialError {
    /// The input string was not valid JSON or did not match the expected
    /// credential schema.
    #[error("invalid credential json: {0}")]
    InvalidJson(#[from] serde_json::Error),

    /// The credential is missing `dob_days`, `r_bits`, or both. Proof
    /// generation requires both fields to be present.
    #[error("credential missing required private fields")]
    MissingPrivateFields,

    /// The credential structure is syntactically valid JSON but does not
    /// conform to the expected field layout.
    #[error("invalid credential format")]
    InvalidFormat,

    /// The credential's `exp` timestamp is in the past relative to the
    /// supplied current time.
    #[error("credential expired")]
    Expired,

    /// The supplied timestamp precedes the credential's `iat` (issued-at)
    /// value, so the credential is not yet valid.
    #[error("credential not yet valid")]
    NotYetValid,

    /// The credential's `iat` (issued-at) timestamp exceeds its `exp`
    /// (expiration) timestamp, which is structurally invalid.
    #[error("credential iat ({iat}) exceeds exp ({exp})")]
    InvalidTimestampOrder {
        /// The issued-at timestamp that violates the invariant.
        iat: u64,
        /// The expiration timestamp that violates the invariant.
        exp: u64,
    },

    /// The credential version field `v` is not the expected value (2).
    #[error("unsupported credential version: expected 2, got {0}")]
    UnsupportedVersion(u8),
}

impl CredentialV2 {
    /// Parse a credential from a JSON string, stripping any secret fields.
    ///
    /// Deserialises the full credential structure but unconditionally clears
    /// `dob_days` and `r_bits` afterwards. JSON is not a trusted transport
    /// for secret witness values; use bincode storage for credentials that
    /// need to preserve secrets across sessions.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::InvalidJson`] if `s` is not valid JSON or
    /// does not match the expected credential schema.
    pub fn from_json(s: &str) -> Result<Self, CredentialError> {
        use zeroize::Zeroize;
        let mut cred: Self = serde_json::from_str(s)?;
        if cred.v != 2 {
            return Err(CredentialError::UnsupportedVersion(cred.v));
        }
        if cred.kid.len() > 256 {
            return Err(CredentialError::InvalidFormat);
        }
        if cred.schema.len() > 256 {
            return Err(CredentialError::InvalidFormat);
        }
        let mut old_dob = cred.dob_days.take();
        let mut old_r_bits = cred.r_bits.take();
        old_dob.zeroize();
        old_r_bits.zeroize();
        cred.validate_timestamp_order()?;
        Ok(cred)
    }

    /// Checks that `iat <= exp`. A credential whose issuance timestamp
    /// exceeds its expiration timestamp is structurally invalid and must
    /// be rejected at construction boundaries.
    fn validate_timestamp_order(&self) -> Result<(), CredentialError> {
        if self.iat > self.exp {
            return Err(CredentialError::InvalidTimestampOrder {
                iat: self.iat,
                exp: self.exp,
            });
        }
        Ok(())
    }

    /// Serialise the credential to a compact JSON string.
    ///
    /// The output is always redacted: `dob_days` and `r_bits` are omitted.
    /// This makes the result safe for logging, display, export, and
    /// transmission. Use postcard storage to persist credentials with
    /// their secrets intact.
    ///
    /// # Errors
    ///
    /// Returns a [`serde_json::Error`] if serialisation fails (should not
    /// happen for a well-formed credential).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.redacted())
    }

    /// Serialise the credential to a pretty-printed JSON string.
    ///
    /// Behaves identically to [`to_json`](Self::to_json) but with
    /// human-readable indentation. The output is always redacted.
    ///
    /// # Errors
    ///
    /// Returns a [`serde_json::Error`] if serialisation fails.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.redacted())
    }

    /// Returns `true` when both `dob_days` and `r_bits` are present.
    ///
    /// Proof generation requires both secret witness values. Credentials
    /// loaded from JSON will always return `false` here because
    /// [`from_json`](Self::from_json) strips secrets on parse.
    pub fn has_private_fields(&self) -> bool {
        self.dob_days.is_some() && self.r_bits.as_ref().is_some_and(|r| !r.is_empty())
    }

    /// Validates that the credential carries the secret fields required for
    /// zero knowledge proof generation.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::MissingPrivateFields`] if `dob_days` is
    /// `None` or `r_bits` is absent, empty, or not exactly
    /// [`R_BITS_LEN`](crate::issuance::R_BITS_LEN) bits.
    pub fn validate_for_proving(&self) -> Result<(), CredentialError> {
        if self.dob_days.is_none() {
            return Err(CredentialError::MissingPrivateFields);
        }
        match &self.r_bits {
            Some(r) if r.len() == crate::issuance::R_BITS_LEN => Ok(()),
            _ => Err(CredentialError::MissingPrivateFields),
        }
    }

    /// Returns `true` when `current_timestamp` is strictly past the
    /// credential's `exp` field.
    pub fn is_expired(&self, current_timestamp: u64) -> bool {
        self.exp < current_timestamp
    }

    /// Checks that the credential is temporally valid at `timestamp`.
    ///
    /// A credential is valid when `iat <= timestamp <= exp`.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::NotYetValid`] if `timestamp` precedes
    /// `iat`, or [`CredentialError::Expired`] if `timestamp` exceeds `exp`.
    pub fn is_valid_at(&self, timestamp: u64) -> Result<(), CredentialError> {
        if timestamp < self.iat {
            return Err(CredentialError::NotYetValid);
        }
        if timestamp > self.exp {
            return Err(CredentialError::Expired);
        }
        Ok(())
    }

    /// Derives a deterministic storage key from the commitment bytes.
    ///
    /// The key has the form `provii.cred.<blake3-hex>` and is suitable for
    /// use as a platform secure storage identifier.
    pub fn storage_key(&self) -> String {
        let hash = blake3::hash(&self.c_bytes);
        format!("provii.cred.{}", hash.to_hex())
    }

    /// Produces a deterministic hex-encoded identifier from the commitment
    /// bytes using BLAKE3.
    ///
    /// Two credentials with identical `c_bytes` will always yield the same
    /// identifier regardless of other field values.
    pub fn credential_id(&self) -> String {
        hex::encode(blake3::hash(&self.c_bytes).as_bytes())
    }

    /// Constructs a [`CredentialMetadata`] snapshot for this credential.
    ///
    /// The `imported_at` timestamp is set to the current UTC wall clock
    /// time. Pass `label` to attach a human-readable name.
    pub fn to_metadata(&self, label: Option<String>) -> CredentialMetadata {
        CredentialMetadata {
            id: self.credential_id(),
            label,
            imported_at: u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0),
            issuer_name: Some(self.kid.clone()),
        }
    }

    /// Returns a clone with `dob_days` and `r_bits` set to `None`.
    ///
    /// The clone briefly copies the secret fields into the new struct before
    /// they are overwritten. The taken `Option` values are explicitly zeroized
    /// before being dropped to clear the brief copy from memory.
    pub fn redacted(&self) -> Self {
        use zeroize::Zeroize;

        let mut redacted = self.clone();
        // Take the secret fields out so we can zeroize them explicitly.
        let mut old_dob = redacted.dob_days.take();
        let mut old_r_bits = redacted.r_bits.take();
        old_dob.zeroize();
        old_r_bits.zeroize();
        redacted
    }

    /// Computes a SHA-256 fingerprint over the credential's public
    /// cryptographic binding (issuer verification key, RedJubjub signature,
    /// commitment bytes, and schema).
    ///
    /// The fingerprint is useful for deduplication: two credentials with
    /// identical public cryptographic material will produce the same 32-byte
    /// digest. Timestamp and private fields are intentionally excluded so
    /// that re-issued credentials with different validity windows still
    /// match when the core binding is unchanged.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.issuer_vk);
        hasher.update(self.sig_rj);
        hasher.update(self.c_bytes);
        hasher.update(self.schema.as_bytes());
        let result = hasher.finalize();
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&result);
        fingerprint
    }
}

/// Validates a slice of credentials, returning one [`Result`] per entry.
///
/// Each credential is checked for the presence of private fields (via
/// [`CredentialV2::validate_for_proving`]) and temporal validity (via
/// [`CredentialV2::is_valid_at`]). The returned `Vec` has the same length
/// and ordering as `credentials`.
pub fn validate_credentials(
    credentials: &[CredentialV2],
    current_timestamp: u64,
) -> Vec<Result<(), CredentialError>> {
    credentials
        .iter()
        .map(|cred| {
            cred.validate_for_proving()?;
            cred.is_valid_at(current_timestamp)?;
            Ok(())
        })
        .collect()
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
#[path = "credential_tests.rs"]
mod tests;
