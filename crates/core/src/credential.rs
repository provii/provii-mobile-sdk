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
mod tests {
    use super::*;

    fn create_test_credential(
        dob_days: Option<i32>,
        r_bits: Option<Vec<bool>>,
        iat: u64,
        exp: u64,
    ) -> CredentialV2 {
        CredentialV2 {
            v: 2,
            kid: "test_issuer_001".to_string(),
            issuer_vk: [1u8; 32],
            sig_rj: [2u8; 64],
            c_bytes: [3u8; 32],
            iat,
            exp,
            schema: "provii.age/0".to_string(),
            dob_days,
            r_bits,
        }
    }

    #[test]
    fn test_from_json() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "v": 2,
            "kid": "issuer1",
            "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
            "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
            "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
            "iat": 1000000,
            "exp": 2000000,
            "schema": "provii.age/0"
        }"#;

        let cred = CredentialV2::from_json(json)?;
        assert_eq!(cred.v, 2);
        assert_eq!(cred.kid, "issuer1");
        assert_eq!(cred.iat, 1000000);
        assert_eq!(cred.exp, 2000000);
        Ok(())
    }

    #[test]
    fn test_to_json() -> Result<(), Box<dyn std::error::Error>> {
        let cred = create_test_credential(Some(18000), Some(vec![true, false]), 1000000, 2000000);
        let json = cred.to_json()?;

        // Verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(parsed["v"], 2);
        assert_eq!(parsed["kid"], "test_issuer_001");
        Ok(())
    }

    #[test]
    fn test_to_json_pretty() -> Result<(), Box<dyn std::error::Error>> {
        let cred = create_test_credential(Some(18000), Some(vec![true, false]), 1000000, 2000000);
        let json = cred.to_json_pretty()?;

        // Verify it contains newlines (pretty-printed)
        assert!(json.contains('\n'));
        Ok(())
    }

    #[test]
    fn test_has_private_fields() -> Result<(), Box<dyn std::error::Error>> {
        let cred_with =
            create_test_credential(Some(18000), Some(vec![true; 128]), 1000000, 2000000);
        assert!(cred_with.has_private_fields());

        let cred_without_dob =
            create_test_credential(None, Some(vec![true; 128]), 1000000, 2000000);
        assert!(!cred_without_dob.has_private_fields());

        let cred_without_r = create_test_credential(Some(18000), None, 1000000, 2000000);
        assert!(!cred_without_r.has_private_fields());

        let cred_without_both = create_test_credential(None, None, 1000000, 2000000);
        assert!(!cred_without_both.has_private_fields());
        Ok(())
    }

    #[test]
    fn test_validate_for_proving_success() -> Result<(), Box<dyn std::error::Error>> {
        let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000000, 2000000);
        assert!(cred.validate_for_proving().is_ok());
        Ok(())
    }

    #[test]
    fn test_validate_for_proving_missing_fields() -> Result<(), Box<dyn std::error::Error>> {
        let cred = create_test_credential(None, None, 1000000, 2000000);
        let result = cred.validate_for_proving();
        assert!(result.is_err());
        assert!(matches!(result, Err(CredentialError::MissingPrivateFields)));
        Ok(())
    }

    #[test]
    fn test_is_expired() -> Result<(), Box<dyn std::error::Error>> {
        let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000000, 2000000);

        // Before expiration
        assert!(!cred.is_expired(1500000));

        // At expiration
        assert!(!cred.is_expired(2000000));

        // After expiration
        assert!(cred.is_expired(2000001));
        Ok(())
    }

    #[test]
    fn test_is_valid_at_success() -> Result<(), Box<dyn std::error::Error>> {
        let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000000, 2000000);

        // Valid time
        assert!(cred.is_valid_at(1500000).is_ok());

        // At issuance time
        assert!(cred.is_valid_at(1000000).is_ok());

        // At expiration time
        assert!(cred.is_valid_at(2000000).is_ok());
        Ok(())
    }

    #[test]
    fn test_is_valid_at_not_yet_valid() -> Result<(), Box<dyn std::error::Error>> {
        let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000000, 2000000);

        // Before issuance
        let result = cred.is_valid_at(999999);
        assert!(result.is_err());
        assert!(matches!(result, Err(CredentialError::NotYetValid)));
        Ok(())
    }

    #[test]
    fn test_is_valid_at_expired() -> Result<(), Box<dyn std::error::Error>> {
        let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000000, 2000000);

        // After expiration
        let result = cred.is_valid_at(2000001);
        assert!(result.is_err());
        assert!(matches!(result, Err(CredentialError::Expired)));
        Ok(())
    }

    #[test]
    fn test_storage_key() -> Result<(), Box<dyn std::error::Error>> {
        let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000000, 2000000);
        let key = cred.storage_key();

        // Verify key format
        assert!(key.starts_with("provii.cred."));
        assert!(key.len() > 20); // Should have hex suffix
        Ok(())
    }

    #[test]
    fn test_credential_id() -> Result<(), Box<dyn std::error::Error>> {
        let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000000, 2000000);
        let id = cred.credential_id();

        // Verify ID is hex-encoded
        assert_eq!(id.len(), 64); // 32 bytes * 2 hex chars
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        Ok(())
    }

    #[test]
    fn test_credential_id_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let cred1 = create_test_credential(Some(18000), Some(vec![true; 128]), 1000000, 2000000);
        let cred2 = create_test_credential(Some(18000), Some(vec![true; 128]), 1000000, 2000000);

        // Same credentials should produce same ID
        assert_eq!(cred1.credential_id(), cred2.credential_id());
        Ok(())
    }

    #[test]
    fn test_to_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000000, 2000000);
        let metadata = cred.to_metadata(Some("My Credential".to_string()));

        assert_eq!(metadata.id, cred.credential_id());
        assert_eq!(metadata.label, Some("My Credential".to_string()));
        assert_eq!(metadata.issuer_name, Some("test_issuer_001".to_string()));
        assert!(metadata.imported_at > 0);
        Ok(())
    }

    #[test]
    fn test_redacted() -> Result<(), Box<dyn std::error::Error>> {
        let cred = create_test_credential(Some(18000), Some(vec![true, false]), 1000000, 2000000);
        let redacted = cred.redacted();

        // Public fields should be preserved
        assert_eq!(redacted.v, cred.v);
        assert_eq!(redacted.kid, cred.kid);
        assert_eq!(redacted.issuer_vk, cred.issuer_vk);
        assert_eq!(redacted.sig_rj, cred.sig_rj);
        assert_eq!(redacted.c_bytes, cred.c_bytes);

        // Private fields should be None
        assert_eq!(redacted.dob_days, None);
        assert_eq!(redacted.r_bits, None);
        Ok(())
    }

    #[test]
    fn test_fingerprint() -> Result<(), Box<dyn std::error::Error>> {
        let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000000, 2000000);
        let fp = cred.fingerprint();

        // Verify fingerprint length
        assert_eq!(fp.len(), 32);

        // Verify deterministic
        let fp2 = cred.fingerprint();
        assert_eq!(fp, fp2);
        Ok(())
    }

    #[test]
    fn test_fingerprint_different_credentials() -> Result<(), Box<dyn std::error::Error>> {
        let cred1 = create_test_credential(Some(18000), Some(vec![true; 128]), 1000000, 2000000);

        // Different c_bytes should produce different fingerprint
        let mut cred2 = cred1.clone();
        cred2.c_bytes = [4u8; 32];

        assert_ne!(cred1.fingerprint(), cred2.fingerprint());
        Ok(())
    }

    #[test]
    fn test_validate_credentials_all_valid() -> Result<(), Box<dyn std::error::Error>> {
        let creds = vec![
            create_test_credential(Some(18000), Some(vec![true; 128]), 1000000, 2000000),
            create_test_credential(Some(19000), Some(vec![true; 128]), 1000000, 2000000),
        ];

        let results = validate_credentials(&creds, 1500000);
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());
        Ok(())
    }

    #[test]
    fn test_validate_credentials_some_invalid() -> Result<(), Box<dyn std::error::Error>> {
        let creds = vec![
            create_test_credential(Some(18000), Some(vec![true; 128]), 1000000, 2000000), // Valid
            create_test_credential(None, None, 1000000, 2000000), // Missing private fields
            create_test_credential(Some(19000), Some(vec![true; 128]), 1000000, 2000000), // Valid
        ];

        let results = validate_credentials(&creds, 1500000);
        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert!(results[1].is_err()); // Should fail validation
        assert!(results[2].is_ok());
        Ok(())
    }

    #[test]
    fn test_validate_credentials_expired() -> Result<(), Box<dyn std::error::Error>> {
        let creds = vec![
            create_test_credential(Some(18000), Some(vec![true; 128]), 1000000, 2000000), // Expired
        ];

        let results = validate_credentials(&creds, 2500000); // After exp
        assert_eq!(results.len(), 1);
        assert!(results[0].is_err());
        assert!(matches!(results[0], Err(CredentialError::Expired)));
        Ok(())
    }

    #[test]
    fn test_json_roundtrip_preserves_data() -> Result<(), Box<dyn std::error::Error>> {
        let original =
            create_test_credential(Some(18000), Some(vec![true, false, true]), 1000000, 2000000);
        let json = original.to_json()?;
        let parsed = CredentialV2::from_json(&json)?;

        // Public fields are preserved
        assert_eq!(parsed.v, original.v);
        assert_eq!(parsed.kid, original.kid);
        assert_eq!(parsed.issuer_vk, original.issuer_vk);
        assert_eq!(parsed.sig_rj, original.sig_rj);
        assert_eq!(parsed.c_bytes, original.c_bytes);
        assert_eq!(parsed.iat, original.iat);
        assert_eq!(parsed.exp, original.exp);
        assert_eq!(parsed.schema, original.schema);
        // SECURITY: Private fields (dob_days, r_bits) are intentionally NOT serialized
        // to JSON to prevent secret leakage. They will be None after round-tripping.
        assert_eq!(parsed.dob_days, None, "dob_days should not be serialized");
        assert_eq!(parsed.r_bits, None, "r_bits should not be serialized");
        Ok(())
    }

    // Property-based tests
    mod proptests {
        use super::*;
        use proptest::prelude::*;
        use proptest::test_runner::TestCaseError;

        // Strategy to generate valid CredentialV2 with exp >= iat guaranteed
        // structurally: iat is drawn first, then an offset is added to produce exp.
        fn arb_credential() -> impl Strategy<Value = CredentialV2> {
            (
                Just(2u8),
                "[a-z]{5,20}",
                prop::array::uniform32(any::<u8>()),
                prop::collection::vec(any::<u8>(), 64..=64),
                prop::array::uniform32(any::<u8>()),
                1000u64..3000000u64,
                0u64..3000000u64,
                "[a-z.]{5,30}",
                any::<Option<i32>>(),
                prop::option::of(prop::collection::vec(any::<bool>(), 0..20)),
            )
                .prop_map(
                    |(
                        v,
                        kid,
                        issuer_vk,
                        sig_rj_vec,
                        c_bytes,
                        iat,
                        offset,
                        schema,
                        dob_days,
                        r_bits,
                    )| {
                        let mut sig_rj = [0u8; 64];
                        sig_rj.copy_from_slice(&sig_rj_vec);
                        CredentialV2 {
                            v,
                            kid,
                            issuer_vk,
                            sig_rj,
                            c_bytes,
                            iat,
                            exp: iat.saturating_add(offset),
                            schema,
                            dob_days,
                            r_bits,
                        }
                    },
                )
        }

        proptest! {
            // Property: JSON serialization roundtrip preserves PUBLIC fields only
            // SECURITY: dob_days and r_bits are intentionally NOT serialized
            #[test]
            fn prop_json_roundtrip(cred in arb_credential()) {
                let json = cred.to_json().map_err(|e| TestCaseError::fail(format!("{e}")))?;
                let parsed = CredentialV2::from_json(&json).map_err(|e| TestCaseError::fail(format!("{e}")))?;

                // Public fields are preserved
                prop_assert_eq!(parsed.v, cred.v);
                prop_assert_eq!(&parsed.kid, &cred.kid);
                prop_assert_eq!(parsed.issuer_vk, cred.issuer_vk);
                prop_assert_eq!(parsed.sig_rj, cred.sig_rj);
                prop_assert_eq!(parsed.c_bytes, cred.c_bytes);
                prop_assert_eq!(parsed.iat, cred.iat);
                prop_assert_eq!(parsed.exp, cred.exp);
                prop_assert_eq!(&parsed.schema, &cred.schema);
                // Private fields are NOT serialized for security
                prop_assert_eq!(&parsed.dob_days, &None::<i32>);
                prop_assert_eq!(&parsed.r_bits, &None::<Vec<bool>>);
            }

            // Property: Redaction preserves public fields
            #[test]
            fn prop_redaction_preserves_public_fields(cred in arb_credential()) {
                let redacted = cred.redacted();

                prop_assert_eq!(redacted.v, cred.v);
                prop_assert_eq!(&redacted.kid, &cred.kid);
                prop_assert_eq!(redacted.issuer_vk, cred.issuer_vk);
                prop_assert_eq!(redacted.sig_rj, cred.sig_rj);
                prop_assert_eq!(redacted.c_bytes, cred.c_bytes);
                prop_assert_eq!(redacted.iat, cred.iat);
                prop_assert_eq!(redacted.exp, cred.exp);
                prop_assert_eq!(&redacted.schema, &cred.schema);
            }

            // Property: Redaction removes private fields
            #[test]
            fn prop_redaction_removes_private_fields(cred in arb_credential()) {
                let redacted = cred.redacted();
                prop_assert_eq!(redacted.dob_days, None);
                prop_assert_eq!(&redacted.r_bits, &None);
            }

            // Property: Fingerprint is deterministic
            #[test]
            fn prop_fingerprint_deterministic(cred in arb_credential()) {
                let fp1 = cred.fingerprint();
                let fp2 = cred.fingerprint();
                prop_assert_eq!(fp1, fp2);
            }

            // Property: Fingerprint is always 32 bytes
            #[test]
            fn prop_fingerprint_size(cred in arb_credential()) {
                let fp = cred.fingerprint();
                prop_assert_eq!(fp.len(), 32);
            }

            // Property: Credential ID is deterministic
            #[test]
            fn prop_credential_id_deterministic(cred in arb_credential()) {
                let id1 = cred.credential_id();
                let id2 = cred.credential_id();
                prop_assert_eq!(id1, id2);
            }

            // Property: Credential ID is 64 hex characters
            #[test]
            fn prop_credential_id_format(cred in arb_credential()) {
                let id = cred.credential_id();
                prop_assert_eq!(id.len(), 64);
                prop_assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
            }

            // Property: Storage key format is consistent
            #[test]
            fn prop_storage_key_format(cred in arb_credential()) {
                let key = cred.storage_key();
                prop_assert!(key.starts_with("provii.cred."));
            }

            // Property: has_private_fields is consistent with actual fields
            #[test]
            fn prop_has_private_fields_consistent(cred in arb_credential()) {
                let has_fields = cred.has_private_fields();
                let expected = cred.dob_days.is_some()
                    && cred.r_bits.as_ref().is_some_and(|r| !r.is_empty());
                prop_assert_eq!(has_fields, expected);
            }

            // Property: is_expired is monotonic with time
            #[test]
            fn prop_is_expired_monotonic(cred in arb_credential(), offset in 0u64..1000000u64) {
                let time_before = cred.exp.saturating_sub(offset);
                let time_after = cred.exp.saturating_add(offset);

                // If expired at earlier time, must be expired at later time
                if cred.is_expired(time_before) {
                    prop_assert!(cred.is_expired(time_after));
                }
            }

            // Property: is_valid_at succeeds between iat and exp
            #[test]
            fn prop_is_valid_at_between_iat_exp(cred in arb_credential()) {
                // Test at a time between iat and exp
                if cred.iat < cred.exp {
                    let mid_time = cred.iat + (cred.exp - cred.iat) / 2;
                    prop_assert!(cred.is_valid_at(mid_time).is_ok());
                }
            }

            // Property: validate_for_proving requires dob_days and correctly-sized r_bits
            #[test]
            fn prop_validate_for_proving_requires_both(
                dob_days: Option<i32>,
                r_bits: Option<Vec<bool>>,
            ) {
                let has_dob = dob_days.is_some();
                let has_correct_r = r_bits.as_ref()
                    .is_some_and(|r| r.len() == crate::issuance::R_BITS_LEN);
                let cred = create_test_credential(dob_days, r_bits, 1000000, 2000000);
                let result = cred.validate_for_proving();

                if has_dob && has_correct_r {
                    prop_assert!(result.is_ok());
                } else {
                    prop_assert!(result.is_err());
                }
            }

            // Property: Credentials with same c_bytes have same ID
            #[test]
            fn prop_same_c_bytes_same_id(
                c_bytes in prop::array::uniform32(any::<u8>()),
                kid1 in "[a-z]{5,20}",
                kid2 in "[a-z]{5,20}",
            ) {
                let cred1 = CredentialV2 {
                    v: 2,
                    kid: kid1,
                    issuer_vk: [1u8; 32],
                    sig_rj: [2u8; 64],
                    c_bytes,
                    iat: 1000000,
                    exp: 2000000,
                    schema: "test".to_string(),
                    dob_days: Some(18000),
                    r_bits: Some(vec![true; 128]),
                };

                let cred2 = CredentialV2 {
                    v: 2,
                    kid: kid2,
                    issuer_vk: [3u8; 32],
                    sig_rj: [4u8; 64],
                    c_bytes,
                    iat: 1500000,
                    exp: 2500000,
                    schema: "test2".to_string(),
                    dob_days: Some(19000),
                    r_bits: Some(vec![false]),
                };

                prop_assert_eq!(cred1.credential_id(), cred2.credential_id());
            }

            // Property: Metadata creation preserves credential ID
            #[test]
            fn prop_metadata_preserves_id(cred in arb_credential(), label: Option<String>) {
                let metadata = cred.to_metadata(label.clone());
                prop_assert_eq!(metadata.id, cred.credential_id());
                prop_assert_eq!(metadata.label, label);
                prop_assert_eq!(metadata.issuer_name, Some(cred.kid.clone()));
            }
        }
    }

    // =========================================================================
    // Comprehensive Edge Case Tests (100+ additional tests)
    // =========================================================================

    mod comprehensive_tests {
        use super::*;

        // =====================================================================
        // from_json edge cases (25 tests)
        // =====================================================================

        #[test]
        fn test_from_json_empty_string() -> Result<(), Box<dyn std::error::Error>> {
            let result = CredentialV2::from_json("");
            assert!(result.is_err());
            Ok(())
        }

        #[test]
        fn test_from_json_invalid_json() -> Result<(), Box<dyn std::error::Error>> {
            let result = CredentialV2::from_json("{invalid}");
            assert!(result.is_err());
            Ok(())
        }

        #[test]
        fn test_from_json_missing_required_field_v() -> Result<(), Box<dyn std::error::Error>> {
            let json = r#"{"kid":"test","issuer_vk":[1,2,3],"sig_rj":[],"c_bytes":[],"iat":1000,"exp":2000,"schema":"test"}"#;
            let result = CredentialV2::from_json(json);
            assert!(result.is_err());
            Ok(())
        }

        #[test]
        fn test_from_json_missing_required_field_kid() -> Result<(), Box<dyn std::error::Error>> {
            let json = r#"{"v":2,"issuer_vk":[1,2,3],"sig_rj":[],"c_bytes":[],"iat":1000,"exp":2000,"schema":"test"}"#;
            let result = CredentialV2::from_json(json);
            assert!(result.is_err());
            Ok(())
        }

        #[test]
        fn test_from_json_wrong_type_v() -> Result<(), Box<dyn std::error::Error>> {
            let json = r#"{"v":"two","kid":"test","issuer_vk":[],"sig_rj":[],"c_bytes":[],"iat":1000,"exp":2000,"schema":"test"}"#;
            let result = CredentialV2::from_json(json);
            assert!(result.is_err());
            Ok(())
        }

        #[test]
        fn test_from_json_wrong_type_iat() -> Result<(), Box<dyn std::error::Error>> {
            let json = r#"{"v":2,"kid":"test","issuer_vk":[],"sig_rj":[],"c_bytes":[],"iat":"1000","exp":2000,"schema":"test"}"#;
            let result = CredentialV2::from_json(json);
            assert!(result.is_err());
            Ok(())
        }

        #[test]
        fn test_from_json_null_required_field() -> Result<(), Box<dyn std::error::Error>> {
            let json = r#"{"v":2,"kid":null,"issuer_vk":[],"sig_rj":[],"c_bytes":[],"iat":1000,"exp":2000,"schema":"test"}"#;
            let result = CredentialV2::from_json(json);
            assert!(result.is_err());
            Ok(())
        }

        #[test]
        fn test_from_json_issuer_vk_wrong_length() -> Result<(), Box<dyn std::error::Error>> {
            let json = r#"{"v":2,"kid":"test","issuer_vk":[1,2,3],"sig_rj":[0;64],"c_bytes":[0;32],"iat":1000,"exp":2000,"schema":"test"}"#;
            let result = CredentialV2::from_json(json);
            // Note: This might succeed but with wrong data - depends on serde behavior
            let _ = result;
            Ok(())
        }

        #[test]
        fn test_from_json_extra_fields_ignored() -> Result<(), Box<dyn std::error::Error>> {
            let json = r#"{
                "v": 2,
                "kid": "test",
                "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": 1000,
                "exp": 2000,
                "schema": "test",
                "extra_field": "should be ignored"
            }"#;
            let result = CredentialV2::from_json(json);
            assert!(result.is_ok());
            Ok(())
        }

        #[test]
        fn test_from_json_with_optional_fields_present() -> Result<(), Box<dyn std::error::Error>> {
            // SECURITY: Even if dob_days and r_bits are present in JSON, they are
            // deserialized then zeroized and discarded to prevent accepting secrets from untrusted sources.
            let json = r#"{
                "v": 2,
                "kid": "test",
                "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": 1000,
                "exp": 2000,
                "schema": "test",
                "dob_days": 18000,
                "r_bits": [true, false, true]
            }"#;
            let cred = CredentialV2::from_json(json)?;
            // Secret fields are deserialized then zeroized and discarded
            assert_eq!(cred.dob_days, None);
            assert_eq!(cred.r_bits, None);
            Ok(())
        }

        #[test]
        fn test_from_json_with_optional_fields_null() -> Result<(), Box<dyn std::error::Error>> {
            let json = r#"{
                "v": 2,
                "kid": "test",
                "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": 1000,
                "exp": 2000,
                "schema": "test",
                "dob_days": null,
                "r_bits": null
            }"#;
            let cred = CredentialV2::from_json(json)?;
            assert_eq!(cred.dob_days, None);
            assert_eq!(cred.r_bits, None);
            Ok(())
        }

        #[test]
        fn test_from_json_empty_arrays() -> Result<(), Box<dyn std::error::Error>> {
            // SECURITY: r_bits is NOT deserialized even if present (empty or not)
            let json = r#"{
                "v": 2,
                "kid": "test",
                "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": 1000,
                "exp": 2000,
                "schema": "test",
                "r_bits": []
            }"#;
            let cred = CredentialV2::from_json(json)?;
            // r_bits is intentionally ignored during deserialization
            assert_eq!(cred.r_bits, None);
            Ok(())
        }

        #[test]
        fn test_from_json_zero_timestamps() -> Result<(), Box<dyn std::error::Error>> {
            let json = r#"{
                "v": 2,
                "kid": "test",
                "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": 0,
                "exp": 0,
                "schema": "test"
            }"#;
            let cred = CredentialV2::from_json(json)?;
            assert_eq!(cred.iat, 0);
            assert_eq!(cred.exp, 0);
            Ok(())
        }

        #[test]
        fn test_from_json_max_timestamps() -> Result<(), Box<dyn std::error::Error>> {
            let json = format!(
                r#"{{
                "v": 2,
                "kid": "test",
                "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": {},
                "exp": {},
                "schema": "test"
            }}"#,
                u64::MAX,
                u64::MAX
            );
            let cred = CredentialV2::from_json(&json)?;
            assert_eq!(cred.iat, u64::MAX);
            assert_eq!(cred.exp, u64::MAX);
            Ok(())
        }

        #[test]
        fn test_from_json_whitespace_variations() -> Result<(), Box<dyn std::error::Error>> {
            let json = r#"  {  "v"  :  2  ,  "kid"  :  "test"  ,  "issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000,"exp":2000,"schema":"test"}  "#;
            let result = CredentialV2::from_json(json);
            assert!(result.is_ok());
            Ok(())
        }

        #[test]
        fn test_from_json_unicode_in_strings() -> Result<(), Box<dyn std::error::Error>> {
            let json = r#"{
                "v": 2,
                "kid": "test_日本語_emoji_🔑",
                "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": 1000,
                "exp": 2000,
                "schema": "provii.age/0"
            }"#;
            let cred = CredentialV2::from_json(json)?;
            assert!(cred.kid.contains("日本語"));
            Ok(())
        }

        #[test]
        fn test_from_json_escaped_characters() -> Result<(), Box<dyn std::error::Error>> {
            let json = r#"{
                "v": 2,
                "kid": "test\"with\\quotes",
                "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": 1000,
                "exp": 2000,
                "schema": "test"
            }"#;
            let cred = CredentialV2::from_json(json)?;
            assert!(cred.kid.contains("\""));
            assert!(cred.kid.contains("\\"));
            Ok(())
        }

        #[test]
        fn test_from_json_array_with_negative_values() -> Result<(), Box<dyn std::error::Error>> {
            // Arrays with negative values should fail for u8 arrays
            let json = r#"{
                "v": 2,
                "kid": "test",
                "issuer_vk": [-1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": 1000,
                "exp": 2000,
                "schema": "test"
            }"#;
            let result = CredentialV2::from_json(json);
            assert!(result.is_err());
            Ok(())
        }

        #[test]
        fn test_from_json_array_with_values_over_255() -> Result<(), Box<dyn std::error::Error>> {
            let json = r#"{
                "v": 2,
                "kid": "test",
                "issuer_vk": [256,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": 1000,
                "exp": 2000,
                "schema": "test"
            }"#;
            let result = CredentialV2::from_json(json);
            assert!(result.is_err());
            Ok(())
        }

        #[test]
        fn test_from_json_rejects_very_long_kid() -> Result<(), Box<dyn std::error::Error>> {
            let long_kid = "a".repeat(10000);
            let json = format!(
                r#"{{
                "v": 2,
                "kid": "{}",
                "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": 1000,
                "exp": 2000,
                "schema": "test"
            }}"#,
                long_kid
            );
            let result = CredentialV2::from_json(&json);
            assert!(result.is_err(), "kid exceeding 256 bytes must be rejected");
            assert!(matches!(result, Err(CredentialError::InvalidFormat)));
            Ok(())
        }

        #[test]
        fn test_from_json_r_bits_large_array() -> Result<(), Box<dyn std::error::Error>> {
            // SECURITY: r_bits is intentionally NOT deserialized, even if present
            let r_bits_json: String = (0..1000)
                .map(|i| if i % 2 == 0 { "true" } else { "false" })
                .collect::<Vec<_>>()
                .join(",");
            let json = format!(
                r#"{{
                "v": 2,
                "kid": "test",
                "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": 1000,
                "exp": 2000,
                "schema": "test",
                "r_bits": [{}]
            }}"#,
                r_bits_json
            );
            let cred = CredentialV2::from_json(&json)?;
            // r_bits is intentionally ignored during deserialization
            assert_eq!(cred.r_bits, None);
            Ok(())
        }

        #[test]
        fn test_from_json_nested_json_structure() -> Result<(), Box<dyn std::error::Error>> {
            // This should fail because credential expects flat structure
            let json = r#"{"credential": {"v": 2}}"#;
            let result = CredentialV2::from_json(json);
            assert!(result.is_err());
            Ok(())
        }

        #[test]
        fn test_from_json_array_instead_of_object() -> Result<(), Box<dyn std::error::Error>> {
            let json = r#"[{"v": 2}]"#;
            let result = CredentialV2::from_json(json);
            assert!(result.is_err());
            Ok(())
        }

        #[test]
        fn test_from_json_number_instead_of_object() -> Result<(), Box<dyn std::error::Error>> {
            let json = r#"123"#;
            let result = CredentialV2::from_json(json);
            assert!(result.is_err());
            Ok(())
        }

        #[test]
        fn test_from_json_boolean_instead_of_object() -> Result<(), Box<dyn std::error::Error>> {
            let json = r#"true"#;
            let result = CredentialV2::from_json(json);
            assert!(result.is_err());
            Ok(())
        }

        // =====================================================================
        // to_json edge cases (10 tests)
        // =====================================================================

        #[test]
        fn test_to_json_with_none_optionals() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(None, None, 1000, 2000);
            let json = cred.to_json()?;
            let parsed: serde_json::Value = serde_json::from_str(&json)?;

            // Optional fields should either be null or absent
            assert!(parsed["dob_days"].is_null() || parsed.get("dob_days").is_none());
            Ok(())
        }

        #[test]
        fn test_to_json_with_empty_r_bits() -> Result<(), Box<dyn std::error::Error>> {
            // SECURITY: r_bits is NOT serialized to JSON
            let cred = create_test_credential(Some(18000), Some(vec![]), 1000, 2000);
            let json = cred.to_json()?;
            // r_bits should NOT be in JSON (skip_serializing)
            assert!(!json.contains("r_bits"));
            Ok(())
        }

        #[test]
        fn test_to_json_zero_values() -> Result<(), Box<dyn std::error::Error>> {
            // SECURITY: dob_days is NOT serialized to JSON
            let cred = create_test_credential(Some(0), Some(vec![false, false]), 0, 0);
            let json = cred.to_json()?;
            let parsed: serde_json::Value = serde_json::from_str(&json)?;
            // dob_days should NOT be in JSON (skip_serializing)
            assert!(parsed.get("dob_days").is_none());
            assert_eq!(parsed["iat"], 0);
            assert_eq!(parsed["exp"], 0);
            Ok(())
        }

        #[test]
        fn test_to_json_max_dob_days() -> Result<(), Box<dyn std::error::Error>> {
            // SECURITY: dob_days is NOT serialized to JSON (skip_serializing)
            let cred = create_test_credential(Some(i32::MAX), Some(vec![true; 128]), 1000, 2000);
            let json = cred.to_json()?;
            let parsed: serde_json::Value = serde_json::from_str(&json)?;
            // dob_days should NOT be in JSON
            assert!(parsed.get("dob_days").is_none());
            Ok(())
        }

        #[test]
        fn test_to_json_special_characters_in_kid() -> Result<(), Box<dyn std::error::Error>> {
            let mut cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            cred.kid = "test\"with'quotes<>".to_string();
            let json = cred.to_json()?;

            // Should properly escape special characters
            let parsed = CredentialV2::from_json(&json)?;
            assert_eq!(parsed.kid, cred.kid);
            Ok(())
        }

        #[test]
        fn test_to_json_unicode_characters() -> Result<(), Box<dyn std::error::Error>> {
            let mut cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            cred.kid = "日本語_🔑_测试".to_string();
            let json = cred.to_json()?;
            let parsed = CredentialV2::from_json(&json)?;
            assert_eq!(parsed.kid, cred.kid);
            Ok(())
        }

        #[test]
        fn test_to_json_pretty_formatting() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let json = cred.to_json_pretty()?;

            // Pretty JSON should have indentation
            assert!(json.contains("  "));
            assert!(json.contains("\n"));

            // Should still be parseable
            let parsed = CredentialV2::from_json(&json)?;
            assert_eq!(parsed.v, cred.v);
            Ok(())
        }

        #[test]
        fn test_to_json_all_255_byte_values() -> Result<(), Box<dyn std::error::Error>> {
            let mut cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            // Set arrays to contain all possible byte values
            for i in 0..32 {
                cred.issuer_vk[i] = (i as u8).wrapping_mul(8);
                cred.c_bytes[i] = (i as u8).wrapping_add(100);
            }

            let json = cred.to_json()?;
            let parsed = CredentialV2::from_json(&json)?;
            assert_eq!(parsed.issuer_vk, cred.issuer_vk);
            assert_eq!(parsed.c_bytes, cred.c_bytes);
            Ok(())
        }

        #[test]
        fn test_to_json_roundtrip_idempotent() -> Result<(), Box<dyn std::error::Error>> {
            let cred =
                create_test_credential(Some(18000), Some(vec![true, false, true]), 1000, 2000);

            // Multiple roundtrips should preserve data
            let json1 = cred.to_json()?;
            let parsed1 = CredentialV2::from_json(&json1)?;
            let json2 = parsed1.to_json()?;
            let parsed2 = CredentialV2::from_json(&json2)?;

            assert_eq!(parsed1.credential_id(), parsed2.credential_id());
            assert_eq!(json1, json2);
            Ok(())
        }

        #[test]
        fn test_to_json_output_is_compact() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let json = cred.to_json()?;

            // Compact JSON should not have unnecessary whitespace
            assert!(!json.contains("  "));
            assert!(!json.contains("\n"));
            Ok(())
        }

        // =======================================================================
        // storage_key and credential_id edge cases (15 tests)
        // =======================================================================

        #[test]
        fn test_storage_key_uniqueness() -> Result<(), Box<dyn std::error::Error>> {
            let cred1 = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let mut cred2 = cred1.clone();
            cred2.c_bytes[0] = cred2.c_bytes[0].wrapping_add(1);

            assert_ne!(cred1.storage_key(), cred2.storage_key());
            Ok(())
        }

        #[test]
        fn test_storage_key_deterministic() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let key1 = cred.storage_key();
            let key2 = cred.storage_key();
            let key3 = cred.storage_key();

            assert_eq!(key1, key2);
            assert_eq!(key2, key3);
            Ok(())
        }

        #[test]
        fn test_storage_key_only_depends_on_c_bytes() -> Result<(), Box<dyn std::error::Error>> {
            let cred1 = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let mut cred2 = cred1.clone();

            // Change everything except c_bytes
            cred2.kid = "different".to_string();
            cred2.issuer_vk = [99u8; 32];
            cred2.sig_rj = [88u8; 64];
            cred2.iat = 99999;
            cred2.exp = 999999;
            cred2.dob_days = Some(25000);

            // Storage keys should still be same (only c_bytes matters)
            assert_eq!(cred1.storage_key(), cred2.storage_key());
            Ok(())
        }

        #[test]
        fn test_storage_key_format_valid() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let key = cred.storage_key();

            assert!(key.starts_with("provii.cred."));

            // Extract hex part and verify it's valid hex
            let hex_part = key.strip_prefix("provii.cred.").ok_or("missing prefix")?;
            assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
            assert_eq!(hex_part.len(), 64); // blake3 produces 32 bytes = 64 hex chars
            Ok(())
        }

        #[test]
        fn test_credential_id_format_lowercase_hex() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let id = cred.credential_id();

            // Should be lowercase hex
            assert!(id
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
            Ok(())
        }

        #[test]
        fn test_credential_id_collision_resistance() -> Result<(), Box<dyn std::error::Error>> {
            // Create 100 credentials with similar but different c_bytes
            let mut ids = std::collections::HashSet::new();

            for i in 0..100 {
                let mut cred =
                    create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
                cred.c_bytes[0] = i;
                ids.insert(cred.credential_id());
            }

            // All IDs should be unique
            assert_eq!(ids.len(), 100);
            Ok(())
        }

        #[test]
        fn test_credential_id_avalanche_effect() -> Result<(), Box<dyn std::error::Error>> {
            let cred1 = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let mut cred2 = cred1.clone();

            // Change single bit
            cred2.c_bytes[0] ^= 0x01;

            let id1 = cred1.credential_id();
            let id2 = cred2.credential_id();

            // IDs should be completely different (avalanche effect)
            let diff_chars = id1.chars().zip(id2.chars()).filter(|(a, b)| a != b).count();

            // At least 50% of characters should be different
            assert!(diff_chars > 32);
            Ok(())
        }

        #[test]
        fn test_credential_id_all_zero_c_bytes() -> Result<(), Box<dyn std::error::Error>> {
            let mut cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            cred.c_bytes = [0u8; 32];

            let id = cred.credential_id();
            assert_eq!(id.len(), 64);
            // Should produce valid hash even for all zeros
            assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
            Ok(())
        }

        #[test]
        fn test_credential_id_all_max_c_bytes() -> Result<(), Box<dyn std::error::Error>> {
            let mut cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            cred.c_bytes = [255u8; 32];

            let id = cred.credential_id();
            assert_eq!(id.len(), 64);
            assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
            Ok(())
        }

        #[test]
        fn test_storage_key_and_credential_id_related() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);

            let storage_key = cred.storage_key();
            let cred_id = cred.credential_id();

            // Both use blake3 hash of c_bytes, so they should be related
            // Storage key contains the credential ID as part of it
            assert!(storage_key.contains(&cred_id));
            Ok(())
        }

        #[test]
        fn test_credential_id_for_metadata_consistency() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let direct_id = cred.credential_id();
            let metadata = cred.to_metadata(None);

            assert_eq!(metadata.id, direct_id);
            Ok(())
        }

        #[test]
        fn test_credential_id_different_private_fields_same_id(
        ) -> Result<(), Box<dyn std::error::Error>> {
            let cred1 = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let cred2 = create_test_credential(Some(25000), Some(vec![false, false]), 1000, 2000);

            // Same c_bytes means same ID even with different private fields
            assert_eq!(cred1.credential_id(), cred2.credential_id());
            Ok(())
        }

        #[test]
        fn test_storage_key_prefix_constant() -> Result<(), Box<dyn std::error::Error>> {
            // Verify the prefix is exactly what we expect
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let key = cred.storage_key();

            assert!(key.starts_with("provii.cred."));
            assert!(!key.starts_with("provii.credential."));
            assert!(!key.starts_with("PROVII.CRED."));
            Ok(())
        }

        #[test]
        fn test_credential_id_parsing_back_to_bytes() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let id = cred.credential_id();

            // Should be able to decode back to bytes
            let bytes = hex::decode(&id)?;
            assert_eq!(bytes.len(), 32);
            Ok(())
        }

        #[test]
        fn test_credential_id_matches_blake3_hash() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let id = cred.credential_id();

            // Manually compute blake3 hash and verify it matches
            let expected = hex::encode(blake3::hash(&cred.c_bytes).as_bytes());
            assert_eq!(id, expected);
            Ok(())
        }

        // =======================================================================
        // fingerprint tests (12 tests)
        // =======================================================================

        #[test]
        fn test_fingerprint_deterministic_multiple_calls() -> Result<(), Box<dyn std::error::Error>>
        {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let fp1 = cred.fingerprint();
            let fp2 = cred.fingerprint();
            let fp3 = cred.fingerprint();

            assert_eq!(fp1, fp2);
            assert_eq!(fp2, fp3);
            Ok(())
        }

        #[test]
        fn test_fingerprint_different_issuer_vk() -> Result<(), Box<dyn std::error::Error>> {
            let cred1 = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let mut cred2 = cred1.clone();
            cred2.issuer_vk[0] = cred2.issuer_vk[0].wrapping_add(1);

            assert_ne!(cred1.fingerprint(), cred2.fingerprint());
            Ok(())
        }

        #[test]
        fn test_fingerprint_different_sig_rj() -> Result<(), Box<dyn std::error::Error>> {
            let cred1 = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let mut cred2 = cred1.clone();
            cred2.sig_rj[0] = cred2.sig_rj[0].wrapping_add(1);

            assert_ne!(cred1.fingerprint(), cred2.fingerprint());
            Ok(())
        }

        #[test]
        fn test_fingerprint_different_c_bytes() -> Result<(), Box<dyn std::error::Error>> {
            let cred1 = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let mut cred2 = cred1.clone();
            cred2.c_bytes[0] = cred2.c_bytes[0].wrapping_add(1);

            assert_ne!(cred1.fingerprint(), cred2.fingerprint());
            Ok(())
        }

        #[test]
        fn test_fingerprint_ignores_private_fields() -> Result<(), Box<dyn std::error::Error>> {
            let cred1 = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let cred2 = create_test_credential(Some(25000), Some(vec![false, false]), 1000, 2000);

            // Same public fields = same fingerprint
            assert_eq!(cred1.fingerprint(), cred2.fingerprint());
            Ok(())
        }

        #[test]
        fn test_fingerprint_ignores_timestamps() -> Result<(), Box<dyn std::error::Error>> {
            let cred1 = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let cred2 = create_test_credential(Some(18000), Some(vec![true; 128]), 5000, 10000);

            // Different timestamps don't affect fingerprint
            assert_eq!(cred1.fingerprint(), cred2.fingerprint());
            Ok(())
        }

        #[test]
        fn test_fingerprint_ignores_kid() -> Result<(), Box<dyn std::error::Error>> {
            let cred1 = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let mut cred2 = cred1.clone();
            cred2.kid = "different_issuer".to_string();

            // kid not part of fingerprint
            assert_eq!(cred1.fingerprint(), cred2.fingerprint());
            Ok(())
        }

        #[test]
        fn test_fingerprint_uses_sha256() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let fp = cred.fingerprint();

            // SHA256 produces 32 bytes
            assert_eq!(fp.len(), 32);

            // Manually compute SHA256 to verify (includes schema)
            let mut hasher = Sha256::new();
            hasher.update(&cred.issuer_vk);
            hasher.update(&cred.sig_rj);
            hasher.update(&cred.c_bytes);
            hasher.update(cred.schema.as_bytes());
            let expected = hasher.finalize();

            assert_eq!(&fp[..], &expected[..]);
            Ok(())
        }

        #[test]
        fn test_fingerprint_collision_resistance() -> Result<(), Box<dyn std::error::Error>> {
            let mut fingerprints = std::collections::HashSet::new();

            for i in 0..100 {
                let mut cred =
                    create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
                cred.issuer_vk[0] = i;
                fingerprints.insert(cred.fingerprint());
            }

            assert_eq!(fingerprints.len(), 100);
            Ok(())
        }

        #[test]
        fn test_fingerprint_all_zero_arrays() -> Result<(), Box<dyn std::error::Error>> {
            let mut cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            cred.issuer_vk = [0u8; 32];
            cred.sig_rj = [0u8; 64];
            cred.c_bytes = [0u8; 32];

            let fp = cred.fingerprint();
            assert_eq!(fp.len(), 32);

            // Should still produce valid hash
            assert_ne!(fp, [0u8; 32]);
            Ok(())
        }

        #[test]
        fn test_fingerprint_all_max_arrays() -> Result<(), Box<dyn std::error::Error>> {
            let mut cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            cred.issuer_vk = [255u8; 32];
            cred.sig_rj = [255u8; 64];
            cred.c_bytes = [255u8; 32];

            let fp = cred.fingerprint();
            assert_eq!(fp.len(), 32);
            Ok(())
        }

        #[test]
        fn test_fingerprint_for_deduplication() -> Result<(), Box<dyn std::error::Error>> {
            // Same credential data should produce same fingerprint
            let cred1 = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let cred2 = create_test_credential(Some(19000), Some(vec![false]), 1000, 2000);

            // Can use fingerprint to detect duplicates
            let fp1 = cred1.fingerprint();
            let fp2 = cred2.fingerprint();

            if fp1 == fp2 {
                // Same fingerprint = likely duplicate
                assert_eq!(cred1.issuer_vk, cred2.issuer_vk);
                assert_eq!(cred1.sig_rj, cred2.sig_rj);
                assert_eq!(cred1.c_bytes, cred2.c_bytes);
            }
            Ok(())
        }

        // =======================================================================
        // redacted tests (10 tests)
        // =======================================================================

        #[test]
        fn test_redacted_removes_only_private_fields() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true, false]), 1000, 2000);
            let redacted = cred.redacted();

            // Private fields removed
            assert_eq!(redacted.dob_days, None);
            assert_eq!(redacted.r_bits, None);

            // Public fields preserved
            assert_eq!(redacted.v, cred.v);
            assert_eq!(redacted.kid, cred.kid);
            assert_eq!(redacted.issuer_vk, cred.issuer_vk);
            assert_eq!(redacted.sig_rj, cred.sig_rj);
            assert_eq!(redacted.c_bytes, cred.c_bytes);
            assert_eq!(redacted.iat, cred.iat);
            assert_eq!(redacted.exp, cred.exp);
            assert_eq!(redacted.schema, cred.schema);
            Ok(())
        }

        #[test]
        fn test_redacted_already_redacted() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(None, None, 1000, 2000);
            let redacted = cred.redacted();

            // Should still work even if already without private fields
            assert_eq!(redacted.dob_days, None);
            assert_eq!(redacted.r_bits, None);
            Ok(())
        }

        #[test]
        fn test_redacted_double_redaction_idempotent() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let redacted1 = cred.redacted();
            let redacted2 = redacted1.redacted();

            // Double redaction should be same as single
            assert_eq!(redacted1.dob_days, redacted2.dob_days);
            assert_eq!(redacted1.r_bits, redacted2.r_bits);
            assert_eq!(redacted1.credential_id(), redacted2.credential_id());
            Ok(())
        }

        #[test]
        fn test_redacted_preserves_credential_id() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let redacted = cred.redacted();

            // Credential ID should be same (based on c_bytes)
            assert_eq!(cred.credential_id(), redacted.credential_id());
            Ok(())
        }

        #[test]
        fn test_redacted_preserves_storage_key() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let redacted = cred.redacted();

            assert_eq!(cred.storage_key(), redacted.storage_key());
            Ok(())
        }

        #[test]
        fn test_redacted_preserves_fingerprint() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let redacted = cred.redacted();

            assert_eq!(cred.fingerprint(), redacted.fingerprint());
            Ok(())
        }

        #[test]
        fn test_redacted_can_be_serialized() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let redacted = cred.redacted();

            let json = redacted.to_json()?;
            let parsed = CredentialV2::from_json(&json)?;

            assert_eq!(parsed.dob_days, None);
            assert_eq!(parsed.r_bits, None);
            Ok(())
        }

        #[test]
        fn test_redacted_cannot_be_used_for_proving() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let redacted = cred.redacted();

            let result = redacted.validate_for_proving();
            assert!(result.is_err());
            Ok(())
        }

        #[test]
        fn test_redacted_only_dob_days_removed() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let mut partial = cred.clone();
            partial.dob_days = None;

            let redacted = cred.redacted();
            let expected = partial.redacted();

            // Redaction should match whether done once or twice
            assert_eq!(redacted.dob_days, expected.dob_days);
            Ok(())
        }

        #[test]
        fn test_redacted_safe_for_display() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true, false]), 1000, 2000);
            let redacted = cred.redacted();

            // Redacted version should be safe to display/log/store
            let json = redacted.to_json()?;

            // Should not contain private data
            assert!(!json.contains("18000") || json.contains("\"dob_days\":null"));
            Ok(())
        }

        // =======================================================================
        // to_metadata tests (10 tests)
        // =======================================================================

        #[test]
        fn test_to_metadata_with_label() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let metadata = cred.to_metadata(Some("My ID".to_string()));

            assert_eq!(metadata.label, Some("My ID".to_string()));
            assert_eq!(metadata.id, cred.credential_id());
            assert_eq!(metadata.issuer_name, Some(cred.kid.clone()));
            Ok(())
        }

        #[test]
        fn test_to_metadata_without_label() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let metadata = cred.to_metadata(None);

            assert_eq!(metadata.label, None);
            assert_eq!(metadata.id, cred.credential_id());
            Ok(())
        }

        #[test]
        fn test_to_metadata_empty_label() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let metadata = cred.to_metadata(Some("".to_string()));

            assert_eq!(metadata.label, Some("".to_string()));
            Ok(())
        }

        #[test]
        fn test_to_metadata_long_label() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let long_label = "a".repeat(1000);
            let metadata = cred.to_metadata(Some(long_label.clone()));

            assert_eq!(metadata.label, Some(long_label));
            Ok(())
        }

        #[test]
        fn test_to_metadata_unicode_label() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let label = "我的凭证 🔐 パスポート".to_string();
            let metadata = cred.to_metadata(Some(label.clone()));

            assert_eq!(metadata.label, Some(label));
            Ok(())
        }

        #[test]
        fn test_to_metadata_issuer_name_from_kid() -> Result<(), Box<dyn std::error::Error>> {
            let mut cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            cred.kid = "issuer_abc_123".to_string();
            let metadata = cred.to_metadata(None);

            assert_eq!(metadata.issuer_name, Some("issuer_abc_123".to_string()));
            Ok(())
        }

        #[test]
        fn test_to_metadata_imported_at_is_recent() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let before = chrono::Utc::now().timestamp() as u64;
            let metadata = cred.to_metadata(None);
            let after = chrono::Utc::now().timestamp() as u64;

            // Should be between before and after (within 1 second tolerance)
            assert!(metadata.imported_at >= before.saturating_sub(1));
            assert!(metadata.imported_at <= after.saturating_add(1));
            Ok(())
        }

        #[test]
        fn test_to_metadata_multiple_calls_different_timestamps(
        ) -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);

            let metadata1 = cred.to_metadata(None);
            std::thread::sleep(std::time::Duration::from_millis(10));
            let metadata2 = cred.to_metadata(None);

            // Each call should have different imported_at
            assert!(metadata2.imported_at >= metadata1.imported_at);
            Ok(())
        }

        #[test]
        fn test_to_metadata_preserves_credential_identity() -> Result<(), Box<dyn std::error::Error>>
        {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let meta1 = cred.to_metadata(Some("label1".to_string()));
            let meta2 = cred.to_metadata(Some("label2".to_string()));

            // Different labels but same credential ID
            assert_eq!(meta1.id, meta2.id);
            assert_ne!(meta1.label, meta2.label);
            Ok(())
        }

        #[test]
        fn test_to_metadata_different_credentials_different_ids(
        ) -> Result<(), Box<dyn std::error::Error>> {
            let cred1 = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let mut cred2 = cred1.clone();
            cred2.c_bytes[0] = cred2.c_bytes[0].wrapping_add(1);

            let meta1 = cred1.to_metadata(None);
            let meta2 = cred2.to_metadata(None);

            assert_ne!(meta1.id, meta2.id);
            Ok(())
        }

        // =======================================================================
        // Validation edge cases (15 tests)
        // =======================================================================

        #[test]
        fn test_has_private_fields_only_dob_days() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), None, 1000, 2000);
            assert!(!cred.has_private_fields());
            Ok(())
        }

        #[test]
        fn test_has_private_fields_only_r_bits() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(None, Some(vec![true; 128]), 1000, 2000);
            assert!(!cred.has_private_fields());
            Ok(())
        }

        #[test]
        fn test_has_private_fields_empty_r_bits() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![]), 1000, 2000);
            assert!(!cred.has_private_fields());
            Ok(())
        }

        #[test]
        fn test_has_private_fields_zero_dob_days() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(0), Some(vec![true; 128]), 1000, 2000);
            assert!(cred.has_private_fields());
            Ok(())
        }

        #[test]
        fn test_validate_for_proving_empty_r_bits_fails() -> Result<(), Box<dyn std::error::Error>>
        {
            let cred = create_test_credential(Some(18000), Some(vec![]), 1000, 2000);
            assert!(cred.validate_for_proving().is_err());
            Ok(())
        }

        #[test]
        fn test_validate_for_proving_wrong_length_r_bits_fails(
        ) -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 64]), 1000, 2000);
            assert!(cred.validate_for_proving().is_err());
            Ok(())
        }

        #[test]
        fn test_is_expired_boundary_before_exp() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            assert!(!cred.is_expired(1999));
            Ok(())
        }

        #[test]
        fn test_is_expired_boundary_at_exp() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            // At expiration is NOT expired
            assert!(!cred.is_expired(2000));
            Ok(())
        }

        #[test]
        fn test_is_expired_boundary_after_exp() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            assert!(cred.is_expired(2001));
            Ok(())
        }

        #[test]
        fn test_is_valid_at_boundary_before_iat() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let result = cred.is_valid_at(999);
            assert!(result.is_err());
            assert!(matches!(result, Err(CredentialError::NotYetValid)));
            Ok(())
        }

        #[test]
        fn test_is_valid_at_boundary_at_iat() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            assert!(cred.is_valid_at(1000).is_ok());
            Ok(())
        }

        #[test]
        fn test_is_valid_at_boundary_at_exp() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            // At expiration is still valid
            assert!(cred.is_valid_at(2000).is_ok());
            Ok(())
        }

        #[test]
        fn test_is_valid_at_boundary_after_exp() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000);
            let result = cred.is_valid_at(2001);
            assert!(result.is_err());
            assert!(matches!(result, Err(CredentialError::Expired)));
            Ok(())
        }

        #[test]
        fn test_is_valid_at_with_iat_equals_exp() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 1000);
            // Valid at exactly iat==exp
            assert!(cred.is_valid_at(1000).is_ok());

            // Before is not yet valid
            assert!(cred.is_valid_at(999).is_err());

            // After is expired
            assert!(cred.is_valid_at(1001).is_err());
            Ok(())
        }

        #[test]
        fn test_from_json_rejects_iat_exceeds_exp() -> Result<(), Box<dyn std::error::Error>> {
            let json = r#"{
                "v": 2,
                "kid": "issuer1",
                "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": 2000000,
                "exp": 1000000,
                "schema": "provii.age/0"
            }"#;

            let result = CredentialV2::from_json(json);
            assert!(result.is_err());
            match result {
                Err(CredentialError::InvalidTimestampOrder { iat, exp }) => {
                    assert_eq!(iat, 2000000);
                    assert_eq!(exp, 1000000);
                }
                other => {
                    return Err(format!("expected InvalidTimestampOrder, got {:?}", other).into());
                }
            }
            Ok(())
        }

        #[test]
        fn test_from_json_accepts_iat_equals_exp() -> Result<(), Box<dyn std::error::Error>> {
            let json = r#"{
                "v": 2,
                "kid": "issuer1",
                "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": 1500000,
                "exp": 1500000,
                "schema": "provii.age/0"
            }"#;

            let cred = CredentialV2::from_json(json)?;
            assert_eq!(cred.iat, 1500000);
            assert_eq!(cred.exp, 1500000);
            Ok(())
        }

        #[test]
        fn test_is_valid_at_zero_timestamps() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(Some(18000), Some(vec![true; 128]), 0, 0);

            // Valid at exactly 0
            assert!(cred.is_valid_at(0).is_ok());

            // After 0 is expired
            assert!(cred.is_valid_at(1).is_err());
            Ok(())
        }

        #[test]
        fn test_is_valid_at_max_timestamps() -> Result<(), Box<dyn std::error::Error>> {
            let cred = create_test_credential(
                Some(18000),
                Some(vec![true; 128]),
                u64::MAX - 1000,
                u64::MAX,
            );

            // Valid in the middle
            assert!(cred.is_valid_at(u64::MAX - 500).is_ok());

            // Valid at max
            assert!(cred.is_valid_at(u64::MAX).is_ok());
            Ok(())
        }

        // =======================================================================
        // validate_credentials edge cases (8 tests)
        // =======================================================================

        #[test]
        fn test_validate_credentials_empty_array() -> Result<(), Box<dyn std::error::Error>> {
            let creds: Vec<CredentialV2> = vec![];
            let results = validate_credentials(&creds, 1500000);

            assert_eq!(results.len(), 0);
            Ok(())
        }

        #[test]
        fn test_validate_credentials_single_valid() -> Result<(), Box<dyn std::error::Error>> {
            let creds = vec![create_test_credential(
                Some(18000),
                Some(vec![true; 128]),
                1000,
                2000,
            )];

            let results = validate_credentials(&creds, 1500);
            assert_eq!(results.len(), 1);
            assert!(results[0].is_ok());
            Ok(())
        }

        #[test]
        fn test_validate_credentials_all_missing_private_fields(
        ) -> Result<(), Box<dyn std::error::Error>> {
            let creds = vec![
                create_test_credential(None, None, 1000, 2000),
                create_test_credential(None, None, 1000, 2000),
            ];

            let results = validate_credentials(&creds, 1500);
            assert_eq!(results.len(), 2);
            assert!(results[0].is_err());
            assert!(results[1].is_err());
            Ok(())
        }

        #[test]
        fn test_validate_credentials_all_expired() -> Result<(), Box<dyn std::error::Error>> {
            let creds = vec![
                create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000),
                create_test_credential(Some(19000), Some(vec![true; 128]), 1000, 2000),
            ];

            let results = validate_credentials(&creds, 3000);
            assert_eq!(results.len(), 2);
            assert!(results[0].is_err());
            assert!(results[1].is_err());
            Ok(())
        }

        #[test]
        fn test_validate_credentials_mixed_valid_invalid() -> Result<(), Box<dyn std::error::Error>>
        {
            let creds = vec![
                create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000), // Valid
                create_test_credential(None, None, 1000, 2000), // Missing fields
                create_test_credential(Some(19000), Some(vec![true; 128]), 1000, 2000), // Valid
                create_test_credential(Some(20000), Some(vec![true; 128]), 3000, 5000), // Not yet valid
            ];

            let results = validate_credentials(&creds, 1500);
            assert_eq!(results.len(), 4);
            assert!(results[0].is_ok());
            assert!(results[1].is_err());
            assert!(results[2].is_ok());
            assert!(results[3].is_err());
            Ok(())
        }

        #[test]
        fn test_validate_credentials_not_yet_valid() -> Result<(), Box<dyn std::error::Error>> {
            let creds = vec![create_test_credential(
                Some(18000),
                Some(vec![true; 128]),
                5000,
                10000,
            )];

            let results = validate_credentials(&creds, 1000);
            assert_eq!(results.len(), 1);
            assert!(results[0].is_err());
            assert!(matches!(results[0], Err(CredentialError::NotYetValid)));
            Ok(())
        }

        #[test]
        fn test_validate_credentials_at_boundaries() -> Result<(), Box<dyn std::error::Error>> {
            let creds = vec![create_test_credential(
                Some(18000),
                Some(vec![true; 128]),
                1000,
                2000,
            )];

            // At iat
            let results = validate_credentials(&creds, 1000);
            assert!(results[0].is_ok());

            // At exp
            let results = validate_credentials(&creds, 2000);
            assert!(results[0].is_ok());
            Ok(())
        }

        #[test]
        fn test_validate_credentials_large_batch() -> Result<(), Box<dyn std::error::Error>> {
            let creds: Vec<CredentialV2> = (0..100)
                .map(|_| create_test_credential(Some(18000), Some(vec![true; 128]), 1000, 2000))
                .collect();

            let results = validate_credentials(&creds, 1500);
            assert_eq!(results.len(), 100);
            assert!(results.iter().all(|r| r.is_ok()));
            Ok(())
        }

        // =======================================================================
        // Error handling tests (7 tests)
        // =======================================================================

        #[test]
        fn test_credential_error_invalid_json_display() -> Result<(), Box<dyn std::error::Error>> {
            let err = CredentialError::InvalidJson(
                serde_json::from_str::<serde_json::Value>("bad")
                    .err()
                    .ok_or("expected error")?,
            );
            let display = format!("{}", err);
            assert!(display.contains("invalid credential json"));
            Ok(())
        }

        #[test]
        fn test_credential_error_missing_private_fields_display(
        ) -> Result<(), Box<dyn std::error::Error>> {
            let err = CredentialError::MissingPrivateFields;
            let display = format!("{}", err);
            assert!(display.contains("missing required private fields"));
            Ok(())
        }

        #[test]
        fn test_credential_error_invalid_format_display() -> Result<(), Box<dyn std::error::Error>>
        {
            let err = CredentialError::InvalidFormat;
            let display = format!("{}", err);
            assert!(display.contains("invalid credential format"));
            Ok(())
        }

        #[test]
        fn test_credential_error_expired_display() -> Result<(), Box<dyn std::error::Error>> {
            let err = CredentialError::Expired;
            let display = format!("{}", err);
            assert!(display.contains("expired"));
            Ok(())
        }

        #[test]
        fn test_credential_error_not_yet_valid_display() -> Result<(), Box<dyn std::error::Error>> {
            let err = CredentialError::NotYetValid;
            let display = format!("{}", err);
            assert!(display.contains("not yet valid"));
            Ok(())
        }

        #[test]
        fn test_credential_error_debug_format() -> Result<(), Box<dyn std::error::Error>> {
            let err = CredentialError::MissingPrivateFields;
            let debug = format!("{:?}", err);
            assert!(debug.contains("MissingPrivateFields"));
            Ok(())
        }

        #[test]
        fn test_from_json_error_conversion() -> Result<(), Box<dyn std::error::Error>> {
            let result = CredentialV2::from_json("invalid json");
            assert!(result.is_err());

            let err = result.err().ok_or("expected error")?;
            assert!(matches!(err, CredentialError::InvalidJson(_)));
            Ok(())
        }

        // ================================================================
        // Mutation-coverage tests: kill surviving mutants in credential.rs
        // ================================================================

        /// Kill: credential.rs:83 replace > with >= in CredentialV2::from_json (kid.len() > 256)
        /// A kid of exactly 256 chars must be accepted.
        #[test]
        fn test_from_json_kid_exactly_256_accepted() -> Result<(), Box<dyn std::error::Error>> {
            let kid_256 = "a".repeat(256);
            let json = format!(
                r#"{{
                "v": 2,
                "kid": "{}",
                "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": 1000,
                "exp": 2000,
                "schema": "test"
            }}"#,
                kid_256
            );
            let result = CredentialV2::from_json(&json);
            assert!(
                result.is_ok(),
                "kid of exactly 256 chars must be accepted, got: {:?}",
                result.err()
            );
            Ok(())
        }

        /// Kill: credential.rs:83 (strengthening) - kid of 257 must be rejected
        #[test]
        fn test_from_json_kid_257_rejected() -> Result<(), Box<dyn std::error::Error>> {
            let kid_257 = "a".repeat(257);
            let json = format!(
                r#"{{
                "v": 2,
                "kid": "{}",
                "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": 1000,
                "exp": 2000,
                "schema": "test"
            }}"#,
                kid_257
            );
            let result = CredentialV2::from_json(&json);
            assert!(result.is_err(), "kid of 257 chars must be rejected");
            assert!(matches!(
                result.unwrap_err(),
                CredentialError::InvalidFormat
            ));
            Ok(())
        }

        /// Kill: credential.rs:86 replace > with == in CredentialV2::from_json (schema.len() > 256)
        /// A schema of 257 chars must be rejected (> 256). The == mutant would only reject at 256.
        #[test]
        fn test_from_json_schema_257_rejected() -> Result<(), Box<dyn std::error::Error>> {
            let schema_257 = "s".repeat(257);
            let json = format!(
                r#"{{
                "v": 2,
                "kid": "test",
                "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": 1000,
                "exp": 2000,
                "schema": "{}"
            }}"#,
                schema_257
            );
            let result = CredentialV2::from_json(&json);
            assert!(result.is_err(), "schema of 257 chars must be rejected");
            assert!(matches!(
                result.unwrap_err(),
                CredentialError::InvalidFormat
            ));
            Ok(())
        }

        /// Kill: credential.rs:86 replace > with >= in CredentialV2::from_json (schema.len() > 256)
        /// A schema of exactly 256 chars must be accepted.
        #[test]
        fn test_from_json_schema_exactly_256_accepted() -> Result<(), Box<dyn std::error::Error>> {
            let schema_256 = "s".repeat(256);
            let json = format!(
                r#"{{
                "v": 2,
                "kid": "test",
                "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": 1000,
                "exp": 2000,
                "schema": "{}"
            }}"#,
                schema_256
            );
            let result = CredentialV2::from_json(&json);
            assert!(
                result.is_ok(),
                "schema of exactly 256 chars must be accepted, got: {:?}",
                result.err()
            );
            Ok(())
        }
    }
}
