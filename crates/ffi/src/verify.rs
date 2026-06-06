// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Verification request assembly for the FFI layer.
//!
//! This module builds a JSON verification request body from a stored
//! [`CredentialV2`] and a [`QrChallengePayload`] scanned from a verifier's
//! QR code. The operation is synchronous, offline, and deterministic: it
//! extracts the credential fields required by the verifier API, pairs them
//! with the challenge parameters, generates a Groth16 zero knowledge proof
//! via the global prover, and serialises the result as a
//! [`SubmitProofRequest`].
//!
//! Both input strings are wrapped in [`Zeroizing`] because they may contain
//! secret material (DOB days, blinding randomness, submit secret).

use anyhow::Result;
use provii_mobile_sdk_core::prover::build_verify_request as core_build_verify_request;
use provii_mobile_sdk_core::types::{CredentialV2, QrChallengePayload, SubmitProofRequest};
use zeroize::Zeroizing;

/// Deserialise a credential and QR challenge payload, then build the
/// verification request JSON that the mobile app posts to the verifier API.
///
/// Both `credential_json` and `qr_payload_json` are consumed by value and
/// wrapped in [`Zeroizing`] so their memory is scrubbed on drop. The
/// returned string is the serialised [`SubmitProofRequest`], which includes
/// the Groth16 proof, public inputs, and challenge metadata.
///
/// # Errors
///
/// Returns an error if either JSON string fails to deserialise, or if proof
/// generation fails (typically because the global prover has not been
/// initialised via [`sdk_init_prover`](crate::sdk_init_prover) or
/// [`sdk_init_prover_mmap`](crate::sdk_init_prover_mmap)).
pub fn build_verify_request(credential_json: String, qr_payload_json: String) -> Result<String> {
    // Wrap owned Strings in Zeroizing so they are wiped on drop.
    // Both may contain secret material (dob_days, r_bits, submit_secret).
    let credential_json = Zeroizing::new(credential_json);
    let qr_payload_json = Zeroizing::new(qr_payload_json);

    let cred: CredentialV2 = serde_json::from_str(&credential_json)?;
    let qr: QrChallengePayload = serde_json::from_str(&qr_payload_json)?;
    qr.validate_field_lengths()
        .map_err(|e| anyhow::anyhow!(e))?;
    let req: SubmitProofRequest = core_build_verify_request(&cred, &qr)?;
    Ok(serde_json::to_string(&req)?)
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

    // Helper to create valid credential JSON
    fn create_valid_credential_json() -> String {
        serde_json::json!({
            "v": 2,
            "schema": "provii.age/0",
            "kid": "issuer:TestIssuer:key1",
            "iat": 1700000000u64,
            "exp": 1800000000u64,
            "c_bytes": vec![1u8; 32],
            "issuer_vk": vec![2u8; 32],
            "sig_rj": vec![3u8; 64],
        })
        .to_string()
    }

    // Helper to create valid QR challenge payload JSON
    fn create_valid_qr_payload_json() -> String {
        serde_json::json!({
            "challenge_id": "test-challenge-123",
            "rp_challenge": "abc123def456",
            "cutoff_days": 19000i32,
            "verifying_key_id": 1243800079u32,
            "submit_secret": "submit_secret_base64url_32bytes",
            "expires_at": 1800000000u64,
            "verify_url": "https://verify.example.com/submit"
        })
        .to_string()
    }

    #[test]
    fn test_build_verify_request_requires_prover() -> Result<(), Box<dyn std::error::Error>> {
        // This test verifies that build_verify_request correctly propagates the prover error
        // when the prover hasn't been initialized (which is the case in unit tests)
        let cred_json = create_valid_credential_json();
        let qr_json = create_valid_qr_payload_json();

        let result = build_verify_request(cred_json, qr_json);

        // Without prover initialization, should get an error
        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        let err_msg = err_val.to_string();
        assert!(err_msg.contains("prover not initialized") || err_msg.contains("prover"));
        Ok(())
    }

    #[test]
    fn test_build_verify_request_parses_inputs() -> Result<(), Box<dyn std::error::Error>> {
        // Test that the function successfully parses both JSON inputs
        // (even though proof generation will fail without prover)
        let cred_json = create_valid_credential_json();
        let qr_json = create_valid_qr_payload_json();

        // The function should at least successfully parse the JSON before hitting prover error
        let result = build_verify_request(cred_json, qr_json);

        // We expect an error about prover, not about JSON parsing
        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        let err_msg = err_val.to_string();
        // Should be prover error, not JSON parsing error
        assert!(!err_msg.contains("expected") && !err_msg.contains("JSON"));
        Ok(())
    }

    #[test]
    fn test_build_verify_request_invalid_credential_json() {
        let invalid_json = "not valid json".to_string();
        let qr_json = create_valid_qr_payload_json();

        let result = build_verify_request(invalid_json, qr_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_missing_credential_fields() {
        let incomplete_json = serde_json::json!({
            "v": 2,
            "schema": "provii.age/0"
            // Missing required fields
        })
        .to_string();
        let qr_json = create_valid_qr_payload_json();

        let result = build_verify_request(incomplete_json, qr_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_wrong_credential_type() {
        let wrong_type = serde_json::json!({
            "v": 999,
            "wrong_field": "value"
        })
        .to_string();
        let qr_json = create_valid_qr_payload_json();

        let result = build_verify_request(wrong_type, qr_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_invalid_qr_json() {
        let cred_json = create_valid_credential_json();
        let invalid_qr = "not valid json".to_string();

        let result = build_verify_request(cred_json, invalid_qr);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_missing_qr_fields() {
        let cred_json = create_valid_credential_json();
        let incomplete_qr = serde_json::json!({
            "challenge_id": "test"
            // Missing required fields
        })
        .to_string();

        let result = build_verify_request(cred_json, incomplete_qr);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_wrong_qr_type() {
        let cred_json = create_valid_credential_json();
        let wrong_qr = serde_json::json!({
            "wrong_field": "value"
        })
        .to_string();

        let result = build_verify_request(cred_json, wrong_qr);
        assert!(result.is_err());
    }

    // ========== Additional Edge Case Tests ==========

    #[test]
    fn test_build_verify_request_empty_credential_json() {
        let empty = String::new();
        let qr_json = create_valid_qr_payload_json();

        let result = build_verify_request(empty, qr_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_empty_qr_json() {
        let cred_json = create_valid_credential_json();
        let empty = String::new();

        let result = build_verify_request(cred_json, empty);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_both_empty() {
        let result = build_verify_request(String::new(), String::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_credential_as_array() {
        let array_json = serde_json::json!([1, 2, 3]).to_string();
        let qr_json = create_valid_qr_payload_json();

        let result = build_verify_request(array_json, qr_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_qr_as_array() {
        let cred_json = create_valid_credential_json();
        let array_json = serde_json::json!([1, 2, 3]).to_string();

        let result = build_verify_request(cred_json, array_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_credential_as_number() {
        let number_json = "42".to_string();
        let qr_json = create_valid_qr_payload_json();

        let result = build_verify_request(number_json, qr_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_qr_as_boolean() {
        let cred_json = create_valid_credential_json();
        let bool_json = "true".to_string();

        let result = build_verify_request(cred_json, bool_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_credential_as_null() {
        let null_json = "null".to_string();
        let qr_json = create_valid_qr_payload_json();

        let result = build_verify_request(null_json, qr_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_credential_with_extra_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let extra_fields_json = serde_json::json!({
            "v": 2,
            "schema": "provii.age/0",
            "kid": "issuer:TestIssuer:key1",
            "iat": 1700000000u64,
            "exp": 1800000000u64,
            "c_bytes": vec![1u8; 32],
            "issuer_vk": vec![2u8; 32],
            "sig_rj": vec![3u8; 64],
            "extra_field_1": "should be ignored",
            "extra_field_2": 999,
        })
        .to_string();
        let qr_json = create_valid_qr_payload_json();

        // Should still fail due to prover not initialized, not JSON parsing
        let result = build_verify_request(extra_fields_json, qr_json);
        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        let err_msg = err_val.to_string();
        assert!(!err_msg.contains("unknown field"));
        Ok(())
    }

    #[test]
    fn test_build_verify_request_unicode_in_kid() {
        let unicode_json = serde_json::json!({
            "v": 2,
            "schema": "provii.age/0",
            "kid": "issuer:TestIssuer日本語:key1",
            "iat": 1700000000u64,
            "exp": 1800000000u64,
            "c_bytes": vec![1u8; 32],
            "issuer_vk": vec![2u8; 32],
            "sig_rj": vec![3u8; 64],
        })
        .to_string();
        let qr_json = create_valid_qr_payload_json();

        let result = build_verify_request(unicode_json, qr_json);
        // Should parse but fail at prover
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_special_chars_in_challenge_id() {
        let cred_json = create_valid_credential_json();
        let special_chars_qr = serde_json::json!({
            "challenge_id": "test-🔥-challenge-<>&\"'",
            "rp_challenge": "abc123def456",
            "cutoff_days": 19000i32,
            "verifying_key_id": 1243800079u32,
            "submit_secret": "submit_secret_base64url_32bytes",
            "expires_at": 1800000000u64,
            "verify_url": "https://verify.example.com/submit"
        })
        .to_string();

        let result = build_verify_request(cred_json, special_chars_qr);
        // Should parse but fail at prover
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_zero_cutoff_days() {
        let cred_json = create_valid_credential_json();
        let zero_cutoff = serde_json::json!({
            "challenge_id": "test-challenge-123",
            "rp_challenge": "abc123def456",
            "cutoff_days": 0i32,
            "verifying_key_id": 1243800079u32,
            "submit_secret": "submit_secret_base64url_32bytes",
            "expires_at": 1800000000u64,
            "verify_url": "https://verify.example.com/submit"
        })
        .to_string();

        let result = build_verify_request(cred_json, zero_cutoff);
        // Should parse but likely fail at validation or prover
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_max_cutoff_days() {
        let cred_json = create_valid_credential_json();
        let max_cutoff = serde_json::json!({
            "challenge_id": "test-challenge-123",
            "rp_challenge": "abc123def456",
            "cutoff_days": i32::MAX,
            "verifying_key_id": 1243800079u32,
            "submit_secret": "submit_secret_base64url_32bytes",
            "expires_at": 1800000000u64,
            "verify_url": "https://verify.example.com/submit"
        })
        .to_string();

        let result = build_verify_request(cred_json, max_cutoff);
        // Should parse but might fail at validation
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_negative_iat_as_string() {
        let negative_iat = serde_json::json!({
            "v": 2,
            "schema": "provii.age/0",
            "kid": "issuer:TestIssuer:key1",
            "iat": "-1",
            "exp": 1800000000u64,
            "c_bytes": vec![1u8; 32],
            "issuer_vk": vec![2u8; 32],
            "sig_rj": vec![3u8; 64],
        })
        .to_string();
        let qr_json = create_valid_qr_payload_json();

        let result = build_verify_request(negative_iat, qr_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_empty_kid() {
        let empty_kid = serde_json::json!({
            "v": 2,
            "schema": "provii.age/0",
            "kid": "",
            "iat": 1700000000u64,
            "exp": 1800000000u64,
            "c_bytes": vec![1u8; 32],
            "issuer_vk": vec![2u8; 32],
            "sig_rj": vec![3u8; 64],
        })
        .to_string();
        let qr_json = create_valid_qr_payload_json();

        let result = build_verify_request(empty_kid, qr_json);
        // Should parse but might fail at validation
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_empty_c_bytes() {
        let empty_bytes = serde_json::json!({
            "v": 2,
            "schema": "provii.age/0",
            "kid": "issuer:TestIssuer:key1",
            "iat": 1700000000u64,
            "exp": 1800000000u64,
            "c_bytes": Vec::<u8>::new(),
            "issuer_vk": vec![2u8; 32],
            "sig_rj": vec![3u8; 64],
        })
        .to_string();
        let qr_json = create_valid_qr_payload_json();

        let result = build_verify_request(empty_bytes, qr_json);
        // Should parse but might fail at validation
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_wrong_c_bytes_length() {
        let wrong_length = serde_json::json!({
            "v": 2,
            "schema": "provii.age/0",
            "kid": "issuer:TestIssuer:key1",
            "iat": 1700000000u64,
            "exp": 1800000000u64,
            "c_bytes": vec![1u8; 16], // Wrong length (should be 32)
            "issuer_vk": vec![2u8; 32],
            "sig_rj": vec![3u8; 64],
        })
        .to_string();
        let qr_json = create_valid_qr_payload_json();

        let result = build_verify_request(wrong_length, qr_json);
        // Should parse but might fail at validation
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_invalid_verify_url() {
        let cred_json = create_valid_credential_json();
        let invalid_url = serde_json::json!({
            "challenge_id": "test-challenge-123",
            "rp_challenge": "abc123def456",
            "cutoff_days": 19000i32,
            "verifying_key_id": 1243800079u32,
            "submit_secret": "submit_secret_base64url_32bytes",
            "expires_at": 1800000000u64,
            "verify_url": "not a valid url"
        })
        .to_string();

        let result = build_verify_request(cred_json, invalid_url);
        // Should parse but might fail at validation
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_http_verify_url() {
        let cred_json = create_valid_credential_json();
        let http_url = serde_json::json!({
            "challenge_id": "test-challenge-123",
            "rp_challenge": "abc123def456",
            "cutoff_days": 19000i32,
            "verifying_key_id": 1243800079u32,
            "submit_secret": "submit_secret_base64url_32bytes",
            "expires_at": 1800000000u64,
            "verify_url": "http://verify.example.com/submit" // HTTP instead of HTTPS
        })
        .to_string();

        let result = build_verify_request(cred_json, http_url);
        // Should parse but might fail at validation (HTTPS required)
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_very_long_kid() {
        let long_kid = "A".repeat(10000);
        let long_kid_json = serde_json::json!({
            "v": 2,
            "schema": "provii.age/0",
            "kid": long_kid,
            "iat": 1700000000u64,
            "exp": 1800000000u64,
            "c_bytes": vec![1u8; 32],
            "issuer_vk": vec![2u8; 32],
            "sig_rj": vec![3u8; 64],
        })
        .to_string();
        let qr_json = create_valid_qr_payload_json();

        let result = build_verify_request(long_kid_json, qr_json);
        // Should parse but might fail at validation or prover
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_expired_timestamp() {
        let expired = serde_json::json!({
            "v": 2,
            "schema": "provii.age/0",
            "kid": "issuer:TestIssuer:key1",
            "iat": 1700000000u64,
            "exp": 1000000u64, // Expired (before iat)
            "c_bytes": vec![1u8; 32],
            "issuer_vk": vec![2u8; 32],
            "sig_rj": vec![3u8; 64],
        })
        .to_string();
        let qr_json = create_valid_qr_payload_json();

        let result = build_verify_request(expired, qr_json);
        // Should parse but might fail at validation
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_whitespace_only_challenge_id() {
        let cred_json = create_valid_credential_json();
        let whitespace_challenge = serde_json::json!({
            "challenge_id": "   ",
            "rp_challenge": "abc123def456",
            "cutoff_days": 19000i32,
            "verifying_key_id": 1243800079u32,
            "submit_secret": "submit_secret_base64url_32bytes",
            "expires_at": 1800000000u64,
            "verify_url": "https://verify.example.com/submit"
        })
        .to_string();

        let result = build_verify_request(cred_json, whitespace_challenge);
        // Should parse but might fail at validation
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_null_byte_in_schema() {
        let null_byte = serde_json::json!({
            "v": 2,
            "schema": "provii.age\0.v2",
            "kid": "issuer:TestIssuer:key1",
            "iat": 1700000000u64,
            "exp": 1800000000u64,
            "c_bytes": vec![1u8; 32],
            "issuer_vk": vec![2u8; 32],
            "sig_rj": vec![3u8; 64],
        })
        .to_string();
        let qr_json = create_valid_qr_payload_json();

        let result = build_verify_request(null_byte, qr_json);
        // Should parse but might fail at validation
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_case_sensitive_schema() {
        let wrong_case = serde_json::json!({
            "v": 2,
            "schema": "PROVII.AGE.V2",
            "kid": "issuer:TestIssuer:key1",
            "iat": 1700000000u64,
            "exp": 1800000000u64,
            "c_bytes": vec![1u8; 32],
            "issuer_vk": vec![2u8; 32],
            "sig_rj": vec![3u8; 64],
        })
        .to_string();
        let qr_json = create_valid_qr_payload_json();

        let result = build_verify_request(wrong_case, qr_json);
        // Should parse but might fail at validation
        assert!(result.is_err());
    }

    #[test]
    fn test_build_verify_request_rejects_oversized_challenge_id() {
        let cred_json = create_valid_credential_json();
        let oversized_id = "X".repeat(600);
        let oversized_qr = serde_json::json!({
            "challenge_id": oversized_id,
            "rp_challenge": "abc123def456",
            "cutoff_days": 19000i32,
            "verifying_key_id": 1243800079u32,
            "submit_secret": "submit_secret_base64url_32bytes",
            "expires_at": 1800000000u64,
            "verify_url": "https://verify.example.com/submit"
        })
        .to_string();

        let result = build_verify_request(cred_json, oversized_qr);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("challenge_id"),
            "expected field-length error about challenge_id, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_build_verify_request_rejects_oversized_submit_secret() {
        let cred_json = create_valid_credential_json();
        let oversized_secret = "S".repeat(600);
        let oversized_qr = serde_json::json!({
            "challenge_id": "valid-id-123",
            "rp_challenge": "abc123def456",
            "cutoff_days": 19000i32,
            "verifying_key_id": 1243800079u32,
            "submit_secret": oversized_secret,
            "expires_at": 1800000000u64,
            "verify_url": "https://verify.example.com/submit"
        })
        .to_string();

        let result = build_verify_request(cred_json, oversized_qr);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("submit_secret"),
            "expected field-length error about submit_secret, got: {}",
            err_msg
        );
    }
}
