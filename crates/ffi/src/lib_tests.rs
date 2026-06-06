// Copyright (c) 2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust (ABN 61 633 823 792)
// SPDX-License-Identifier: Apache-2.0

// Tests for all FFI functions exported from lib.rs.
//
// Covers issuance commitment, storage creation, SDK utilities, prover
// initialisation, deeplink parsing, credential storage, credential
// finalisation, verify request building, and HTTP-gated issuance flows.

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
    use super::super::*;

    // ========================================================================
    // Issuance commitment
    // ========================================================================

    #[test]
    fn test_sdk_issue_compute_commitment_iso_date() -> Result<(), Box<dyn std::error::Error>> {
        let result = sdk_issue_compute_commitment("2000-01-01".to_string());

        assert!(result.is_ok());
        let json_str = result?;
        let json: serde_json::Value = serde_json::from_str(&json_str)?;

        assert!(json.get("dob_days").is_some());
        assert!(json.get("r_bits").is_some());
        assert!(json.get("commitment").is_some());

        assert!(json["dob_days"].is_number());
        Ok(())
    }

    #[test]
    fn test_sdk_issue_compute_commitment_numeric_days() -> Result<(), Box<dyn std::error::Error>> {
        let result = sdk_issue_compute_commitment("19000".to_string());

        assert!(result.is_ok());
        let json_str = result?;
        let json: serde_json::Value = serde_json::from_str(&json_str)?;

        assert_eq!(json["dob_days"], 19000);
        Ok(())
    }

    #[test]
    fn test_sdk_issue_compute_commitment_invalid_date() {
        let result = sdk_issue_compute_commitment("invalid-date".to_string());
        assert!(result.is_err());

        let result = sdk_issue_compute_commitment("2000-13-01".to_string());
        assert!(result.is_err());

        let result = sdk_issue_compute_commitment("2000-01-32".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_sdk_issue_compute_commitment_empty_string() {
        let result = sdk_issue_compute_commitment("".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_sdk_issue_compute_commitment_leap_year() {
        let result = sdk_issue_compute_commitment("2000-02-29".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_sdk_issue_compute_commitment_json_structure() -> Result<(), Box<dyn std::error::Error>>
    {
        let result = sdk_issue_compute_commitment("1990-06-15".to_string());
        assert!(result.is_ok());

        let json_str = result?;
        let json: serde_json::Value = serde_json::from_str(&json_str)?;

        assert!(json.is_object());
        assert_eq!(json.as_object().ok_or("expected object")?.len(), 3);

        let r_bits = json["r_bits"].as_str().ok_or("expected str")?;
        let commitment = json["commitment"].as_str().ok_or("expected str")?;
        assert!(!r_bits.is_empty());
        assert!(!commitment.is_empty());
        Ok(())
    }

    #[test]
    fn test_sdk_issue_compute_commitment_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let result1 = sdk_issue_compute_commitment("19000".to_string());
        let result2 = sdk_issue_compute_commitment("19000".to_string());

        assert!(result1.is_ok());
        assert!(result2.is_ok());

        let json1: serde_json::Value = serde_json::from_str(&result1?)?;
        let json2: serde_json::Value = serde_json::from_str(&result2?)?;

        // dob_days is deterministic; r_bits uses fresh randomness each call.
        assert_eq!(json1["dob_days"], json2["dob_days"]);
        assert_ne!(json1["r_bits"], json2["r_bits"]);
        Ok(())
    }

    #[test]
    fn test_sdk_issue_compute_commitment_zero_days() {
        let result = sdk_issue_compute_commitment("0".to_string());
        assert!(
            result.is_ok(),
            "zero dob_days should produce a valid commitment, got {:?}",
            result.err()
        );
    }

    #[test]
    fn test_sdk_issue_compute_commitment_very_large_days() {
        let result = sdk_issue_compute_commitment("999999".to_string());
        assert!(
            result.is_ok(),
            "large dob_days should produce a valid commitment, got {:?}",
            result.err()
        );
    }

    #[test]
    fn test_sdk_issue_compute_commitment_negative_days() {
        let result = sdk_issue_compute_commitment("-100".to_string());
        assert!(result.is_err());
    }

    // ========================================================================
    // Storage creation
    // ========================================================================

    #[test]
    fn test_create_default_secure_store() -> Result<(), Box<dyn std::error::Error>> {
        let result = create_default_secure_store();

        assert!(result.is_ok());
        let store = result?;
        assert!(Arc::strong_count(&store) >= 1);
        Ok(())
    }

    #[test]
    fn test_create_development_secure_store() -> Result<(), Box<dyn std::error::Error>> {
        let result = create_development_secure_store();

        assert!(result.is_ok());
        let store = result?;
        assert!(Arc::strong_count(&store) >= 1);
        Ok(())
    }

    #[test]
    fn test_secure_storage_independence() -> Result<(), Box<dyn std::error::Error>> {
        let store1 = create_default_secure_store()?;
        let store2 = create_default_secure_store()?;

        assert!(Arc::strong_count(&store1) >= 1);
        assert!(Arc::strong_count(&store2) >= 1);
        Ok(())
    }

    #[test]
    fn test_secure_storage_handle_clone() -> Result<(), Box<dyn std::error::Error>> {
        let store = create_default_secure_store()?;
        let count_before = Arc::strong_count(&store);

        let store_clone = Arc::clone(&store);
        let count_after = Arc::strong_count(&store);

        assert_eq!(count_after, count_before + 1);

        drop(store_clone);
        assert_eq!(Arc::strong_count(&store), count_before);
        Ok(())
    }

    #[test]
    fn test_secure_storage_multiple_creation() {
        for _ in 0..10 {
            let result = create_default_secure_store();
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_development_store_on_desktop() -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            let default_store = create_default_secure_store()?;
            let dev_store = create_development_secure_store()?;

            assert!(Arc::strong_count(&default_store) >= 1);
            assert!(Arc::strong_count(&dev_store) >= 1);
        }
        Ok(())
    }

    #[test]
    fn test_storage_handle_memory_safety() -> Result<(), Box<dyn std::error::Error>> {
        {
            let _store = create_default_secure_store()?;
        }

        let result = create_default_secure_store();
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_storage_concurrent_creation() -> Result<(), Box<dyn std::error::Error>> {
        use std::thread;

        let handle1 = thread::spawn(create_default_secure_store);
        let handle2 = thread::spawn(create_default_secure_store);

        let result1 = handle1.join().map_err(|_| "thread panicked")?;
        let result2 = handle2.join().map_err(|_| "thread panicked")?;

        assert!(result1.is_ok());
        assert!(result2.is_ok());
        Ok(())
    }

    // ========================================================================
    // SDK utilities
    // ========================================================================

    #[test]
    fn test_get_sdk_version() {
        let version = get_sdk_version();

        assert!(!version.is_empty());
        assert!(version.contains('.'));
    }

    #[test]
    fn test_get_sdk_version_consistency() {
        let v1 = get_sdk_version();
        let v2 = get_sdk_version();

        assert_eq!(v1, v2);
    }

    #[test]
    fn test_init_android_logging() {
        init_android_logging();

        // Must be safe to call repeatedly.
        init_android_logging();
        init_android_logging();
    }

    #[test]
    fn test_sdk_set_user_agent_basic() {
        let app_info = AppInfo {
            version: "1.0.0".to_string(),
            build_number: "100".to_string(),
            platform: "test".to_string(),
            device_model: None,
            os_version: None,
        };

        sdk_set_user_agent(app_info);
    }

    #[test]
    fn test_sdk_set_user_agent_with_device_info() {
        let app_info = AppInfo {
            version: "2.0.0".to_string(),
            build_number: "200".to_string(),
            platform: "iOS".to_string(),
            device_model: Some("iPhone14".to_string()),
            os_version: Some("16.0".to_string()),
        };

        sdk_set_user_agent(app_info);
    }

    #[test]
    fn test_sdk_set_user_agent_empty_strings() {
        let app_info = AppInfo {
            version: "".to_string(),
            build_number: "".to_string(),
            platform: "".to_string(),
            device_model: None,
            os_version: None,
        };

        sdk_set_user_agent(app_info);
    }

    #[test]
    fn test_sdk_set_user_agent_unicode() {
        let app_info = AppInfo {
            version: "1.0.0-\u{65E5}\u{672C}\u{8A9E}".to_string(),
            build_number: "100".to_string(),
            platform: "\u{30C6}\u{30B9}\u{30C8}".to_string(),
            device_model: Some("\u{30C7}\u{30D0}\u{30A4}\u{30B9}".to_string()),
            os_version: None,
        };

        sdk_set_user_agent(app_info);
    }

    #[test]
    fn test_sdk_set_user_agent_multiple_calls() {
        for i in 0..10 {
            let app_info = AppInfo {
                version: format!("1.0.{}", i),
                build_number: i.to_string(),
                platform: "test".to_string(),
                device_model: None,
                os_version: None,
            };
            sdk_set_user_agent(app_info);
        }
    }

    #[test]
    fn test_sdk_diagnose_thread_config() {
        let result = sdk_diagnose_thread_config();

        assert!(!result.is_empty());
        assert!(result.contains("THREAD CONFIGURATION"));
        assert!(result.contains("Hardware cores"));
        assert!(result.contains("Rayon pool threads"));
    }

    #[test]
    fn test_sdk_diagnose_thread_config_consistency() {
        let result1 = sdk_diagnose_thread_config();
        let result2 = sdk_diagnose_thread_config();

        assert!(!result1.is_empty());
        assert!(!result2.is_empty());
    }

    // ========================================================================
    // Prover initialisation
    // ========================================================================

    #[test]
    fn test_sdk_init_prover_empty_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let result = sdk_init_prover(vec![]);

        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::Prover { .. } => {}
            _ => panic!("Expected Prover error"),
        }
        Ok(())
    }

    #[test]
    fn test_sdk_init_prover_small_bytes() {
        let result = sdk_init_prover(vec![0u8; 100]);

        assert!(result.is_err());
    }

    #[test]
    fn test_sdk_init_prover_invalid_data() {
        let result = sdk_init_prover(vec![0xFFu8; 1000]);

        assert!(result.is_err());
    }

    #[test]
    fn test_sdk_init_prover_concurrent() -> Result<(), Box<dyn std::error::Error>> {
        use std::thread;

        let handle1 = thread::spawn(|| sdk_init_prover(vec![0u8; 100]));
        let handle2 = thread::spawn(|| sdk_init_prover(vec![1u8; 100]));

        let result1 = handle1.join().map_err(|_| "thread panicked")?;
        let result2 = handle2.join().map_err(|_| "thread panicked")?;

        assert!(result1.is_err() || result2.is_err());
        Ok(())
    }

    #[test]
    fn test_sdk_init_prover_error_message() -> Result<(), Box<dyn std::error::Error>> {
        let result = sdk_init_prover(vec![0u8; 10]);

        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        let err_str = format!("{:?}", err_val);
        assert!(!err_str.is_empty());
        Ok(())
    }

    #[test]
    #[cfg(feature = "mmap")]
    fn test_sdk_init_prover_mmap_nonexistent() {
        let result = sdk_init_prover_mmap("/nonexistent/path/to/pk".to_string());

        assert!(result.is_err());
    }

    // ========================================================================
    // Deeplink parsing
    // ========================================================================

    #[test]
    fn test_sdk_parse_deeplink_empty() {
        let result = sdk_parse_deeplink("".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_sdk_parse_deeplink_invalid_scheme() {
        let result = sdk_parse_deeplink("https://example.com".to_string());
        assert!(result.is_err());

        let result = sdk_parse_deeplink("http://proviiwallet".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_sdk_parse_deeplink_malformed() {
        let result = sdk_parse_deeplink("not a url".to_string());
        assert!(result.is_err());

        let result = sdk_parse_deeplink("proviiwallet".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_sdk_parse_deeplink_missing_components() {
        let result = sdk_parse_deeplink("proviiwallet://".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_sdk_parse_deeplink_unicode() {
        let result = sdk_parse_deeplink("proviiwallet://\u{65E5}\u{672C}\u{8A9E}".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_sdk_parse_deeplink_very_long() {
        // URL exceeds the 4096-byte MAX_DEEPLINK_SIZE limit
        let long_url = format!("proviiwallet://{}", "a".repeat(10000));
        let result = sdk_parse_deeplink(long_url);
        assert!(
            result.is_err(),
            "deep link URL exceeding 4096 bytes must be rejected"
        );
    }

    #[test]
    fn test_sdk_parse_deeplink_special_chars() {
        // "test" is not a supported deeplink action (only "verify" is)
        let result =
            sdk_parse_deeplink("proviiwallet://test?param=value%20with%20spaces".to_string());
        assert!(
            result.is_err(),
            "deep link with unsupported action must be rejected"
        );
    }

    #[test]
    fn test_sdk_parse_deeplink_null_bytes() {
        let result = sdk_parse_deeplink("proviiwallet://test\0".to_string());
        assert!(
            result.is_err(),
            "deep link with null byte should be rejected"
        );
    }

    // ========================================================================
    // Store finalised credential
    // ========================================================================

    #[test]
    fn test_sdk_store_finalized_credential_invalid_json() -> Result<(), Box<dyn std::error::Error>>
    {
        let result = sdk_store_finalized_credential("not json".to_string());

        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::InvalidFormat { .. } => {}
            _ => panic!("Expected InvalidFormat error"),
        }
        Ok(())
    }

    #[test]
    fn test_sdk_store_finalized_credential_empty() {
        let result = sdk_store_finalized_credential("".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_sdk_store_finalized_credential_wrong_structure() {
        let json = serde_json::json!({
            "wrong": "structure"
        })
        .to_string();

        let result = sdk_store_finalized_credential(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_sdk_store_finalized_credential_missing_fields() {
        let json = serde_json::json!({
            "v": 2,
            "schema": "provii.age/0"
        })
        .to_string();

        let result = sdk_store_finalized_credential(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_sdk_store_finalized_credential_unicode() {
        let json = serde_json::json!({
            "v": 2,
            "schema": "test-\u{65E5}\u{672C}\u{8A9E}",
            "kid": "\u{30C6}\u{30B9}\u{30C8}"
        })
        .to_string();

        let result = sdk_store_finalized_credential(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_sdk_store_finalized_credential_very_large() {
        let large_field = "x".repeat(100000);
        let json = serde_json::json!({
            "v": 2,
            "schema": large_field
        })
        .to_string();

        let result = sdk_store_finalized_credential(json);
        assert!(result.is_err());
    }

    // ========================================================================
    // Finalise credential
    // ========================================================================

    fn create_test_header_json() -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        serde_json::json!({
            "v": 2,
            "schema": "provii.age/0",
            "kid": "issuer:TestIssuer:key1",
            "iat": 1700000000u64,
            "exp": 1800000000u64,
            "c_bytes": URL_SAFE_NO_PAD.encode(vec![1u8; 32]),
            "issuer_vk": URL_SAFE_NO_PAD.encode(vec![2u8; 32]),
            "sig_rj": URL_SAFE_NO_PAD.encode(vec![3u8; 64]),
        })
        .to_string()
    }

    #[test]
    fn test_sdk_issue_finalize_credential_valid() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let header_json = create_test_header_json();
        let dob_days = 19000i32;
        let r_bits_bytes = vec![0u8; 32];
        let r_bits_b64 = URL_SAFE_NO_PAD.encode(&r_bits_bytes);

        let result = sdk_issue_finalize_credential(header_json, dob_days, r_bits_b64, None);

        // Crypto validation of test stub data will fail (commitment mismatch).
        assert!(
            result.is_err(),
            "finalize with stub crypto data should fail validation"
        );
    }

    #[test]
    fn test_sdk_issue_finalize_credential_invalid_header_json(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let invalid_json = "not json".to_string();
        let r_bits_b64 = URL_SAFE_NO_PAD.encode(vec![0u8; 32]);

        let result = sdk_issue_finalize_credential(invalid_json, 19000, r_bits_b64, None);

        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::InvalidFormat { .. } => {}
            _ => panic!("Expected InvalidFormat error"),
        }
        Ok(())
    }

    #[test]
    fn test_sdk_issue_finalize_credential_empty_header() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let result = sdk_issue_finalize_credential(
            "".to_string(),
            19000,
            URL_SAFE_NO_PAD.encode(vec![0u8; 32]),
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_sdk_issue_finalize_credential_invalid_r_bits_base64() {
        let header_json = create_test_header_json();
        let invalid_b64 = "not-valid-base64!!!".to_string();

        let result = sdk_issue_finalize_credential(header_json, 19000, invalid_b64, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_sdk_issue_finalize_credential_empty_r_bits() {
        let header_json = create_test_header_json();

        let result = sdk_issue_finalize_credential(header_json, 19000, "".to_string(), None);

        assert!(result.is_err());
    }

    #[test]
    fn test_sdk_issue_finalize_credential_zero_dob() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let header_json = create_test_header_json();
        let r_bits_b64 = URL_SAFE_NO_PAD.encode(vec![0u8; 32]);

        let result = sdk_issue_finalize_credential(header_json, 0, r_bits_b64, None);

        // Stub test data will fail commitment verification.
        assert!(
            result.is_err(),
            "finalize with zero dob and stub data should fail validation"
        );
    }

    #[test]
    fn test_sdk_issue_finalize_credential_max_dob() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let header_json = create_test_header_json();
        let r_bits_b64 = URL_SAFE_NO_PAD.encode(vec![0u8; 32]);

        let result = sdk_issue_finalize_credential(header_json, i32::MAX, r_bits_b64, None);

        // Stub test data will fail commitment verification.
        assert!(
            result.is_err(),
            "finalize with max dob and stub data should fail validation"
        );
    }

    #[test]
    fn test_sdk_issue_finalize_credential_wrong_r_bits_length() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let header_json = create_test_header_json();
        let r_bits_b64 = URL_SAFE_NO_PAD.encode(vec![0u8; 10]);

        let result = sdk_issue_finalize_credential(header_json, 19000, r_bits_b64, None);

        // Wrong r_bits length will fail validation.
        assert!(
            result.is_err(),
            "finalize with wrong r_bits length should fail"
        );
    }

    // ========================================================================
    // Build verify request
    // ========================================================================

    fn create_test_qr_payload_json() -> String {
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

    fn create_test_credential_v2_json() -> String {
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

    #[test]
    fn test_sdk_build_verify_request_requires_prover() {
        let cred_json = create_test_credential_v2_json();
        let qr_json = create_test_qr_payload_json();

        let result = sdk_build_verify_request(cred_json, qr_json);

        assert!(result.is_err());
    }

    #[test]
    fn test_sdk_build_verify_request_invalid_credential_json() {
        let qr_json = create_test_qr_payload_json();

        let result = sdk_build_verify_request("not json".to_string(), qr_json);

        assert!(result.is_err());
    }

    #[test]
    fn test_sdk_build_verify_request_invalid_qr_json() {
        let cred_json = create_test_credential_v2_json();

        let result = sdk_build_verify_request(cred_json, "not json".to_string());

        assert!(result.is_err());
    }

    #[test]
    fn test_sdk_build_verify_request_empty_inputs() {
        let result = sdk_build_verify_request("".to_string(), "".to_string());

        assert!(result.is_err());
    }

    #[test]
    fn test_sdk_build_verify_request_missing_credential_fields() {
        let incomplete_cred = serde_json::json!({
            "v": 2,
            "schema": "provii.age/0"
        })
        .to_string();
        let qr_json = create_test_qr_payload_json();

        let result = sdk_build_verify_request(incomplete_cred, qr_json);

        assert!(result.is_err());
    }

    #[test]
    fn test_sdk_build_verify_request_missing_qr_fields() {
        let cred_json = create_test_credential_v2_json();
        let incomplete_qr = serde_json::json!({
            "challenge_id": "test"
        })
        .to_string();

        let result = sdk_build_verify_request(cred_json, incomplete_qr);

        assert!(result.is_err());
    }

    // ========================================================================
    // HTTP feature-gated issuance flows
    // ========================================================================

    #[test]
    #[cfg(feature = "http")]
    fn test_sdk_issue_get_yubikey_challenge_empty_officer_id() {
        let result =
            sdk_issue_get_yubikey_challenge("https://example.com".to_string(), "".to_string());

        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "http")]
    fn test_sdk_issue_get_yubikey_challenge_invalid_url() {
        let result =
            sdk_issue_get_yubikey_challenge("not a url".to_string(), "officer123".to_string());

        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "http")]
    fn test_sdk_issue_start_session_invalid_authorizer() -> Result<(), Box<dyn std::error::Error>> {
        let result = sdk_issue_start_session(
            "https://example.com".to_string(),
            "actor".to_string(),
            "not json".to_string(),
            None,
            None,
            None,
            None,
        );

        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::InvalidFormat { .. } => {}
            _ => panic!("Expected InvalidFormat error"),
        }
        Ok(())
    }

    #[test]
    #[cfg(feature = "http")]
    fn test_sdk_issue_start_session_empty_actor() {
        let authorizer_json = serde_json::json!({
            "type": "yubikey",
            "challenge": "test",
            "signature": "test"
        })
        .to_string();

        let result = sdk_issue_start_session(
            "https://example.com".to_string(),
            "".to_string(),
            authorizer_json,
            None,
            None,
            None,
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "http")]
    fn test_sdk_issue_sign_commitment_invalid_authorizer() {
        let result = sdk_issue_sign_commitment(
            "https://example.com".to_string(),
            "session123".to_string(),
            "commitment_base64".to_string(),
            "not json".to_string(),
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "http")]
    fn test_sdk_issue_sign_commitment_empty_session() {
        let authorizer_json = serde_json::json!({
            "type": "yubikey",
            "challenge": "test",
            "signature": "test"
        })
        .to_string();

        let result = sdk_issue_sign_commitment(
            "https://example.com".to_string(),
            "".to_string(),
            "commitment".to_string(),
            authorizer_json,
            None,
        );

        assert!(result.is_err());
    }

    // ========================================================================
    // Base URL validation
    // ========================================================================

    #[test]
    fn test_validate_base_url_valid_https() {
        let result = super::super::validate_base_url("https://issuer.proviiwallet.app");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://issuer.proviiwallet.app");
    }

    #[test]
    fn test_validate_base_url_strips_trailing_slash() {
        let result = super::super::validate_base_url("https://issuer.proviiwallet.app/");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://issuer.proviiwallet.app");
    }

    #[test]
    fn test_validate_base_url_rejects_http() {
        let result = super::super::validate_base_url("http://issuer.proviiwallet.app");
        assert!(result.is_err());
        let Err(err) = result else {
            panic!("expected error")
        };
        match err {
            FfiError::InvalidFormat { msg } => {
                assert!(msg.contains("HTTPS"));
            }
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn test_validate_base_url_rejects_no_scheme() {
        let result = super::super::validate_base_url("issuer.proviiwallet.app");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_base_url_rejects_empty() {
        let result = super::super::validate_base_url("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_base_url_rejects_garbage() {
        let result = super::super::validate_base_url("not a url at all");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_base_url_preserves_path() {
        let result = super::super::validate_base_url("https://example.com/api/v2");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://example.com/api/v2");
    }

    #[test]
    fn test_validate_base_url_preserves_port() {
        let result = super::super::validate_base_url("https://localhost:8443");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://localhost:8443");
    }

    #[test]
    #[cfg(feature = "http")]
    fn test_sdk_issue_get_yubikey_challenge_rejects_http_url() {
        let result = sdk_issue_get_yubikey_challenge(
            "http://example.com".to_string(),
            "officer123".to_string(),
        );
        assert!(result.is_err());
        let Err(err) = result else {
            panic!("expected error")
        };
        match err {
            FfiError::InvalidFormat { msg } => {
                assert!(msg.contains("HTTPS"));
            }
            _ => panic!("Expected InvalidFormat error for HTTP URL"),
        }
    }

    #[test]
    #[cfg(feature = "http")]
    fn test_sdk_issue_blind_rejects_http_url() {
        let result = sdk_issue_blind(
            "http://example.com".to_string(),
            "attestation".to_string(),
            "rbits".to_string(),
        );
        assert!(result.is_err());
        let Err(err) = result else {
            panic!("expected error")
        };
        match err {
            FfiError::InvalidFormat { msg } => {
                assert!(msg.contains("HTTPS"));
            }
            _ => panic!("Expected InvalidFormat error for HTTP URL"),
        }
    }

    #[test]
    #[cfg(feature = "http")]
    fn test_sdk_create_attestation_rejects_http_url() {
        let authorizer_json = serde_json::json!({
            "type": "yubikey",
            "challenge": "test",
            "signature": "test"
        })
        .to_string();

        let result =
            sdk_create_attestation("http://example.com".to_string(), 19000, authorizer_json);
        assert!(result.is_err());
        let Err(err) = result else {
            panic!("expected error")
        };
        match err {
            FfiError::InvalidFormat { msg } => {
                assert!(msg.contains("HTTPS"));
            }
            _ => panic!("Expected InvalidFormat error for HTTP URL"),
        }
    }
}
